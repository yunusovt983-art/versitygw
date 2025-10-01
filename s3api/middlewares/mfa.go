// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package middlewares

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
)

// MFAMiddleware handles multi-factor authentication validation
type MFAMiddleware struct {
	mfaService auth.MFAService
	logger     s3log.AuditLogger
	metrics    *metrics.Manager
}

// NewMFAMiddleware creates a new MFA middleware instance
func NewMFAMiddleware(mfaService auth.MFAService, logger s3log.AuditLogger, metrics *metrics.Manager) *MFAMiddleware {
	return &MFAMiddleware{
		mfaService: mfaService,
		logger:     logger,
		metrics:    metrics,
	}
}

// VerifyMFA creates a middleware handler that verifies MFA tokens when required
func (m *MFAMiddleware) VerifyMFA() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// Skip MFA check for public buckets
		if utils.ContextKeyPublicBucket.IsSet(ctx) {
			return ctx.Next()
		}

		// Skip MFA check if not authenticated yet
		if !utils.ContextKeyAuthenticated.IsSet(ctx) && !utils.ContextKeyAccount.IsSet(ctx) {
			return ctx.Next()
		}

		// Get the authenticated account
		accountVal := utils.ContextKeyAccount.Get(ctx)
		if accountVal == nil {
			return ctx.Next() // No account context, skip MFA
		}
		
		account, ok := accountVal.(auth.Account)
		if !ok {
			return ctx.Next() // Invalid account type
		}

		// Check if MFA is required for this user/role
		if !m.mfaService.IsMFARequiredForRole(account.Access, account.Role) {
			// Check if user has MFA enabled voluntarily
			status, err := m.mfaService.GetMFAStatus(account.Access)
			if err != nil || !status.Enabled {
				return ctx.Next() // MFA not required and not enabled
			}
		}

		// MFA is required or enabled, check for MFA token
		mfaToken := m.extractMFAToken(ctx)
		if mfaToken == "" {
			m.logMFAEvent(account.Access, "missing_token", false, ctx)
			return m.sendMFAError(ctx, s3err.APIError{
				Code:           "MFARequired",
				Description:    "Multi-factor authentication token is required",
				HTTPStatusCode: http.StatusUnauthorized,
			})
		}

		// Validate MFA token
		err := m.mfaService.ValidateTOTP(account.Access, mfaToken)
		if err != nil {
			m.logMFAEvent(account.Access, "invalid_token", false, ctx)
			
			// Handle specific MFA errors
			switch err {
			case auth.ErrMFAUserLocked:
				return m.sendMFAError(ctx, s3err.APIError{
					Code:           "MFAUserLocked",
					Description:    "User is temporarily locked due to failed MFA attempts",
					HTTPStatusCode: http.StatusTooManyRequests,
				})
			case auth.ErrMFAInvalidToken:
				return m.sendMFAError(ctx, s3err.APIError{
					Code:           "MFAInvalidToken",
					Description:    "Invalid multi-factor authentication token",
					HTTPStatusCode: http.StatusUnauthorized,
				})
			case auth.ErrMFANotEnabled:
				return m.sendMFAError(ctx, s3err.APIError{
					Code:           "MFANotEnabled",
					Description:    "Multi-factor authentication is not enabled for this user",
					HTTPStatusCode: http.StatusBadRequest,
				})
			default:
				return m.sendMFAError(ctx, s3err.APIError{
					Code:           "MFAValidationError",
					Description:    fmt.Sprintf("MFA validation failed: %v", err),
					HTTPStatusCode: http.StatusInternalServerError,
				})
			}
		}

		// MFA validation successful
		m.logMFAEvent(account.Access, "token_validated", true, ctx)
		
		// Set MFA verified flag in context
		utils.ContextKeyMFAVerified.Set(ctx, true)
		
		return ctx.Next()
	}
}

// RequireMFA creates a middleware that enforces MFA for specific operations
func (m *MFAMiddleware) RequireMFA() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// Skip for public buckets
		if utils.ContextKeyPublicBucket.IsSet(ctx) {
			return ctx.Next()
		}

		// Get the authenticated account
		accountVal := utils.ContextKeyAccount.Get(ctx)
		if accountVal == nil {
			return ctx.Next() // No account context, let authentication middleware handle
		}
		
		account, ok := accountVal.(auth.Account)
		if !ok {
			return ctx.Next() // Invalid account type
		}

		// Check if MFA is verified
		if !utils.ContextKeyMFAVerified.IsSet(ctx) {
			m.logMFAEvent(account.Access, "mfa_required", false, ctx)
			return m.sendMFAError(ctx, s3err.APIError{
				Code:           "MFARequired",
				Description:    "This operation requires multi-factor authentication",
				HTTPStatusCode: http.StatusUnauthorized,
			})
		}

		return ctx.Next()
	}
}

// extractMFAToken extracts the MFA token from the request
func (m *MFAMiddleware) extractMFAToken(ctx *fiber.Ctx) string {
	// Try multiple sources for MFA token
	
	// 1. X-Amz-MFA header (AWS-style)
	if token := ctx.Get("X-Amz-MFA"); token != "" {
		return token
	}
	
	// 2. X-MFA-Token header
	if token := ctx.Get("X-MFA-Token"); token != "" {
		return token
	}
	
	// 3. Authorization header with MFA token
	auth := ctx.Get("Authorization")
	if auth != "" {
		// Look for MFA token in Authorization header
		// Format: "AWS4-HMAC-SHA256 ... MFA=token"
		if strings.Contains(auth, "MFA=") {
			parts := strings.Split(auth, "MFA=")
			if len(parts) > 1 {
				token := strings.TrimSpace(parts[1])
				// Remove any trailing parameters
				if idx := strings.Index(token, ","); idx != -1 {
					token = token[:idx]
				}
				if idx := strings.Index(token, " "); idx != -1 {
					token = token[:idx]
				}
				return token
			}
		}
	}
	
	// 4. Query parameter (for presigned URLs)
	if token := ctx.Query("X-Amz-MFA"); token != "" {
		return token
	}
	
	return ""
}

// logMFAEvent logs MFA-related events for audit purposes
func (m *MFAMiddleware) logMFAEvent(userID, action string, success bool, ctx *fiber.Ctx) {
	if m.logger == nil {
		return
	}

	logMeta := s3log.LogMeta{
		Action:     action,
		HttpStatus: 200,
	}
	
	if !success {
		logMeta.HttpStatus = 401
	}

	var err error
	if !success {
		err = fmt.Errorf("MFA validation failed for user %s", userID)
	}

	// Log the MFA event
	m.logger.Log(ctx, err, []byte(fmt.Sprintf("MFA %s for user %s", action, userID)), logMeta)

	// Update metrics if available
	if m.metrics != nil {
		if success {
			m.metrics.Send(ctx, nil, "mfa_validation_success", 1, 200)
		} else {
			m.metrics.Send(ctx, err, "mfa_validation_failure", 1, 401)
		}
	}
}

// sendMFAError sends an MFA-related error response
func (m *MFAMiddleware) sendMFAError(ctx *fiber.Ctx, err s3err.APIError) error {
	return controllers.SendResponse(ctx, err, &controllers.MetaOpts{
		Logger:     m.logger,
		MetricsMng: m.metrics,
	})
}

// MFATokenValidator provides utilities for validating MFA tokens in different contexts
type MFATokenValidator struct {
	mfaService auth.MFAService
}

// NewMFATokenValidator creates a new MFA token validator
func NewMFATokenValidator(mfaService auth.MFAService) *MFATokenValidator {
	return &MFATokenValidator{
		mfaService: mfaService,
	}
}

// ValidateTokenForUser validates an MFA token for a specific user
func (v *MFATokenValidator) ValidateTokenForUser(userID, token string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	
	if token == "" {
		return auth.ErrMFAInvalidToken
	}
	
	return v.mfaService.ValidateTOTP(userID, token)
}

// ValidateBackupCodeForUser validates a backup code for a specific user
func (v *MFATokenValidator) ValidateBackupCodeForUser(userID, code string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	
	if code == "" {
		return auth.ErrMFAInvalidBackupCode
	}
	
	return v.mfaService.ValidateBackupCode(userID, code)
}

// IsUserMFAEnabled checks if MFA is enabled for a user
func (v *MFATokenValidator) IsUserMFAEnabled(userID string) (bool, error) {
	if userID == "" {
		return false, fmt.Errorf("user ID cannot be empty")
	}
	
	status, err := v.mfaService.GetMFAStatus(userID)
	if err != nil {
		return false, err
	}
	
	return status.Enabled, nil
}

// GetUserMFAStatus returns the MFA status for a user
func (v *MFATokenValidator) GetUserMFAStatus(userID string) (*auth.MFAStatus, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}
	
	return v.mfaService.GetMFAStatus(userID)
}