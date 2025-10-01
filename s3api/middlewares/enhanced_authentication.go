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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/metrics"
	"github.com/versity/versitygw/s3api/controllers"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
)

// EnhancedAuthConfig contains configuration for enhanced authentication with MFA
type EnhancedAuthConfig struct {
	Root      RootUserConfig
	IAM       auth.IAMService
	MFA       auth.MFAService
	Logger    s3log.AuditLogger
	Metrics   *metrics.Manager
	Region    string
	Debug     bool
	MFAConfig *MFAAuthConfig
}

// MFAAuthConfig contains MFA-specific authentication configuration
type MFAAuthConfig struct {
	// RequireForAdmins requires MFA for admin users
	RequireForAdmins bool
	
	// RequireForOperations specifies operations that require MFA
	RequireForOperations []string
	
	// GracePeriod allows access without MFA for a period after enabling
	GracePeriod time.Duration
	
	// AllowBackupCodes allows using backup codes instead of TOTP
	AllowBackupCodes bool
}

// DefaultMFAAuthConfig returns default MFA authentication configuration
func DefaultMFAAuthConfig() *MFAAuthConfig {
	return &MFAAuthConfig{
		RequireForAdmins:     true,
		RequireForOperations: []string{"DeleteBucket", "PutBucketPolicy", "DeleteBucketPolicy"},
		GracePeriod:          24 * time.Hour,
		AllowBackupCodes:     true,
	}
}

// VerifyV4SignatureWithMFA creates an enhanced authentication middleware that includes MFA validation
func VerifyV4SignatureWithMFA(config *EnhancedAuthConfig) fiber.Handler {
	if config.MFAConfig == nil {
		config.MFAConfig = DefaultMFAAuthConfig()
	}
	
	acct := accounts{root: config.Root, iam: config.IAM}
	mfaMiddleware := NewMFAMiddleware(config.MFA, config.Logger, config.Metrics)

	return func(ctx *fiber.Ctx) error {
		// The bucket is public, no need to check this signature
		if utils.ContextKeyPublicBucket.IsSet(ctx) {
			return ctx.Next()
		}
		
		// If ContextKeyAuthenticated is set in context locals, it means it was presigned url case
		if utils.ContextKeyAuthenticated.IsSet(ctx) {
			return ctx.Next()
		}

		// First, perform standard authentication
		err := performStandardAuth(ctx, acct, config)
		if err != nil {
			return err
		}

		// Get the authenticated account
		accountVal := utils.ContextKeyAccount.Get(ctx)
		if accountVal == nil {
			return ctx.Next() // Should not happen after successful auth, but be safe
		}
		
		account, ok := accountVal.(auth.Account)
		if !ok {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrInternalError), &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
		}

		// Check if MFA is required for this user/operation
		if shouldRequireMFA(ctx, account, config) {
			// Extract and validate MFA token
			mfaToken := mfaMiddleware.extractMFAToken(ctx)
			if mfaToken == "" {
				logMFAFailure(ctx, account.Access, "missing_mfa_token", config)
				return sendMFARequiredResponse(ctx, config)
			}

			// Try TOTP validation first
			err := config.MFA.ValidateTOTP(account.Access, mfaToken)
			if err != nil {
				// If TOTP fails and backup codes are allowed, try backup code validation
				if config.MFAConfig.AllowBackupCodes && err == auth.ErrMFAInvalidToken {
					backupErr := config.MFA.ValidateBackupCode(account.Access, mfaToken)
					if backupErr == nil {
						// Backup code validation successful
						logMFASuccess(ctx, account.Access, "backup_code_validated", config)
						utils.ContextKeyMFAVerified.Set(ctx, true)
						return ctx.Next()
					}
				}

				// Handle MFA validation errors
				logMFAFailure(ctx, account.Access, "invalid_mfa_token", config)
				return handleMFAError(ctx, err, config)
			}

			// MFA validation successful
			logMFASuccess(ctx, account.Access, "totp_validated", config)
			utils.ContextKeyMFAVerified.Set(ctx, true)
		}

		return ctx.Next()
	}
}

// performStandardAuth performs the standard V4 signature authentication
func performStandardAuth(ctx *fiber.Ctx, acct accounts, config *EnhancedAuthConfig) error {
	authorization := ctx.Get("Authorization")
	if authorization == "" {
		return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrAuthHeaderEmpty), &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	}

	authData, err := utils.ParseAuthorization(authorization)
	if err != nil {
		return controllers.SendResponse(ctx, err, &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	}

	if authData.Region != config.Region {
		return controllers.SendResponse(ctx, s3err.APIError{
			Code:           "SignatureDoesNotMatch",
			Description:    fmt.Sprintf("Credential should be scoped to a valid Region, not %v", authData.Region),
			HTTPStatusCode: http.StatusForbidden,
		}, &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	}

	utils.ContextKeyIsRoot.Set(ctx, authData.Access == config.Root.Access)

	account, err := acct.getAccount(authData.Access)
	if err == auth.ErrNoSuchUser {
		return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidAccessKeyID), &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	}
	if err != nil {
		return controllers.SendResponse(ctx, err, &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	}

	utils.ContextKeyAccount.Set(ctx, account)

	// Check X-Amz-Date header
	date := ctx.Get("X-Amz-Date")
	if date == "" {
		return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrMissingDateHeader), &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	}

	// Parse the date and check the date validity
	tdate, err := time.Parse(iso8601Format, date)
	if err != nil {
		return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrMalformedDate), &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	}

	if date[:8] != authData.Date {
		return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrSignatureDateDoesNotMatch), &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	}

	// Validate the dates difference
	err = utils.ValidateDate(tdate)
	if err != nil {
		return controllers.SendResponse(ctx, err, &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	}

	var contentLength int64
	contentLengthStr := ctx.Get("Content-Length")
	if contentLengthStr != "" {
		contentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrInvalidRequest), &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
		}
	}

	hashPayload := ctx.Get("X-Amz-Content-Sha256")
	if utils.IsBigDataAction(ctx) {
		// for streaming PUT actions, authorization is deferred
		// until end of stream due to need to get length and
		// checksum of the stream to validate authorization
		wrapBodyReaderEnhanced(ctx, func(r io.Reader) io.Reader {
			return utils.NewAuthReader(ctx, r, authData, account.Secret, config.Debug)
		})

		// wrap the io.Reader with ChunkReader if x-amz-content-sha256
		// provide chunk encoding value
		if utils.IsStreamingPayload(hashPayload) {
			var err error
			wrapBodyReaderEnhanced(ctx, func(r io.Reader) io.Reader {
				var cr io.Reader
				cr, err = utils.NewChunkReader(ctx, r, authData, config.Region, account.Secret, tdate)
				return cr
			})
			if err != nil {
				return controllers.SendResponse(ctx, err, &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
			}

			return nil
		}

		// Content-Length has to be set for data uploads: PutObject, UploadPart
		if contentLengthStr == "" {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrMissingContentLength), &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
		}
		// the upload limit for big data actions: PutObject, UploadPart
		// is 5gb. If the size exceeds the limit, return 'EntityTooLarge' err
		if contentLength > maxObjSizeLimit {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrEntityTooLarge), &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
		}

		return nil
	}

	if !utils.IsSpecialPayload(hashPayload) {
		// Calculate the hash of the request payload
		hashedPayload := sha256.Sum256(ctx.Body())
		hexPayload := hex.EncodeToString(hashedPayload[:])

		// Compare the calculated hash with the hash provided
		if hashPayload != hexPayload {
			return controllers.SendResponse(ctx, s3err.GetAPIError(s3err.ErrContentSHA256Mismatch), &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
		}
	}

	err = utils.CheckValidSignature(ctx, authData, account.Secret, hashPayload, tdate, contentLength, config.Debug)
	if err != nil {
		return controllers.SendResponse(ctx, err, &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	}

	return nil
}

// shouldRequireMFA determines if MFA should be required for the current request
func shouldRequireMFA(ctx *fiber.Ctx, account auth.Account, config *EnhancedAuthConfig) bool {
	// Skip MFA for root user (configurable)
	if utils.ContextKeyIsRoot.IsSet(ctx) {
		return false
	}

	// Check if MFA is required for the user's role
	if config.MFAConfig.RequireForAdmins && account.Role == auth.RoleAdmin {
		return true
	}

	// Check if MFA is required for this specific operation
	operation := getOperationFromContext(ctx)
	for _, requiredOp := range config.MFAConfig.RequireForOperations {
		if operation == requiredOp {
			return true
		}
	}

	// Check if user has MFA enabled (voluntary MFA)
	if config.MFA != nil {
		status, err := config.MFA.GetMFAStatus(account.Access)
		if err == nil && status.Enabled {
			return true
		}
	}

	return false
}

// getOperationFromContext extracts the S3 operation from the request context
func getOperationFromContext(ctx *fiber.Ctx) string {
	// This is a simplified operation detection
	// In a real implementation, you'd want more sophisticated operation detection
	method := ctx.Method()
	path := ctx.Path()

	switch method {
	case "DELETE":
		if path == "/" {
			return "DeleteBucket"
		}
		return "DeleteObject"
	case "PUT":
		// Check for policy query parameter (bucket policy operations)
		if _, exists := ctx.Queries()["policy"]; exists {
			return "PutBucketPolicy"
		}
		if path == "/" {
			return "CreateBucket"
		}
		return "PutObject"
	case "GET":
		// Check for policy query parameter (bucket policy operations)
		if _, exists := ctx.Queries()["policy"]; exists {
			return "GetBucketPolicy"
		}
		return "GetObject"
	default:
		return "Unknown"
	}
}

// handleMFAError handles different types of MFA errors
func handleMFAError(ctx *fiber.Ctx, err error, config *EnhancedAuthConfig) error {
	switch err {
	case auth.ErrMFAUserLocked:
		return controllers.SendResponse(ctx, s3err.APIError{
			Code:           "MFAUserLocked",
			Description:    "User is temporarily locked due to failed MFA attempts",
			HTTPStatusCode: http.StatusTooManyRequests,
		}, &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	case auth.ErrMFAInvalidToken:
		return controllers.SendResponse(ctx, s3err.APIError{
			Code:           "MFAInvalidToken",
			Description:    "Invalid multi-factor authentication token",
			HTTPStatusCode: http.StatusUnauthorized,
		}, &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	case auth.ErrMFANotEnabled:
		return controllers.SendResponse(ctx, s3err.APIError{
			Code:           "MFANotEnabled",
			Description:    "Multi-factor authentication is not enabled for this user",
			HTTPStatusCode: http.StatusBadRequest,
		}, &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	default:
		return controllers.SendResponse(ctx, s3err.APIError{
			Code:           "MFAValidationError",
			Description:    fmt.Sprintf("MFA validation failed: %v", err),
			HTTPStatusCode: http.StatusInternalServerError,
		}, &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
	}
}

// sendMFARequiredResponse sends a response indicating MFA is required
func sendMFARequiredResponse(ctx *fiber.Ctx, config *EnhancedAuthConfig) error {
	return controllers.SendResponse(ctx, s3err.APIError{
		Code:           "MFARequired",
		Description:    "Multi-factor authentication token is required for this operation",
		HTTPStatusCode: http.StatusUnauthorized,
	}, &controllers.MetaOpts{Logger: config.Logger, MetricsMng: config.Metrics})
}

// logMFASuccess logs successful MFA validation
func logMFASuccess(ctx *fiber.Ctx, userID, action string, config *EnhancedAuthConfig) {
	if config.Logger == nil {
		return
	}

	logMeta := s3log.LogMeta{
		Action:     fmt.Sprintf("mfa_%s", action),
		HttpStatus: 200,
	}

	config.Logger.Log(ctx, nil, []byte(fmt.Sprintf("MFA success: %s for user %s", action, userID)), logMeta)

	if config.Metrics != nil {
		config.Metrics.Send(ctx, nil, "mfa_validation_success", 1, 200)
	}
}

// logMFAFailure logs failed MFA validation
func logMFAFailure(ctx *fiber.Ctx, userID, action string, config *EnhancedAuthConfig) {
	if config.Logger == nil {
		return
	}

	err := fmt.Errorf("MFA failure: %s for user %s", action, userID)
	logMeta := s3log.LogMeta{
		Action:     fmt.Sprintf("mfa_%s", action),
		HttpStatus: 401,
	}

	config.Logger.Log(ctx, err, []byte(err.Error()), logMeta)

	if config.Metrics != nil {
		config.Metrics.Send(ctx, err, "mfa_validation_failure", 1, 401)
	}
}

// wrapBodyReaderEnhanced wraps the body reader with the provided wrapper function
func wrapBodyReaderEnhanced(ctx *fiber.Ctx, wrapper func(io.Reader) io.Reader) {
	if existingReader := utils.ContextKeyBodyReader.Get(ctx); existingReader != nil {
		if reader, ok := existingReader.(io.Reader); ok {
			utils.ContextKeyBodyReader.Set(ctx, wrapper(reader))
		}
	}
}