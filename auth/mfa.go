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

package auth

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// MFAService defines the interface for multi-factor authentication operations
type MFAService interface {
	// GenerateSecret creates a new MFA secret for a user
	GenerateSecret(userID string) (*MFASecret, error)
	
	// ValidateTOTP validates a TOTP token for a user
	ValidateTOTP(userID, token string) error
	
	// IsMFARequired checks if MFA is required for a user
	IsMFARequired(userID string) bool
	
	// IsMFARequiredForRole checks if MFA is required for a user with a specific role
	IsMFARequiredForRole(userID string, role Role) bool
	
	// EnableMFA enables MFA for a user with the provided secret
	EnableMFA(userID string, secret *MFASecret) error
	
	// DisableMFA disables MFA for a user
	DisableMFA(userID string) error
	
	// GetMFAStatus returns the MFA status for a user
	GetMFAStatus(userID string) (*MFAStatus, error)
	
	// ValidateBackupCode validates a backup code for a user
	ValidateBackupCode(userID, code string) error
	
	// RegenerateBackupCodes generates new backup codes for a user
	RegenerateBackupCodes(userID string) ([]string, error)
}

// MFASecret contains the secret and related data for MFA setup
type MFASecret struct {
	// Secret is the base32-encoded secret key
	Secret string `json:"secret"`
	
	// QRCode is the QR code image data for easy setup
	QRCode []byte `json:"qr_code,omitempty"`
	
	// BackupCodes are one-time use backup codes
	BackupCodes []string `json:"backup_codes"`
	
	// Issuer is the service name for TOTP apps
	Issuer string `json:"issuer"`
	
	// AccountName is the user identifier for TOTP apps
	AccountName string `json:"account_name"`
}

// MFAStatus represents the current MFA status for a user
type MFAStatus struct {
	// Enabled indicates if MFA is enabled for the user
	Enabled bool `json:"enabled"`
	
	// LastUsed is the timestamp of the last successful MFA validation
	LastUsed time.Time `json:"last_used"`
	
	// BackupCodesRemaining is the number of unused backup codes
	BackupCodesRemaining int `json:"backup_codes_remaining"`
	
	// SetupCompleted indicates if the user has completed MFA setup
	SetupCompleted bool `json:"setup_completed"`
	
	// FailedAttempts is the number of consecutive failed MFA attempts
	FailedAttempts int `json:"failed_attempts"`
	
	// LockedUntil is the timestamp until which MFA is locked due to failed attempts
	LockedUntil *time.Time `json:"locked_until,omitempty"`
}

// MFAConfig defines the configuration for MFA functionality
type MFAConfig struct {
	// Required indicates if MFA is required for all users
	Required bool `json:"required"`
	
	// TOTPWindow is the number of time steps to allow for TOTP validation (default: 1)
	TOTPWindow int `json:"totp_window"`
	
	// BackupCodes is the number of backup codes to generate (default: 10)
	BackupCodes int `json:"backup_codes"`
	
	// GracePeriod is the time period during which users can access without MFA after enabling
	GracePeriod time.Duration `json:"grace_period"`
	
	// Issuer is the service name displayed in TOTP apps
	Issuer string `json:"issuer"`
	
	// MaxFailedAttempts is the maximum number of failed attempts before locking
	MaxFailedAttempts int `json:"max_failed_attempts"`
	
	// LockoutDuration is how long to lock MFA after max failed attempts
	LockoutDuration time.Duration `json:"lockout_duration"`
	
	// SecretLength is the length of the generated secret in bytes (default: 20)
	SecretLength int `json:"secret_length"`
}

// DefaultMFAConfig returns a default MFA configuration
func DefaultMFAConfig() *MFAConfig {
	return &MFAConfig{
		Required:          false,
		TOTPWindow:        1,
		BackupCodes:       10,
		GracePeriod:       24 * time.Hour,
		Issuer:            "Versity S3 Gateway",
		MaxFailedAttempts: 5,
		LockoutDuration:   15 * time.Minute,
		SecretLength:      20,
	}
}

// Validate validates the MFA configuration
func (c *MFAConfig) Validate() error {
	if c.TOTPWindow < 0 || c.TOTPWindow > 10 {
		return errors.New("totp_window must be between 0 and 10")
	}
	
	if c.BackupCodes < 0 || c.BackupCodes > 50 {
		return errors.New("backup_codes must be between 0 and 50")
	}
	
	if c.GracePeriod < 0 {
		return errors.New("grace_period cannot be negative")
	}
	
	if c.Issuer == "" {
		return errors.New("issuer cannot be empty")
	}
	
	if c.MaxFailedAttempts < 1 || c.MaxFailedAttempts > 100 {
		return errors.New("max_failed_attempts must be between 1 and 100")
	}
	
	if c.LockoutDuration < 0 {
		return errors.New("lockout_duration cannot be negative")
	}
	
	if c.SecretLength < 16 || c.SecretLength > 64 {
		return errors.New("secret_length must be between 16 and 64")
	}
	
	return nil
}

// MFAUserData represents MFA-related data stored for a user
type MFAUserData struct {
	// UserID is the unique identifier for the user
	UserID string `json:"user_id"`
	
	// Secret is the base32-encoded TOTP secret
	Secret string `json:"secret"`
	
	// BackupCodes are the remaining backup codes (hashed)
	BackupCodes []string `json:"backup_codes"`
	
	// Enabled indicates if MFA is enabled
	Enabled bool `json:"enabled"`
	
	// SetupCompleted indicates if setup is complete
	SetupCompleted bool `json:"setup_completed"`
	
	// LastUsed is the timestamp of last successful validation
	LastUsed time.Time `json:"last_used"`
	
	// FailedAttempts is the count of consecutive failed attempts
	FailedAttempts int `json:"failed_attempts"`
	
	// LockedUntil is the timestamp until which MFA is locked
	LockedUntil *time.Time `json:"locked_until,omitempty"`
	
	// CreatedAt is when MFA was first set up
	CreatedAt time.Time `json:"created_at"`
	
	// UpdatedAt is when MFA data was last updated
	UpdatedAt time.Time `json:"updated_at"`
}

// TOTPGenerator provides TOTP token generation and validation
type TOTPGenerator struct {
	config *MFAConfig
}

// NewTOTPGenerator creates a new TOTP generator with the given configuration
func NewTOTPGenerator(config *MFAConfig) *TOTPGenerator {
	if config == nil {
		config = DefaultMFAConfig()
	}
	return &TOTPGenerator{config: config}
}

// GenerateSecret generates a new random secret for TOTP
func (t *TOTPGenerator) GenerateSecret() (string, error) {
	secret := make([]byte, t.config.SecretLength)
	_, err := rand.Read(secret)
	if err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}
	
	return base32.StdEncoding.EncodeToString(secret), nil
}

// GenerateTOTP generates a TOTP token for the given secret at the specified time
func (t *TOTPGenerator) GenerateTOTP(secret string, timestamp time.Time) (string, error) {
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("invalid secret format: %w", err)
	}
	
	// Calculate time step (30-second intervals)
	timeStep := timestamp.Unix() / 30
	
	return t.generateHOTP(key, timeStep)
}

// ValidateTOTP validates a TOTP token against the secret within the configured time window
func (t *TOTPGenerator) ValidateTOTP(secret, token string, timestamp time.Time) bool {
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}
	
	// Calculate current time step
	currentTimeStep := timestamp.Unix() / 30
	
	// Check current time step and surrounding window
	for i := -t.config.TOTPWindow; i <= t.config.TOTPWindow; i++ {
		timeStep := currentTimeStep + int64(i)
		expectedToken, err := t.generateHOTP(key, timeStep)
		if err != nil {
			continue
		}
		
		if expectedToken == token {
			return true
		}
	}
	
	return false
}

// generateHOTP generates an HOTP token using the provided key and counter
func (t *TOTPGenerator) generateHOTP(key []byte, counter int64) (string, error) {
	// Convert counter to byte array
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))
	
	// Calculate HMAC-SHA1
	h := sha1.New()
	h.Write(key)
	h.Write(counterBytes)
	hash := h.Sum(nil)
	
	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0F
	truncatedHash := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF
	
	// Generate 6-digit code
	code := truncatedHash % uint32(math.Pow10(6))
	
	return fmt.Sprintf("%06d", code), nil
}

// GenerateBackupCodes generates a set of backup codes
func (t *TOTPGenerator) GenerateBackupCodes(count int) ([]string, error) {
	if count <= 0 {
		return nil, errors.New("count must be positive")
	}
	
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		// Generate 8-character alphanumeric code
		codeBytes := make([]byte, 6)
		_, err := rand.Read(codeBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		
		// Convert to base32 and take first 8 characters
		code := base32.StdEncoding.EncodeToString(codeBytes)[:8]
		codes[i] = strings.ToUpper(code)
	}
	
	return codes, nil
}

// MFAPolicy defines policies for MFA enforcement
type MFAPolicy struct {
	// Name is the policy name
	Name string `json:"name"`
	
	// Description describes the policy
	Description string `json:"description"`
	
	// RequiredForRoles specifies which roles require MFA
	RequiredForRoles []Role `json:"required_for_roles"`
	
	// RequiredForUsers specifies which specific users require MFA
	RequiredForUsers []string `json:"required_for_users"`
	
	// ExemptUsers specifies users exempt from MFA requirements
	ExemptUsers []string `json:"exempt_users"`
	
	// GracePeriod is the grace period for new MFA requirements
	GracePeriod time.Duration `json:"grace_period"`
	
	// EnforceFromTime is when the policy becomes active
	EnforceFromTime *time.Time `json:"enforce_from_time,omitempty"`
	
	// Active indicates if the policy is currently active
	Active bool `json:"active"`
}

// IsUserRequired checks if MFA is required for a specific user and role
func (p *MFAPolicy) IsUserRequired(userID string, role Role) bool {
	if !p.Active {
		return false
	}
	
	// Check if user is explicitly exempt
	for _, exemptUser := range p.ExemptUsers {
		if exemptUser == userID {
			return false
		}
	}
	
	// Check if user is explicitly required
	for _, requiredUser := range p.RequiredForUsers {
		if requiredUser == userID {
			return true
		}
	}
	
	// Check if role is required
	for _, requiredRole := range p.RequiredForRoles {
		if requiredRole == role {
			return true
		}
	}
	
	return false
}

// Validate validates the MFA policy
func (p *MFAPolicy) Validate() error {
	if p.Name == "" {
		return errors.New("policy name cannot be empty")
	}
	
	if p.GracePeriod < 0 {
		return errors.New("grace_period cannot be negative")
	}
	
	// Validate roles
	for _, role := range p.RequiredForRoles {
		if !role.IsValid() {
			return fmt.Errorf("invalid role: %s", role)
		}
	}
	
	return nil
}

// MFAError represents MFA-specific errors
type MFAError struct {
	Code    MFAErrorCode `json:"code"`
	Message string       `json:"message"`
	UserID  string       `json:"user_id,omitempty"`
}

func (e *MFAError) Error() string {
	return e.Message
}

// MFAErrorCode represents different types of MFA errors
type MFAErrorCode int

const (
	MFAErrorInvalidToken MFAErrorCode = iota
	MFAErrorNotEnabled
	MFAErrorAlreadyEnabled
	MFAErrorUserLocked
	MFAErrorInvalidSecret
	MFAErrorInvalidBackupCode
	MFAErrorSetupIncomplete
	MFAErrorTooManyAttempts
	MFAErrorConfigurationInvalid
)

// Common MFA errors
var (
	ErrMFAInvalidToken      = &MFAError{Code: MFAErrorInvalidToken, Message: "invalid MFA token"}
	ErrMFANotEnabled        = &MFAError{Code: MFAErrorNotEnabled, Message: "MFA is not enabled for this user"}
	ErrMFAAlreadyEnabled    = &MFAError{Code: MFAErrorAlreadyEnabled, Message: "MFA is already enabled for this user"}
	ErrMFAUserLocked        = &MFAError{Code: MFAErrorUserLocked, Message: "user is temporarily locked due to failed MFA attempts"}
	ErrMFAInvalidSecret     = &MFAError{Code: MFAErrorInvalidSecret, Message: "invalid MFA secret"}
	ErrMFAInvalidBackupCode = &MFAError{Code: MFAErrorInvalidBackupCode, Message: "invalid backup code"}
	ErrMFASetupIncomplete   = &MFAError{Code: MFAErrorSetupIncomplete, Message: "MFA setup is not complete"}
	ErrMFATooManyAttempts   = &MFAError{Code: MFAErrorTooManyAttempts, Message: "too many failed MFA attempts"}
)