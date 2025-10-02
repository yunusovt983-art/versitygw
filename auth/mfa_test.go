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
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestMFAConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *MFAConfig
		wantErr bool
	}{
		{
			name:    "valid default config",
			config:  DefaultMFAConfig(),
			wantErr: false,
		},
		{
			name: "invalid totp window - negative",
			config: &MFAConfig{
				TOTPWindow:        -1,
				BackupCodes:       10,
				GracePeriod:       time.Hour,
				Issuer:            "Test",
				MaxFailedAttempts: 5,
				LockoutDuration:   time.Minute,
				SecretLength:      20,
			},
			wantErr: true,
		},
		{
			name: "invalid totp window - too large",
			config: &MFAConfig{
				TOTPWindow:        11,
				BackupCodes:       10,
				GracePeriod:       time.Hour,
				Issuer:            "Test",
				MaxFailedAttempts: 5,
				LockoutDuration:   time.Minute,
				SecretLength:      20,
			},
			wantErr: true,
		},
		{
			name: "invalid backup codes - negative",
			config: &MFAConfig{
				TOTPWindow:        1,
				BackupCodes:       -1,
				GracePeriod:       time.Hour,
				Issuer:            "Test",
				MaxFailedAttempts: 5,
				LockoutDuration:   time.Minute,
				SecretLength:      20,
			},
			wantErr: true,
		},
		{
			name: "empty issuer",
			config: &MFAConfig{
				TOTPWindow:        1,
				BackupCodes:       10,
				GracePeriod:       time.Hour,
				Issuer:            "",
				MaxFailedAttempts: 5,
				LockoutDuration:   time.Minute,
				SecretLength:      20,
			},
			wantErr: true,
		},
		{
			name: "invalid secret length - too small",
			config: &MFAConfig{
				TOTPWindow:        1,
				BackupCodes:       10,
				GracePeriod:       time.Hour,
				Issuer:            "Test",
				MaxFailedAttempts: 5,
				LockoutDuration:   time.Minute,
				SecretLength:      15,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("MFAConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTOTPGenerator_GenerateSecret(t *testing.T) {
	config := DefaultMFAConfig()
	generator := NewTOTPGenerator(config)

	secret, err := generator.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	if secret == "" {
		t.Error("GenerateSecret() returned empty secret")
	}

	// Verify it's valid base32
	_, err = base32.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Errorf("Generated secret is not valid base32: %v", err)
	}

	// Verify length
	decoded, _ := base32.StdEncoding.DecodeString(secret)
	if len(decoded) != config.SecretLength {
		t.Errorf("Secret length = %d, want %d", len(decoded), config.SecretLength)
	}
}

func TestTOTPGenerator_GenerateTOTP(t *testing.T) {
	config := DefaultMFAConfig()
	generator := NewTOTPGenerator(config)

	// Use a known secret for testing
	secret := "JBSWY3DPEHPK3PXP" // "Hello!" in base32
	timestamp := time.Unix(1234567890, 0)

	token, err := generator.GenerateTOTP(secret, timestamp)
	if err != nil {
		t.Fatalf("GenerateTOTP() error = %v", err)
	}

	if len(token) != 6 {
		t.Errorf("Token length = %d, want 6", len(token))
	}

	// Verify token is numeric
	for _, char := range token {
		if char < '0' || char > '9' {
			t.Errorf("Token contains non-numeric character: %c", char)
		}
	}
}

func TestTOTPGenerator_ValidateTOTP(t *testing.T) {
	config := DefaultMFAConfig()
	generator := NewTOTPGenerator(config)

	secret := "JBSWY3DPEHPK3PXP"
	timestamp := time.Unix(1234567890, 0)

	// Generate a token
	token, err := generator.GenerateTOTP(secret, timestamp)
	if err != nil {
		t.Fatalf("GenerateTOTP() error = %v", err)
	}

	// Validate the same token at the same time
	if !generator.ValidateTOTP(secret, token, timestamp) {
		t.Error("ValidateTOTP() failed for valid token")
	}

	// Validate with wrong token
	if generator.ValidateTOTP(secret, "000000", timestamp) {
		t.Error("ValidateTOTP() succeeded for invalid token")
	}

	// Validate with time window
	futureTime := timestamp.Add(30 * time.Second) // Next time step
	if !generator.ValidateTOTP(secret, token, futureTime) {
		t.Error("ValidateTOTP() failed within time window")
	}

	// Validate outside time window
	farFutureTime := timestamp.Add(300 * time.Second) // 5 time steps ahead
	if generator.ValidateTOTP(secret, token, farFutureTime) {
		t.Error("ValidateTOTP() succeeded outside time window")
	}
}

func TestTOTPGenerator_GenerateBackupCodes(t *testing.T) {
	config := DefaultMFAConfig()
	generator := NewTOTPGenerator(config)

	count := 10
	codes, err := generator.GenerateBackupCodes(count)
	if err != nil {
		t.Fatalf("GenerateBackupCodes() error = %v", err)
	}

	if len(codes) != count {
		t.Errorf("Generated %d codes, want %d", len(codes), count)
	}

	// Verify codes are unique
	codeMap := make(map[string]bool)
	for _, code := range codes {
		if len(code) != 8 {
			t.Errorf("Code length = %d, want 8", len(code))
		}

		if codeMap[code] {
			t.Errorf("Duplicate code generated: %s", code)
		}
		codeMap[code] = true

		// Verify code is uppercase alphanumeric
		if code != strings.ToUpper(code) {
			t.Errorf("Code is not uppercase: %s", code)
		}
	}
}

func TestMFAPolicy_IsUserRequired(t *testing.T) {
	policy := &MFAPolicy{
		Name:             "test-policy",
		RequiredForRoles: []Role{RoleAdmin},
		RequiredForUsers: []string{"user1"},
		ExemptUsers:      []string{"user2"},
		Active:           true,
	}

	tests := []struct {
		name   string
		userID string
		role   Role
		want   bool
	}{
		{
			name:   "admin role required",
			userID: "admin1",
			role:   RoleAdmin,
			want:   true,
		},
		{
			name:   "user role not required",
			userID: "user3",
			role:   RoleUser,
			want:   false,
		},
		{
			name:   "specific user required",
			userID: "user1",
			role:   RoleUser,
			want:   true,
		},
		{
			name:   "exempt user",
			userID: "user2",
			role:   RoleAdmin,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policy.IsUserRequired(tt.userID, tt.role)
			if got != tt.want {
				t.Errorf("MFAPolicy.IsUserRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMFAPolicy_Validate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *MFAPolicy
		wantErr bool
	}{
		{
			name: "valid policy",
			policy: &MFAPolicy{
				Name:             "test-policy",
				RequiredForRoles: []Role{RoleAdmin},
				GracePeriod:      time.Hour,
				Active:           true,
			},
			wantErr: false,
		},
		{
			name: "empty name",
			policy: &MFAPolicy{
				Name:        "",
				GracePeriod: time.Hour,
				Active:      true,
			},
			wantErr: true,
		},
		{
			name: "negative grace period",
			policy: &MFAPolicy{
				Name:        "test-policy",
				GracePeriod: -time.Hour,
				Active:      true,
			},
			wantErr: true,
		},
		{
			name: "invalid role",
			policy: &MFAPolicy{
				Name:             "test-policy",
				RequiredForRoles: []Role{"invalid"},
				GracePeriod:      time.Hour,
				Active:           true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("MFAPolicy.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMFAService_GenerateSecret(t *testing.T) {
	storage := NewMemoryMFAStorage()
	config := DefaultMFAConfig()
	service := NewMFAService(storage, config)

	userID := "test-user"

	secret, err := service.GenerateSecret(userID)
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	if secret.Secret == "" {
		t.Error("Generated secret is empty")
	}

	if len(secret.BackupCodes) != config.BackupCodes {
		t.Errorf("Generated %d backup codes, want %d", len(secret.BackupCodes), config.BackupCodes)
	}

	if secret.Issuer != config.Issuer {
		t.Errorf("Issuer = %s, want %s", secret.Issuer, config.Issuer)
	}

	if secret.AccountName != userID {
		t.Errorf("AccountName = %s, want %s", secret.AccountName, userID)
	}
}

func TestMFAService_EnableDisableMFA(t *testing.T) {
	storage := NewMemoryMFAStorage()
	config := DefaultMFAConfig()
	service := NewMFAService(storage, config)

	userID := "test-user"

	// Generate secret
	secret, err := service.GenerateSecret(userID)
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	// Enable MFA
	err = service.EnableMFA(userID, secret)
	if err != nil {
		t.Fatalf("EnableMFA() error = %v", err)
	}

	// Check status
	status, err := service.GetMFAStatus(userID)
	if err != nil {
		t.Fatalf("GetMFAStatus() error = %v", err)
	}

	if !status.Enabled {
		t.Error("MFA should be enabled")
	}

	if !status.SetupCompleted {
		t.Error("MFA setup should be completed")
	}

	// Try to enable again (should fail)
	err = service.EnableMFA(userID, secret)
	if err != ErrMFAAlreadyEnabled {
		t.Errorf("EnableMFA() error = %v, want %v", err, ErrMFAAlreadyEnabled)
	}

	// Disable MFA
	err = service.DisableMFA(userID)
	if err != nil {
		t.Fatalf("DisableMFA() error = %v", err)
	}

	// Check status after disable
	status, err = service.GetMFAStatus(userID)
	if err != nil {
		t.Fatalf("GetMFAStatus() error = %v", err)
	}

	if status.Enabled {
		t.Error("MFA should be disabled")
	}
}

func TestMFAService_ValidateTOTP(t *testing.T) {
	storage := NewMemoryMFAStorage()
	config := DefaultMFAConfig()
	service := NewMFAService(storage, config)

	userID := "test-user"

	// Generate and enable MFA
	secret, err := service.GenerateSecret(userID)
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	err = service.EnableMFA(userID, secret)
	if err != nil {
		t.Fatalf("EnableMFA() error = %v", err)
	}

	// Generate a valid token
	generator := NewTOTPGenerator(config)
	now := time.Now()
	token, err := generator.GenerateTOTP(secret.Secret, now)
	if err != nil {
		t.Fatalf("GenerateTOTP() error = %v", err)
	}

	// Validate the token
	err = service.ValidateTOTP(userID, token)
	if err != nil {
		t.Errorf("ValidateTOTP() error = %v", err)
	}

	// Validate invalid token
	err = service.ValidateTOTP(userID, "000000")
	if err != ErrMFAInvalidToken {
		t.Errorf("ValidateTOTP() error = %v, want %v", err, ErrMFAInvalidToken)
	}

	// Check that failed attempts are tracked
	status, err := service.GetMFAStatus(userID)
	if err != nil {
		t.Fatalf("GetMFAStatus() error = %v", err)
	}

	if status.FailedAttempts == 0 {
		t.Error("Failed attempts should be tracked")
	}
}

func TestMFAService_ValidateBackupCode(t *testing.T) {
	storage := NewMemoryMFAStorage()
	config := DefaultMFAConfig()
	service := NewMFAService(storage, config)

	userID := "test-user"

	// Generate and enable MFA
	secret, err := service.GenerateSecret(userID)
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	err = service.EnableMFA(userID, secret)
	if err != nil {
		t.Fatalf("EnableMFA() error = %v", err)
	}

	// Get initial backup codes count
	status, err := service.GetMFAStatus(userID)
	if err != nil {
		t.Fatalf("GetMFAStatus() error = %v", err)
	}
	initialCount := status.BackupCodesRemaining

	// Use a backup code
	backupCode := secret.BackupCodes[0]
	err = service.ValidateBackupCode(userID, backupCode)
	if err != nil {
		t.Errorf("ValidateBackupCode() error = %v", err)
	}

	// Check that backup codes count decreased
	status, err = service.GetMFAStatus(userID)
	if err != nil {
		t.Fatalf("GetMFAStatus() error = %v", err)
	}

	if status.BackupCodesRemaining != initialCount-1 {
		t.Errorf("Backup codes remaining = %d, want %d", status.BackupCodesRemaining, initialCount-1)
	}

	// Try to use the same backup code again (should fail)
	err = service.ValidateBackupCode(userID, backupCode)
	if err != ErrMFAInvalidBackupCode {
		t.Errorf("ValidateBackupCode() error = %v, want %v", err, ErrMFAInvalidBackupCode)
	}

	// Use invalid backup code
	err = service.ValidateBackupCode(userID, "INVALID1")
	if err != ErrMFAInvalidBackupCode {
		t.Errorf("ValidateBackupCode() error = %v, want %v", err, ErrMFAInvalidBackupCode)
	}
}