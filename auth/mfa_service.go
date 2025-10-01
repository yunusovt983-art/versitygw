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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// MFAServiceImpl implements the MFAService interface
type MFAServiceImpl struct {
	storage   MFAStorage
	generator *TOTPGenerator
	config    *MFAConfig
	policies  []*MFAPolicy
}

// NewMFAService creates a new MFA service instance
func NewMFAService(storage MFAStorage, config *MFAConfig) *MFAServiceImpl {
	if config == nil {
		config = DefaultMFAConfig()
	}
	
	return &MFAServiceImpl{
		storage:   storage,
		generator: NewTOTPGenerator(config),
		config:    config,
		policies:  make([]*MFAPolicy, 0),
	}
}

// GenerateSecret creates a new MFA secret for a user
func (m *MFAServiceImpl) GenerateSecret(userID string) (*MFASecret, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID cannot be empty")
	}
	
	// Check if MFA is already enabled
	if data, err := m.storage.GetMFAData(userID); err == nil && data.Enabled {
		return nil, ErrMFAAlreadyEnabled
	}
	
	// Generate secret
	secret, err := m.generator.GenerateSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}
	
	// Generate backup codes
	backupCodes, err := m.generator.GenerateBackupCodes(m.config.BackupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}
	
	return &MFASecret{
		Secret:      secret,
		BackupCodes: backupCodes,
		Issuer:      m.config.Issuer,
		AccountName: userID,
	}, nil
}

// ValidateTOTP validates a TOTP token for a user
func (m *MFAServiceImpl) ValidateTOTP(userID, token string) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	
	if token == "" {
		return ErrMFAInvalidToken
	}
	
	// Get MFA data
	data, err := m.storage.GetMFAData(userID)
	if err != nil {
		return err
	}
	
	if !data.Enabled {
		return ErrMFANotEnabled
	}
	
	// Check if user is locked
	if data.LockedUntil != nil && time.Now().Before(*data.LockedUntil) {
		return ErrMFAUserLocked
	}
	
	// Validate token
	now := time.Now()
	if !m.generator.ValidateTOTP(data.Secret, token, now) {
		// Increment failed attempts
		failedAttempts := data.FailedAttempts + 1
		var lockedUntil *time.Time
		
		if failedAttempts >= m.config.MaxFailedAttempts {
			lockTime := now.Add(m.config.LockoutDuration)
			lockedUntil = &lockTime
		}
		
		if err := m.storage.UpdateFailedAttempts(userID, failedAttempts, lockedUntil); err != nil {
			// Log error but don't fail the validation
			fmt.Printf("Failed to update failed attempts for user %s: %v\n", userID, err)
		}
		
		if lockedUntil != nil {
			return ErrMFAUserLocked
		}
		
		return ErrMFAInvalidToken
	}
	
	// Update last used timestamp and reset failed attempts
	if err := m.storage.UpdateLastUsed(userID, now); err != nil {
		// Log error but don't fail the validation since token was valid
		fmt.Printf("Failed to update last used timestamp for user %s: %v\n", userID, err)
	}
	
	return nil
}

// IsMFARequired checks if MFA is required for a user
func (m *MFAServiceImpl) IsMFARequired(userID string) bool {
	// Check global configuration
	if m.config.Required {
		return true
	}
	
	// Check policies (would need user role information)
	// For now, return false as we don't have role context here
	// This would be enhanced when integrating with the IAM system
	return false
}

// IsMFARequiredForRole checks if MFA is required for a user with a specific role
func (m *MFAServiceImpl) IsMFARequiredForRole(userID string, role Role) bool {
	// Check global configuration
	if m.config.Required {
		return true
	}
	
	// Check policies
	for _, policy := range m.policies {
		if policy.IsUserRequired(userID, role) {
			return true
		}
	}
	
	return false
}

// EnableMFA enables MFA for a user with the provided secret
func (m *MFAServiceImpl) EnableMFA(userID string, secret *MFASecret) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	
	if secret == nil {
		return fmt.Errorf("secret cannot be nil")
	}
	
	// Check if MFA is already enabled
	if data, err := m.storage.GetMFAData(userID); err == nil && data.Enabled {
		return ErrMFAAlreadyEnabled
	}
	
	// Hash backup codes for storage
	hashedBackupCodes := make([]string, len(secret.BackupCodes))
	for i, code := range secret.BackupCodes {
		hash := sha256.Sum256([]byte(strings.ToUpper(code)))
		hashedBackupCodes[i] = hex.EncodeToString(hash[:])
	}
	
	// Create MFA data
	mfaData := &MFAUserData{
		UserID:         userID,
		Secret:         secret.Secret,
		BackupCodes:    hashedBackupCodes,
		Enabled:        true,
		SetupCompleted: true,
		LastUsed:       time.Time{}, // Will be set on first use
		FailedAttempts: 0,
		LockedUntil:    nil,
	}
	
	// Store MFA data
	return m.storage.StoreMFAData(userID, mfaData)
}

// DisableMFA disables MFA for a user
func (m *MFAServiceImpl) DisableMFA(userID string) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	
	// Check if MFA is enabled
	_, err := m.storage.GetMFAData(userID)
	if err != nil {
		return err
	}
	
	// Delete MFA data
	return m.storage.DeleteMFAData(userID)
}

// GetMFAStatus returns the MFA status for a user
func (m *MFAServiceImpl) GetMFAStatus(userID string) (*MFAStatus, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID cannot be empty")
	}
	
	data, err := m.storage.GetMFAData(userID)
	if err != nil {
		if err == ErrMFANotEnabled {
			return &MFAStatus{
				Enabled:              false,
				LastUsed:             time.Time{},
				BackupCodesRemaining: 0,
				SetupCompleted:       false,
				FailedAttempts:       0,
				LockedUntil:          nil,
			}, nil
		}
		return nil, err
	}
	
	return &MFAStatus{
		Enabled:              data.Enabled,
		LastUsed:             data.LastUsed,
		BackupCodesRemaining: len(data.BackupCodes),
		SetupCompleted:       data.SetupCompleted,
		FailedAttempts:       data.FailedAttempts,
		LockedUntil:          data.LockedUntil,
	}, nil
}

// ValidateBackupCode validates a backup code for a user
func (m *MFAServiceImpl) ValidateBackupCode(userID, code string) error {
	if userID == "" {
		return fmt.Errorf("userID cannot be empty")
	}
	
	if code == "" {
		return ErrMFAInvalidBackupCode
	}
	
	// Get MFA data
	data, err := m.storage.GetMFAData(userID)
	if err != nil {
		return err
	}
	
	if !data.Enabled {
		return ErrMFANotEnabled
	}
	
	// Check if user is locked
	if data.LockedUntil != nil && time.Now().Before(*data.LockedUntil) {
		return ErrMFAUserLocked
	}
	
	// Hash the provided code
	hash := sha256.Sum256([]byte(strings.ToUpper(code)))
	hashedCode := hex.EncodeToString(hash[:])
	
	// Find and remove the backup code
	codeFound := false
	newBackupCodes := make([]string, 0, len(data.BackupCodes))
	for _, storedCode := range data.BackupCodes {
		if storedCode == hashedCode {
			codeFound = true
			// Don't add this code to the new list (effectively removing it)
		} else {
			newBackupCodes = append(newBackupCodes, storedCode)
		}
	}
	
	if !codeFound {
		// Increment failed attempts
		failedAttempts := data.FailedAttempts + 1
		var lockedUntil *time.Time
		
		if failedAttempts >= m.config.MaxFailedAttempts {
			lockTime := time.Now().Add(m.config.LockoutDuration)
			lockedUntil = &lockTime
		}
		
		if err := m.storage.UpdateFailedAttempts(userID, failedAttempts, lockedUntil); err != nil {
			fmt.Printf("Failed to update failed attempts for user %s: %v\n", userID, err)
		}
		
		if lockedUntil != nil {
			return ErrMFAUserLocked
		}
		
		return ErrMFAInvalidBackupCode
	}
	
	// Update backup codes and reset failed attempts
	data.BackupCodes = newBackupCodes
	data.LastUsed = time.Now()
	data.FailedAttempts = 0
	data.LockedUntil = nil
	
	return m.storage.StoreMFAData(userID, data)
}

// RegenerateBackupCodes generates new backup codes for a user
func (m *MFAServiceImpl) RegenerateBackupCodes(userID string) ([]string, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID cannot be empty")
	}
	
	// Get MFA data
	data, err := m.storage.GetMFAData(userID)
	if err != nil {
		return nil, err
	}
	
	if !data.Enabled {
		return nil, ErrMFANotEnabled
	}
	
	// Generate new backup codes
	backupCodes, err := m.generator.GenerateBackupCodes(m.config.BackupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}
	
	// Hash backup codes for storage
	hashedBackupCodes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		hash := sha256.Sum256([]byte(strings.ToUpper(code)))
		hashedBackupCodes[i] = hex.EncodeToString(hash[:])
	}
	
	// Update stored data
	data.BackupCodes = hashedBackupCodes
	if err := m.storage.StoreMFAData(userID, data); err != nil {
		return nil, fmt.Errorf("failed to store updated backup codes: %w", err)
	}
	
	return backupCodes, nil
}

// AddPolicy adds an MFA policy
func (m *MFAServiceImpl) AddPolicy(policy *MFAPolicy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}
	
	m.policies = append(m.policies, policy)
	return nil
}

// RemovePolicy removes an MFA policy by name
func (m *MFAServiceImpl) RemovePolicy(name string) error {
	for i, policy := range m.policies {
		if policy.Name == name {
			// Remove policy from slice
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			return nil
		}
	}
	
	return fmt.Errorf("policy not found: %s", name)
}

// GetPolicies returns all MFA policies
func (m *MFAServiceImpl) GetPolicies() []*MFAPolicy {
	// Return a copy to prevent external modifications
	policies := make([]*MFAPolicy, len(m.policies))
	copy(policies, m.policies)
	return policies
}

// UpdateConfig updates the MFA configuration
func (m *MFAServiceImpl) UpdateConfig(config *MFAConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	
	m.config = config
	m.generator = NewTOTPGenerator(config)
	
	return nil
}

// GetConfig returns the current MFA configuration
func (m *MFAServiceImpl) GetConfig() *MFAConfig {
	// Return a copy to prevent external modifications
	configCopy := *m.config
	return &configCopy
}

// Shutdown gracefully shuts down the MFA service
func (m *MFAServiceImpl) Shutdown() error {
	if m.storage != nil {
		return m.storage.Close()
	}
	return nil
}