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
	"context"
	"testing"
	"time"
)

// TestBackwardCompatibilityManager tests the backward compatibility manager
func TestBackwardCompatibilityManager(t *testing.T) {
	// Setup test environment
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	migrationService := NewMigrationService(legacyIAM, enhancedRoles, nil, nil, nil)

	// Test different compatibility modes
	testModes := []struct {
		name string
		mode CompatibilityMode
	}{
		{"FullCompatibility", FullCompatibility},
		{"HybridMode", HybridMode},
		{"EnhancedOnlyMode", EnhancedOnlyMode},
	}

	for _, tm := range testModes {
		t.Run(tm.name, func(t *testing.T) {
			compatManager := NewBackwardCompatibilityManager(
				legacyIAM,
				enhancedRoles,
				migrationService,
				tm.mode,
			)

			testBackwardCompatibilityMode(t, compatManager, tm.mode)
		})
	}
}

func testBackwardCompatibilityMode(t *testing.T, compatManager *BackwardCompatibilityManager, mode CompatibilityMode) {
	// Test IAM service compatibility
	compatIAM := compatManager.GetCompatibleIAMService()

	// Test account creation
	testAccount := Account{
		Access: "test-user",
		Secret: "test-secret",
		Role:   RoleUser,
		UserID: 1001,
	}

	err := compatIAM.CreateAccount(testAccount)
	if err != nil {
		t.Fatalf("Failed to create account in %v mode: %v", mode, err)
	}

	// Test account retrieval
	retrievedAccount, err := compatIAM.GetUserAccount("test-user")
	if err != nil {
		t.Fatalf("Failed to get account in %v mode: %v", mode, err)
	}

	if retrievedAccount.Access != testAccount.Access {
		t.Errorf("Expected access %s, got %s", testAccount.Access, retrievedAccount.Access)
	}

	// Test account update
	updateProps := MutableProps{
		Role: RoleAdmin,
	}

	err = compatIAM.UpdateUserAccount("test-user", updateProps)
	if err != nil {
		t.Fatalf("Failed to update account in %v mode: %v", mode, err)
	}

	// Verify update
	updatedAccount, err := compatIAM.GetUserAccount("test-user")
	if err != nil {
		t.Fatalf("Failed to get updated account: %v", err)
	}

	if updatedAccount.Role != RoleAdmin {
		t.Errorf("Expected role %s, got %s", RoleAdmin, updatedAccount.Role)
	}

	// Test account listing
	accounts, err := compatIAM.ListUserAccounts()
	if err != nil {
		t.Fatalf("Failed to list accounts in %v mode: %v", mode, err)
	}

	if len(accounts) == 0 {
		t.Error("Expected at least one account in list")
	}

	// Test account deletion
	err = compatIAM.DeleteUserAccount("test-user")
	if err != nil {
		t.Fatalf("Failed to delete account in %v mode: %v", mode, err)
	}

	// Verify deletion
	_, err = compatIAM.GetUserAccount("test-user")
	if err == nil {
		t.Error("Expected error when getting deleted account")
	}
}

// TestCompatibleVerifyAccess tests backward-compatible access verification
func TestCompatibleVerifyAccess(t *testing.T) {
	ctx := context.Background()
	backend := NewMockBackend()
	
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	migrationService := NewMigrationService(legacyIAM, enhancedRoles, nil, nil, nil)

	// Create test user in legacy system
	testAccount := Account{
		Access: "compat-test-user",
		Secret: "test-secret",
		Role:   RoleUser,
	}
	legacyIAM.CreateAccount(testAccount)

	testCases := []struct {
		name           string
		mode           CompatibilityMode
		expectSuccess  bool
		description    string
	}{
		{
			name:          "FullCompatibilityMode",
			mode:          FullCompatibility,
			expectSuccess: true,
			description:   "Should work with legacy system only",
		},
		{
			name:          "HybridMode",
			mode:          HybridMode,
			expectSuccess: true,
			description:   "Should work with enhanced system and fallback",
		},
		{
			name:          "EnhancedOnlyMode",
			mode:          EnhancedOnlyMode,
			expectSuccess: false, // User not migrated to enhanced system
			description:   "Should require enhanced system",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			compatManager := NewBackwardCompatibilityManager(
				legacyIAM,
				enhancedRoles,
				migrationService,
				tc.mode,
			)

			opts := AccessOptions{
				IsRoot: false,
				Acc:    testAccount,
				Bucket: "test-bucket",
				Object: "test-object",
				Action: GetObjectAction,
			}

			err := CompatibleVerifyAccess(ctx, backend, opts, compatManager)

			if tc.expectSuccess && err != nil {
				t.Errorf("Expected success but got error: %v. %s", err, tc.description)
			}
			if !tc.expectSuccess && err == nil {
				t.Errorf("Expected error but got success. %s", tc.description)
			}
		})
	}
}

// TestMigrationAndCompatibility tests migration with compatibility
func TestMigrationAndCompatibility(t *testing.T) {
	ctx := context.Background()
	
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	migrationService := NewMigrationService(legacyIAM, enhancedRoles, nil, nil, nil)

	// Create test users in legacy system
	testUsers := []Account{
		{Access: "admin-user", Secret: "secret1", Role: RoleAdmin},
		{Access: "regular-user", Secret: "secret2", Role: RoleUser},
		{Access: "plus-user", Secret: "secret3", Role: RoleUserPlus},
	}

	for _, user := range testUsers {
		err := legacyIAM.CreateAccount(user)
		if err != nil {
			t.Fatalf("Failed to create test user %s: %v", user.Access, err)
		}
	}

	// Test migration
	config := MigrationConfig{
		DryRun:             false,
		BatchSize:          10,
		CreateDefaultRoles: true,
		EnableMFAForAdmins: false,
		PreserveSessions:   false,
	}

	result, err := migrationService.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	if result.MigratedUsers != len(testUsers) {
		t.Errorf("Expected %d migrated users, got %d", len(testUsers), result.MigratedUsers)
	}

	if result.FailedUsers > 0 {
		t.Errorf("Expected no failed users, got %d", result.FailedUsers)
	}

	// Test compatibility after migration
	compatManager := NewBackwardCompatibilityManager(
		legacyIAM,
		enhancedRoles,
		migrationService,
		HybridMode,
	)

	backend := NewMockBackend()

	// Test access for each migrated user
	for _, user := range testUsers {
		opts := AccessOptions{
			RoleManager: enhancedRoles,
			IsRoot:      false,
			Acc:         user,
			Bucket:      "test-bucket",
			Object:      "test-object",
			Action:      GetObjectAction,
		}

		err := CompatibleVerifyAccess(ctx, backend, opts, compatManager)
		if err != nil {
			t.Errorf("Access verification failed for migrated user %s: %v", user.Access, err)
		}
	}

	// Validate migration
	validationResult, err := migrationService.ValidateMigration()
	if err != nil {
		t.Fatalf("Migration validation failed: %v", err)
	}

	if validationResult.ValidUsers != len(testUsers) {
		t.Errorf("Expected %d valid users, got %d", len(testUsers), validationResult.ValidUsers)
	}

	if len(validationResult.Issues) > 0 {
		t.Errorf("Expected no validation issues, got %d", len(validationResult.Issues))
		for _, issue := range validationResult.Issues {
			t.Logf("Validation issue: %s - %s", issue.Type, issue.Description)
		}
	}
}

// TestRollbackMigration tests migration rollback functionality
func TestRollbackMigration(t *testing.T) {
	ctx := context.Background()
	
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	migrationService := NewMigrationService(legacyIAM, enhancedRoles, nil, nil, nil)

	// Create and migrate test user
	testUser := Account{
		Access: "rollback-test-user",
		Secret: "test-secret",
		Role:   RoleUser,
	}

	err := legacyIAM.CreateAccount(testUser)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Migrate user
	config := MigrationConfig{
		DryRun:             false,
		BatchSize:          1,
		CreateDefaultRoles: true,
	}

	_, err = migrationService.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify user has enhanced roles
	roles, err := enhancedRoles.GetUserRoles(testUser.Access)
	if err != nil {
		t.Fatalf("Failed to get user roles: %v", err)
	}

	if len(roles) == 0 {
		t.Fatal("Expected user to have enhanced roles after migration")
	}

	// Rollback migration
	rollbackResult, err := migrationService.RollbackMigration([]string{testUser.Access})
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	if rollbackResult.MigratedUsers != 1 {
		t.Errorf("Expected 1 rolled back user, got %d", rollbackResult.MigratedUsers)
	}

	// Verify user no longer has enhanced roles
	rolesAfterRollback, err := enhancedRoles.GetUserRoles(testUser.Access)
	if err != nil {
		t.Fatalf("Failed to get user roles after rollback: %v", err)
	}

	migratedRoleCount := 0
	for _, role := range rolesAfterRollback {
		if isMigratedRole(role.ID) {
			migratedRoleCount++
		}
	}

	if migratedRoleCount > 0 {
		t.Errorf("Expected no migrated roles after rollback, got %d", migratedRoleCount)
	}
}

// TestDryRunMigration tests dry run migration functionality
func TestDryRunMigration(t *testing.T) {
	ctx := context.Background()
	
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	migrationService := NewMigrationService(legacyIAM, enhancedRoles, nil, nil, nil)

	// Create test user
	testUser := Account{
		Access: "dryrun-test-user",
		Secret: "test-secret",
		Role:   RoleUser,
	}

	err := legacyIAM.CreateAccount(testUser)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Run dry run migration
	config := MigrationConfig{
		DryRun:             true,
		BatchSize:          1,
		CreateDefaultRoles: true,
	}

	result, err := migrationService.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Dry run migration failed: %v", err)
	}

	if result.TotalUsers != 1 {
		t.Errorf("Expected 1 total user, got %d", result.TotalUsers)
	}

	// In dry run, users should be "migrated" but no actual changes made
	if result.MigratedUsers != 1 {
		t.Errorf("Expected 1 migrated user in dry run, got %d", result.MigratedUsers)
	}

	// Verify no actual changes were made
	roles, err := enhancedRoles.GetUserRoles(testUser.Access)
	if err == nil && len(roles) > 0 {
		t.Error("Expected no roles to be created in dry run mode")
	}
}

// MockLegacyIAMService implements IAMService for testing
type MockLegacyIAMService struct {
	accounts map[string]Account
}

func (m *MockLegacyIAMService) CreateAccount(account Account) error {
	if m.accounts == nil {
		m.accounts = make(map[string]Account)
	}
	m.accounts[account.Access] = account
	return nil
}

func (m *MockLegacyIAMService) GetUserAccount(access string) (Account, error) {
	if m.accounts == nil {
		return Account{}, fmt.Errorf("account not found")
	}
	account, exists := m.accounts[access]
	if !exists {
		return Account{}, fmt.Errorf("account not found")
	}
	return account, nil
}

func (m *MockLegacyIAMService) UpdateUserAccount(access string, props MutableProps) error {
	if m.accounts == nil {
		return fmt.Errorf("account not found")
	}
	account, exists := m.accounts[access]
	if !exists {
		return fmt.Errorf("account not found")
	}
	updateAcc(&account, props)
	m.accounts[access] = account
	return nil
}

func (m *MockLegacyIAMService) DeleteUserAccount(access string) error {
	if m.accounts == nil {
		return fmt.Errorf("account not found")
	}
	delete(m.accounts, access)
	return nil
}

func (m *MockLegacyIAMService) ListUserAccounts() ([]Account, error) {
	if m.accounts == nil {
		return []Account{}, nil
	}
	
	accounts := make([]Account, 0, len(m.accounts))
	for _, account := range m.accounts {
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (m *MockLegacyIAMService) Shutdown() error {
	return nil
}

// TestCompatibilityModeTransitions tests transitioning between compatibility modes
func TestCompatibilityModeTransitions(t *testing.T) {
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	migrationService := NewMigrationService(legacyIAM, enhancedRoles, nil, nil, nil)

	compatManager := NewBackwardCompatibilityManager(
		legacyIAM,
		enhancedRoles,
		migrationService,
		FullCompatibility,
	)

	// Test initial mode
	if compatManager.GetCompatibilityMode() != FullCompatibility {
		t.Errorf("Expected initial mode to be FullCompatibility")
	}

	// Test mode transitions
	transitions := []CompatibilityMode{
		HybridMode,
		EnhancedOnlyMode,
		FullCompatibility,
	}

	for _, mode := range transitions {
		compatManager.SetCompatibilityMode(mode)
		if compatManager.GetCompatibilityMode() != mode {
			t.Errorf("Expected mode %v, got %v", mode, compatManager.GetCompatibilityMode())
		}
	}
}

// TestCompatibilityValidation tests compatibility validation
func TestCompatibilityValidation(t *testing.T) {
	testCases := []struct {
		name          string
		legacyIAM     IAMService
		enhancedRoles EnhancedRoleManager
		mode          CompatibilityMode
		expectError   bool
	}{
		{
			name:          "ValidFullCompatibility",
			legacyIAM:     &MockLegacyIAMService{},
			enhancedRoles: nil,
			mode:          FullCompatibility,
			expectError:   false,
		},
		{
			name:          "ValidHybridMode",
			legacyIAM:     &MockLegacyIAMService{},
			enhancedRoles: NewInMemoryRoleManager(),
			mode:          HybridMode,
			expectError:   false,
		},
		{
			name:          "InvalidHybridMode",
			legacyIAM:     &MockLegacyIAMService{},
			enhancedRoles: nil,
			mode:          HybridMode,
			expectError:   true,
		},
		{
			name:          "InvalidNoLegacyIAM",
			legacyIAM:     nil,
			enhancedRoles: NewInMemoryRoleManager(),
			mode:          FullCompatibility,
			expectError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			compatManager := NewBackwardCompatibilityManager(
				tc.legacyIAM,
				tc.enhancedRoles,
				nil,
				tc.mode,
			)

			err := compatManager.ValidateCompatibility()

			if tc.expectError && err == nil {
				t.Error("Expected validation error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no validation error but got: %v", err)
			}
		})
	}
}

// TestLegacyAPIClientCompatibility tests that existing API clients continue to work
func TestLegacyAPIClientCompatibility(t *testing.T) {
	// This test simulates existing API clients that use the legacy IAM interface
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	migrationService := NewMigrationService(legacyIAM, enhancedRoles, nil, nil, nil)

	compatManager := NewBackwardCompatibilityManager(
		legacyIAM,
		enhancedRoles,
		migrationService,
		HybridMode,
	)

	// Get compatible IAM service (this is what existing clients would use)
	iamService := compatManager.GetCompatibleIAMService()

	// Test all IAM operations that existing clients might use
	testAccount := Account{
		Access: "legacy-client-user",
		Secret: "legacy-secret",
		Role:   RoleUser,
		UserID: 2001,
	}

	// Test account creation (existing client behavior)
	err := iamService.CreateAccount(testAccount)
	if err != nil {
		t.Fatalf("Legacy client account creation failed: %v", err)
	}

	// Test account retrieval (existing client behavior)
	retrievedAccount, err := iamService.GetUserAccount(testAccount.Access)
	if err != nil {
		t.Fatalf("Legacy client account retrieval failed: %v", err)
	}

	// Verify account data matches what legacy client expects
	if retrievedAccount.Access != testAccount.Access {
		t.Errorf("Expected access %s, got %s", testAccount.Access, retrievedAccount.Access)
	}
	if retrievedAccount.Role != testAccount.Role {
		t.Errorf("Expected role %s, got %s", testAccount.Role, retrievedAccount.Role)
	}
	if retrievedAccount.UserID != testAccount.UserID {
		t.Errorf("Expected UserID %d, got %d", testAccount.UserID, retrievedAccount.UserID)
	}

	// Test account update (existing client behavior)
	updateProps := MutableProps{
		Role: RoleAdmin,
	}
	err = iamService.UpdateUserAccount(testAccount.Access, updateProps)
	if err != nil {
		t.Fatalf("Legacy client account update failed: %v", err)
	}

	// Test account listing (existing client behavior)
	accounts, err := iamService.ListUserAccounts()
	if err != nil {
		t.Fatalf("Legacy client account listing failed: %v", err)
	}

	if len(accounts) == 0 {
		t.Error("Expected at least one account in list")
	}

	// Verify the updated account appears in the list with correct data
	found := false
	for _, account := range accounts {
		if account.Access == testAccount.Access {
			found = true
			if account.Role != RoleAdmin {
				t.Errorf("Expected updated role %s, got %s", RoleAdmin, account.Role)
			}
			break
		}
	}

	if !found {
		t.Error("Updated account not found in account list")
	}

	// Test account deletion (existing client behavior)
	err = iamService.DeleteUserAccount(testAccount.Access)
	if err != nil {
		t.Fatalf("Legacy client account deletion failed: %v", err)
	}

	// Verify account is deleted
	_, err = iamService.GetUserAccount(testAccount.Access)
	if err == nil {
		t.Error("Expected error when getting deleted account")
	}

	// Test service shutdown (existing client behavior)
	err = iamService.Shutdown()
	if err != nil {
		t.Fatalf("Legacy client service shutdown failed: %v", err)
	}
}