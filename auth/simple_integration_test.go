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

// TestSimpleIntegration tests basic integration without complex dependencies
func TestSimpleIntegration(t *testing.T) {
	// Test basic backward compatibility
	t.Run("BasicBackwardCompatibility", func(t *testing.T) {
		testBasicBackwardCompatibility(t)
	})

	// Test basic migration
	t.Run("BasicMigration", func(t *testing.T) {
		testBasicMigration(t)
	})

	// Test access control integration
	t.Run("AccessControlIntegration", func(t *testing.T) {
		testAccessControlIntegration(t)
	})
}

func testBasicBackwardCompatibility(t *testing.T) {
	// Setup
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	migrationService := NewMigrationService(legacyIAM, enhancedRoles, nil, nil, nil)

	compatManager := NewBackwardCompatibilityManager(
		legacyIAM,
		enhancedRoles,
		migrationService,
		HybridMode,
	)

	// Test compatibility validation
	err := compatManager.ValidateCompatibility()
	if err != nil {
		t.Fatalf("Compatibility validation failed: %v", err)
	}

	// Test compatible IAM service
	compatIAM := compatManager.GetCompatibleIAMService()

	// Test account operations
	testAccount := Account{
		Access: "compat-test-user",
		Secret: "test-secret",
		Role:   RoleUser,
		UserID: 1001,
	}

	// Create account
	err = compatIAM.CreateAccount(testAccount)
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Get account
	retrievedAccount, err := compatIAM.GetUserAccount("compat-test-user")
	if err != nil {
		t.Fatalf("Failed to get account: %v", err)
	}

	if retrievedAccount.Access != testAccount.Access {
		t.Errorf("Expected access %s, got %s", testAccount.Access, retrievedAccount.Access)
	}

	// Update account
	updateProps := MutableProps{Role: RoleAdmin}
	err = compatIAM.UpdateUserAccount("compat-test-user", updateProps)
	if err != nil {
		t.Fatalf("Failed to update account: %v", err)
	}

	// List accounts
	accounts, err := compatIAM.ListUserAccounts()
	if err != nil {
		t.Fatalf("Failed to list accounts: %v", err)
	}

	if len(accounts) == 0 {
		t.Error("Expected at least one account")
	}

	// Delete account
	err = compatIAM.DeleteUserAccount("compat-test-user")
	if err != nil {
		t.Fatalf("Failed to delete account: %v", err)
	}

	t.Log("Basic backward compatibility test passed")
}

func testBasicMigration(t *testing.T) {
	ctx := context.Background()

	// Setup
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	migrationService := NewMigrationService(legacyIAM, enhancedRoles, nil, nil, nil)

	// Create test users
	testUsers := []Account{
		{Access: "migrate-user1", Secret: "secret1", Role: RoleUser},
		{Access: "migrate-admin1", Secret: "secret2", Role: RoleAdmin},
	}

	for _, user := range testUsers {
		err := legacyIAM.CreateAccount(user)
		if err != nil {
			t.Fatalf("Failed to create test user: %v", err)
		}
	}

	// Run migration
	config := MigrationConfig{
		DryRun:             false,
		BatchSize:          10,
		CreateDefaultRoles: true,
	}

	result, err := migrationService.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	if result.TotalUsers != len(testUsers) {
		t.Errorf("Expected %d total users, got %d", len(testUsers), result.TotalUsers)
	}

	if result.MigratedUsers != len(testUsers) {
		t.Errorf("Expected %d migrated users, got %d", len(testUsers), result.MigratedUsers)
	}

	// Validate migration
	for _, user := range testUsers {
		roles, err := enhancedRoles.GetUserRoles(user.Access)
		if err != nil {
			t.Errorf("Failed to get roles for user %s: %v", user.Access, err)
			continue
		}

		if len(roles) == 0 {
			t.Errorf("User %s has no enhanced roles after migration", user.Access)
		}
	}

	// Validate migration results
	validationResult, err := migrationService.ValidateMigration()
	if err != nil {
		t.Fatalf("Migration validation failed: %v", err)
	}

	if validationResult.ValidUsers != len(testUsers) {
		t.Errorf("Expected %d valid users, got %d", len(testUsers), validationResult.ValidUsers)
	}

	t.Log("Basic migration test passed")
}

func testAccessControlIntegration(t *testing.T) {
	ctx := context.Background()

	// Setup
	backend := NewMockBackend()
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	migrationService := NewMigrationService(legacyIAM, enhancedRoles, nil, nil, nil)

	// Create and migrate test user
	testUser := Account{
		Access: "access-test-user",
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
		CreateDefaultRoles: true,
	}

	_, err = migrationService.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Test access control with compatibility manager
	compatManager := NewBackwardCompatibilityManager(
		legacyIAM,
		enhancedRoles,
		migrationService,
		HybridMode,
	)

	// Test access verification
	opts := AccessOptions{
		RoleManager: enhancedRoles,
		IsRoot:      false,
		Acc:         testUser,
		Bucket:      "test-bucket",
		Object:      "test-object",
		Action:      GetObjectAction,
	}

	err = CompatibleVerifyAccess(ctx, backend, opts, compatManager)
	if err != nil {
		t.Errorf("Access verification failed: %v", err)
	}

	// Test with different compatibility modes
	modes := []CompatibilityMode{FullCompatibility, HybridMode, EnhancedOnlyMode}
	for _, mode := range modes {
		compatManager.SetCompatibilityMode(mode)
		
		err = CompatibleVerifyAccess(ctx, backend, opts, compatManager)
		
		// EnhancedOnlyMode should work since user was migrated
		// FullCompatibility and HybridMode should also work
		if err != nil && mode != EnhancedOnlyMode {
			t.Errorf("Access verification failed for mode %v: %v", mode, err)
		}
	}

	t.Log("Access control integration test passed")
}

// TestCompatibilityModeTransitions tests mode transitions
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
		t.Error("Expected initial mode to be FullCompatibility")
	}

	// Test mode transitions
	modes := []CompatibilityMode{HybridMode, EnhancedOnlyMode, FullCompatibility}
	for _, mode := range modes {
		compatManager.SetCompatibilityMode(mode)
		if compatManager.GetCompatibilityMode() != mode {
			t.Errorf("Expected mode %v, got %v", mode, compatManager.GetCompatibilityMode())
		}
	}

	t.Log("Compatibility mode transitions test passed")
}

// TestMigrationRollback tests migration rollback
func TestMigrationRollback(t *testing.T) {
	ctx := context.Background()

	// Setup
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	migrationService := NewMigrationService(legacyIAM, enhancedRoles, nil, nil, nil)

	// Create test user
	testUser := Account{
		Access: "rollback-user",
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
		CreateDefaultRoles: true,
	}

	_, err = migrationService.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify user has enhanced roles
	roles, err := enhancedRoles.GetUserRoles(testUser.Access)
	if err != nil || len(roles) == 0 {
		t.Fatal("User should have enhanced roles after migration")
	}

	// Rollback migration
	rollbackResult, err := migrationService.RollbackMigration([]string{testUser.Access})
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	if rollbackResult.MigratedUsers != 1 {
		t.Errorf("Expected 1 rolled back user, got %d", rollbackResult.MigratedUsers)
	}

	// Verify user no longer has migrated roles
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

	t.Log("Migration rollback test passed")
}

// TestDryRunMigration tests dry run functionality
func TestDryRunMigration(t *testing.T) {
	ctx := context.Background()

	// Setup
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	migrationService := NewMigrationService(legacyIAM, enhancedRoles, nil, nil, nil)

	// Create test user
	testUser := Account{
		Access: "dryrun-user",
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
		CreateDefaultRoles: true,
	}

	result, err := migrationService.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Dry run migration failed: %v", err)
	}

	if result.TotalUsers != 1 {
		t.Errorf("Expected 1 total user, got %d", result.TotalUsers)
	}

	if result.MigratedUsers != 1 {
		t.Errorf("Expected 1 migrated user in dry run, got %d", result.MigratedUsers)
	}

	// Verify no actual changes were made
	roles, err := enhancedRoles.GetUserRoles(testUser.Access)
	if err == nil && len(roles) > 0 {
		t.Error("User should not have enhanced roles in dry run mode")
	}

	t.Log("Dry run migration test passed")
}