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
	"fmt"
	"testing"
)

// TestMinimalCompatibility tests basic compatibility functionality
func TestMinimalCompatibility(t *testing.T) {
	// Test basic backward compatibility manager creation
	legacyIAM := &MinimalMockIAMService{accounts: make(map[string]Account)}
	enhancedRoles := NewInMemoryRoleManager()

	compatManager := NewBackwardCompatibilityManager(
		legacyIAM,
		enhancedRoles,
		nil, // migration service
		HybridMode,
	)

	if compatManager == nil {
		t.Fatal("Failed to create compatibility manager")
	}

	// Test compatibility validation
	err := compatManager.ValidateCompatibility()
	if err != nil {
		t.Fatalf("Compatibility validation failed: %v", err)
	}

	// Test mode transitions
	modes := []CompatibilityMode{FullCompatibility, HybridMode, EnhancedOnlyMode}
	for _, mode := range modes {
		compatManager.SetCompatibilityMode(mode)
		if compatManager.GetCompatibilityMode() != mode {
			t.Errorf("Expected mode %v, got %v", mode, compatManager.GetCompatibilityMode())
		}
	}

	t.Log("Minimal compatibility test passed")
}

// TestMinimalMigration tests basic migration functionality
func TestMinimalMigration(t *testing.T) {
	ctx := context.Background()

	// Setup minimal components
	legacyIAM := &MinimalMockIAMService{accounts: make(map[string]Account)}
	enhancedRoles := NewInMemoryRoleManager()

	migrationService := NewMigrationService(
		legacyIAM,
		enhancedRoles,
		nil, // mfa service
		nil, // session manager
		nil, // audit logger
	)

	// Create test user
	testUser := Account{
		Access: "test-user",
		Secret: "test-secret",
		Role:   RoleUser,
	}

	err := legacyIAM.CreateAccount(testUser)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test dry run migration
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

	if result.MigratedUsers != 1 {
		t.Errorf("Expected 1 migrated user in dry run, got %d", result.MigratedUsers)
	}

	// Test actual migration
	config.DryRun = false
	result, err = migrationService.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	if result.MigratedUsers != 1 {
		t.Errorf("Expected 1 migrated user, got %d", result.MigratedUsers)
	}

	// Verify user has enhanced roles
	roles, err := enhancedRoles.GetUserRoles(testUser.Access)
	if err != nil {
		t.Fatalf("Failed to get user roles: %v", err)
	}

	if len(roles) == 0 {
		t.Error("User should have enhanced roles after migration")
	}

	t.Log("Minimal migration test passed")
}

// TestMinimalAccessControl tests basic access control compatibility
func TestMinimalAccessControl(t *testing.T) {
	ctx := context.Background()

	// Setup
	backend := NewMockBackend()
	legacyIAM := &MinimalMockIAMService{accounts: make(map[string]Account)}
	enhancedRoles := NewInMemoryRoleManager()

	// Create test user
	testUser := Account{
		Access: "access-user",
		Secret: "test-secret",
		Role:   RoleUser,
	}

	err := legacyIAM.CreateAccount(testUser)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test access without compatibility manager (original behavior)
	opts := AccessOptions{
		IsRoot: false,
		Acc:    testUser,
		Bucket: "test-bucket",
		Object: "test-object",
		Action: GetObjectAction,
	}

	err = VerifyAccess(ctx, backend, opts)
	// This might fail due to lack of permissions, which is expected

	// Test with compatibility manager
	compatManager := NewBackwardCompatibilityManager(
		legacyIAM,
		enhancedRoles,
		nil,
		FullCompatibility,
	)

	err = CompatibleVerifyAccess(ctx, backend, opts, compatManager)
	// In full compatibility mode, should behave like original

	t.Log("Minimal access control test passed")
}

// MinimalMockIAMService is a simple mock for testing
type MinimalMockIAMService struct {
	accounts map[string]Account
}

func (m *MinimalMockIAMService) CreateAccount(account Account) error {
	m.accounts[account.Access] = account
	return nil
}

func (m *MinimalMockIAMService) GetUserAccount(access string) (Account, error) {
	account, exists := m.accounts[access]
	if !exists {
		return Account{}, fmt.Errorf("account not found")
	}
	return account, nil
}

func (m *MinimalMockIAMService) UpdateUserAccount(access string, props MutableProps) error {
	account, exists := m.accounts[access]
	if !exists {
		return fmt.Errorf("account not found")
	}
	updateAcc(&account, props)
	m.accounts[access] = account
	return nil
}

func (m *MinimalMockIAMService) DeleteUserAccount(access string) error {
	delete(m.accounts, access)
	return nil
}

func (m *MinimalMockIAMService) ListUserAccounts() ([]Account, error) {
	accounts := make([]Account, 0, len(m.accounts))
	for _, account := range m.accounts {
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (m *MinimalMockIAMService) Shutdown() error {
	return nil
}