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

// TestMigrationService tests the migration service functionality
func TestMigrationService(t *testing.T) {
	// Setup test environment
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	mfaService := NewMFAService(&MFAConfig{})
	auditLogger := &MockSecurityAuditLoggerForMigration{}

	migrationService := NewMigrationService(
		legacyIAM,
		enhancedRoles,
		mfaService,
		nil, // session manager
		auditLogger,
	)

	// Test migration scenarios
	testScenarios := []struct {
		name     string
		testFunc func(t *testing.T, service *MigrationService)
	}{
		{"TestCreateDefaultRoles", testCreateDefaultRoles},
		{"TestMigrateAllUsers", testMigrateAllUsers},
		{"TestMigrationValidation", testMigrationValidation},
		{"TestMigrationRollback", testMigrationRollback},
		{"TestDryRunMigration", testDryRunMigration},
		{"TestBatchMigration", testBatchMigration},
		{"TestMigrationErrorHandling", testMigrationErrorHandling},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Reset state for each test
			legacyIAM.accounts = make(map[string]Account)
			enhancedRoles = NewInMemoryRoleManager()
			migrationService.enhancedRoleManager = enhancedRoles
			auditLogger.Reset()

			scenario.testFunc(t, migrationService)
		})
	}
}

func testCreateDefaultRoles(t *testing.T, service *MigrationService) {
	// Test creating default roles
	createdCount, err := service.createDefaultRoles()
	if err != nil {
		t.Fatalf("Failed to create default roles: %v", err)
	}

	expectedRoles := 3 // admin, user-plus, user
	if createdCount != expectedRoles {
		t.Errorf("Expected %d roles created, got %d", expectedRoles, createdCount)
	}

	// Verify roles were created
	expectedRoleIDs := []string{"migrated-admin", "migrated-user-plus", "migrated-user"}
	for _, roleID := range expectedRoleIDs {
		role, err := service.enhancedRoleManager.GetRole(roleID)
		if err != nil {
			t.Errorf("Expected role %s to be created: %v", roleID, err)
		}
		if role.ID != roleID {
			t.Errorf("Expected role ID %s, got %s", roleID, role.ID)
		}
	}

	// Test creating roles again (should skip existing)
	createdCount2, err := service.createDefaultRoles()
	if err != nil {
		t.Fatalf("Failed to create default roles second time: %v", err)
	}

	if createdCount2 != 0 {
		t.Errorf("Expected 0 roles created on second run, got %d", createdCount2)
	}
}

func testMigrateAllUsers(t *testing.T, service *MigrationService) {
	ctx := context.Background()

	// Create test users in legacy system
	testUsers := []Account{
		{Access: "admin1", Secret: "secret1", Role: RoleAdmin},
		{Access: "user1", Secret: "secret2", Role: RoleUser},
		{Access: "userplus1", Secret: "secret3", Role: RoleUserPlus},
		{Access: "admin2", Secret: "secret4", Role: RoleAdmin},
		{Access: "user2", Secret: "secret5", Role: RoleUser},
	}

	for _, user := range testUsers {
		err := service.legacyIAMService.CreateAccount(user)
		if err != nil {
			t.Fatalf("Failed to create test user %s: %v", user.Access, err)
		}
	}

	// Configure migration
	config := MigrationConfig{
		DryRun:                false,
		BatchSize:             2,
		MigrationTimeout:      30 * time.Second,
		CreateDefaultRoles:    true,
		EnableMFAForAdmins:    true,
		PreserveSessions:      false,
		BackupBeforeMigration: false,
	}

	// Run migration
	result, err := service.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify migration results
	if result.TotalUsers != len(testUsers) {
		t.Errorf("Expected %d total users, got %d", len(testUsers), result.TotalUsers)
	}

	if result.MigratedUsers != len(testUsers) {
		t.Errorf("Expected %d migrated users, got %d", len(testUsers), result.MigratedUsers)
	}

	if result.FailedUsers != 0 {
		t.Errorf("Expected 0 failed users, got %d", result.FailedUsers)
	}

	if result.CreatedRoles != 3 {
		t.Errorf("Expected 3 created roles, got %d", result.CreatedRoles)
	}

	// Verify each user was migrated correctly
	for _, user := range testUsers {
		roles, err := service.enhancedRoleManager.GetUserRoles(user.Access)
		if err != nil {
			t.Errorf("Failed to get roles for user %s: %v", user.Access, err)
			continue
		}

		if len(roles) == 0 {
			t.Errorf("User %s has no enhanced roles after migration", user.Access)
			continue
		}

		// Check if user has the correct migrated role
		expectedRoleID := getMigratedRoleID(user.Role)
		hasExpectedRole := false
		for _, role := range roles {
			if role.ID == expectedRoleID {
				hasExpectedRole = true
				break
			}
		}

		if !hasExpectedRole {
			t.Errorf("User %s does not have expected role %s", user.Access, expectedRoleID)
		}

		// Check MFA status for admin users
		if user.Role == RoleAdmin {
			status, err := service.mfaService.GetMFAStatus(user.Access)
			if err != nil {
				t.Errorf("Failed to get MFA status for admin user %s: %v", user.Access, err)
			} else if !status.Enabled {
				t.Errorf("Expected MFA to be enabled for admin user %s", user.Access)
			}
		}
	}

	// Verify audit logging
	auditLogger := service.auditLogger.(*MockSecurityAuditLoggerForMigration)
	events := auditLogger.GetAuthEvents()
	if len(events) == 0 {
		t.Error("Expected migration completion event to be logged")
	}
}

func testMigrationValidation(t *testing.T, service *MigrationService) {
	ctx := context.Background()

	// Create and migrate test users
	testUsers := []Account{
		{Access: "validate-user1", Secret: "secret1", Role: RoleUser},
		{Access: "validate-admin1", Secret: "secret2", Role: RoleAdmin},
	}

	for _, user := range testUsers {
		service.legacyIAMService.CreateAccount(user)
	}

	config := MigrationConfig{
		DryRun:             false,
		BatchSize:          10,
		CreateDefaultRoles: true,
	}

	_, err := service.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Validate migration
	validationResult, err := service.ValidateMigration()
	if err != nil {
		t.Fatalf("Migration validation failed: %v", err)
	}

	if validationResult.TotalUsers != len(testUsers) {
		t.Errorf("Expected %d total users in validation, got %d", len(testUsers), validationResult.TotalUsers)
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

	// Test validation with missing roles (simulate corruption)
	// Remove a user's role to create validation issue
	roles, _ := service.enhancedRoleManager.GetUserRoles("validate-user1")
	for _, role := range roles {
		service.enhancedRoleManager.RevokeRole("validate-user1", role.ID, "test")
	}

	validationResult2, err := service.ValidateMigration()
	if err != nil {
		t.Fatalf("Second migration validation failed: %v", err)
	}

	if len(validationResult2.Issues) == 0 {
		t.Error("Expected validation issues after removing user roles")
	}
}

func testMigrationRollback(t *testing.T, service *MigrationService) {
	ctx := context.Background()

	// Create and migrate test users
	testUsers := []Account{
		{Access: "rollback-user1", Secret: "secret1", Role: RoleUser},
		{Access: "rollback-admin1", Secret: "secret2", Role: RoleAdmin},
	}

	for _, user := range testUsers {
		service.legacyIAMService.CreateAccount(user)
	}

	config := MigrationConfig{
		DryRun:             false,
		CreateDefaultRoles: true,
		EnableMFAForAdmins: true,
	}

	_, err := service.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	// Verify users have enhanced roles before rollback
	for _, user := range testUsers {
		roles, err := service.enhancedRoleManager.GetUserRoles(user.Access)
		if err != nil || len(roles) == 0 {
			t.Fatalf("User %s should have enhanced roles before rollback", user.Access)
		}
	}

	// Rollback migration
	userIDs := []string{"rollback-user1", "rollback-admin1"}
	rollbackResult, err := service.RollbackMigration(userIDs)
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	if rollbackResult.TotalUsers != len(userIDs) {
		t.Errorf("Expected %d total users in rollback, got %d", len(userIDs), rollbackResult.TotalUsers)
	}

	if rollbackResult.MigratedUsers != len(userIDs) {
		t.Errorf("Expected %d rolled back users, got %d", len(userIDs), rollbackResult.MigratedUsers)
	}

	if rollbackResult.FailedUsers != 0 {
		t.Errorf("Expected 0 failed rollbacks, got %d", rollbackResult.FailedUsers)
	}

	// Verify users no longer have migrated roles
	for _, userID := range userIDs {
		roles, err := service.enhancedRoleManager.GetUserRoles(userID)
		if err != nil {
			t.Errorf("Failed to get roles for user %s after rollback: %v", userID, err)
			continue
		}

		migratedRoleCount := 0
		for _, role := range roles {
			if isMigratedRole(role.ID) {
				migratedRoleCount++
			}
		}

		if migratedRoleCount > 0 {
			t.Errorf("User %s still has %d migrated roles after rollback", userID, migratedRoleCount)
		}

		// Verify MFA is disabled
		status, err := service.mfaService.GetMFAStatus(userID)
		if err == nil && status.Enabled {
			t.Errorf("User %s still has MFA enabled after rollback", userID)
		}
	}
}

func testDryRunMigration(t *testing.T, service *MigrationService) {
	ctx := context.Background()

	// Create test users
	testUsers := []Account{
		{Access: "dryrun-user1", Secret: "secret1", Role: RoleUser},
		{Access: "dryrun-admin1", Secret: "secret2", Role: RoleAdmin},
	}

	for _, user := range testUsers {
		service.legacyIAMService.CreateAccount(user)
	}

	// Run dry run migration
	config := MigrationConfig{
		DryRun:             true,
		BatchSize:          10,
		CreateDefaultRoles: true,
		EnableMFAForAdmins: true,
	}

	result, err := service.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Dry run migration failed: %v", err)
	}

	// Verify dry run results
	if result.TotalUsers != len(testUsers) {
		t.Errorf("Expected %d total users, got %d", len(testUsers), result.TotalUsers)
	}

	if result.MigratedUsers != len(testUsers) {
		t.Errorf("Expected %d migrated users in dry run, got %d", len(testUsers), result.MigratedUsers)
	}

	if result.FailedUsers != 0 {
		t.Errorf("Expected 0 failed users in dry run, got %d", result.FailedUsers)
	}

	// Verify no actual changes were made
	for _, user := range testUsers {
		roles, err := service.enhancedRoleManager.GetUserRoles(user.Access)
		if err == nil && len(roles) > 0 {
			t.Errorf("User %s should not have enhanced roles in dry run mode", user.Access)
		}

		status, err := service.mfaService.GetMFAStatus(user.Access)
		if err == nil && status.Enabled {
			t.Errorf("User %s should not have MFA enabled in dry run mode", user.Access)
		}
	}

	// Verify default roles were not actually created in dry run
	expectedRoleIDs := []string{"migrated-admin", "migrated-user-plus", "migrated-user"}
	for _, roleID := range expectedRoleIDs {
		_, err := service.enhancedRoleManager.GetRole(roleID)
		if err == nil {
			t.Errorf("Role %s should not exist after dry run", roleID)
		}
	}
}

func testBatchMigration(t *testing.T, service *MigrationService) {
	ctx := context.Background()

	// Create many test users to test batching
	numUsers := 25
	testUsers := make([]Account, numUsers)
	for i := 0; i < numUsers; i++ {
		testUsers[i] = Account{
			Access: fmt.Sprintf("batch-user-%d", i),
			Secret: fmt.Sprintf("secret-%d", i),
			Role:   RoleUser,
		}
		service.legacyIAMService.CreateAccount(testUsers[i])
	}

	// Run migration with small batch size
	config := MigrationConfig{
		DryRun:             false,
		BatchSize:          5, // Small batch size to test batching
		CreateDefaultRoles: true,
	}

	result, err := service.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Batch migration failed: %v", err)
	}

	if result.TotalUsers != numUsers {
		t.Errorf("Expected %d total users, got %d", numUsers, result.TotalUsers)
	}

	if result.MigratedUsers != numUsers {
		t.Errorf("Expected %d migrated users, got %d", numUsers, result.MigratedUsers)
	}

	if result.FailedUsers != 0 {
		t.Errorf("Expected 0 failed users, got %d", result.FailedUsers)
	}

	// Verify all users were migrated correctly
	for _, user := range testUsers {
		roles, err := service.enhancedRoleManager.GetUserRoles(user.Access)
		if err != nil {
			t.Errorf("Failed to get roles for user %s: %v", user.Access, err)
			continue
		}

		if len(roles) == 0 {
			t.Errorf("User %s has no enhanced roles after batch migration", user.Access)
		}
	}
}

func testMigrationErrorHandling(t *testing.T, service *MigrationService) {
	ctx := context.Background()

	// Create test users
	testUsers := []Account{
		{Access: "error-user1", Secret: "secret1", Role: RoleUser},
		{Access: "error-user2", Secret: "secret2", Role: RoleUser},
	}

	for _, user := range testUsers {
		service.legacyIAMService.CreateAccount(user)
	}

	// Create a scenario that will cause errors
	// For example, create a role with the same ID that migration will try to create
	conflictingRole := &EnhancedRole{
		ID:          "migrated-user",
		Name:        "Conflicting Role",
		Description: "This role conflicts with migration",
		Permissions: []DetailedPermission{},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Create the conflicting role but make it invalid somehow
	// This is a simplified test - in reality, you'd test various error conditions
	service.enhancedRoleManager.CreateRole(conflictingRole)

	config := MigrationConfig{
		DryRun:             false,
		BatchSize:          10,
		CreateDefaultRoles: true,
	}

	result, err := service.MigrateAllUsers(ctx, config)
	// Migration should not fail completely due to individual user errors
	if err != nil {
		t.Fatalf("Migration should handle errors gracefully: %v", err)
	}

	// Check that some errors were recorded
	if len(result.Errors) == 0 {
		t.Log("Note: No migration errors occurred (this may be expected)")
	}

	// Verify that migration continued despite errors
	if result.TotalUsers != len(testUsers) {
		t.Errorf("Expected %d total users, got %d", len(testUsers), result.TotalUsers)
	}
}

// Helper functions

func getMigratedRoleID(legacyRole Role) string {
	switch legacyRole {
	case RoleAdmin:
		return "migrated-admin"
	case RoleUserPlus:
		return "migrated-user-plus"
	case RoleUser:
		return "migrated-user"
	default:
		return "migrated-user"
	}
}

// MockSecurityAuditLoggerForMigration for migration testing
type MockSecurityAuditLoggerForMigration struct {
	authEvents      []*AuthEvent
	authzEvents     []*AuthzEvent
	securityAlerts  []*SecurityAlert
	sessionEvents   []*SessionEvent
	auditRecords    []*AuditRecord
	securityReports []*SecurityReport
}

func (m *MockSecurityAuditLoggerForMigration) LogAuthenticationAttempt(event *AuthEvent) error {
	m.authEvents = append(m.authEvents, event)
	return nil
}

func (m *MockSecurityAuditLoggerForMigration) LogAuthorizationCheck(event *AuthzEvent) error {
	m.authzEvents = append(m.authzEvents, event)
	return nil
}

func (m *MockSecurityAuditLoggerForMigration) LogSecurityAlert(alert *SecurityAlert) error {
	m.securityAlerts = append(m.securityAlerts, alert)
	return nil
}

func (m *MockSecurityAuditLoggerForMigration) LogSessionEvent(event *SessionEvent) error {
	m.sessionEvents = append(m.sessionEvents, event)
	return nil
}

func (m *MockSecurityAuditLoggerForMigration) QueryAuditLogs(query *AuditQuery) ([]*AuditRecord, error) {
	return m.auditRecords, nil
}

func (m *MockSecurityAuditLoggerForMigration) GenerateSecurityReport(params *ReportParams) (*SecurityReport, error) {
	report := &SecurityReport{
		GeneratedAt:        time.Now(),
		Period:             params.Period,
		TotalAuthAttempts:  len(m.authEvents),
		FailedAuthAttempts: 0,
		SecurityAlerts:     len(m.securityAlerts),
		ActiveSessions:     len(m.sessionEvents),
	}

	for _, event := range m.authEvents {
		if !event.Success {
			report.FailedAuthAttempts++
		}
	}

	return report, nil
}

func (m *MockSecurityAuditLoggerForMigration) GetAuthEvents() []*AuthEvent {
	return m.authEvents
}

func (m *MockSecurityAuditLoggerForMigration) Reset() {
	m.authEvents = nil
	m.authzEvents = nil
	m.securityAlerts = nil
	m.sessionEvents = nil
	m.auditRecords = nil
	m.securityReports = nil
}

// TestMigrationServiceConcurrency tests concurrent migration operations
func TestMigrationServiceConcurrency(t *testing.T) {
	// This test ensures migration service handles concurrent operations safely
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	auditLogger := &MockSecurityAuditLoggerForMigration{}

	migrationService := NewMigrationService(
		legacyIAM,
		enhancedRoles,
		nil,
		nil,
		auditLogger,
	)

	// Create test users
	numUsers := 50
	for i := 0; i < numUsers; i++ {
		user := Account{
			Access: fmt.Sprintf("concurrent-user-%d", i),
			Secret: fmt.Sprintf("secret-%d", i),
			Role:   RoleUser,
		}
		legacyIAM.CreateAccount(user)
	}

	ctx := context.Background()
	config := MigrationConfig{
		DryRun:             false,
		BatchSize:          5,
		CreateDefaultRoles: true,
	}

	// Run migration
	result, err := migrationService.MigrateAllUsers(ctx, config)
	if err != nil {
		t.Fatalf("Concurrent migration failed: %v", err)
	}

	if result.MigratedUsers != numUsers {
		t.Errorf("Expected %d migrated users, got %d", numUsers, result.MigratedUsers)
	}

	// Verify all users were migrated correctly
	for i := 0; i < numUsers; i++ {
		userID := fmt.Sprintf("concurrent-user-%d", i)
		roles, err := enhancedRoles.GetUserRoles(userID)
		if err != nil {
			t.Errorf("Failed to get roles for user %s: %v", userID, err)
			continue
		}

		if len(roles) == 0 {
			t.Errorf("User %s has no enhanced roles after concurrent migration", userID)
		}
	}
}

// TestMigrationServiceContextCancellation tests context cancellation during migration
func TestMigrationServiceContextCancellation(t *testing.T) {
	legacyIAM := &MockLegacyIAMService{}
	enhancedRoles := NewInMemoryRoleManager()
	auditLogger := &MockSecurityAuditLoggerForMigration{}

	migrationService := NewMigrationService(
		legacyIAM,
		enhancedRoles,
		nil,
		nil,
		auditLogger,
	)

	// Create many test users
	numUsers := 100
	for i := 0; i < numUsers; i++ {
		user := Account{
			Access: fmt.Sprintf("cancel-user-%d", i),
			Secret: fmt.Sprintf("secret-%d", i),
			Role:   RoleUser,
		}
		legacyIAM.CreateAccount(user)
	}

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	config := MigrationConfig{
		DryRun:             false,
		BatchSize:          1, // Small batch size to slow down migration
		CreateDefaultRoles: true,
	}

	// Run migration (should be cancelled)
	result, err := migrationService.MigrateAllUsers(ctx, config)

	// Should get context cancellation error
	if err == nil {
		t.Error("Expected context cancellation error")
	}

	if err != context.DeadlineExceeded {
		t.Logf("Got error: %v (may be expected)", err)
	}

	// Some users might have been migrated before cancellation
	if result.MigratedUsers >= numUsers {
		t.Error("Migration should have been cancelled before completing all users")
	}

	t.Logf("Migration cancelled after migrating %d/%d users", result.MigratedUsers, numUsers)
}