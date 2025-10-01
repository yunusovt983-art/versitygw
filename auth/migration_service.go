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
	"log"
	"time"
)

// MigrationService handles migration of existing user data to enhanced auth system
type MigrationService struct {
	legacyIAMService    IAMService
	enhancedRoleManager EnhancedRoleManager
	mfaService          MFAService
	sessionManager      SessionManager
	auditLogger         SecurityAuditLogger
	logger              *log.Logger
	dryRun              bool
}

// MigrationConfig configures the migration process
type MigrationConfig struct {
	DryRun                bool
	BatchSize             int
	MigrationTimeout      time.Duration
	CreateDefaultRoles    bool
	EnableMFAForAdmins    bool
	PreserveSessions      bool
	BackupBeforeMigration bool
}

// MigrationResult contains the results of a migration operation
type MigrationResult struct {
	TotalUsers          int
	MigratedUsers       int
	FailedUsers         int
	CreatedRoles        int
	MigratedSessions    int
	Errors              []MigrationError
	StartTime           time.Time
	EndTime             time.Time
	Duration            time.Duration
}

// MigrationError represents an error during migration
type MigrationError struct {
	UserID      string
	Operation   string
	Error       error
	Timestamp   time.Time
	Recoverable bool
}

// MigrationStatus represents the current status of migration
type MigrationStatus struct {
	InProgress      bool
	CurrentUser     string
	ProcessedUsers  int
	TotalUsers      int
	StartTime       time.Time
	EstimatedEnd    time.Time
	LastError       *MigrationError
}

// NewMigrationService creates a new migration service
func NewMigrationService(
	legacyIAM IAMService,
	enhancedRoles EnhancedRoleManager,
	mfa MFAService,
	sessions SessionManager,
	audit SecurityAuditLogger,
) *MigrationService {
	return &MigrationService{
		legacyIAMService:    legacyIAM,
		enhancedRoleManager: enhancedRoles,
		mfaService:          mfa,
		sessionManager:      sessions,
		auditLogger:         audit,
		logger:              log.New(log.Writer(), "[Migration] ", log.LstdFlags),
		dryRun:              false,
	}
}

// MigrateAllUsers migrates all users from legacy system to enhanced system
func (m *MigrationService) MigrateAllUsers(ctx context.Context, config MigrationConfig) (*MigrationResult, error) {
	m.dryRun = config.DryRun
	
	result := &MigrationResult{
		StartTime: time.Now(),
		Errors:    make([]MigrationError, 0),
	}

	m.logger.Printf("Starting user migration (dry run: %v)", m.dryRun)

	// Get all legacy users
	accounts, err := m.legacyIAMService.ListUserAccounts()
	if err != nil {
		return result, fmt.Errorf("failed to list legacy accounts: %v", err)
	}

	result.TotalUsers = len(accounts)
	m.logger.Printf("Found %d users to migrate", result.TotalUsers)

	// Create default roles if requested
	if config.CreateDefaultRoles {
		createdRoles, err := m.createDefaultRoles()
		if err != nil {
			m.logger.Printf("Warning: Failed to create default roles: %v", err)
		} else {
			result.CreatedRoles = createdRoles
		}
	}

	// Migrate users in batches
	batchSize := config.BatchSize
	if batchSize <= 0 {
		batchSize = 10 // Default batch size
	}

	for i := 0; i < len(accounts); i += batchSize {
		end := i + batchSize
		if end > len(accounts) {
			end = len(accounts)
		}

		batch := accounts[i:end]
		m.logger.Printf("Processing batch %d-%d of %d users", i+1, end, len(accounts))

		for _, account := range batch {
			select {
			case <-ctx.Done():
				m.logger.Printf("Migration cancelled by context")
				result.EndTime = time.Now()
				result.Duration = result.EndTime.Sub(result.StartTime)
				return result, ctx.Err()
			default:
			}

			if err := m.migrateUser(account, config); err != nil {
				result.FailedUsers++
				migrationErr := MigrationError{
					UserID:      account.Access,
					Operation:   "migrate_user",
					Error:       err,
					Timestamp:   time.Now(),
					Recoverable: true,
				}
				result.Errors = append(result.Errors, migrationErr)
				m.logger.Printf("Failed to migrate user %s: %v", account.Access, err)
			} else {
				result.MigratedUsers++
				m.logger.Printf("Successfully migrated user %s", account.Access)
			}
		}

		// Small delay between batches to avoid overwhelming the system
		time.Sleep(100 * time.Millisecond)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	m.logger.Printf("Migration completed: %d/%d users migrated, %d failed, duration: %v",
		result.MigratedUsers, result.TotalUsers, result.FailedUsers, result.Duration)

	// Log migration completion
	if m.auditLogger != nil {
		migrationEvent := &AuthEvent{
			UserID:    "system",
			Action:    "migration_completed",
			Success:   result.FailedUsers == 0,
			IPAddress: "localhost",
			UserAgent: "MigrationService",
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"total_users":    result.TotalUsers,
				"migrated_users": result.MigratedUsers,
				"failed_users":   result.FailedUsers,
				"duration":       result.Duration.String(),
				"dry_run":        m.dryRun,
			},
		}
		m.auditLogger.LogAuthenticationAttempt(migrationEvent)
	}

	return result, nil
}

// migrateUser migrates a single user to the enhanced system
func (m *MigrationService) migrateUser(account Account, config MigrationConfig) error {
	m.logger.Printf("Migrating user: %s (role: %s)", account.Access, account.Role)

	if m.dryRun {
		m.logger.Printf("DRY RUN: Would migrate user %s", account.Access)
		return nil
	}

	// 1. Create enhanced role mapping
	if err := m.createEnhancedRoleMapping(account); err != nil {
		return fmt.Errorf("failed to create enhanced role mapping: %v", err)
	}

	// 2. Set up MFA for admin users if requested
	if config.EnableMFAForAdmins && account.Role == RoleAdmin {
		if err := m.setupMFAForUser(account.Access); err != nil {
			m.logger.Printf("Warning: Failed to setup MFA for admin user %s: %v", account.Access, err)
			// Don't fail migration for MFA setup failure
		}
	}

	// 3. Migrate existing sessions if requested
	if config.PreserveSessions {
		if err := m.migrateSessions(account.Access); err != nil {
			m.logger.Printf("Warning: Failed to migrate sessions for user %s: %v", account.Access, err)
			// Don't fail migration for session migration failure
		}
	}

	return nil
}

// createEnhancedRoleMapping creates enhanced role mapping for legacy user
func (m *MigrationService) createEnhancedRoleMapping(account Account) error {
	// Determine enhanced role based on legacy role
	var enhancedRoleID string
	switch account.Role {
	case RoleAdmin:
		enhancedRoleID = "migrated-admin"
	case RoleUserPlus:
		enhancedRoleID = "migrated-user-plus"
	case RoleUser:
		enhancedRoleID = "migrated-user"
	default:
		enhancedRoleID = "migrated-user" // Default to user role
	}

	// Ensure the role exists
	if err := m.ensureMigratedRoleExists(enhancedRoleID, account.Role); err != nil {
		return fmt.Errorf("failed to ensure migrated role exists: %v", err)
	}

	// Assign role to user
	if err := m.enhancedRoleManager.AssignRole(account.Access, enhancedRoleID, "migration"); err != nil {
		return fmt.Errorf("failed to assign enhanced role: %v", err)
	}

	return nil
}

// ensureMigratedRoleExists creates migrated role if it doesn't exist
func (m *MigrationService) ensureMigratedRoleExists(roleID string, legacyRole Role) error {
	// Check if role already exists
	_, err := m.enhancedRoleManager.GetRole(roleID)
	if err == nil {
		return nil // Role already exists
	}

	// Create the role
	role := &EnhancedRole{
		ID:          roleID,
		Name:        fmt.Sprintf("Migrated %s Role", string(legacyRole)),
		Description: fmt.Sprintf("Migrated from legacy %s role", string(legacyRole)),
		Permissions: m.getMigratedRolePermissions(legacyRole),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return m.enhancedRoleManager.CreateRole(role)
}

// getMigratedRolePermissions returns permissions for migrated roles
func (m *MigrationService) getMigratedRolePermissions(legacyRole Role) []DetailedPermission {
	switch legacyRole {
	case RoleAdmin:
		return []DetailedPermission{
			{
				Resource: "arn:aws:s3:::*",
				Action:   "*",
				Effect:   PermissionAllow,
				Conditions: map[string]interface{}{
					"migrated_from": "admin",
					"migration_date": time.Now().Format(time.RFC3339),
				},
			},
		}
	case RoleUserPlus:
		return []DetailedPermission{
			{
				Resource: "arn:aws:s3:::*/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
				Conditions: map[string]interface{}{
					"migrated_from": "userplus",
				},
			},
			{
				Resource: "arn:aws:s3:::*/*",
				Action:   "s3:PutObject",
				Effect:   PermissionAllow,
				Conditions: map[string]interface{}{
					"migrated_from": "userplus",
				},
			},
			{
				Resource: "arn:aws:s3:::*/*",
				Action:   "s3:DeleteObject",
				Effect:   PermissionAllow,
				Conditions: map[string]interface{}{
					"migrated_from": "userplus",
				},
			},
			{
				Resource: "arn:aws:s3:::*",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
				Conditions: map[string]interface{}{
					"migrated_from": "userplus",
				},
			},
		}
	case RoleUser:
		return []DetailedPermission{
			{
				Resource: "arn:aws:s3:::*/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
				Conditions: map[string]interface{}{
					"migrated_from": "user",
				},
			},
			{
				Resource: "arn:aws:s3:::*",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
				Conditions: map[string]interface{}{
					"migrated_from": "user",
				},
			},
		}
	default:
		return []DetailedPermission{}
	}
}

// setupMFAForUser sets up MFA for a user during migration
func (m *MigrationService) setupMFAForUser(userID string) error {
	if m.mfaService == nil {
		return fmt.Errorf("MFA service not available")
	}

	// Generate MFA secret
	secret, err := m.mfaService.GenerateSecret(userID)
	if err != nil {
		return fmt.Errorf("failed to generate MFA secret: %v", err)
	}

	// Enable MFA (user will need to complete setup manually)
	if err := m.mfaService.EnableMFA(userID, secret); err != nil {
		return fmt.Errorf("failed to enable MFA: %v", err)
	}

	m.logger.Printf("MFA enabled for user %s (manual setup required)", userID)
	return nil
}

// migrateSessions migrates existing sessions for a user
func (m *MigrationService) migrateSessions(userID string) error {
	if m.sessionManager == nil {
		return fmt.Errorf("session manager not available")
	}

	// In a real implementation, you would:
	// 1. Get existing sessions from legacy system
	// 2. Create equivalent sessions in new system
	// 3. Maintain session continuity

	// For now, we'll create a placeholder session
	metadata := &SessionMetadata{
		IPAddress:   "migrated",
		UserAgent:   "MigrationService",
		LoginMethod: "migration",
	}

	_, err := m.sessionManager.CreateSession(userID, metadata)
	if err != nil {
		return fmt.Errorf("failed to create migrated session: %v", err)
	}

	return nil
}

// createDefaultRoles creates default roles for the enhanced system
func (m *MigrationService) createDefaultRoles() (int, error) {
	defaultRoles := []*EnhancedRole{
		{
			ID:          "migrated-admin",
			Name:        "Migrated Administrator",
			Description: "Full administrative access (migrated from legacy admin role)",
			Permissions: []DetailedPermission{
				{
					Resource: "arn:aws:s3:::*",
					Action:   "*",
					Effect:   PermissionAllow,
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "migrated-user-plus",
			Name:        "Migrated User Plus",
			Description: "Enhanced user access (migrated from legacy userplus role)",
			Permissions: []DetailedPermission{
				{
					Resource: "arn:aws:s3:::*/*",
					Action:   "s3:GetObject",
					Effect:   PermissionAllow,
				},
				{
					Resource: "arn:aws:s3:::*/*",
					Action:   "s3:PutObject",
					Effect:   PermissionAllow,
				},
				{
					Resource: "arn:aws:s3:::*/*",
					Action:   "s3:DeleteObject",
					Effect:   PermissionAllow,
				},
				{
					Resource: "arn:aws:s3:::*",
					Action:   "s3:ListBucket",
					Effect:   PermissionAllow,
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "migrated-user",
			Name:        "Migrated User",
			Description: "Basic user access (migrated from legacy user role)",
			Permissions: []DetailedPermission{
				{
					Resource: "arn:aws:s3:::*/*",
					Action:   "s3:GetObject",
					Effect:   PermissionAllow,
				},
				{
					Resource: "arn:aws:s3:::*",
					Action:   "s3:ListBucket",
					Effect:   PermissionAllow,
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	createdCount := 0
	for _, role := range defaultRoles {
		// Check if role already exists
		_, err := m.enhancedRoleManager.GetRole(role.ID)
		if err == nil {
			m.logger.Printf("Role %s already exists, skipping", role.ID)
			continue
		}

		if m.dryRun {
			m.logger.Printf("DRY RUN: Would create role %s", role.ID)
			createdCount++
			continue
		}

		if err := m.enhancedRoleManager.CreateRole(role); err != nil {
			m.logger.Printf("Warning: Failed to create default role %s: %v", role.ID, err)
		} else {
			m.logger.Printf("Created default role: %s", role.ID)
			createdCount++
		}
	}

	return createdCount, nil
}

// ValidateMigration validates that migration was successful
func (m *MigrationService) ValidateMigration() (*MigrationValidationResult, error) {
	result := &MigrationValidationResult{
		StartTime: time.Now(),
		Issues:    make([]ValidationIssue, 0),
	}

	// Get all legacy users
	legacyAccounts, err := m.legacyIAMService.ListUserAccounts()
	if err != nil {
		return result, fmt.Errorf("failed to list legacy accounts: %v", err)
	}

	result.TotalUsers = len(legacyAccounts)

	// Validate each user
	for _, account := range legacyAccounts {
		if err := m.validateUserMigration(account, result); err != nil {
			m.logger.Printf("Validation failed for user %s: %v", account.Access, err)
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.ValidUsers = result.TotalUsers - len(result.Issues)

	return result, nil
}

// validateUserMigration validates migration for a single user
func (m *MigrationService) validateUserMigration(account Account, result *MigrationValidationResult) error {
	// Check if user has enhanced roles
	roles, err := m.enhancedRoleManager.GetUserRoles(account.Access)
	if err != nil {
		issue := ValidationIssue{
			UserID:      account.Access,
			Type:        "missing_enhanced_roles",
			Description: fmt.Sprintf("User has no enhanced roles: %v", err),
			Severity:    "high",
		}
		result.Issues = append(result.Issues, issue)
		return err
	}

	if len(roles) == 0 {
		issue := ValidationIssue{
			UserID:      account.Access,
			Type:        "no_roles_assigned",
			Description: "User has no enhanced roles assigned",
			Severity:    "high",
		}
		result.Issues = append(result.Issues, issue)
	}

	// Validate role permissions match legacy role
	expectedRoleID := fmt.Sprintf("migrated-%s", string(account.Role))
	if account.Role == RoleUserPlus {
		expectedRoleID = "migrated-user-plus"
	}

	hasExpectedRole := false
	for _, role := range roles {
		if role.ID == expectedRoleID {
			hasExpectedRole = true
			break
		}
	}

	if !hasExpectedRole {
		issue := ValidationIssue{
			UserID:      account.Access,
			Type:        "incorrect_role_mapping",
			Description: fmt.Sprintf("User does not have expected role %s", expectedRoleID),
			Severity:    "medium",
		}
		result.Issues = append(result.Issues, issue)
	}

	return nil
}

// MigrationValidationResult contains validation results
type MigrationValidationResult struct {
	TotalUsers int
	ValidUsers int
	Issues     []ValidationIssue
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
}

// ValidationIssue represents a validation issue
type ValidationIssue struct {
	UserID      string
	Type        string
	Description string
	Severity    string
}

// RollbackMigration rolls back migration for specified users
func (m *MigrationService) RollbackMigration(userIDs []string) (*MigrationResult, error) {
	result := &MigrationResult{
		StartTime: time.Now(),
		Errors:    make([]MigrationError, 0),
	}

	result.TotalUsers = len(userIDs)
	m.logger.Printf("Starting migration rollback for %d users", result.TotalUsers)

	for _, userID := range userIDs {
		if err := m.rollbackUser(userID); err != nil {
			result.FailedUsers++
			migrationErr := MigrationError{
				UserID:      userID,
				Operation:   "rollback_user",
				Error:       err,
				Timestamp:   time.Now(),
				Recoverable: true,
			}
			result.Errors = append(result.Errors, migrationErr)
			m.logger.Printf("Failed to rollback user %s: %v", userID, err)
		} else {
			result.MigratedUsers++
			m.logger.Printf("Successfully rolled back user %s", userID)
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result, nil
}

// rollbackUser rolls back migration for a single user
func (m *MigrationService) rollbackUser(userID string) error {
	// Remove enhanced roles
	roles, err := m.enhancedRoleManager.GetUserRoles(userID)
	if err != nil {
		return fmt.Errorf("failed to get user roles: %v", err)
	}

	for _, role := range roles {
		if isMigratedRole(role.ID) {
			if err := m.enhancedRoleManager.RevokeRole(userID, role.ID, "rollback"); err != nil {
				m.logger.Printf("Warning: Failed to revoke role %s from user %s: %v", role.ID, userID, err)
			}
		}
	}

	// Disable MFA if it was enabled during migration
	if m.mfaService != nil {
		status, err := m.mfaService.GetMFAStatus(userID)
		if err == nil && status.Enabled {
			if err := m.mfaService.DisableMFA(userID); err != nil {
				m.logger.Printf("Warning: Failed to disable MFA for user %s: %v", userID, err)
			}
		}
	}

	// Terminate migrated sessions
	if m.sessionManager != nil {
		if err := m.sessionManager.TerminateAllUserSessions(userID); err != nil {
			m.logger.Printf("Warning: Failed to terminate sessions for user %s: %v", userID, err)
		}
	}

	return nil
}

// isMigratedRole checks if a role ID represents a migrated role
func isMigratedRole(roleID string) bool {
	migratedRoles := []string{"migrated-admin", "migrated-user-plus", "migrated-user"}
	for _, migratedRole := range migratedRoles {
		if roleID == migratedRole {
			return true
		}
	}
	return false
}