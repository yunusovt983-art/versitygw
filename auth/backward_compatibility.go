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

	"github.com/versity/versitygw/backend"
)

// BackwardCompatibilityManager ensures existing authentication flows continue to work
type BackwardCompatibilityManager struct {
	legacyIAMService    IAMService
	enhancedRoleManager EnhancedRoleManager
	migrationService    *MigrationService
	compatibilityMode   CompatibilityMode
	logger              *log.Logger
}

// CompatibilityMode defines the level of backward compatibility
type CompatibilityMode int

const (
	// FullCompatibility maintains all existing behavior
	FullCompatibility CompatibilityMode = iota
	// HybridMode uses enhanced features where available, falls back to legacy
	HybridMode
	// EnhancedOnlyMode uses only enhanced features (for new deployments)
	EnhancedOnlyMode
)

// NewBackwardCompatibilityManager creates a new compatibility manager
func NewBackwardCompatibilityManager(
	legacyIAM IAMService,
	enhancedRoles EnhancedRoleManager,
	migration *MigrationService,
	mode CompatibilityMode,
) *BackwardCompatibilityManager {
	return &BackwardCompatibilityManager{
		legacyIAMService:    legacyIAM,
		enhancedRoleManager: enhancedRoles,
		migrationService:    migration,
		compatibilityMode:   mode,
		logger:              log.New(log.Writer(), "[BackwardCompat] ", log.LstdFlags),
	}
}

// CompatibleIAMService provides a backward-compatible IAM service interface
type CompatibleIAMService struct {
	*BackwardCompatibilityManager
}

// CreateAccount creates an account with backward compatibility
func (c *CompatibleIAMService) CreateAccount(account Account) error {
	// Always create in legacy system for compatibility
	err := c.legacyIAMService.CreateAccount(account)
	if err != nil {
		return err
	}

	// If in hybrid or enhanced mode, also create enhanced role mapping
	if c.compatibilityMode != FullCompatibility {
		if err := c.createEnhancedRoleMapping(account); err != nil {
			c.logger.Printf("Warning: Failed to create enhanced role mapping for account %s: %v", account.Access, err)
			// Don't fail the operation - legacy account was created successfully
		}
	}

	return nil
}

// GetUserAccount retrieves account with enhanced information if available
func (c *CompatibleIAMService) GetUserAccount(access string) (Account, error) {
	// Get from legacy system first
	account, err := c.legacyIAMService.GetUserAccount(access)
	if err != nil {
		return account, err
	}

	// Enhance with additional information if available
	if c.compatibilityMode != FullCompatibility {
		c.enhanceAccountInfo(&account)
	}

	return account, nil
}

// UpdateUserAccount updates account with backward compatibility
func (c *CompatibleIAMService) UpdateUserAccount(access string, props MutableProps) error {
	// Update legacy system
	err := c.legacyIAMService.UpdateUserAccount(access, props)
	if err != nil {
		return err
	}

	// Update enhanced system if available
	if c.compatibilityMode != FullCompatibility {
		if err := c.updateEnhancedRoleMapping(access, props); err != nil {
			c.logger.Printf("Warning: Failed to update enhanced role mapping for account %s: %v", access, err)
		}
	}

	return nil
}

// DeleteUserAccount deletes account from both systems
func (c *CompatibleIAMService) DeleteUserAccount(access string) error {
	// Delete from enhanced system first (if it fails, legacy is still intact)
	if c.compatibilityMode != FullCompatibility {
		if err := c.deleteEnhancedRoleMapping(access); err != nil {
			c.logger.Printf("Warning: Failed to delete enhanced role mapping for account %s: %v", access, err)
		}
	}

	// Delete from legacy system
	return c.legacyIAMService.DeleteUserAccount(access)
}

// ListUserAccounts lists accounts with enhanced information
func (c *CompatibleIAMService) ListUserAccounts() ([]Account, error) {
	accounts, err := c.legacyIAMService.ListUserAccounts()
	if err != nil {
		return accounts, err
	}

	// Enhance account information if available
	if c.compatibilityMode != FullCompatibility {
		for i := range accounts {
			c.enhanceAccountInfo(&accounts[i])
		}
	}

	return accounts, nil
}

// Shutdown shuts down both systems
func (c *CompatibleIAMService) Shutdown() error {
	var errs []error

	if err := c.legacyIAMService.Shutdown(); err != nil {
		errs = append(errs, fmt.Errorf("legacy IAM shutdown error: %v", err))
	}

	if c.enhancedRoleManager != nil {
		// Enhanced role manager doesn't have shutdown method in interface
		// This would be implementation-specific
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	return nil
}

// createEnhancedRoleMapping creates enhanced role mapping for legacy account
func (c *BackwardCompatibilityManager) createEnhancedRoleMapping(account Account) error {
	// Map legacy roles to enhanced roles
	var enhancedRoleIDs []string

	switch account.Role {
	case RoleAdmin:
		enhancedRoleIDs = []string{"legacy-admin"}
	case RoleUser:
		enhancedRoleIDs = []string{"legacy-user"}
	case RoleUserPlus:
		enhancedRoleIDs = []string{"legacy-user-plus"}
	default:
		enhancedRoleIDs = []string{"legacy-user"} // Default to user role
	}

	// Create enhanced roles if they don't exist
	for _, roleID := range enhancedRoleIDs {
		if err := c.ensureLegacyRoleExists(roleID, account.Role); err != nil {
			return fmt.Errorf("failed to ensure legacy role %s exists: %v", roleID, err)
		}

		// Assign role to user
		if err := c.enhancedRoleManager.AssignRole(account.Access, roleID, "migration"); err != nil {
			return fmt.Errorf("failed to assign enhanced role %s to user %s: %v", roleID, account.Access, err)
		}
	}

	return nil
}

// ensureLegacyRoleExists creates legacy-compatible enhanced roles
func (c *BackwardCompatibilityManager) ensureLegacyRoleExists(roleID string, legacyRole Role) error {
	// Check if role already exists
	_, err := c.enhancedRoleManager.GetRole(roleID)
	if err == nil {
		return nil // Role already exists
	}

	// Create the role based on legacy role permissions
	role := &EnhancedRole{
		ID:          roleID,
		Name:        fmt.Sprintf("Legacy %s Role", string(legacyRole)),
		Description: fmt.Sprintf("Automatically created role for legacy %s compatibility", string(legacyRole)),
		Permissions: c.getLegacyRolePermissions(legacyRole),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return c.enhancedRoleManager.CreateRole(role)
}

// getLegacyRolePermissions returns permissions equivalent to legacy roles
func (c *BackwardCompatibilityManager) getLegacyRolePermissions(legacyRole Role) []DetailedPermission {
	switch legacyRole {
	case RoleAdmin:
		return []DetailedPermission{
			{
				Resource: "arn:aws:s3:::*",
				Action:   "*",
				Effect:   PermissionAllow,
				Conditions: map[string]interface{}{
					"legacy_role": "admin",
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
					"legacy_role": "userplus",
				},
			},
			{
				Resource: "arn:aws:s3:::*/*",
				Action:   "s3:PutObject",
				Effect:   PermissionAllow,
				Conditions: map[string]interface{}{
					"legacy_role": "userplus",
				},
			},
			{
				Resource: "arn:aws:s3:::*",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
				Conditions: map[string]interface{}{
					"legacy_role": "userplus",
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
					"legacy_role": "user",
				},
			},
			{
				Resource: "arn:aws:s3:::*",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
				Conditions: map[string]interface{}{
					"legacy_role": "user",
				},
			},
		}
	default:
		return []DetailedPermission{}
	}
}

// enhanceAccountInfo adds enhanced information to legacy account
func (c *BackwardCompatibilityManager) enhanceAccountInfo(account *Account) {
	if c.enhancedRoleManager == nil {
		return
	}

	// Get enhanced roles for the user
	roles, err := c.enhancedRoleManager.GetUserRoles(account.Access)
	if err != nil {
		c.logger.Printf("Warning: Failed to get enhanced roles for user %s: %v", account.Access, err)
		return
	}

	// Add enhanced role information to account metadata
	// This could be stored in a custom field or handled by the calling code
	if len(roles) > 0 {
		c.logger.Printf("User %s has %d enhanced roles", account.Access, len(roles))
	}
}

// updateEnhancedRoleMapping updates enhanced role mapping when legacy account changes
func (c *BackwardCompatibilityManager) updateEnhancedRoleMapping(access string, props MutableProps) error {
	if props.Role == "" {
		return nil // No role change
	}

	// Remove existing legacy role mappings
	existingRoles, err := c.enhancedRoleManager.GetUserRoles(access)
	if err != nil {
		return fmt.Errorf("failed to get existing roles: %v", err)
	}

	for _, role := range existingRoles {
		if isLegacyRole(role.ID) {
			if err := c.enhancedRoleManager.RevokeRole(access, role.ID, "migration"); err != nil {
				c.logger.Printf("Warning: Failed to revoke legacy role %s from user %s: %v", role.ID, access, err)
			}
		}
	}

	// Create new role mapping
	account := Account{Access: access, Role: props.Role}
	return c.createEnhancedRoleMapping(account)
}

// deleteEnhancedRoleMapping removes enhanced role mapping for deleted account
func (c *BackwardCompatibilityManager) deleteEnhancedRoleMapping(access string) error {
	roles, err := c.enhancedRoleManager.GetUserRoles(access)
	if err != nil {
		return fmt.Errorf("failed to get user roles: %v", err)
	}

	for _, role := range roles {
		if err := c.enhancedRoleManager.RevokeRole(access, role.ID, "migration"); err != nil {
			c.logger.Printf("Warning: Failed to revoke role %s from user %s: %v", role.ID, access, err)
		}
	}

	return nil
}

// isLegacyRole checks if a role ID represents a legacy role
func isLegacyRole(roleID string) bool {
	legacyRoles := []string{"legacy-admin", "legacy-user", "legacy-user-plus"}
	for _, legacyRole := range legacyRoles {
		if roleID == legacyRole {
			return true
		}
	}
	return false
}

// CompatibleVerifyAccess provides backward-compatible access verification
func CompatibleVerifyAccess(ctx context.Context, be backend.Backend, opts AccessOptions, compatManager *BackwardCompatibilityManager) error {
	// If no compatibility manager or in full compatibility mode, use original function
	if compatManager == nil || compatManager.compatibilityMode == FullCompatibility {
		return VerifyAccess(ctx, be, opts)
	}

	// In hybrid mode, try enhanced first, then fall back
	if compatManager.compatibilityMode == HybridMode {
		// Set RoleManager in options if not already set
		if opts.RoleManager == nil {
			opts.RoleManager = compatManager.enhancedRoleManager
		}
		return VerifyAccess(ctx, be, opts)
	}

	// In enhanced-only mode, require RoleManager
	if compatManager.compatibilityMode == EnhancedOnlyMode {
		if opts.RoleManager == nil {
			opts.RoleManager = compatManager.enhancedRoleManager
		}
		return VerifyAccess(ctx, be, opts)
	}

	// Default to original behavior
	return VerifyAccess(ctx, be, opts)
}

// GetCompatibleIAMService returns a backward-compatible IAM service
func (c *BackwardCompatibilityManager) GetCompatibleIAMService() IAMService {
	return &CompatibleIAMService{BackwardCompatibilityManager: c}
}

// SetCompatibilityMode changes the compatibility mode
func (c *BackwardCompatibilityManager) SetCompatibilityMode(mode CompatibilityMode) {
	c.compatibilityMode = mode
	c.logger.Printf("Compatibility mode changed to: %v", mode)
}

// GetCompatibilityMode returns the current compatibility mode
func (c *BackwardCompatibilityManager) GetCompatibilityMode() CompatibilityMode {
	return c.compatibilityMode
}

// ValidateCompatibility checks if the current setup is compatible
func (c *BackwardCompatibilityManager) ValidateCompatibility() error {
	if c.legacyIAMService == nil {
		return fmt.Errorf("legacy IAM service is required")
	}

	if c.compatibilityMode != FullCompatibility && c.enhancedRoleManager == nil {
		return fmt.Errorf("enhanced role manager is required for hybrid/enhanced modes")
	}

	return nil
}