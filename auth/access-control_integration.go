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

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
)

// EnhancedAccessControlConfig holds configuration for enhanced access control
type EnhancedAccessControlConfig struct {
	RoleManager RoleManager
	Enabled     bool
}

// IntegrateEnhancedAccessControl provides a way to integrate enhanced role-based access control
// with the existing middleware system
func IntegrateEnhancedAccessControl(ctx *fiber.Ctx, be backend.Backend, config *EnhancedAccessControlConfig, opts AccessOptions) error {
	// If enhanced access control is not enabled or configured, fall back to traditional method
	if config == nil || !config.Enabled || config.RoleManager == nil {
		return VerifyAccess(ctx.Context(), be, opts)
	}

	// Set the role manager in options for enhanced access control
	opts.RoleManager = config.RoleManager
	return VerifyAccess(ctx.Context(), be, opts)
}

// GetEnhancedAccessOptionsFromContext extracts access options from fiber context
// This is a helper function to build AccessOptions from the current request context
func GetEnhancedAccessOptionsFromContext(ctx *fiber.Ctx, action Action, aclPermission Permission) AccessOptions {
	// Extract values from context
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	account := utils.ContextKeyAccount.Get(ctx).(Account)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(ACL)
	isPublicBucket := utils.ContextKeyPublicBucket.IsSet(ctx)

	// Extract bucket and object from request path
	bucket := ctx.Params("bucket", "")
	object := ctx.Params("object", "")

	return AccessOptions{
		Acl:            parsedAcl,
		AclPermission:  aclPermission,
		IsRoot:         isRoot,
		Acc:            account,
		Bucket:         bucket,
		Object:         object,
		Action:         action,
		IsBucketPublic: isPublicBucket,
		// RoleManager will be set by IntegrateEnhancedAccessControl
	}
}

// EnhancedAccessMiddleware creates a middleware function that uses enhanced role-based access control
func EnhancedAccessMiddleware(be backend.Backend, config *EnhancedAccessControlConfig) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// Skip if not authenticated
		if !utils.ContextKeyAuthenticated.IsSet(ctx) {
			return ctx.Next()
		}

		// This middleware would be used in specific endpoints where access control is needed
		// For now, it just sets up the infrastructure and continues
		// Actual access checks would be done in individual handlers

		return ctx.Next()
	}
}

// CheckEnhancedPermissionInHandler is a helper function for use within request handlers
// to check permissions using the enhanced role system
func CheckEnhancedPermissionInHandler(ctx *fiber.Ctx, be backend.Backend, config *EnhancedAccessControlConfig, action Action, aclPermission Permission) error {
	opts := GetEnhancedAccessOptionsFromContext(ctx, action, aclPermission)
	return IntegrateEnhancedAccessControl(ctx, be, config, opts)
}

// EnhancedAccessControlManager provides a centralized way to manage enhanced access control
type EnhancedAccessControlManager struct {
	roleManager RoleManager
	backend     backend.Backend
	enabled     bool
}

// NewEnhancedAccessControlManager creates a new enhanced access control manager
func NewEnhancedAccessControlManager(roleManager RoleManager, backend backend.Backend) *EnhancedAccessControlManager {
	return &EnhancedAccessControlManager{
		roleManager: roleManager,
		backend:     backend,
		enabled:     roleManager != nil,
	}
}

// IsEnabled returns whether enhanced access control is enabled
func (eacm *EnhancedAccessControlManager) IsEnabled() bool {
	return eacm.enabled
}

// SetEnabled enables or disables enhanced access control
func (eacm *EnhancedAccessControlManager) SetEnabled(enabled bool) {
	eacm.enabled = enabled && eacm.roleManager != nil
}

// CheckAccess performs access control check using enhanced roles if enabled
func (eacm *EnhancedAccessControlManager) CheckAccess(ctx context.Context, opts AccessOptions) error {
	if eacm.enabled {
		opts.RoleManager = eacm.roleManager
	}
	return VerifyAccess(ctx, eacm.backend, opts)
}

// GetUserPermissions returns effective permissions for a user
func (eacm *EnhancedAccessControlManager) GetUserPermissions(userID string) (*PermissionSet, error) {
	if !eacm.enabled {
		return nil, fmt.Errorf("enhanced access control is not enabled")
	}
	return eacm.roleManager.GetEffectivePermissions(userID)
}

// CheckUserPermission checks if a user has a specific permission
func (eacm *EnhancedAccessControlManager) CheckUserPermission(userID, bucket, object string, action Action) (bool, error) {
	if !eacm.enabled {
		return false, fmt.Errorf("enhanced access control is not enabled")
	}
	resource := buildResourceARN(bucket, object)
	return eacm.roleManager.CheckPermission(userID, resource, string(action))
}

// GetRoleManager returns the underlying role manager
func (eacm *EnhancedAccessControlManager) GetRoleManager() RoleManager {
	return eacm.roleManager
}

// MigrateFromTraditionalRoles helps migrate from traditional role system to enhanced roles
func (eacm *EnhancedAccessControlManager) MigrateFromTraditionalRoles(accounts []Account) error {
	if !eacm.enabled {
		return fmt.Errorf("enhanced access control is not enabled")
	}

	for _, account := range accounts {
		// Create enhanced role based on traditional role
		var enhancedRole *EnhancedRole
		
		switch account.Role {
		case RoleAdmin:
			enhancedRole = &EnhancedRole{
				ID:          fmt.Sprintf("migrated-admin-%s", account.Access),
				Name:        fmt.Sprintf("Migrated Admin Role for %s", account.Access),
				Description: "Migrated from traditional admin role",
				Permissions: []DetailedPermission{
					{
						Resource: "*",
						Action:   "s3:*",
						Effect:   PermissionAllow,
					},
				},
			}
		case RoleUser:
			enhancedRole = &EnhancedRole{
				ID:          fmt.Sprintf("migrated-user-%s", account.Access),
				Name:        fmt.Sprintf("Migrated User Role for %s", account.Access),
				Description: "Migrated from traditional user role",
				Permissions: []DetailedPermission{
					{
						Resource: "*",
						Action:   "s3:GetObject",
						Effect:   PermissionAllow,
					},
					{
						Resource: "*",
						Action:   "s3:PutObject",
						Effect:   PermissionAllow,
					},
					{
						Resource: "*",
						Action:   "s3:ListBucket",
						Effect:   PermissionAllow,
					},
				},
			}
		default:
			continue // Skip unknown roles
		}

		// Create the role
		if err := eacm.roleManager.CreateRole(enhancedRole); err != nil {
			return fmt.Errorf("failed to create migrated role for %s: %w", account.Access, err)
		}

		// Assign the role to the user
		if err := eacm.roleManager.AssignRole(account.Access, enhancedRole.ID, "migration"); err != nil {
			return fmt.Errorf("failed to assign migrated role to %s: %w", account.Access, err)
		}
	}

	return nil
}

// ValidateConfiguration validates the enhanced access control configuration
func (eacm *EnhancedAccessControlManager) ValidateConfiguration() error {
	if eacm.roleManager == nil {
		return fmt.Errorf("role manager is required")
	}
	if eacm.backend == nil {
		return fmt.Errorf("backend is required")
	}
	return nil
}

// GetStats returns statistics about the enhanced access control system
func (eacm *EnhancedAccessControlManager) GetStats() (map[string]interface{}, error) {
	if !eacm.enabled {
		return map[string]interface{}{
			"enabled": false,
		}, nil
	}

	roles, err := eacm.roleManager.ListRoles()
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	stats := map[string]interface{}{
		"enabled":    true,
		"role_count": len(roles),
		"roles":      make([]map[string]interface{}, len(roles)),
	}

	for i, role := range roles {
		roleStats := map[string]interface{}{
			"id":               role.ID,
			"name":             role.Name,
			"permission_count": len(role.Permissions),
			"parent_count":     len(role.ParentRoles),
			"created_at":       role.CreatedAt,
			"updated_at":       role.UpdatedAt,
		}
		stats["roles"].([]map[string]interface{})[i] = roleStats
	}

	return stats, nil
}