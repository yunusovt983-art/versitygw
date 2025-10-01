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
	"fmt"
	"strings"
	"time"
)

// PermissionEffect defines whether a permission allows or denies access
type PermissionEffect int

const (
	PermissionAllow PermissionEffect = iota
	PermissionDeny
)

func (pe PermissionEffect) String() string {
	switch pe {
	case PermissionAllow:
		return "Allow"
	case PermissionDeny:
		return "Deny"
	default:
		return "Unknown"
	}
}

// DetailedPermission represents a granular permission with conditions
type DetailedPermission struct {
	Resource   string                 `json:"resource"`
	Action     string                 `json:"action"`
	Effect     PermissionEffect       `json:"effect"`
	Conditions map[string]interface{} `json:"conditions,omitempty"`
}

// Validate checks if the permission is valid
func (dp *DetailedPermission) Validate() error {
	if dp.Resource == "" {
		return fmt.Errorf("permission resource cannot be empty")
	}
	if dp.Action == "" {
		return fmt.Errorf("permission action cannot be empty")
	}
	
	// Validate action format (should be s3:ActionName)
	if !strings.HasPrefix(dp.Action, "s3:") {
		return fmt.Errorf("invalid action format: %s", dp.Action)
	}
	
	return nil
}

// Matches checks if this permission applies to the given resource and action
func (dp *DetailedPermission) Matches(resource, action string) bool {
	return dp.matchesResource(resource) && dp.matchesAction(action)
}

// matchesResource checks if the resource pattern matches the given resource
func (dp *DetailedPermission) matchesResource(resource string) bool {
	// Support wildcard matching
	if dp.Resource == "*" {
		return true
	}
	
	// Exact match
	if dp.Resource == resource {
		return true
	}
	
	// Handle AWS ARN-style wildcards
	if strings.Contains(dp.Resource, "*") {
		return matchesARNPattern(dp.Resource, resource)
	}
	
	return false
}

// matchesARNPattern provides pattern matching for AWS ARN-style resources
func matchesARNPattern(pattern, resource string) bool {
	// Handle specific AWS S3 ARN patterns
	switch pattern {
	case "arn:aws:s3:::*":
		// Matches any bucket: arn:aws:s3:::bucket-name
		return strings.HasPrefix(resource, "arn:aws:s3:::") && !strings.Contains(resource[13:], "/")
	case "arn:aws:s3:::*/*":
		// Matches any object in any bucket: arn:aws:s3:::bucket-name/object-key
		return strings.HasPrefix(resource, "arn:aws:s3:::") && strings.Contains(resource[13:], "/")
	case "*":
		// Matches everything
		return true
	}
	
	// Handle patterns with wildcards at the end
	if strings.HasSuffix(pattern, "*") && !strings.Contains(pattern[:len(pattern)-1], "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(resource, prefix)
	}
	
	// For more complex patterns, you could implement full glob or regex matching
	// For now, fall back to exact match
	return pattern == resource
}

// matchesAction checks if the action pattern matches the given action
func (dp *DetailedPermission) matchesAction(action string) bool {
	// Support wildcard matching
	if dp.Action == "s3:*" {
		return strings.HasPrefix(action, "s3:")
	}
	
	// Exact match
	if dp.Action == action {
		return true
	}
	
	// Wildcard pattern matching
	if strings.HasSuffix(dp.Action, "*") {
		prefix := strings.TrimSuffix(dp.Action, "*")
		return strings.HasPrefix(action, prefix)
	}
	
	return false
}

// EnhancedRole represents a role with detailed permissions and inheritance
type EnhancedRole struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Permissions []DetailedPermission `json:"permissions"`
	ParentRoles []string             `json:"parent_roles,omitempty"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
	Metadata    map[string]string    `json:"metadata,omitempty"`
}

// Validate checks if the role is valid
func (er *EnhancedRole) Validate() error {
	if er.ID == "" {
		return fmt.Errorf("role ID cannot be empty")
	}
	if er.Name == "" {
		return fmt.Errorf("role name cannot be empty")
	}
	
	// Validate all permissions
	for i, perm := range er.Permissions {
		if err := perm.Validate(); err != nil {
			return fmt.Errorf("invalid permission at index %d: %w", i, err)
		}
	}
	
	// Check for circular dependencies in parent roles
	if err := er.validateParentRoles(); err != nil {
		return fmt.Errorf("invalid parent roles: %w", err)
	}
	
	return nil
}

// validateParentRoles checks for circular dependencies
func (er *EnhancedRole) validateParentRoles() error {
	visited := make(map[string]bool)
	
	var checkCircular func(roleID string, path []string) error
	checkCircular = func(roleID string, path []string) error {
		if visited[roleID] {
			return fmt.Errorf("circular dependency detected: %s", strings.Join(append(path, roleID), " -> "))
		}
		
		visited[roleID] = true
		defer func() { visited[roleID] = false }()
		
		// This would need to be implemented with actual role lookup
		// For now, we just check direct parent roles
		for _, parentID := range er.ParentRoles {
			if parentID == roleID {
				return fmt.Errorf("role cannot be its own parent: %s", roleID)
			}
		}
		
		return nil
	}
	
	return checkCircular(er.ID, []string{})
}

// HasPermission checks if the role has a specific permission
func (er *EnhancedRole) HasPermission(resource, action string) PermissionEffect {
	// Check direct permissions (deny takes precedence)
	var hasAllow bool
	
	for _, perm := range er.Permissions {
		if perm.Matches(resource, action) {
			if perm.Effect == PermissionDeny {
				return PermissionDeny
			}
			hasAllow = true
		}
	}
	
	if hasAllow {
		return PermissionAllow
	}
	
	// Default deny
	return PermissionDeny
}

// PermissionSet represents an aggregated set of permissions from multiple roles
type PermissionSet struct {
	Permissions []DetailedPermission `json:"permissions"`
	ComputedAt  time.Time            `json:"computed_at"`
}

// HasPermission checks if the permission set allows access to a resource/action
func (ps *PermissionSet) HasPermission(resource, action string) bool {
	// Apply "deny by default" principle
	// First check for explicit deny permissions
	for _, perm := range ps.Permissions {
		if perm.Matches(resource, action) && perm.Effect == PermissionDeny {
			return false
		}
	}
	
	// Then check for allow permissions
	for _, perm := range ps.Permissions {
		if perm.Matches(resource, action) && perm.Effect == PermissionAllow {
			return true
		}
	}
	
	// Default deny
	return false
}

// RoleAssignment represents a user's role assignment
type RoleAssignment struct {
	UserID     string    `json:"user_id"`
	RoleID     string    `json:"role_id"`
	AssignedAt time.Time `json:"assigned_at"`
	AssignedBy string    `json:"assigned_by"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// IsExpired checks if the role assignment has expired
func (ra *RoleAssignment) IsExpired() bool {
	if ra.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*ra.ExpiresAt)
}

// RoleManager interface defines operations for managing enhanced roles
type RoleManager interface {
	// Role CRUD operations
	CreateRole(role *EnhancedRole) error
	GetRole(roleID string) (*EnhancedRole, error)
	UpdateRole(roleID string, updates *RoleUpdates) error
	DeleteRole(roleID string) error
	ListRoles() ([]*EnhancedRole, error)
	
	// Role assignment operations
	AssignRole(userID, roleID, assignedBy string) error
	RevokeRole(userID, roleID string) error
	GetUserRoles(userID string) ([]*EnhancedRole, error)
	GetRoleAssignments(userID string) ([]*RoleAssignment, error)
	GetUsersWithRole(roleID string) ([]string, error)
	
	// Permission computation
	GetEffectivePermissions(userID string) (*PermissionSet, error)
	CheckPermission(userID, resource, action string) (bool, error)
	
	// Role hierarchy operations
	GetRoleHierarchy(roleID string) ([]*EnhancedRole, error)
	ValidateRoleHierarchy(roleID string, parentRoles []string) error
}

// RoleUpdates represents updates to a role
type RoleUpdates struct {
	Name        *string               `json:"name,omitempty"`
	Description *string               `json:"description,omitempty"`
	Permissions *[]DetailedPermission `json:"permissions,omitempty"`
	ParentRoles *[]string             `json:"parent_roles,omitempty"`
	Metadata    *map[string]string    `json:"metadata,omitempty"`
}

// Apply applies the updates to a role
func (ru *RoleUpdates) Apply(role *EnhancedRole) {
	if ru.Name != nil {
		role.Name = *ru.Name
	}
	if ru.Description != nil {
		role.Description = *ru.Description
	}
	if ru.Permissions != nil {
		role.Permissions = *ru.Permissions
	}
	if ru.ParentRoles != nil {
		role.ParentRoles = *ru.ParentRoles
	}
	if ru.Metadata != nil {
		role.Metadata = *ru.Metadata
	}
	role.UpdatedAt = time.Now()
}

// PredefinedRoles contains commonly used role definitions
var PredefinedRoles = map[string]*EnhancedRole{
	"s3-read-only": {
		ID:          "s3-read-only",
		Name:        "S3 Read Only",
		Description: "Read-only access to S3 resources",
		Permissions: []DetailedPermission{
			{
				Resource: "*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "*",
				Action:   "s3:GetObjectAcl",
				Effect:   PermissionAllow,
			},
			{
				Resource: "*",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
			},
			{
				Resource: "*",
				Action:   "s3:GetBucketAcl",
				Effect:   PermissionAllow,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	},
	"s3-full-access": {
		ID:          "s3-full-access",
		Name:        "S3 Full Access",
		Description: "Full access to S3 resources",
		Permissions: []DetailedPermission{
			{
				Resource: "*",
				Action:   "s3:*",
				Effect:   PermissionAllow,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	},
	"s3-bucket-admin": {
		ID:          "s3-bucket-admin",
		Name:        "S3 Bucket Administrator",
		Description: "Administrative access to bucket operations",
		Permissions: []DetailedPermission{
			{
				Resource: "*",
				Action:   "s3:CreateBucket",
				Effect:   PermissionAllow,
			},
			{
				Resource: "*",
				Action:   "s3:DeleteBucket",
				Effect:   PermissionAllow,
			},
			{
				Resource: "*",
				Action:   "s3:PutBucketPolicy",
				Effect:   PermissionAllow,
			},
			{
				Resource: "*",
				Action:   "s3:GetBucketPolicy",
				Effect:   PermissionAllow,
			},
			{
				Resource: "*",
				Action:   "s3:DeleteBucketPolicy",
				Effect:   PermissionAllow,
			},
			{
				Resource: "*",
				Action:   "s3:PutBucketAcl",
				Effect:   PermissionAllow,
			},
			{
				Resource: "*",
				Action:   "s3:GetBucketAcl",
				Effect:   PermissionAllow,
			},
		},
		ParentRoles: []string{"s3-read-only"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	},
}

// PermissionValidator provides validation utilities for permissions
type PermissionValidator struct{}

// ValidatePermissionSet validates a set of permissions for consistency
func (pv *PermissionValidator) ValidatePermissionSet(permissions []DetailedPermission) error {
	for i, perm := range permissions {
		if err := perm.Validate(); err != nil {
			return fmt.Errorf("invalid permission at index %d: %w", i, err)
		}
	}
	
	// Check for conflicting permissions (same resource/action with different effects)
	conflicts := pv.findConflicts(permissions)
	if len(conflicts) > 0 {
		return fmt.Errorf("conflicting permissions found: %v", conflicts)
	}
	
	return nil
}

// findConflicts identifies conflicting permissions
func (pv *PermissionValidator) findConflicts(permissions []DetailedPermission) []string {
	var conflicts []string
	seen := make(map[string]PermissionEffect)
	
	for _, perm := range permissions {
		key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
		if existingEffect, exists := seen[key]; exists {
			if existingEffect != perm.Effect {
				conflicts = append(conflicts, key)
			}
		} else {
			seen[key] = perm.Effect
		}
	}
	
	return conflicts
}

// ComputeEffectivePermissions computes the effective permissions from multiple roles
func ComputeEffectivePermissions(roles []*EnhancedRole) *PermissionSet {
	var allPermissions []DetailedPermission
	
	// Collect all permissions from all roles
	for _, role := range roles {
		allPermissions = append(allPermissions, role.Permissions...)
	}
	
	// Remove duplicates and resolve conflicts (deny wins)
	effectivePerms := resolvePermissionConflicts(allPermissions)
	
	return &PermissionSet{
		Permissions: effectivePerms,
		ComputedAt:  time.Now(),
	}
}

// resolvePermissionConflicts resolves conflicts between permissions using "deny wins" principle
func resolvePermissionConflicts(permissions []DetailedPermission) []DetailedPermission {
	// Group permissions by resource:action
	permMap := make(map[string][]DetailedPermission)
	
	for _, perm := range permissions {
		key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
		permMap[key] = append(permMap[key], perm)
	}
	
	var resolved []DetailedPermission
	
	// Resolve conflicts for each resource:action combination
	for _, perms := range permMap {
		if len(perms) == 1 {
			resolved = append(resolved, perms[0])
			continue
		}
		
		// Check if there's any deny permission
		hasDeny := false
		var finalPerm DetailedPermission
		
		for _, perm := range perms {
			if perm.Effect == PermissionDeny {
				hasDeny = true
				finalPerm = perm
				break
			}
		}
		
		// If no deny, use the first allow permission
		if !hasDeny {
			for _, perm := range perms {
				if perm.Effect == PermissionAllow {
					finalPerm = perm
					break
				}
			}
		}
		
		resolved = append(resolved, finalPerm)
	}
	
	return resolved
}