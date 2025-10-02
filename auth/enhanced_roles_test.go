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
	"testing"
	"time"
)

func TestDetailedPermission_Validate(t *testing.T) {
	tests := []struct {
		name        string
		permission  DetailedPermission
		expectError bool
	}{
		{
			name: "valid permission",
			permission: DetailedPermission{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			expectError: false,
		},
		{
			name: "empty resource",
			permission: DetailedPermission{
				Resource: "",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			expectError: true,
		},
		{
			name: "empty action",
			permission: DetailedPermission{
				Resource: "bucket/*",
				Action:   "",
				Effect:   PermissionAllow,
			},
			expectError: true,
		},
		{
			name: "invalid action format",
			permission: DetailedPermission{
				Resource: "bucket/*",
				Action:   "GetObject",
				Effect:   PermissionAllow,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.permission.Validate()
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDetailedPermission_Matches(t *testing.T) {
	tests := []struct {
		name       string
		permission DetailedPermission
		resource   string
		action     string
		expected   bool
	}{
		{
			name: "exact match",
			permission: DetailedPermission{
				Resource: "bucket/object",
				Action:   "s3:GetObject",
			},
			resource: "bucket/object",
			action:   "s3:GetObject",
			expected: true,
		},
		{
			name: "wildcard resource match",
			permission: DetailedPermission{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
			},
			resource: "bucket/object",
			action:   "s3:GetObject",
			expected: true,
		},
		{
			name: "wildcard action match",
			permission: DetailedPermission{
				Resource: "bucket/object",
				Action:   "s3:*",
			},
			resource: "bucket/object",
			action:   "s3:GetObject",
			expected: true,
		},
		{
			name: "no match - different resource",
			permission: DetailedPermission{
				Resource: "bucket1/object",
				Action:   "s3:GetObject",
			},
			resource: "bucket2/object",
			action:   "s3:GetObject",
			expected: false,
		},
		{
			name: "no match - different action",
			permission: DetailedPermission{
				Resource: "bucket/object",
				Action:   "s3:GetObject",
			},
			resource: "bucket/object",
			action:   "s3:PutObject",
			expected: false,
		},
		{
			name: "universal wildcard",
			permission: DetailedPermission{
				Resource: "*",
				Action:   "s3:*",
			},
			resource: "any/resource",
			action:   "s3:AnyAction",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.permission.Matches(tt.resource, tt.action)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestEnhancedRole_Validate(t *testing.T) {
	tests := []struct {
		name        string
		role        EnhancedRole
		expectError bool
	}{
		{
			name: "valid role",
			role: EnhancedRole{
				ID:   "test-role",
				Name: "Test Role",
				Permissions: []DetailedPermission{
					{
						Resource: "bucket/*",
						Action:   "s3:GetObject",
						Effect:   PermissionAllow,
					},
				},
			},
			expectError: false,
		},
		{
			name: "empty ID",
			role: EnhancedRole{
				ID:   "",
				Name: "Test Role",
			},
			expectError: true,
		},
		{
			name: "empty name",
			role: EnhancedRole{
				ID:   "test-role",
				Name: "",
			},
			expectError: true,
		},
		{
			name: "invalid permission",
			role: EnhancedRole{
				ID:   "test-role",
				Name: "Test Role",
				Permissions: []DetailedPermission{
					{
						Resource: "",
						Action:   "s3:GetObject",
						Effect:   PermissionAllow,
					},
				},
			},
			expectError: true,
		},
		{
			name: "self-referencing parent role",
			role: EnhancedRole{
				ID:          "test-role",
				Name:        "Test Role",
				ParentRoles: []string{"test-role"},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.role.Validate()
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestEnhancedRole_HasPermission(t *testing.T) {
	role := EnhancedRole{
		ID:   "test-role",
		Name: "Test Role",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "secret-bucket/*",
				Action:   "s3:*",
				Effect:   PermissionDeny,
			},
		},
	}

	tests := []struct {
		name     string
		resource string
		action   string
		expected PermissionEffect
	}{
		{
			name:     "allowed permission",
			resource: "bucket/object",
			action:   "s3:GetObject",
			expected: PermissionAllow,
		},
		{
			name:     "denied permission",
			resource: "secret-bucket/object",
			action:   "s3:GetObject",
			expected: PermissionDeny,
		},
		{
			name:     "no matching permission",
			resource: "other-bucket/object",
			action:   "s3:GetObject",
			expected: PermissionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := role.HasPermission(tt.resource, tt.action)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestPermissionSet_HasPermission(t *testing.T) {
	permSet := PermissionSet{
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "secret-bucket/*",
				Action:   "s3:*",
				Effect:   PermissionDeny,
			},
		},
	}

	tests := []struct {
		name     string
		resource string
		action   string
		expected bool
	}{
		{
			name:     "allowed permission",
			resource: "bucket/object",
			action:   "s3:GetObject",
			expected: true,
		},
		{
			name:     "denied permission overrides allow",
			resource: "secret-bucket/object",
			action:   "s3:GetObject",
			expected: false,
		},
		{
			name:     "no matching permission - default deny",
			resource: "other-bucket/object",
			action:   "s3:GetObject",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := permSet.HasPermission(tt.resource, tt.action)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRoleAssignment_IsExpired(t *testing.T) {
	now := time.Now()
	
	tests := []struct {
		name       string
		assignment RoleAssignment
		expected   bool
	}{
		{
			name: "no expiration",
			assignment: RoleAssignment{
				UserID:     "user1",
				RoleID:     "role1",
				AssignedAt: now,
				ExpiresAt:  nil,
			},
			expected: false,
		},
		{
			name: "not expired",
			assignment: RoleAssignment{
				UserID:     "user1",
				RoleID:     "role1",
				AssignedAt: now,
				ExpiresAt:  &[]time.Time{now.Add(time.Hour)}[0],
			},
			expected: false,
		},
		{
			name: "expired",
			assignment: RoleAssignment{
				UserID:     "user1",
				RoleID:     "role1",
				AssignedAt: now.Add(-2 * time.Hour),
				ExpiresAt:  &[]time.Time{now.Add(-time.Hour)}[0],
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.assignment.IsExpired()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRoleUpdates_Apply(t *testing.T) {
	originalRole := EnhancedRole{
		ID:          "test-role",
		Name:        "Original Name",
		Description: "Original Description",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
		ParentRoles: []string{"parent1"},
		CreatedAt:   time.Now().Add(-time.Hour),
		UpdatedAt:   time.Now().Add(-time.Hour),
	}

	newName := "Updated Name"
	newDescription := "Updated Description"
	newPermissions := []DetailedPermission{
		{
			Resource: "bucket/*",
			Action:   "s3:*",
			Effect:   PermissionAllow,
		},
	}
	newParentRoles := []string{"parent1", "parent2"}

	updates := RoleUpdates{
		Name:        &newName,
		Description: &newDescription,
		Permissions: &newPermissions,
		ParentRoles: &newParentRoles,
	}

	updates.Apply(&originalRole)

	if originalRole.Name != newName {
		t.Errorf("expected name %s, got %s", newName, originalRole.Name)
	}
	if originalRole.Description != newDescription {
		t.Errorf("expected description %s, got %s", newDescription, originalRole.Description)
	}
	if len(originalRole.Permissions) != len(newPermissions) {
		t.Errorf("expected %d permissions, got %d", len(newPermissions), len(originalRole.Permissions))
	}
	if len(originalRole.ParentRoles) != len(newParentRoles) {
		t.Errorf("expected %d parent roles, got %d", len(newParentRoles), len(originalRole.ParentRoles))
	}
}

func TestPermissionValidator_ValidatePermissionSet(t *testing.T) {
	validator := PermissionValidator{}

	tests := []struct {
		name        string
		permissions []DetailedPermission
		expectError bool
	}{
		{
			name: "valid permission set",
			permissions: []DetailedPermission{
				{
					Resource: "bucket/*",
					Action:   "s3:GetObject",
					Effect:   PermissionAllow,
				},
				{
					Resource: "bucket/*",
					Action:   "s3:PutObject",
					Effect:   PermissionAllow,
				},
			},
			expectError: false,
		},
		{
			name: "invalid permission in set",
			permissions: []DetailedPermission{
				{
					Resource: "",
					Action:   "s3:GetObject",
					Effect:   PermissionAllow,
				},
			},
			expectError: true,
		},
		{
			name: "conflicting permissions",
			permissions: []DetailedPermission{
				{
					Resource: "bucket/object",
					Action:   "s3:GetObject",
					Effect:   PermissionAllow,
				},
				{
					Resource: "bucket/object",
					Action:   "s3:GetObject",
					Effect:   PermissionDeny,
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePermissionSet(tt.permissions)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestComputeEffectivePermissions(t *testing.T) {
	role1 := &EnhancedRole{
		ID:   "role1",
		Name: "Role 1",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}

	role2 := &EnhancedRole{
		ID:   "role2",
		Name: "Role 2",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:PutObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "secret-bucket/*",
				Action:   "s3:*",
				Effect:   PermissionDeny,
			},
		},
	}

	roles := []*EnhancedRole{role1, role2}
	permSet := ComputeEffectivePermissions(roles)

	// Should have permissions from both roles
	if !permSet.HasPermission("bucket/object", "s3:GetObject") {
		t.Error("expected GetObject permission")
	}
	if !permSet.HasPermission("bucket/object", "s3:PutObject") {
		t.Error("expected PutObject permission")
	}
	if permSet.HasPermission("secret-bucket/object", "s3:GetObject") {
		t.Error("expected deny to override allow")
	}
}

func TestResolvePermissionConflicts(t *testing.T) {
	permissions := []DetailedPermission{
		{
			Resource: "bucket/object",
			Action:   "s3:GetObject",
			Effect:   PermissionAllow,
		},
		{
			Resource: "bucket/object",
			Action:   "s3:GetObject",
			Effect:   PermissionDeny,
		},
		{
			Resource: "bucket/object",
			Action:   "s3:PutObject",
			Effect:   PermissionAllow,
		},
	}

	resolved := resolvePermissionConflicts(permissions)

	// Should have 2 permissions (GetObject deny wins, PutObject allow)
	if len(resolved) != 2 {
		t.Errorf("expected 2 resolved permissions, got %d", len(resolved))
	}

	// Find the GetObject permission - should be deny
	var getObjectPerm *DetailedPermission
	for _, perm := range resolved {
		if perm.Action == "s3:GetObject" {
			getObjectPerm = &perm
			break
		}
	}

	if getObjectPerm == nil {
		t.Error("GetObject permission not found in resolved set")
	} else if getObjectPerm.Effect != PermissionDeny {
		t.Error("expected GetObject permission to be deny (deny wins)")
	}
}

func TestPredefinedRoles(t *testing.T) {
	// Test that predefined roles are valid
	for roleID, role := range PredefinedRoles {
		t.Run(roleID, func(t *testing.T) {
			if err := role.Validate(); err != nil {
				t.Errorf("predefined role %s is invalid: %v", roleID, err)
			}
		})
	}

	// Test specific predefined roles
	readOnlyRole := PredefinedRoles["s3-read-only"]
	if readOnlyRole == nil {
		t.Fatal("s3-read-only role not found")
	}

	// Should allow read operations
	if readOnlyRole.HasPermission("bucket/object", "s3:GetObject") != PermissionAllow {
		t.Error("s3-read-only should allow GetObject")
	}

	fullAccessRole := PredefinedRoles["s3-full-access"]
	if fullAccessRole == nil {
		t.Fatal("s3-full-access role not found")
	}

	// Should allow all operations
	if fullAccessRole.HasPermission("bucket/object", "s3:PutObject") != PermissionAllow {
		t.Error("s3-full-access should allow PutObject")
	}
	if fullAccessRole.HasPermission("bucket/object", "s3:DeleteObject") != PermissionAllow {
		t.Error("s3-full-access should allow DeleteObject")
	}
}