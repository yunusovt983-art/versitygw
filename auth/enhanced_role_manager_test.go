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
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInMemoryRoleManager_CreateRole(t *testing.T) {
	rm := NewInMemoryRoleManager()

	tests := []struct {
		name        string
		role        *EnhancedRole
		expectError bool
	}{
		{
			name: "valid role",
			role: &EnhancedRole{
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
			name:        "nil role",
			role:        nil,
			expectError: true,
		},
		{
			name: "invalid role",
			role: &EnhancedRole{
				ID:   "",
				Name: "Test Role",
			},
			expectError: true,
		},
		{
			name: "duplicate role ID",
			role: &EnhancedRole{
				ID:   "test-role",
				Name: "Duplicate Role",
			},
			expectError: true,
		},
		{
			name: "role with non-existent parent",
			role: &EnhancedRole{
				ID:          "child-role",
				Name:        "Child Role",
				ParentRoles: []string{"non-existent-parent"},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rm.CreateRole(tt.role)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestInMemoryRoleManager_GetRole(t *testing.T) {
	rm := NewInMemoryRoleManager()

	// Create a test role
	testRole := &EnhancedRole{
		ID:   "test-role",
		Name: "Test Role",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}
	rm.CreateRole(testRole)

	tests := []struct {
		name        string
		roleID      string
		expectError bool
	}{
		{
			name:        "existing role",
			roleID:      "test-role",
			expectError: false,
		},
		{
			name:        "non-existent role",
			roleID:      "non-existent",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role, err := rm.GetRole(tt.roleID)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.expectError && role == nil {
				t.Errorf("expected role but got nil")
			}
		})
	}
}

func TestInMemoryRoleManager_UpdateRole(t *testing.T) {
	rm := NewInMemoryRoleManager()

	// Create a test role
	testRole := &EnhancedRole{
		ID:   "test-role",
		Name: "Test Role",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}
	rm.CreateRole(testRole)

	newName := "Updated Role"
	updates := &RoleUpdates{
		Name: &newName,
	}

	tests := []struct {
		name        string
		roleID      string
		updates     *RoleUpdates
		expectError bool
	}{
		{
			name:        "valid update",
			roleID:      "test-role",
			updates:     updates,
			expectError: false,
		},
		{
			name:        "nil updates",
			roleID:      "test-role",
			updates:     nil,
			expectError: true,
		},
		{
			name:        "non-existent role",
			roleID:      "non-existent",
			updates:     updates,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rm.UpdateRole(tt.roleID, tt.updates)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}

	// Verify the update was applied
	updatedRole, _ := rm.GetRole("test-role")
	if updatedRole.Name != newName {
		t.Errorf("expected name %s, got %s", newName, updatedRole.Name)
	}
}

func TestInMemoryRoleManager_DeleteRole(t *testing.T) {
	rm := NewInMemoryRoleManager()

	// Create test roles
	parentRole := &EnhancedRole{
		ID:   "parent-role",
		Name: "Parent Role",
	}
	rm.CreateRole(parentRole)

	childRole := &EnhancedRole{
		ID:          "child-role",
		Name:        "Child Role",
		ParentRoles: []string{"parent-role"},
	}
	rm.CreateRole(childRole)

	// Assign a role to a user
	rm.AssignRole("user1", "parent-role", "admin")

	tests := []struct {
		name        string
		roleID      string
		expectError bool
	}{
		{
			name:        "role used as parent",
			roleID:      "parent-role",
			expectError: true,
		},
		{
			name:        "non-existent role",
			roleID:      "non-existent",
			expectError: true,
		},
		{
			name:        "valid deletion",
			roleID:      "child-role",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rm.DeleteRole(tt.roleID)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestInMemoryRoleManager_AssignRole(t *testing.T) {
	rm := NewInMemoryRoleManager()

	// Create a test role
	testRole := &EnhancedRole{
		ID:   "test-role",
		Name: "Test Role",
	}
	rm.CreateRole(testRole)

	tests := []struct {
		name        string
		userID      string
		roleID      string
		assignedBy  string
		expectError bool
	}{
		{
			name:        "valid assignment",
			userID:      "user1",
			roleID:      "test-role",
			assignedBy:  "admin",
			expectError: false,
		},
		{
			name:        "non-existent role",
			userID:      "user1",
			roleID:      "non-existent",
			assignedBy:  "admin",
			expectError: true,
		},
		{
			name:        "duplicate assignment",
			userID:      "user1",
			roleID:      "test-role",
			assignedBy:  "admin",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rm.AssignRole(tt.userID, tt.roleID, tt.assignedBy)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestInMemoryRoleManager_RevokeRole(t *testing.T) {
	rm := NewInMemoryRoleManager()

	// Create and assign a test role
	testRole := &EnhancedRole{
		ID:   "test-role",
		Name: "Test Role",
	}
	rm.CreateRole(testRole)
	rm.AssignRole("user1", "test-role", "admin")

	tests := []struct {
		name        string
		userID      string
		roleID      string
		expectError bool
	}{
		{
			name:        "valid revocation",
			userID:      "user1",
			roleID:      "test-role",
			expectError: false,
		},
		{
			name:        "non-assigned role",
			userID:      "user1",
			roleID:      "test-role",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rm.RevokeRole(tt.userID, tt.roleID)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestInMemoryRoleManager_GetUserRoles(t *testing.T) {
	rm := NewInMemoryRoleManager()

	// Create test roles
	role1 := &EnhancedRole{
		ID:   "role1",
		Name: "Role 1",
	}
	role2 := &EnhancedRole{
		ID:   "role2",
		Name: "Role 2",
	}
	rm.CreateRole(role1)
	rm.CreateRole(role2)

	// Assign roles to user
	rm.AssignRole("user1", "role1", "admin")
	rm.AssignRole("user1", "role2", "admin")

	roles, err := rm.GetUserRoles("user1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}

	// Check that we got the right roles
	roleIDs := make(map[string]bool)
	for _, role := range roles {
		roleIDs[role.ID] = true
	}

	if !roleIDs["role1"] || !roleIDs["role2"] {
		t.Error("did not get expected roles")
	}
}

func TestInMemoryRoleManager_GetEffectivePermissions(t *testing.T) {
	rm := NewInMemoryRoleManager()

	// Create roles with different permissions
	role1 := &EnhancedRole{
		ID:   "role1",
		Name: "Role 1",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket1/*",
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
				Resource: "bucket2/*",
				Action:   "s3:PutObject",
				Effect:   PermissionAllow,
			},
		},
	}
	rm.CreateRole(role1)
	rm.CreateRole(role2)

	// Assign both roles to user
	rm.AssignRole("user1", "role1", "admin")
	rm.AssignRole("user1", "role2", "admin")

	permissions, err := rm.GetEffectivePermissions("user1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should have permissions from both roles
	if !permissions.HasPermission("bucket1/object", "s3:GetObject") {
		t.Error("expected GetObject permission on bucket1")
	}
	if !permissions.HasPermission("bucket2/object", "s3:PutObject") {
		t.Error("expected PutObject permission on bucket2")
	}
	if permissions.HasPermission("bucket3/object", "s3:GetObject") {
		t.Error("should not have permission on bucket3")
	}
}

func TestInMemoryRoleManager_CheckPermission(t *testing.T) {
	rm := NewInMemoryRoleManager()

	// Create a role with specific permissions
	role := &EnhancedRole{
		ID:   "test-role",
		Name: "Test Role",
		Permissions: []DetailedPermission{
			{
				Resource: "allowed-bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "denied-bucket/*",
				Action:   "s3:*",
				Effect:   PermissionDeny,
			},
		},
	}
	rm.CreateRole(role)
	rm.AssignRole("user1", "test-role", "admin")

	tests := []struct {
		name     string
		userID   string
		resource string
		action   string
		expected bool
	}{
		{
			name:     "allowed permission",
			userID:   "user1",
			resource: "allowed-bucket/object",
			action:   "s3:GetObject",
			expected: true,
		},
		{
			name:     "denied permission",
			userID:   "user1",
			resource: "denied-bucket/object",
			action:   "s3:GetObject",
			expected: false,
		},
		{
			name:     "no permission",
			userID:   "user1",
			resource: "other-bucket/object",
			action:   "s3:GetObject",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := rm.CheckPermission(tt.userID, tt.resource, tt.action)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestInMemoryRoleManager_RoleHierarchy(t *testing.T) {
	rm := NewInMemoryRoleManager()

	// Create a role hierarchy: grandparent -> parent -> child
	grandparentRole := &EnhancedRole{
		ID:   "grandparent",
		Name: "Grandparent Role",
		Permissions: []DetailedPermission{
			{
				Resource: "*",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
			},
		},
	}
	parentRole := &EnhancedRole{
		ID:          "parent",
		Name:        "Parent Role",
		ParentRoles: []string{"grandparent"},
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}
	childRole := &EnhancedRole{
		ID:          "child",
		Name:        "Child Role",
		ParentRoles: []string{"parent"},
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:PutObject",
				Effect:   PermissionAllow,
			},
		},
	}

	rm.CreateRole(grandparentRole)
	rm.CreateRole(parentRole)
	rm.CreateRole(childRole)

	// Assign child role to user
	rm.AssignRole("user1", "child", "admin")

	// Get effective permissions - should include all inherited permissions
	permissions, err := rm.GetEffectivePermissions("user1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should have permissions from all roles in hierarchy
	if !permissions.HasPermission("bucket", "s3:ListBucket") {
		t.Error("expected ListBucket permission from grandparent role")
	}
	if !permissions.HasPermission("bucket/object", "s3:GetObject") {
		t.Error("expected GetObject permission from parent role")
	}
	if !permissions.HasPermission("bucket/object", "s3:PutObject") {
		t.Error("expected PutObject permission from child role")
	}
}

func TestInMemoryRoleManager_ValidateRoleHierarchy(t *testing.T) {
	rm := NewInMemoryRoleManager()

	// Create test roles
	role1 := &EnhancedRole{ID: "role1", Name: "Role 1"}
	role2 := &EnhancedRole{ID: "role2", Name: "Role 2", ParentRoles: []string{"role1"}}
	rm.CreateRole(role1)
	rm.CreateRole(role2)

	tests := []struct {
		name        string
		roleID      string
		parentRoles []string
		expectError bool
	}{
		{
			name:        "valid hierarchy",
			roleID:      "role3",
			parentRoles: []string{"role1"},
			expectError: false,
		},
		{
			name:        "self-reference",
			roleID:      "role1",
			parentRoles: []string{"role1"},
			expectError: true,
		},
		{
			name:        "circular dependency",
			roleID:      "role1",
			parentRoles: []string{"role2"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rm.ValidateRoleHierarchy(tt.roleID, tt.parentRoles)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestFileBasedRoleManager(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "role_manager_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	rm, err := NewFileBasedRoleManager(tempDir)
	if err != nil {
		t.Fatalf("failed to create file-based role manager: %v", err)
	}

	// Test creating a role
	testRole := &EnhancedRole{
		ID:   "test-role",
		Name: "Test Role",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}

	err = rm.CreateRole(testRole)
	if err != nil {
		t.Errorf("failed to create role: %v", err)
	}

	// Verify role file was created
	rolePath := filepath.Join(tempDir, "roles", "test-role.json")
	if _, err := os.Stat(rolePath); os.IsNotExist(err) {
		t.Error("role file was not created")
	}

	// Test assigning role
	err = rm.AssignRole("user1", "test-role", "admin")
	if err != nil {
		t.Errorf("failed to assign role: %v", err)
	}

	// Verify assignment file was created
	assignmentPath := filepath.Join(tempDir, "assignments", "user1.json")
	if _, err := os.Stat(assignmentPath); os.IsNotExist(err) {
		t.Error("assignment file was not created")
	}

	// Create a new manager instance to test loading from disk
	rm2, err := NewFileBasedRoleManager(tempDir)
	if err != nil {
		t.Fatalf("failed to create second role manager: %v", err)
	}

	// Verify role was loaded
	loadedRole, err := rm2.GetRole("test-role")
	if err != nil {
		t.Errorf("failed to get loaded role: %v", err)
	}
	if loadedRole.Name != testRole.Name {
		t.Errorf("expected role name %s, got %s", testRole.Name, loadedRole.Name)
	}

	// Verify assignment was loaded
	roles, err := rm2.GetUserRoles("user1")
	if err != nil {
		t.Errorf("failed to get user roles: %v", err)
	}
	if len(roles) != 1 || roles[0].ID != "test-role" {
		t.Error("assignment was not loaded correctly")
	}
}

func TestRoleAssignmentExpiration(t *testing.T) {
	rm := NewInMemoryRoleManager()

	// Create a test role
	testRole := &EnhancedRole{
		ID:   "test-role",
		Name: "Test Role",
	}
	rm.CreateRole(testRole)

	// Manually create an expired assignment
	expiredTime := time.Now().Add(-time.Hour)
	expiredAssignment := &RoleAssignment{
		UserID:     "user1",
		RoleID:     "test-role",
		AssignedAt: time.Now().Add(-2 * time.Hour),
		AssignedBy: "admin",
		ExpiresAt:  &expiredTime,
	}
	rm.assignments["user1"] = []*RoleAssignment{expiredAssignment}

	// GetUserRoles should not return expired roles
	roles, err := rm.GetUserRoles("user1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("expected 0 roles (expired), got %d", len(roles))
	}

	// But GetRoleAssignments should return all assignments
	assignments, err := rm.GetRoleAssignments("user1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(assignments) != 1 {
		t.Errorf("expected 1 assignment, got %d", len(assignments))
	}
}