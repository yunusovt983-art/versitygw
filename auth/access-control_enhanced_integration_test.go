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
	"errors"
	"testing"
	"time"

	"github.com/versity/versitygw/s3err"
)

func TestVerifyAccessWithEnhancedRoles(t *testing.T) {
	mockBackend := NewMockBackend()
	roleManager := NewInMemoryRoleManager()
	
	// Create test roles
	readOnlyRole := &EnhancedRole{
		ID:          "read-only-test",
		Name:        "Read Only Test Role",
		Description: "Test role with read-only permissions",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::test-bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "arn:aws:s3:::test-bucket",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	writeRole := &EnhancedRole{
		ID:          "write-test",
		Name:        "Write Test Role",
		Description: "Test role with write permissions",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::test-bucket/*",
				Action:   "s3:PutObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "arn:aws:s3:::test-bucket/*",
				Action:   "s3:DeleteObject",
				Effect:   PermissionAllow,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	denyRole := &EnhancedRole{
		ID:          "deny-test",
		Name:        "Deny Test Role",
		Description: "Test role with explicit deny permissions",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::restricted-bucket/*",
				Action:   "s3:*",
				Effect:   PermissionDeny,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	// Create roles
	if err := roleManager.CreateRole(readOnlyRole); err != nil {
		t.Fatalf("Failed to create read-only role: %v", err)
	}
	if err := roleManager.CreateRole(writeRole); err != nil {
		t.Fatalf("Failed to create write role: %v", err)
	}
	if err := roleManager.CreateRole(denyRole); err != nil {
		t.Fatalf("Failed to create deny role: %v", err)
	}
	
	// Test users
	testUser1 := "test-user-1"
	testUser2 := "test-user-2"
	testUser3 := "test-user-3"
	
	// Assign roles
	if err := roleManager.AssignRole(testUser1, "read-only-test", "admin"); err != nil {
		t.Fatalf("Failed to assign read-only role: %v", err)
	}
	if err := roleManager.AssignRole(testUser2, "read-only-test", "admin"); err != nil {
		t.Fatalf("Failed to assign read-only role to user2: %v", err)
	}
	if err := roleManager.AssignRole(testUser2, "write-test", "admin"); err != nil {
		t.Fatalf("Failed to assign write role to user2: %v", err)
	}
	if err := roleManager.AssignRole(testUser3, "read-only-test", "admin"); err != nil {
		t.Fatalf("Failed to assign read-only role to user3: %v", err)
	}
	if err := roleManager.AssignRole(testUser3, "deny-test", "admin"); err != nil {
		t.Fatalf("Failed to assign deny role to user3: %v", err)
	}
	
	tests := []struct {
		name        string
		userID      string
		bucket      string
		object      string
		action      Action
		expectAllow bool
		description string
	}{
		{
			name:        "Read access allowed",
			userID:      testUser1,
			bucket:      "test-bucket",
			object:      "test-object",
			action:      GetObjectAction,
			expectAllow: true,
			description: "User with read-only role should be able to read objects",
		},
		{
			name:        "Write access denied for read-only user",
			userID:      testUser1,
			bucket:      "test-bucket",
			object:      "test-object",
			action:      PutObjectAction,
			expectAllow: false,
			description: "User with read-only role should not be able to write objects",
		},
		{
			name:        "List bucket allowed",
			userID:      testUser1,
			bucket:      "test-bucket",
			object:      "",
			action:      ListBucketAction,
			expectAllow: true,
			description: "User with read-only role should be able to list bucket",
		},
		{
			name:        "Multiple roles - read access",
			userID:      testUser2,
			bucket:      "test-bucket",
			object:      "test-object",
			action:      GetObjectAction,
			expectAllow: true,
			description: "User with multiple roles should have read access",
		},
		{
			name:        "Multiple roles - write access",
			userID:      testUser2,
			bucket:      "test-bucket",
			object:      "test-object",
			action:      PutObjectAction,
			expectAllow: true,
			description: "User with multiple roles should have write access",
		},
		{
			name:        "Multiple roles - delete access",
			userID:      testUser2,
			bucket:      "test-bucket",
			object:      "test-object",
			action:      DeleteObjectAction,
			expectAllow: true,
			description: "User with multiple roles should have delete access",
		},
		{
			name:        "Explicit deny overrides allow",
			userID:      testUser3,
			bucket:      "restricted-bucket",
			object:      "test-object",
			action:      GetObjectAction,
			expectAllow: false,
			description: "Explicit deny should override allow permissions",
		},
		{
			name:        "Access to non-restricted bucket with deny role",
			userID:      testUser3,
			bucket:      "test-bucket",
			object:      "test-object",
			action:      GetObjectAction,
			expectAllow: true,
			description: "Deny role should not affect access to non-restricted resources",
		},
		{
			name:        "No access to unknown bucket",
			userID:      testUser1,
			bucket:      "unknown-bucket",
			object:      "test-object",
			action:      GetObjectAction,
			expectAllow: false,
			description: "User should not have access to resources not covered by roles",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			opts := AccessOptions{
				RoleManager: roleManager,
				IsRoot:      false,
				Acc: Account{
					Access: tt.userID,
					Role:   RoleUser,
				},
				Bucket: tt.bucket,
				Object: tt.object,
				Action: tt.action,
			}
			
			err := VerifyAccess(ctx, mockBackend, opts)
			
			if tt.expectAllow {
				if err != nil {
					t.Errorf("Expected access to be allowed but got error: %v. %s", err, tt.description)
				}
			} else {
				if err == nil {
					t.Errorf("Expected access to be denied but got no error. %s", tt.description)
				}
			}
		})
	}
}

func TestPermissionAggregationFromMultipleRoles(t *testing.T) {
	roleManager := NewInMemoryRoleManager()
	
	// Create roles with different permissions
	role1 := &EnhancedRole{
		ID:          "aggregation-role-1",
		Name:        "Aggregation Role 1",
		Description: "First role for aggregation testing",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::bucket1/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "arn:aws:s3:::bucket1",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	role2 := &EnhancedRole{
		ID:          "aggregation-role-2",
		Name:        "Aggregation Role 2",
		Description: "Second role for aggregation testing",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::bucket2/*",
				Action:   "s3:PutObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "arn:aws:s3:::bucket1/*",
				Action:   "s3:DeleteObject",
				Effect:   PermissionAllow,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	role3 := &EnhancedRole{
		ID:          "aggregation-role-3",
		Name:        "Aggregation Role 3",
		Description: "Third role with deny permission",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::bucket1/restricted/*",
				Action:   "s3:*",
				Effect:   PermissionDeny,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	// Create roles
	for _, role := range []*EnhancedRole{role1, role2, role3} {
		if err := roleManager.CreateRole(role); err != nil {
			t.Fatalf("Failed to create role %s: %v", role.ID, err)
		}
	}
	
	testUser := "aggregation-test-user"
	
	// Assign all roles to user
	for _, roleID := range []string{"aggregation-role-1", "aggregation-role-2", "aggregation-role-3"} {
		if err := roleManager.AssignRole(testUser, roleID, "admin"); err != nil {
			t.Fatalf("Failed to assign role %s: %v", roleID, err)
		}
	}
	
	// Test aggregated permissions
	tests := []struct {
		name        string
		bucket      string
		object      string
		action      Action
		expectAllow bool
		description string
	}{
		{
			name:        "Permission from role 1",
			bucket:      "bucket1",
			object:      "test-object",
			action:      GetObjectAction,
			expectAllow: true,
			description: "Should have GetObject permission from role 1",
		},
		{
			name:        "Permission from role 2",
			bucket:      "bucket2",
			object:      "test-object",
			action:      PutObjectAction,
			expectAllow: true,
			description: "Should have PutObject permission from role 2",
		},
		{
			name:        "Combined permissions",
			bucket:      "bucket1",
			object:      "test-object",
			action:      DeleteObjectAction,
			expectAllow: true,
			description: "Should have DeleteObject permission from role 2 on bucket1",
		},
		{
			name:        "List bucket permission",
			bucket:      "bucket1",
			object:      "",
			action:      ListBucketAction,
			expectAllow: true,
			description: "Should have ListBucket permission from role 1",
		},
		{
			name:        "Deny overrides allow",
			bucket:      "bucket1",
			object:      "restricted/file.txt",
			action:      GetObjectAction,
			expectAllow: false,
			description: "Deny permission should override allow permission",
		},
		{
			name:        "No permission for unspecified action",
			bucket:      "bucket1",
			object:      "test-object",
			action:      PutObjectAction,
			expectAllow: false,
			description: "Should not have PutObject permission on bucket1",
		},
		{
			name:        "No permission for unspecified bucket",
			bucket:      "bucket3",
			object:      "test-object",
			action:      GetObjectAction,
			expectAllow: false,
			description: "Should not have any permission on bucket3",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := verifyEnhancedRoleAccessWithAggregation(roleManager, testUser, tt.bucket, tt.object, tt.action)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			if allowed != tt.expectAllow {
				t.Errorf("Expected allowed=%v but got %v. %s", tt.expectAllow, allowed, tt.description)
			}
		})
	}
}

func TestEnhancedAccessCheckerIntegration(t *testing.T) {
	mockBackend := NewMockBackend()
	roleManager := NewInMemoryRoleManager()
	
	// Create test role
	testRole := &EnhancedRole{
		ID:          "checker-test-role",
		Name:        "Checker Test Role",
		Description: "Role for testing EnhancedAccessChecker",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::allowed-bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "arn:aws:s3:::allowed-bucket",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	if err := roleManager.CreateRole(testRole); err != nil {
		t.Fatalf("Failed to create test role: %v", err)
	}
	
	testUser := "checker-test-user"
	if err := roleManager.AssignRole(testUser, "checker-test-role", "admin"); err != nil {
		t.Fatalf("Failed to assign role: %v", err)
	}
	
	// Create enhanced access checker
	checker := NewEnhancedAccessChecker(roleManager, mockBackend)
	
	tests := []struct {
		name        string
		opts        AccessOptions
		expectError bool
		description string
	}{
		{
			name: "Allowed access through enhanced checker",
			opts: AccessOptions{
				IsRoot: false,
				Acc: Account{
					Access: testUser,
					Role:   RoleUser,
				},
				Bucket: "allowed-bucket",
				Object: "test-object",
				Action: GetObjectAction,
			},
			expectError: false,
			description: "Should allow access to permitted resource",
		},
		{
			name: "Denied access through enhanced checker",
			opts: AccessOptions{
				IsRoot: false,
				Acc: Account{
					Access: testUser,
					Role:   RoleUser,
				},
				Bucket: "denied-bucket",
				Object: "test-object",
				Action: GetObjectAction,
			},
			expectError: true,
			description: "Should deny access to non-permitted resource",
		},
		{
			name: "Root user bypass",
			opts: AccessOptions{
				IsRoot: true,
				Acc: Account{
					Access: testUser,
					Role:   RoleUser,
				},
				Bucket: "any-bucket",
				Object: "test-object",
				Action: GetObjectAction,
			},
			expectError: false,
			description: "Root user should bypass all checks",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := checker.CheckAccess(ctx, tt.opts)
			
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none. %s", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v. %s", err, tt.description)
			}
		})
	}
	
	// Test specific permission checking
	t.Run("CheckSpecificPermission", func(t *testing.T) {
		allowed, err := checker.CheckSpecificPermission(testUser, "allowed-bucket", "test-object", GetObjectAction)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !allowed {
			t.Error("Expected permission to be allowed")
		}
		
		allowed, err = checker.CheckSpecificPermission(testUser, "denied-bucket", "test-object", GetObjectAction)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if allowed {
			t.Error("Expected permission to be denied")
		}
	})
	
	// Test user permissions retrieval
	t.Run("GetUserPermissions", func(t *testing.T) {
		permissions, err := checker.GetUserPermissions(testUser)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if permissions == nil {
			t.Error("Expected permissions to be returned")
		}
		if len(permissions.Permissions) == 0 {
			t.Error("Expected non-empty permissions")
		}
	})
}

func TestComplexRoleHierarchyAccess(t *testing.T) {
	roleManager := NewInMemoryRoleManager()
	
	// Create a hierarchy of roles
	baseRole := &EnhancedRole{
		ID:          "base-role",
		Name:        "Base Role",
		Description: "Base role with basic permissions",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::*",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	readRole := &EnhancedRole{
		ID:          "read-role",
		Name:        "Read Role",
		Description: "Role with read permissions",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::*/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
		ParentRoles: []string{"base-role"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	writeRole := &EnhancedRole{
		ID:          "write-role",
		Name:        "Write Role",
		Description: "Role with write permissions",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::*/*",
				Action:   "s3:PutObject",
				Effect:   PermissionAllow,
			},
		},
		ParentRoles: []string{"read-role"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	// Create roles in order
	for _, role := range []*EnhancedRole{baseRole, readRole, writeRole} {
		if err := roleManager.CreateRole(role); err != nil {
			t.Fatalf("Failed to create role %s: %v", role.ID, err)
		}
	}
	
	testUser := "hierarchy-test-user"
	
	// Assign only the top-level role
	if err := roleManager.AssignRole(testUser, "write-role", "admin"); err != nil {
		t.Fatalf("Failed to assign role: %v", err)
	}
	
	// Test that user has permissions from all roles in hierarchy
	tests := []struct {
		name        string
		bucket      string
		object      string
		action      Action
		expectAllow bool
		description string
	}{
		{
			name:        "Permission from base role",
			bucket:      "test-bucket",
			object:      "",
			action:      ListBucketAction,
			expectAllow: true,
			description: "Should inherit ListBucket permission from base role",
		},
		{
			name:        "Permission from read role",
			bucket:      "test-bucket",
			object:      "test-object",
			action:      GetObjectAction,
			expectAllow: true,
			description: "Should inherit GetObject permission from read role",
		},
		{
			name:        "Permission from write role",
			bucket:      "test-bucket",
			object:      "test-object",
			action:      PutObjectAction,
			expectAllow: true,
			description: "Should have PutObject permission from write role",
		},
		{
			name:        "No permission for unspecified action",
			bucket:      "test-bucket",
			object:      "test-object",
			action:      DeleteObjectAction,
			expectAllow: false,
			description: "Should not have DeleteObject permission",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := verifyEnhancedRoleAccessWithAggregation(roleManager, testUser, tt.bucket, tt.object, tt.action)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			if allowed != tt.expectAllow {
				t.Errorf("Expected allowed=%v but got %v. %s", tt.expectAllow, allowed, tt.description)
			}
		})
	}
}

func TestFallbackToTraditionalAccessControl(t *testing.T) {
	mockBackend := NewMockBackend()
	
	// Test without role manager (should fall back to traditional methods)
	tests := []struct {
		name        string
		opts        AccessOptions
		expectError bool
		description string
	}{
		{
			name: "Root user access",
			opts: AccessOptions{
				IsRoot: true,
				Acc: Account{
					Access: "root-user",
					Role:   RoleAdmin,
				},
				Bucket: "test-bucket",
				Object: "test-object",
				Action: GetObjectAction,
			},
			expectError: false,
			description: "Root user should have access without role manager",
		},
		{
			name: "Admin user access",
			opts: AccessOptions{
				IsRoot: false,
				Acc: Account{
					Access: "admin-user",
					Role:   RoleAdmin,
				},
				Bucket: "test-bucket",
				Object: "test-object",
				Action: GetObjectAction,
			},
			expectError: false,
			description: "Admin user should have access without role manager",
		},
		{
			name: "Regular user without permissions",
			opts: AccessOptions{
				IsRoot: false,
				Acc: Account{
					Access: "regular-user",
					Role:   RoleUser,
				},
				Bucket: "test-bucket",
				Object: "test-object",
				Action: GetObjectAction,
				Acl: ACL{
					Owner:    "other-user",
					Grantees: []Grantee{},
				},
			},
			expectError: true,
			description: "Regular user should be denied without proper ACL or role permissions",
		},
		{
			name: "Public bucket access",
			opts: AccessOptions{
				IsRoot:         false,
				IsBucketPublic: true,
				Acc: Account{
					Access: "regular-user",
					Role:   RoleUser,
				},
				Bucket: "public-bucket",
				Object: "test-object",
				Action: GetObjectAction,
			},
			expectError: false,
			description: "Public bucket should allow access without role manager",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := VerifyAccess(ctx, mockBackend, tt.opts)
			
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none. %s", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v. %s", err, tt.description)
			}
		})
	}
}

func TestAccessControlErrorHandling(t *testing.T) {
	mockBackend := NewMockBackend()
	roleManager := NewInMemoryRoleManager()
	
	// Test with non-existent user
	t.Run("NonExistentUser", func(t *testing.T) {
		ctx := context.Background()
		opts := AccessOptions{
			RoleManager: roleManager,
			IsRoot:      false,
			Acc: Account{
				Access: "non-existent-user",
				Role:   RoleUser,
			},
			Bucket: "test-bucket",
			Object: "test-object",
			Action: GetObjectAction,
		}
		
		err := VerifyAccess(ctx, mockBackend, opts)
		// Should fall back to traditional access control and deny access
		if err == nil {
			t.Error("Expected access to be denied for non-existent user")
		}
		
		// Verify it's an access denied error
		if !errors.Is(err, s3err.GetAPIError(s3err.ErrAccessDenied)) {
			t.Errorf("Expected access denied error, got: %v", err)
		}
	})
	
	// Test with user that has no roles
	t.Run("UserWithNoRoles", func(t *testing.T) {
		ctx := context.Background()
		opts := AccessOptions{
			RoleManager: roleManager,
			IsRoot:      false,
			Acc: Account{
				Access: "user-with-no-roles",
				Role:   RoleUser,
			},
			Bucket: "test-bucket",
			Object: "test-object",
			Action: GetObjectAction,
		}
		
		err := VerifyAccess(ctx, mockBackend, opts)
		// Should deny access since user has no roles
		if err == nil {
			t.Error("Expected access to be denied for user with no roles")
		}
	})
}