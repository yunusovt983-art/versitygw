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

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
)

// MockBackend provides a mock implementation of backend.Backend for testing
type MockBackend struct {
	backend.BackendUnsupported
	bucketPolicies map[string][]byte
	bucketACLs     map[string][]byte
}

func NewMockBackend() *MockBackend {
	return &MockBackend{
		bucketPolicies: make(map[string][]byte),
		bucketACLs:     make(map[string][]byte),
	}
}

func (mb *MockBackend) GetBucketPolicy(ctx context.Context, bucket string) ([]byte, error) {
	if policy, exists := mb.bucketPolicies[bucket]; exists {
		return policy, nil
	}
	return nil, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)
}

func (mb *MockBackend) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) ([]byte, error) {
	bucket := *input.Bucket
	if acl, exists := mb.bucketACLs[bucket]; exists {
		return acl, nil
	}
	return []byte(`{"owner":"test-user","grants":[]}`), nil
}

func (mb *MockBackend) SetBucketPolicy(bucket string, policy []byte) {
	mb.bucketPolicies[bucket] = policy
}

func (mb *MockBackend) SetBucketACL(bucket string, acl []byte) {
	mb.bucketACLs[bucket] = acl
}

func (mb *MockBackend) String() string { return "mock-backend" }

func TestVerifyEnhancedRoleAccess(t *testing.T) {
	// Create a role manager with test roles
	roleManager := NewInMemoryRoleManager()
	
	// Create test roles
	readOnlyRole := &EnhancedRole{
		ID:          "test-read-only",
		Name:        "Test Read Only",
		Description: "Read-only access for testing",
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
		ID:          "test-write",
		Name:        "Test Write",
		Description: "Write access for testing",
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
		ID:          "test-deny",
		Name:        "Test Deny",
		Description: "Explicit deny for testing",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::test-bucket/secret/*",
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
	
	// Assign roles to test users
	testUser1 := "user1"
	testUser2 := "user2"
	testUser3 := "user3"
	
	if err := roleManager.AssignRole(testUser1, "test-read-only", "admin"); err != nil {
		t.Fatalf("Failed to assign read-only role to user1: %v", err)
	}
	if err := roleManager.AssignRole(testUser2, "test-write", "admin"); err != nil {
		t.Fatalf("Failed to assign write role to user2: %v", err)
	}
	if err := roleManager.AssignRole(testUser2, "test-read-only", "admin"); err != nil {
		t.Fatalf("Failed to assign read-only role to user2: %v", err)
	}
	if err := roleManager.AssignRole(testUser3, "test-deny", "admin"); err != nil {
		t.Fatalf("Failed to assign deny role to user3: %v", err)
	}
	
	tests := []struct {
		name     string
		userID   string
		bucket   string
		object   string
		action   Action
		expected bool
	}{
		{
			name:     "User1 can read objects",
			userID:   testUser1,
			bucket:   "test-bucket",
			object:   "test-object",
			action:   GetObjectAction,
			expected: true,
		},
		{
			name:     "User1 can list bucket",
			userID:   testUser1,
			bucket:   "test-bucket",
			object:   "",
			action:   ListBucketAction,
			expected: true,
		},
		{
			name:     "User1 cannot write objects",
			userID:   testUser1,
			bucket:   "test-bucket",
			object:   "test-object",
			action:   PutObjectAction,
			expected: false,
		},
		{
			name:     "User2 can read and write objects",
			userID:   testUser2,
			bucket:   "test-bucket",
			object:   "test-object",
			action:   GetObjectAction,
			expected: true,
		},
		{
			name:     "User2 can write objects",
			userID:   testUser2,
			bucket:   "test-bucket",
			object:   "test-object",
			action:   PutObjectAction,
			expected: true,
		},
		{
			name:     "User2 can delete objects",
			userID:   testUser2,
			bucket:   "test-bucket",
			object:   "test-object",
			action:   DeleteObjectAction,
			expected: true,
		},
		{
			name:     "User3 is denied access to secret objects",
			userID:   testUser3,
			bucket:   "test-bucket",
			object:   "secret/file.txt",
			action:   GetObjectAction,
			expected: false,
		},
		{
			name:     "User3 is denied write access to secret objects",
			userID:   testUser3,
			bucket:   "test-bucket",
			object:   "secret/file.txt",
			action:   PutObjectAction,
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := verifyEnhancedRoleAccess(roleManager, tt.userID, tt.bucket, tt.object, tt.action)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if allowed != tt.expected {
				t.Errorf("Expected %v, got %v for user %s accessing %s/%s with action %s",
					tt.expected, allowed, tt.userID, tt.bucket, tt.object, tt.action)
			}
		})
	}
}

func TestBuildResourceARN(t *testing.T) {
	tests := []struct {
		name     string
		bucket   string
		object   string
		expected string
	}{
		{
			name:     "Bucket only",
			bucket:   "test-bucket",
			object:   "",
			expected: "arn:aws:s3:::test-bucket",
		},
		{
			name:     "Bucket and object",
			bucket:   "test-bucket",
			object:   "test-object",
			expected: "arn:aws:s3:::test-bucket/test-object",
		},
		{
			name:     "Bucket and nested object",
			bucket:   "test-bucket",
			object:   "folder/subfolder/file.txt",
			expected: "arn:aws:s3:::test-bucket/folder/subfolder/file.txt",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildResourceARN(tt.bucket, tt.object)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestVerifyAccessWithRoles(t *testing.T) {
	ctx := context.Background()
	mockBackend := NewMockBackend()
	roleManager := NewInMemoryRoleManager()
	
	// Create a test role
	testRole := &EnhancedRole{
		ID:          "test-access-role",
		Name:        "Test Access Role",
		Description: "Role for access testing",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::allowed-bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "arn:aws:s3:::denied-bucket/*",
				Action:   "s3:*",
				Effect:   PermissionDeny,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	if err := roleManager.CreateRole(testRole); err != nil {
		t.Fatalf("Failed to create test role: %v", err)
	}
	
	testUser := "test-user"
	if err := roleManager.AssignRole(testUser, "test-access-role", "admin"); err != nil {
		t.Fatalf("Failed to assign role to test user: %v", err)
	}
	
	tests := []struct {
		name        string
		opts        AccessOptions
		expectError bool
	}{
		{
			name: "Root user access",
			opts: AccessOptions{
				IsRoot: true,
				Bucket: "any-bucket",
				Object: "any-object",
				Action: GetObjectAction,
			},
			expectError: false,
		},
		{
			name: "Admin role access",
			opts: AccessOptions{
				Acc: Account{
					Access: testUser,
					Role:   RoleAdmin,
				},
				Bucket: "any-bucket",
				Object: "any-object",
				Action: GetObjectAction,
			},
			expectError: false,
		},
		{
			name: "Public bucket access",
			opts: AccessOptions{
				IsBucketPublic: true,
				Bucket:         "public-bucket",
				Object:         "public-object",
				Action:         GetObjectAction,
			},
			expectError: false,
		},
		{
			name: "Enhanced role allowed access",
			opts: AccessOptions{
				Acc: Account{
					Access: testUser,
					Role:   RoleUser,
				},
				Bucket:      "allowed-bucket",
				Object:      "test-object",
				Action:      GetObjectAction,
				RoleManager: roleManager,
			},
			expectError: false,
		},
		{
			name: "Enhanced role denied access",
			opts: AccessOptions{
				Acc: Account{
					Access: testUser,
					Role:   RoleUser,
				},
				Bucket:      "denied-bucket",
				Object:      "test-object",
				Action:      GetObjectAction,
				RoleManager: roleManager,
			},
			expectError: true,
		},
		{
			name: "No permission for action",
			opts: AccessOptions{
				Acc: Account{
					Access: testUser,
					Role:   RoleUser,
				},
				Bucket:      "allowed-bucket",
				Object:      "test-object",
				Action:      PutObjectAction, // Not allowed by the role
				RoleManager: roleManager,
			},
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyAccess(ctx, mockBackend, tt.opts)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestAggregatePermissionsFromRoles(t *testing.T) {
	// Create test roles with different permissions
	role1 := &EnhancedRole{
		ID:   "role1",
		Name: "Role 1",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::bucket1/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "arn:aws:s3:::bucket1/*",
				Action:   "s3:PutObject",
				Effect:   PermissionAllow,
			},
		},
	}
	
	role2 := &EnhancedRole{
		ID:   "role2",
		Name: "Role 2",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::bucket2/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "arn:aws:s3:::bucket1/*",
				Action:   "s3:DeleteObject",
				Effect:   PermissionAllow,
			},
		},
	}
	
	role3 := &EnhancedRole{
		ID:   "role3",
		Name: "Role 3 (Deny)",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::bucket1/secret/*",
				Action:   "s3:*",
				Effect:   PermissionDeny,
			},
		},
	}
	
	roles := []*EnhancedRole{role1, role2, role3}
	permissionSet := AggregatePermissionsFromRoles(roles)
	
	// Test aggregated permissions
	tests := []struct {
		name     string
		resource string
		action   string
		expected bool
	}{
		{
			name:     "Allow GetObject from role1",
			resource: "arn:aws:s3:::bucket1/file.txt",
			action:   "s3:GetObject",
			expected: true,
		},
		{
			name:     "Allow PutObject from role1",
			resource: "arn:aws:s3:::bucket1/file.txt",
			action:   "s3:PutObject",
			expected: true,
		},
		{
			name:     "Allow DeleteObject from role2",
			resource: "arn:aws:s3:::bucket1/file.txt",
			action:   "s3:DeleteObject",
			expected: true,
		},
		{
			name:     "Allow GetObject from role2",
			resource: "arn:aws:s3:::bucket2/file.txt",
			action:   "s3:GetObject",
			expected: true,
		},
		{
			name:     "Deny access to secret files (role3 deny wins)",
			resource: "arn:aws:s3:::bucket1/secret/file.txt",
			action:   "s3:GetObject",
			expected: false,
		},
		{
			name:     "Deny write to secret files (role3 deny wins)",
			resource: "arn:aws:s3:::bucket1/secret/file.txt",
			action:   "s3:PutObject",
			expected: false,
		},
		{
			name:     "No permission for unspecified action",
			resource: "arn:aws:s3:::bucket3/file.txt",
			action:   "s3:GetObject",
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := permissionSet.HasPermission(tt.resource, tt.action)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for resource %s and action %s",
					tt.expected, result, tt.resource, tt.action)
			}
		})
	}
}

func TestValidateAccessWithMultipleRoles(t *testing.T) {
	// Create roles with overlapping permissions
	readRole := &EnhancedRole{
		ID:   "read-role",
		Name: "Read Role",
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
	}
	
	writeRole := &EnhancedRole{
		ID:   "write-role",
		Name: "Write Role",
		Permissions: []DetailedPermission{
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
		},
	}
	
	restrictRole := &EnhancedRole{
		ID:   "restrict-role",
		Name: "Restriction Role",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::restricted-bucket/*",
				Action:   "s3:*",
				Effect:   PermissionDeny,
			},
		},
	}
	
	tests := []struct {
		name     string
		roles    []*EnhancedRole
		bucket   string
		object   string
		action   Action
		expected bool
	}{
		{
			name:     "No roles - no access",
			roles:    []*EnhancedRole{},
			bucket:   "test-bucket",
			object:   "test-object",
			action:   GetObjectAction,
			expected: false,
		},
		{
			name:     "Read role allows GetObject",
			roles:    []*EnhancedRole{readRole},
			bucket:   "test-bucket",
			object:   "test-object",
			action:   GetObjectAction,
			expected: true,
		},
		{
			name:     "Read role allows ListBucket",
			roles:    []*EnhancedRole{readRole},
			bucket:   "test-bucket",
			object:   "",
			action:   ListBucketAction,
			expected: true,
		},
		{
			name:     "Read role denies PutObject",
			roles:    []*EnhancedRole{readRole},
			bucket:   "test-bucket",
			object:   "test-object",
			action:   PutObjectAction,
			expected: false,
		},
		{
			name:     "Multiple roles allow combined permissions",
			roles:    []*EnhancedRole{readRole, writeRole},
			bucket:   "test-bucket",
			object:   "test-object",
			action:   PutObjectAction,
			expected: true,
		},
		{
			name:     "Deny role overrides allow permissions",
			roles:    []*EnhancedRole{readRole, writeRole, restrictRole},
			bucket:   "restricted-bucket",
			object:   "test-object",
			action:   GetObjectAction,
			expected: false,
		},
		{
			name:     "Deny role overrides write permissions",
			roles:    []*EnhancedRole{readRole, writeRole, restrictRole},
			bucket:   "restricted-bucket",
			object:   "test-object",
			action:   PutObjectAction,
			expected: false,
		},
		{
			name:     "Non-restricted bucket still allows access",
			roles:    []*EnhancedRole{readRole, writeRole, restrictRole},
			bucket:   "normal-bucket",
			object:   "test-object",
			action:   GetObjectAction,
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateAccessWithMultipleRoles(tt.roles, tt.bucket, tt.object, tt.action)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for roles %v accessing %s/%s with action %s",
					tt.expected, result, getRoleNames(tt.roles), tt.bucket, tt.object, tt.action)
			}
		})
	}
}

func TestEnhancedAccessChecker(t *testing.T) {
	mockBackend := NewMockBackend()
	roleManager := NewInMemoryRoleManager()
	
	// Create test role
	testRole := &EnhancedRole{
		ID:          "checker-test-role",
		Name:        "Checker Test Role",
		Description: "Role for testing EnhancedAccessChecker",
		Permissions: []DetailedPermission{
			{
				Resource: "arn:aws:s3:::test-bucket/*",
				Action:   "s3:GetObject",
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
	
	checker := NewEnhancedAccessChecker(roleManager, mockBackend)
	
	// Test CheckAccess
	ctx := context.Background()
	opts := AccessOptions{
		Acc: Account{
			Access: testUser,
			Role:   RoleUser,
		},
		Bucket: "test-bucket",
		Object: "test-object",
		Action: GetObjectAction,
	}
	
	err := checker.CheckAccess(ctx, opts)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	
	// Test GetUserPermissions
	permissions, err := checker.GetUserPermissions(testUser)
	if err != nil {
		t.Errorf("Failed to get user permissions: %v", err)
	}
	if permissions == nil {
		t.Error("Expected permissions, got nil")
	}
	
	// Test CheckSpecificPermission
	allowed, err := checker.CheckSpecificPermission(testUser, "test-bucket", "test-object", GetObjectAction)
	if err != nil {
		t.Errorf("Failed to check specific permission: %v", err)
	}
	if !allowed {
		t.Error("Expected permission to be allowed")
	}
	
	// Test denied permission
	allowed, err = checker.CheckSpecificPermission(testUser, "test-bucket", "test-object", PutObjectAction)
	if err != nil {
		t.Errorf("Failed to check specific permission: %v", err)
	}
	if allowed {
		t.Error("Expected permission to be denied")
	}
}

// Helper function to get role names for test output
func getRoleNames(roles []*EnhancedRole) []string {
	names := make([]string, len(roles))
	for i, role := range roles {
		names[i] = role.Name
	}
	return names
}