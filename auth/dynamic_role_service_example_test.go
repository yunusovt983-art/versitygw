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

func TestExampleRoleChangeListener(t *testing.T) {
	listener := NewExampleRoleChangeListener("TestListener")
	
	event := &RoleChangeEvent{
		Type:      RoleAssigned,
		UserID:    "test-user",
		RoleID:    "test-role",
		Timestamp: time.Now(),
	}
	
	err := listener.OnRoleChange(event)
	if err != nil {
		t.Errorf("Expected no error from listener, got: %v", err)
	}
}

func TestExampleDynamicRoleServiceUsage(t *testing.T) {
	// This test runs the example to ensure it doesn't panic or error
	// In a real scenario, you might want to capture output and verify specific behaviors
	
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ExampleDynamicRoleServiceUsage panicked: %v", r)
		}
	}()
	
	// Run the example - this should complete without errors
	ExampleDynamicRoleServiceUsage()
}

func TestExampleConflictResolution(t *testing.T) {
	// This test runs the conflict resolution example to ensure it works correctly
	
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ExampleConflictResolution panicked: %v", r)
		}
	}()
	
	// Run the example - this should complete without errors
	ExampleConflictResolution()
}

func TestDynamicRoleServiceIntegration(t *testing.T) {
	// Comprehensive integration test
	roleManager := NewInMemoryRoleManager()
	cache := NewEnhancedCache(DefaultEnhancedCacheConfig())
	sessionManager := NewInMemorySessionManager(cache)
	
	service := NewDynamicRoleService(roleManager, sessionManager, cache, DefaultDynamicRoleServiceConfig())
	defer service.Shutdown()
	
	// Create test role
	testRole := &EnhancedRole{
		ID:          "integration-test-role",
		Name:        "Integration Test Role",
		Description: "Role for integration testing",
		Permissions: []DetailedPermission{
			{
				Resource: "test-bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}
	
	err := roleManager.CreateRole(testRole)
	if err != nil {
		t.Fatalf("Failed to create test role: %v", err)
	}
	
	// Create test user and session
	userID := "integration-test-user"
	session, err := sessionManager.CreateSession(userID, map[string]interface{}{
		"test": "integration",
	})
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}
	
	// Test role assignment
	err = service.AssignRoleWithPropagation(userID, "integration-test-role", "test-admin")
	if err != nil {
		t.Fatalf("Failed to assign role: %v", err)
	}
	
	// Give time for event processing
	time.Sleep(100 * time.Millisecond)
	
	// Verify role assignment
	userRoles, err := roleManager.GetUserRoles(userID)
	if err != nil {
		t.Fatalf("Failed to get user roles: %v", err)
	}
	
	if len(userRoles) != 1 || userRoles[0].ID != "integration-test-role" {
		t.Errorf("Expected user to have integration-test-role, got: %v", userRoles)
	}
	
	// Test permission check
	allowed, err := service.CheckPermissionWithConflictResolution(userID, "test-bucket/file.txt", "s3:GetObject")
	if err != nil {
		t.Fatalf("Failed to check permission: %v", err)
	}
	
	if !allowed {
		t.Error("Expected permission to be allowed")
	}
	
	// Test role update
	newDescription := "Updated integration test role"
	updates := &RoleUpdates{
		Description: &newDescription,
	}
	
	err = service.UpdateRoleWithPropagation("integration-test-role", updates)
	if err != nil {
		t.Fatalf("Failed to update role: %v", err)
	}
	
	// Give time for event processing
	time.Sleep(100 * time.Millisecond)
	
	// Verify role update
	updatedRole, err := roleManager.GetRole("integration-test-role")
	if err != nil {
		t.Fatalf("Failed to get updated role: %v", err)
	}
	
	if updatedRole.Description != "Updated integration test role" {
		t.Errorf("Expected role description to be updated, got: %s", updatedRole.Description)
	}
	
	// Test role revocation
	err = service.RevokeRoleWithPropagation(userID, "integration-test-role")
	if err != nil {
		t.Fatalf("Failed to revoke role: %v", err)
	}
	
	// Give time for event processing
	time.Sleep(100 * time.Millisecond)
	
	// Verify role revocation
	userRoles, err = roleManager.GetUserRoles(userID)
	if err != nil {
		t.Fatalf("Failed to get user roles after revocation: %v", err)
	}
	
	if len(userRoles) != 0 {
		t.Errorf("Expected user to have no roles after revocation, got: %v", userRoles)
	}
	
	// Verify session updates were created
	updates_list, err := sessionManager.GetSessionUpdates(session.ID)
	if err != nil {
		t.Fatalf("Failed to get session updates: %v", err)
	}
	
	if len(updates_list) == 0 {
		t.Error("Expected session to have updates after role changes")
	}
}

func TestDynamicRoleServiceWithMultipleUsers(t *testing.T) {
	// Test role updates affecting multiple users
	roleManager := NewInMemoryRoleManager()
	cache := NewEnhancedCache(DefaultEnhancedCacheConfig())
	sessionManager := NewInMemorySessionManager(cache)
	
	service := NewDynamicRoleService(roleManager, sessionManager, cache, DefaultDynamicRoleServiceConfig())
	defer service.Shutdown()
	
	// Create shared role
	sharedRole := &EnhancedRole{
		ID:          "shared-role",
		Name:        "Shared Role",
		Description: "Role shared by multiple users",
		Permissions: []DetailedPermission{
			{
				Resource: "shared/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}
	
	err := roleManager.CreateRole(sharedRole)
	if err != nil {
		t.Fatalf("Failed to create shared role: %v", err)
	}
	
	// Create multiple users and assign the same role
	users := []string{"user1", "user2", "user3"}
	
	for _, userID := range users {
		// Create session for each user
		_, err := sessionManager.CreateSession(userID, map[string]interface{}{
			"user": userID,
		})
		if err != nil {
			t.Fatalf("Failed to create session for user %s: %v", userID, err)
		}
		
		// Assign shared role
		err = service.AssignRoleWithPropagation(userID, "shared-role", "admin")
		if err != nil {
			t.Fatalf("Failed to assign role to user %s: %v", userID, err)
		}
	}
	
	// Give time for event processing
	time.Sleep(100 * time.Millisecond)
	
	// Verify all users have the role
	for _, userID := range users {
		userRoles, err := roleManager.GetUserRoles(userID)
		if err != nil {
			t.Fatalf("Failed to get roles for user %s: %v", userID, err)
		}
		
		if len(userRoles) != 1 || userRoles[0].ID != "shared-role" {
			t.Errorf("Expected user %s to have shared-role, got: %v", userID, userRoles)
		}
	}
	
	// Update the shared role - this should affect all users
	newDescription := "Updated shared role affecting all users"
	updates := &RoleUpdates{
		Description: &newDescription,
	}
	
	err = service.UpdateRoleWithPropagation("shared-role", updates)
	if err != nil {
		t.Fatalf("Failed to update shared role: %v", err)
	}
	
	// Give time for event processing
	time.Sleep(100 * time.Millisecond)
	
	// Verify role was updated
	updatedRole, err := roleManager.GetRole("shared-role")
	if err != nil {
		t.Fatalf("Failed to get updated role: %v", err)
	}
	
	if updatedRole.Description != "Updated shared role affecting all users" {
		t.Errorf("Expected role description to be updated, got: %s", updatedRole.Description)
	}
	
	// Verify all users still have access to the updated role
	for _, userID := range users {
		allowed, err := service.CheckPermissionWithConflictResolution(userID, "shared/file.txt", "s3:GetObject")
		if err != nil {
			t.Fatalf("Failed to check permission for user %s: %v", userID, err)
		}
		
		if !allowed {
			t.Errorf("Expected user %s to have permission after role update", userID)
		}
	}
}