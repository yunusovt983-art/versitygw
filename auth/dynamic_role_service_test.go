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

// MockRoleChangeListener implements RoleChangeListener for testing
type MockRoleChangeListener struct {
	events []RoleChangeEvent
}

func (m *MockRoleChangeListener) OnRoleChange(event *RoleChangeEvent) error {
	m.events = append(m.events, *event)
	return nil
}

func (m *MockRoleChangeListener) GetEvents() []RoleChangeEvent {
	return m.events
}

func (m *MockRoleChangeListener) Reset() {
	m.events = []RoleChangeEvent{}
}

func TestDynamicRoleService_AssignRoleWithPropagation(t *testing.T) {
	// Setup
	roleManager := NewInMemoryRoleManager()
	cache := NewEnhancedCache(DefaultEnhancedCacheConfig())
	sessionManager := NewInMemorySessionManager(cache)
	
	service := NewDynamicRoleService(roleManager, sessionManager, cache, DefaultDynamicRoleServiceConfig())
	defer service.Shutdown()

	// Create a test role
	testRole := &EnhancedRole{
		ID:          "test-role",
		Name:        "Test Role",
		Description: "A test role",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}
	
	err := roleManager.CreateRole(testRole)
	if err != nil {
		t.Fatalf("Failed to create test role: %v", err)
	}

	// Create a test session for the user
	userID := "test-user"
	session, err := sessionManager.CreateSession(userID, map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Add a mock listener
	listener := &MockRoleChangeListener{}
	service.AddListener(listener)

	// Test role assignment with propagation
	err = service.AssignRoleWithPropagation(userID, "test-role", "admin")
	if err != nil {
		t.Fatalf("Failed to assign role with propagation: %v", err)
	}

	// Give some time for event processing
	time.Sleep(100 * time.Millisecond)

	// Verify the role was assigned
	userRoles, err := roleManager.GetUserRoles(userID)
	if err != nil {
		t.Fatalf("Failed to get user roles: %v", err)
	}

	if len(userRoles) != 1 || userRoles[0].ID != "test-role" {
		t.Errorf("Expected user to have test-role assigned, got: %v", userRoles)
	}

	// Verify the listener received the event
	events := listener.GetEvents()
	if len(events) != 1 {
		t.Errorf("Expected 1 role change event, got: %d", len(events))
	}

	if len(events) > 0 {
		event := events[0]
		if event.Type != RoleAssigned {
			t.Errorf("Expected RoleAssigned event, got: %v", event.Type)
		}
		if event.UserID != userID {
			t.Errorf("Expected event for user %s, got: %s", userID, event.UserID)
		}
		if event.RoleID != "test-role" {
			t.Errorf("Expected event for role test-role, got: %s", event.RoleID)
		}
	}

	// Verify session was updated
	updatedSession, err := sessionManager.GetSession(session.ID)
	if err != nil {
		t.Fatalf("Failed to get updated session: %v", err)
	}

	updates, err := sessionManager.GetSessionUpdates(updatedSession.ID)
	if err != nil {
		t.Fatalf("Failed to get session updates: %v", err)
	}

	if len(updates) == 0 {
		t.Error("Expected session to have pending updates")
	}
}

func TestDynamicRoleService_RevokeRoleWithPropagation(t *testing.T) {
	// Setup
	roleManager := NewInMemoryRoleManager()
	cache := NewEnhancedCache(DefaultEnhancedCacheConfig())
	sessionManager := NewInMemorySessionManager(cache)
	
	service := NewDynamicRoleService(roleManager, sessionManager, cache, DefaultDynamicRoleServiceConfig())
	defer service.Shutdown()

	// Create and assign a test role
	testRole := &EnhancedRole{
		ID:          "test-role",
		Name:        "Test Role",
		Description: "A test role",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}
	
	err := roleManager.CreateRole(testRole)
	if err != nil {
		t.Fatalf("Failed to create test role: %v", err)
	}

	userID := "test-user"
	err = roleManager.AssignRole(userID, "test-role", "admin")
	if err != nil {
		t.Fatalf("Failed to assign test role: %v", err)
	}

	// Create a test session
	session, err := sessionManager.CreateSession(userID, map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Add a mock listener
	listener := &MockRoleChangeListener{}
	service.AddListener(listener)

	// Test role revocation with propagation
	err = service.RevokeRoleWithPropagation(userID, "test-role")
	if err != nil {
		t.Fatalf("Failed to revoke role with propagation: %v", err)
	}

	// Give some time for event processing
	time.Sleep(100 * time.Millisecond)

	// Verify the role was revoked
	userRoles, err := roleManager.GetUserRoles(userID)
	if err != nil {
		t.Fatalf("Failed to get user roles: %v", err)
	}

	if len(userRoles) != 0 {
		t.Errorf("Expected user to have no roles, got: %v", userRoles)
	}

	// Verify the listener received the event
	events := listener.GetEvents()
	if len(events) != 1 {
		t.Errorf("Expected 1 role change event, got: %d", len(events))
	}

	if len(events) > 0 {
		event := events[0]
		if event.Type != RoleRevoked {
			t.Errorf("Expected RoleRevoked event, got: %v", event.Type)
		}
		if event.UserID != userID {
			t.Errorf("Expected event for user %s, got: %s", userID, event.UserID)
		}
		if event.RoleID != "test-role" {
			t.Errorf("Expected event for role test-role, got: %s", event.RoleID)
		}
	}

	// Verify session was updated
	updates, err := sessionManager.GetSessionUpdates(session.ID)
	if err != nil {
		t.Fatalf("Failed to get session updates: %v", err)
	}

	if len(updates) == 0 {
		t.Error("Expected session to have pending updates")
	}
}

func TestRoleConflictResolver_ResolvePermissionConflicts(t *testing.T) {
	resolver := NewRoleConflictResolver()

	// Create roles with conflicting permissions
	role1 := &EnhancedRole{
		ID:   "role1",
		Name: "Role 1",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/test",
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
				Resource: "bucket/test",
				Action:   "s3:GetObject",
				Effect:   PermissionDeny,
			},
		},
	}

	roles := []*EnhancedRole{role1, role2}

	// Test conflict resolution - deny should win
	resolved, err := resolver.ResolvePermissionConflicts(roles)
	if err != nil {
		t.Fatalf("Failed to resolve permission conflicts: %v", err)
	}

	if len(resolved) != 1 {
		t.Errorf("Expected 1 resolved permission, got: %d", len(resolved))
	}

	if len(resolved) > 0 {
		perm := resolved[0]
		if perm.Effect != PermissionDeny {
			t.Errorf("Expected DENY effect due to conflict resolution, got: %v", perm.Effect)
		}
		if perm.Resource != "bucket/test" {
			t.Errorf("Expected resource bucket/test, got: %s", perm.Resource)
		}
		if perm.Action != "s3:GetObject" {
			t.Errorf("Expected action s3:GetObject, got: %s", perm.Action)
		}
	}
}

func TestRoleConflictResolver_NoConflicts(t *testing.T) {
	resolver := NewRoleConflictResolver()

	// Create roles with non-conflicting permissions
	role1 := &EnhancedRole{
		ID:   "role1",
		Name: "Role 1",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/test1",
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
				Resource: "bucket/test2",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}

	roles := []*EnhancedRole{role1, role2}

	// Test no conflicts - both permissions should be preserved
	resolved, err := resolver.ResolvePermissionConflicts(roles)
	if err != nil {
		t.Fatalf("Failed to resolve permission conflicts: %v", err)
	}

	if len(resolved) != 2 {
		t.Errorf("Expected 2 resolved permissions, got: %d", len(resolved))
	}

	// Verify both permissions are present
	resourceMap := make(map[string]PermissionEffect)
	for _, perm := range resolved {
		resourceMap[perm.Resource] = perm.Effect
	}

	if effect, exists := resourceMap["bucket/test1"]; !exists || effect != PermissionAllow {
		t.Error("Expected bucket/test1 to have ALLOW permission")
	}

	if effect, exists := resourceMap["bucket/test2"]; !exists || effect != PermissionAllow {
		t.Error("Expected bucket/test2 to have ALLOW permission")
	}
}

func TestDynamicRoleService_GetEffectivePermissionsWithConflictResolution(t *testing.T) {
	// Setup
	roleManager := NewInMemoryRoleManager()
	cache := NewEnhancedCache(DefaultEnhancedCacheConfig())
	sessionManager := NewInMemorySessionManager(cache)
	
	service := NewDynamicRoleService(roleManager, sessionManager, cache, DefaultDynamicRoleServiceConfig())
	defer service.Shutdown()

	// Create conflicting roles
	role1 := &EnhancedRole{
		ID:   "allow-role",
		Name: "Allow Role",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/test",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}

	role2 := &EnhancedRole{
		ID:   "deny-role",
		Name: "Deny Role",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/test",
				Action:   "s3:GetObject",
				Effect:   PermissionDeny,
			},
		},
	}

	err := roleManager.CreateRole(role1)
	if err != nil {
		t.Fatalf("Failed to create allow role: %v", err)
	}

	err = roleManager.CreateRole(role2)
	if err != nil {
		t.Fatalf("Failed to create deny role: %v", err)
	}

	// Assign both roles to user
	userID := "test-user"
	err = roleManager.AssignRole(userID, "allow-role", "admin")
	if err != nil {
		t.Fatalf("Failed to assign allow role: %v", err)
	}

	err = roleManager.AssignRole(userID, "deny-role", "admin")
	if err != nil {
		t.Fatalf("Failed to assign deny role: %v", err)
	}

	// Get effective permissions with conflict resolution
	permissions, err := service.GetEffectivePermissionsWithConflictResolution(userID)
	if err != nil {
		t.Fatalf("Failed to get effective permissions: %v", err)
	}

	// Verify deny wins in conflict resolution
	hasPermission := permissions.HasPermission("bucket/test", "s3:GetObject")
	if hasPermission {
		t.Error("Expected permission to be denied due to conflict resolution")
	}

	// Test the CheckPermission method as well
	allowed, err := service.CheckPermissionWithConflictResolution(userID, "bucket/test", "s3:GetObject")
	if err != nil {
		t.Fatalf("Failed to check permission: %v", err)
	}

	if allowed {
		t.Error("Expected permission to be denied due to conflict resolution")
	}
}

func TestDynamicRoleService_UpdateRoleWithPropagation(t *testing.T) {
	// Setup
	roleManager := NewInMemoryRoleManager()
	cache := NewEnhancedCache(DefaultEnhancedCacheConfig())
	sessionManager := NewInMemorySessionManager(cache)
	
	service := NewDynamicRoleService(roleManager, sessionManager, cache, DefaultDynamicRoleServiceConfig())
	defer service.Shutdown()

	// Create a test role
	testRole := &EnhancedRole{
		ID:          "test-role",
		Name:        "Test Role",
		Description: "Original description",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}
	
	err := roleManager.CreateRole(testRole)
	if err != nil {
		t.Fatalf("Failed to create test role: %v", err)
	}

	// Assign role to user
	userID := "test-user"
	err = roleManager.AssignRole(userID, "test-role", "admin")
	if err != nil {
		t.Fatalf("Failed to assign test role: %v", err)
	}

	// Create a test session
	_, err = sessionManager.CreateSession(userID, map[string]interface{}{})
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}

	// Add a mock listener
	listener := &MockRoleChangeListener{}
	service.AddListener(listener)

	// Update the role
	newDescription := "Updated description"
	updates := &RoleUpdates{
		Description: &newDescription,
	}

	err = service.UpdateRoleWithPropagation("test-role", updates)
	if err != nil {
		t.Fatalf("Failed to update role with propagation: %v", err)
	}

	// Give some time for event processing
	time.Sleep(100 * time.Millisecond)

	// Verify the role was updated
	updatedRole, err := roleManager.GetRole("test-role")
	if err != nil {
		t.Fatalf("Failed to get updated role: %v", err)
	}

	if updatedRole.Description != "Updated description" {
		t.Errorf("Expected role description to be updated, got: %s", updatedRole.Description)
	}

	// Verify the listener received the event
	events := listener.GetEvents()
	if len(events) != 1 {
		t.Errorf("Expected 1 role change event, got: %d", len(events))
	}

	if len(events) > 0 {
		event := events[0]
		if event.Type != RoleUpdated {
			t.Errorf("Expected RoleUpdated event, got: %v", event.Type)
		}
		if event.UserID != userID {
			t.Errorf("Expected event for user %s, got: %s", userID, event.UserID)
		}
		if event.RoleID != "test-role" {
			t.Errorf("Expected event for role test-role, got: %s", event.RoleID)
		}
	}
}