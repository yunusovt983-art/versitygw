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
)

func TestExampleEnhancedRoleSystem(t *testing.T) {
	// This test ensures the example code runs without panicking
	// In a real scenario, you might want to capture output and verify specific behaviors
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ExampleEnhancedRoleSystem panicked: %v", r)
		}
	}()
	
	ExampleEnhancedRoleSystem()
}

func TestExampleRoleComposition(t *testing.T) {
	// This test ensures the role composition example runs without panicking
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ExampleRoleComposition panicked: %v", r)
		}
	}()
	
	ExampleRoleComposition()
}

func TestComplexRoleScenario(t *testing.T) {
	rm := NewInMemoryRoleManager()
	
	// Create a complex scenario with multiple inheritance and conflicts
	
	// Base roles
	readRole := &EnhancedRole{
		ID:   "reader",
		Name: "Reader",
		Permissions: []DetailedPermission{
			{Resource: "*", Action: "s3:GetObject", Effect: PermissionAllow},
			{Resource: "*", Action: "s3:ListBucket", Effect: PermissionAllow},
		},
	}
	
	writeRole := &EnhancedRole{
		ID:   "writer",
		Name: "Writer",
		Permissions: []DetailedPermission{
			{Resource: "*", Action: "s3:PutObject", Effect: PermissionAllow},
			{Resource: "*", Action: "s3:DeleteObject", Effect: PermissionAllow},
		},
	}
	
	// Composite role that inherits from both
	editorRole := &EnhancedRole{
		ID:          "editor",
		Name:        "Editor",
		ParentRoles: []string{"reader", "writer"},
		Permissions: []DetailedPermission{
			// Deny access to sensitive areas
			{Resource: "sensitive/*", Action: "s3:*", Effect: PermissionDeny},
		},
	}
	
	// Create roles
	roles := []*EnhancedRole{readRole, writeRole, editorRole}
	for _, role := range roles {
		if err := rm.CreateRole(role); err != nil {
			t.Fatalf("Failed to create role %s: %v", role.ID, err)
		}
	}
	
	// Assign editor role
	if err := rm.AssignRole("user1", "editor", "admin"); err != nil {
		t.Fatalf("Failed to assign role: %v", err)
	}
	
	// Test permissions
	tests := []struct {
		resource string
		action   string
		expected bool
	}{
		{"public/file.txt", "s3:GetObject", true},    // From reader
		{"public/file.txt", "s3:PutObject", true},    // From writer
		{"public", "s3:ListBucket", true},            // From reader
		{"public/file.txt", "s3:DeleteObject", true}, // From writer
		{"sensitive/secret.txt", "s3:GetObject", false}, // Denied by editor
		{"sensitive/secret.txt", "s3:PutObject", false}, // Denied by editor
	}
	
	for _, test := range tests {
		hasPermission, err := rm.CheckPermission("user1", test.resource, test.action)
		if err != nil {
			t.Errorf("Error checking permission: %v", err)
			continue
		}
		
		if hasPermission != test.expected {
			t.Errorf("Permission check failed for %s on %s: expected %v, got %v",
				test.action, test.resource, test.expected, hasPermission)
		}
	}
	
	// Verify effective permissions include both inherited and direct permissions
	permissions, err := rm.GetEffectivePermissions("user1")
	if err != nil {
		t.Fatalf("Failed to get effective permissions: %v", err)
	}
	
	// Should have permissions from reader, writer, and editor roles
	if len(permissions.Permissions) == 0 {
		t.Error("Expected some effective permissions")
	}
	
	// Verify deny permissions take precedence
	if permissions.HasPermission("sensitive/secret.txt", "s3:GetObject") {
		t.Error("Deny permission should override allow permissions")
	}
}