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
	"time"
)

// ExampleRoleChangeListener demonstrates how to implement a role change listener
type ExampleRoleChangeListener struct {
	name string
}

// NewExampleRoleChangeListener creates a new example listener
func NewExampleRoleChangeListener(name string) *ExampleRoleChangeListener {
	return &ExampleRoleChangeListener{name: name}
}

// OnRoleChange handles role change events
func (l *ExampleRoleChangeListener) OnRoleChange(event *RoleChangeEvent) error {
	fmt.Printf("[%s] Role change event: %s for user %s, role %s at %s\n",
		l.name, event.Type, event.UserID, event.RoleID, event.Timestamp.Format(time.RFC3339))
	
	// Perform custom logic based on event type
	switch event.Type {
	case RoleAssigned:
		fmt.Printf("[%s] User %s was assigned role %s\n", l.name, event.UserID, event.RoleID)
	case RoleRevoked:
		fmt.Printf("[%s] User %s had role %s revoked\n", l.name, event.UserID, event.RoleID)
	case RoleUpdated:
		fmt.Printf("[%s] Role %s was updated, affecting user %s\n", l.name, event.RoleID, event.UserID)
	case RoleDeleted:
		fmt.Printf("[%s] Role %s was deleted, affecting user %s\n", l.name, event.RoleID, event.UserID)
	}
	
	return nil
}

// ExampleDynamicRoleServiceUsage demonstrates how to use the DynamicRoleService
func ExampleDynamicRoleServiceUsage() {
	fmt.Println("=== Dynamic Role Service Example ===")
	
	// 1. Set up the components
	roleManager := NewInMemoryRoleManager()
	cache := NewEnhancedCache(DefaultEnhancedCacheConfig())
	sessionManager := NewInMemorySessionManager(cache)
	
	// 2. Create the dynamic role service
	service := NewDynamicRoleService(roleManager, sessionManager, cache, DefaultDynamicRoleServiceConfig())
	defer service.Shutdown()
	
	// 3. Add listeners for role changes
	auditListener := NewExampleRoleChangeListener("AuditLogger")
	notificationListener := NewExampleRoleChangeListener("NotificationService")
	
	service.AddListener(auditListener)
	service.AddListener(notificationListener)
	
	// 4. Create some test roles
	adminRole := &EnhancedRole{
		ID:          "admin",
		Name:        "Administrator",
		Description: "Full administrative access",
		Permissions: []DetailedPermission{
			{
				Resource: "*",
				Action:   "s3:*",
				Effect:   PermissionAllow,
			},
		},
	}
	
	readOnlyRole := &EnhancedRole{
		ID:          "read-only",
		Name:        "Read Only",
		Description: "Read-only access to all resources",
		Permissions: []DetailedPermission{
			{
				Resource: "*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "*",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
			},
		},
	}
	
	restrictedRole := &EnhancedRole{
		ID:          "restricted",
		Name:        "Restricted Access",
		Description: "Restricted access with explicit denies",
		Permissions: []DetailedPermission{
			{
				Resource: "sensitive/*",
				Action:   "s3:*",
				Effect:   PermissionDeny,
			},
			{
				Resource: "*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}
	
	// Create the roles
	roleManager.CreateRole(adminRole)
	roleManager.CreateRole(readOnlyRole)
	roleManager.CreateRole(restrictedRole)
	
	// 5. Create test users and sessions
	userID := "john.doe"
	session, _ := sessionManager.CreateSession(userID, map[string]interface{}{
		"ip_address": "192.168.1.100",
		"user_agent": "S3Client/1.0",
	})
	
	fmt.Printf("Created session %s for user %s\n", session.ID, userID)
	
	// 6. Demonstrate role assignment with propagation
	fmt.Println("\n--- Assigning Roles ---")
	service.AssignRoleWithPropagation(userID, "read-only", "admin")
	service.AssignRoleWithPropagation(userID, "restricted", "admin")
	
	// Give time for event processing
	time.Sleep(100 * time.Millisecond)
	
	// 7. Check effective permissions with conflict resolution
	fmt.Println("\n--- Checking Permissions ---")
	
	// Test permission for a regular resource
	allowed, _ := service.CheckPermissionWithConflictResolution(userID, "bucket/file.txt", "s3:GetObject")
	fmt.Printf("Permission for 'bucket/file.txt' s3:GetObject: %t\n", allowed)
	
	// Test permission for a sensitive resource (should be denied due to conflict resolution)
	allowed, _ = service.CheckPermissionWithConflictResolution(userID, "sensitive/secret.txt", "s3:GetObject")
	fmt.Printf("Permission for 'sensitive/secret.txt' s3:GetObject: %t (denied due to conflict resolution)\n", allowed)
	
	// 8. Demonstrate role updates with propagation
	fmt.Println("\n--- Updating Role ---")
	newDescription := "Updated read-only role with enhanced permissions"
	updates := &RoleUpdates{
		Description: &newDescription,
	}
	
	service.UpdateRoleWithPropagation("read-only", updates)
	
	// Give time for event processing
	time.Sleep(100 * time.Millisecond)
	
	// 9. Demonstrate role revocation
	fmt.Println("\n--- Revoking Role ---")
	service.RevokeRoleWithPropagation(userID, "restricted")
	
	// Give time for event processing
	time.Sleep(100 * time.Millisecond)
	
	// 10. Check permissions after revocation
	fmt.Println("\n--- Checking Permissions After Revocation ---")
	allowed, _ = service.CheckPermissionWithConflictResolution(userID, "sensitive/secret.txt", "s3:GetObject")
	fmt.Printf("Permission for 'sensitive/secret.txt' s3:GetObject after revocation: %t\n", allowed)
	
	// 11. Check session updates
	fmt.Println("\n--- Session Updates ---")
	updates_list, _ := sessionManager.GetSessionUpdates(session.ID)
	fmt.Printf("Session has %d pending updates\n", len(updates_list))
	
	for i, update := range updates_list {
		fmt.Printf("Update %d: Type=%s, Time=%s\n", i+1, update.Type, update.Timestamp.Format(time.RFC3339))
	}
	
	fmt.Println("\n=== Example Complete ===")
}

// ExampleConflictResolution demonstrates the conflict resolution mechanism
func ExampleConflictResolution() {
	fmt.Println("=== Conflict Resolution Example ===")
	
	resolver := NewRoleConflictResolver()
	
	// Create roles with conflicting permissions
	allowRole := &EnhancedRole{
		ID:   "allow-role",
		Name: "Allow Role",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/test.txt",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "bucket/*",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
			},
		},
	}
	
	denyRole := &EnhancedRole{
		ID:   "deny-role",
		Name: "Deny Role",
		Permissions: []DetailedPermission{
			{
				Resource: "bucket/test.txt",
				Action:   "s3:GetObject",
				Effect:   PermissionDeny,
			},
		},
	}
	
	roles := []*EnhancedRole{allowRole, denyRole}
	
	fmt.Println("Roles with conflicting permissions:")
	fmt.Printf("- %s: ALLOW s3:GetObject on bucket/test.txt\n", allowRole.Name)
	fmt.Printf("- %s: DENY s3:GetObject on bucket/test.txt\n", denyRole.Name)
	
	// Resolve conflicts
	resolved, err := resolver.ResolvePermissionConflicts(roles)
	if err != nil {
		fmt.Printf("Error resolving conflicts: %v\n", err)
		return
	}
	
	fmt.Println("\nResolved permissions (deny wins):")
	for _, perm := range resolved {
		fmt.Printf("- %s %s on %s\n", perm.Effect, perm.Action, perm.Resource)
	}
	
	// Test the resolved permissions
	permSet := &PermissionSet{
		Permissions: resolved,
		ComputedAt:  time.Now(),
	}
	
	fmt.Println("\nPermission checks:")
	fmt.Printf("- bucket/test.txt s3:GetObject: %t (should be false due to deny)\n", 
		permSet.HasPermission("bucket/test.txt", "s3:GetObject"))
	fmt.Printf("- bucket/other.txt s3:ListBucket: %t (should be true, no conflict)\n", 
		permSet.HasPermission("bucket/other.txt", "s3:ListBucket"))
	
	fmt.Println("\n=== Conflict Resolution Example Complete ===")
}