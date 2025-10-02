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
	"log"
)

// ExampleEnhancedRoleSystem demonstrates the usage of the enhanced role system
func ExampleEnhancedRoleSystem() {
	// Create a role manager
	rm := NewInMemoryRoleManager()
	
	// Create custom roles with detailed permissions
	
	// 1. Create a base read role
	readRole := &EnhancedRole{
		ID:          "data-reader",
		Name:        "Data Reader",
		Description: "Basic read access to data buckets",
		Permissions: []DetailedPermission{
			{
				Resource: "data-*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "data-*",
				Action:   "s3:ListBucket",
				Effect:   PermissionAllow,
			},
		},
	}
	
	// 2. Create an analytics role that inherits from read role
	analyticsRole := &EnhancedRole{
		ID:          "analytics-user",
		Name:        "Analytics User",
		Description: "Analytics team member with read access and specific write permissions",
		ParentRoles: []string{"data-reader"},
		Permissions: []DetailedPermission{
			{
				Resource: "analytics-results/*",
				Action:   "s3:PutObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "analytics-results/*",
				Action:   "s3:DeleteObject",
				Effect:   PermissionAllow,
			},
			// Deny access to sensitive data
			{
				Resource: "data-sensitive/*",
				Action:   "s3:*",
				Effect:   PermissionDeny,
			},
		},
	}
	
	// 3. Create an admin role with broad permissions
	adminRole := &EnhancedRole{
		ID:          "data-admin",
		Name:        "Data Administrator",
		Description: "Administrative access to data infrastructure",
		Permissions: []DetailedPermission{
			{
				Resource: "data-*",
				Action:   "s3:*",
				Effect:   PermissionAllow,
			},
			{
				Resource: "analytics-*",
				Action:   "s3:*",
				Effect:   PermissionAllow,
			},
		},
	}
	
	// Create the roles
	if err := rm.CreateRole(readRole); err != nil {
		log.Printf("Failed to create read role: %v", err)
		return
	}
	
	if err := rm.CreateRole(analyticsRole); err != nil {
		log.Printf("Failed to create analytics role: %v", err)
		return
	}
	
	if err := rm.CreateRole(adminRole); err != nil {
		log.Printf("Failed to create admin role: %v", err)
		return
	}
	
	// Assign roles to users
	rm.AssignRole("alice", "analytics-user", "admin")
	rm.AssignRole("bob", "data-reader", "admin")
	rm.AssignRole("charlie", "data-admin", "admin")
	
	// Demonstrate permission checking
	fmt.Println("=== Enhanced Role System Demo ===")
	
	// Test Alice (analytics user)
	fmt.Println("\nAlice (Analytics User):")
	testPermissions(rm, "alice", []permissionTest{
		{"data-public/file.txt", "s3:GetObject", true},      // Inherited from data-reader
		{"data-public", "s3:ListBucket", true},              // Inherited from data-reader
		{"analytics-results/report.csv", "s3:PutObject", true}, // Direct permission
		{"data-sensitive/secret.txt", "s3:GetObject", false},   // Explicitly denied
		{"other-bucket/file.txt", "s3:GetObject", false},       // No permission
	})
	
	// Test Bob (read-only user)
	fmt.Println("\nBob (Data Reader):")
	testPermissions(rm, "bob", []permissionTest{
		{"data-public/file.txt", "s3:GetObject", true},      // Direct permission
		{"data-public", "s3:ListBucket", true},              // Direct permission
		{"analytics-results/report.csv", "s3:PutObject", false}, // No write permission
		{"data-sensitive/secret.txt", "s3:GetObject", true},     // Has read access (no deny)
	})
	
	// Test Charlie (admin)
	fmt.Println("\nCharlie (Data Admin):")
	testPermissions(rm, "charlie", []permissionTest{
		{"data-public/file.txt", "s3:GetObject", true},      // Admin access
		{"data-public/file.txt", "s3:PutObject", true},      // Admin access
		{"data-public/file.txt", "s3:DeleteObject", true},   // Admin access
		{"analytics-results/report.csv", "s3:PutObject", true}, // Admin access
		{"data-sensitive/secret.txt", "s3:GetObject", true},     // Admin access
	})
	
	// Demonstrate role hierarchy
	fmt.Println("\n=== Role Hierarchy Demo ===")
	hierarchy, _ := rm.GetRoleHierarchy("analytics-user")
	fmt.Printf("Analytics User role hierarchy: ")
	for i, role := range hierarchy {
		if i > 0 {
			fmt.Print(" -> ")
		}
		fmt.Print(role.Name)
	}
	fmt.Println()
	
	// Show effective permissions
	fmt.Println("\n=== Effective Permissions Demo ===")
	permissions, _ := rm.GetEffectivePermissions("alice")
	fmt.Printf("Alice has %d effective permissions:\n", len(permissions.Permissions))
	for i, perm := range permissions.Permissions {
		if i < 5 { // Show first 5 for brevity
			fmt.Printf("  %s: %s on %s (%s)\n", 
				perm.Effect, perm.Action, perm.Resource, 
				func() string {
					if perm.Effect == PermissionAllow {
						return "ALLOW"
					}
					return "DENY"
				}())
		}
	}
	if len(permissions.Permissions) > 5 {
		fmt.Printf("  ... and %d more\n", len(permissions.Permissions)-5)
	}
	
	// Demonstrate role updates
	fmt.Println("\n=== Role Update Demo ===")
	newDescription := "Updated: Analytics team member with enhanced permissions"
	updates := &RoleUpdates{
		Description: &newDescription,
	}
	
	if err := rm.UpdateRole("analytics-user", updates); err != nil {
		log.Printf("Failed to update role: %v", err)
	} else {
		updatedRole, _ := rm.GetRole("analytics-user")
		fmt.Printf("Updated analytics role description: %s\n", updatedRole.Description)
	}
	
	fmt.Println("\n=== Demo Complete ===")
}

type permissionTest struct {
	resource string
	action   string
	expected bool
}

func testPermissions(rm RoleManager, userID string, tests []permissionTest) {
	for _, test := range tests {
		hasPermission, err := rm.CheckPermission(userID, test.resource, test.action)
		if err != nil {
			fmt.Printf("  ERROR checking %s on %s: %v\n", test.action, test.resource, err)
			continue
		}
		
		status := "✗"
		if hasPermission == test.expected {
			status = "✓"
		}
		
		result := "DENY"
		if hasPermission {
			result = "ALLOW"
		}
		
		fmt.Printf("  %s %s on %s: %s\n", status, test.action, test.resource, result)
	}
}

// ExampleRoleComposition demonstrates complex role composition scenarios
func ExampleRoleComposition() {
	rm := NewInMemoryRoleManager()
	
	// Create a hierarchy: base -> department -> team -> individual
	
	// Base role - minimal permissions
	baseRole := &EnhancedRole{
		ID:   "employee",
		Name: "Employee",
		Permissions: []DetailedPermission{
			{
				Resource: "public/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
		},
	}
	
	// Department role - inherits from base
	deptRole := &EnhancedRole{
		ID:          "engineering",
		Name:        "Engineering Department",
		ParentRoles: []string{"employee"},
		Permissions: []DetailedPermission{
			{
				Resource: "engineering/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "engineering/*",
				Action:   "s3:PutObject",
				Effect:   PermissionAllow,
			},
		},
	}
	
	// Team role - inherits from department
	teamRole := &EnhancedRole{
		ID:          "backend-team",
		Name:        "Backend Team",
		ParentRoles: []string{"engineering"},
		Permissions: []DetailedPermission{
			{
				Resource: "backend-services/*",
				Action:   "s3:*",
				Effect:   PermissionAllow,
			},
			// Deny access to frontend resources
			{
				Resource: "frontend/*",
				Action:   "s3:*",
				Effect:   PermissionDeny,
			},
		},
	}
	
	// Senior role - additional permissions
	seniorRole := &EnhancedRole{
		ID:          "senior-engineer",
		Name:        "Senior Engineer",
		ParentRoles: []string{"backend-team"},
		Permissions: []DetailedPermission{
			{
				Resource: "production/*",
				Action:   "s3:GetObject",
				Effect:   PermissionAllow,
			},
			{
				Resource: "deployment/*",
				Action:   "s3:*",
				Effect:   PermissionAllow,
			},
		},
	}
	
	// Create all roles
	roles := []*EnhancedRole{baseRole, deptRole, teamRole, seniorRole}
	for _, role := range roles {
		if err := rm.CreateRole(role); err != nil {
			log.Printf("Failed to create role %s: %v", role.ID, err)
			return
		}
	}
	
	// Assign senior role to user (inherits all parent permissions)
	rm.AssignRole("senior-dev", "senior-engineer", "admin")
	
	fmt.Println("=== Role Composition Demo ===")
	
	// Show the complete hierarchy
	hierarchy, _ := rm.GetRoleHierarchy("senior-engineer")
	fmt.Print("Role hierarchy: ")
	for i, role := range hierarchy {
		if i > 0 {
			fmt.Print(" -> ")
		}
		fmt.Print(role.Name)
	}
	fmt.Println()
	
	// Test inherited permissions
	fmt.Println("\nPermission inheritance test:")
	testPermissions(rm, "senior-dev", []permissionTest{
		{"public/readme.txt", "s3:GetObject", true},           // From employee
		{"engineering/docs.pdf", "s3:GetObject", true},        // From engineering
		{"backend-services/api.jar", "s3:PutObject", true},    // From backend-team
		{"frontend/app.js", "s3:GetObject", false},            // Denied by backend-team
		{"production/config.json", "s3:GetObject", true},      // From senior-engineer
		{"deployment/script.sh", "s3:DeleteObject", true},     // From senior-engineer
	})
	
	fmt.Println("\n=== Composition Demo Complete ===")
}