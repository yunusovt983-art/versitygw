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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// InMemoryRoleManager provides an in-memory implementation of RoleManager
// This is suitable for development and testing, but should be replaced with
// a persistent storage implementation for production use
type InMemoryRoleManager struct {
	roles       map[string]*EnhancedRole
	assignments map[string][]*RoleAssignment // userID -> assignments
	mutex       sync.RWMutex
	validator   *PermissionValidator
}

// NewInMemoryRoleManager creates a new in-memory role manager
func NewInMemoryRoleManager() *InMemoryRoleManager {
	rm := &InMemoryRoleManager{
		roles:       make(map[string]*EnhancedRole),
		assignments: make(map[string][]*RoleAssignment),
		validator:   &PermissionValidator{},
	}
	
	// Initialize with predefined roles
	for _, role := range PredefinedRoles {
		rm.roles[role.ID] = role
	}
	
	return rm
}

// CreateRole creates a new role
func (rm *InMemoryRoleManager) CreateRole(role *EnhancedRole) error {
	if role == nil {
		return fmt.Errorf("role cannot be nil")
	}
	
	if err := role.Validate(); err != nil {
		return fmt.Errorf("invalid role: %w", err)
	}
	
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	
	if _, exists := rm.roles[role.ID]; exists {
		return fmt.Errorf("role with ID %s already exists", role.ID)
	}
	
	// Validate parent roles exist
	for _, parentID := range role.ParentRoles {
		if _, exists := rm.roles[parentID]; !exists {
			return fmt.Errorf("parent role %s does not exist", parentID)
		}
	}
	
	// Validate permission set
	if err := rm.validator.ValidatePermissionSet(role.Permissions); err != nil {
		return fmt.Errorf("invalid permission set: %w", err)
	}
	
	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()
	rm.roles[role.ID] = role
	
	return nil
}

// GetRole retrieves a role by ID
func (rm *InMemoryRoleManager) GetRole(roleID string) (*EnhancedRole, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	
	role, exists := rm.roles[roleID]
	if !exists {
		return nil, fmt.Errorf("role %s not found", roleID)
	}
	
	// Return a copy to prevent external modification
	roleCopy := *role
	return &roleCopy, nil
}

// UpdateRole updates an existing role
func (rm *InMemoryRoleManager) UpdateRole(roleID string, updates *RoleUpdates) error {
	if updates == nil {
		return fmt.Errorf("updates cannot be nil")
	}
	
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	
	role, exists := rm.roles[roleID]
	if !exists {
		return fmt.Errorf("role %s not found", roleID)
	}
	
	// Create a copy for validation
	updatedRole := *role
	updates.Apply(&updatedRole)
	
	if err := updatedRole.Validate(); err != nil {
		return fmt.Errorf("invalid updated role: %w", err)
	}
	
	// Validate parent roles exist
	for _, parentID := range updatedRole.ParentRoles {
		if _, exists := rm.roles[parentID]; !exists {
			return fmt.Errorf("parent role %s does not exist", parentID)
		}
	}
	
	// Validate permission set
	if err := rm.validator.ValidatePermissionSet(updatedRole.Permissions); err != nil {
		return fmt.Errorf("invalid permission set: %w", err)
	}
	
	// Apply updates
	updates.Apply(role)
	
	return nil
}

// DeleteRole deletes a role
func (rm *InMemoryRoleManager) DeleteRole(roleID string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	
	if _, exists := rm.roles[roleID]; !exists {
		return fmt.Errorf("role %s not found", roleID)
	}
	
	// Check if role is used as parent by other roles
	for _, role := range rm.roles {
		for _, parentID := range role.ParentRoles {
			if parentID == roleID {
				return fmt.Errorf("cannot delete role %s: it is used as parent by role %s", roleID, role.ID)
			}
		}
	}
	
	// Check if role is assigned to any users
	for userID, assignments := range rm.assignments {
		for _, assignment := range assignments {
			if assignment.RoleID == roleID {
				return fmt.Errorf("cannot delete role %s: it is assigned to user %s", roleID, userID)
			}
		}
	}
	
	delete(rm.roles, roleID)
	return nil
}

// ListRoles returns all roles
func (rm *InMemoryRoleManager) ListRoles() ([]*EnhancedRole, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	
	roles := make([]*EnhancedRole, 0, len(rm.roles))
	for _, role := range rm.roles {
		roleCopy := *role
		roles = append(roles, &roleCopy)
	}
	
	return roles, nil
}

// AssignRole assigns a role to a user
func (rm *InMemoryRoleManager) AssignRole(userID, roleID, assignedBy string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	
	if _, exists := rm.roles[roleID]; !exists {
		return fmt.Errorf("role %s not found", roleID)
	}
	
	// Check if already assigned
	assignments := rm.assignments[userID]
	for _, assignment := range assignments {
		if assignment.RoleID == roleID && !assignment.IsExpired() {
			return fmt.Errorf("role %s is already assigned to user %s", roleID, userID)
		}
	}
	
	assignment := &RoleAssignment{
		UserID:     userID,
		RoleID:     roleID,
		AssignedAt: time.Now(),
		AssignedBy: assignedBy,
	}
	
	rm.assignments[userID] = append(rm.assignments[userID], assignment)
	return nil
}

// RevokeRole revokes a role from a user
func (rm *InMemoryRoleManager) RevokeRole(userID, roleID string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	
	assignments := rm.assignments[userID]
	for i, assignment := range assignments {
		if assignment.RoleID == roleID && !assignment.IsExpired() {
			// Remove the assignment
			rm.assignments[userID] = append(assignments[:i], assignments[i+1:]...)
			return nil
		}
	}
	
	return fmt.Errorf("role %s is not assigned to user %s", roleID, userID)
}

// GetUserRoles returns all roles assigned to a user
func (rm *InMemoryRoleManager) GetUserRoles(userID string) ([]*EnhancedRole, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	
	assignments := rm.assignments[userID]
	var roles []*EnhancedRole
	
	for _, assignment := range assignments {
		if assignment.IsExpired() {
			continue
		}
		
		if role, exists := rm.roles[assignment.RoleID]; exists {
			roleCopy := *role
			roles = append(roles, &roleCopy)
		}
	}
	
	return roles, nil
}

// GetRoleAssignments returns all role assignments for a user
func (rm *InMemoryRoleManager) GetRoleAssignments(userID string) ([]*RoleAssignment, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	
	assignments := rm.assignments[userID]
	result := make([]*RoleAssignment, len(assignments))
	
	for i, assignment := range assignments {
		assignmentCopy := *assignment
		result[i] = &assignmentCopy
	}
	
	return result, nil
}

// GetUsersWithRole returns all users that have a specific role assigned
func (rm *InMemoryRoleManager) GetUsersWithRole(roleID string) ([]string, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	
	var users []string
	
	for userID, assignments := range rm.assignments {
		for _, assignment := range assignments {
			if assignment.RoleID == roleID && !assignment.IsExpired() {
				users = append(users, userID)
				break // User found, no need to check other assignments
			}
		}
	}
	
	return users, nil
}

// GetEffectivePermissions computes effective permissions for a user
func (rm *InMemoryRoleManager) GetEffectivePermissions(userID string) (*PermissionSet, error) {
	roles, err := rm.GetUserRoles(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	
	// Include inherited roles
	allRoles, err := rm.expandRoleHierarchy(roles)
	if err != nil {
		return nil, fmt.Errorf("failed to expand role hierarchy: %w", err)
	}
	
	return ComputeEffectivePermissions(allRoles), nil
}

// CheckPermission checks if a user has permission for a specific resource/action
func (rm *InMemoryRoleManager) CheckPermission(userID, resource, action string) (bool, error) {
	permissions, err := rm.GetEffectivePermissions(userID)
	if err != nil {
		return false, fmt.Errorf("failed to get effective permissions: %w", err)
	}
	
	return permissions.HasPermission(resource, action), nil
}

// GetRoleHierarchy returns the complete hierarchy for a role
func (rm *InMemoryRoleManager) GetRoleHierarchy(roleID string) ([]*EnhancedRole, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	
	role, exists := rm.roles[roleID]
	if !exists {
		return nil, fmt.Errorf("role %s not found", roleID)
	}
	
	return rm.expandRoleHierarchy([]*EnhancedRole{role})
}

// ValidateRoleHierarchy validates that adding parent roles won't create cycles
func (rm *InMemoryRoleManager) ValidateRoleHierarchy(roleID string, parentRoles []string) error {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	
	// Check for direct self-reference
	for _, parentID := range parentRoles {
		if parentID == roleID {
			return fmt.Errorf("role cannot be its own parent")
		}
	}
	
	// Check for circular dependencies by simulating the hierarchy
	// Create a temporary view of what the hierarchy would look like
	tempHierarchy := make(map[string][]string)
	
	// Copy existing hierarchy
	for id, role := range rm.roles {
		tempHierarchy[id] = role.ParentRoles
	}
	
	// Add the proposed changes
	tempHierarchy[roleID] = parentRoles
	
	// Check for cycles using DFS
	visited := make(map[string]int) // 0: unvisited, 1: visiting, 2: visited
	
	var checkCycle func(currentID string) error
	checkCycle = func(currentID string) error {
		if visited[currentID] == 1 {
			return fmt.Errorf("circular dependency detected involving role: %s", currentID)
		}
		if visited[currentID] == 2 {
			return nil // already processed
		}
		
		visited[currentID] = 1 // mark as visiting
		
		if parents, exists := tempHierarchy[currentID]; exists {
			for _, parentID := range parents {
				if err := checkCycle(parentID); err != nil {
					return err
				}
			}
		}
		
		visited[currentID] = 2 // mark as visited
		return nil
	}
	
	// Check all roles for cycles
	for id := range tempHierarchy {
		if visited[id] == 0 {
			if err := checkCycle(id); err != nil {
				return err
			}
		}
	}
	
	return nil
}

// expandRoleHierarchy expands roles to include all inherited roles
func (rm *InMemoryRoleManager) expandRoleHierarchy(roles []*EnhancedRole) ([]*EnhancedRole, error) {
	visited := make(map[string]bool)
	var allRoles []*EnhancedRole
	
	var expandRole func(role *EnhancedRole) error
	expandRole = func(role *EnhancedRole) error {
		if visited[role.ID] {
			return nil
		}
		
		visited[role.ID] = true
		allRoles = append(allRoles, role)
		
		// Expand parent roles
		for _, parentID := range role.ParentRoles {
			if parentRole, exists := rm.roles[parentID]; exists {
				if err := expandRole(parentRole); err != nil {
					return err
				}
			}
		}
		
		return nil
	}
	
	for _, role := range roles {
		if err := expandRole(role); err != nil {
			return nil, err
		}
	}
	
	return allRoles, nil
}

// FileBasedRoleManager provides a file-based implementation of RoleManager
type FileBasedRoleManager struct {
	*InMemoryRoleManager
	dataDir string
}

// NewFileBasedRoleManager creates a new file-based role manager
func NewFileBasedRoleManager(dataDir string) (*FileBasedRoleManager, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}
	
	rm := &FileBasedRoleManager{
		InMemoryRoleManager: NewInMemoryRoleManager(),
		dataDir:             dataDir,
	}
	
	// Load existing data
	if err := rm.loadFromDisk(); err != nil {
		return nil, fmt.Errorf("failed to load data from disk: %w", err)
	}
	
	return rm, nil
}

// CreateRole creates a role and persists it to disk
func (rm *FileBasedRoleManager) CreateRole(role *EnhancedRole) error {
	if err := rm.InMemoryRoleManager.CreateRole(role); err != nil {
		return err
	}
	
	return rm.saveRoleToDisk(role)
}

// UpdateRole updates a role and persists changes to disk
func (rm *FileBasedRoleManager) UpdateRole(roleID string, updates *RoleUpdates) error {
	if err := rm.InMemoryRoleManager.UpdateRole(roleID, updates); err != nil {
		return err
	}
	
	role, _ := rm.InMemoryRoleManager.GetRole(roleID)
	return rm.saveRoleToDisk(role)
}

// DeleteRole deletes a role and removes it from disk
func (rm *FileBasedRoleManager) DeleteRole(roleID string) error {
	if err := rm.InMemoryRoleManager.DeleteRole(roleID); err != nil {
		return err
	}
	
	rolePath := filepath.Join(rm.dataDir, "roles", roleID+".json")
	return os.Remove(rolePath)
}

// AssignRole assigns a role and persists the assignment
func (rm *FileBasedRoleManager) AssignRole(userID, roleID, assignedBy string) error {
	if err := rm.InMemoryRoleManager.AssignRole(userID, roleID, assignedBy); err != nil {
		return err
	}
	
	return rm.saveAssignmentsToDisk(userID)
}

// RevokeRole revokes a role and persists the change
func (rm *FileBasedRoleManager) RevokeRole(userID, roleID string) error {
	if err := rm.InMemoryRoleManager.RevokeRole(userID, roleID); err != nil {
		return err
	}
	
	return rm.saveAssignmentsToDisk(userID)
}

// loadFromDisk loads roles and assignments from disk
func (rm *FileBasedRoleManager) loadFromDisk() error {
	// Load roles
	rolesDir := filepath.Join(rm.dataDir, "roles")
	if _, err := os.Stat(rolesDir); os.IsNotExist(err) {
		return nil // No roles directory yet
	}
	
	entries, err := os.ReadDir(rolesDir)
	if err != nil {
		return fmt.Errorf("failed to read roles directory: %w", err)
	}
	
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			rolePath := filepath.Join(rolesDir, entry.Name())
			if err := rm.loadRoleFromDisk(rolePath); err != nil {
				return fmt.Errorf("failed to load role from %s: %w", rolePath, err)
			}
		}
	}
	
	// Load assignments
	assignmentsDir := filepath.Join(rm.dataDir, "assignments")
	if _, err := os.Stat(assignmentsDir); os.IsNotExist(err) {
		return nil // No assignments directory yet
	}
	
	entries, err = os.ReadDir(assignmentsDir)
	if err != nil {
		return fmt.Errorf("failed to read assignments directory: %w", err)
	}
	
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			userID := entry.Name()[:len(entry.Name())-5] // Remove .json extension
			assignmentPath := filepath.Join(assignmentsDir, entry.Name())
			if err := rm.loadAssignmentsFromDisk(userID, assignmentPath); err != nil {
				return fmt.Errorf("failed to load assignments from %s: %w", assignmentPath, err)
			}
		}
	}
	
	return nil
}

// saveRoleToDisk saves a role to disk
func (rm *FileBasedRoleManager) saveRoleToDisk(role *EnhancedRole) error {
	rolesDir := filepath.Join(rm.dataDir, "roles")
	if err := os.MkdirAll(rolesDir, 0755); err != nil {
		return fmt.Errorf("failed to create roles directory: %w", err)
	}
	
	rolePath := filepath.Join(rolesDir, role.ID+".json")
	data, err := json.MarshalIndent(role, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal role: %w", err)
	}
	
	return os.WriteFile(rolePath, data, 0644)
}

// loadRoleFromDisk loads a role from disk
func (rm *FileBasedRoleManager) loadRoleFromDisk(rolePath string) error {
	data, err := os.ReadFile(rolePath)
	if err != nil {
		return fmt.Errorf("failed to read role file: %w", err)
	}
	
	var role EnhancedRole
	if err := json.Unmarshal(data, &role); err != nil {
		return fmt.Errorf("failed to unmarshal role: %w", err)
	}
	
	rm.roles[role.ID] = &role
	return nil
}

// saveAssignmentsToDisk saves user role assignments to disk
func (rm *FileBasedRoleManager) saveAssignmentsToDisk(userID string) error {
	assignmentsDir := filepath.Join(rm.dataDir, "assignments")
	if err := os.MkdirAll(assignmentsDir, 0755); err != nil {
		return fmt.Errorf("failed to create assignments directory: %w", err)
	}
	
	assignmentPath := filepath.Join(assignmentsDir, userID+".json")
	assignments := rm.assignments[userID]
	
	data, err := json.MarshalIndent(assignments, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal assignments: %w", err)
	}
	
	return os.WriteFile(assignmentPath, data, 0644)
}

// loadAssignmentsFromDisk loads user role assignments from disk
func (rm *FileBasedRoleManager) loadAssignmentsFromDisk(userID, assignmentPath string) error {
	data, err := os.ReadFile(assignmentPath)
	if err != nil {
		return fmt.Errorf("failed to read assignment file: %w", err)
	}
	
	var assignments []*RoleAssignment
	if err := json.Unmarshal(data, &assignments); err != nil {
		return fmt.Errorf("failed to unmarshal assignments: %w", err)
	}
	
	rm.assignments[userID] = assignments
	return nil
}

// GetUsersWithRole returns all users that have a specific role assigned (delegates to InMemoryRoleManager)
func (rm *FileBasedRoleManager) GetUsersWithRole(roleID string) ([]string, error) {
	return rm.InMemoryRoleManager.GetUsersWithRole(roleID)
}