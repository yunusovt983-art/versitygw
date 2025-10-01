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

package ipfs

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/versity/versitygw/auth"
)

// IPFSRoleManager manages IPFS-specific roles and permissions
type IPFSRoleManager struct {
	roleManager     auth.RoleManager
	userPermissions map[string]*IPFSPermissionSet
	roleTemplates   map[string][]IPFSPermRule
	mu              sync.RWMutex
}

// IPFSPermissionSet contains IPFS-specific permissions for a user
type IPFSPermissionSet struct {
	UserID      string          `json:"user_id"`
	Permissions []IPFSPermRule  `json:"permissions"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// IPFSPermRule defines a fine-grained IPFS permission rule
type IPFSPermRule struct {
	ID          string                 `json:"id"`
	Effect      string                 `json:"effect"`      // "allow" or "deny"
	Resource    string                 `json:"resource"`    // Resource pattern (e.g., "ipfs:cid:*", "ipfs:bucket:mybucket/*")
	Action      string                 `json:"action"`      // Action pattern (e.g., "pin", "unpin", "metadata:*")
	Conditions  map[string]interface{} `json:"conditions"`  // Additional conditions
	Priority    int                    `json:"priority"`    // Rule priority (higher number = higher priority)
	Description string                 `json:"description"` // Human-readable description
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// NewIPFSRoleManager creates a new IPFS role manager
func NewIPFSRoleManager(roleManager auth.RoleManager) *IPFSRoleManager {
	manager := &IPFSRoleManager{
		roleManager:     roleManager,
		userPermissions: make(map[string]*IPFSPermissionSet),
		roleTemplates:   make(map[string][]IPFSPermRule),
	}

	// Initialize default role templates
	manager.initializeRoleTemplates()

	return manager
}

// GrantIPFSPermission grants an IPFS permission to a user
func (irm *IPFSRoleManager) GrantIPFSPermission(userID, resource, action string, conditions map[string]interface{}) error {
	irm.mu.Lock()
	defer irm.mu.Unlock()

	permSet, exists := irm.userPermissions[userID]
	if !exists {
		permSet = &IPFSPermissionSet{
			UserID:      userID,
			Permissions: make([]IPFSPermRule, 0),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		irm.userPermissions[userID] = permSet
	}

	// Create new permission rule
	rule := IPFSPermRule{
		ID:          generatePermissionID(),
		Effect:      "allow",
		Resource:    resource,
		Action:      action,
		Conditions:  conditions,
		Priority:    100, // Default priority
		Description: fmt.Sprintf("Allow %s on %s", action, resource),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Add the rule
	permSet.Permissions = append(permSet.Permissions, rule)
	permSet.UpdatedAt = time.Now()

	return nil
}

// RevokeIPFSPermission revokes an IPFS permission from a user
func (irm *IPFSRoleManager) RevokeIPFSPermission(userID, resource, action string) error {
	irm.mu.Lock()
	defer irm.mu.Unlock()

	permSet, exists := irm.userPermissions[userID]
	if !exists {
		return fmt.Errorf("user %s has no IPFS permissions", userID)
	}

	// Find and remove matching permissions
	var newPermissions []IPFSPermRule
	removed := false

	for _, rule := range permSet.Permissions {
		if rule.Resource == resource && rule.Action == action {
			removed = true
			continue // Skip this rule (remove it)
		}
		newPermissions = append(newPermissions, rule)
	}

	if !removed {
		return fmt.Errorf("permission not found for user %s: %s on %s", userID, action, resource)
	}

	permSet.Permissions = newPermissions
	permSet.UpdatedAt = time.Now()

	return nil
}

// ListUserIPFSPermissions lists all IPFS permissions for a user
func (irm *IPFSRoleManager) ListUserIPFSPermissions(userID string) (*IPFSPermissionSet, error) {
	irm.mu.RLock()
	defer irm.mu.RUnlock()

	permSet, exists := irm.userPermissions[userID]
	if !exists {
		// Return empty permission set
		return &IPFSPermissionSet{
			UserID:      userID,
			Permissions: make([]IPFSPermRule, 0),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}, nil
	}

	// Return a copy to prevent external modifications
	copy := *permSet
	copy.Permissions = make([]IPFSPermRule, len(permSet.Permissions))
	for i, rule := range permSet.Permissions {
		copy.Permissions[i] = rule
	}

	return &copy, nil
}

// CheckIPFSPermission checks if a user has a specific IPFS permission
func (irm *IPFSRoleManager) CheckIPFSPermission(userID, resource, action string) (bool, error) {
	irm.mu.RLock()
	defer irm.mu.RUnlock()

	permSet, exists := irm.userPermissions[userID]
	if !exists {
		return false, nil // No permissions = deny
	}

	// Sort rules by priority (highest first)
	rules := make([]IPFSPermRule, len(permSet.Permissions))
	copy(rules, permSet.Permissions)
	
	// Simple bubble sort by priority (descending)
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[i].Priority < rules[j].Priority {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}

	// Check rules in priority order
	for _, rule := range rules {
		if irm.matchesRule(&rule, resource, action) {
			return rule.Effect == "allow", nil
		}
	}

	return false, nil // No matching rule = deny
}

// ApplyPermissionTemplate applies a permission template to a user
func (irm *IPFSRoleManager) ApplyPermissionTemplate(userID string, template []IPFSPermRule) error {
	irm.mu.Lock()
	defer irm.mu.Unlock()

	permSet, exists := irm.userPermissions[userID]
	if !exists {
		permSet = &IPFSPermissionSet{
			UserID:      userID,
			Permissions: make([]IPFSPermRule, 0),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		irm.userPermissions[userID] = permSet
	}

	// Add template rules
	for _, templateRule := range template {
		rule := templateRule
		rule.ID = generatePermissionID()
		rule.CreatedAt = time.Now()
		rule.UpdatedAt = time.Now()
		
		permSet.Permissions = append(permSet.Permissions, rule)
	}

	permSet.UpdatedAt = time.Now()
	return nil
}

// CreateIPFSRole creates a new IPFS role template
func (irm *IPFSRoleManager) CreateIPFSRole(roleName string, permissions []IPFSPermRule) error {
	irm.mu.Lock()
	defer irm.mu.Unlock()

	irm.roleTemplates[roleName] = permissions
	return nil
}

// GetIPFSRole gets an IPFS role template
func (irm *IPFSRoleManager) GetIPFSRole(roleName string) ([]IPFSPermRule, error) {
	irm.mu.RLock()
	defer irm.mu.RUnlock()

	template, exists := irm.roleTemplates[roleName]
	if !exists {
		return nil, fmt.Errorf("IPFS role not found: %s", roleName)
	}

	// Return a copy
	copy := make([]IPFSPermRule, len(template))
	for i, rule := range template {
		copy[i] = rule
	}

	return copy, nil
}

// ListIPFSRoles lists all available IPFS role templates
func (irm *IPFSRoleManager) ListIPFSRoles() []string {
	irm.mu.RLock()
	defer irm.mu.RUnlock()

	roles := make([]string, 0, len(irm.roleTemplates))
	for roleName := range irm.roleTemplates {
		roles = append(roles, roleName)
	}

	return roles
}

// RemoveUserIPFSPermissions removes all IPFS permissions for a user
func (irm *IPFSRoleManager) RemoveUserIPFSPermissions(userID string) error {
	irm.mu.Lock()
	defer irm.mu.Unlock()

	delete(irm.userPermissions, userID)
	return nil
}

// GetUserIPFSRoles gets the IPFS roles assigned to a user (based on their permissions)
func (irm *IPFSRoleManager) GetUserIPFSRoles(userID string) ([]string, error) {
	permSet, err := irm.ListUserIPFSPermissions(userID)
	if err != nil {
		return nil, err
	}

	// This is a simplified implementation
	// In a real system, you might track role assignments separately
	var roles []string

	// Determine roles based on permission patterns
	hasReadOnly := true
	hasWrite := false
	hasAdmin := false

	for _, rule := range permSet.Permissions {
		if rule.Effect == "allow" {
			if strings.Contains(rule.Action, "write") || strings.Contains(rule.Action, "create") || strings.Contains(rule.Action, "delete") {
				hasWrite = true
				hasReadOnly = false
			}
			if strings.Contains(rule.Action, "admin") || strings.Contains(rule.Resource, "cluster") {
				hasAdmin = true
				hasWrite = true
				hasReadOnly = false
			}
		}
	}

	if hasAdmin {
		roles = append(roles, "ipfs-admin")
	} else if hasWrite {
		roles = append(roles, "ipfs-user")
	} else if hasReadOnly && len(permSet.Permissions) > 0 {
		roles = append(roles, "ipfs-readonly")
	}

	return roles, nil
}

// Helper methods

func (irm *IPFSRoleManager) matchesRule(rule *IPFSPermRule, resource, action string) bool {
	// Match resource pattern
	if !irm.matchesPattern(rule.Resource, resource) {
		return false
	}

	// Match action pattern
	if !irm.matchesPattern(rule.Action, action) {
		return false
	}

	// Check additional conditions
	if len(rule.Conditions) > 0 {
		// For now, we'll skip condition checking
		// In a real implementation, you would evaluate conditions here
	}

	return true
}

func (irm *IPFSRoleManager) matchesPattern(pattern, value string) bool {
	// Simple pattern matching with wildcards
	if pattern == "*" {
		return true
	}

	if pattern == value {
		return true
	}

	// Handle prefix wildcards (e.g., "ipfs:*")
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}

	// Handle suffix wildcards (e.g., "*:read")
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(value, suffix)
	}

	return false
}

func (irm *IPFSRoleManager) initializeRoleTemplates() {
	// Initialize predefined role templates
	irm.roleTemplates["ipfs-readonly"] = IPFSReadOnlyPermissions
	irm.roleTemplates["ipfs-user"] = IPFSUserPermissions
	irm.roleTemplates["ipfs-admin"] = IPFSAdminPermissions
}

// Predefined permission templates

var IPFSReadOnlyPermissions = []IPFSPermRule{
	{
		Effect:      "allow",
		Resource:    "ipfs:cid:*",
		Action:      "pin:read",
		Priority:    100,
		Description: "Allow reading pin status",
	},
	{
		Effect:      "allow",
		Resource:    "ipfs:cid:*",
		Action:      "pin:list",
		Priority:    100,
		Description: "Allow listing pins",
	},
	{
		Effect:      "allow",
		Resource:    "ipfs:metadata:*",
		Action:      "metadata:read",
		Priority:    100,
		Description: "Allow reading metadata",
	},
	{
		Effect:      "allow",
		Resource:    "ipfs:replication:*",
		Action:      "replication:view",
		Priority:    100,
		Description: "Allow viewing replication status",
	},
}

var IPFSUserPermissions = []IPFSPermRule{
	{
		Effect:      "allow",
		Resource:    "ipfs:cid:*",
		Action:      "pin:*",
		Priority:    200,
		Description: "Allow all pin operations",
	},
	{
		Effect:      "allow",
		Resource:    "ipfs:metadata:*",
		Action:      "metadata:*",
		Priority:    200,
		Description: "Allow all metadata operations",
	},
	{
		Effect:      "allow",
		Resource:    "ipfs:replication:*",
		Action:      "replication:view",
		Priority:    200,
		Description: "Allow viewing replication status",
	},
	{
		Effect:      "deny",
		Resource:    "ipfs:cluster:*",
		Action:      "cluster:admin",
		Priority:    300,
		Description: "Deny cluster admin operations",
	},
}

var IPFSAdminPermissions = []IPFSPermRule{
	{
		Effect:      "allow",
		Resource:    "ipfs:*",
		Action:      "*",
		Priority:    1000,
		Description: "Allow all IPFS operations",
	},
}

// GetPermissionTemplate returns a permission template by name
func GetPermissionTemplate(templateName string) []IPFSPermRule {
	switch templateName {
	case "ipfs-readonly":
		return IPFSReadOnlyPermissions
	case "ipfs-user":
		return IPFSUserPermissions
	case "ipfs-admin":
		return IPFSAdminPermissions
	default:
		return []IPFSPermRule{}
	}
}

// Helper function to generate permission IDs
func generatePermissionID() string {
	return fmt.Sprintf("ipfs_perm_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%1000)
}

// ValidatePermissionRule validates a permission rule
func ValidatePermissionRule(rule *IPFSPermRule) error {
	if rule.Effect != "allow" && rule.Effect != "deny" {
		return fmt.Errorf("invalid effect: %s (must be 'allow' or 'deny')", rule.Effect)
	}

	if rule.Resource == "" {
		return fmt.Errorf("resource cannot be empty")
	}

	if rule.Action == "" {
		return fmt.Errorf("action cannot be empty")
	}

	if rule.Priority < 0 {
		return fmt.Errorf("priority cannot be negative")
	}

	return nil
}

// ExportUserPermissions exports user permissions to a transferable format
func (irm *IPFSRoleManager) ExportUserPermissions(userID string) (*IPFSPermissionSet, error) {
	return irm.ListUserIPFSPermissions(userID)
}

// ImportUserPermissions imports user permissions from a transferable format
func (irm *IPFSRoleManager) ImportUserPermissions(permSet *IPFSPermissionSet) error {
	if permSet == nil {
		return fmt.Errorf("permission set cannot be nil")
	}

	// Validate all rules
	for _, rule := range permSet.Permissions {
		if err := ValidatePermissionRule(&rule); err != nil {
			return fmt.Errorf("invalid permission rule: %w", err)
		}
	}

	irm.mu.Lock()
	defer irm.mu.Unlock()

	// Update timestamps
	permSet.UpdatedAt = time.Now()
	if permSet.CreatedAt.IsZero() {
		permSet.CreatedAt = time.Now()
	}

	// Store the permission set
	irm.userPermissions[permSet.UserID] = permSet

	return nil
}

// GetPermissionStatistics returns statistics about IPFS permissions
func (irm *IPFSRoleManager) GetPermissionStatistics() *IPFSPermissionStatistics {
	irm.mu.RLock()
	defer irm.mu.RUnlock()

	stats := &IPFSPermissionStatistics{
		TotalUsers:           len(irm.userPermissions),
		TotalRoleTemplates:   len(irm.roleTemplates),
		PermissionsByEffect:  make(map[string]int),
		PermissionsByAction:  make(map[string]int),
		PermissionsByResource: make(map[string]int),
		Timestamp:           time.Now(),
	}

	totalPermissions := 0
	for _, permSet := range irm.userPermissions {
		totalPermissions += len(permSet.Permissions)
		
		for _, rule := range permSet.Permissions {
			stats.PermissionsByEffect[rule.Effect]++
			stats.PermissionsByAction[rule.Action]++
			stats.PermissionsByResource[rule.Resource]++
		}
	}

	stats.TotalPermissions = totalPermissions
	return stats
}

// IPFSPermissionStatistics contains statistics about IPFS permissions
type IPFSPermissionStatistics struct {
	TotalUsers            int               `json:"total_users"`
	TotalPermissions      int               `json:"total_permissions"`
	TotalRoleTemplates    int               `json:"total_role_templates"`
	PermissionsByEffect   map[string]int    `json:"permissions_by_effect"`
	PermissionsByAction   map[string]int    `json:"permissions_by_action"`
	PermissionsByResource map[string]int    `json:"permissions_by_resource"`
	Timestamp             time.Time         `json:"timestamp"`
}