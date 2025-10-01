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
	"time"

	"github.com/versity/versitygw/auth"
)

// IPFSRoleManager extends the base role manager with IPFS-specific functionality
type IPFSRoleManager struct {
	baseRoleManager auth.RoleManager
	ipfsPermissions map[string]*IPFSPermissionSet
}

// IPFSPermissionSet represents a set of IPFS-specific permissions
type IPFSPermissionSet struct {
	UserID      string                    `json:"user_id"`
	Permissions map[string]*IPFSPermRule  `json:"permissions"`
	CreatedAt   time.Time                 `json:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at"`
}

// IPFSPermRule represents a specific IPFS permission rule
type IPFSPermRule struct {
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	Effect     string                 `json:"effect"` // "allow" or "deny"
	Conditions map[string]interface{} `json:"conditions,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

// NewIPFSRoleManager creates a new IPFS role manager
func NewIPFSRoleManager(baseRoleManager auth.RoleManager) *IPFSRoleManager {
	return &IPFSRoleManager{
		baseRoleManager: baseRoleManager,
		ipfsPermissions: make(map[string]*IPFSPermissionSet),
	}
}

// CheckPermission checks if a user has permission for an IPFS operation
func (irm *IPFSRoleManager) CheckPermission(userID, resource, action string) (bool, error) {
	// First check base role manager
	if irm.baseRoleManager != nil {
		allowed, err := irm.baseRoleManager.CheckPermission(userID, resource, action)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}

	// Check IPFS-specific permissions
	permSet, exists := irm.ipfsPermissions[userID]
	if !exists {
		return false, nil // No specific permissions, deny by default
	}

	// Check each permission rule
	for _, rule := range permSet.Permissions {
		if irm.matchesRule(rule, resource, action) {
			return rule.Effect == "allow", nil
		}
	}

	return false, nil // No matching rule found, deny by default
}

// GetEffectivePermissions returns effective permissions for a user
func (irm *IPFSRoleManager) GetEffectivePermissions(userID string) (*auth.PermissionSet, error) {
	// Get base permissions
	var basePerms *auth.PermissionSet
	var err error
	
	if irm.baseRoleManager != nil {
		basePerms, err = irm.baseRoleManager.GetEffectivePermissions(userID)
		if err != nil {
			return nil, err
		}
	}

	// Get IPFS-specific permissions
	ipfsPerms := irm.getIPFSPermissions(userID)

	// Merge permissions
	return irm.mergePermissions(basePerms, ipfsPerms), nil
}

// GrantIPFSPermission grants an IPFS-specific permission to a user
func (irm *IPFSRoleManager) GrantIPFSPermission(userID, resource, action string, conditions map[string]interface{}) error {
	permSet, exists := irm.ipfsPermissions[userID]
	if !exists {
		permSet = &IPFSPermissionSet{
			UserID:      userID,
			Permissions: make(map[string]*IPFSPermRule),
			CreatedAt:   time.Now(),
		}
		irm.ipfsPermissions[userID] = permSet
	}

	ruleKey := fmt.Sprintf("%s:%s", resource, action)
	permSet.Permissions[ruleKey] = &IPFSPermRule{
		Action:     action,
		Resource:   resource,
		Effect:     "allow",
		Conditions: conditions,
		CreatedAt:  time.Now(),
	}
	permSet.UpdatedAt = time.Now()

	return nil
}

// RevokeIPFSPermission revokes an IPFS-specific permission from a user
func (irm *IPFSRoleManager) RevokeIPFSPermission(userID, resource, action string) error {
	permSet, exists := irm.ipfsPermissions[userID]
	if !exists {
		return nil // Nothing to revoke
	}

	ruleKey := fmt.Sprintf("%s:%s", resource, action)
	delete(permSet.Permissions, ruleKey)
	permSet.UpdatedAt = time.Now()

	return nil
}

// DenyIPFSPermission explicitly denies an IPFS permission for a user
func (irm *IPFSRoleManager) DenyIPFSPermission(userID, resource, action string, conditions map[string]interface{}) error {
	permSet, exists := irm.ipfsPermissions[userID]
	if !exists {
		permSet = &IPFSPermissionSet{
			UserID:      userID,
			Permissions: make(map[string]*IPFSPermRule),
			CreatedAt:   time.Now(),
		}
		irm.ipfsPermissions[userID] = permSet
	}

	ruleKey := fmt.Sprintf("%s:%s:deny", resource, action)
	permSet.Permissions[ruleKey] = &IPFSPermRule{
		Action:     action,
		Resource:   resource,
		Effect:     "deny",
		Conditions: conditions,
		CreatedAt:  time.Now(),
	}
	permSet.UpdatedAt = time.Now()

	return nil
}

// ListUserIPFSPermissions lists all IPFS permissions for a user
func (irm *IPFSRoleManager) ListUserIPFSPermissions(userID string) (*IPFSPermissionSet, error) {
	permSet, exists := irm.ipfsPermissions[userID]
	if !exists {
		return &IPFSPermissionSet{
			UserID:      userID,
			Permissions: make(map[string]*IPFSPermRule),
			CreatedAt:   time.Now(),
		}, nil
	}

	return permSet, nil
}

// Helper methods

func (irm *IPFSRoleManager) matchesRule(rule *IPFSPermRule, resource, action string) bool {
	// Check action match
	if !irm.matchesPattern(rule.Action, action) {
		return false
	}

	// Check resource match
	if !irm.matchesPattern(rule.Resource, resource) {
		return false
	}

	// Check conditions if any
	if len(rule.Conditions) > 0 {
		// For now, we'll implement basic condition checking
		// In a full implementation, this would be more sophisticated
		return irm.evaluateConditions(rule.Conditions, resource, action)
	}

	return true
}

func (irm *IPFSRoleManager) matchesPattern(pattern, value string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}

	if strings.Contains(pattern, "*") {
		// Handle wildcards
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			prefix, suffix := parts[0], parts[1]
			return strings.HasPrefix(value, prefix) && strings.HasSuffix(value, suffix)
		}
	}

	return pattern == value
}

func (irm *IPFSRoleManager) evaluateConditions(conditions map[string]interface{}, resource, action string) bool {
	// Basic condition evaluation
	for key, value := range conditions {
		switch key {
		case "time_range":
			if !irm.checkTimeRange(value) {
				return false
			}
		case "ip_range":
			if !irm.checkIPRange(value) {
				return false
			}
		case "resource_size":
			if !irm.checkResourceSize(value, resource) {
				return false
			}
		}
	}
	return true
}

func (irm *IPFSRoleManager) checkTimeRange(condition interface{}) bool {
	// Implement time range checking
	// For now, always return true
	return true
}

func (irm *IPFSRoleManager) checkIPRange(condition interface{}) bool {
	// Implement IP range checking
	// For now, always return true
	return true
}

func (irm *IPFSRoleManager) checkResourceSize(condition interface{}, resource string) bool {
	// Implement resource size checking
	// For now, always return true
	return true
}

func (irm *IPFSRoleManager) getIPFSPermissions(userID string) *auth.PermissionSet {
	permSet, exists := irm.ipfsPermissions[userID]
	if !exists {
		return &auth.PermissionSet{
			Permissions: make(map[string]*auth.Permission),
		}
	}

	// Convert IPFS permissions to standard permission format
	permissions := make(map[string]*auth.Permission)
	for key, rule := range permSet.Permissions {
		permissions[key] = &auth.Permission{
			Action:   rule.Action,
			Resource: rule.Resource,
			Effect:   rule.Effect,
		}
	}

	return &auth.PermissionSet{
		Permissions: permissions,
	}
}

func (irm *IPFSRoleManager) mergePermissions(base, ipfs *auth.PermissionSet) *auth.PermissionSet {
	merged := &auth.PermissionSet{
		Permissions: make(map[string]*auth.Permission),
	}

	// Add base permissions
	if base != nil {
		for key, perm := range base.Permissions {
			merged.Permissions[key] = perm
		}
	}

	// Add IPFS permissions (they override base permissions)
	if ipfs != nil {
		for key, perm := range ipfs.Permissions {
			merged.Permissions[key] = perm
		}
	}

	return merged
}

// Predefined IPFS permission templates
var (
	IPFSReadOnlyPermissions = []IPFSPermRule{
		{Action: "ipfs:pin:read", Resource: "*", Effect: "allow"},
		{Action: "ipfs:pin:list", Resource: "*", Effect: "allow"},
		{Action: "ipfs:metadata:read", Resource: "*", Effect: "allow"},
		{Action: "ipfs:replication:view", Resource: "*", Effect: "allow"},
	}

	IPFSUserPermissions = []IPFSPermRule{
		{Action: "ipfs:pin:create", Resource: "arn:aws:ipfs:::bucket/*", Effect: "allow"},
		{Action: "ipfs:pin:read", Resource: "*", Effect: "allow"},
		{Action: "ipfs:pin:delete", Resource: "arn:aws:ipfs:::bucket/*", Effect: "allow"},
		{Action: "ipfs:pin:list", Resource: "*", Effect: "allow"},
		{Action: "ipfs:metadata:read", Resource: "*", Effect: "allow"},
		{Action: "ipfs:metadata:write", Resource: "arn:aws:ipfs:::bucket/*", Effect: "allow"},
		{Action: "ipfs:replication:view", Resource: "*", Effect: "allow"},
	}

	IPFSAdminPermissions = []IPFSPermRule{
		{Action: "*", Resource: "*", Effect: "allow"},
	}
)

// ApplyPermissionTemplate applies a predefined permission template to a user
func (irm *IPFSRoleManager) ApplyPermissionTemplate(userID string, template []IPFSPermRule) error {
	permSet := &IPFSPermissionSet{
		UserID:      userID,
		Permissions: make(map[string]*IPFSPermRule),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	for _, rule := range template {
		ruleKey := fmt.Sprintf("%s:%s", rule.Resource, rule.Action)
		ruleCopy := rule
		ruleCopy.CreatedAt = time.Now()
		permSet.Permissions[ruleKey] = &ruleCopy
	}

	irm.ipfsPermissions[userID] = permSet
	return nil
}

// GetPermissionTemplate returns a predefined permission template
func GetPermissionTemplate(templateName string) []IPFSPermRule {
	switch templateName {
	case "readonly":
		return IPFSReadOnlyPermissions
	case "user":
		return IPFSUserPermissions
	case "admin":
		return IPFSAdminPermissions
	default:
		return IPFSReadOnlyPermissions
	}
}

// ValidateIPFSPermission validates an IPFS permission rule
func ValidateIPFSPermission(rule *IPFSPermRule) error {
	if rule.Action == "" {
		return fmt.Errorf("action cannot be empty")
	}

	if rule.Resource == "" {
		return fmt.Errorf("resource cannot be empty")
	}

	if rule.Effect != "allow" && rule.Effect != "deny" {
		return fmt.Errorf("effect must be 'allow' or 'deny'")
	}

	// Validate action format
	if !strings.HasPrefix(rule.Action, "ipfs:") && rule.Action != "*" {
		return fmt.Errorf("IPFS actions must start with 'ipfs:' or be '*'")
	}

	return nil
}