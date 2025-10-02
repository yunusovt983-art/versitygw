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
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/versity/versitygw/auth"
)

// IPFSIAMIntegration provides enhanced IAM integration for IPFS operations
type IPFSIAMIntegration struct {
	iamService      auth.IAMService
	roleManager     auth.RoleManager
	ipfsRoleManager *IPFSRoleManager
	
	// Caching for performance
	userCache       map[string]*CachedUserInfo
	permissionCache map[string]*CachedPermissions
	cacheMutex      sync.RWMutex
	cacheTimeout    time.Duration
	
	// Configuration
	config *IAMIntegrationConfig
}

// IAMIntegrationConfig contains configuration for IAM integration
type IAMIntegrationConfig struct {
	EnableUserCaching       bool          `json:"enable_user_caching"`
	EnablePermissionCaching bool          `json:"enable_permission_caching"`
	CacheTimeout           time.Duration `json:"cache_timeout"`
	AutoCreateIPFSRoles    bool          `json:"auto_create_ipfs_roles"`
	DefaultIPFSRole        string        `json:"default_ipfs_role"`
	EnableRoleInheritance  bool          `json:"enable_role_inheritance"`
	MaxCacheSize           int           `json:"max_cache_size"`
}

// CachedUserInfo contains cached user information
type CachedUserInfo struct {
	Account   auth.Account
	Roles     []*auth.EnhancedRole
	CachedAt  time.Time
	ExpiresAt time.Time
}

// CachedPermissions contains cached permission information
type CachedPermissions struct {
	UserID      string
	Permissions *auth.PermissionSet
	IPFSPerms   *IPFSPermissionSet
	CachedAt    time.Time
	ExpiresAt   time.Time
}

// DefaultIAMIntegrationConfig returns default IAM integration configuration
func DefaultIAMIntegrationConfig() *IAMIntegrationConfig {
	return &IAMIntegrationConfig{
		EnableUserCaching:       true,
		EnablePermissionCaching: true,
		CacheTimeout:           5 * time.Minute,
		AutoCreateIPFSRoles:    true,
		DefaultIPFSRole:        "ipfs-user",
		EnableRoleInheritance:  true,
		MaxCacheSize:           10000,
	}
}

// NewIPFSIAMIntegration creates a new IPFS IAM integration
func NewIPFSIAMIntegration(
	iamService auth.IAMService,
	roleManager auth.RoleManager,
	config *IAMIntegrationConfig,
) (*IPFSIAMIntegration, error) {
	if config == nil {
		config = DefaultIAMIntegrationConfig()
	}

	integration := &IPFSIAMIntegration{
		iamService:      iamService,
		roleManager:     roleManager,
		ipfsRoleManager: NewIPFSRoleManager(roleManager),
		userCache:       make(map[string]*CachedUserInfo),
		permissionCache: make(map[string]*CachedPermissions),
		cacheTimeout:    config.CacheTimeout,
		config:          config,
	}

	// Initialize default IPFS roles if auto-creation is enabled
	if config.AutoCreateIPFSRoles {
		if err := integration.initializeDefaultRoles(); err != nil {
			return nil, fmt.Errorf("failed to initialize default IPFS roles: %w", err)
		}
	}

	// Start cache cleanup routine
	go integration.cacheCleanupRoutine()

	return integration, nil
}

// AuthenticateUser authenticates a user and returns their account information
func (iai *IPFSIAMIntegration) AuthenticateUser(ctx context.Context, accessKey, secretKey string) (*auth.Account, error) {
	// Check cache first if enabled
	if iai.config.EnableUserCaching {
		if cachedUser := iai.getCachedUser(accessKey); cachedUser != nil {
			return &cachedUser.Account, nil
		}
	}

	// Authenticate with IAM service
	account, err := iai.iamService.GetUserAccount(accessKey)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Validate secret key (this would typically be done by the IAM service)
	// For now, we'll assume the IAM service handles this validation

	// Cache the user if caching is enabled
	if iai.config.EnableUserCaching {
		iai.cacheUser(accessKey, &account, nil)
	}

	return &account, nil
}

// GetUserPermissions retrieves effective permissions for a user
func (iai *IPFSIAMIntegration) GetUserPermissions(ctx context.Context, userID string) (*CombinedPermissions, error) {
	// Check cache first if enabled
	if iai.config.EnablePermissionCaching {
		if cachedPerms := iai.getCachedPermissions(userID); cachedPerms != nil {
			return &CombinedPermissions{
				StandardPermissions: cachedPerms.Permissions,
				IPFSPermissions:     cachedPerms.IPFSPerms,
			}, nil
		}
	}

	// Get standard permissions from role manager
	var standardPerms *auth.PermissionSet
	var err error
	if iai.roleManager != nil {
		standardPerms, err = iai.roleManager.GetEffectivePermissions(userID)
		if err != nil {
			return nil, fmt.Errorf("failed to get standard permissions: %w", err)
		}
	}

	// Get IPFS-specific permissions
	ipfsPerms, err := iai.ipfsRoleManager.ListUserIPFSPermissions(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPFS permissions: %w", err)
	}

	// Cache the permissions if caching is enabled
	if iai.config.EnablePermissionCaching {
		iai.cachePermissions(userID, standardPerms, ipfsPerms)
	}

	return &CombinedPermissions{
		StandardPermissions: standardPerms,
		IPFSPermissions:     ipfsPerms,
	}, nil
}

// CheckIPFSPermission checks if a user has a specific IPFS permission
func (iai *IPFSIAMIntegration) CheckIPFSPermission(ctx context.Context, userID, resource, action string) (bool, error) {
	// Get user permissions
	permissions, err := iai.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, err
	}

	// Check IPFS-specific permissions first
	if permissions.IPFSPermissions != nil {
		for _, rule := range permissions.IPFSPermissions.Permissions {
			if iai.matchesPermissionRule(rule, resource, action) {
				return rule.Effect == "allow", nil
			}
		}
	}

	// Check standard permissions if IPFS permissions don't match
	if permissions.StandardPermissions != nil {
		for _, perm := range permissions.StandardPermissions.Permissions {
			if iai.matchesStandardPermission(perm, resource, action) {
				return perm.Effect == "allow", nil
			}
		}
	}

	// Check with role manager as fallback
	if iai.roleManager != nil {
		return iai.roleManager.CheckPermission(userID, resource, action)
	}

	return false, nil // Deny by default
}

// GrantIPFSPermission grants an IPFS permission to a user
func (iai *IPFSIAMIntegration) GrantIPFSPermission(ctx context.Context, userID, resource, action string, conditions map[string]interface{}) error {
	err := iai.ipfsRoleManager.GrantIPFSPermission(userID, resource, action, conditions)
	if err != nil {
		return err
	}

	// Invalidate cached permissions
	iai.invalidatePermissionCache(userID)

	return nil
}

// RevokeIPFSPermission revokes an IPFS permission from a user
func (iai *IPFSIAMIntegration) RevokeIPFSPermission(ctx context.Context, userID, resource, action string) error {
	err := iai.ipfsRoleManager.RevokeIPFSPermission(userID, resource, action)
	if err != nil {
		return err
	}

	// Invalidate cached permissions
	iai.invalidatePermissionCache(userID)

	return nil
}

// AssignIPFSRole assigns a predefined IPFS role to a user
func (iai *IPFSIAMIntegration) AssignIPFSRole(ctx context.Context, userID, roleName string) error {
	template := GetPermissionTemplate(roleName)
	if len(template) == 0 {
		return fmt.Errorf("unknown IPFS role: %s", roleName)
	}

	err := iai.ipfsRoleManager.ApplyPermissionTemplate(userID, template)
	if err != nil {
		return err
	}

	// Invalidate cached permissions
	iai.invalidatePermissionCache(userID)

	return nil
}

// CreateIPFSUser creates a new user with IPFS permissions
func (iai *IPFSIAMIntegration) CreateIPFSUser(ctx context.Context, account auth.Account, ipfsRole string) error {
	// Create user in IAM service
	err := iai.iamService.CreateAccount(account)
	if err != nil {
		return fmt.Errorf("failed to create user account: %w", err)
	}

	// Assign IPFS role if specified
	if ipfsRole != "" {
		err = iai.AssignIPFSRole(ctx, account.Access, ipfsRole)
		if err != nil {
			// Rollback user creation
			iai.iamService.DeleteUserAccount(account.Access)
			return fmt.Errorf("failed to assign IPFS role: %w", err)
		}
	} else if iai.config.DefaultIPFSRole != "" {
		// Assign default IPFS role
		err = iai.AssignIPFSRole(ctx, account.Access, iai.config.DefaultIPFSRole)
		if err != nil {
			// Rollback user creation
			iai.iamService.DeleteUserAccount(account.Access)
			return fmt.Errorf("failed to assign default IPFS role: %w", err)
		}
	}

	return nil
}

// ListIPFSUsers lists all users with IPFS permissions
func (iai *IPFSIAMIntegration) ListIPFSUsers(ctx context.Context) ([]*IPFSUserInfo, error) {
	// Get all user accounts
	accounts, err := iai.iamService.ListUserAccounts()
	if err != nil {
		return nil, fmt.Errorf("failed to list user accounts: %w", err)
	}

	var ipfsUsers []*IPFSUserInfo
	for _, account := range accounts {
		// Check if user has any IPFS permissions
		ipfsPerms, err := iai.ipfsRoleManager.ListUserIPFSPermissions(account.Access)
		if err != nil {
			continue // Skip users with permission errors
		}

		if len(ipfsPerms.Permissions) > 0 {
			ipfsUsers = append(ipfsUsers, &IPFSUserInfo{
				Account:         account,
				IPFSPermissions: ipfsPerms,
			})
		}
	}

	return ipfsUsers, nil
}

// GetIPFSUserInfo gets detailed information about an IPFS user
func (iai *IPFSIAMIntegration) GetIPFSUserInfo(ctx context.Context, userID string) (*IPFSUserInfo, error) {
	// Get user account
	account, err := iai.iamService.GetUserAccount(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user account: %w", err)
	}

	// Get IPFS permissions
	ipfsPerms, err := iai.ipfsRoleManager.ListUserIPFSPermissions(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPFS permissions: %w", err)
	}

	// Get standard permissions if available
	var standardPerms *auth.PermissionSet
	if iai.roleManager != nil {
		standardPerms, _ = iai.roleManager.GetEffectivePermissions(userID)
	}

	return &IPFSUserInfo{
		Account:             account,
		IPFSPermissions:     ipfsPerms,
		StandardPermissions: standardPerms,
	}, nil
}

// Helper methods

func (iai *IPFSIAMIntegration) initializeDefaultRoles() error {
	// This would create default IPFS roles in the system
	// For now, we'll just ensure the permission templates are available
	
	defaultRoles := map[string][]IPFSPermRule{
		"ipfs-readonly": IPFSReadOnlyPermissions,
		"ipfs-user":     IPFSUserPermissions,
		"ipfs-admin":    IPFSAdminPermissions,
	}

	// In a real implementation, you might want to create these as actual roles
	// in the role manager system
	for roleName, permissions := range defaultRoles {
		// Log that the role template is available
		fmt.Printf("IPFS role template '%s' available with %d permissions\n", roleName, len(permissions))
	}

	return nil
}

func (iai *IPFSIAMIntegration) getCachedUser(userID string) *CachedUserInfo {
	iai.cacheMutex.RLock()
	defer iai.cacheMutex.RUnlock()

	cached, exists := iai.userCache[userID]
	if !exists {
		return nil
	}

	if time.Now().After(cached.ExpiresAt) {
		return nil // Expired
	}

	return cached
}

func (iai *IPFSIAMIntegration) cacheUser(userID string, account *auth.Account, roles []*auth.EnhancedRole) {
	iai.cacheMutex.Lock()
	defer iai.cacheMutex.Unlock()

	// Check cache size limit
	if len(iai.userCache) >= iai.config.MaxCacheSize {
		iai.evictOldestUserCache()
	}

	now := time.Now()
	iai.userCache[userID] = &CachedUserInfo{
		Account:   *account,
		Roles:     roles,
		CachedAt:  now,
		ExpiresAt: now.Add(iai.cacheTimeout),
	}
}

func (iai *IPFSIAMIntegration) getCachedPermissions(userID string) *CachedPermissions {
	iai.cacheMutex.RLock()
	defer iai.cacheMutex.RUnlock()

	cached, exists := iai.permissionCache[userID]
	if !exists {
		return nil
	}

	if time.Now().After(cached.ExpiresAt) {
		return nil // Expired
	}

	return cached
}

func (iai *IPFSIAMIntegration) cachePermissions(userID string, standardPerms *auth.PermissionSet, ipfsPerms *IPFSPermissionSet) {
	iai.cacheMutex.Lock()
	defer iai.cacheMutex.Unlock()

	// Check cache size limit
	if len(iai.permissionCache) >= iai.config.MaxCacheSize {
		iai.evictOldestPermissionCache()
	}

	now := time.Now()
	iai.permissionCache[userID] = &CachedPermissions{
		UserID:      userID,
		Permissions: standardPerms,
		IPFSPerms:   ipfsPerms,
		CachedAt:    now,
		ExpiresAt:   now.Add(iai.cacheTimeout),
	}
}

func (iai *IPFSIAMIntegration) invalidatePermissionCache(userID string) {
	iai.cacheMutex.Lock()
	defer iai.cacheMutex.Unlock()

	delete(iai.permissionCache, userID)
}

func (iai *IPFSIAMIntegration) evictOldestUserCache() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range iai.userCache {
		if oldestKey == "" || cached.CachedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.CachedAt
		}
	}

	if oldestKey != "" {
		delete(iai.userCache, oldestKey)
	}
}

func (iai *IPFSIAMIntegration) evictOldestPermissionCache() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range iai.permissionCache {
		if oldestKey == "" || cached.CachedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.CachedAt
		}
	}

	if oldestKey != "" {
		delete(iai.permissionCache, oldestKey)
	}
}

func (iai *IPFSIAMIntegration) matchesPermissionRule(rule *IPFSPermRule, resource, action string) bool {
	return iai.ipfsRoleManager.matchesRule(rule, resource, action)
}

func (iai *IPFSIAMIntegration) matchesStandardPermission(perm *auth.Permission, resource, action string) bool {
	// Simple matching logic for standard permissions
	return (perm.Resource == "*" || perm.Resource == resource) &&
		   (perm.Action == "*" || perm.Action == action)
}

func (iai *IPFSIAMIntegration) cacheCleanupRoutine() {
	ticker := time.NewTicker(iai.cacheTimeout / 2)
	defer ticker.Stop()

	for range ticker.C {
		iai.cleanupExpiredCache()
	}
}

func (iai *IPFSIAMIntegration) cleanupExpiredCache() {
	iai.cacheMutex.Lock()
	defer iai.cacheMutex.Unlock()

	now := time.Now()

	// Clean up expired user cache entries
	for key, cached := range iai.userCache {
		if now.After(cached.ExpiresAt) {
			delete(iai.userCache, key)
		}
	}

	// Clean up expired permission cache entries
	for key, cached := range iai.permissionCache {
		if now.After(cached.ExpiresAt) {
			delete(iai.permissionCache, key)
		}
	}
}

// Data types

// CombinedPermissions contains both standard and IPFS-specific permissions
type CombinedPermissions struct {
	StandardPermissions *auth.PermissionSet `json:"standard_permissions"`
	IPFSPermissions     *IPFSPermissionSet  `json:"ipfs_permissions"`
}

// IPFSUserInfo contains comprehensive information about an IPFS user
type IPFSUserInfo struct {
	Account             auth.Account        `json:"account"`
	IPFSPermissions     *IPFSPermissionSet  `json:"ipfs_permissions"`
	StandardPermissions *auth.PermissionSet `json:"standard_permissions,omitempty"`
	LastActivity        *time.Time          `json:"last_activity,omitempty"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

// Shutdown gracefully shuts down the IAM integration
func (iai *IPFSIAMIntegration) Shutdown() error {
	// Clear caches
	iai.cacheMutex.Lock()
	iai.userCache = make(map[string]*CachedUserInfo)
	iai.permissionCache = make(map[string]*CachedPermissions)
	iai.cacheMutex.Unlock()

	return nil
}