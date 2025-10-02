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
	"regexp"
	"strings"
	"time"
)

// EnhancedIAMCache provides enhanced caching capabilities for IAM operations
type EnhancedIAMCache struct {
	service       IAMService
	cache         EnhancedCache
	fallbackCache EnhancedCache // Separate cache for fallback data
}

var _ IAMService = &EnhancedIAMCache{}

// EnhancedIAMCacheConfig holds configuration for the enhanced IAM cache
type EnhancedIAMCacheConfig struct {
	CacheConfig         *EnhancedCacheConfig
	FallbackCacheConfig *EnhancedCacheConfig
	FallbackEnabled     bool
}

// DefaultEnhancedIAMCacheConfig returns a default configuration
func DefaultEnhancedIAMCacheConfig() *EnhancedIAMCacheConfig {
	return &EnhancedIAMCacheConfig{
		CacheConfig:         DefaultEnhancedCacheConfig(),
		FallbackCacheConfig: DefaultEnhancedCacheConfig(),
		FallbackEnabled:     true,
	}
}

// NewEnhancedIAMCache creates a new enhanced IAM cache
func NewEnhancedIAMCache(service IAMService, config *EnhancedIAMCacheConfig) *EnhancedIAMCache {
	if config == nil {
		config = DefaultEnhancedIAMCacheConfig()
	}

	cache := NewEnhancedCache(config.CacheConfig)
	var fallbackCache EnhancedCache
	
	if config.FallbackEnabled {
		// Fallback cache with longer TTL for emergency situations
		fallbackConfig := config.FallbackCacheConfig
		if fallbackConfig == nil {
			fallbackConfig = DefaultEnhancedCacheConfig()
		}
		if fallbackConfig.DefaultTTLs == nil {
			fallbackConfig.DefaultTTLs = make(map[CacheEntryType]time.Duration)
		}
		
		// Set longer TTLs for fallback cache
		for entryType, ttl := range config.CacheConfig.DefaultTTLs {
			fallbackConfig.DefaultTTLs[entryType] = ttl * 4 // 4x longer for fallback
		}
		
		fallbackCache = NewEnhancedCache(fallbackConfig)
	}

	return &EnhancedIAMCache{
		service:       service,
		cache:         cache,
		fallbackCache: fallbackCache,
	}
}

// CreateAccount creates an account and updates both caches
func (c *EnhancedIAMCache) CreateAccount(account Account) error {
	err := c.service.CreateAccount(account)
	if err != nil {
		return err
	}

	// Create a copy to avoid memory issues
	acct := Account{
		Access:  strings.Clone(account.Access),
		Secret:  strings.Clone(account.Secret),
		Role:    Role(strings.Clone(string(account.Role))),
		UserID:  account.UserID,
		GroupID: account.GroupID,
	}

	// Store in primary cache
	key := c.getUserKey(acct.Access)
	c.cache.Set(key, acct, 0, UserCredentials)

	// Store in fallback cache if enabled
	if c.fallbackCache != nil {
		c.fallbackCache.Set(key, acct, 0, UserCredentials)
	}

	return nil
}

// GetUserAccount retrieves user account with fallback support
func (c *EnhancedIAMCache) GetUserAccount(access string) (Account, error) {
	key := c.getUserKey(access)

	// Try primary cache first
	if value, found := c.cache.Get(key, UserCredentials); found {
		if account, ok := value.(Account); ok {
			return account, nil
		}
	}

	// Try to get from IAM service
	account, err := c.service.GetUserAccount(access)
	if err == nil {
		// Success - update both caches
		c.cache.Set(key, account, 0, UserCredentials)
		if c.fallbackCache != nil {
			c.fallbackCache.Set(key, account, 0, UserCredentials)
		}
		return account, nil
	}

	// IAM service failed - try fallback cache if available
	if c.fallbackCache != nil {
		if value, found := c.fallbackCache.Get(key, UserCredentials); found {
			if account, ok := value.(Account); ok {
				// Enable fallback mode to indicate we're using stale data
				c.cache.SetFallbackMode(true)
				return account, nil
			}
		}
	}

	// No fallback available
	return Account{}, err
}

// UpdateUserAccount updates an account and invalidates related cache entries
func (c *EnhancedIAMCache) UpdateUserAccount(access string, props MutableProps) error {
	err := c.service.UpdateUserAccount(access, props)
	if err != nil {
		return err
	}

	// Invalidate user-specific cache entries
	key := c.getUserKey(access)
	c.cache.Invalidate("^" + regexp.QuoteMeta(key) + "$")
	if c.fallbackCache != nil {
		c.fallbackCache.Invalidate("^" + regexp.QuoteMeta(key) + "$")
	}

	// Get updated account and cache it
	if account, err := c.service.GetUserAccount(access); err == nil {
		key := c.getUserKey(access)
		c.cache.Set(key, account, 0, UserCredentials)
		if c.fallbackCache != nil {
			c.fallbackCache.Set(key, account, 0, UserCredentials)
		}
	}

	return nil
}

// DeleteUserAccount deletes an account and removes from caches
func (c *EnhancedIAMCache) DeleteUserAccount(access string) error {
	err := c.service.DeleteUserAccount(access)
	if err != nil {
		return err
	}

	// Remove from both caches
	key := c.getUserKey(access)
	c.cache.Invalidate("^" + regexp.QuoteMeta(key) + "$")
	if c.fallbackCache != nil {
		c.fallbackCache.Invalidate("^" + regexp.QuoteMeta(key) + "$")
	}

	return nil
}

// ListUserAccounts is a passthrough to the underlying service
func (c *EnhancedIAMCache) ListUserAccounts() ([]Account, error) {
	return c.service.ListUserAccounts()
}

// Shutdown gracefully shuts down the cache
func (c *EnhancedIAMCache) Shutdown() error {
	if c.cache != nil {
		c.cache.Shutdown()
	}
	if c.fallbackCache != nil {
		c.fallbackCache.Shutdown()
	}
	return c.service.Shutdown()
}

// InvalidateUser invalidates all cache entries for a specific user
func (c *EnhancedIAMCache) InvalidateUser(userID string) error {
	if err := c.cache.InvalidateUser(userID); err != nil {
		return err
	}
	
	if c.fallbackCache != nil {
		if err := c.fallbackCache.InvalidateUser(userID); err != nil {
			return err
		}
	}
	
	return nil
}

// InvalidatePattern invalidates cache entries matching a pattern
func (c *EnhancedIAMCache) InvalidatePattern(pattern string) error {
	if err := c.cache.Invalidate(pattern); err != nil {
		return err
	}
	
	if c.fallbackCache != nil {
		if err := c.fallbackCache.Invalidate(pattern); err != nil {
			return err
		}
	}
	
	return nil
}

// InvalidateType invalidates all cache entries of a specific type
func (c *EnhancedIAMCache) InvalidateType(entryType CacheEntryType) error {
	if err := c.cache.InvalidateType(entryType); err != nil {
		return err
	}
	
	if c.fallbackCache != nil {
		if err := c.fallbackCache.InvalidateType(entryType); err != nil {
			return err
		}
	}
	
	return nil
}

// SetFallbackMode enables or disables fallback mode
func (c *EnhancedIAMCache) SetFallbackMode(enabled bool) {
	c.cache.SetFallbackMode(enabled)
	if c.fallbackCache != nil {
		c.fallbackCache.SetFallbackMode(enabled)
	}
}

// GetCacheStats returns statistics for the primary cache
func (c *EnhancedIAMCache) GetCacheStats() CacheStats {
	return c.cache.GetStats()
}

// GetFallbackCacheStats returns statistics for the fallback cache
func (c *EnhancedIAMCache) GetFallbackCacheStats() CacheStats {
	if c.fallbackCache != nil {
		return c.fallbackCache.GetStats()
	}
	return CacheStats{}
}

// IsHealthy checks if the underlying IAM service is healthy
func (c *EnhancedIAMCache) IsHealthy() bool {
	// Try a simple operation to check service health
	_, err := c.service.ListUserAccounts()
	healthy := err == nil
	
	// Update fallback mode based on health
	c.cache.SetFallbackMode(!healthy)
	if c.fallbackCache != nil {
		c.fallbackCache.SetFallbackMode(!healthy)
	}
	
	return healthy
}

// getUserKey generates a cache key for user credentials
func (c *EnhancedIAMCache) getUserKey(access string) string {
	return fmt.Sprintf("user:%s", access)
}

// getRoleKey generates a cache key for user roles
func (c *EnhancedIAMCache) getRoleKey(userID string) string {
	return fmt.Sprintf("role:%s", userID)
}

// getPermissionKey generates a cache key for permissions
func (c *EnhancedIAMCache) getPermissionKey(userID string) string {
	return fmt.Sprintf("perm:%s", userID)
}

// getMFAKey generates a cache key for MFA settings
func (c *EnhancedIAMCache) getMFAKey(userID string) string {
	return fmt.Sprintf("mfa:%s", userID)
}

// getSessionKey generates a cache key for session data
func (c *EnhancedIAMCache) getSessionKey(sessionID string) string {
	return fmt.Sprintf("session:%s", sessionID)
}