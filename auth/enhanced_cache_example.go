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

// ExampleEnhancedCacheUsage demonstrates how to use the enhanced cache system
func ExampleEnhancedCacheUsage() {
	// Create enhanced cache configuration
	config := &EnhancedCacheConfig{
		MaxSize:         1000,
		CleanupInterval: 5 * time.Minute,
		DefaultTTLs: map[CacheEntryType]time.Duration{
			UserCredentials: 15 * time.Minute,
			UserRoles:       30 * time.Minute,
			Permissions:     1 * time.Hour,
			MFASettings:     2 * time.Hour,
			SessionData:     10 * time.Minute,
		},
	}

	// Create enhanced cache
	cache := NewEnhancedCache(config)
	defer cache.Shutdown()

	// Store different types of data with appropriate TTLs
	cache.Set("user:alice:creds", Account{Access: "alice", Role: RoleUser}, 0, UserCredentials)
	cache.Set("user:alice:roles", []string{"user", "reader"}, 0, UserRoles)
	cache.Set("user:alice:perms", []string{"read", "write"}, 0, Permissions)
	cache.Set("user:alice:mfa", map[string]interface{}{"enabled": true}, 0, MFASettings)
	cache.Set("session:abc123", map[string]interface{}{"user": "alice"}, 0, SessionData)

	// Retrieve data
	if creds, found := cache.Get("user:alice:creds", UserCredentials); found {
		fmt.Printf("Found credentials: %+v\n", creds)
	}

	// Invalidate specific user data
	cache.InvalidateUser("alice")

	// Check cache statistics
	stats := cache.GetStats()
	fmt.Printf("Cache stats - Hits: %d, Misses: %d, Hit Rate: %.2f%%\n", 
		stats.Hits, stats.Misses, stats.HitRate())
}

// ExampleEnhancedIAMCacheUsage demonstrates how to use the enhanced IAM cache
func ExampleEnhancedIAMCacheUsage(baseService IAMService) {
	// Create enhanced IAM cache configuration
	config := &EnhancedIAMCacheConfig{
		CacheConfig: &EnhancedCacheConfig{
			MaxSize:         500,
			CleanupInterval: 5 * time.Minute,
			DefaultTTLs: map[CacheEntryType]time.Duration{
				UserCredentials: 15 * time.Minute,
			},
		},
		FallbackEnabled: true,
	}

	// Create enhanced IAM cache
	iamCache := NewEnhancedIAMCache(baseService, config)
	defer iamCache.Shutdown()

	// Use like a regular IAM service
	account := Account{
		Access: "testuser",
		Secret: "testsecret",
		Role:   RoleUser,
	}

	// Create account (will be cached)
	err := iamCache.CreateAccount(account)
	if err != nil {
		fmt.Printf("Error creating account: %v\n", err)
		return
	}

	// Get account (will hit cache on subsequent calls)
	retrievedAccount, err := iamCache.GetUserAccount("testuser")
	if err != nil {
		fmt.Printf("Error getting account: %v\n", err)
		return
	}

	fmt.Printf("Retrieved account: %+v\n", retrievedAccount)

	// Check cache performance
	stats := iamCache.GetCacheStats()
	fmt.Printf("Primary cache - Hits: %d, Misses: %d\n", stats.Hits, stats.Misses)

	fallbackStats := iamCache.GetFallbackCacheStats()
	fmt.Printf("Fallback cache - Size: %d, Fallback Active: %t\n", 
		fallbackStats.Size, fallbackStats.FallbackActive)

	// Check service health
	if iamCache.IsHealthy() {
		fmt.Println("IAM service is healthy")
	} else {
		fmt.Println("IAM service is unhealthy - using fallback cache")
	}
}

// ExampleCacheIntegrationWithExistingSystem shows how to integrate with existing IAM cache
func ExampleCacheIntegrationWithExistingSystem(opts *Opts) (IAMService, error) {
	// Create base IAM service as usual
	baseService, err := New(opts)
	if err != nil {
		return nil, err
	}

	// If caching is disabled, return base service
	if opts.CacheDisable {
		return baseService, nil
	}

	// Check if enhanced caching is requested (could be a new config option)
	useEnhancedCache := true // This could be a new config option

	if useEnhancedCache {
		// Use enhanced cache instead of basic cache
		config := &EnhancedIAMCacheConfig{
			CacheConfig: &EnhancedCacheConfig{
				MaxSize:         1000,
				CleanupInterval: time.Duration(opts.CachePrune) * time.Second,
				DefaultTTLs: map[CacheEntryType]time.Duration{
					UserCredentials: time.Duration(opts.CacheTTL) * time.Second,
				},
			},
			FallbackEnabled: true,
		}

		return NewEnhancedIAMCache(baseService, config), nil
	}

	// Fall back to existing cache implementation
	return NewCache(baseService,
		time.Duration(opts.CacheTTL)*time.Second,
		time.Duration(opts.CachePrune)*time.Second), nil
}