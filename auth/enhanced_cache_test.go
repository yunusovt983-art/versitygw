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

func TestEnhancedCache_BasicOperations(t *testing.T) {
	cache := NewEnhancedCache(nil) // Use default config
	defer cache.Shutdown()

	// Test Set and Get
	testValue := "test-value"
	cache.Set("test-key", testValue, 1*time.Minute, UserCredentials)

	value, found := cache.Get("test-key", UserCredentials)
	if !found {
		t.Fatal("Expected to find cached value")
	}

	if value != testValue {
		t.Fatalf("Expected %s, got %s", testValue, value)
	}

	// Test cache miss
	_, found = cache.Get("non-existent-key", UserCredentials)
	if found {
		t.Fatal("Expected cache miss for non-existent key")
	}
}

func TestEnhancedCache_TTLExpiration(t *testing.T) {
	cache := NewEnhancedCache(nil)
	defer cache.Shutdown()

	// Set with very short TTL
	cache.Set("expire-key", "expire-value", 10*time.Millisecond, UserCredentials)

	// Should be available immediately
	_, found := cache.Get("expire-key", UserCredentials)
	if !found {
		t.Fatal("Expected to find cached value before expiration")
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Should be expired now
	_, found = cache.Get("expire-key", UserCredentials)
	if found {
		t.Fatal("Expected cache miss after expiration")
	}
}

func TestEnhancedCache_LRUEviction(t *testing.T) {
	config := &EnhancedCacheConfig{
		MaxSize:         3, // Small cache for testing
		CleanupInterval: 1 * time.Minute,
		DefaultTTLs: map[CacheEntryType]time.Duration{
			UserCredentials: 1 * time.Hour,
		},
	}

	cache := NewEnhancedCache(config)
	defer cache.Shutdown()

	// Fill cache to capacity
	cache.Set("key1", "value1", 1*time.Hour, UserCredentials)
	cache.Set("key2", "value2", 1*time.Hour, UserCredentials)
	cache.Set("key3", "value3", 1*time.Hour, UserCredentials)

	// Access key1 to make it recently used
	cache.Get("key1", UserCredentials)

	// Add one more item, should evict key2 (least recently used)
	cache.Set("key4", "value4", 1*time.Hour, UserCredentials)

	// key1 should still be there (recently accessed)
	_, found := cache.Get("key1", UserCredentials)
	if !found {
		t.Fatal("Expected key1 to still be in cache (recently accessed)")
	}

	// key2 should be evicted
	_, found = cache.Get("key2", UserCredentials)
	if found {
		t.Fatal("Expected key2 to be evicted (LRU)")
	}

	// key3 and key4 should still be there
	_, found = cache.Get("key3", UserCredentials)
	if !found {
		t.Fatal("Expected key3 to still be in cache")
	}

	_, found = cache.Get("key4", UserCredentials)
	if !found {
		t.Fatal("Expected key4 to still be in cache")
	}
}

func TestEnhancedCache_EntryTypeValidation(t *testing.T) {
	cache := NewEnhancedCache(nil)
	defer cache.Shutdown()

	// Set with UserCredentials type
	cache.Set("test-key", "test-value", 1*time.Minute, UserCredentials)

	// Try to get with correct type
	_, found := cache.Get("test-key", UserCredentials)
	if !found {
		t.Fatal("Expected to find value with correct entry type")
	}

	// Try to get with wrong type
	_, found = cache.Get("test-key", UserRoles)
	if found {
		t.Fatal("Expected cache miss with wrong entry type")
	}
}

func TestEnhancedCache_PatternInvalidation(t *testing.T) {
	cache := NewEnhancedCache(nil)
	defer cache.Shutdown()

	// Set multiple keys with pattern
	cache.Set("user:alice:creds", "alice-creds", 1*time.Hour, UserCredentials)
	cache.Set("user:alice:roles", "alice-roles", 1*time.Hour, UserRoles)
	cache.Set("user:bob:creds", "bob-creds", 1*time.Hour, UserCredentials)
	cache.Set("session:123", "session-data", 1*time.Hour, SessionData)

	// Invalidate all alice entries
	err := cache.Invalidate("^user:alice:")
	if err != nil {
		t.Fatalf("Failed to invalidate pattern: %v", err)
	}

	// Alice entries should be gone
	_, found := cache.Get("user:alice:creds", UserCredentials)
	if found {
		t.Fatal("Expected alice creds to be invalidated")
	}

	_, found = cache.Get("user:alice:roles", UserRoles)
	if found {
		t.Fatal("Expected alice roles to be invalidated")
	}

	// Bob and session entries should remain
	_, found = cache.Get("user:bob:creds", UserCredentials)
	if !found {
		t.Fatal("Expected bob creds to remain")
	}

	_, found = cache.Get("session:123", SessionData)
	if !found {
		t.Fatal("Expected session data to remain")
	}
}

func TestEnhancedCache_UserInvalidation(t *testing.T) {
	cache := NewEnhancedCache(nil)
	defer cache.Shutdown()

	// Set multiple entries for a user
	cache.Set("alice:creds", "alice-creds", 1*time.Hour, UserCredentials)
	cache.Set("alice:roles", "alice-roles", 1*time.Hour, UserRoles)
	cache.Set("bob:creds", "bob-creds", 1*time.Hour, UserCredentials)

	// Invalidate all alice entries
	err := cache.InvalidateUser("alice")
	if err != nil {
		t.Fatalf("Failed to invalidate user: %v", err)
	}

	// Alice entries should be gone
	_, found := cache.Get("alice:creds", UserCredentials)
	if found {
		t.Fatal("Expected alice creds to be invalidated")
	}

	_, found = cache.Get("alice:roles", UserRoles)
	if found {
		t.Fatal("Expected alice roles to be invalidated")
	}

	// Bob entries should remain
	_, found = cache.Get("bob:creds", UserCredentials)
	if !found {
		t.Fatal("Expected bob creds to remain")
	}
}

func TestEnhancedCache_TypeInvalidation(t *testing.T) {
	cache := NewEnhancedCache(nil)
	defer cache.Shutdown()

	// Set entries of different types
	cache.Set("user1:creds", "creds1", 1*time.Hour, UserCredentials)
	cache.Set("user2:creds", "creds2", 1*time.Hour, UserCredentials)
	cache.Set("user1:roles", "roles1", 1*time.Hour, UserRoles)
	cache.Set("session1", "session1", 1*time.Hour, SessionData)

	// Invalidate all UserCredentials entries
	err := cache.InvalidateType(UserCredentials)
	if err != nil {
		t.Fatalf("Failed to invalidate type: %v", err)
	}

	// UserCredentials entries should be gone
	_, found := cache.Get("user1:creds", UserCredentials)
	if found {
		t.Fatal("Expected user1 creds to be invalidated")
	}

	_, found = cache.Get("user2:creds", UserCredentials)
	if found {
		t.Fatal("Expected user2 creds to be invalidated")
	}

	// Other types should remain
	_, found = cache.Get("user1:roles", UserRoles)
	if !found {
		t.Fatal("Expected user1 roles to remain")
	}

	_, found = cache.Get("session1", SessionData)
	if !found {
		t.Fatal("Expected session1 to remain")
	}
}

func TestEnhancedCache_Stats(t *testing.T) {
	cache := NewEnhancedCache(nil)
	defer cache.Shutdown()

	// Initial stats
	stats := cache.GetStats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Fatal("Expected zero hits and misses initially")
	}

	// Add some entries and access them
	cache.Set("key1", "value1", 1*time.Hour, UserCredentials)
	cache.Set("key2", "value2", 1*time.Hour, UserCredentials)

	// Hit
	cache.Get("key1", UserCredentials)
	// Miss
	cache.Get("non-existent", UserCredentials)

	stats = cache.GetStats()
	if stats.Hits != 1 {
		t.Fatalf("Expected 1 hit, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Fatalf("Expected 1 miss, got %d", stats.Misses)
	}
	if stats.Size != 2 {
		t.Fatalf("Expected size 2, got %d", stats.Size)
	}

	// Test hit rate calculation
	hitRate := stats.HitRate()
	expectedRate := 50.0 // 1 hit out of 2 total
	if hitRate != expectedRate {
		t.Fatalf("Expected hit rate %.1f%%, got %.1f%%", expectedRate, hitRate)
	}
}

func TestEnhancedCache_FallbackMode(t *testing.T) {
	cache := NewEnhancedCache(nil)
	defer cache.Shutdown()

	// Initially not in fallback mode
	stats := cache.GetStats()
	if stats.FallbackActive {
		t.Fatal("Expected fallback mode to be inactive initially")
	}

	// Enable fallback mode
	cache.SetFallbackMode(true)

	stats = cache.GetStats()
	if !stats.FallbackActive {
		t.Fatal("Expected fallback mode to be active")
	}

	// Disable fallback mode
	cache.SetFallbackMode(false)

	stats = cache.GetStats()
	if stats.FallbackActive {
		t.Fatal("Expected fallback mode to be inactive")
	}
}

func TestEnhancedCache_DefaultTTLs(t *testing.T) {
	config := &EnhancedCacheConfig{
		MaxSize:         100,
		CleanupInterval: 1 * time.Minute,
		DefaultTTLs: map[CacheEntryType]time.Duration{
			UserCredentials: 10 * time.Millisecond,
			UserRoles:       20 * time.Millisecond,
		},
	}

	cache := NewEnhancedCache(config)
	defer cache.Shutdown()

	// Set without explicit TTL (should use default)
	cache.Set("creds-key", "creds-value", 0, UserCredentials)
	cache.Set("roles-key", "roles-value", 0, UserRoles)

	// Both should be available immediately
	_, found := cache.Get("creds-key", UserCredentials)
	if !found {
		t.Fatal("Expected creds to be available immediately")
	}

	_, found = cache.Get("roles-key", UserRoles)
	if !found {
		t.Fatal("Expected roles to be available immediately")
	}

	// Wait for creds to expire (10ms)
	time.Sleep(15 * time.Millisecond)

	_, found = cache.Get("creds-key", UserCredentials)
	if found {
		t.Fatal("Expected creds to be expired")
	}

	// Roles should still be available (20ms TTL)
	_, found = cache.Get("roles-key", UserRoles)
	if !found {
		t.Fatal("Expected roles to still be available")
	}

	// Wait for roles to expire
	time.Sleep(10 * time.Millisecond)

	_, found = cache.Get("roles-key", UserRoles)
	if found {
		t.Fatal("Expected roles to be expired")
	}
}

func TestCacheEntryType_String(t *testing.T) {
	tests := []struct {
		entryType CacheEntryType
		expected  string
	}{
		{UserCredentials, "UserCredentials"},
		{UserRoles, "UserRoles"},
		{Permissions, "Permissions"},
		{MFASettings, "MFASettings"},
		{SessionData, "SessionData"},
		{CacheEntryType(999), "Unknown"},
	}

	for _, test := range tests {
		result := test.entryType.String()
		if result != test.expected {
			t.Fatalf("Expected %s, got %s", test.expected, result)
		}
	}
}