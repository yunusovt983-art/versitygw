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
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// CacheEntryType defines the type of cache entry for different TTL policies
type CacheEntryType int

const (
	UserCredentials CacheEntryType = iota
	UserRoles
	Permissions
	MFASettings
	SessionData
)

// String returns the string representation of CacheEntryType
func (c CacheEntryType) String() string {
	switch c {
	case UserCredentials:
		return "UserCredentials"
	case UserRoles:
		return "UserRoles"
	case Permissions:
		return "Permissions"
	case MFASettings:
		return "MFASettings"
	case SessionData:
		return "SessionData"
	default:
		return "Unknown"
	}
}

// CacheStats provides statistics about cache performance
type CacheStats struct {
	Hits           int64
	Misses         int64
	Evictions      int64
	Size           int
	MaxSize        int
	FallbackActive bool
	LastCleanup    time.Time
}

// HitRate returns the cache hit rate as a percentage
func (s CacheStats) HitRate() float64 {
	total := s.Hits + s.Misses
	if total == 0 {
		return 0
	}
	return float64(s.Hits) / float64(total) * 100
}

// EnhancedCache defines the interface for the enhanced caching system
type EnhancedCache interface {
	Get(key string, entryType CacheEntryType) (interface{}, bool)
	Set(key string, value interface{}, ttl time.Duration, entryType CacheEntryType)
	Invalidate(pattern string) error
	InvalidateUser(userID string) error
	InvalidateType(entryType CacheEntryType) error
	SetFallbackMode(enabled bool)
	GetStats() CacheStats
	Shutdown() error
}

// cacheEntry represents a single cache entry with metadata
type cacheEntry struct {
	value      interface{}
	expiry     time.Time
	entryType  CacheEntryType
	accessTime time.Time
	key        string
}

// isExpired checks if the cache entry has expired
func (e *cacheEntry) isExpired() bool {
	return time.Now().After(e.expiry)
}

// touch updates the access time for LRU tracking
func (e *cacheEntry) touch() {
	e.accessTime = time.Now()
}

// enhancedCacheImpl implements the EnhancedCache interface
type enhancedCacheImpl struct {
	mu           sync.RWMutex
	entries      map[string]*cacheEntry
	maxSize      int
	fallbackMode bool
	stats        CacheStats
	cancel       context.CancelFunc
	
	// Default TTL values for different entry types
	defaultTTLs map[CacheEntryType]time.Duration
}

// EnhancedCacheConfig holds configuration for the enhanced cache
type EnhancedCacheConfig struct {
	MaxSize         int
	CleanupInterval time.Duration
	DefaultTTLs     map[CacheEntryType]time.Duration
}

// DefaultEnhancedCacheConfig returns a default configuration
func DefaultEnhancedCacheConfig() *EnhancedCacheConfig {
	return &EnhancedCacheConfig{
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
}

// NewEnhancedCache creates a new enhanced cache instance
func NewEnhancedCache(config *EnhancedCacheConfig) EnhancedCache {
	if config == nil {
		config = DefaultEnhancedCacheConfig()
	}

	cache := &enhancedCacheImpl{
		entries:     make(map[string]*cacheEntry),
		maxSize:     config.MaxSize,
		defaultTTLs: config.DefaultTTLs,
		stats: CacheStats{
			MaxSize: config.MaxSize,
		},
	}

	// Start cleanup goroutine
	ctx, cancel := context.WithCancel(context.Background())
	cache.cancel = cancel
	go cache.cleanupLoop(ctx, config.CleanupInterval)

	return cache
}

// Get retrieves a value from the cache
func (c *enhancedCacheImpl) Get(key string, entryType CacheEntryType) (interface{}, bool) {
	c.mu.RLock()
	entry, exists := c.entries[key]
	c.mu.RUnlock()

	if !exists {
		c.mu.Lock()
		c.stats.Misses++
		c.mu.Unlock()
		return nil, false
	}

	if entry.isExpired() {
		c.mu.Lock()
		delete(c.entries, key)
		c.stats.Misses++
		c.mu.Unlock()
		return nil, false
	}

	// Check if entry type matches (optional validation)
	if entry.entryType != entryType {
		c.mu.Lock()
		c.stats.Misses++
		c.mu.Unlock()
		return nil, false
	}

	// Update access time for LRU
	c.mu.Lock()
	entry.touch()
	c.stats.Hits++
	c.mu.Unlock()

	return entry.value, true
}

// Set stores a value in the cache with the specified TTL
func (c *enhancedCacheImpl) Set(key string, value interface{}, ttl time.Duration, entryType CacheEntryType) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Use default TTL if not specified
	if ttl == 0 {
		if defaultTTL, exists := c.defaultTTLs[entryType]; exists {
			ttl = defaultTTL
		} else {
			ttl = 15 * time.Minute // fallback default
		}
	}

	// Check if we need to evict entries (LRU)
	if len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	entry := &cacheEntry{
		value:      value,
		expiry:     time.Now().Add(ttl),
		entryType:  entryType,
		accessTime: time.Now(),
		key:        key,
	}

	c.entries[key] = entry
	c.stats.Size = len(c.entries)
}

// evictLRU removes the least recently used entry
func (c *enhancedCacheImpl) evictLRU() {
	if len(c.entries) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range c.entries {
		if first || entry.accessTime.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.accessTime
			first = false
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
		c.stats.Evictions++
		c.stats.Size = len(c.entries)
	}
}

// Invalidate removes cache entries matching the given pattern
func (c *enhancedCacheImpl) Invalidate(pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	keysToDelete := make([]string, 0)
	for key := range c.entries {
		if regex.MatchString(key) {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		delete(c.entries, key)
	}

	c.stats.Size = len(c.entries)
	return nil
}

// InvalidateUser removes all cache entries for a specific user
func (c *enhancedCacheImpl) InvalidateUser(userID string) error {
	pattern := fmt.Sprintf("^%s:", regexp.QuoteMeta(userID))
	return c.Invalidate(pattern)
}

// InvalidateType removes all cache entries of a specific type
func (c *enhancedCacheImpl) InvalidateType(entryType CacheEntryType) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	keysToDelete := make([]string, 0)
	for key, entry := range c.entries {
		if entry.entryType == entryType {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		delete(c.entries, key)
	}

	c.stats.Size = len(c.entries)
	return nil
}

// SetFallbackMode enables or disables fallback mode
func (c *enhancedCacheImpl) SetFallbackMode(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.fallbackMode = enabled
	c.stats.FallbackActive = enabled
}

// GetStats returns current cache statistics
func (c *enhancedCacheImpl) GetStats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	statsCopy := c.stats
	statsCopy.Size = len(c.entries)
	return statsCopy
}

// Shutdown gracefully shuts down the cache
func (c *enhancedCacheImpl) Shutdown() error {
	if c.cancel != nil {
		c.cancel()
	}
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Clear all entries
	c.entries = make(map[string]*cacheEntry)
	c.stats.Size = 0
	
	return nil
}

// cleanupLoop periodically removes expired entries
func (c *enhancedCacheImpl) cleanupLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// cleanup removes expired entries
func (c *enhancedCacheImpl) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	keysToDelete := make([]string, 0)

	for key, entry := range c.entries {
		if now.After(entry.expiry) {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		delete(c.entries, key)
	}

	c.stats.Size = len(c.entries)
	c.stats.LastCleanup = now
}