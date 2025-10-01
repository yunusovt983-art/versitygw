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
	"log"
	"sync"
	"time"
)

// MemoryCache represents the L1 in-memory cache with LRU eviction
type MemoryCache interface {
	Get(ctx context.Context, key string) (interface{}, error)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
	GetStats() *MemoryCacheStats
	IsHealthy() bool
	Shutdown(ctx context.Context) error
}

// MemoryCacheConfig holds configuration for the memory cache
type MemoryCacheConfig struct {
	MaxSize         int64         `json:"max_size"`          // Maximum cache size in bytes
	MaxEntries      int           `json:"max_entries"`       // Maximum number of entries
	DefaultTTL      time.Duration `json:"default_ttl"`       // Default TTL for entries
	CleanupInterval time.Duration `json:"cleanup_interval"`  // Cleanup interval for expired entries
	MetricsEnabled  bool          `json:"metrics_enabled"`   // Enable metrics collection
}

// MemoryCacheStats represents memory cache statistics
type MemoryCacheStats struct {
	Hits          int64         `json:"hits"`
	Misses        int64         `json:"misses"`
	Size          int64         `json:"size"`
	MaxSize       int64         `json:"max_size"`
	Entries       int           `json:"entries"`
	MaxEntries    int           `json:"max_entries"`
	Utilization   float64       `json:"utilization"`
	Evictions     int64         `json:"evictions"`
	AvgGetLatency time.Duration `json:"avg_get_latency"`
	AvgSetLatency time.Duration `json:"avg_set_latency"`
	Healthy       bool          `json:"healthy"`
}

// memoryCacheEntry represents a cache entry with LRU metadata
type memoryCacheEntry struct {
	key        string
	value      interface{}
	size       int64
	createdAt  time.Time
	accessedAt time.Time
	expiresAt  time.Time
	accessCount int64
	
	// LRU linked list pointers
	prev *memoryCacheEntry
	next *memoryCacheEntry
}

// lruMemoryCache implements MemoryCache with LRU eviction policy
type lruMemoryCache struct {
	config *MemoryCacheConfig
	logger *log.Logger
	
	// Cache storage
	entries map[string]*memoryCacheEntry
	mu      sync.RWMutex
	
	// LRU linked list
	head *memoryCacheEntry
	tail *memoryCacheEntry
	
	// Current state
	currentSize    int64
	currentEntries int
	
	// Statistics
	stats   *MemoryCacheStats
	statsMu sync.RWMutex
	
	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Health
	healthy bool
}

// NewMemoryCache creates a new LRU memory cache
func NewMemoryCache(config *MemoryCacheConfig, logger *log.Logger) (MemoryCache, error) {
	if config == nil {
		return nil, fmt.Errorf("memory cache config cannot be nil")
	}
	
	if logger == nil {
		logger = log.Default()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	cache := &lruMemoryCache{
		config:  config,
		logger:  logger,
		entries: make(map[string]*memoryCacheEntry),
		ctx:     ctx,
		cancel:  cancel,
		stats: &MemoryCacheStats{
			MaxSize:    config.MaxSize,
			MaxEntries: config.MaxEntries,
			Healthy:    true,
		},
		healthy: true,
	}
	
	// Initialize LRU linked list with dummy head and tail
	cache.head = &memoryCacheEntry{}
	cache.tail = &memoryCacheEntry{}
	cache.head.next = cache.tail
	cache.tail.prev = cache.head
	
	// Start cleanup goroutine
	cache.wg.Add(1)
	go cache.cleanupExpired()
	
	logger.Printf("Memory cache initialized with max size: %d bytes, max entries: %d", 
		config.MaxSize, config.MaxEntries)
	
	return cache, nil
}

// Get retrieves a value from the memory cache
func (c *lruMemoryCache) Get(ctx context.Context, key string) (interface{}, error) {
	start := time.Now()
	defer func() {
		c.statsMu.Lock()
		c.stats.AvgGetLatency = (c.stats.AvgGetLatency + time.Since(start)) / 2
		c.statsMu.Unlock()
	}()
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	entry, exists := c.entries[key]
	if !exists {
		c.statsMu.Lock()
		c.stats.Misses++
		c.statsMu.Unlock()
		return nil, fmt.Errorf("key not found: %s", key)
	}
	
	// Check if entry is expired
	if time.Now().After(entry.expiresAt) {
		c.removeEntryUnsafe(entry)
		c.statsMu.Lock()
		c.stats.Misses++
		c.statsMu.Unlock()
		return nil, fmt.Errorf("key expired: %s", key)
	}
	
	// Update access information
	entry.accessedAt = time.Now()
	entry.accessCount++
	
	// Move to front (most recently used)
	c.moveToFrontUnsafe(entry)
	
	c.statsMu.Lock()
	c.stats.Hits++
	c.statsMu.Unlock()
	
	return entry.value, nil
}

// Set stores a value in the memory cache
func (c *lruMemoryCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	start := time.Now()
	defer func() {
		c.statsMu.Lock()
		c.stats.AvgSetLatency = (c.stats.AvgSetLatency + time.Since(start)) / 2
		c.statsMu.Unlock()
	}()
	
	if ttl <= 0 {
		ttl = c.config.DefaultTTL
	}
	
	// Calculate entry size
	entrySize := c.calculateSize(value)
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Check if key already exists
	if existingEntry, exists := c.entries[key]; exists {
		// Update existing entry
		c.currentSize = c.currentSize - existingEntry.size + entrySize
		existingEntry.value = value
		existingEntry.size = entrySize
		existingEntry.accessedAt = time.Now()
		existingEntry.expiresAt = time.Now().Add(ttl)
		existingEntry.accessCount++
		
		// Move to front
		c.moveToFrontUnsafe(existingEntry)
		return nil
	}
	
	// Create new entry
	entry := &memoryCacheEntry{
		key:         key,
		value:       value,
		size:        entrySize,
		createdAt:   time.Now(),
		accessedAt:  time.Now(),
		expiresAt:   time.Now().Add(ttl),
		accessCount: 1,
	}
	
	// Check if we need to evict entries
	for (c.currentSize+entrySize > c.config.MaxSize || c.currentEntries >= c.config.MaxEntries) && c.currentEntries > 0 {
		c.evictLRUUnsafe()
	}
	
	// Add new entry
	c.entries[key] = entry
	c.currentSize += entrySize
	c.currentEntries++
	
	// Add to front of LRU list
	c.addToFrontUnsafe(entry)
	
	return nil
}

// Delete removes a value from the memory cache
func (c *lruMemoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	entry, exists := c.entries[key]
	if !exists {
		return nil // Key doesn't exist, consider it successful
	}
	
	c.removeEntryUnsafe(entry)
	return nil
}

// Clear removes all entries from the memory cache
func (c *lruMemoryCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Clear all entries
	c.entries = make(map[string]*memoryCacheEntry)
	c.currentSize = 0
	c.currentEntries = 0
	
	// Reset LRU list
	c.head.next = c.tail
	c.tail.prev = c.head
	
	return nil
}

// GetStats returns memory cache statistics
func (c *lruMemoryCache) GetStats() *MemoryCacheStats {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()
	
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	stats := *c.stats
	stats.Size = c.currentSize
	stats.Entries = c.currentEntries
	
	if c.config.MaxSize > 0 {
		stats.Utilization = float64(c.currentSize) / float64(c.config.MaxSize)
	}
	
	return &stats
}

// IsHealthy returns true if the memory cache is healthy
func (c *lruMemoryCache) IsHealthy() bool {
	return c.healthy
}

// Shutdown gracefully shuts down the memory cache
func (c *lruMemoryCache) Shutdown(ctx context.Context) error {
	c.logger.Println("Shutting down memory cache...")
	
	// Cancel context to stop background tasks
	c.cancel()
	
	// Wait for cleanup goroutine to finish
	c.wg.Wait()
	
	// Clear all entries
	c.Clear(ctx)
	
	c.logger.Println("Memory cache shutdown completed")
	return nil
}

// Private helper methods

// removeEntryUnsafe removes an entry from the cache (must be called with lock held)
func (c *lruMemoryCache) removeEntryUnsafe(entry *memoryCacheEntry) {
	// Remove from map
	delete(c.entries, entry.key)
	c.currentSize -= entry.size
	c.currentEntries--
	
	// Remove from LRU list
	if entry.prev != nil {
		entry.prev.next = entry.next
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	}
}

// moveToFrontUnsafe moves an entry to the front of the LRU list (must be called with lock held)
func (c *lruMemoryCache) moveToFrontUnsafe(entry *memoryCacheEntry) {
	// Remove from current position
	if entry.prev != nil {
		entry.prev.next = entry.next
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	}
	
	// Add to front
	c.addToFrontUnsafe(entry)
}

// addToFrontUnsafe adds an entry to the front of the LRU list (must be called with lock held)
func (c *lruMemoryCache) addToFrontUnsafe(entry *memoryCacheEntry) {
	entry.prev = c.head
	entry.next = c.head.next
	c.head.next.prev = entry
	c.head.next = entry
}

// evictLRUUnsafe evicts the least recently used entry (must be called with lock held)
func (c *lruMemoryCache) evictLRUUnsafe() {
	if c.tail.prev == c.head {
		return // No entries to evict
	}
	
	lru := c.tail.prev
	c.removeEntryUnsafe(lru)
	
	c.statsMu.Lock()
	c.stats.Evictions++
	c.statsMu.Unlock()
}

// calculateSize estimates the size of a value in bytes
func (c *lruMemoryCache) calculateSize(value interface{}) int64 {
	// This is a simplified size calculation
	// In a production system, you might want more accurate size calculation
	switch v := value.(type) {
	case string:
		return int64(len(v))
	case []byte:
		return int64(len(v))
	case *ObjectMapping:
		// Estimate size of ObjectMapping
		size := int64(len(v.S3Key) + len(v.Bucket) + len(v.CID))
		size += int64(len(v.ContentType) + len(v.ContentEncoding))
		for k, val := range v.UserMetadata {
			size += int64(len(k) + len(val))
		}
		for k, val := range v.Tags {
			size += int64(len(k) + len(val))
		}
		return size + 200 // Add overhead for struct fields
	case *ObjectMetadata:
		size := int64(len(v.ContentType) + len(v.ContentEncoding))
		for k, val := range v.UserMetadata {
			size += int64(len(k) + len(val))
		}
		for k, val := range v.Tags {
			size += int64(len(k) + len(val))
		}
		return size + 100 // Add overhead for struct fields
	case *BucketMetadata:
		size := int64(len(v.Name) + len(v.Region))
		for k, val := range v.Tags {
			size += int64(len(k) + len(val))
		}
		return size + 100 // Add overhead for struct fields
	case *PinStatusInfo:
		return int64(len(v.CID)) + 100 // Add overhead for struct fields
	default:
		// Default size estimation
		return 100
	}
}

// cleanupExpired removes expired entries from the cache
func (c *lruMemoryCache) cleanupExpired() {
	defer c.wg.Done()
	
	ticker := time.NewTicker(c.config.CleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.performCleanup()
		}
	}
}

// performCleanup performs the actual cleanup of expired entries
func (c *lruMemoryCache) performCleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	now := time.Now()
	var expiredKeys []string
	
	// Find expired entries
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}
	
	// Remove expired entries
	for _, key := range expiredKeys {
		if entry, exists := c.entries[key]; exists {
			c.removeEntryUnsafe(entry)
		}
	}
	
	if len(expiredKeys) > 0 {
		c.logger.Printf("Cleaned up %d expired entries from memory cache", len(expiredKeys))
	}
}