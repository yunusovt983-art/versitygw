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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"
)

// RedisCache represents the L2 Redis cluster cache
type RedisCache interface {
	Get(ctx context.Context, key string) (interface{}, error)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
	GetStats() *RedisCacheStats
	IsHealthy() bool
	Shutdown(ctx context.Context) error
}

// RedisCacheConfig holds configuration for the Redis cache
type RedisCacheConfig struct {
	Endpoints      []string      `json:"endpoints"`       // Redis cluster endpoints
	Password       string        `json:"password"`        // Redis password
	DB             int           `json:"db"`              // Redis database number
	MaxRetries     int           `json:"max_retries"`     // Maximum retry attempts
	DialTimeout    time.Duration `json:"dial_timeout"`    // Connection timeout
	ReadTimeout    time.Duration `json:"read_timeout"`    // Read timeout
	WriteTimeout   time.Duration `json:"write_timeout"`   // Write timeout
	PoolSize       int           `json:"pool_size"`       // Connection pool size
	DefaultTTL     time.Duration `json:"default_ttl"`     // Default TTL for entries
	AsyncWrites    bool          `json:"async_writes"`    // Enable asynchronous writes
	Compression    bool          `json:"compression"`     // Enable compression
	MetricsEnabled bool          `json:"metrics_enabled"` // Enable metrics collection
}

// RedisCacheStats represents Redis cache statistics
type RedisCacheStats struct {
	Hits          int64         `json:"hits"`
	Misses        int64         `json:"misses"`
	Size          int64         `json:"size"`
	MaxSize       int64         `json:"max_size"`
	Utilization   float64       `json:"utilization"`
	Evictions     int64         `json:"evictions"`
	AvgGetLatency time.Duration `json:"avg_get_latency"`
	AvgSetLatency time.Duration `json:"avg_set_latency"`
	Connections   int           `json:"connections"`
	Healthy       bool          `json:"healthy"`
}

// MockRedisClient is a simple in-memory implementation for testing/development
// In production, this would be replaced with a real Redis client like go-redis
type MockRedisClient struct {
	data    map[string]*redisEntry
	mu      sync.RWMutex
	logger  *log.Logger
	healthy bool
}

type redisEntry struct {
	value     []byte
	expiresAt time.Time
	createdAt time.Time
}

// redisCache implements RedisCache using a mock Redis client
type redisCache struct {
	config *RedisCacheConfig
	logger *log.Logger
	client *MockRedisClient
	
	// Statistics
	stats   *RedisCacheStats
	statsMu sync.RWMutex
	
	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Health
	healthy bool
}

// NewRedisCache creates a new Redis cache
func NewRedisCache(config *RedisCacheConfig, logger *log.Logger) (RedisCache, error) {
	if config == nil {
		return nil, fmt.Errorf("Redis cache config cannot be nil")
	}
	
	if logger == nil {
		logger = log.Default()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	// Initialize mock Redis client
	// In production, this would initialize a real Redis cluster client
	client := &MockRedisClient{
		data:    make(map[string]*redisEntry),
		logger:  logger,
		healthy: true,
	}
	
	cache := &redisCache{
		config: config,
		logger: logger,
		client: client,
		ctx:    ctx,
		cancel: cancel,
		stats: &RedisCacheStats{
			Healthy: true,
		},
		healthy: true,
	}
	
	// Start background tasks
	if config.MetricsEnabled {
		cache.wg.Add(1)
		go cache.metricsCollector()
	}
	
	cache.wg.Add(1)
	go cache.cleanupExpired()
	
	logger.Printf("Redis cache initialized with %d endpoints", len(config.Endpoints))
	return cache, nil
}

// Get retrieves a value from the Redis cache
func (c *redisCache) Get(ctx context.Context, key string) (interface{}, error) {
	start := time.Now()
	defer func() {
		c.statsMu.Lock()
		c.stats.AvgGetLatency = (c.stats.AvgGetLatency + time.Since(start)) / 2
		c.statsMu.Unlock()
	}()
	
	c.client.mu.RLock()
	entry, exists := c.client.data[key]
	c.client.mu.RUnlock()
	
	if !exists {
		c.statsMu.Lock()
		c.stats.Misses++
		c.statsMu.Unlock()
		return nil, fmt.Errorf("key not found: %s", key)
	}
	
	// Check if entry is expired
	if time.Now().After(entry.expiresAt) {
		c.client.mu.Lock()
		delete(c.client.data, key)
		c.client.mu.Unlock()
		
		c.statsMu.Lock()
		c.stats.Misses++
		c.statsMu.Unlock()
		return nil, fmt.Errorf("key expired: %s", key)
	}
	
	// Deserialize value
	value, err := c.deserializeValue(entry.value)
	if err != nil {
		c.statsMu.Lock()
		c.stats.Misses++
		c.statsMu.Unlock()
		return nil, fmt.Errorf("failed to deserialize value: %w", err)
	}
	
	c.statsMu.Lock()
	c.stats.Hits++
	c.statsMu.Unlock()
	
	return value, nil
}

// Set stores a value in the Redis cache
func (c *redisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	start := time.Now()
	defer func() {
		c.statsMu.Lock()
		c.stats.AvgSetLatency = (c.stats.AvgSetLatency + time.Since(start)) / 2
		c.statsMu.Unlock()
	}()
	
	if ttl <= 0 {
		ttl = c.config.DefaultTTL
	}
	
	// Serialize value
	data, err := c.serializeValue(value)
	if err != nil {
		return fmt.Errorf("failed to serialize value: %w", err)
	}
	
	entry := &redisEntry{
		value:     data,
		expiresAt: time.Now().Add(ttl),
		createdAt: time.Now(),
	}
	
	c.client.mu.Lock()
	c.client.data[key] = entry
	c.client.mu.Unlock()
	
	return nil
}

// Delete removes a value from the Redis cache
func (c *redisCache) Delete(ctx context.Context, key string) error {
	c.client.mu.Lock()
	delete(c.client.data, key)
	c.client.mu.Unlock()
	
	return nil
}

// Clear removes all entries from the Redis cache
func (c *redisCache) Clear(ctx context.Context) error {
	c.client.mu.Lock()
	c.client.data = make(map[string]*redisEntry)
	c.client.mu.Unlock()
	
	return nil
}

// GetStats returns Redis cache statistics
func (c *redisCache) GetStats() *RedisCacheStats {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()
	
	c.client.mu.RLock()
	defer c.client.mu.RUnlock()
	
	stats := *c.stats
	stats.Size = int64(len(c.client.data))
	stats.Connections = 1 // Mock value
	
	return &stats
}

// IsHealthy returns true if the Redis cache is healthy
func (c *redisCache) IsHealthy() bool {
	return c.healthy && c.client.healthy
}

// Shutdown gracefully shuts down the Redis cache
func (c *redisCache) Shutdown(ctx context.Context) error {
	c.logger.Println("Shutting down Redis cache...")
	
	// Cancel context to stop background tasks
	c.cancel()
	
	// Wait for background tasks to finish
	c.wg.Wait()
	
	// Clear all entries
	c.Clear(ctx)
	
	c.logger.Println("Redis cache shutdown completed")
	return nil
}

// Private helper methods

// serializeValue serializes a value to bytes with optional compression
func (c *redisCache) serializeValue(value interface{}) ([]byte, error) {
	// Serialize to JSON
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("JSON marshal error: %w", err)
	}
	
	// Apply compression if enabled
	if c.config.Compression {
		return c.compressData(data)
	}
	
	return data, nil
}

// deserializeValue deserializes bytes to a value with optional decompression
func (c *redisCache) deserializeValue(data []byte) (interface{}, error) {
	// Apply decompression if needed
	if c.config.Compression {
		var err error
		data, err = c.decompressData(data)
		if err != nil {
			return nil, fmt.Errorf("decompression error: %w", err)
		}
	}
	
	// Try to unmarshal as different types based on JSON structure
	var temp map[string]interface{}
	if err := json.Unmarshal(data, &temp); err != nil {
		// If it's not a JSON object, try as string
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return nil, fmt.Errorf("JSON unmarshal error: %w", err)
		}
		return str, nil
	}
	
	// Determine specific type based on fields
	if _, hasS3Key := temp["s3_key"]; hasS3Key {
		var mapping ObjectMapping
		if err := json.Unmarshal(data, &mapping); err != nil {
			return nil, fmt.Errorf("ObjectMapping unmarshal error: %w", err)
		}
		return &mapping, nil
	}
	
	if _, hasContentType := temp["content_type"]; hasContentType {
		var metadata ObjectMetadata
		if err := json.Unmarshal(data, &metadata); err != nil {
			return nil, fmt.Errorf("ObjectMetadata unmarshal error: %w", err)
		}
		return &metadata, nil
	}
	
	if _, hasName := temp["name"]; hasName {
		var bucketMeta BucketMetadata
		if err := json.Unmarshal(data, &bucketMeta); err != nil {
			return nil, fmt.Errorf("BucketMetadata unmarshal error: %w", err)
		}
		return &bucketMeta, nil
	}
	
	if _, hasCID := temp["cid"]; hasCID {
		var pinStatus PinStatusInfo
		if err := json.Unmarshal(data, &pinStatus); err != nil {
			return nil, fmt.Errorf("PinStatusInfo unmarshal error: %w", err)
		}
		return &pinStatus, nil
	}
	
	// Default to generic interface{}
	return temp, nil
}

// compressData compresses data using gzip
func (c *redisCache) compressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return nil, err
	}
	
	if err := writer.Close(); err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// decompressData decompresses gzip data
func (c *redisCache) decompressData(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	
	return io.ReadAll(reader)
}

// metricsCollector collects Redis cache metrics
func (c *redisCache) metricsCollector() {
	defer c.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.updateMetrics()
		}
	}
}

// updateMetrics updates cache metrics
func (c *redisCache) updateMetrics() {
	c.client.mu.RLock()
	entryCount := len(c.client.data)
	c.client.mu.RUnlock()
	
	c.statsMu.Lock()
	c.stats.Size = int64(entryCount)
	c.stats.Healthy = c.client.healthy
	c.statsMu.Unlock()
}

// cleanupExpired removes expired entries from Redis cache
func (c *redisCache) cleanupExpired() {
	defer c.wg.Done()
	
	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
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
func (c *redisCache) performCleanup() {
	c.client.mu.Lock()
	defer c.client.mu.Unlock()
	
	now := time.Now()
	var expiredKeys []string
	
	// Find expired entries
	for key, entry := range c.client.data {
		if now.After(entry.expiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}
	
	// Remove expired entries
	for _, key := range expiredKeys {
		delete(c.client.data, key)
	}
	
	if len(expiredKeys) > 0 {
		c.logger.Printf("Cleaned up %d expired entries from Redis cache", len(expiredKeys))
	}
}

// Batch operations for improved performance

// BatchGet retrieves multiple values from Redis cache
func (c *redisCache) BatchGet(ctx context.Context, keys []string) (map[string]interface{}, error) {
	results := make(map[string]interface{})
	
	c.client.mu.RLock()
	defer c.client.mu.RUnlock()
	
	now := time.Now()
	for _, key := range keys {
		if entry, exists := c.client.data[key]; exists && now.Before(entry.expiresAt) {
			if value, err := c.deserializeValue(entry.value); err == nil {
				results[key] = value
			}
		}
	}
	
	return results, nil
}

// BatchSet stores multiple values in Redis cache
func (c *redisCache) BatchSet(ctx context.Context, items map[string]interface{}, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = c.config.DefaultTTL
	}
	
	c.client.mu.Lock()
	defer c.client.mu.Unlock()
	
	expiresAt := time.Now().Add(ttl)
	createdAt := time.Now()
	
	for key, value := range items {
		data, err := c.serializeValue(value)
		if err != nil {
			c.logger.Printf("Failed to serialize value for key %s: %v", key, err)
			continue
		}
		
		c.client.data[key] = &redisEntry{
			value:     data,
			expiresAt: expiresAt,
			createdAt: createdAt,
		}
	}
	
	return nil
}

// BatchDelete removes multiple values from Redis cache
func (c *redisCache) BatchDelete(ctx context.Context, keys []string) error {
	c.client.mu.Lock()
	defer c.client.mu.Unlock()
	
	for _, key := range keys {
		delete(c.client.data, key)
	}
	
	return nil
}

// GetKeysByPattern returns keys matching a pattern
func (c *redisCache) GetKeysByPattern(ctx context.Context, pattern string) ([]string, error) {
	c.client.mu.RLock()
	defer c.client.mu.RUnlock()
	
	var matchingKeys []string
	
	for key := range c.client.data {
		if c.matchPattern(key, pattern) {
			matchingKeys = append(matchingKeys, key)
		}
	}
	
	return matchingKeys, nil
}

// matchPattern performs simple pattern matching (supports * wildcard)
func (c *redisCache) matchPattern(key, pattern string) bool {
	if pattern == "*" {
		return true
	}
	
	if !strings.Contains(pattern, "*") {
		return key == pattern
	}
	
	// Simple wildcard matching
	parts := strings.Split(pattern, "*")
	if len(parts) == 2 {
		prefix := parts[0]
		suffix := parts[1]
		return strings.HasPrefix(key, prefix) && strings.HasSuffix(key, suffix)
	}
	
	// More complex patterns would need proper regex or glob matching
	return false
}