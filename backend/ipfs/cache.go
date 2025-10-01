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
	
	"github.com/versity/versitygw/s3response"
)

// CacheLayer represents the multi-level caching system
type CacheLayer interface {
	// Get retrieves a value from the cache
	Get(ctx context.Context, key string) (interface{}, error)
	
	// Set stores a value in the cache with TTL
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	
	// Delete removes a value from the cache
	Delete(ctx context.Context, key string) error
	
	// GetMapping retrieves an object mapping from cache
	GetMapping(ctx context.Context, s3Key, bucket string) (*ObjectMapping, error)
	
	// SetMapping stores an object mapping in cache
	SetMapping(ctx context.Context, s3Key, bucket string, mapping *ObjectMapping, ttl time.Duration) error
	
	// DeleteMapping removes an object mapping from cache
	DeleteMapping(ctx context.Context, s3Key, bucket string) error
	
	// GetMetadata retrieves object metadata from cache
	GetMetadata(ctx context.Context, cid string) (*ObjectMetadata, error)
	
	// SetMetadata stores object metadata in cache
	SetMetadata(ctx context.Context, cid string, metadata *ObjectMetadata, ttl time.Duration) error
	
	// DeleteMetadata removes object metadata from cache
	DeleteMetadata(ctx context.Context, cid string) error
	
	// Warm preloads popular objects into cache
	Warm(ctx context.Context, keys []string) error
	
	// GetStats returns cache statistics
	GetStats() *CacheStats
	
	// Clear clears all cache entries
	Clear(ctx context.Context) error
	
	// Shutdown gracefully shuts down the cache layer
	Shutdown(ctx context.Context) error
	
	// IsHealthy returns true if the cache layer is healthy
	IsHealthy() bool
	
	// GetBucketMetadata retrieves bucket metadata from cache
	GetBucketMetadata(ctx context.Context, bucket string) (*BucketMetadata, error)
	
	// SetBucketMetadata stores bucket metadata in cache
	SetBucketMetadata(ctx context.Context, bucket string, metadata *BucketMetadata) error
	
	// DeleteBucketMetadata removes bucket metadata from cache
	DeleteBucketMetadata(ctx context.Context, bucket string) error
	
	// GetPinStatus retrieves pin status from cache
	GetPinStatus(ctx context.Context, cid string) (*PinStatusInfo, error)
	
	// SetPinStatus stores pin status in cache
	SetPinStatus(ctx context.Context, cid string, status *PinStatusInfo) error
	
	// DeletePinStatus removes pin status from cache
	DeletePinStatus(ctx context.Context, cid string) error
	
	// GetListResult retrieves ListObjects result from cache
	GetListResult(ctx context.Context, cacheKey string) (*s3response.ListObjectsResult, error)
	
	// SetListResult stores ListObjects result in cache
	SetListResult(ctx context.Context, cacheKey string, result *s3response.ListObjectsResult, ttl time.Duration) error
	
	// GetListV2Result retrieves ListObjectsV2 result from cache
	GetListV2Result(ctx context.Context, cacheKey string) (*s3response.ListObjectsV2Result, error)
	
	// SetListV2Result stores ListObjectsV2 result in cache
	SetListV2Result(ctx context.Context, cacheKey string, result *s3response.ListObjectsV2Result, ttl time.Duration) error
}

// CacheStats represents cache statistics
type CacheStats struct {
	// L1 Cache (Memory) stats
	L1Hits        int64   `json:"l1_hits"`
	L1Misses      int64   `json:"l1_misses"`
	L1Size        int64   `json:"l1_size"`
	L1MaxSize     int64   `json:"l1_max_size"`
	L1Utilization float64 `json:"l1_utilization"`
	L1Evictions   int64   `json:"l1_evictions"`
	
	// L2 Cache (Redis) stats
	L2Hits        int64   `json:"l2_hits"`
	L2Misses      int64   `json:"l2_misses"`
	L2Size        int64   `json:"l2_size"`
	L2MaxSize     int64   `json:"l2_max_size"`
	L2Utilization float64 `json:"l2_utilization"`
	L2Evictions   int64   `json:"l2_evictions"`
	
	// Overall stats
	TotalHits     int64   `json:"total_hits"`
	TotalMisses   int64   `json:"total_misses"`
	HitRatio      float64 `json:"hit_ratio"`
	TotalOps      int64   `json:"total_ops"`
	
	// Performance stats
	AvgGetLatency time.Duration `json:"avg_get_latency"`
	AvgSetLatency time.Duration `json:"avg_set_latency"`
	
	// Warming stats
	WarmingActive bool  `json:"warming_active"`
	WarmingCount  int64 `json:"warming_count"`
	
	// Health
	Healthy bool `json:"healthy"`
}

// CacheConfig holds configuration for the cache layer
type CacheConfig struct {
	// L1 Memory Cache settings
	L1MaxSize        int64         `json:"l1_max_size"`         // Maximum memory cache size in bytes
	L1MaxEntries     int           `json:"l1_max_entries"`      // Maximum number of entries in memory cache
	L1DefaultTTL     time.Duration `json:"l1_default_ttl"`      // Default TTL for L1 cache entries
	L1CleanupInterval time.Duration `json:"l1_cleanup_interval"` // Cleanup interval for expired entries
	
	// L2 Redis Cache settings
	L2Endpoints      []string      `json:"l2_endpoints"`        // Redis cluster endpoints
	L2Password       string        `json:"l2_password"`         // Redis password
	L2DB             int           `json:"l2_db"`               // Redis database number
	L2MaxRetries     int           `json:"l2_max_retries"`      // Maximum retry attempts
	L2DialTimeout    time.Duration `json:"l2_dial_timeout"`     // Connection timeout
	L2ReadTimeout    time.Duration `json:"l2_read_timeout"`     // Read timeout
	L2WriteTimeout   time.Duration `json:"l2_write_timeout"`    // Write timeout
	L2PoolSize       int           `json:"l2_pool_size"`        // Connection pool size
	L2DefaultTTL     time.Duration `json:"l2_default_ttl"`      // Default TTL for L2 cache entries
	
	// TTL Policies for different data types
	MappingTTL       time.Duration `json:"mapping_ttl"`         // TTL for object mappings
	MetadataTTL      time.Duration `json:"metadata_ttl"`        // TTL for object metadata
	BucketTTL        time.Duration `json:"bucket_ttl"`          // TTL for bucket metadata
	PinStatusTTL     time.Duration `json:"pin_status_ttl"`      // TTL for pin status
	
	// Cache warming settings
	WarmingEnabled   bool          `json:"warming_enabled"`     // Enable cache warming
	WarmingBatchSize int           `json:"warming_batch_size"`  // Batch size for warming operations
	WarmingInterval  time.Duration `json:"warming_interval"`    // Interval between warming cycles
	WarmingThreshold float64       `json:"warming_threshold"`   // Access frequency threshold for warming
	
	// Performance settings
	AsyncWrites      bool          `json:"async_writes"`        // Enable asynchronous writes to L2
	CompressionEnabled bool        `json:"compression_enabled"` // Enable compression for cached data
	
	// Monitoring
	MetricsEnabled   bool          `json:"metrics_enabled"`     // Enable metrics collection
	MetricsInterval  time.Duration `json:"metrics_interval"`    // Metrics collection interval
	
	// Health checking
	HealthCheckEnabled  bool          `json:"health_check_enabled"`  // Enable health checking
	HealthCheckInterval time.Duration `json:"health_check_interval"` // Health check interval
}

// CacheEntry represents a cache entry with metadata
type CacheEntry struct {
	Key        string      `json:"key"`
	Value      interface{} `json:"value"`
	Size       int64       `json:"size"`
	CreatedAt  time.Time   `json:"created_at"`
	AccessedAt time.Time   `json:"accessed_at"`
	TTL        time.Duration `json:"ttl"`
	AccessCount int64      `json:"access_count"`
	Compressed bool        `json:"compressed"`
}

// ObjectMetadata represents metadata for IPFS objects
type ObjectMetadata struct {
	ContentType     string            `json:"content_type"`
	ContentEncoding string            `json:"content_encoding"`
	ContentLanguage string            `json:"content_language"`
	CacheControl    string            `json:"cache_control"`
	UserMetadata    map[string]string `json:"user_metadata"`
	Tags            map[string]string `json:"tags"`
	ETag            string            `json:"etag"`
	Size            int64             `json:"size"`
	LastModified    time.Time         `json:"last_modified"`
}

// CacheKeyType represents the type of cache key
type CacheKeyType int

const (
	CacheKeyMapping CacheKeyType = iota
	CacheKeyMetadata
	CacheKeyBucket
	CacheKeyPinStatus
	CacheKeyListObjects
	CacheKeyListObjectsV2
	CacheKeyGeneric
)

// CacheKey represents a structured cache key
type CacheKey struct {
	Type   CacheKeyType `json:"type"`
	Bucket string       `json:"bucket,omitempty"`
	S3Key  string       `json:"s3_key,omitempty"`
	CID    string       `json:"cid,omitempty"`
	Key    string       `json:"key,omitempty"`
	Custom string       `json:"custom,omitempty"`
}

// String returns the string representation of the cache key
func (ck *CacheKey) String() string {
	switch ck.Type {
	case CacheKeyMapping:
		return fmt.Sprintf("mapping:%s:%s", ck.Bucket, ck.S3Key)
	case CacheKeyMetadata:
		return fmt.Sprintf("metadata:%s", ck.CID)
	case CacheKeyBucket:
		return fmt.Sprintf("bucket:%s", ck.Bucket)
	case CacheKeyPinStatus:
		return fmt.Sprintf("pin_status:%s", ck.CID)
	case CacheKeyListObjects:
		return fmt.Sprintf("list_objects:%s", ck.Key)
	case CacheKeyListObjectsV2:
		return fmt.Sprintf("list_objects_v2:%s", ck.Key)
	case CacheKeyGeneric:
		return fmt.Sprintf("generic:%s", ck.Custom)
	default:
		return fmt.Sprintf("unknown:%s", ck.Custom)
	}
}

// MultiLevelCache implements the CacheLayer interface with L1 memory and L2 Redis caching
type MultiLevelCache struct {
	config *CacheConfig
	logger *log.Logger
	
	// Cache levels
	l1Cache MemoryCache
	l2Cache RedisCache
	
	// Statistics
	stats     *CacheStats
	statsMu   sync.RWMutex
	
	// Cache warming
	warmer    *CacheWarmer
	
	// Lifecycle management
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	
	// Health monitoring
	healthy   bool
	healthMu  sync.RWMutex
}

// NewCacheLayer creates a new multi-level cache layer
func NewCacheLayer(config *CacheConfig, logger *log.Logger) (CacheLayer, error) {
	if config == nil {
		return nil, fmt.Errorf("cache config cannot be nil")
	}
	
	if logger == nil {
		logger = log.Default()
	}
	
	// Validate and set defaults
	if err := validateCacheConfig(config); err != nil {
		return nil, fmt.Errorf("invalid cache config: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	cache := &MultiLevelCache{
		config: config,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
		stats: &CacheStats{
			L1MaxSize: config.L1MaxSize,
			Healthy:   true,
		},
		healthy: true,
	}
	
	// Initialize L1 memory cache
	l1Config := &MemoryCacheConfig{
		MaxSize:         config.L1MaxSize,
		MaxEntries:      config.L1MaxEntries,
		DefaultTTL:      config.L1DefaultTTL,
		CleanupInterval: config.L1CleanupInterval,
		MetricsEnabled:  config.MetricsEnabled,
	}
	
	var err error
	cache.l1Cache, err = NewMemoryCache(l1Config, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize L1 memory cache: %w", err)
	}
	
	// Initialize L2 Redis cache
	l2Config := &RedisCacheConfig{
		Endpoints:     config.L2Endpoints,
		Password:      config.L2Password,
		DB:            config.L2DB,
		MaxRetries:    config.L2MaxRetries,
		DialTimeout:   config.L2DialTimeout,
		ReadTimeout:   config.L2ReadTimeout,
		WriteTimeout:  config.L2WriteTimeout,
		PoolSize:      config.L2PoolSize,
		DefaultTTL:    config.L2DefaultTTL,
		AsyncWrites:   config.AsyncWrites,
		Compression:   config.CompressionEnabled,
		MetricsEnabled: config.MetricsEnabled,
	}
	
	cache.l2Cache, err = NewRedisCache(l2Config, logger)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize L2 Redis cache: %w", err)
	}
	
	// Initialize cache warmer if enabled
	if config.WarmingEnabled {
		warmerConfig := &CacheWarmerConfig{
			BatchSize:   config.WarmingBatchSize,
			Interval:    config.WarmingInterval,
			Threshold:   config.WarmingThreshold,
			Enabled:     true,
		}
		
		cache.warmer, err = NewCacheWarmer(warmerConfig, cache, logger)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to initialize cache warmer: %w", err)
		}
	}
	
	// Start background tasks
	cache.startBackgroundTasks()
	
	logger.Printf("Multi-level cache initialized successfully")
	return cache, nil
}

// validateCacheConfig validates and sets defaults for cache configuration
func validateCacheConfig(config *CacheConfig) error {
	// L1 Memory Cache defaults
	if config.L1MaxSize <= 0 {
		config.L1MaxSize = 1024 * 1024 * 1024 // 1GB default
	}
	
	if config.L1MaxEntries <= 0 {
		config.L1MaxEntries = 100000 // 100K entries default
	}
	
	if config.L1DefaultTTL <= 0 {
		config.L1DefaultTTL = 5 * time.Minute // 5 minutes default
	}
	
	if config.L1CleanupInterval <= 0 {
		config.L1CleanupInterval = 1 * time.Minute // 1 minute default
	}
	
	// L2 Redis Cache defaults
	if len(config.L2Endpoints) == 0 {
		config.L2Endpoints = []string{"localhost:6379"} // Default Redis endpoint
	}
	
	if config.L2MaxRetries <= 0 {
		config.L2MaxRetries = 3
	}
	
	if config.L2DialTimeout <= 0 {
		config.L2DialTimeout = 5 * time.Second
	}
	
	if config.L2ReadTimeout <= 0 {
		config.L2ReadTimeout = 3 * time.Second
	}
	
	if config.L2WriteTimeout <= 0 {
		config.L2WriteTimeout = 3 * time.Second
	}
	
	if config.L2PoolSize <= 0 {
		config.L2PoolSize = 10
	}
	
	if config.L2DefaultTTL <= 0 {
		config.L2DefaultTTL = 1 * time.Hour // 1 hour default
	}
	
	// TTL Policies defaults
	if config.MappingTTL <= 0 {
		config.MappingTTL = 30 * time.Minute
	}
	
	if config.MetadataTTL <= 0 {
		config.MetadataTTL = 15 * time.Minute
	}
	
	if config.BucketTTL <= 0 {
		config.BucketTTL = 1 * time.Hour
	}
	
	if config.PinStatusTTL <= 0 {
		config.PinStatusTTL = 5 * time.Minute
	}
	
	// Cache warming defaults
	if config.WarmingBatchSize <= 0 {
		config.WarmingBatchSize = 100
	}
	
	if config.WarmingInterval <= 0 {
		config.WarmingInterval = 10 * time.Minute
	}
	
	if config.WarmingThreshold <= 0 {
		config.WarmingThreshold = 0.1 // 10% access frequency
	}
	
	// Monitoring defaults
	if config.MetricsInterval <= 0 {
		config.MetricsInterval = 30 * time.Second
	}
	
	if config.HealthCheckInterval <= 0 {
		config.HealthCheckInterval = 1 * time.Minute
	}
	
	return nil
}

// startBackgroundTasks starts background maintenance tasks
func (c *MultiLevelCache) startBackgroundTasks() {
	// Start metrics collection
	if c.config.MetricsEnabled {
		c.wg.Add(1)
		go c.metricsCollector()
	}
	
	// Start health checking
	if c.config.HealthCheckEnabled {
		c.wg.Add(1)
		go c.healthChecker()
	}
	
	// Start cache warmer
	if c.warmer != nil {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.warmer.Start(c.ctx)
		}()
	}
}

// metricsCollector collects and updates cache metrics
func (c *MultiLevelCache) metricsCollector() {
	defer c.wg.Done()
	
	ticker := time.NewTicker(c.config.MetricsInterval)
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

// healthChecker monitors cache health
func (c *MultiLevelCache) healthChecker() {
	defer c.wg.Done()
	
	ticker := time.NewTicker(c.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.checkHealth()
		}
	}
}

// updateMetrics updates cache statistics
func (c *MultiLevelCache) updateMetrics() {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	
	// Get L1 stats
	l1Stats := c.l1Cache.GetStats()
	c.stats.L1Hits = l1Stats.Hits
	c.stats.L1Misses = l1Stats.Misses
	c.stats.L1Size = l1Stats.Size
	c.stats.L1Utilization = l1Stats.Utilization
	c.stats.L1Evictions = l1Stats.Evictions
	
	// Get L2 stats
	l2Stats := c.l2Cache.GetStats()
	c.stats.L2Hits = l2Stats.Hits
	c.stats.L2Misses = l2Stats.Misses
	c.stats.L2Size = l2Stats.Size
	c.stats.L2MaxSize = l2Stats.MaxSize
	c.stats.L2Utilization = l2Stats.Utilization
	c.stats.L2Evictions = l2Stats.Evictions
	
	// Calculate overall stats
	c.stats.TotalHits = c.stats.L1Hits + c.stats.L2Hits
	c.stats.TotalMisses = c.stats.L1Misses + c.stats.L2Misses
	c.stats.TotalOps = c.stats.TotalHits + c.stats.TotalMisses
	
	if c.stats.TotalOps > 0 {
		c.stats.HitRatio = float64(c.stats.TotalHits) / float64(c.stats.TotalOps)
	}
	
	// Update performance stats
	c.stats.AvgGetLatency = (l1Stats.AvgGetLatency + l2Stats.AvgGetLatency) / 2
	c.stats.AvgSetLatency = (l1Stats.AvgSetLatency + l2Stats.AvgSetLatency) / 2
	
	// Update warming stats
	if c.warmer != nil {
		warmerStats := c.warmer.GetStats()
		c.stats.WarmingActive = warmerStats.Active
		c.stats.WarmingCount = warmerStats.TotalWarmed
	}
}

// checkHealth checks the health of cache components
func (c *MultiLevelCache) checkHealth() {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	
	healthy := true
	
	// Check L1 cache health
	if !c.l1Cache.IsHealthy() {
		healthy = false
		c.logger.Printf("L1 cache is unhealthy")
	}
	
	// Check L2 cache health
	if !c.l2Cache.IsHealthy() {
		healthy = false
		c.logger.Printf("L2 cache is unhealthy")
	}
	
	c.healthy = healthy
	c.stats.Healthy = healthy
}

// Get retrieves a value from the cache (L1 first, then L2)
func (c *MultiLevelCache) Get(ctx context.Context, key string) (interface{}, error) {
	start := time.Now()
	defer func() {
		c.statsMu.Lock()
		c.stats.AvgGetLatency = (c.stats.AvgGetLatency + time.Since(start)) / 2
		c.statsMu.Unlock()
	}()
	
	// Try L1 cache first
	if value, err := c.l1Cache.Get(ctx, key); err == nil {
		return value, nil
	}
	
	// Try L2 cache
	value, err := c.l2Cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	
	// Promote to L1 cache asynchronously
	go func() {
		promoteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := c.l1Cache.Set(promoteCtx, key, value, c.config.L1DefaultTTL); err != nil {
			c.logger.Printf("Failed to promote key %s to L1 cache: %v", key, err)
		}
	}()
	
	return value, nil
}

// Set stores a value in both cache levels
func (c *MultiLevelCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	start := time.Now()
	defer func() {
		c.statsMu.Lock()
		c.stats.AvgSetLatency = (c.stats.AvgSetLatency + time.Since(start)) / 2
		c.statsMu.Unlock()
	}()
	
	// Set in L1 cache
	l1TTL := ttl
	if l1TTL > c.config.L1DefaultTTL {
		l1TTL = c.config.L1DefaultTTL
	}
	
	if err := c.l1Cache.Set(ctx, key, value, l1TTL); err != nil {
		c.logger.Printf("Failed to set key %s in L1 cache: %v", key, err)
	}
	
	// Set in L2 cache
	l2TTL := ttl
	if l2TTL > c.config.L2DefaultTTL {
		l2TTL = c.config.L2DefaultTTL
	}
	
	if c.config.AsyncWrites {
		// Asynchronous write to L2
		go func() {
			asyncCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			
			if err := c.l2Cache.Set(asyncCtx, key, value, l2TTL); err != nil {
				c.logger.Printf("Failed to set key %s in L2 cache: %v", key, err)
			}
		}()
		return nil
	} else {
		// Synchronous write to L2
		return c.l2Cache.Set(ctx, key, value, l2TTL)
	}
}

// Delete removes a value from both cache levels
func (c *MultiLevelCache) Delete(ctx context.Context, key string) error {
	var errs []error
	
	// Delete from L1 cache
	if err := c.l1Cache.Delete(ctx, key); err != nil {
		errs = append(errs, fmt.Errorf("L1 delete error: %w", err))
	}
	
	// Delete from L2 cache
	if err := c.l2Cache.Delete(ctx, key); err != nil {
		errs = append(errs, fmt.Errorf("L2 delete error: %w", err))
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("cache delete errors: %v", errs)
	}
	
	return nil
}

// GetMapping retrieves an object mapping from cache
func (c *MultiLevelCache) GetMapping(ctx context.Context, s3Key, bucket string) (*ObjectMapping, error) {
	key := &CacheKey{
		Type:   CacheKeyMapping,
		Bucket: bucket,
		S3Key:  s3Key,
	}
	
	value, err := c.Get(ctx, key.String())
	if err != nil {
		return nil, err
	}
	
	mapping, ok := value.(*ObjectMapping)
	if !ok {
		return nil, fmt.Errorf("cached value is not an ObjectMapping")
	}
	
	return mapping, nil
}

// SetMapping stores an object mapping in cache
func (c *MultiLevelCache) SetMapping(ctx context.Context, s3Key, bucket string, mapping *ObjectMapping, ttl time.Duration) error {
	key := &CacheKey{
		Type:   CacheKeyMapping,
		Bucket: bucket,
		S3Key:  s3Key,
	}
	
	if ttl <= 0 {
		ttl = c.config.MappingTTL
	}
	
	return c.Set(ctx, key.String(), mapping, ttl)
}

// DeleteMapping removes an object mapping from cache
func (c *MultiLevelCache) DeleteMapping(ctx context.Context, s3Key, bucket string) error {
	key := &CacheKey{
		Type:   CacheKeyMapping,
		Bucket: bucket,
		S3Key:  s3Key,
	}
	
	return c.Delete(ctx, key.String())
}

// GetMetadata retrieves object metadata from cache
func (c *MultiLevelCache) GetMetadata(ctx context.Context, cid string) (*ObjectMetadata, error) {
	key := &CacheKey{
		Type: CacheKeyMetadata,
		CID:  cid,
	}
	
	value, err := c.Get(ctx, key.String())
	if err != nil {
		return nil, err
	}
	
	metadata, ok := value.(*ObjectMetadata)
	if !ok {
		return nil, fmt.Errorf("cached value is not ObjectMetadata")
	}
	
	return metadata, nil
}

// SetMetadata stores object metadata in cache
func (c *MultiLevelCache) SetMetadata(ctx context.Context, cid string, metadata *ObjectMetadata, ttl time.Duration) error {
	key := &CacheKey{
		Type: CacheKeyMetadata,
		CID:  cid,
	}
	
	if ttl <= 0 {
		ttl = c.config.MetadataTTL
	}
	
	return c.Set(ctx, key.String(), metadata, ttl)
}

// DeleteMetadata removes object metadata from cache
func (c *MultiLevelCache) DeleteMetadata(ctx context.Context, cid string) error {
	key := &CacheKey{
		Type: CacheKeyMetadata,
		CID:  cid,
	}
	
	return c.Delete(ctx, key.String())
}

// Warm preloads popular objects into cache
func (c *MultiLevelCache) Warm(ctx context.Context, keys []string) error {
	if c.warmer == nil {
		return fmt.Errorf("cache warming is not enabled")
	}
	
	return c.warmer.WarmKeys(ctx, keys)
}

// GetStats returns cache statistics
func (c *MultiLevelCache) GetStats() *CacheStats {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()
	
	// Create a copy to avoid race conditions
	stats := *c.stats
	return &stats
}

// Clear clears all cache entries
func (c *MultiLevelCache) Clear(ctx context.Context) error {
	var errs []error
	
	// Clear L1 cache
	if err := c.l1Cache.Clear(ctx); err != nil {
		errs = append(errs, fmt.Errorf("L1 clear error: %w", err))
	}
	
	// Clear L2 cache
	if err := c.l2Cache.Clear(ctx); err != nil {
		errs = append(errs, fmt.Errorf("L2 clear error: %w", err))
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("cache clear errors: %v", errs)
	}
	
	return nil
}

// Shutdown gracefully shuts down the cache layer
func (c *MultiLevelCache) Shutdown(ctx context.Context) error {
	c.logger.Println("Shutting down multi-level cache...")
	
	// Cancel context to stop background tasks
	c.cancel()
	
	// Wait for background tasks to finish
	c.wg.Wait()
	
	var errs []error
	
	// Shutdown cache warmer
	if c.warmer != nil {
		if err := c.warmer.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("warmer shutdown error: %w", err))
		}
	}
	
	// Shutdown L1 cache
	if err := c.l1Cache.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("L1 shutdown error: %w", err))
	}
	
	// Shutdown L2 cache
	if err := c.l2Cache.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("L2 shutdown error: %w", err))
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("cache shutdown errors: %v", errs)
	}
	
	c.logger.Println("Multi-level cache shutdown completed")
	return nil
}

// IsHealthy returns true if the cache layer is healthy
func (c *MultiLevelCache) IsHealthy() bool {
	c.healthMu.RLock()
	defer c.healthMu.RUnlock()
	return c.healthy
}

// Helper methods for specific cache operations

// GetBucketMetadata retrieves bucket metadata from cache
func (c *MultiLevelCache) GetBucketMetadata(ctx context.Context, bucket string) (*BucketMetadata, error) {
	key := &CacheKey{
		Type:   CacheKeyBucket,
		Bucket: bucket,
	}
	
	value, err := c.Get(ctx, key.String())
	if err != nil {
		return nil, err
	}
	
	metadata, ok := value.(*BucketMetadata)
	if !ok {
		return nil, fmt.Errorf("cached value is not BucketMetadata")
	}
	
	return metadata, nil
}

// SetBucketMetadata stores bucket metadata in cache
func (c *MultiLevelCache) SetBucketMetadata(ctx context.Context, bucket string, metadata *BucketMetadata) error {
	key := &CacheKey{
		Type:   CacheKeyBucket,
		Bucket: bucket,
	}
	
	return c.Set(ctx, key.String(), metadata, c.config.BucketTTL)
}

// DeleteBucketMetadata removes bucket metadata from cache
func (c *MultiLevelCache) DeleteBucketMetadata(ctx context.Context, bucket string) error {
	key := &CacheKey{
		Type:   CacheKeyBucket,
		Bucket: bucket,
	}
	
	return c.Delete(ctx, key.String())
}

// GetPinStatus retrieves pin status from cache
func (c *MultiLevelCache) GetPinStatus(ctx context.Context, cid string) (*PinStatusInfo, error) {
	key := &CacheKey{
		Type: CacheKeyPinStatus,
		CID:  cid,
	}
	
	value, err := c.Get(ctx, key.String())
	if err != nil {
		return nil, err
	}
	
	status, ok := value.(*PinStatusInfo)
	if !ok {
		return nil, fmt.Errorf("cached value is not PinStatusInfo")
	}
	
	return status, nil
}

// SetPinStatus stores pin status in cache
func (c *MultiLevelCache) SetPinStatus(ctx context.Context, cid string, status *PinStatusInfo) error {
	key := &CacheKey{
		Type: CacheKeyPinStatus,
		CID:  cid,
	}
	
	return c.Set(ctx, key.String(), status, c.config.PinStatusTTL)
}

// DeletePinStatus removes pin status from cache
func (c *MultiLevelCache) DeletePinStatus(ctx context.Context, cid string) error {
	key := &CacheKey{
		Type: CacheKeyPinStatus,
		CID:  cid,
	}
	
	return c.Delete(ctx, key.String())
}

// Batch operations for improved performance

// BatchGet retrieves multiple values from cache
func (c *MultiLevelCache) BatchGet(ctx context.Context, keys []string) (map[string]interface{}, error) {
	results := make(map[string]interface{})
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Process keys in batches to avoid overwhelming the cache
	batchSize := 100
	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}
		
		batch := keys[i:end]
		wg.Add(1)
		
		go func(batchKeys []string) {
			defer wg.Done()
			
			for _, key := range batchKeys {
				if value, err := c.Get(ctx, key); err == nil {
					mu.Lock()
					results[key] = value
					mu.Unlock()
				}
			}
		}(batch)
	}
	
	wg.Wait()
	return results, nil
}

// BatchSet stores multiple values in cache
func (c *MultiLevelCache) BatchSet(ctx context.Context, items map[string]interface{}, ttl time.Duration) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	
	// Process items in batches
	batchSize := 100
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	
	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}
		
		batch := keys[i:end]
		wg.Add(1)
		
		go func(batchKeys []string) {
			defer wg.Done()
			
			for _, key := range batchKeys {
				if err := c.Set(ctx, key, items[key], ttl); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("failed to set key %s: %w", key, err))
					mu.Unlock()
				}
			}
		}(batch)
	}
	
	wg.Wait()
	
	if len(errs) > 0 {
		return fmt.Errorf("batch set errors: %v", errs)
	}
	
	return nil
}

// BatchDelete removes multiple values from cache
func (c *MultiLevelCache) BatchDelete(ctx context.Context, keys []string) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	
	// Process keys in batches
	batchSize := 100
	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}
		
		batch := keys[i:end]
		wg.Add(1)
		
		go func(batchKeys []string) {
			defer wg.Done()
			
			for _, key := range batchKeys {
				if err := c.Delete(ctx, key); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("failed to delete key %s: %w", key, err))
					mu.Unlock()
				}
			}
		}(batch)
	}
	
	wg.Wait()
	
	if len(errs) > 0 {
		return fmt.Errorf("batch delete errors: %v", errs)
	}
	
	return nil
}

// GetListResult retrieves ListObjects result from cache
func (c *MultiLevelCache) GetListResult(ctx context.Context, cacheKey string) (*s3response.ListObjectsResult, error) {
	key := &CacheKey{
		Type: CacheKeyListObjects,
		Key:  cacheKey,
	}
	
	keyStr := key.String()
	value, err := c.Get(ctx, keyStr)
	if err != nil {
		return nil, err
	}
	
	result, ok := value.(*s3response.ListObjectsResult)
	if !ok {
		return nil, fmt.Errorf("cached value is not a ListObjectsResult")
	}
	
	return result, nil
}

// SetListResult stores ListObjects result in cache
func (c *MultiLevelCache) SetListResult(ctx context.Context, cacheKey string, result *s3response.ListObjectsResult, ttl time.Duration) error {
	key := &CacheKey{
		Type: CacheKeyListObjects,
		Key:  cacheKey,
	}
	
	keyStr := key.String()
	return c.Set(ctx, keyStr, result, ttl)
}

// GetListV2Result retrieves ListObjectsV2 result from cache
func (c *MultiLevelCache) GetListV2Result(ctx context.Context, cacheKey string) (*s3response.ListObjectsV2Result, error) {
	key := &CacheKey{
		Type: CacheKeyListObjectsV2,
		Key:  cacheKey,
	}
	
	keyStr := key.String()
	value, err := c.Get(ctx, keyStr)
	if err != nil {
		return nil, err
	}
	
	result, ok := value.(*s3response.ListObjectsV2Result)
	if !ok {
		return nil, fmt.Errorf("cached value is not a ListObjectsV2Result")
	}
	
	return result, nil
}

// SetListV2Result stores ListObjectsV2 result in cache
func (c *MultiLevelCache) SetListV2Result(ctx context.Context, cacheKey string, result *s3response.ListObjectsV2Result, ttl time.Duration) error {
	key := &CacheKey{
		Type: CacheKeyListObjectsV2,
		Key:  cacheKey,
	}
	
	keyStr := key.String()
	return c.Set(ctx, keyStr, result, ttl)
}