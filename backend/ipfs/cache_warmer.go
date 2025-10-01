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
	"sort"
	"sync"
	"time"
)

// CacheWarmer handles preloading popular objects into cache
type CacheWarmer struct {
	config *CacheWarmerConfig
	cache  CacheLayer
	logger *log.Logger
	
	// Access tracking
	accessTracker *AccessTracker
	
	// Statistics
	stats   *CacheWarmerStats
	statsMu sync.RWMutex
	
	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Control
	running bool
	runMu   sync.RWMutex
}

// CacheWarmerConfig holds configuration for cache warming
type CacheWarmerConfig struct {
	BatchSize   int           `json:"batch_size"`   // Number of keys to warm in each batch
	Interval    time.Duration `json:"interval"`     // Interval between warming cycles
	Threshold   float64       `json:"threshold"`    // Access frequency threshold for warming
	Enabled     bool          `json:"enabled"`      // Enable cache warming
	MaxKeys     int           `json:"max_keys"`     // Maximum number of keys to track
	WindowSize  time.Duration `json:"window_size"`  // Time window for access frequency calculation
}

// CacheWarmerStats represents cache warmer statistics
type CacheWarmerStats struct {
	Active         bool  `json:"active"`
	TotalWarmed    int64 `json:"total_warmed"`
	TotalCycles    int64 `json:"total_cycles"`
	LastWarmTime   time.Time `json:"last_warm_time"`
	AvgWarmTime    time.Duration `json:"avg_warm_time"`
	TrackedKeys    int   `json:"tracked_keys"`
	WarmingErrors  int64 `json:"warming_errors"`
}

// AccessTracker tracks access patterns for cache warming
type AccessTracker struct {
	accesses map[string]*AccessInfo
	mu       sync.RWMutex
	maxKeys  int
	window   time.Duration
}

// AccessInfo holds access information for a key
type AccessInfo struct {
	Key         string    `json:"key"`
	AccessCount int64     `json:"access_count"`
	LastAccess  time.Time `json:"last_access"`
	FirstAccess time.Time `json:"first_access"`
	Frequency   float64   `json:"frequency"` // Accesses per hour
}

// WarmingCandidate represents a key candidate for warming
type WarmingCandidate struct {
	Key       string  `json:"key"`
	Frequency float64 `json:"frequency"`
	Priority  int     `json:"priority"`
}

// NewCacheWarmer creates a new cache warmer
func NewCacheWarmer(config *CacheWarmerConfig, cache CacheLayer, logger *log.Logger) (*CacheWarmer, error) {
	if config == nil {
		return nil, fmt.Errorf("cache warmer config cannot be nil")
	}
	
	if cache == nil {
		return nil, fmt.Errorf("cache layer cannot be nil")
	}
	
	if logger == nil {
		logger = log.Default()
	}
	
	// Set defaults
	if config.BatchSize <= 0 {
		config.BatchSize = 100
	}
	if config.Interval <= 0 {
		config.Interval = 10 * time.Minute
	}
	if config.Threshold <= 0 {
		config.Threshold = 0.1 // 10% access frequency
	}
	if config.MaxKeys <= 0 {
		config.MaxKeys = 10000
	}
	if config.WindowSize <= 0 {
		config.WindowSize = 1 * time.Hour
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	warmer := &CacheWarmer{
		config: config,
		cache:  cache,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
		accessTracker: &AccessTracker{
			accesses: make(map[string]*AccessInfo),
			maxKeys:  config.MaxKeys,
			window:   config.WindowSize,
		},
		stats: &CacheWarmerStats{},
	}
	
	logger.Printf("Cache warmer initialized with batch size: %d, interval: %v", 
		config.BatchSize, config.Interval)
	
	return warmer, nil
}

// Start starts the cache warming process
func (w *CacheWarmer) Start(ctx context.Context) {
	if !w.config.Enabled {
		w.logger.Println("Cache warming is disabled")
		return
	}
	
	w.runMu.Lock()
	w.running = true
	w.runMu.Unlock()
	
	w.logger.Println("Starting cache warmer...")
	
	ticker := time.NewTicker(w.config.Interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			w.logger.Println("Cache warmer stopped")
			return
		case <-w.ctx.Done():
			w.logger.Println("Cache warmer stopped")
			return
		case <-ticker.C:
			w.performWarmingCycle(ctx)
		}
	}
}

// Stop stops the cache warming process
func (w *CacheWarmer) Stop(ctx context.Context) error {
	w.logger.Println("Stopping cache warmer...")
	
	w.runMu.Lock()
	w.running = false
	w.runMu.Unlock()
	
	// Cancel context
	w.cancel()
	
	// Wait for warming cycle to complete
	w.wg.Wait()
	
	w.logger.Println("Cache warmer stopped")
	return nil
}

// TrackAccess records an access to a key for warming analysis
func (w *CacheWarmer) TrackAccess(key string) {
	if !w.config.Enabled {
		return
	}
	
	w.accessTracker.mu.Lock()
	defer w.accessTracker.mu.Unlock()
	
	now := time.Now()
	
	if info, exists := w.accessTracker.accesses[key]; exists {
		info.AccessCount++
		info.LastAccess = now
		
		// Calculate frequency (accesses per hour)
		duration := now.Sub(info.FirstAccess)
		if duration > 0 {
			info.Frequency = float64(info.AccessCount) / duration.Hours()
		}
	} else {
		// Check if we need to evict old entries
		if len(w.accessTracker.accesses) >= w.accessTracker.maxKeys {
			w.evictOldAccessesUnsafe()
		}
		
		w.accessTracker.accesses[key] = &AccessInfo{
			Key:         key,
			AccessCount: 1,
			LastAccess:  now,
			FirstAccess: now,
			Frequency:   0, // Will be calculated after more accesses
		}
	}
}

// WarmKeys manually warms specific keys
func (w *CacheWarmer) WarmKeys(ctx context.Context, keys []string) error {
	if !w.config.Enabled {
		return fmt.Errorf("cache warming is disabled")
	}
	
	w.logger.Printf("Manually warming %d keys", len(keys))
	
	// Process keys in batches
	for i := 0; i < len(keys); i += w.config.BatchSize {
		end := i + w.config.BatchSize
		if end > len(keys) {
			end = len(keys)
		}
		
		batch := keys[i:end]
		if err := w.warmBatch(ctx, batch); err != nil {
			w.logger.Printf("Error warming batch: %v", err)
			w.statsMu.Lock()
			w.stats.WarmingErrors++
			w.statsMu.Unlock()
		}
		
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	
	return nil
}

// GetStats returns cache warmer statistics
func (w *CacheWarmer) GetStats() *CacheWarmerStats {
	w.statsMu.RLock()
	defer w.statsMu.RUnlock()
	
	w.runMu.RLock()
	running := w.running
	w.runMu.RUnlock()
	
	w.accessTracker.mu.RLock()
	trackedKeys := len(w.accessTracker.accesses)
	w.accessTracker.mu.RUnlock()
	
	stats := *w.stats
	stats.Active = running
	stats.TrackedKeys = trackedKeys
	
	return &stats
}

// GetTopAccessedKeys returns the most frequently accessed keys
func (w *CacheWarmer) GetTopAccessedKeys(limit int) []*AccessInfo {
	w.accessTracker.mu.RLock()
	defer w.accessTracker.mu.RUnlock()
	
	var accesses []*AccessInfo
	for _, info := range w.accessTracker.accesses {
		accesses = append(accesses, info)
	}
	
	// Sort by frequency (descending)
	sort.Slice(accesses, func(i, j int) bool {
		return accesses[i].Frequency > accesses[j].Frequency
	})
	
	if limit > 0 && limit < len(accesses) {
		accesses = accesses[:limit]
	}
	
	return accesses
}

// Private methods

// performWarmingCycle performs a single warming cycle
func (w *CacheWarmer) performWarmingCycle(ctx context.Context) {
	start := time.Now()
	
	w.logger.Println("Starting cache warming cycle...")
	
	// Get warming candidates
	candidates := w.getWarmingCandidates()
	if len(candidates) == 0 {
		w.logger.Println("No warming candidates found")
		return
	}
	
	w.logger.Printf("Found %d warming candidates", len(candidates))
	
	// Warm candidates in batches
	warmed := 0
	for i := 0; i < len(candidates); i += w.config.BatchSize {
		end := i + w.config.BatchSize
		if end > len(candidates) {
			end = len(candidates)
		}
		
		batch := make([]string, 0, end-i)
		for j := i; j < end; j++ {
			batch = append(batch, candidates[j].Key)
		}
		
		if err := w.warmBatch(ctx, batch); err != nil {
			w.logger.Printf("Error warming batch: %v", err)
			w.statsMu.Lock()
			w.stats.WarmingErrors++
			w.statsMu.Unlock()
		} else {
			warmed += len(batch)
		}
		
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
	
	// Update statistics
	duration := time.Since(start)
	w.statsMu.Lock()
	w.stats.TotalWarmed += int64(warmed)
	w.stats.TotalCycles++
	w.stats.LastWarmTime = time.Now()
	w.stats.AvgWarmTime = (w.stats.AvgWarmTime + duration) / 2
	w.statsMu.Unlock()
	
	w.logger.Printf("Cache warming cycle completed: warmed %d keys in %v", warmed, duration)
}

// getWarmingCandidates identifies keys that should be warmed
func (w *CacheWarmer) getWarmingCandidates() []*WarmingCandidate {
	w.accessTracker.mu.RLock()
	defer w.accessTracker.mu.RUnlock()
	
	var candidates []*WarmingCandidate
	now := time.Now()
	
	for key, info := range w.accessTracker.accesses {
		// Skip keys that haven't been accessed recently
		if now.Sub(info.LastAccess) > w.accessTracker.window {
			continue
		}
		
		// Skip keys with low frequency
		if info.Frequency < w.config.Threshold {
			continue
		}
		
		// Calculate priority based on frequency and recency
		recencyScore := 1.0 - (now.Sub(info.LastAccess).Hours() / w.accessTracker.window.Hours())
		priority := int(info.Frequency * 100 * recencyScore)
		
		candidates = append(candidates, &WarmingCandidate{
			Key:       key,
			Frequency: info.Frequency,
			Priority:  priority,
		})
	}
	
	// Sort by priority (descending)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Priority > candidates[j].Priority
	})
	
	return candidates
}

// warmBatch warms a batch of keys by loading them into cache
func (w *CacheWarmer) warmBatch(ctx context.Context, keys []string) error {
	// This is a simplified warming implementation
	// In a real system, you would load the data from the metadata store
	// and populate the cache
	
	for _, key := range keys {
		// Check if key is already in cache
		if _, err := w.cache.Get(ctx, key); err == nil {
			continue // Already in cache
		}
		
		// In a real implementation, you would:
		// 1. Parse the cache key to determine the type (mapping, metadata, etc.)
		// 2. Load the data from the appropriate source (metadata store, IPFS, etc.)
		// 3. Store the data in cache with appropriate TTL
		
		// For now, we'll just log that we would warm this key
		w.logger.Printf("Would warm key: %s", key)
		
		// Simulate some work
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Millisecond):
		}
	}
	
	return nil
}

// evictOldAccessesUnsafe removes old access entries to make room for new ones
func (w *CacheWarmer) evictOldAccessesUnsafe() {
	// Convert to slice for sorting
	var accesses []*AccessInfo
	for _, info := range w.accessTracker.accesses {
		accesses = append(accesses, info)
	}
	
	// Sort by last access time (ascending, oldest first)
	sort.Slice(accesses, func(i, j int) bool {
		return accesses[i].LastAccess.Before(accesses[j].LastAccess)
	})
	
	// Remove oldest 25% of entries
	removeCount := len(accesses) / 4
	if removeCount == 0 {
		removeCount = 1
	}
	
	for i := 0; i < removeCount && i < len(accesses); i++ {
		delete(w.accessTracker.accesses, accesses[i].Key)
	}
}

// CleanupOldAccesses removes access entries older than the window
func (w *CacheWarmer) CleanupOldAccesses() {
	w.accessTracker.mu.Lock()
	defer w.accessTracker.mu.Unlock()
	
	now := time.Now()
	cutoff := now.Add(-w.accessTracker.window)
	
	var keysToRemove []string
	for key, info := range w.accessTracker.accesses {
		if info.LastAccess.Before(cutoff) {
			keysToRemove = append(keysToRemove, key)
		}
	}
	
	for _, key := range keysToRemove {
		delete(w.accessTracker.accesses, key)
	}
	
	if len(keysToRemove) > 0 {
		w.logger.Printf("Cleaned up %d old access entries", len(keysToRemove))
	}
}