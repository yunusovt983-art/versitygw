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
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter for IPFS operations
type RateLimiter struct {
	buckets map[string]*TokenBucket
	window  time.Duration
	mu      sync.RWMutex
}

// TokenBucket represents a token bucket for rate limiting
type TokenBucket struct {
	tokens    int
	capacity  int
	lastRefill time.Time
	mu        sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*TokenBucket),
		window:  window,
	}
	
	// Start cleanup routine
	go rl.cleanupRoutine()
	
	return rl
}

// Allow checks if an operation is allowed under the rate limit
func (rl *RateLimiter) Allow(key string, limit int) bool {
	rl.mu.Lock()
	bucket, exists := rl.buckets[key]
	if !exists {
		bucket = &TokenBucket{
			tokens:    limit,
			capacity:  limit,
			lastRefill: time.Now(),
		}
		rl.buckets[key] = bucket
	}
	rl.mu.Unlock()

	return bucket.consume()
}

// GetUsage returns current usage for a key
func (rl *RateLimiter) GetUsage(key string) (used int, capacity int) {
	rl.mu.RLock()
	bucket, exists := rl.buckets[key]
	rl.mu.RUnlock()
	
	if !exists {
		return 0, 0
	}
	
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	
	bucket.refill()
	return bucket.capacity - bucket.tokens, bucket.capacity
}

// Reset resets the rate limit for a key
func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	delete(rl.buckets, key)
	rl.mu.Unlock()
}

// consume attempts to consume a token from the bucket
func (tb *TokenBucket) consume() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	tb.refill()
	
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}
	
	return false
}

// refill refills the token bucket based on elapsed time
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	
	// Refill tokens based on elapsed time (1 token per second for simplicity)
	tokensToAdd := int(elapsed.Seconds())
	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}
}

// cleanupRoutine periodically cleans up old buckets
func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		rl.cleanup()
	}
}

// cleanup removes old unused buckets
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	cutoff := time.Now().Add(-time.Hour) // Remove buckets older than 1 hour
	
	for key, bucket := range rl.buckets {
		bucket.mu.Lock()
		if bucket.lastRefill.Before(cutoff) {
			delete(rl.buckets, key)
		}
		bucket.mu.Unlock()
	}
}

// RateLimitConfig contains configuration for different operation types
type RateLimitConfig struct {
	PinOperations      int `json:"pin_operations"`      // per minute
	UnpinOperations    int `json:"unpin_operations"`    // per minute
	MetadataOperations int `json:"metadata_operations"` // per minute
	ListOperations     int `json:"list_operations"`     // per minute
}

// DefaultRateLimitConfig returns default rate limit configuration
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		PinOperations:      1000, // 1000 pins per minute
		UnpinOperations:    500,  // 500 unpins per minute
		MetadataOperations: 2000, // 2000 metadata ops per minute
		ListOperations:     5000, // 5000 list ops per minute
	}
}

// AdaptiveRateLimiter implements an adaptive rate limiter that adjusts limits based on system load
type AdaptiveRateLimiter struct {
	baseLimiter    *RateLimiter
	config         *RateLimitConfig
	systemLoad     float64
	adaptiveFactor float64
	mu             sync.RWMutex
}

// NewAdaptiveRateLimiter creates a new adaptive rate limiter
func NewAdaptiveRateLimiter(window time.Duration, config *RateLimitConfig) *AdaptiveRateLimiter {
	if config == nil {
		config = DefaultRateLimitConfig()
	}
	
	return &AdaptiveRateLimiter{
		baseLimiter:    NewRateLimiter(window),
		config:         config,
		systemLoad:     0.0,
		adaptiveFactor: 1.0,
	}
}

// Allow checks if an operation is allowed with adaptive limits
func (arl *AdaptiveRateLimiter) Allow(key string, operationType string) bool {
	arl.mu.RLock()
	factor := arl.adaptiveFactor
	arl.mu.RUnlock()
	
	var baseLimit int
	switch operationType {
	case "pin":
		baseLimit = arl.config.PinOperations
	case "unpin":
		baseLimit = arl.config.UnpinOperations
	case "metadata":
		baseLimit = arl.config.MetadataOperations
	case "list":
		baseLimit = arl.config.ListOperations
	default:
		baseLimit = arl.config.MetadataOperations
	}
	
	// Adjust limit based on system load
	adjustedLimit := int(float64(baseLimit) * factor)
	if adjustedLimit < 1 {
		adjustedLimit = 1
	}
	
	return arl.baseLimiter.Allow(key, adjustedLimit)
}

// UpdateSystemLoad updates the system load factor
func (arl *AdaptiveRateLimiter) UpdateSystemLoad(load float64) {
	arl.mu.Lock()
	defer arl.mu.Unlock()
	
	arl.systemLoad = load
	
	// Adjust adaptive factor based on system load
	// High load = lower limits, low load = higher limits
	if load > 0.8 {
		arl.adaptiveFactor = 0.5 // Reduce limits by 50%
	} else if load > 0.6 {
		arl.adaptiveFactor = 0.75 // Reduce limits by 25%
	} else if load < 0.3 {
		arl.adaptiveFactor = 1.5 // Increase limits by 50%
	} else {
		arl.adaptiveFactor = 1.0 // Normal limits
	}
}

// GetSystemLoad returns current system load
func (arl *AdaptiveRateLimiter) GetSystemLoad() float64 {
	arl.mu.RLock()
	defer arl.mu.RUnlock()
	return arl.systemLoad
}

// GetAdaptiveFactor returns current adaptive factor
func (arl *AdaptiveRateLimiter) GetAdaptiveFactor() float64 {
	arl.mu.RLock()
	defer arl.mu.RUnlock()
	return arl.adaptiveFactor
}

// Reset resets rate limits for a key
func (arl *AdaptiveRateLimiter) Reset(key string) {
	arl.baseLimiter.Reset(key)
}

// GetUsage returns current usage for a key and operation type
func (arl *AdaptiveRateLimiter) GetUsage(key string, operationType string) (used int, capacity int) {
	var baseLimit int
	switch operationType {
	case "pin":
		baseLimit = arl.config.PinOperations
	case "unpin":
		baseLimit = arl.config.UnpinOperations
	case "metadata":
		baseLimit = arl.config.MetadataOperations
	case "list":
		baseLimit = arl.config.ListOperations
	default:
		baseLimit = arl.config.MetadataOperations
	}
	
	arl.mu.RLock()
	factor := arl.adaptiveFactor
	arl.mu.RUnlock()
	
	adjustedLimit := int(float64(baseLimit) * factor)
	if adjustedLimit < 1 {
		adjustedLimit = 1
	}
	
	used, _ = arl.baseLimiter.GetUsage(key)
	return used, adjustedLimit
}