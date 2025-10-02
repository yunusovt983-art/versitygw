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
	"net"
	"sync"
	"time"
)

// RateLimiter provides rate limiting functionality for authentication requests
type RateLimiter interface {
	// Rate limiting checks
	Allow(key string) bool
	AllowN(key string, n int) bool
	
	// Rate limiting with context
	Wait(ctx context.Context, key string) error
	WaitN(ctx context.Context, key string, n int) error
	
	// Configuration
	SetLimit(key string, limit RateLimit) error
	GetLimit(key string) (RateLimit, error)
	RemoveLimit(key string) error
	
	// Statistics
	GetStats(key string) (*RateLimitStats, error)
	GetAllStats() map[string]*RateLimitStats
	
	// Lifecycle
	Start() error
	Stop() error
	Reset() error
}

// RateLimit defines rate limiting parameters
type RateLimit struct {
	RequestsPerSecond float64       `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	WindowSize        time.Duration `json:"window_size"`
	Algorithm         RateLimitAlgorithm `json:"algorithm"`
}

// RateLimitAlgorithm defines different rate limiting algorithms
type RateLimitAlgorithm int

const (
	TokenBucket RateLimitAlgorithm = iota
	LeakyBucket
	SlidingWindow
	FixedWindow
)

// String returns string representation of RateLimitAlgorithm
func (a RateLimitAlgorithm) String() string {
	switch a {
	case TokenBucket:
		return "token_bucket"
	case LeakyBucket:
		return "leaky_bucket"
	case SlidingWindow:
		return "sliding_window"
	case FixedWindow:
		return "fixed_window"
	default:
		return "unknown"
	}
}

// RateLimitStats provides statistics about rate limiting
type RateLimitStats struct {
	Key               string        `json:"key"`
	RequestsAllowed   int64         `json:"requests_allowed"`
	RequestsBlocked   int64         `json:"requests_blocked"`
	CurrentRate       float64       `json:"current_rate"`
	LastRequest       time.Time     `json:"last_request"`
	WindowStart       time.Time     `json:"window_start"`
	TokensRemaining   int           `json:"tokens_remaining"`
	NextRefill        time.Time     `json:"next_refill"`
}

// RateLimiterConfig holds configuration for rate limiter
type RateLimiterConfig struct {
	DefaultLimit        RateLimit     `json:"default_limit"`
	CleanupInterval     time.Duration `json:"cleanup_interval"`
	MaxKeys             int           `json:"max_keys"`
	EnableDistributed   bool          `json:"enable_distributed"`
	RedisAddr           string        `json:"redis_addr,omitempty"`
	RedisPassword       string        `json:"redis_password,omitempty"`
	RedisDB             int           `json:"redis_db"`
}

// DefaultRateLimiterConfig returns default rate limiter configuration
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		DefaultLimit: RateLimit{
			RequestsPerSecond: 10.0,
			BurstSize:         20,
			WindowSize:        1 * time.Minute,
			Algorithm:         TokenBucket,
		},
		CleanupInterval:   5 * time.Minute,
		MaxKeys:           10000,
		EnableDistributed: false,
	}
}

// rateLimiterImpl implements RateLimiter
type rateLimiterImpl struct {
	config    *RateLimiterConfig
	limiters  map[string]*bucketLimiter
	mu        sync.RWMutex
	
	// Background cleanup
	ctx       context.Context
	cancel    context.CancelFunc
	running   bool
}

// bucketLimiter implements token bucket algorithm
type bucketLimiter struct {
	limit           RateLimit
	tokens          float64
	lastRefill      time.Time
	stats           *RateLimitStats
	mu              sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *RateLimiterConfig) RateLimiter {
	if config == nil {
		config = DefaultRateLimiterConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	rl := &rateLimiterImpl{
		config:   config,
		limiters: make(map[string]*bucketLimiter),
		ctx:      ctx,
		cancel:   cancel,
	}
	
	return rl
}

// Allow checks if a request is allowed for the given key
func (rl *rateLimiterImpl) Allow(key string) bool {
	return rl.AllowN(key, 1)
}

// AllowN checks if n requests are allowed for the given key
func (rl *rateLimiterImpl) AllowN(key string, n int) bool {
	if n <= 0 {
		return true
	}
	
	limiter := rl.getLimiter(key)
	return limiter.allowN(n)
}

// Wait waits until a request is allowed for the given key
func (rl *rateLimiterImpl) Wait(ctx context.Context, key string) error {
	return rl.WaitN(ctx, key, 1)
}

// WaitN waits until n requests are allowed for the given key
func (rl *rateLimiterImpl) WaitN(ctx context.Context, key string, n int) error {
	if n <= 0 {
		return nil
	}
	
	limiter := rl.getLimiter(key)
	
	for {
		if limiter.allowN(n) {
			return nil
		}
		
		// Calculate wait time
		waitTime := limiter.calculateWaitTime(n)
		if waitTime <= 0 {
			continue
		}
		
		// Wait with context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
			// Continue to next iteration
		}
	}
}

// SetLimit sets a custom rate limit for a key
func (rl *rateLimiterImpl) SetLimit(key string, limit RateLimit) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	if limiter, exists := rl.limiters[key]; exists {
		limiter.mu.Lock()
		limiter.limit = limit
		limiter.mu.Unlock()
	} else {
		rl.limiters[key] = newBucketLimiter(key, limit)
	}
	
	return nil
}

// GetLimit gets the rate limit for a key
func (rl *rateLimiterImpl) GetLimit(key string) (RateLimit, error) {
	if key == "" {
		return RateLimit{}, fmt.Errorf("key cannot be empty")
	}
	
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	
	if limiter, exists := rl.limiters[key]; exists {
		limiter.mu.Lock()
		limit := limiter.limit
		limiter.mu.Unlock()
		return limit, nil
	}
	
	return rl.config.DefaultLimit, nil
}

// RemoveLimit removes the rate limit for a key
func (rl *rateLimiterImpl) RemoveLimit(key string) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	delete(rl.limiters, key)
	return nil
}

// GetStats returns statistics for a key
func (rl *rateLimiterImpl) GetStats(key string) (*RateLimitStats, error) {
	if key == "" {
		return nil, fmt.Errorf("key cannot be empty")
	}
	
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	
	if limiter, exists := rl.limiters[key]; exists {
		limiter.mu.Lock()
		stats := *limiter.stats // Copy
		limiter.mu.Unlock()
		return &stats, nil
	}
	
	return nil, fmt.Errorf("no stats found for key: %s", key)
}

// GetAllStats returns statistics for all keys
func (rl *rateLimiterImpl) GetAllStats() map[string]*RateLimitStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	
	stats := make(map[string]*RateLimitStats)
	for key, limiter := range rl.limiters {
		limiter.mu.Lock()
		stats[key] = &(*limiter.stats) // Copy
		limiter.mu.Unlock()
	}
	
	return stats
}

// Start starts the rate limiter
func (rl *rateLimiterImpl) Start() error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	if rl.running {
		return nil
	}
	
	// Start cleanup goroutine
	go rl.cleanupLoop()
	
	rl.running = true
	return nil
}

// Stop stops the rate limiter
func (rl *rateLimiterImpl) Stop() error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	if !rl.running {
		return nil
	}
	
	if rl.cancel != nil {
		rl.cancel()
	}
	
	rl.running = false
	return nil
}

// Reset resets all rate limiters
func (rl *rateLimiterImpl) Reset() error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	rl.limiters = make(map[string]*bucketLimiter)
	return nil
}

// Helper methods

// getLimiter gets or creates a limiter for a key
func (rl *rateLimiterImpl) getLimiter(key string) *bucketLimiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[key]
	rl.mu.RUnlock()
	
	if exists {
		return limiter
	}
	
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	// Double-check after acquiring write lock
	if limiter, exists := rl.limiters[key]; exists {
		return limiter
	}
	
	// Check if we've reached max keys
	if len(rl.limiters) >= rl.config.MaxKeys {
		// Remove oldest limiter (simplified LRU)
		rl.removeOldestLimiter()
	}
	
	limiter = newBucketLimiter(key, rl.config.DefaultLimit)
	rl.limiters[key] = limiter
	
	return limiter
}

// removeOldestLimiter removes the oldest limiter
func (rl *rateLimiterImpl) removeOldestLimiter() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	
	for key, limiter := range rl.limiters {
		limiter.mu.Lock()
		lastRequest := limiter.stats.LastRequest
		limiter.mu.Unlock()
		
		if first || lastRequest.Before(oldestTime) {
			oldestKey = key
			oldestTime = lastRequest
			first = false
		}
	}
	
	if oldestKey != "" {
		delete(rl.limiters, oldestKey)
	}
}

// cleanupLoop periodically cleans up inactive limiters
func (rl *rateLimiterImpl) cleanupLoop() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			rl.cleanup()
		}
	}
}

// cleanup removes inactive limiters
func (rl *rateLimiterImpl) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	inactiveThreshold := 10 * time.Minute
	
	keysToRemove := make([]string, 0)
	
	for key, limiter := range rl.limiters {
		limiter.mu.Lock()
		lastRequest := limiter.stats.LastRequest
		limiter.mu.Unlock()
		
		if now.Sub(lastRequest) > inactiveThreshold {
			keysToRemove = append(keysToRemove, key)
		}
	}
	
	for _, key := range keysToRemove {
		delete(rl.limiters, key)
	}
}

// bucketLimiter implementation

// newBucketLimiter creates a new bucket limiter
func newBucketLimiter(key string, limit RateLimit) *bucketLimiter {
	now := time.Now()
	
	return &bucketLimiter{
		limit:      limit,
		tokens:     float64(limit.BurstSize),
		lastRefill: now,
		stats: &RateLimitStats{
			Key:             key,
			WindowStart:     now,
			TokensRemaining: limit.BurstSize,
		},
	}
}

// allowN checks if n tokens are available
func (bl *bucketLimiter) allowN(n int) bool {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	
	now := time.Now()
	bl.refill(now)
	
	bl.stats.LastRequest = now
	
	if bl.tokens >= float64(n) {
		bl.tokens -= float64(n)
		bl.stats.RequestsAllowed++
		bl.stats.TokensRemaining = int(bl.tokens)
		return true
	}
	
	bl.stats.RequestsBlocked++
	return false
}

// calculateWaitTime calculates how long to wait for n tokens
func (bl *bucketLimiter) calculateWaitTime(n int) time.Duration {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	
	now := time.Now()
	bl.refill(now)
	
	if bl.tokens >= float64(n) {
		return 0
	}
	
	tokensNeeded := float64(n) - bl.tokens
	waitTime := time.Duration(tokensNeeded/bl.limit.RequestsPerSecond) * time.Second
	
	return waitTime
}

// refill adds tokens to the bucket based on elapsed time
func (bl *bucketLimiter) refill(now time.Time) {
	elapsed := now.Sub(bl.lastRefill)
	if elapsed <= 0 {
		return
	}
	
	tokensToAdd := elapsed.Seconds() * bl.limit.RequestsPerSecond
	bl.tokens = min(bl.tokens+tokensToAdd, float64(bl.limit.BurstSize))
	bl.lastRefill = now
	
	bl.stats.TokensRemaining = int(bl.tokens)
	bl.stats.NextRefill = now.Add(time.Second / time.Duration(bl.limit.RequestsPerSecond))
	
	// Calculate current rate
	if elapsed > 0 {
		bl.stats.CurrentRate = float64(bl.stats.RequestsAllowed) / elapsed.Seconds()
	}
}

// AuthenticationRateLimiter provides rate limiting specifically for authentication requests
type AuthenticationRateLimiter struct {
	rateLimiter RateLimiter
	config      *AuthRateLimitConfig
}

// AuthRateLimitConfig holds configuration for authentication rate limiting
type AuthRateLimitConfig struct {
	// Per-IP limits
	IPLimit           RateLimit `json:"ip_limit"`
	IPBurstLimit      RateLimit `json:"ip_burst_limit"`
	
	// Per-user limits
	UserLimit         RateLimit `json:"user_limit"`
	UserFailureLimit  RateLimit `json:"user_failure_limit"`
	
	// Global limits
	GlobalLimit       RateLimit `json:"global_limit"`
	
	// Failure-specific limits
	FailureWindow     time.Duration `json:"failure_window"`
	MaxFailures       int           `json:"max_failures"`
	LockoutDuration   time.Duration `json:"lockout_duration"`
	
	// Whitelist/Blacklist
	WhitelistedIPs    []string `json:"whitelisted_ips"`
	BlacklistedIPs    []string `json:"blacklisted_ips"`
}

// DefaultAuthRateLimitConfig returns default authentication rate limit configuration
func DefaultAuthRateLimitConfig() *AuthRateLimitConfig {
	return &AuthRateLimitConfig{
		IPLimit: RateLimit{
			RequestsPerSecond: 5.0,
			BurstSize:         10,
			WindowSize:        1 * time.Minute,
			Algorithm:         TokenBucket,
		},
		IPBurstLimit: RateLimit{
			RequestsPerSecond: 1.0,
			BurstSize:         3,
			WindowSize:        5 * time.Minute,
			Algorithm:         TokenBucket,
		},
		UserLimit: RateLimit{
			RequestsPerSecond: 2.0,
			BurstSize:         5,
			WindowSize:        1 * time.Minute,
			Algorithm:         TokenBucket,
		},
		UserFailureLimit: RateLimit{
			RequestsPerSecond: 0.1, // 1 attempt per 10 seconds
			BurstSize:         3,
			WindowSize:        10 * time.Minute,
			Algorithm:         TokenBucket,
		},
		GlobalLimit: RateLimit{
			RequestsPerSecond: 100.0,
			BurstSize:         200,
			WindowSize:        1 * time.Minute,
			Algorithm:         TokenBucket,
		},
		FailureWindow:   15 * time.Minute,
		MaxFailures:     5,
		LockoutDuration: 30 * time.Minute,
	}
}

// NewAuthenticationRateLimiter creates a new authentication rate limiter
func NewAuthenticationRateLimiter(config *AuthRateLimitConfig) *AuthenticationRateLimiter {
	if config == nil {
		config = DefaultAuthRateLimitConfig()
	}
	
	rateLimiterConfig := DefaultRateLimiterConfig()
	rateLimiter := NewRateLimiter(rateLimiterConfig)
	
	arl := &AuthenticationRateLimiter{
		rateLimiter: rateLimiter,
		config:      config,
	}
	
	// Set up different limits
	rateLimiter.SetLimit("global", config.GlobalLimit)
	
	return arl
}

// CheckAuthenticationRequest checks if an authentication request is allowed
func (arl *AuthenticationRateLimiter) CheckAuthenticationRequest(ipAddress, userID string, isFailure bool) error {
	// Check blacklist
	if arl.isBlacklisted(ipAddress) {
		return fmt.Errorf("IP address is blacklisted: %s", ipAddress)
	}
	
	// Skip rate limiting for whitelisted IPs
	if arl.isWhitelisted(ipAddress) {
		return nil
	}
	
	// Check global limit
	if !arl.rateLimiter.Allow("global") {
		return fmt.Errorf("global rate limit exceeded")
	}
	
	// Check IP-based limits
	ipKey := fmt.Sprintf("ip:%s", ipAddress)
	if isFailure {
		arl.rateLimiter.SetLimit(ipKey, arl.config.IPBurstLimit)
	} else {
		arl.rateLimiter.SetLimit(ipKey, arl.config.IPLimit)
	}
	
	if !arl.rateLimiter.Allow(ipKey) {
		return fmt.Errorf("IP rate limit exceeded: %s", ipAddress)
	}
	
	// Check user-based limits if userID is provided
	if userID != "" {
		userKey := fmt.Sprintf("user:%s", userID)
		if isFailure {
			arl.rateLimiter.SetLimit(userKey, arl.config.UserFailureLimit)
		} else {
			arl.rateLimiter.SetLimit(userKey, arl.config.UserLimit)
		}
		
		if !arl.rateLimiter.Allow(userKey) {
			return fmt.Errorf("user rate limit exceeded: %s", userID)
		}
	}
	
	return nil
}

// isWhitelisted checks if an IP is whitelisted
func (arl *AuthenticationRateLimiter) isWhitelisted(ipAddress string) bool {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}
	
	for _, whitelistedIP := range arl.config.WhitelistedIPs {
		if whitelistedIP == ipAddress {
			return true
		}
		
		// Check CIDR ranges
		if _, cidr, err := net.ParseCIDR(whitelistedIP); err == nil {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	
	return false
}

// isBlacklisted checks if an IP is blacklisted
func (arl *AuthenticationRateLimiter) isBlacklisted(ipAddress string) bool {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}
	
	for _, blacklistedIP := range arl.config.BlacklistedIPs {
		if blacklistedIP == ipAddress {
			return true
		}
		
		// Check CIDR ranges
		if _, cidr, err := net.ParseCIDR(blacklistedIP); err == nil {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	
	return false
}

// GetStats returns rate limiting statistics
func (arl *AuthenticationRateLimiter) GetStats() map[string]*RateLimitStats {
	return arl.rateLimiter.GetAllStats()
}

// Start starts the authentication rate limiter
func (arl *AuthenticationRateLimiter) Start() error {
	return arl.rateLimiter.Start()
}

// Stop stops the authentication rate limiter
func (arl *AuthenticationRateLimiter) Stop() error {
	return arl.rateLimiter.Stop()
}

// Helper function
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}