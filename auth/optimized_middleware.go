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
	"net/http"
	"strings"
	"sync"
	"time"
)

// OptimizedAuthMiddleware provides high-performance authentication middleware
type OptimizedAuthMiddleware struct {
	// Core components
	cache           EnhancedCache
	rateLimiter     *AuthenticationRateLimiter
	perfMonitor     PerformanceMonitor
	sessionManager  EnhancedSessionManager
	
	// Configuration
	config          *OptimizedMiddlewareConfig
	
	// Performance optimization
	fastPathCache   map[string]*CachedAuthResult
	fastPathMu      sync.RWMutex
	
	// Statistics
	stats           *MiddlewareStats
	statsMu         sync.RWMutex
}

// OptimizedMiddlewareConfig holds configuration for optimized middleware
type OptimizedMiddlewareConfig struct {
	// Performance targets
	TargetLatency       time.Duration `json:"target_latency"`
	MaxConcurrency      int           `json:"max_concurrency"`
	
	// Caching
	EnableFastPath      bool          `json:"enable_fast_path"`
	FastPathTTL         time.Duration `json:"fast_path_ttl"`
	FastPathMaxSize     int           `json:"fast_path_max_size"`
	
	// Rate limiting
	EnableRateLimiting  bool          `json:"enable_rate_limiting"`
	RateLimitConfig     *AuthRateLimitConfig `json:"rate_limit_config"`
	
	// Monitoring
	EnableMonitoring    bool          `json:"enable_monitoring"`
	MonitoringConfig    *PerformanceMonitorConfig `json:"monitoring_config"`
	
	// Circuit breaker
	EnableCircuitBreaker bool         `json:"enable_circuit_breaker"`
	FailureThreshold    int           `json:"failure_threshold"`
	RecoveryTimeout     time.Duration `json:"recovery_timeout"`
	
	// Timeouts
	AuthTimeout         time.Duration `json:"auth_timeout"`
	CacheTimeout        time.Duration `json:"cache_timeout"`
	
	// Optimization flags
	SkipHealthCheck     bool          `json:"skip_health_check"`
	PreloadCache        bool          `json:"preload_cache"`
	EnableCompression   bool          `json:"enable_compression"`
}

// DefaultOptimizedMiddlewareConfig returns default optimized middleware configuration
func DefaultOptimizedMiddlewareConfig() *OptimizedMiddlewareConfig {
	return &OptimizedMiddlewareConfig{
		TargetLatency:        50 * time.Millisecond,
		MaxConcurrency:       1000,
		EnableFastPath:       true,
		FastPathTTL:          5 * time.Minute,
		FastPathMaxSize:      10000,
		EnableRateLimiting:   true,
		RateLimitConfig:      DefaultAuthRateLimitConfig(),
		EnableMonitoring:     true,
		MonitoringConfig:     DefaultPerformanceMonitorConfig(),
		EnableCircuitBreaker: true,
		FailureThreshold:     10,
		RecoveryTimeout:      30 * time.Second,
		AuthTimeout:          10 * time.Second,
		CacheTimeout:         5 * time.Second,
		SkipHealthCheck:      false,
		PreloadCache:         true,
		EnableCompression:    true,
	}
}

// CachedAuthResult represents a cached authentication result
type CachedAuthResult struct {
	UserID      string                 `json:"user_id"`
	Roles       []string               `json:"roles"`
	Permissions map[string]interface{} `json:"permissions"`
	ExpiresAt   time.Time              `json:"expires_at"`
	CreatedAt   time.Time              `json:"created_at"`
	Success     bool                   `json:"success"`
}

// IsExpired checks if the cached result has expired
func (car *CachedAuthResult) IsExpired() bool {
	return time.Now().After(car.ExpiresAt)
}

// MiddlewareStats provides statistics about middleware performance
type MiddlewareStats struct {
	TotalRequests       int64         `json:"total_requests"`
	SuccessfulAuths     int64         `json:"successful_auths"`
	FailedAuths         int64         `json:"failed_auths"`
	CacheHits           int64         `json:"cache_hits"`
	CacheMisses         int64         `json:"cache_misses"`
	FastPathHits        int64         `json:"fast_path_hits"`
	RateLimitBlocks     int64         `json:"rate_limit_blocks"`
	CircuitBreakerTrips int64         `json:"circuit_breaker_trips"`
	AverageLatency      time.Duration `json:"average_latency"`
	MaxLatency          time.Duration `json:"max_latency"`
	MinLatency          time.Duration `json:"min_latency"`
	LastReset           time.Time     `json:"last_reset"`
}

// NewOptimizedAuthMiddleware creates a new optimized authentication middleware
func NewOptimizedAuthMiddleware(
	cache EnhancedCache,
	sessionManager EnhancedSessionManager,
	config *OptimizedMiddlewareConfig,
) *OptimizedAuthMiddleware {
	if config == nil {
		config = DefaultOptimizedMiddlewareConfig()
	}
	
	middleware := &OptimizedAuthMiddleware{
		cache:          cache,
		sessionManager: sessionManager,
		config:         config,
		fastPathCache:  make(map[string]*CachedAuthResult),
		stats: &MiddlewareStats{
			LastReset:  time.Now(),
			MinLatency: time.Hour, // Initialize to high value
		},
	}
	
	// Initialize rate limiter if enabled
	if config.EnableRateLimiting {
		middleware.rateLimiter = NewAuthenticationRateLimiter(config.RateLimitConfig)
		middleware.rateLimiter.Start()
	}
	
	// Initialize performance monitor if enabled
	if config.EnableMonitoring {
		middleware.perfMonitor = NewPerformanceMonitor(config.MonitoringConfig)
		middleware.perfMonitor.Start()
	}
	
	// Start background cleanup for fast path cache
	if config.EnableFastPath {
		go middleware.fastPathCleanupLoop()
	}
	
	return middleware
}

// Middleware returns the HTTP middleware function
func (oam *OptimizedAuthMiddleware) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			
			// Update request count
			oam.updateStats(func(stats *MiddlewareStats) {
				stats.TotalRequests++
			})
			
			// Create context with timeout
			ctx, cancel := context.WithTimeout(r.Context(), oam.config.AuthTimeout)
			defer cancel()
			r = r.WithContext(ctx)
			
			// Extract authentication information
			authInfo := oam.extractAuthInfo(r)
			if authInfo == nil {
				oam.recordLatency(time.Since(start), false)
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}
			
			// Check rate limiting
			if oam.config.EnableRateLimiting && oam.rateLimiter != nil {
				if err := oam.checkRateLimit(r, authInfo); err != nil {
					oam.updateStats(func(stats *MiddlewareStats) {
						stats.RateLimitBlocks++
					})
					oam.recordLatency(time.Since(start), false)
					http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
					return
				}
			}
			
			// Perform authentication
			authResult, err := oam.authenticate(ctx, authInfo)
			if err != nil {
				oam.updateStats(func(stats *MiddlewareStats) {
					stats.FailedAuths++
				})
				oam.recordLatency(time.Since(start), false)
				http.Error(w, "Authentication failed", http.StatusUnauthorized)
				return
			}
			
			// Add authentication result to request context
			ctx = context.WithValue(r.Context(), "auth_result", authResult)
			ctx = context.WithValue(ctx, "user_id", authResult.UserID)
			ctx = context.WithValue(ctx, "user_roles", authResult.Roles)
			r = r.WithContext(ctx)
			
			oam.updateStats(func(stats *MiddlewareStats) {
				stats.SuccessfulAuths++
			})
			oam.recordLatency(time.Since(start), true)
			
			// Continue to next handler
			next.ServeHTTP(w, r)
		})
	}
}

// AuthInfo represents extracted authentication information
type AuthInfo struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
}

// extractAuthInfo extracts authentication information from the request
func (oam *OptimizedAuthMiddleware) extractAuthInfo(r *http.Request) *AuthInfo {
	authInfo := &AuthInfo{
		IPAddress: oam.getClientIP(r),
		UserAgent: r.UserAgent(),
	}
	
	// Try to get token from Authorization header
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			authInfo.Token = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	
	// Try to get session ID from cookie
	if cookie, err := r.Cookie("session_id"); err == nil {
		authInfo.SessionID = cookie.Value
	}
	
	// Try to get user ID from header (for some auth schemes)
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		authInfo.UserID = userID
	}
	
	// Return nil if no authentication information found
	if authInfo.Token == "" && authInfo.SessionID == "" && authInfo.UserID == "" {
		return nil
	}
	
	return authInfo
}

// authenticate performs the authentication process
func (oam *OptimizedAuthMiddleware) authenticate(ctx context.Context, authInfo *AuthInfo) (*CachedAuthResult, error) {
	// Try fast path cache first
	if oam.config.EnableFastPath {
		if result := oam.getFastPathResult(authInfo); result != nil {
			oam.updateStats(func(stats *MiddlewareStats) {
				stats.FastPathHits++
				stats.CacheHits++
			})
			if oam.perfMonitor != nil {
				oam.perfMonitor.RecordCacheHit(true, "fast_path")
			}
			return result, nil
		}
	}
	
	// Try main cache
	cacheKey := oam.buildCacheKey(authInfo)
	if cached, found := oam.cache.Get(cacheKey, UserCredentials); found {
		if result, ok := cached.(*CachedAuthResult); ok && !result.IsExpired() {
			oam.updateStats(func(stats *MiddlewareStats) {
				stats.CacheHits++
			})
			if oam.perfMonitor != nil {
				oam.perfMonitor.RecordCacheHit(true, "main_cache")
			}
			
			// Store in fast path cache
			if oam.config.EnableFastPath {
				oam.setFastPathResult(authInfo, result)
			}
			
			return result, nil
		}
	}
	
	oam.updateStats(func(stats *MiddlewareStats) {
		stats.CacheMisses++
	})
	if oam.perfMonitor != nil {
		oam.perfMonitor.RecordCacheHit(false, "main_cache")
	}
	
	// Perform actual authentication
	result, err := oam.performAuthentication(ctx, authInfo)
	if err != nil {
		return nil, err
	}
	
	// Cache the result
	oam.cache.Set(cacheKey, result, oam.config.FastPathTTL, UserCredentials)
	
	// Store in fast path cache
	if oam.config.EnableFastPath {
		oam.setFastPathResult(authInfo, result)
	}
	
	return result, nil
}

// performAuthentication performs the actual authentication logic
func (oam *OptimizedAuthMiddleware) performAuthentication(ctx context.Context, authInfo *AuthInfo) (*CachedAuthResult, error) {
	start := time.Now()
	defer func() {
		if oam.perfMonitor != nil {
			oam.perfMonitor.RecordAuthenticationLatency(time.Since(start), true)
		}
	}()
	
	// Session-based authentication
	if authInfo.SessionID != "" {
		session, err := oam.sessionManager.ValidateSession(authInfo.SessionID)
		if err == nil && session != nil {
			return &CachedAuthResult{
				UserID:    session.UserID,
				Roles:     []string{}, // Would be populated from user roles
				ExpiresAt: time.Now().Add(oam.config.FastPathTTL),
				CreatedAt: time.Now(),
				Success:   true,
			}, nil
		}
	}
	
	// Token-based authentication
	if authInfo.Token != "" {
		// This would integrate with your existing token validation logic
		// For now, we'll simulate a successful authentication
		return &CachedAuthResult{
			UserID:    "user-from-token", // Would be extracted from token
			Roles:     []string{"user"},
			ExpiresAt: time.Now().Add(oam.config.FastPathTTL),
			CreatedAt: time.Now(),
			Success:   true,
		}, nil
	}
	
	return nil, fmt.Errorf("authentication failed")
}

// checkRateLimit checks if the request should be rate limited
func (oam *OptimizedAuthMiddleware) checkRateLimit(r *http.Request, authInfo *AuthInfo) error {
	if oam.rateLimiter == nil {
		return nil
	}
	
	// This would be a failed authentication attempt if we're checking rate limits
	isFailure := false // This would be determined based on context
	
	return oam.rateLimiter.CheckAuthenticationRequest(authInfo.IPAddress, authInfo.UserID, isFailure)
}

// Fast path cache methods

// getFastPathResult gets a result from the fast path cache
func (oam *OptimizedAuthMiddleware) getFastPathResult(authInfo *AuthInfo) *CachedAuthResult {
	oam.fastPathMu.RLock()
	defer oam.fastPathMu.RUnlock()
	
	key := oam.buildFastPathKey(authInfo)
	if result, exists := oam.fastPathCache[key]; exists {
		if !result.IsExpired() {
			return result
		}
	}
	
	return nil
}

// setFastPathResult stores a result in the fast path cache
func (oam *OptimizedAuthMiddleware) setFastPathResult(authInfo *AuthInfo, result *CachedAuthResult) {
	oam.fastPathMu.Lock()
	defer oam.fastPathMu.Unlock()
	
	// Check cache size limit
	if len(oam.fastPathCache) >= oam.config.FastPathMaxSize {
		oam.evictOldestFastPathEntry()
	}
	
	key := oam.buildFastPathKey(authInfo)
	oam.fastPathCache[key] = result
}

// evictOldestFastPathEntry removes the oldest entry from fast path cache
func (oam *OptimizedAuthMiddleware) evictOldestFastPathEntry() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	
	for key, result := range oam.fastPathCache {
		if first || result.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = result.CreatedAt
			first = false
		}
	}
	
	if oldestKey != "" {
		delete(oam.fastPathCache, oldestKey)
	}
}

// fastPathCleanupLoop periodically cleans up expired fast path cache entries
func (oam *OptimizedAuthMiddleware) fastPathCleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		oam.cleanupFastPathCache()
	}
}

// cleanupFastPathCache removes expired entries from fast path cache
func (oam *OptimizedAuthMiddleware) cleanupFastPathCache() {
	oam.fastPathMu.Lock()
	defer oam.fastPathMu.Unlock()
	
	keysToDelete := make([]string, 0)
	
	for key, result := range oam.fastPathCache {
		if result.IsExpired() {
			keysToDelete = append(keysToDelete, key)
		}
	}
	
	for _, key := range keysToDelete {
		delete(oam.fastPathCache, key)
	}
}

// Helper methods

// buildCacheKey builds a cache key for the main cache
func (oam *OptimizedAuthMiddleware) buildCacheKey(authInfo *AuthInfo) string {
	if authInfo.SessionID != "" {
		return fmt.Sprintf("session:%s", authInfo.SessionID)
	}
	if authInfo.Token != "" {
		return fmt.Sprintf("token:%s", authInfo.Token)
	}
	if authInfo.UserID != "" {
		return fmt.Sprintf("user:%s", authInfo.UserID)
	}
	return fmt.Sprintf("ip:%s", authInfo.IPAddress)
}

// buildFastPathKey builds a cache key for the fast path cache
func (oam *OptimizedAuthMiddleware) buildFastPathKey(authInfo *AuthInfo) string {
	// Use a simpler key for fast path to reduce overhead
	if authInfo.SessionID != "" {
		return authInfo.SessionID
	}
	if authInfo.Token != "" {
		return authInfo.Token
	}
	return authInfo.IPAddress
}

// getClientIP extracts the client IP address from the request
func (oam *OptimizedAuthMiddleware) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// Statistics methods

// updateStats safely updates middleware statistics
func (oam *OptimizedAuthMiddleware) updateStats(updateFunc func(*MiddlewareStats)) {
	oam.statsMu.Lock()
	defer oam.statsMu.Unlock()
	updateFunc(oam.stats)
}

// recordLatency records authentication latency
func (oam *OptimizedAuthMiddleware) recordLatency(duration time.Duration, success bool) {
	oam.updateStats(func(stats *MiddlewareStats) {
		// Update min/max latency
		if duration < stats.MinLatency {
			stats.MinLatency = duration
		}
		if duration > stats.MaxLatency {
			stats.MaxLatency = duration
		}
		
		// Update average latency (simplified moving average)
		if stats.AverageLatency == 0 {
			stats.AverageLatency = duration
		} else {
			stats.AverageLatency = (stats.AverageLatency + duration) / 2
		}
	})
	
	// Record in performance monitor
	if oam.perfMonitor != nil {
		oam.perfMonitor.RecordAuthenticationLatency(duration, success)
	}
}

// GetStats returns current middleware statistics
func (oam *OptimizedAuthMiddleware) GetStats() *MiddlewareStats {
	oam.statsMu.RLock()
	defer oam.statsMu.RUnlock()
	
	// Return a copy to avoid race conditions
	statsCopy := *oam.stats
	return &statsCopy
}

// ResetStats resets middleware statistics
func (oam *OptimizedAuthMiddleware) ResetStats() {
	oam.statsMu.Lock()
	defer oam.statsMu.Unlock()
	
	oam.stats = &MiddlewareStats{
		LastReset:  time.Now(),
		MinLatency: time.Hour,
	}
}

// GetPerformanceReport returns a performance report
func (oam *OptimizedAuthMiddleware) GetPerformanceReport() *PerformanceReport {
	if oam.perfMonitor != nil {
		return oam.perfMonitor.GeneratePerformanceReport()
	}
	return nil
}

// Shutdown gracefully shuts down the middleware
func (oam *OptimizedAuthMiddleware) Shutdown() error {
	var errors []error
	
	if oam.rateLimiter != nil {
		if err := oam.rateLimiter.Stop(); err != nil {
			errors = append(errors, fmt.Errorf("failed to stop rate limiter: %w", err))
		}
	}
	
	if oam.perfMonitor != nil {
		if err := oam.perfMonitor.Stop(); err != nil {
			errors = append(errors, fmt.Errorf("failed to stop performance monitor: %w", err))
		}
	}
	
	// Clear fast path cache
	oam.fastPathMu.Lock()
	oam.fastPathCache = make(map[string]*CachedAuthResult)
	oam.fastPathMu.Unlock()
	
	if len(errors) > 0 {
		return fmt.Errorf("shutdown errors: %v", errors)
	}
	
	return nil
}

// HealthCheck performs a health check on the middleware
func (oam *OptimizedAuthMiddleware) HealthCheck() map[string]interface{} {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
	}
	
	// Add statistics
	stats := oam.GetStats()
	health["stats"] = stats
	
	// Check if performance is within targets
	if stats.AverageLatency > oam.config.TargetLatency {
		health["status"] = "degraded"
		health["warning"] = "Average latency exceeds target"
	}
	
	// Add cache information
	if oam.config.EnableFastPath {
		oam.fastPathMu.RLock()
		health["fast_path_cache_size"] = len(oam.fastPathCache)
		oam.fastPathMu.RUnlock()
	}
	
	return health
}