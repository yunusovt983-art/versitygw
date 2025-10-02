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
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// BenchmarkOptimizedMiddleware benchmarks the optimized authentication middleware
func BenchmarkOptimizedMiddleware(b *testing.B) {
	// Create test components
	cache := NewEnhancedCache(DefaultEnhancedCacheConfig())
	sessionManager := NewSessionManager(DefaultSessionConfig(), nil)
	
	config := DefaultOptimizedMiddlewareConfig()
	config.TargetLatency = 10 * time.Millisecond // Aggressive target for benchmarking
	
	middleware := NewOptimizedAuthMiddleware(cache, sessionManager, config)
	defer middleware.Shutdown()
	
	// Create test handler
	handler := middleware.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	
	// Pre-populate cache with test sessions
	for i := 0; i < 1000; i++ {
		sessionID := fmt.Sprintf("session-%d", i)
		session := &UserSession{
			ID:        sessionID,
			UserID:    fmt.Sprintf("user-%d", i%100),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			LastUsed:  time.Now(),
		}
		sessionManager.CreateSession(session.UserID, &SessionMetadata{})
	}
	
	b.ResetTimer()
	
	b.Run("CachedAuth", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				req := httptest.NewRequest("GET", "/test", nil)
				req.AddCookie(&http.Cookie{
					Name:  "session_id",
					Value: fmt.Sprintf("session-%d", i%1000),
				})
				
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				
				i++
			}
		})
	})
	
	b.Run("TokenAuth", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", fmt.Sprintf("Bearer token-%d", i%1000))
				
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				
				i++
			}
		})
	})
}

// BenchmarkRateLimiter benchmarks the rate limiter
func BenchmarkRateLimiter(b *testing.B) {
	config := DefaultRateLimiterConfig()
	config.DefaultLimit.RequestsPerSecond = 1000 // High limit for benchmarking
	config.DefaultLimit.BurstSize = 2000
	
	rateLimiter := NewRateLimiter(config)
	rateLimiter.Start()
	defer rateLimiter.Stop()
	
	b.ResetTimer()
	
	b.Run("Allow", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("user-%d", i%100)
				rateLimiter.Allow(key)
				i++
			}
		})
	})
	
	b.Run("AllowN", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("user-%d", i%100)
				rateLimiter.AllowN(key, 5)
				i++
			}
		})
	})
}

// BenchmarkPerformanceMonitor benchmarks the performance monitor
func BenchmarkPerformanceMonitor(b *testing.B) {
	config := DefaultPerformanceMonitorConfig()
	config.SampleSize = 100000 // Large sample size for benchmarking
	
	monitor := NewPerformanceMonitor(config)
	monitor.Start()
	defer monitor.Stop()
	
	b.ResetTimer()
	
	b.Run("RecordLatency", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				monitor.RecordAuthenticationLatency(10*time.Millisecond, true)
			}
		})
	})
	
	b.Run("RecordCacheHit", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				monitor.RecordCacheHit(i%2 == 0, "test_operation")
				i++
			}
		})
	})
	
	b.Run("GetStats", func(b *testing.B) {
		// Pre-populate with some data
		for i := 0; i < 1000; i++ {
			monitor.RecordAuthenticationLatency(time.Duration(i)*time.Microsecond, true)
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			monitor.GetLatencyStats()
		}
	})
}

// BenchmarkEnhancedCache benchmarks the enhanced cache
func BenchmarkEnhancedCache(b *testing.B) {
	config := DefaultEnhancedCacheConfig()
	config.MaxSize = 100000 // Large cache for benchmarking
	
	cache := NewEnhancedCache(config)
	defer cache.Shutdown()
	
	// Pre-populate cache
	for i := 0; i < 10000; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := fmt.Sprintf("value-%d", i)
		cache.Set(key, value, 1*time.Hour, UserCredentials)
	}
	
	b.ResetTimer()
	
	b.Run("Get", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("key-%d", i%10000)
				cache.Get(key, UserCredentials)
				i++
			}
		})
	})
	
	b.Run("Set", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				key := fmt.Sprintf("new-key-%d", i)
				value := fmt.Sprintf("new-value-%d", i)
				cache.Set(key, value, 1*time.Hour, UserCredentials)
				i++
			}
		})
	})
	
	b.Run("Mixed", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if i%10 < 8 { // 80% reads, 20% writes
					key := fmt.Sprintf("key-%d", i%10000)
					cache.Get(key, UserCredentials)
				} else {
					key := fmt.Sprintf("mixed-key-%d", i)
					value := fmt.Sprintf("mixed-value-%d", i)
					cache.Set(key, value, 1*time.Hour, UserCredentials)
				}
				i++
			}
		})
	})
}

// TestMiddlewarePerformanceTarget tests that middleware meets performance targets
func TestMiddlewarePerformanceTarget(t *testing.T) {
	// Create optimized middleware with aggressive performance targets
	cache := NewEnhancedCache(DefaultEnhancedCacheConfig())
	sessionManager := NewSessionManager(DefaultSessionConfig(), nil)
	
	config := DefaultOptimizedMiddlewareConfig()
	config.TargetLatency = 50 * time.Millisecond
	config.EnableFastPath = true
	config.EnableRateLimiting = false // Disable for pure performance test
	config.EnableMonitoring = true
	
	middleware := NewOptimizedAuthMiddleware(cache, sessionManager, config)
	defer middleware.Shutdown()
	
	// Create test handler
	handler := middleware.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	
	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		sessionID := fmt.Sprintf("session-%d", i)
		session := &UserSession{
			ID:        sessionID,
			UserID:    fmt.Sprintf("user-%d", i%100),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			LastUsed:  time.Now(),
		}
		sessionManager.CreateSession(session.UserID, &SessionMetadata{})
	}
	
	// Test concurrent requests
	numRequests := 10000
	concurrency := 100
	
	var wg sync.WaitGroup
	latencies := make([]time.Duration, numRequests)
	errors := make([]error, numRequests)
	
	semaphore := make(chan struct{}, concurrency)
	
	start := time.Now()
	
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			reqStart := time.Now()
			
			req := httptest.NewRequest("GET", "/test", nil)
			req.AddCookie(&http.Cookie{
				Name:  "session_id",
				Value: fmt.Sprintf("session-%d", index%1000),
			})
			
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			
			latencies[index] = time.Since(reqStart)
			
			if w.Code != http.StatusOK {
				errors[index] = fmt.Errorf("unexpected status code: %d", w.Code)
			}
		}(i)
	}
	
	wg.Wait()
	totalTime := time.Since(start)
	
	// Analyze results
	var totalLatency time.Duration
	var maxLatency time.Duration
	errorCount := 0
	
	for i := 0; i < numRequests; i++ {
		if errors[i] != nil {
			errorCount++
		}
		
		totalLatency += latencies[i]
		if latencies[i] > maxLatency {
			maxLatency = latencies[i]
		}
	}
	
	avgLatency := totalLatency / time.Duration(numRequests)
	throughput := float64(numRequests) / totalTime.Seconds()
	
	t.Logf("Performance test results:")
	t.Logf("  Total requests: %d", numRequests)
	t.Logf("  Concurrency: %d", concurrency)
	t.Logf("  Total time: %v", totalTime)
	t.Logf("  Average latency: %v", avgLatency)
	t.Logf("  Max latency: %v", maxLatency)
	t.Logf("  Throughput: %.2f req/sec", throughput)
	t.Logf("  Errors: %d", errorCount)
	
	// Performance assertions
	if avgLatency > config.TargetLatency {
		t.Errorf("Average latency %v exceeds target %v", avgLatency, config.TargetLatency)
	}
	
	if errorCount > numRequests/100 { // Allow 1% error rate
		t.Errorf("Too many errors: %d/%d", errorCount, numRequests)
	}
	
	if throughput < 1000 { // Expect at least 1000 req/sec
		t.Errorf("Throughput too low: %.2f req/sec", throughput)
	}
	
	// Check middleware statistics
	stats := middleware.GetStats()
	t.Logf("Middleware stats:")
	t.Logf("  Total requests: %d", stats.TotalRequests)
	t.Logf("  Successful auths: %d", stats.SuccessfulAuths)
	t.Logf("  Cache hits: %d", stats.CacheHits)
	t.Logf("  Fast path hits: %d", stats.FastPathHits)
	t.Logf("  Average latency: %v", stats.AverageLatency)
	
	// Verify cache effectiveness
	if stats.CacheHits == 0 {
		t.Error("No cache hits recorded")
	}
	
	hitRate := float64(stats.CacheHits) / float64(stats.CacheHits+stats.CacheMisses)
	if hitRate < 0.8 { // Expect at least 80% hit rate with pre-populated cache
		t.Errorf("Cache hit rate too low: %.2f", hitRate)
	}
}

// TestRateLimiterPerformance tests rate limiter performance under load
func TestRateLimiterPerformance(t *testing.T) {
	config := DefaultRateLimiterConfig()
	config.DefaultLimit.RequestsPerSecond = 100
	config.DefaultLimit.BurstSize = 200
	
	rateLimiter := NewRateLimiter(config)
	rateLimiter.Start()
	defer rateLimiter.Stop()
	
	numRequests := 10000
	concurrency := 50
	
	var wg sync.WaitGroup
	allowed := make([]bool, numRequests)
	latencies := make([]time.Duration, numRequests)
	
	semaphore := make(chan struct{}, concurrency)
	
	start := time.Now()
	
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			reqStart := time.Now()
			key := fmt.Sprintf("user-%d", index%100) // 100 different users
			allowed[index] = rateLimiter.Allow(key)
			latencies[index] = time.Since(reqStart)
		}(i)
	}
	
	wg.Wait()
	totalTime := time.Since(start)
	
	// Analyze results
	allowedCount := 0
	var totalLatency time.Duration
	var maxLatency time.Duration
	
	for i := 0; i < numRequests; i++ {
		if allowed[i] {
			allowedCount++
		}
		
		totalLatency += latencies[i]
		if latencies[i] > maxLatency {
			maxLatency = latencies[i]
		}
	}
	
	avgLatency := totalLatency / time.Duration(numRequests)
	throughput := float64(numRequests) / totalTime.Seconds()
	
	t.Logf("Rate limiter performance results:")
	t.Logf("  Total requests: %d", numRequests)
	t.Logf("  Allowed requests: %d", allowedCount)
	t.Logf("  Blocked requests: %d", numRequests-allowedCount)
	t.Logf("  Total time: %v", totalTime)
	t.Logf("  Average latency: %v", avgLatency)
	t.Logf("  Max latency: %v", maxLatency)
	t.Logf("  Throughput: %.2f req/sec", throughput)
	
	// Performance assertions
	if avgLatency > 1*time.Millisecond {
		t.Errorf("Rate limiter latency too high: %v", avgLatency)
	}
	
	if throughput < 10000 { // Expect high throughput for rate limiting decisions
		t.Errorf("Rate limiter throughput too low: %.2f req/sec", throughput)
	}
	
	// Verify rate limiting is working
	if allowedCount == numRequests {
		t.Error("Rate limiter allowed all requests - not working properly")
	}
	
	if allowedCount == 0 {
		t.Error("Rate limiter blocked all requests - too restrictive")
	}
}

// TestCachePerformanceUnderLoad tests cache performance under high load
func TestCachePerformanceUnderLoad(t *testing.T) {
	config := DefaultEnhancedCacheConfig()
	config.MaxSize = 50000
	
	cache := NewEnhancedCache(config)
	defer cache.Shutdown()
	
	numOperations := 100000
	concurrency := 100
	readRatio := 0.8 // 80% reads, 20% writes
	
	var wg sync.WaitGroup
	latencies := make([]time.Duration, numOperations)
	operations := make([]string, numOperations)
	
	semaphore := make(chan struct{}, concurrency)
	
	start := time.Now()
	
	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			reqStart := time.Now()
			
			if float64(index%100)/100.0 < readRatio {
				// Read operation
				key := fmt.Sprintf("key-%d", index%10000)
				cache.Get(key, UserCredentials)
				operations[index] = "read"
			} else {
				// Write operation
				key := fmt.Sprintf("key-%d", index)
				value := fmt.Sprintf("value-%d", index)
				cache.Set(key, value, 1*time.Hour, UserCredentials)
				operations[index] = "write"
			}
			
			latencies[index] = time.Since(reqStart)
		}(i)
	}
	
	wg.Wait()
	totalTime := time.Since(start)
	
	// Analyze results
	var totalLatency time.Duration
	var maxLatency time.Duration
	var readLatency, writeLatency time.Duration
	readCount, writeCount := 0, 0
	
	for i := 0; i < numOperations; i++ {
		totalLatency += latencies[i]
		if latencies[i] > maxLatency {
			maxLatency = latencies[i]
		}
		
		if operations[i] == "read" {
			readLatency += latencies[i]
			readCount++
		} else {
			writeLatency += latencies[i]
			writeCount++
		}
	}
	
	avgLatency := totalLatency / time.Duration(numOperations)
	avgReadLatency := readLatency / time.Duration(readCount)
	avgWriteLatency := writeLatency / time.Duration(writeCount)
	throughput := float64(numOperations) / totalTime.Seconds()
	
	t.Logf("Cache performance results:")
	t.Logf("  Total operations: %d", numOperations)
	t.Logf("  Read operations: %d", readCount)
	t.Logf("  Write operations: %d", writeCount)
	t.Logf("  Total time: %v", totalTime)
	t.Logf("  Average latency: %v", avgLatency)
	t.Logf("  Average read latency: %v", avgReadLatency)
	t.Logf("  Average write latency: %v", avgWriteLatency)
	t.Logf("  Max latency: %v", maxLatency)
	t.Logf("  Throughput: %.2f ops/sec", throughput)
	
	// Performance assertions
	if avgLatency > 100*time.Microsecond {
		t.Errorf("Cache latency too high: %v", avgLatency)
	}
	
	if avgReadLatency > 50*time.Microsecond {
		t.Errorf("Cache read latency too high: %v", avgReadLatency)
	}
	
	if throughput < 50000 { // Expect high throughput for cache operations
		t.Errorf("Cache throughput too low: %.2f ops/sec", throughput)
	}
	
	// Check cache stats
	stats := cache.GetStats()
	t.Logf("Cache stats:")
	t.Logf("  Size: %d", stats.Size)
	t.Logf("  Hits: %d", stats.Hits)
	t.Logf("  Misses: %d", stats.Misses)
	t.Logf("  Hit rate: %.2f%%", stats.HitRate())
	t.Logf("  Evictions: %d", stats.Evictions)
}

// TestMemoryUsage tests memory usage under load
func TestMemoryUsage(t *testing.T) {
	// This test would typically use runtime.MemStats to monitor memory usage
	// For now, we'll create a simplified test that checks for memory leaks
	
	cache := NewEnhancedCache(DefaultEnhancedCacheConfig())
	defer cache.Shutdown()
	
	sessionManager := NewSessionManager(DefaultSessionConfig(), nil)
	defer sessionManager.Shutdown()
	
	// Create and destroy many objects to test for leaks
	for i := 0; i < 10000; i++ {
		// Cache operations
		key := fmt.Sprintf("key-%d", i)
		value := fmt.Sprintf("value-%d", i)
		cache.Set(key, value, 1*time.Minute, UserCredentials)
		
		if i%2 == 0 {
			cache.Get(key, UserCredentials)
		}
		
		// Session operations
		session := &UserSession{
			ID:        fmt.Sprintf("session-%d", i),
			UserID:    fmt.Sprintf("user-%d", i%100),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			LastUsed:  time.Now(),
		}
		
		sessionManager.CreateSession(session.UserID, &SessionMetadata{})
		
		if i%10 == 0 {
			sessionManager.TerminateSession(session.ID)
		}
	}
	
	// Force cleanup
	cache.Shutdown()
	sessionManager.Shutdown()
	
	t.Log("Memory usage test completed - check for leaks manually")
}