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
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"
)

// TestAuthenticationPerformanceAndLoad tests performance and load characteristics
func TestAuthenticationPerformanceAndLoad(t *testing.T) {
	system := setupCompleteAuthSystem(t)
	defer system.cleanup()

	// Performance test scenarios
	testScenarios := []struct {
		name        string
		description string
		testFunc    func(t *testing.T, system *IntegratedAuthSystem)
	}{
		{
			name:        "AuthenticationLatencyBenchmark",
			description: "Measure authentication latency under various conditions",
			testFunc:    testAuthenticationLatencyBenchmark,
		},
		{
			name:        "CachePerformanceBenchmark",
			description: "Measure cache performance and hit rates",
			testFunc:    testCachePerformanceBenchmark,
		},
		{
			name:        "ConcurrentUserLoadTest",
			description: "Test system under concurrent user load",
			testFunc:    testConcurrentUserLoadTest,
		},
		{
			name:        "SessionManagementLoadTest",
			description: "Test session management under load",
			testFunc:    testSessionManagementLoadTest,
		},
		{
			name:        "RoleResolutionPerformanceTest",
			description: "Test role resolution performance",
			testFunc:    testRoleResolutionPerformanceTest,
		},
		{
			name:        "MFAValidationPerformanceTest",
			description: "Test MFA validation performance",
			testFunc:    testMFAValidationPerformanceTest,
		},
		{
			name:        "MemoryUsageTest",
			description: "Test memory usage under load",
			testFunc:    testMemoryUsageTest,
		},
		{
			name:        "ThroughputTest",
			description: "Test maximum throughput",
			testFunc:    testThroughputTest,
		},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("Running performance test: %s - %s", scenario.name, scenario.description)
			scenario.testFunc(t, system)
		})
	}
}

// PerformanceMetrics holds performance measurement data
type PerformanceMetrics struct {
	TotalRequests    int
	SuccessfulReqs   int
	FailedReqs       int
	TotalDuration    time.Duration
	MinLatency       time.Duration
	MaxLatency       time.Duration
	AvgLatency       time.Duration
	P50Latency       time.Duration
	P95Latency       time.Duration
	P99Latency       time.Duration
	RequestsPerSec   float64
	MemoryUsageMB    float64
	CacheHitRate     float64
}

// measurePerformance runs a performance test and collects metrics
func measurePerformance(testFunc func() error, iterations int) *PerformanceMetrics {
	var latencies []time.Duration
	var successful, failed int
	
	start := time.Now()
	
	for i := 0; i < iterations; i++ {
		reqStart := time.Now()
		err := testFunc()
		latency := time.Since(reqStart)
		
		latencies = append(latencies, latency)
		
		if err != nil {
			failed++
		} else {
			successful++
		}
	}
	
	totalDuration := time.Since(start)
	
	// Sort latencies for percentile calculations
	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})
	
	// Calculate percentiles
	p50Index := int(float64(len(latencies)) * 0.5)
	p95Index := int(float64(len(latencies)) * 0.95)
	p99Index := int(float64(len(latencies)) * 0.99)
	
	// Calculate average
	var totalLatency time.Duration
	for _, lat := range latencies {
		totalLatency += lat
	}
	avgLatency := totalLatency / time.Duration(len(latencies))
	
	// Get memory usage
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	memoryUsageMB := float64(memStats.Alloc) / 1024 / 1024
	
	return &PerformanceMetrics{
		TotalRequests:  iterations,
		SuccessfulReqs: successful,
		FailedReqs:     failed,
		TotalDuration:  totalDuration,
		MinLatency:     latencies[0],
		MaxLatency:     latencies[len(latencies)-1],
		AvgLatency:     avgLatency,
		P50Latency:     latencies[p50Index],
		P95Latency:     latencies[p95Index],
		P99Latency:     latencies[p99Index],
		RequestsPerSec: float64(iterations) / totalDuration.Seconds(),
		MemoryUsageMB:  memoryUsageMB,
	}
}

// testAuthenticationLatencyBenchmark measures authentication latency
func testAuthenticationLatencyBenchmark(t *testing.T, system *IntegratedAuthSystem) {
	ctx := context.Background()
	userID := "test-user-1"
	
	// Test authentication latency
	testFunc := func() error {
		opts := AccessOptions{
			RoleManager: system.RoleManager,
			IsRoot:      false,
			Acc: Account{
				Access: userID,
				Role:   RoleUser,
			},
			Bucket: "test-bucket",
			Object: "test-object",
			Action: GetObjectAction,
		}
		
		return VerifyAccess(ctx, system.Backend, opts)
	}
	
	// Warm up
	for i := 0; i < 10; i++ {
		testFunc()
	}
	
	// Measure performance
	metrics := measurePerformance(testFunc, 1000)
	
	t.Logf("Authentication Latency Benchmark Results:")
	t.Logf("  Total Requests: %d", metrics.TotalRequests)
	t.Logf("  Successful: %d, Failed: %d", metrics.SuccessfulReqs, metrics.FailedReqs)
	t.Logf("  Average Latency: %v", metrics.AvgLatency)
	t.Logf("  P50 Latency: %v", metrics.P50Latency)
	t.Logf("  P95 Latency: %v", metrics.P95Latency)
	t.Logf("  P99 Latency: %v", metrics.P99Latency)
	t.Logf("  Min/Max Latency: %v / %v", metrics.MinLatency, metrics.MaxLatency)
	t.Logf("  Requests/sec: %.2f", metrics.RequestsPerSec)
	
	// Performance assertions
	if metrics.P95Latency > 100*time.Millisecond {
		t.Errorf("P95 latency (%v) exceeds target of 100ms", metrics.P95Latency)
	}
	
	if metrics.RequestsPerSec < 100 {
		t.Errorf("Throughput (%.2f req/sec) is below target of 100 req/sec", metrics.RequestsPerSec)
	}
	
	if metrics.FailedReqs > 0 {
		t.Errorf("Expected no failed requests, got %d", metrics.FailedReqs)
	}
}

// testCachePerformanceBenchmark measures cache performance
func testCachePerformanceBenchmark(t *testing.T, system *IntegratedAuthSystem) {
	// Test cache set performance
	setCacheFunc := func() error {
		key := fmt.Sprintf("perf-test-key-%d", time.Now().UnixNano())
		value := "test-value"
		system.Cache.Set(key, value, 5*time.Minute, UserCredentials)
		return nil
	}
	
	setMetrics := measurePerformance(setCacheFunc, 10000)
	
	// Populate cache for get tests
	testKeys := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("get-test-key-%d", i)
		testKeys[i] = key
		system.Cache.Set(key, fmt.Sprintf("value-%d", i), 5*time.Minute, UserCredentials)
	}
	
	// Test cache get performance
	getCacheFunc := func() error {
		key := testKeys[time.Now().UnixNano()%int64(len(testKeys))]
		_, _ = system.Cache.Get(key, UserCredentials)
		return nil
	}
	
	getMetrics := measurePerformance(getCacheFunc, 10000)
	
	// Get cache statistics
	stats := system.Cache.GetStats()
	
	t.Logf("Cache Performance Benchmark Results:")
	t.Logf("  Set Operations:")
	t.Logf("    Average Latency: %v", setMetrics.AvgLatency)
	t.Logf("    P95 Latency: %v", setMetrics.P95Latency)
	t.Logf("    Operations/sec: %.2f", setMetrics.RequestsPerSec)
	t.Logf("  Get Operations:")
	t.Logf("    Average Latency: %v", getMetrics.AvgLatency)
	t.Logf("    P95 Latency: %v", getMetrics.P95Latency)
	t.Logf("    Operations/sec: %.2f", getMetrics.RequestsPerSec)
	t.Logf("  Cache Statistics:")
	t.Logf("    Hit Rate: %.2f%%", stats.HitRate*100)
	t.Logf("    Total Hits: %d", stats.Hits)
	t.Logf("    Total Misses: %d", stats.Misses)
	t.Logf("    Cache Size: %d", stats.Size)
	
	// Performance assertions
	if setMetrics.P95Latency > 10*time.Millisecond {
		t.Errorf("Cache set P95 latency (%v) exceeds target of 10ms", setMetrics.P95Latency)
	}
	
	if getMetrics.P95Latency > 1*time.Millisecond {
		t.Errorf("Cache get P95 latency (%v) exceeds target of 1ms", getMetrics.P95Latency)
	}
	
	if stats.HitRate < 0.8 {
		t.Errorf("Cache hit rate (%.2f%%) is below target of 80%%", stats.HitRate*100)
	}
}

// testConcurrentUserLoadTest tests system under concurrent user load
func testConcurrentUserLoadTest(t *testing.T, system *IntegratedAuthSystem) {
	ctx := context.Background()
	numUsers := 100
	requestsPerUser := 50
	
	// Create test users
	for i := 0; i < numUsers; i++ {
		userID := fmt.Sprintf("load-test-user-%d", i)
		err := system.RoleManager.AssignRole(userID, "read-only", "system")
		if err != nil {
			t.Fatalf("Failed to create test user %s: %v", userID, err)
		}
	}
	
	var wg sync.WaitGroup
	results := make(chan *PerformanceMetrics, numUsers)
	
	start := time.Now()
	
	// Launch concurrent users
	for i := 0; i < numUsers; i++ {
		wg.Add(1)
		go func(userIndex int) {
			defer wg.Done()
			
			userID := fmt.Sprintf("load-test-user-%d", userIndex)
			
			userTestFunc := func() error {
				opts := AccessOptions{
					RoleManager: system.RoleManager,
					IsRoot:      false,
					Acc: Account{
						Access: userID,
						Role:   RoleUser,
					},
					Bucket: fmt.Sprintf("bucket-%d", userIndex%10),
					Object: fmt.Sprintf("object-%d", time.Now().UnixNano()%1000),
					Action: GetObjectAction,
				}
				
				return VerifyAccess(ctx, system.Backend, opts)
			}
			
			metrics := measurePerformance(userTestFunc, requestsPerUser)
			results <- metrics
		}(i)
	}
	
	wg.Wait()
	close(results)
	
	totalDuration := time.Since(start)
	
	// Aggregate results
	var totalRequests, totalSuccessful, totalFailed int
	var totalLatency time.Duration
	var maxLatency time.Duration
	
	for metrics := range results {
		totalRequests += metrics.TotalRequests
		totalSuccessful += metrics.SuccessfulReqs
		totalFailed += metrics.FailedReqs
		totalLatency += metrics.AvgLatency
		if metrics.MaxLatency > maxLatency {
			maxLatency = metrics.MaxLatency
		}
	}
	
	avgLatency := totalLatency / time.Duration(numUsers)
	overallThroughput := float64(totalRequests) / totalDuration.Seconds()
	
	t.Logf("Concurrent User Load Test Results:")
	t.Logf("  Users: %d", numUsers)
	t.Logf("  Requests per User: %d", requestsPerUser)
	t.Logf("  Total Requests: %d", totalRequests)
	t.Logf("  Successful: %d, Failed: %d", totalSuccessful, totalFailed)
	t.Logf("  Test Duration: %v", totalDuration)
	t.Logf("  Average User Latency: %v", avgLatency)
	t.Logf("  Maximum Latency: %v", maxLatency)
	t.Logf("  Overall Throughput: %.2f req/sec", overallThroughput)
	t.Logf("  Success Rate: %.2f%%", float64(totalSuccessful)/float64(totalRequests)*100)
	
	// Performance assertions
	if totalFailed > totalRequests/100 { // Allow 1% failure rate
		t.Errorf("Failure rate (%.2f%%) exceeds acceptable threshold of 1%%", 
			float64(totalFailed)/float64(totalRequests)*100)
	}
	
	if overallThroughput < 1000 {
		t.Errorf("Overall throughput (%.2f req/sec) is below target of 1000 req/sec", overallThroughput)
	}
	
	if maxLatency > 5*time.Second {
		t.Errorf("Maximum latency (%v) exceeds acceptable threshold of 5s", maxLatency)
	}
}

// testSessionManagementLoadTest tests session management under load
func testSessionManagementLoadTest(t *testing.T, system *IntegratedAuthSystem) {
	numUsers := 50
	sessionsPerUser := 10
	
	var wg sync.WaitGroup
	errors := make(chan error, numUsers*sessionsPerUser*3) // create, validate, terminate
	
	start := time.Now()
	
	for i := 0; i < numUsers; i++ {
		wg.Add(1)
		go func(userIndex int) {
			defer wg.Done()
			
			userID := fmt.Sprintf("session-load-user-%d", userIndex)
			var sessions []*Session
			
			// Create sessions
			for j := 0; j < sessionsPerUser; j++ {
				metadata := &SessionMetadata{
					IPAddress:   fmt.Sprintf("192.168.%d.%d", userIndex%255, j%255),
					UserAgent:   fmt.Sprintf("LoadTestClient/%d.%d", userIndex, j),
					LoginMethod: "password",
				}
				
				session, err := system.SessionManager.CreateSession(userID, metadata)
				if err != nil {
					errors <- fmt.Errorf("user %d: failed to create session %d: %v", userIndex, j, err)
					continue
				}
				sessions = append(sessions, session)
			}
			
			// Validate sessions concurrently
			var validateWg sync.WaitGroup
			for _, session := range sessions {
				validateWg.Add(1)
				go func(s *Session) {
					defer validateWg.Done()
					_, err := system.SessionManager.ValidateSession(s.ID)
					if err != nil {
						errors <- fmt.Errorf("user %d: failed to validate session %s: %v", userIndex, s.ID, err)
					}
				}(session)
			}
			validateWg.Wait()
			
			// Terminate half the sessions
			for i, session := range sessions {
				if i%2 == 0 {
					err := system.SessionManager.TerminateSession(session.ID)
					if err != nil {
						errors <- fmt.Errorf("user %d: failed to terminate session %s: %v", userIndex, session.ID, err)
					}
				}
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	duration := time.Since(start)
	
	// Count errors
	var errorCount int
	for err := range errors {
		t.Logf("Session management error: %v", err)
		errorCount++
	}
	
	expectedSessions := numUsers * sessionsPerUser
	expectedOperations := expectedSessions * 3 // create, validate, terminate
	
	t.Logf("Session Management Load Test Results:")
	t.Logf("  Users: %d", numUsers)
	t.Logf("  Sessions per User: %d", sessionsPerUser)
	t.Logf("  Expected Sessions: %d", expectedSessions)
	t.Logf("  Test Duration: %v", duration)
	t.Logf("  Operations per Second: %.2f", float64(expectedOperations)/duration.Seconds())
	t.Logf("  Error Count: %d", errorCount)
	t.Logf("  Error Rate: %.2f%%", float64(errorCount)/float64(expectedOperations)*100)
	
	// Performance assertions
	if errorCount > expectedOperations/100 { // Allow 1% error rate
		t.Errorf("Session management error rate (%.2f%%) exceeds acceptable threshold of 1%%", 
			float64(errorCount)/float64(expectedOperations)*100)
	}
	
	if duration > 30*time.Second {
		t.Errorf("Session management test took too long (%v), expected under 30s", duration)
	}
}

// testRoleResolutionPerformanceTest tests role resolution performance
func testRoleResolutionPerformanceTest(t *testing.T, system *IntegratedAuthSystem) {
	// Create complex role hierarchy
	numRoles := 100
	numUsers := 50
	
	// Create roles with inheritance
	for i := 0; i < numRoles; i++ {
		role := &EnhancedRole{
			ID:          fmt.Sprintf("perf-role-%d", i),
			Name:        fmt.Sprintf("Performance Role %d", i),
			Description: "Role for performance testing",
			Permissions: []DetailedPermission{
				{
					Resource: fmt.Sprintf("arn:aws:s3:::bucket-%d/*", i),
					Action:   "s3:GetObject",
					Effect:   PermissionAllow,
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		
		// Add parent roles for inheritance
		if i > 0 {
			role.ParentRoles = []string{fmt.Sprintf("perf-role-%d", i-1)}
		}
		
		err := system.RoleManager.CreateRole(role)
		if err != nil {
			t.Fatalf("Failed to create role %d: %v", i, err)
		}
	}
	
	// Assign multiple roles to users
	for i := 0; i < numUsers; i++ {
		userID := fmt.Sprintf("perf-user-%d", i)
		
		// Assign 3-5 roles per user
		numRolesToAssign := 3 + (i % 3)
		for j := 0; j < numRolesToAssign; j++ {
			roleIndex := (i*numRolesToAssign + j) % numRoles
			roleID := fmt.Sprintf("perf-role-%d", roleIndex)
			
			err := system.RoleManager.AssignRole(userID, roleID, "system")
			if err != nil {
				t.Fatalf("Failed to assign role %s to user %s: %v", roleID, userID, err)
			}
		}
	}
	
	// Test role resolution performance
	testFunc := func() error {
		userIndex := time.Now().UnixNano() % int64(numUsers)
		userID := fmt.Sprintf("perf-user-%d", userIndex)
		
		_, err := system.RoleManager.GetUserRoles(userID)
		return err
	}
	
	metrics := measurePerformance(testFunc, 1000)
	
	t.Logf("Role Resolution Performance Test Results:")
	t.Logf("  Roles Created: %d", numRoles)
	t.Logf("  Users Created: %d", numUsers)
	t.Logf("  Average Resolution Time: %v", metrics.AvgLatency)
	t.Logf("  P95 Resolution Time: %v", metrics.P95Latency)
	t.Logf("  P99 Resolution Time: %v", metrics.P99Latency)
	t.Logf("  Resolutions/sec: %.2f", metrics.RequestsPerSec)
	t.Logf("  Failed Resolutions: %d", metrics.FailedReqs)
	
	// Performance assertions
	if metrics.P95Latency > 50*time.Millisecond {
		t.Errorf("Role resolution P95 latency (%v) exceeds target of 50ms", metrics.P95Latency)
	}
	
	if metrics.RequestsPerSec < 200 {
		t.Errorf("Role resolution throughput (%.2f/sec) is below target of 200/sec", metrics.RequestsPerSec)
	}
}

// testMFAValidationPerformanceTest tests MFA validation performance
func testMFAValidationPerformanceTest(t *testing.T, system *IntegratedAuthSystem) {
	userID := "mfa-perf-user"
	
	// Enable MFA for test user
	secret, err := system.MFAService.GenerateSecret(userID)
	if err != nil {
		t.Fatalf("Failed to generate MFA secret: %v", err)
	}
	
	err = system.MFAService.EnableMFA(userID, secret)
	if err != nil {
		t.Fatalf("Failed to enable MFA: %v", err)
	}
	
	// Test MFA validation performance
	testFunc := func() error {
		// Use a predictable but invalid token for consistent timing
		return system.MFAService.ValidateTOTP(userID, "123456")
	}
	
	metrics := measurePerformance(testFunc, 1000)
	
	t.Logf("MFA Validation Performance Test Results:")
	t.Logf("  Average Validation Time: %v", metrics.AvgLatency)
	t.Logf("  P95 Validation Time: %v", metrics.P95Latency)
	t.Logf("  P99 Validation Time: %v", metrics.P99Latency)
	t.Logf("  Validations/sec: %.2f", metrics.RequestsPerSec)
	t.Logf("  Expected Failures: %d", metrics.FailedReqs) // Should be all failures with invalid token
	
	// Performance assertions
	if metrics.P95Latency > 100*time.Millisecond {
		t.Errorf("MFA validation P95 latency (%v) exceeds target of 100ms", metrics.P95Latency)
	}
	
	if metrics.RequestsPerSec < 100 {
		t.Errorf("MFA validation throughput (%.2f/sec) is below target of 100/sec", metrics.RequestsPerSec)
	}
}

// testMemoryUsageTest tests memory usage under load
func testMemoryUsageTest(t *testing.T, system *IntegratedAuthSystem) {
	// Get initial memory usage
	var initialMem runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&initialMem)
	
	// Create load
	numOperations := 10000
	
	for i := 0; i < numOperations; i++ {
		// Mix of operations that could cause memory usage
		switch i % 4 {
		case 0: // Cache operations
			key := fmt.Sprintf("mem-test-key-%d", i)
			value := fmt.Sprintf("mem-test-value-%d", i)
			system.Cache.Set(key, value, 1*time.Minute, UserCredentials)
			
		case 1: // Session operations
			userID := fmt.Sprintf("mem-test-user-%d", i)
			metadata := &SessionMetadata{
				IPAddress:   "192.168.1.100",
				UserAgent:   "MemTestClient/1.0",
				LoginMethod: "password",
			}
			session, err := system.SessionManager.CreateSession(userID, metadata)
			if err == nil && i%100 == 0 { // Clean up some sessions
				system.SessionManager.TerminateSession(session.ID)
			}
			
		case 2: // Role operations
			userID := fmt.Sprintf("mem-test-user-%d", i)
			system.RoleManager.GetUserRoles(userID)
			
		case 3: // MFA operations
			userID := fmt.Sprintf("mem-test-user-%d", i)
			system.MFAService.GetMFAStatus(userID)
		}
		
		// Periodic memory checks
		if i%1000 == 0 {
			var currentMem runtime.MemStats
			runtime.ReadMemStats(&currentMem)
			currentUsageMB := float64(currentMem.Alloc) / 1024 / 1024
			t.Logf("Memory usage at operation %d: %.2f MB", i, currentUsageMB)
		}
	}
	
	// Force garbage collection and get final memory usage
	runtime.GC()
	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)
	
	initialUsageMB := float64(initialMem.Alloc) / 1024 / 1024
	finalUsageMB := float64(finalMem.Alloc) / 1024 / 1024
	memoryIncreaseMB := finalUsageMB - initialUsageMB
	
	t.Logf("Memory Usage Test Results:")
	t.Logf("  Operations Performed: %d", numOperations)
	t.Logf("  Initial Memory Usage: %.2f MB", initialUsageMB)
	t.Logf("  Final Memory Usage: %.2f MB", finalUsageMB)
	t.Logf("  Memory Increase: %.2f MB", memoryIncreaseMB)
	t.Logf("  Memory per Operation: %.2f KB", memoryIncreaseMB*1024/float64(numOperations))
	t.Logf("  Total Allocations: %d", finalMem.TotalAlloc-initialMem.TotalAlloc)
	t.Logf("  GC Cycles: %d", finalMem.NumGC-initialMem.NumGC)
	
	// Memory usage assertions
	if memoryIncreaseMB > 100 { // Allow up to 100MB increase
		t.Errorf("Memory increase (%.2f MB) exceeds acceptable threshold of 100MB", memoryIncreaseMB)
	}
	
	if finalUsageMB > 500 { // Total usage should not exceed 500MB
		t.Errorf("Final memory usage (%.2f MB) exceeds acceptable threshold of 500MB", finalUsageMB)
	}
}

// testThroughputTest tests maximum throughput
func testThroughputTest(t *testing.T, system *IntegratedAuthSystem) {
	ctx := context.Background()
	duration := 30 * time.Second
	numWorkers := runtime.NumCPU() * 2
	
	// Create test users
	for i := 0; i < numWorkers; i++ {
		userID := fmt.Sprintf("throughput-user-%d", i)
		err := system.RoleManager.AssignRole(userID, "read-only", "system")
		if err != nil {
			t.Fatalf("Failed to create throughput test user: %v", err)
		}
	}
	
	var wg sync.WaitGroup
	requestCounts := make([]int, numWorkers)
	errorCounts := make([]int, numWorkers)
	
	start := time.Now()
	
	// Launch workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerIndex int) {
			defer wg.Done()
			
			userID := fmt.Sprintf("throughput-user-%d", workerIndex)
			requests := 0
			errors := 0
			
			for time.Since(start) < duration {
				opts := AccessOptions{
					RoleManager: system.RoleManager,
					IsRoot:      false,
					Acc: Account{
						Access: userID,
						Role:   RoleUser,
					},
					Bucket: fmt.Sprintf("bucket-%d", requests%10),
					Object: fmt.Sprintf("object-%d", requests),
					Action: GetObjectAction,
				}
				
				err := VerifyAccess(ctx, system.Backend, opts)
				if err != nil {
					errors++
				}
				requests++
			}
			
			requestCounts[workerIndex] = requests
			errorCounts[workerIndex] = errors
		}(i)
	}
	
	wg.Wait()
	actualDuration := time.Since(start)
	
	// Calculate totals
	totalRequests := 0
	totalErrors := 0
	for i := 0; i < numWorkers; i++ {
		totalRequests += requestCounts[i]
		totalErrors += errorCounts[i]
	}
	
	throughput := float64(totalRequests) / actualDuration.Seconds()
	errorRate := float64(totalErrors) / float64(totalRequests) * 100
	
	t.Logf("Maximum Throughput Test Results:")
	t.Logf("  Test Duration: %v", actualDuration)
	t.Logf("  Workers: %d", numWorkers)
	t.Logf("  Total Requests: %d", totalRequests)
	t.Logf("  Total Errors: %d", totalErrors)
	t.Logf("  Throughput: %.2f req/sec", throughput)
	t.Logf("  Error Rate: %.2f%%", errorRate)
	t.Logf("  Average per Worker: %.2f req/sec", throughput/float64(numWorkers))
	
	// Get final system stats
	cacheStats := system.Cache.GetStats()
	t.Logf("  Final Cache Hit Rate: %.2f%%", cacheStats.HitRate*100)
	
	// Performance assertions
	if throughput < 5000 { // Target: 5000 req/sec
		t.Errorf("Throughput (%.2f req/sec) is below target of 5000 req/sec", throughput)
	}
	
	if errorRate > 1 { // Allow 1% error rate
		t.Errorf("Error rate (%.2f%%) exceeds acceptable threshold of 1%%", errorRate)
	}
}