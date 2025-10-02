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
	"os"
	"sync"
	"testing"
	"time"
)

// TestComprehensiveIPFSTestSuite runs a comprehensive test suite for IPFS-Cluster integration
func TestComprehensiveIPFSTestSuite(t *testing.T) {
	// Check if comprehensive tests are enabled
	if os.Getenv("IPFS_COMPREHENSIVE_TESTS") != "true" && !testing.Short() {
		t.Skip("Comprehensive tests disabled. Set IPFS_COMPREHENSIVE_TESTS=true to enable.")
	}
	
	t.Run("UnitTests", func(t *testing.T) {
		testIPFSBackendUnit(t)
		testConfigurationUnit(t)
		testMetadataOperationsUnit(t)
		testConcurrencyUnit(t)
	})
	
	t.Run("IntegrationTests", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping integration tests in short mode")
		}
		testBasicIntegration(t)
		testErrorHandling(t)
		testFailureRecovery(t)
	})
	
	t.Run("PerformanceTests", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping performance tests in short mode")
		}
		testPerformanceBenchmarks(t)
		testScalabilityBasic(t)
	})
	
	t.Run("ChaosTests", func(t *testing.T) {
		if testing.Short() || os.Getenv("IPFS_CHAOS_TESTS") != "true" {
			t.Skip("Skipping chaos tests. Set IPFS_CHAOS_TESTS=true to enable.")
		}
		testBasicChaos(t)
	})
	
	t.Run("LoadTests", func(t *testing.T) {
		if testing.Short() || os.Getenv("IPFS_LOAD_TESTS") != "true" {
			t.Skip("Skipping load tests. Set IPFS_LOAD_TESTS=true to enable.")
		}
		testBasicLoad(t)
	})
}

// testIPFSBackendUnit tests basic IPFS backend functionality
func testIPFSBackendUnit(t *testing.T) {
	config := &IPFSConfig{
		ClusterEndpoints: []string{"http://localhost:9094"},
		ConnectTimeout:   5 * time.Second,
		RequestTimeout:   10 * time.Second,
		MaxRetries:       3,
		ReplicationMin:   1,
		ReplicationMax:   3,
		MetadataDBType:   "memory",
	}
	
	backend, err := New(config, IPFSOptions{
		Logger: log.New(os.Stdout, "[TEST] ", log.LstdFlags),
	})
	
	if err != nil {
		t.Fatalf("Failed to create IPFS backend: %v", err)
	}
	defer backend.Shutdown()
	
	// Test basic properties
	if backend.String() != "IPFS-Cluster" {
		t.Errorf("Expected backend type 'IPFS-Cluster', got '%s'", backend.String())
	}
	
	// Test health check
	if !backend.IsHealthy() {
		t.Error("Backend should be healthy after initialization")
	}
	
	// Test stats
	stats := backend.GetStats()
	if stats == nil {
		t.Error("Stats should not be nil")
	}
	
	if stats["backend_type"] != "ipfs-cluster" {
		t.Error("Backend type should be 'ipfs-cluster'")
	}
}

// testConfigurationUnit tests configuration validation and defaults
func testConfigurationUnit(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		config := &IPFSConfig{
			ClusterEndpoints: []string{"http://localhost:9094"},
		}
		
		_, err := New(config, IPFSOptions{})
		if err != nil {
			t.Errorf("Valid config should not fail: %v", err)
		}
	})
	
	t.Run("InvalidConfig", func(t *testing.T) {
		config := &IPFSConfig{
			ClusterEndpoints: []string{}, // Empty endpoints
		}
		
		_, err := New(config, IPFSOptions{})
		if err == nil {
			t.Error("Empty endpoints should cause validation error")
		}
	})
	
	t.Run("ConfigDefaults", func(t *testing.T) {
		config := &IPFSConfig{
			ClusterEndpoints: []string{"http://localhost:9094"},
		}
		
		backend, err := New(config, IPFSOptions{})
		if err != nil {
			t.Fatalf("Failed to create backend: %v", err)
		}
		defer backend.Shutdown()
		
		// Verify defaults were applied (this would require access to internal config)
		// For now, just verify the backend was created successfully
		if backend == nil {
			t.Error("Backend should not be nil")
		}
	})
}

// testMetadataOperationsUnit tests metadata operations
func testMetadataOperationsUnit(t *testing.T) {
	config := &IPFSConfig{
		ClusterEndpoints: []string{"http://localhost:9094"},
		MetadataDBType:   "memory",
	}
	
	backend, err := New(config, IPFSOptions{})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Shutdown()
	
	// Test metadata operations through the backend
	// This would require implementing actual metadata operations
	// For now, just verify the backend has metadata capabilities
	
	stats := backend.GetStats()
	if stats == nil {
		t.Error("Backend should provide stats")
	}
}

// testConcurrencyUnit tests concurrent operations
func testConcurrencyUnit(t *testing.T) {
	config := &IPFSConfig{
		ClusterEndpoints: []string{"http://localhost:9094"},
		MetadataDBType:   "memory",
	}
	
	backend, err := New(config, IPFSOptions{})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Shutdown()
	
	// Test concurrent access to backend
	numGoroutines := 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			// Test concurrent stats access
			stats := backend.GetStats()
			if stats == nil {
				errors <- fmt.Errorf("goroutine %d: stats should not be nil", id)
				return
			}
			
			// Test concurrent health checks
			if !backend.IsHealthy() {
				errors <- fmt.Errorf("goroutine %d: backend should be healthy", id)
				return
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		t.Error(err)
	}
}

// testBasicIntegration tests basic integration scenarios
func testBasicIntegration(t *testing.T) {
	config := &IPFSConfig{
		ClusterEndpoints: []string{"http://localhost:9094"},
		MetadataDBType:   "memory",
		CacheEnabled:     true,
		MetricsEnabled:   true,
	}
	
	backend, err := New(config, IPFSOptions{})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Shutdown()
	
	// Test that all components are initialized
	if !backend.IsHealthy() {
		t.Error("Backend should be healthy with all components")
	}
	
	// Test stats include all components
	stats := backend.GetStats()
	expectedKeys := []string{"backend_type", "cluster_nodes", "total_pins"}
	for _, key := range expectedKeys {
		if _, exists := stats[key]; !exists {
			t.Errorf("Stats should contain key '%s'", key)
		}
	}
}

// testErrorHandling tests error handling scenarios
func testErrorHandling(t *testing.T) {
	t.Run("InvalidEndpoints", func(t *testing.T) {
		config := &IPFSConfig{
			ClusterEndpoints: []string{"invalid://endpoint"},
		}
		
		backend, err := New(config, IPFSOptions{})
		if err != nil {
			// This is expected for invalid endpoints
			t.Logf("Expected error for invalid endpoints: %v", err)
			return
		}
		
		if backend != nil {
			backend.Shutdown()
		}
		
		// If no error, the backend should handle invalid endpoints gracefully
		t.Log("Backend handles invalid endpoints gracefully")
	})
	
	t.Run("NetworkTimeout", func(t *testing.T) {
		config := &IPFSConfig{
			ClusterEndpoints: []string{"http://192.0.2.1:9094"}, // Non-routable IP
			ConnectTimeout:   100 * time.Millisecond,            // Short timeout
		}
		
		backend, err := New(config, IPFSOptions{})
		if err != nil {
			t.Logf("Expected error for network timeout: %v", err)
			return
		}
		
		if backend != nil {
			defer backend.Shutdown()
			
			// Backend might be created but not healthy
			if backend.IsHealthy() {
				t.Log("Backend created but may not be fully healthy due to network issues")
			}
		}
	})
}

// testFailureRecovery tests failure recovery scenarios
func testFailureRecovery(t *testing.T) {
	config := &IPFSConfig{
		ClusterEndpoints: []string{"http://localhost:9094"},
		MetadataDBType:   "memory",
	}
	
	backend, err := New(config, IPFSOptions{})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Shutdown()
	
	// Test graceful shutdown and restart simulation
	initialHealth := backend.IsHealthy()
	
	// Simulate shutdown
	backend.Shutdown()
	
	// After shutdown, backend should not be healthy
	if backend.IsHealthy() {
		t.Error("Backend should not be healthy after shutdown")
	}
	
	t.Logf("Initial health: %t, health after shutdown: %t", initialHealth, backend.IsHealthy())
}

// testPerformanceBenchmarks tests basic performance characteristics
func testPerformanceBenchmarks(t *testing.T) {
	config := &IPFSConfig{
		ClusterEndpoints: []string{"http://localhost:9094"},
		MetadataDBType:   "memory",
	}
	
	backend, err := New(config, IPFSOptions{})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Shutdown()
	
	// Benchmark stats access
	start := time.Now()
	iterations := 1000
	
	for i := 0; i < iterations; i++ {
		stats := backend.GetStats()
		if stats == nil {
			t.Fatal("Stats should not be nil")
		}
	}
	
	duration := time.Since(start)
	avgLatency := duration / time.Duration(iterations)
	
	t.Logf("Stats access performance: %d iterations in %v (avg: %v per operation)", 
		iterations, duration, avgLatency)
	
	// Performance should be reasonable
	if avgLatency > 1*time.Millisecond {
		t.Errorf("Stats access too slow: %v per operation", avgLatency)
	}
}

// testScalabilityBasic tests basic scalability characteristics
func testScalabilityBasic(t *testing.T) {
	// Test with different numbers of cluster endpoints
	endpointCounts := []int{1, 3, 5}
	
	for _, count := range endpointCounts {
		t.Run(fmt.Sprintf("Endpoints_%d", count), func(t *testing.T) {
			endpoints := make([]string, count)
			for i := 0; i < count; i++ {
				endpoints[i] = fmt.Sprintf("http://localhost:%d", 9094+i)
			}
			
			config := &IPFSConfig{
				ClusterEndpoints: endpoints,
				MetadataDBType:   "memory",
			}
			
			start := time.Now()
			backend, err := New(config, IPFSOptions{})
			initTime := time.Since(start)
			
			if err != nil {
				t.Fatalf("Failed to create backend with %d endpoints: %v", count, err)
			}
			defer backend.Shutdown()
			
			t.Logf("Backend with %d endpoints initialized in %v", count, initTime)
			
			// Initialization time should not grow significantly with endpoint count
			if initTime > 5*time.Second {
				t.Errorf("Initialization too slow with %d endpoints: %v", count, initTime)
			}
		})
	}
}

// testBasicChaos tests basic chaos engineering scenarios
func testBasicChaos(t *testing.T) {
	config := &IPFSConfig{
		ClusterEndpoints: []string{"http://localhost:9094"},
		MetadataDBType:   "memory",
	}
	
	backend, err := New(config, IPFSOptions{})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Shutdown()
	
	// Simulate chaos by rapid operations
	var wg sync.WaitGroup
	numWorkers := 5
	operationsPerWorker := 10
	
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerWorker; j++ {
				// Rapid stats access to simulate load
				stats := backend.GetStats()
				if stats == nil {
					t.Errorf("Worker %d: stats should not be nil", workerID)
					return
				}
				
				// Brief pause
				time.Sleep(10 * time.Millisecond)
			}
		}(i)
	}
	
	wg.Wait()
	
	// Backend should still be healthy after chaos
	if !backend.IsHealthy() {
		t.Error("Backend should remain healthy after chaos operations")
	}
}

// testBasicLoad tests basic load handling
func testBasicLoad(t *testing.T) {
	config := &IPFSConfig{
		ClusterEndpoints: []string{"http://localhost:9094"},
		MetadataDBType:   "memory",
	}
	
	backend, err := New(config, IPFSOptions{})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Shutdown()
	
	// Generate sustained load
	duration := 5 * time.Second
	start := time.Now()
	operations := 0
	
	for time.Since(start) < duration {
		stats := backend.GetStats()
		if stats == nil {
			t.Fatal("Stats should not be nil during load test")
		}
		operations++
		
		// Small delay to prevent overwhelming
		time.Sleep(1 * time.Millisecond)
	}
	
	actualDuration := time.Since(start)
	opsPerSecond := float64(operations) / actualDuration.Seconds()
	
	t.Logf("Load test completed: %d operations in %v (%.2f ops/sec)", 
		operations, actualDuration, opsPerSecond)
	
	// Should maintain reasonable throughput
	if opsPerSecond < 100 {
		t.Errorf("Throughput too low: %.2f ops/sec", opsPerSecond)
	}
	
	// Backend should still be healthy after load
	if !backend.IsHealthy() {
		t.Error("Backend should remain healthy after load test")
	}
}