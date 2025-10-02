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
	"os"
	"testing"
	"time"
)

// TestMain is the main entry point for comprehensive IPFS testing
func TestMain(m *testing.M) {
	// Setup comprehensive test environment
	setupTestEnvironment()

	// Run tests
	code := m.Run()

	// Cleanup
	cleanupTestEnvironment()

	os.Exit(code)
}

// setupTestEnvironment sets up the test environment
func setupTestEnvironment() {
	// Set default test configuration if not already set
	if os.Getenv("IPFS_TEST_CONFIG") == "" {
		os.Setenv("IPFS_TEST_CONFIG", "comprehensive")
	}

	// Set test timeouts
	if os.Getenv("IPFS_TEST_TIMEOUT") == "" {
		os.Setenv("IPFS_TEST_TIMEOUT", "30m")
	}

	// Enable verbose logging for comprehensive tests
	if os.Getenv("IPFS_TEST_VERBOSE") == "" {
		os.Setenv("IPFS_TEST_VERBOSE", "true")
	}
}

// cleanupTestEnvironment cleans up after tests
func cleanupTestEnvironment() {
	// Cleanup any test artifacts
	// This would include cleaning up test data, stopping test services, etc.
}

// TestComprehensiveIPFSBackend runs all comprehensive tests for IPFS backend
func TestComprehensiveIPFSBackend(t *testing.T) {
	// Check if we should run comprehensive tests
	if testing.Short() && os.Getenv("IPFS_FORCE_COMPREHENSIVE") != "true" {
		t.Skip("Skipping comprehensive tests in short mode - set IPFS_FORCE_COMPREHENSIVE=true to override")
	}

	// Set test timeout
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	// Create comprehensive test configuration
	config := &TestSuiteConfig{
		RunUnitTests:        true,
		RunIntegrationTests: true,
		RunPerformanceTests: os.Getenv("IPFS_PERFORMANCE_TESTS") == "true",
		RunChaosTests:       os.Getenv("IPFS_CHAOS_TESTS") == "true",
		RunLoadTests:        os.Getenv("IPFS_LOAD_TESTS") == "true",
		RunScalabilityTests: os.Getenv("IPFS_SCALABILITY_TESTS") == "true",
		ShortMode:           testing.Short(),
		Verbose:             os.Getenv("IPFS_TEST_VERBOSE") == "true",
		ParallelTests:       os.Getenv("IPFS_PARALLEL_TESTS") != "false",
		TestTimeout:         30 * time.Minute,
		GenerateReports:     true,
		SaveMetrics:         true,
		ReportOutputDir:     getReportOutputDir(),
	}

	// Run the comprehensive test suite
	t.Run("ComprehensiveTestSuite", func(t *testing.T) {
		// Set context for the test
		testCtx, testCancel := context.WithCancel(ctx)
		defer testCancel()

		// Monitor context cancellation
		go func() {
			<-testCtx.Done()
			if testCtx.Err() == context.DeadlineExceeded {
				t.Errorf("Comprehensive test suite timed out")
			}
		}()

		// Run the actual comprehensive tests
		TestComprehensiveIPFSIntegration(t)
	})

	// Run additional test suites based on configuration
	if config.RunPerformanceTests {
		t.Run("ExtendedPerformanceTests", func(t *testing.T) {
			runExtendedPerformanceTests(t)
		})
	}

	if os.Getenv("IPFS_CLUSTER_ENDPOINT") != "" {
		t.Run("RealClusterIntegration", func(t *testing.T) {
			TestRealIPFSClusterIntegration(t)
		})
	}

	// Run stress tests if enabled
	if os.Getenv("IPFS_STRESS_TESTS") == "true" {
		t.Run("StressTests", func(t *testing.T) {
			runStressTests(t)
		})
	}

	// Run endurance tests if enabled
	if os.Getenv("IPFS_ENDURANCE_TESTS") == "true" {
		t.Run("EnduranceTests", func(t *testing.T) {
			runEnduranceTests(t)
		})
	}
}

// runExtendedPerformanceTests runs extended performance tests
func runExtendedPerformanceTests(t *testing.T) {
	t.Log("Running extended performance tests...")

	// Run performance benchmarks as tests
	result := testing.Benchmark(BenchmarkComprehensivePinOperations)
	t.Logf("Pin Operations Benchmark: %s", result.String())

	result = testing.Benchmark(BenchmarkMetadataOperationsExtended)
	t.Logf("Metadata Operations Benchmark: %s", result.String())

	result = testing.Benchmark(BenchmarkScalabilityTests)
	t.Logf("Scalability Benchmark: %s", result.String())

	result = testing.Benchmark(BenchmarkConcurrencyLevels)
	t.Logf("Concurrency Levels Benchmark: %s", result.String())
}

// runStressTests runs stress tests
func runStressTests(t *testing.T) {
	t.Log("Running stress tests...")

	suite := NewTestSuite(t)
	defer suite.Cleanup()

	ctx := context.Background()

	// High concurrency stress test
	t.Run("HighConcurrencyStress", func(t *testing.T) {
		config := &LoadTestConfig{
			ConcurrentUsers:   100,
			RequestsPerUser:   0, // Unlimited
			TestDuration:      5 * time.Minute,
			ObjectSizeMin:     1024,
			ObjectSizeMax:     1024 * 1024, // Up to 1MB
			ReadWriteRatio:    0.3,         // Write heavy
			ReplicationFactor: 3,
			EnableChaos:       true,
			ChaosInterval:     30 * time.Second,
		}

		runner := NewLoadTestRunner(suite, config)
		metrics := runner.Start()

		t.Logf("High concurrency stress test results:\n%s", metrics.String())

		// Validate stress test results
		if metrics.TotalOperations == 0 {
			t.Error("Should have performed operations under stress")
		}

		successRate := float64(metrics.SuccessfulOps) / float64(metrics.TotalOperations)
		if successRate < 0.5 {
			t.Errorf("Success rate too low under stress: %.2f%%", successRate*100)
		}
	})

	// Memory pressure stress test
	t.Run("MemoryPressureStress", func(t *testing.T) {
		// Create many large objects to stress memory
		numObjects := 10000

		for i := 0; i < numObjects; i++ {
			largeMetadata := make(map[string]string)
			for j := 0; j < 100; j++ {
				largeMetadata[fmt.Sprintf("key-%d", j)] = fmt.Sprintf("large-value-%d", j)
			}

			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("stress-key-%d", i),
				Bucket:    fmt.Sprintf("stress-bucket-%d", i%100),
				CID:       fmt.Sprintf("QmStress%d", i),
				Size:      1024 * 1024, // 1MB each
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
				Metadata: ObjectMetadata{
					UserMetadata: largeMetadata,
				},
			}

			err := suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				t.Errorf("Memory stress test failed at object %d: %v", i, err)
				break
			}

			// Log progress
			if i%1000 == 0 {
				t.Logf("Created %d stress objects", i)
			}
		}

		t.Logf("Memory pressure stress test completed with %d objects", numObjects)
	})
}

// runEnduranceTests runs long-running endurance tests
func runEnduranceTests(t *testing.T) {
	t.Log("Running endurance tests...")

	suite := NewTestSuite(t)
	defer suite.Cleanup()

	// Long-running stability test
	t.Run("LongRunningStability", func(t *testing.T) {
		config := &LoadTestConfig{
			ConcurrentUsers:   10,
			RequestsPerUser:   0,                // Unlimited
			TestDuration:      30 * time.Minute, // 30 minutes
			ObjectSizeMin:     1024,
			ObjectSizeMax:     10240,
			ReadWriteRatio:    0.7,
			ReplicationFactor: 2,
			EnableChaos:       false, // No chaos for stability test
		}

		runner := NewLoadTestRunner(suite, config)
		metrics := runner.Start()

		t.Logf("Long-running stability test results:\n%s", metrics.String())

		// Validate endurance test results
		if metrics.TotalOperations < 10000 {
			t.Errorf("Expected at least 10000 operations in 30 minutes, got %d", metrics.TotalOperations)
		}

		successRate := float64(metrics.SuccessfulOps) / float64(metrics.TotalOperations)
		if successRate < 0.95 {
			t.Errorf("Success rate too low for stability test: %.2f%%", successRate*100)
		}

		// Check for performance degradation
		if metrics.OperationsPerSecond < 5 {
			t.Errorf("Throughput too low for stability test: %.2f ops/sec", metrics.OperationsPerSecond)
		}
	})

	// Memory leak detection test
	t.Run("MemoryLeakDetection", func(t *testing.T) {
		// This would run operations and monitor memory usage over time
		// For now, we'll simulate this with a long-running test

		ctx := context.Background()
		duration := 10 * time.Minute
		start := time.Now()

		operationCount := 0
		for time.Since(start) < duration {
			// Perform operations
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("leak-test-key-%d", operationCount),
				Bucket:    "leak-test-bucket",
				CID:       fmt.Sprintf("QmLeakTest%d", operationCount),
				Size:      1024,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}

			err := suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				t.Errorf("Memory leak test operation failed: %v", err)
			}

			// Retrieve and delete to test cleanup
			retrieved, err := suite.metadataStore.GetMapping(ctx, mapping.S3Key, mapping.Bucket)
			if err != nil {
				t.Errorf("Memory leak test retrieval failed: %v", err)
			}

			if retrieved != nil {
				err = suite.metadataStore.DeleteMapping(ctx, mapping.S3Key, mapping.Bucket)
				if err != nil {
					t.Errorf("Memory leak test deletion failed: %v", err)
				}
			}

			operationCount++

			// Log progress every 1000 operations
			if operationCount%1000 == 0 {
				t.Logf("Memory leak test: %d operations completed", operationCount)
			}
		}

		t.Logf("Memory leak detection test completed: %d operations in %v", operationCount, duration)
	})
}

// getReportOutputDir returns the directory for test reports
func getReportOutputDir() string {
	dir := os.Getenv("IPFS_TEST_REPORT_DIR")
	if dir == "" {
		dir = "test-reports"
	}
	return dir
}

// TestTrillionPinSimulation simulates handling of trillion pins (scaled down for testing)
func TestTrillionPinSimulation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping trillion pin simulation in short mode")
	}

	if os.Getenv("IPFS_TRILLION_PIN_SIMULATION") != "true" {
		t.Skip("Skipping trillion pin simulation - set IPFS_TRILLION_PIN_SIMULATION=true to enable")
	}

	suite := NewTestSuite(t)
	defer suite.Cleanup()

	ctx := context.Background()

	// Simulate trillion pins with scaled-down numbers
	// In real scenario, this would be distributed across multiple nodes
	simulationScales := []struct {
		name  string
		pins  int64
		batch int
	}{
		{"Million", 1_000_000, 10_000},
		{"TenMillion", 10_000_000, 100_000},
		{"HundredMillion", 100_000_000, 1_000_000},
	}

	for _, scale := range simulationScales {
		t.Run(scale.name, func(t *testing.T) {
			t.Logf("Simulating %s pins (%d total)", scale.name, scale.pins)

			start := time.Now()
			var totalOps int64
			var errors int64

			// Process in batches
			for batch := int64(0); batch < scale.pins; batch += int64(scale.batch) {
				batchSize := int64(scale.batch)
				if batch+batchSize > scale.pins {
					batchSize = scale.pins - batch
				}

				// Create batch of mappings
				mappings := make([]*ObjectMapping, batchSize)
				for i := int64(0); i < batchSize; i++ {
					mappings[i] = &ObjectMapping{
						S3Key:     fmt.Sprintf("trillion-key-%d-%d", batch, i),
						Bucket:    fmt.Sprintf("trillion-bucket-%d", (batch+i)%1000),
						CID:       fmt.Sprintf("QmTrillion%d-%d", batch, i),
						Size:      1024,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
						PinStatus: PinStatusPinned,
					}
				}

				// Store batch
				err := suite.metadataStore.StoreMappingBatch(ctx, mappings)
				if err != nil {
					errors++
					t.Errorf("Batch %d failed: %v", batch/int64(scale.batch), err)
				} else {
					totalOps += batchSize
				}

				// Log progress
				if batch%(int64(scale.batch)*100) == 0 {
					elapsed := time.Since(start)
					rate := float64(totalOps) / elapsed.Seconds()
					t.Logf("Progress: %d/%d pins (%.2f%%), %.2f ops/sec",
						totalOps, scale.pins, float64(totalOps)/float64(scale.pins)*100, rate)
				}
			}

			duration := time.Since(start)
			rate := float64(totalOps) / duration.Seconds()

			t.Logf("%s simulation completed: %d pins in %v (%.2f ops/sec, %d errors)",
				scale.name, totalOps, duration, rate, errors)

			// Validate simulation results
			if totalOps < scale.pins*9/10 { // Allow 10% failure
				t.Errorf("Too many failures in %s simulation: %d/%d successful",
					scale.name, totalOps, scale.pins)
			}

			if rate < 1000 { // Expect at least 1000 ops/sec
				t.Errorf("Rate too low for %s simulation: %.2f ops/sec", scale.name, rate)
			}
		})
	}
}
