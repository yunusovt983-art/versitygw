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

// TestComprehensiveDemo demonstrates the comprehensive test suite capabilities
func TestComprehensiveDemo(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping comprehensive demo in short mode")
	}

	t.Log("=== IPFS-Cluster Integration Comprehensive Test Suite Demo ===")

	// Demonstrate unit tests
	t.Run("UnitTestsDemo", func(t *testing.T) {
		t.Log("Running unit tests demonstration...")

		suite := NewTestSuite(t)
		defer suite.Cleanup()

		// Test basic functionality
		if !suite.backend.IsHealthy() {
			t.Error("Backend should be healthy")
		} else {
			t.Log("✓ Backend health check passed")
		}

		// Test cluster client
		ctx := context.Background()
		result, err := suite.clusterClient.Pin(ctx, "QmDemo123", 2)
		if err != nil {
			t.Errorf("Demo pin failed: %v", err)
		} else if result.Success {
			t.Log("✓ Pin operation successful")
		}

		// Test metadata store
		mapping := &ObjectMapping{
			S3Key:     "demo-key",
			Bucket:    "demo-bucket",
			CID:       "QmDemo123",
			Size:      1024,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			PinStatus: PinStatusPinned,
		}

		err = suite.metadataStore.StoreMapping(ctx, mapping)
		if err != nil {
			t.Errorf("Demo metadata store failed: %v", err)
		} else {
			t.Log("✓ Metadata store operation successful")
		}

		retrieved, err := suite.metadataStore.GetMapping(ctx, "demo-key", "demo-bucket")
		if err != nil {
			t.Errorf("Demo metadata retrieval failed: %v", err)
		} else if retrieved.CID == "QmDemo123" {
			t.Log("✓ Metadata retrieval successful")
		}
	})

	// Demonstrate integration tests
	t.Run("IntegrationTestsDemo", func(t *testing.T) {
		t.Log("Running integration tests demonstration...")

		suite := NewTestSuite(t)
		defer suite.Cleanup()

		ctx := context.Background()

		// Demonstrate S3-like workflow
		testObjects := []struct {
			key    string
			bucket string
			cid    string
			size   int64
		}{
			{"photo1.jpg", "photos", "QmPhoto1", 1024 * 1024},
			{"document.pdf", "documents", "QmDoc1", 2048 * 1024},
			{"video.mp4", "videos", "QmVideo1", 100 * 1024 * 1024},
		}

		for _, obj := range testObjects {
			t.Logf("Processing object: %s/%s", obj.bucket, obj.key)

			// Pin the object
			result, err := suite.clusterClient.Pin(ctx, obj.cid, 2)
			if err != nil {
				t.Errorf("Failed to pin %s: %v", obj.key, err)
				continue
			}

			// Store metadata
			mapping := &ObjectMapping{
				S3Key:     obj.key,
				Bucket:    obj.bucket,
				CID:       obj.cid,
				Size:      obj.size,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}

			err = suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				t.Errorf("Failed to store metadata for %s: %v", obj.key, err)
				continue
			}

			t.Logf("✓ Successfully processed %s/%s (%d bytes)", obj.bucket, obj.key, obj.size)
		}

		// Demonstrate list operations
		results, err := suite.metadataStore.SearchByPrefix(ctx, "photos", "photo", 10)
		if err != nil {
			t.Errorf("Search failed: %v", err)
		} else {
			t.Logf("✓ Found %d photos", len(results))
		}
	})

	// Demonstrate performance tests
	t.Run("PerformanceTestsDemo", func(t *testing.T) {
		t.Log("Running performance tests demonstration...")

		suite := NewTestSuite(t)
		defer suite.Cleanup()

		ctx := context.Background()

		// Measure pin operation latency
		numOps := 100
		start := time.Now()

		for i := 0; i < numOps; i++ {
			cid := fmt.Sprintf("QmPerf%d", i)
			_, err := suite.clusterClient.Pin(ctx, cid, 2)
			if err != nil {
				t.Errorf("Performance test pin failed: %v", err)
			}
		}

		duration := time.Since(start)
		avgLatency := duration / time.Duration(numOps)
		opsPerSec := float64(numOps) / duration.Seconds()

		t.Logf("✓ Performance test: %d operations in %v", numOps, duration)
		t.Logf("  Average latency: %v", avgLatency)
		t.Logf("  Throughput: %.2f ops/sec", opsPerSec)

		// Measure metadata operation performance
		start = time.Now()

		for i := 0; i < numOps; i++ {
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("perf-key-%d", i),
				Bucket:    "perf-bucket",
				CID:       fmt.Sprintf("QmPerf%d", i),
				Size:      1024,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}

			err := suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				t.Errorf("Performance metadata test failed: %v", err)
			}
		}

		metaDuration := time.Since(start)
		metaOpsPerSec := float64(numOps) / metaDuration.Seconds()

		t.Logf("✓ Metadata performance: %d operations in %v (%.2f ops/sec)",
			numOps, metaDuration, metaOpsPerSec)
	})

	// Demonstrate chaos engineering
	t.Run("ChaosTestsDemo", func(t *testing.T) {
		t.Log("Running chaos engineering demonstration...")

		suite := NewTestSuite(t)
		defer suite.Cleanup()

		ctx := context.Background()

		// Demonstrate failure injection
		t.Log("Injecting cluster failures...")
		suite.clusterClient.SetFailPin(true)

		_, err := suite.clusterClient.Pin(ctx, "QmChaosTest", 2)
		if err == nil {
			t.Error("Expected failure with chaos injection")
		} else {
			t.Log("✓ Chaos failure injection working")
		}

		// Demonstrate recovery
		t.Log("Recovering from failures...")
		suite.clusterClient.SetFailPin(false)

		result, err := suite.clusterClient.Pin(ctx, "QmChaosRecovery", 2)
		if err != nil {
			t.Errorf("Recovery failed: %v", err)
		} else if result.Success {
			t.Log("✓ System recovered from chaos")
		}

		// Demonstrate partial failures
		t.Log("Testing partial failure scenarios...")
		suite.clusterClient.SetFailRate(0.3) // 30% failure rate

		successCount := 0
		failureCount := 0

		for i := 0; i < 20; i++ {
			cid := fmt.Sprintf("QmPartialChaos%d", i)
			_, err := suite.clusterClient.Pin(ctx, cid, 2)
			if err != nil {
				failureCount++
			} else {
				successCount++
			}
		}

		suite.clusterClient.SetFailRate(0) // Reset

		t.Logf("✓ Partial chaos test: %d successes, %d failures", successCount, failureCount)

		if failureCount == 0 {
			t.Log("  Note: No failures occurred (this can happen with random failures)")
		}
	})

	// Demonstrate load testing
	t.Run("LoadTestsDemo", func(t *testing.T) {
		t.Log("Running load testing demonstration...")

		suite := NewTestSuite(t)
		defer suite.Cleanup()

		config := &LoadTestConfig{
			ConcurrentUsers:   5,
			RequestsPerUser:   20,
			TestDuration:      10 * time.Second,
			ObjectSizeMin:     1024,
			ObjectSizeMax:     10240,
			ReadWriteRatio:    0.7,
			ReplicationFactor: 2,
		}

		runner := NewLoadTestRunner(suite, config)
		metrics := runner.Start()

		t.Log("✓ Load test completed:")
		t.Logf("  Total operations: %d", metrics.TotalOperations)
		t.Logf("  Successful: %d (%.2f%%)", metrics.SuccessfulOps,
			float64(metrics.SuccessfulOps)/float64(metrics.TotalOperations)*100)
		t.Logf("  Failed: %d (%.2f%%)", metrics.FailedOps,
			float64(metrics.FailedOps)/float64(metrics.TotalOperations)*100)
		t.Logf("  Throughput: %.2f ops/sec", metrics.OperationsPerSecond)
		t.Logf("  Peak concurrency: %d", metrics.PeakConcurrency)
	})

	// Demonstrate scalability testing
	t.Run("ScalabilityTestsDemo", func(t *testing.T) {
		t.Log("Running scalability testing demonstration...")

		suite := NewTestSuite(t)
		defer suite.Cleanup()

		ctx := context.Background()
		scales := []int{100, 500, 1000}

		for _, scale := range scales {
			t.Logf("Testing scale: %d operations", scale)

			start := time.Now()

			for i := 0; i < scale; i++ {
				mapping := &ObjectMapping{
					S3Key:     fmt.Sprintf("scale-key-%d-%d", scale, i),
					Bucket:    fmt.Sprintf("scale-bucket-%d", i%10),
					CID:       fmt.Sprintf("QmScale%d-%d", scale, i),
					Size:      1024,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					PinStatus: PinStatusPinned,
				}

				err := suite.metadataStore.StoreMapping(ctx, mapping)
				if err != nil {
					t.Errorf("Scalability test failed at scale %d: %v", scale, err)
					break
				}
			}

			duration := time.Since(start)
			opsPerSec := float64(scale) / duration.Seconds()

			t.Logf("✓ Scale %d: %v duration, %.2f ops/sec", scale, duration, opsPerSec)
		}
	})

	t.Log("=== Comprehensive Test Suite Demo Completed ===")
	t.Log("")
	t.Log("Summary of demonstrated capabilities:")
	t.Log("✓ Unit testing of all major components")
	t.Log("✓ Integration testing with S3-like workflows")
	t.Log("✓ Performance benchmarking and latency measurement")
	t.Log("✓ Chaos engineering with failure injection and recovery")
	t.Log("✓ Load testing with concurrent users and mixed workloads")
	t.Log("✓ Scalability testing across different operation scales")
	t.Log("")
	t.Log("To run specific test suites, use environment variables:")
	t.Log("  IPFS_INTEGRATION_TESTS=true")
	t.Log("  IPFS_CHAOS_TESTS=true")
	t.Log("  IPFS_LOAD_TESTS=true")
	t.Log("  IPFS_SCALABILITY_TESTS=true")
	t.Log("  IPFS_PERFORMANCE_TESTS=true")
	t.Log("  IPFS_CLUSTER_ENDPOINT=http://localhost:9094 (for real cluster tests)")
}

// TestEnvironmentConfiguration demonstrates environment-based test configuration
func TestEnvironmentConfiguration(t *testing.T) {
	t.Log("=== Environment Configuration Demo ===")

	// Show current environment configuration
	envVars := []string{
		"IPFS_INTEGRATION_TESTS",
		"IPFS_CHAOS_TESTS",
		"IPFS_LOAD_TESTS",
		"IPFS_SCALABILITY_TESTS",
		"IPFS_PERFORMANCE_TESTS",
		"IPFS_CLUSTER_ENDPOINT",
		"IPFS_TEST_VERBOSE",
		"IPFS_TEST_TIMEOUT",
		"IPFS_TRILLION_PIN_SIMULATION",
		"IPFS_STRESS_TESTS",
		"IPFS_ENDURANCE_TESTS",
	}

	t.Log("Current environment configuration:")
	for _, envVar := range envVars {
		value := os.Getenv(envVar)
		if value == "" {
			value = "(not set)"
		}
		t.Logf("  %s = %s", envVar, value)
	}

	// Demonstrate configuration impact
	config := DefaultTestSuiteConfig()

	t.Log("")
	t.Log("Default test suite configuration:")
	t.Logf("  RunUnitTests: %t", config.RunUnitTests)
	t.Logf("  RunIntegrationTests: %t", config.RunIntegrationTests)
	t.Logf("  RunPerformanceTests: %t", config.RunPerformanceTests)
	t.Logf("  RunChaosTests: %t", config.RunChaosTests)
	t.Logf("  RunLoadTests: %t", config.RunLoadTests)
	t.Logf("  RunScalabilityTests: %t", config.RunScalabilityTests)
	t.Logf("  ShortMode: %t", config.ShortMode)
	t.Logf("  Verbose: %t", config.Verbose)
	t.Logf("  ParallelTests: %t", config.ParallelTests)
	t.Logf("  TestTimeout: %v", config.TestTimeout)
	t.Logf("  GenerateReports: %t", config.GenerateReports)
	t.Logf("  SaveMetrics: %t", config.SaveMetrics)
	t.Logf("  ReportOutputDir: %s", config.ReportOutputDir)

	t.Log("")
	t.Log("To customize test execution, set environment variables before running tests:")
	t.Log("  export IPFS_CHAOS_TESTS=true")
	t.Log("  export IPFS_LOAD_TESTS=true")
	t.Log("  export IPFS_TEST_VERBOSE=true")
	t.Log("  go test -v ./backend/ipfs/")
}

// TestReportGeneration demonstrates test report generation
func TestReportGeneration(t *testing.T) {
	t.Log("=== Test Report Generation Demo ===")

	// Create a test reporter
	reporter := NewTestReporter("Demo Test Suite")

	// Simulate some test results
	testResults := []*TestResult{
		{
			Success:  true,
			Duration: 100 * time.Millisecond,
			Metadata: map[string]interface{}{
				"test_type": "unit",
				"component": "cluster_client",
			},
		},
		{
			Success:  true,
			Duration: 250 * time.Millisecond,
			Metadata: map[string]interface{}{
				"test_type": "integration",
				"component": "metadata_store",
			},
		},
		{
			Success:  false,
			Duration: 500 * time.Millisecond,
			Error:    fmt.Errorf("simulated test failure"),
			Metadata: map[string]interface{}{
				"test_type": "chaos",
				"component": "pin_manager",
			},
		},
		{
			Success:  true,
			Duration: 2 * time.Second,
			Metadata: map[string]interface{}{
				"test_type":  "load",
				"operations": 1000,
			},
		},
	}

	// Record results
	for _, result := range testResults {
		reporter.RecordResult(result)
	}

	// Generate report
	report := reporter.GenerateReport()

	t.Log("Generated test report:")
	t.Log(report)

	// Demonstrate saving report to file
	if os.Getenv("IPFS_SAVE_DEMO_REPORT") == "true" {
		err := reporter.SaveReport("demo-test-report.txt")
		if err != nil {
			t.Errorf("Failed to save demo report: %v", err)
		} else {
			t.Log("✓ Demo report saved to demo-test-report.txt")
		}
	}
}
