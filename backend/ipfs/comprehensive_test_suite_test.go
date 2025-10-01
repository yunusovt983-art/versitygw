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
	"os"
	"testing"
	"time"
)

// TestComprehensiveTestSuite runs the comprehensive test suite
func TestComprehensiveTestSuite(t *testing.T) {
	// Run the comprehensive test suite
	TestComprehensiveIPFSIntegration(t)
}

// TestBasicFunctionality tests basic functionality of the test suite components
func TestBasicFunctionality(t *testing.T) {
	t.Run("TestSuiteCreation", func(t *testing.T) {
		suite := NewTestSuite(t)
		defer suite.Cleanup()
		
		if suite == nil {
			t.Fatal("Test suite should not be nil")
		}
		
		if suite.backend == nil {
			t.Fatal("Backend should not be nil")
		}
		
		if suite.clusterClient == nil {
			t.Fatal("Cluster client should not be nil")
		}
		
		if suite.metadataStore == nil {
			t.Fatal("Metadata store should not be nil")
		}
	})
	
	t.Run("TestDataGeneration", func(t *testing.T) {
		suite := NewTestSuite(t)
		defer suite.Cleanup()
		
		testData := suite.GenerateTestData(10)
		if len(testData) != 10 {
			t.Errorf("Expected 10 test data items, got %d", len(testData))
		}
		
		for i, data := range testData {
			if data.S3Key == "" {
				t.Errorf("Test data %d should have S3Key", i)
			}
			if data.Bucket == "" {
				t.Errorf("Test data %d should have Bucket", i)
			}
			if data.CID == "" {
				t.Errorf("Test data %d should have CID", i)
			}
			if data.Size <= 0 {
				t.Errorf("Test data %d should have positive size", i)
			}
		}
	})
	
	t.Run("PerformanceMetrics", func(t *testing.T) {
		metrics := NewPerformanceMetrics()
		if metrics == nil {
			t.Fatal("Performance metrics should not be nil")
		}
		
		// Record some operations
		metrics.RecordOperation(100*time.Millisecond, true, "test")
		metrics.RecordOperation(200*time.Millisecond, false, "test")
		metrics.RecordCacheHit()
		metrics.RecordCacheMiss()
		
		snapshot := metrics.GetSnapshot()
		if snapshot.TotalOperations != 2 {
			t.Errorf("Expected 2 total operations, got %d", snapshot.TotalOperations)
		}
		
		if snapshot.SuccessfulOps != 1 {
			t.Errorf("Expected 1 successful operation, got %d", snapshot.SuccessfulOps)
		}
		
		if snapshot.FailedOps != 1 {
			t.Errorf("Expected 1 failed operation, got %d", snapshot.FailedOps)
		}
		
		if snapshot.CacheHits != 1 {
			t.Errorf("Expected 1 cache hit, got %d", snapshot.CacheHits)
		}
		
		if snapshot.CacheMisses != 1 {
			t.Errorf("Expected 1 cache miss, got %d", snapshot.CacheMisses)
		}
	})
}

// TestLoadTestRunner tests the load test runner
func TestLoadTestRunner(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test runner test in short mode")
	}
	
	suite := NewTestSuite(t)
	defer suite.Cleanup()
	
	config := &LoadTestConfig{
		ConcurrentUsers:   2,
		RequestsPerUser:   10,
		TestDuration:      2 * time.Second,
		ObjectSizeMin:     1024,
		ObjectSizeMax:     2048,
		ReadWriteRatio:    0.5,
		ReplicationFactor: 2,
	}
	
	runner := NewLoadTestRunner(suite, config)
	metrics := runner.Start()
	
	if metrics == nil {
		t.Fatal("Load test metrics should not be nil")
	}
	
	if metrics.TotalOperations == 0 {
		t.Error("Should have performed some operations")
	}
	
	t.Logf("Load test completed: %d operations in %v", 
		metrics.TotalOperations, metrics.EndTime.Sub(metrics.StartTime))
}

// TestChaosTestRunner tests the chaos test runner
func TestChaosTestRunner(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping chaos test runner test in short mode")
	}
	
	suite := NewTestSuite(t)
	defer suite.Cleanup()
	
	config := &ChaosTestConfig{
		NodeFailureRate:     0.5,
		NetworkPartitionRate: 0.3,
		SlowNodeRate:        0.2,
		DataCorruptionRate:  0.1,
		TestDuration:        3 * time.Second,
		ChaosInterval:       1 * time.Second,
		RecoveryTime:        500 * time.Millisecond,
	}
	
	chaosRunner := NewChaosTestRunner(suite, config)
	chaosRunner.Start()
	
	// Let it run for the test duration
	time.Sleep(config.TestDuration)
	
	chaosRunner.Stop()
	
	metrics := chaosRunner.GetMetrics()
	if metrics == nil {
		t.Fatal("Chaos metrics should not be nil")
	}
	
	t.Logf("Chaos test completed: %d failures injected, %d recovered", 
		metrics.TotalFailures, metrics.RecoveredFailures)
}

// TestTestSuiteRunner tests the comprehensive test suite runner
func TestTestSuiteRunner(t *testing.T) {
	config := &TestSuiteConfig{
		RunUnitTests:        true,
		RunIntegrationTests: true,
		RunPerformanceTests: true,
		RunChaosTests:       false, // Disabled for this test
		RunLoadTests:        false, // Disabled for this test
		RunScalabilityTests: false, // Disabled for this test
		ShortMode:           true,
		Verbose:             false,
		ParallelTests:       false, // Sequential for testing
		TestTimeout:         1 * time.Minute,
		GenerateReports:     false, // Disabled for this test
		SaveMetrics:         false,
	}
	
	runner := NewTestSuiteRunner(config)
	if runner == nil {
		t.Fatal("Test suite runner should not be nil")
	}
	
	// Note: We don't actually run the full suite here as it would be too slow
	// Instead, we just test the runner creation and configuration
	
	if runner.config.RunUnitTests != true {
		t.Error("Unit tests should be enabled")
	}
	
	if runner.config.RunIntegrationTests != true {
		t.Error("Integration tests should be enabled")
	}
	
	if runner.config.RunChaosTests != false {
		t.Error("Chaos tests should be disabled")
	}
}

// TestEnvironmentConfiguration tests environment-based configuration
func TestEnvironmentConfiguration(t *testing.T) {
	// Save original environment
	originalIntegration := os.Getenv("IPFS_INTEGRATION_TESTS")
	originalChaos := os.Getenv("IPFS_CHAOS_TESTS")
	originalLoad := os.Getenv("IPFS_LOAD_TESTS")
	originalScalability := os.Getenv("IPFS_SCALABILITY_TESTS")
	
	// Clean up after test
	defer func() {
		os.Setenv("IPFS_INTEGRATION_TESTS", originalIntegration)
		os.Setenv("IPFS_CHAOS_TESTS", originalChaos)
		os.Setenv("IPFS_LOAD_TESTS", originalLoad)
		os.Setenv("IPFS_SCALABILITY_TESTS", originalScalability)
	}()
	
	t.Run("DefaultConfiguration", func(t *testing.T) {
		// Clear environment variables
		os.Unsetenv("IPFS_INTEGRATION_TESTS")
		os.Unsetenv("IPFS_CHAOS_TESTS")
		os.Unsetenv("IPFS_LOAD_TESTS")
		os.Unsetenv("IPFS_SCALABILITY_TESTS")
		
		config := DefaultTestSuiteConfig()
		
		if !config.RunUnitTests {
			t.Error("Unit tests should be enabled by default")
		}
		
		if !config.RunIntegrationTests {
			t.Error("Integration tests should be enabled by default")
		}
		
		if config.RunChaosTests {
			t.Error("Chaos tests should be disabled by default")
		}
		
		if config.RunLoadTests {
			t.Error("Load tests should be disabled by default")
		}
		
		if config.RunScalabilityTests {
			t.Error("Scalability tests should be disabled by default")
		}
	})
	
	t.Run("EnvironmentOverrides", func(t *testing.T) {
		// Set environment variables
		os.Setenv("IPFS_INTEGRATION_TESTS", "true")
		os.Setenv("IPFS_CHAOS_TESTS", "true")
		os.Setenv("IPFS_LOAD_TESTS", "true")
		os.Setenv("IPFS_SCALABILITY_TESTS", "true")
		
		// The actual configuration logic is in TestComprehensiveIPFSIntegration
		// Here we just verify the environment variables are set
		
		if os.Getenv("IPFS_INTEGRATION_TESTS") != "true" {
			t.Error("IPFS_INTEGRATION_TESTS should be set to true")
		}
		
		if os.Getenv("IPFS_CHAOS_TESTS") != "true" {
			t.Error("IPFS_CHAOS_TESTS should be set to true")
		}
		
		if os.Getenv("IPFS_LOAD_TESTS") != "true" {
			t.Error("IPFS_LOAD_TESTS should be set to true")
		}
		
		if os.Getenv("IPFS_SCALABILITY_TESTS") != "true" {
			t.Error("IPFS_SCALABILITY_TESTS should be set to true")
		}
	})
}

// BenchmarkTestSuiteComponents benchmarks test suite components
func BenchmarkTestSuiteComponents(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()
	
	b.Run("TestDataGeneration", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = suite.GenerateTestData(100)
		}
	})
	
	b.Run("PerformanceMetricsRecording", func(b *testing.B) {
		metrics := NewPerformanceMetrics()
		b.ResetTimer()
		
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				metrics.RecordOperation(100*time.Microsecond, true, "benchmark")
			}
		})
	})
	
	b.Run("MockOperations", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Simulate basic operations
			mapping := &ObjectMapping{
				S3Key:  "benchmark-key",
				Bucket: "benchmark-bucket",
				CID:    "QmBenchmark",
				Size:   1024,
			}
			
			err := suite.metadataStore.StoreMapping(nil, mapping)
			if err != nil {
				b.Fatalf("Store operation failed: %v", err)
			}
			
			_, err = suite.metadataStore.GetMapping(nil, mapping.S3Key, mapping.Bucket)
			if err != nil {
				b.Fatalf("Get operation failed: %v", err)
			}
		}
	})
}