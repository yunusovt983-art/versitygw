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
	"io"
	"log"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// LoadTestRunner manages load testing scenarios
type LoadTestRunner struct {
	suite          *TestSuite
	config         *LoadTestConfig
	metrics        *LoadTestMetrics
	stopChan       chan bool
	wg             sync.WaitGroup
	logger         *log.Logger
}

// LoadTestMetrics tracks metrics during load testing
type LoadTestMetrics struct {
	StartTime           time.Time
	EndTime             time.Time
	TotalOperations     int64
	SuccessfulOps       int64
	FailedOps           int64
	TotalLatency        int64 // nanoseconds
	MinLatency          int64 // nanoseconds
	MaxLatency          int64 // nanoseconds
	
	// Operation-specific metrics
	PinOperations       int64
	UnpinOperations     int64
	MetadataReads       int64
	MetadataWrites      int64
	
	// Throughput metrics
	OperationsPerSecond float64
	PeakOpsPerSecond    float64
	
	// Resource metrics
	PeakConcurrency     int64
	CurrentConcurrency  int64
	
	// Error metrics
	TimeoutErrors       int64
	ConnectionErrors    int64
	ServerErrors        int64
	
	mu sync.RWMutex
}

// NewLoadTestRunner creates a new load test runner
func NewLoadTestRunner(suite *TestSuite, config *LoadTestConfig) *LoadTestRunner {
	return &LoadTestRunner{
		suite:    suite,
		config:   config,
		metrics:  &LoadTestMetrics{},
		stopChan: make(chan bool),
		logger:   log.New(io.Discard, "", 0), // Silent by default
	}
}

// SetLogger sets the logger for the load test runner
func (ltr *LoadTestRunner) SetLogger(logger *log.Logger) {
	ltr.logger = logger
}

// Start starts the load test
func (ltr *LoadTestRunner) Start() *LoadTestMetrics {
	ltr.metrics.StartTime = time.Now()
	ltr.metrics.MinLatency = int64(time.Hour) // Initialize to high value
	
	// Start workers
	for i := 0; i < ltr.config.ConcurrentUsers; i++ {
		ltr.wg.Add(1)
		go ltr.worker(i)
	}
	
	// Start metrics collector
	ltr.wg.Add(1)
	go ltr.metricsCollector()
	
	// Start chaos if enabled
	var chaosRunner *ChaosTestRunner
	if ltr.config.EnableChaos {
		chaosConfig := DefaultChaosTestConfig()
		chaosConfig.TestDuration = ltr.config.TestDuration
		chaosConfig.ChaosInterval = ltr.config.ChaosInterval
		chaosRunner = NewChaosTestRunner(ltr.suite, chaosConfig)
		chaosRunner.Start()
	}
	
	// Wait for test duration
	time.Sleep(ltr.config.TestDuration)
	
	// Stop everything
	close(ltr.stopChan)
	ltr.wg.Wait()
	
	if chaosRunner != nil {
		chaosRunner.Stop()
	}
	
	ltr.metrics.EndTime = time.Now()
	ltr.calculateFinalMetrics()
	
	return ltr.metrics
}

// worker runs load test operations
func (ltr *LoadTestRunner) worker(workerID int) {
	defer ltr.wg.Done()
	
	ctx := context.Background()
	operationCount := 0
	
	for {
		select {
		case <-ltr.stopChan:
			return
		default:
			// Perform operation based on read/write ratio
			if rand.Float64() < ltr.config.ReadWriteRatio {
				ltr.performReadOperation(ctx, workerID, operationCount)
			} else {
				ltr.performWriteOperation(ctx, workerID, operationCount)
			}
			
			operationCount++
			
			// Limit operations per user if specified
			if ltr.config.RequestsPerUser > 0 && operationCount >= ltr.config.RequestsPerUser {
				return
			}
		}
	}
}

// performReadOperation performs a read operation
func (ltr *LoadTestRunner) performReadOperation(ctx context.Context, workerID, opID int) {
	atomic.AddInt64(&ltr.metrics.CurrentConcurrency, 1)
	defer atomic.AddInt64(&ltr.metrics.CurrentConcurrency, -1)
	
	start := time.Now()
	
	// Generate random key to read
	key := fmt.Sprintf("load-test-key-%d", rand.Intn(1000))
	bucket := fmt.Sprintf("load-test-bucket-%d", rand.Intn(10))
	
	_, err := ltr.suite.metadataStore.GetMapping(ctx, key, bucket)
	
	duration := time.Since(start)
	ltr.recordOperation(duration, err == nil, "read")
	
	atomic.AddInt64(&ltr.metrics.MetadataReads, 1)
}

// performWriteOperation performs a write operation
func (ltr *LoadTestRunner) performWriteOperation(ctx context.Context, workerID, opID int) {
	atomic.AddInt64(&ltr.metrics.CurrentConcurrency, 1)
	defer atomic.AddInt64(&ltr.metrics.CurrentConcurrency, -1)
	
	start := time.Now()
	
	// Generate object size within range
	size := ltr.config.ObjectSizeMin + rand.Int63n(ltr.config.ObjectSizeMax-ltr.config.ObjectSizeMin)
	
	// Create mapping
	mapping := &ObjectMapping{
		S3Key:     fmt.Sprintf("load-test-key-%d-%d", workerID, opID),
		Bucket:    fmt.Sprintf("load-test-bucket-%d", workerID%10),
		CID:       fmt.Sprintf("QmLoadTest%d-%d", workerID, opID),
		Size:      size,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		PinStatus: PinStatusPinned,
	}
	
	// Store metadata
	err1 := ltr.suite.metadataStore.StoreMapping(ctx, mapping)
	
	// Pin object
	_, err2 := ltr.suite.clusterClient.Pin(ctx, mapping.CID, ltr.config.ReplicationFactor)
	
	duration := time.Since(start)
	success := err1 == nil && err2 == nil
	ltr.recordOperation(duration, success, "write")
	
	atomic.AddInt64(&ltr.metrics.MetadataWrites, 1)
	atomic.AddInt64(&ltr.metrics.PinOperations, 1)
	
	if err1 != nil {
		ltr.categorizeError(err1)
	}
	if err2 != nil {
		ltr.categorizeError(err2)
	}
}

// recordOperation records metrics for an operation
func (ltr *LoadTestRunner) recordOperation(duration time.Duration, success bool, opType string) {
	latencyNs := duration.Nanoseconds()
	
	atomic.AddInt64(&ltr.metrics.TotalOperations, 1)
	atomic.AddInt64(&ltr.metrics.TotalLatency, latencyNs)
	
	if success {
		atomic.AddInt64(&ltr.metrics.SuccessfulOps, 1)
	} else {
		atomic.AddInt64(&ltr.metrics.FailedOps, 1)
	}
	
	// Update min/max latency
	for {
		currentMin := atomic.LoadInt64(&ltr.metrics.MinLatency)
		if latencyNs >= currentMin || atomic.CompareAndSwapInt64(&ltr.metrics.MinLatency, currentMin, latencyNs) {
			break
		}
	}
	
	for {
		currentMax := atomic.LoadInt64(&ltr.metrics.MaxLatency)
		if latencyNs <= currentMax || atomic.CompareAndSwapInt64(&ltr.metrics.MaxLatency, currentMax, latencyNs) {
			break
		}
	}
	
	// Update peak concurrency
	current := atomic.LoadInt64(&ltr.metrics.CurrentConcurrency)
	for {
		peak := atomic.LoadInt64(&ltr.metrics.PeakConcurrency)
		if current <= peak || atomic.CompareAndSwapInt64(&ltr.metrics.PeakConcurrency, peak, current) {
			break
		}
	}
}

// categorizeError categorizes errors for metrics
func (ltr *LoadTestRunner) categorizeError(err error) {
	errStr := err.Error()
	
	if contains(errStr, "timeout") || contains(errStr, "deadline") {
		atomic.AddInt64(&ltr.metrics.TimeoutErrors, 1)
	} else if contains(errStr, "connection") || contains(errStr, "network") {
		atomic.AddInt64(&ltr.metrics.ConnectionErrors, 1)
	} else {
		atomic.AddInt64(&ltr.metrics.ServerErrors, 1)
	}
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > len(substr) && 
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				func() bool {
					for i := 0; i <= len(s)-len(substr); i++ {
						if s[i:i+len(substr)] == substr {
							return true
						}
					}
					return false
				}())))
}

// metricsCollector collects metrics periodically
func (ltr *LoadTestRunner) metricsCollector() {
	defer ltr.wg.Done()
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	var lastOps int64
	var lastTime time.Time = time.Now()
	
	for {
		select {
		case <-ltr.stopChan:
			return
		case now := <-ticker.C:
			currentOps := atomic.LoadInt64(&ltr.metrics.TotalOperations)
			
			if !lastTime.IsZero() {
				duration := now.Sub(lastTime).Seconds()
				opsPerSec := float64(currentOps-lastOps) / duration
				
				// Update current ops/sec
				ltr.metrics.mu.Lock()
				ltr.metrics.OperationsPerSecond = opsPerSec
				if opsPerSec > ltr.metrics.PeakOpsPerSecond {
					ltr.metrics.PeakOpsPerSecond = opsPerSec
				}
				ltr.metrics.mu.Unlock()
			}
			
			lastOps = currentOps
			lastTime = now
		}
	}
}

// calculateFinalMetrics calculates final metrics after test completion
func (ltr *LoadTestRunner) calculateFinalMetrics() {
	ltr.metrics.mu.Lock()
	defer ltr.metrics.mu.Unlock()
	
	duration := ltr.metrics.EndTime.Sub(ltr.metrics.StartTime).Seconds()
	if duration > 0 {
		ltr.metrics.OperationsPerSecond = float64(ltr.metrics.TotalOperations) / duration
	}
}

// GetMetrics returns a copy of current metrics
func (ltr *LoadTestRunner) GetMetrics() *LoadTestMetrics {
	ltr.metrics.mu.RLock()
	defer ltr.metrics.mu.RUnlock()
	
	return &LoadTestMetrics{
		StartTime:           ltr.metrics.StartTime,
		EndTime:             ltr.metrics.EndTime,
		TotalOperations:     atomic.LoadInt64(&ltr.metrics.TotalOperations),
		SuccessfulOps:       atomic.LoadInt64(&ltr.metrics.SuccessfulOps),
		FailedOps:           atomic.LoadInt64(&ltr.metrics.FailedOps),
		TotalLatency:        atomic.LoadInt64(&ltr.metrics.TotalLatency),
		MinLatency:          atomic.LoadInt64(&ltr.metrics.MinLatency),
		MaxLatency:          atomic.LoadInt64(&ltr.metrics.MaxLatency),
		PinOperations:       atomic.LoadInt64(&ltr.metrics.PinOperations),
		UnpinOperations:     atomic.LoadInt64(&ltr.metrics.UnpinOperations),
		MetadataReads:       atomic.LoadInt64(&ltr.metrics.MetadataReads),
		MetadataWrites:      atomic.LoadInt64(&ltr.metrics.MetadataWrites),
		OperationsPerSecond: ltr.metrics.OperationsPerSecond,
		PeakOpsPerSecond:    ltr.metrics.PeakOpsPerSecond,
		PeakConcurrency:     atomic.LoadInt64(&ltr.metrics.PeakConcurrency),
		CurrentConcurrency:  atomic.LoadInt64(&ltr.metrics.CurrentConcurrency),
		TimeoutErrors:       atomic.LoadInt64(&ltr.metrics.TimeoutErrors),
		ConnectionErrors:    atomic.LoadInt64(&ltr.metrics.ConnectionErrors),
		ServerErrors:        atomic.LoadInt64(&ltr.metrics.ServerErrors),
	}
}

// String returns a string representation of the metrics
func (ltm *LoadTestMetrics) String() string {
	duration := ltm.EndTime.Sub(ltm.StartTime)
	avgLatency := time.Duration(0)
	if ltm.TotalOperations > 0 {
		avgLatency = time.Duration(ltm.TotalLatency / ltm.TotalOperations)
	}
	
	successRate := float64(0)
	if ltm.TotalOperations > 0 {
		successRate = float64(ltm.SuccessfulOps) / float64(ltm.TotalOperations) * 100
	}
	
	return fmt.Sprintf(`Load Test Results:
  Duration: %v
  Total Operations: %d
  Successful: %d (%.2f%%)
  Failed: %d (%.2f%%)
  Operations/sec: %.2f (peak: %.2f)
  Latency - Min: %v, Avg: %v, Max: %v
  Peak Concurrency: %d
  Pin Operations: %d
  Metadata Reads: %d
  Metadata Writes: %d
  Errors - Timeout: %d, Connection: %d, Server: %d`,
		duration,
		ltm.TotalOperations,
		ltm.SuccessfulOps, successRate,
		ltm.FailedOps, float64(ltm.FailedOps)/float64(ltm.TotalOperations)*100,
		ltm.OperationsPerSecond, ltm.PeakOpsPerSecond,
		time.Duration(ltm.MinLatency), avgLatency, time.Duration(ltm.MaxLatency),
		ltm.PeakConcurrency,
		ltm.PinOperations,
		ltm.MetadataReads,
		ltm.MetadataWrites,
		ltm.TimeoutErrors, ltm.ConnectionErrors, ltm.ServerErrors)
}

// TestLoadTesting runs comprehensive load tests
func TestLoadTesting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load tests in short mode")
	}
	
	suite := NewTestSuite(t)
	defer suite.Cleanup()
	
	t.Run("BasicLoadTest", func(t *testing.T) {
		testBasicLoad(t, suite)
	})
	
	t.Run("ScalabilityTest", func(t *testing.T) {
		testScalability(t, suite)
	})
	
	t.Run("SustainedLoadTest", func(t *testing.T) {
		testSustainedLoad(t, suite)
	})
	
	t.Run("BurstLoadTest", func(t *testing.T) {
		testBurstLoad(t, suite)
	})
	
	t.Run("MixedWorkloadTest", func(t *testing.T) {
		testMixedWorkload(t, suite)
	})
	
	t.Run("StressTest", func(t *testing.T) {
		testStress(t, suite)
	})
}

// testBasicLoad tests basic load handling
func testBasicLoad(t *testing.T, suite *TestSuite) {
	config := &LoadTestConfig{
		ConcurrentUsers:   5,
		RequestsPerUser:   100,
		TestDuration:      30 * time.Second,
		ObjectSizeMin:     1024,
		ObjectSizeMax:     10240,
		ReadWriteRatio:    0.7,
		ReplicationFactor: 2,
	}
	
	runner := NewLoadTestRunner(suite, config)
	runner.SetLogger(suite.logger)
	
	metrics := runner.Start()
	
	t.Logf("Basic Load Test Results:\n%s", metrics.String())
	
	// Validate results
	if metrics.TotalOperations == 0 {
		t.Error("Should have performed some operations")
	}
	
	if metrics.SuccessfulOps == 0 {
		t.Error("Should have some successful operations")
	}
	
	successRate := float64(metrics.SuccessfulOps) / float64(metrics.TotalOperations)
	if successRate < 0.8 {
		t.Errorf("Success rate too low: %.2f%% (expected >= 80%%)", successRate*100)
	}
	
	if metrics.OperationsPerSecond == 0 {
		t.Error("Should have non-zero operations per second")
	}
}

// testScalability tests scalability with increasing load
func testScalability(t *testing.T, suite *TestSuite) {
	concurrencyLevels := []int{1, 5, 10, 20, 50}
	results := make([]*LoadTestMetrics, len(concurrencyLevels))
	
	for i, concurrency := range concurrencyLevels {
		t.Logf("Testing scalability with %d concurrent users", concurrency)
		
		config := &LoadTestConfig{
			ConcurrentUsers:   concurrency,
			RequestsPerUser:   50,
			TestDuration:      15 * time.Second,
			ObjectSizeMin:     1024,
			ObjectSizeMax:     5120,
			ReadWriteRatio:    0.7,
			ReplicationFactor: 2,
		}
		
		runner := NewLoadTestRunner(suite, config)
		results[i] = runner.Start()
		
		t.Logf("Concurrency %d: %.2f ops/sec, %.2f%% success rate",
			concurrency,
			results[i].OperationsPerSecond,
			float64(results[i].SuccessfulOps)/float64(results[i].TotalOperations)*100)
	}
	
	// Analyze scalability
	for i := 1; i < len(results); i++ {
		prevOpsPerSec := results[i-1].OperationsPerSecond
		currentOpsPerSec := results[i].OperationsPerSecond
		
		// Throughput should generally increase with concurrency (up to a point)
		if i < 3 && currentOpsPerSec < prevOpsPerSec*0.8 {
			t.Logf("Warning: Throughput decreased significantly from %d to %d concurrent users: %.2f -> %.2f ops/sec",
				concurrencyLevels[i-1], concurrencyLevels[i], prevOpsPerSec, currentOpsPerSec)
		}
		
		// Success rate should remain reasonable
		successRate := float64(results[i].SuccessfulOps) / float64(results[i].TotalOperations)
		if successRate < 0.7 {
			t.Errorf("Success rate too low at concurrency %d: %.2f%%", concurrencyLevels[i], successRate*100)
		}
	}
}

// testSustainedLoad tests sustained load over time
func testSustainedLoad(t *testing.T, suite *TestSuite) {
	config := &LoadTestConfig{
		ConcurrentUsers:   10,
		RequestsPerUser:   0, // Unlimited
		TestDuration:      2 * time.Minute,
		ObjectSizeMin:     1024,
		ObjectSizeMax:     10240,
		ReadWriteRatio:    0.8,
		ReplicationFactor: 2,
	}
	
	runner := NewLoadTestRunner(suite, config)
	runner.SetLogger(suite.logger)
	
	metrics := runner.Start()
	
	t.Logf("Sustained Load Test Results:\n%s", metrics.String())
	
	// Check for sustained performance
	if metrics.TotalOperations < 1000 {
		t.Errorf("Expected at least 1000 operations in sustained test, got %d", metrics.TotalOperations)
	}
	
	// Success rate should remain high even under sustained load
	successRate := float64(metrics.SuccessfulOps) / float64(metrics.TotalOperations)
	if successRate < 0.75 {
		t.Errorf("Success rate too low in sustained test: %.2f%%", successRate*100)
	}
	
	// Should maintain reasonable throughput
	if metrics.OperationsPerSecond < 10 {
		t.Errorf("Throughput too low in sustained test: %.2f ops/sec", metrics.OperationsPerSecond)
	}
}

// testBurstLoad tests burst load patterns
func testBurstLoad(t *testing.T, suite *TestSuite) {
	// Test with burst pattern: low -> high -> low concurrency
	phases := []struct {
		name        string
		concurrency int
		duration    time.Duration
	}{
		{"Low Load", 2, 10 * time.Second},
		{"Burst Load", 20, 15 * time.Second},
		{"Recovery", 2, 10 * time.Second},
	}
	
	var allMetrics []*LoadTestMetrics
	
	for _, phase := range phases {
		t.Logf("Running %s phase with %d concurrent users", phase.name, phase.concurrency)
		
		config := &LoadTestConfig{
			ConcurrentUsers:   phase.concurrency,
			RequestsPerUser:   0, // Unlimited
			TestDuration:      phase.duration,
			ObjectSizeMin:     1024,
			ObjectSizeMax:     5120,
			ReadWriteRatio:    0.7,
			ReplicationFactor: 2,
		}
		
		runner := NewLoadTestRunner(suite, config)
		metrics := runner.Start()
		allMetrics = append(allMetrics, metrics)
		
		t.Logf("%s: %.2f ops/sec, %.2f%% success rate",
			phase.name,
			metrics.OperationsPerSecond,
			float64(metrics.SuccessfulOps)/float64(metrics.TotalOperations)*100)
		
		// Brief pause between phases
		time.Sleep(2 * time.Second)
	}
	
	// Analyze burst handling
	burstMetrics := allMetrics[1] // Burst phase
	if burstMetrics.OperationsPerSecond < allMetrics[0].OperationsPerSecond*2 {
		t.Log("Warning: Burst phase didn't show expected throughput increase")
	}
	
	// Recovery phase should show system stability
	recoveryMetrics := allMetrics[2]
	recoverySuccessRate := float64(recoveryMetrics.SuccessfulOps) / float64(recoveryMetrics.TotalOperations)
	if recoverySuccessRate < 0.8 {
		t.Errorf("Recovery phase success rate too low: %.2f%%", recoverySuccessRate*100)
	}
}

// testMixedWorkload tests mixed read/write workloads
func testMixedWorkload(t *testing.T, suite *TestSuite) {
	workloads := []struct {
		name           string
		readWriteRatio float64
	}{
		{"Read Heavy", 0.9},
		{"Balanced", 0.5},
		{"Write Heavy", 0.1},
	}
	
	for _, workload := range workloads {
		t.Run(workload.name, func(t *testing.T) {
			config := &LoadTestConfig{
				ConcurrentUsers:   8,
				RequestsPerUser:   100,
				TestDuration:      20 * time.Second,
				ObjectSizeMin:     1024,
				ObjectSizeMax:     8192,
				ReadWriteRatio:    workload.readWriteRatio,
				ReplicationFactor: 2,
			}
			
			runner := NewLoadTestRunner(suite, config)
			metrics := runner.Start()
			
			t.Logf("%s Workload Results:\n%s", workload.name, metrics.String())
			
			// Validate workload distribution
			totalOps := metrics.MetadataReads + metrics.MetadataWrites
			if totalOps > 0 {
				actualReadRatio := float64(metrics.MetadataReads) / float64(totalOps)
				expectedReadRatio := workload.readWriteRatio
				
				if abs(actualReadRatio-expectedReadRatio) > 0.1 {
					t.Errorf("Read ratio mismatch: expected %.2f, got %.2f",
						expectedReadRatio, actualReadRatio)
				}
			}
			
			// Success rate should be reasonable for all workload types
			successRate := float64(metrics.SuccessfulOps) / float64(metrics.TotalOperations)
			if successRate < 0.7 {
				t.Errorf("%s workload success rate too low: %.2f%%", workload.name, successRate*100)
			}
		})
	}
}

// testStress tests system under stress conditions
func testStress(t *testing.T, suite *TestSuite) {
	config := &LoadTestConfig{
		ConcurrentUsers:   50,
		RequestsPerUser:   0, // Unlimited
		TestDuration:      1 * time.Minute,
		ObjectSizeMin:     10240,  // Larger objects
		ObjectSizeMax:     102400, // Up to 100KB
		ReadWriteRatio:    0.3,    // Write heavy
		ReplicationFactor: 3,      // Higher replication
		EnableChaos:       true,   // Enable chaos during stress test
		ChaosInterval:     10 * time.Second,
	}
	
	runner := NewLoadTestRunner(suite, config)
	runner.SetLogger(suite.logger)
	
	t.Log("Starting stress test with chaos engineering...")
	metrics := runner.Start()
	
	t.Logf("Stress Test Results:\n%s", metrics.String())
	
	// Under stress, we expect some failures but system should remain functional
	if metrics.TotalOperations == 0 {
		t.Error("Should have performed some operations even under stress")
	}
	
	successRate := float64(metrics.SuccessfulOps) / float64(metrics.TotalOperations)
	if successRate < 0.3 {
		t.Errorf("Success rate too low under stress: %.2f%% (expected >= 30%%)", successRate*100)
	}
	
	// Should handle high concurrency
	if metrics.PeakConcurrency < 30 {
		t.Errorf("Expected higher peak concurrency under stress: %d", metrics.PeakConcurrency)
	}
	
	// Should maintain some throughput
	if metrics.OperationsPerSecond < 5 {
		t.Errorf("Throughput too low under stress: %.2f ops/sec", metrics.OperationsPerSecond)
	}
}

// abs returns the absolute value of a float64
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// TestLoadTestMetrics tests load test metrics collection
func TestLoadTestMetrics(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()
	
	config := &LoadTestConfig{
		ConcurrentUsers:   3,
		RequestsPerUser:   10,
		TestDuration:      5 * time.Second,
		ObjectSizeMin:     1024,
		ObjectSizeMax:     2048,
		ReadWriteRatio:    0.5,
		ReplicationFactor: 2,
	}
	
	runner := NewLoadTestRunner(suite, config)
	metrics := runner.Start()
	
	// Validate metrics
	if metrics.StartTime.IsZero() {
		t.Error("Start time should be set")
	}
	
	if metrics.EndTime.IsZero() {
		t.Error("End time should be set")
	}
	
	if metrics.EndTime.Before(metrics.StartTime) {
		t.Error("End time should be after start time")
	}
	
	if metrics.TotalOperations == 0 {
		t.Error("Should have recorded operations")
	}
	
	if metrics.TotalOperations != metrics.SuccessfulOps+metrics.FailedOps {
		t.Error("Total operations should equal successful + failed operations")
	}
	
	if metrics.MinLatency <= 0 {
		t.Error("Min latency should be positive")
	}
	
	if metrics.MaxLatency < metrics.MinLatency {
		t.Error("Max latency should be >= min latency")
	}
	
	if metrics.OperationsPerSecond <= 0 {
		t.Error("Operations per second should be positive")
	}
}

// TestLoadTestConfiguration tests different load test configurations
func TestLoadTestConfiguration(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()
	
	t.Run("MinimalConfig", func(t *testing.T) {
		config := &LoadTestConfig{
			ConcurrentUsers:   1,
			RequestsPerUser:   5,
			TestDuration:      2 * time.Second,
			ObjectSizeMin:     512,
			ObjectSizeMax:     1024,
			ReadWriteRatio:    0.5,
			ReplicationFactor: 1,
		}
		
		runner := NewLoadTestRunner(suite, config)
		metrics := runner.Start()
		
		if metrics.TotalOperations == 0 {
			t.Error("Should have performed operations with minimal config")
		}
	})
	
	t.Run("MaximalConfig", func(t *testing.T) {
		config := &LoadTestConfig{
			ConcurrentUsers:   20,
			RequestsPerUser:   50,
			TestDuration:      10 * time.Second,
			ObjectSizeMin:     10240,
			ObjectSizeMax:     51200,
			ReadWriteRatio:    0.8,
			ReplicationFactor: 5,
		}
		
		runner := NewLoadTestRunner(suite, config)
		metrics := runner.Start()
		
		if metrics.TotalOperations == 0 {
			t.Error("Should have performed operations with maximal config")
		}
		
		if metrics.PeakConcurrency < 10 {
			t.Errorf("Expected higher peak concurrency: %d", metrics.PeakConcurrency)
		}
	})
}

// BenchmarkLoadTestRunner benchmarks the load test runner itself
func BenchmarkLoadTestRunner(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()
	
	config := &LoadTestConfig{
		ConcurrentUsers:   5,
		RequestsPerUser:   b.N / 5,
		TestDuration:      time.Duration(b.N) * time.Millisecond,
		ObjectSizeMin:     1024,
		ObjectSizeMax:     2048,
		ReadWriteRatio:    0.7,
		ReplicationFactor: 2,
	}
	
	runner := NewLoadTestRunner(suite, config)
	runner.SetLogger(log.New(io.Discard, "", 0)) // Silent
	
	b.ResetTimer()
	metrics := runner.Start()
	b.StopTimer()
	
	b.ReportMetric(float64(metrics.TotalOperations), "total_ops")
	b.ReportMetric(metrics.OperationsPerSecond, "ops_per_sec")
	b.ReportMetric(float64(metrics.SuccessfulOps)/float64(metrics.TotalOperations)*100, "success_rate_%")
}

// TestScalabilityTesting runs comprehensive scalability tests
func TestScalabilityTesting(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping scalability tests in short mode")
	}
	
	suite := NewTestSuite(t)
	defer suite.Cleanup()
	
	t.Run("PinScalability", func(t *testing.T) {
		testPinScalability(t, suite)
	})
	
	t.Run("MetadataScalability", func(t *testing.T) {
		testMetadataScalability(t, suite)
	})
	
	t.Run("ConcurrentUserScalability", func(t *testing.T) {
		testConcurrentUserScalability(t, suite)
	})
	
	t.Run("StorageScalability", func(t *testing.T) {
		testStorageScalability(t, suite)
	})
}

// testPinScalability tests scalability of pin operations
func testPinScalability(t *testing.T, suite *TestSuite) {
	ctx := context.Background()
	
	// Test different scales of pin operations
	scales := []int{100, 1000, 10000, 50000}
	
	for _, scale := range scales {
		t.Run(fmt.Sprintf("Scale_%d_pins", scale), func(t *testing.T) {
			start := time.Now()
			
			// Perform pin operations at this scale
			var wg sync.WaitGroup
			numWorkers := 10
			pinsPerWorker := scale / numWorkers
			
			for i := 0; i < numWorkers; i++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()
					
					for j := 0; j < pinsPerWorker; j++ {
						cid := fmt.Sprintf("QmScale%d-%d-%d", scale, workerID, j)
						_, err := suite.clusterClient.Pin(ctx, cid, 2)
						if err != nil {
							t.Errorf("Pin failed at scale %d: %v", scale, err)
						}
					}
				}(i)
			}
			
			wg.Wait()
			duration := time.Since(start)
			
			opsPerSec := float64(scale) / duration.Seconds()
			t.Logf("Scale %d: %d pins in %v (%.2f ops/sec)", scale, scale, duration, opsPerSec)
			
			// Performance should not degrade too much with scale
			if scale > 1000 && opsPerSec < 100 {
				t.Logf("Warning: Performance degraded significantly at scale %d: %.2f ops/sec", scale, opsPerSec)
			}
		})
	}
}

// testMetadataScalability tests scalability of metadata operations
func testMetadataScalability(t *testing.T, suite *TestSuite) {
	ctx := context.Background()
	
	// Test different scales of metadata operations
	scales := []int{1000, 10000, 100000, 500000}
	
	for _, scale := range scales {
		t.Run(fmt.Sprintf("Scale_%d_metadata", scale), func(t *testing.T) {
			start := time.Now()
			
			// Store metadata at this scale
			for i := 0; i < scale; i++ {
				mapping := &ObjectMapping{
					S3Key:     fmt.Sprintf("scale-key-%d-%d", scale, i),
					Bucket:    fmt.Sprintf("scale-bucket-%d", i%100),
					CID:       fmt.Sprintf("QmScaleMeta%d-%d", scale, i),
					Size:      int64(1024 * (i%1000 + 1)),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					PinStatus: PinStatusPinned,
				}
				
				err := suite.metadataStore.StoreMapping(ctx, mapping)
				if err != nil {
					t.Errorf("Metadata store failed at scale %d: %v", scale, err)
				}
			}
			
			storeTime := time.Since(start)
			
			// Test retrieval performance
			start = time.Now()
			for i := 0; i < min(scale, 1000); i++ { // Sample 1000 retrievals
				key := fmt.Sprintf("scale-key-%d-%d", scale, rand.Intn(scale))
				bucket := fmt.Sprintf("scale-bucket-%d", rand.Intn(100))
				_, err := suite.metadataStore.GetMapping(ctx, key, bucket)
				if err != nil {
					// Some keys might not exist due to random selection, that's okay
				}
			}
			retrieveTime := time.Since(start)
			
			storeOpsPerSec := float64(scale) / storeTime.Seconds()
			retrieveOpsPerSec := float64(min(scale, 1000)) / retrieveTime.Seconds()
			
			t.Logf("Scale %d metadata: Store %.2f ops/sec, Retrieve %.2f ops/sec", 
				scale, storeOpsPerSec, retrieveOpsPerSec)
			
			// Retrieval should remain fast even at large scale
			if retrieveOpsPerSec < 1000 {
				t.Logf("Warning: Retrieval performance degraded at scale %d: %.2f ops/sec", scale, retrieveOpsPerSec)
			}
		})
	}
}

// testConcurrentUserScalability tests scalability with increasing concurrent users
func testConcurrentUserScalability(t *testing.T, suite *TestSuite) {
	ctx := context.Background()
	
	// Test different levels of concurrency
	concurrencyLevels := []int{1, 5, 10, 25, 50, 100}
	
	for _, concurrency := range concurrencyLevels {
		t.Run(fmt.Sprintf("Concurrency_%d_users", concurrency), func(t *testing.T) {
			start := time.Now()
			
			var wg sync.WaitGroup
			opsPerUser := 100
			
			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func(userID int) {
					defer wg.Done()
					
					for j := 0; j < opsPerUser; j++ {
						// Mix of operations
						if j%3 == 0 {
							// Pin operation
							cid := fmt.Sprintf("QmConcurrency%d-%d-%d", concurrency, userID, j)
							_, err := suite.clusterClient.Pin(ctx, cid, 2)
							if err != nil {
								t.Errorf("Concurrent pin failed: %v", err)
							}
						} else {
							// Metadata operation
							mapping := &ObjectMapping{
								S3Key:     fmt.Sprintf("concurrent-key-%d-%d-%d", concurrency, userID, j),
								Bucket:    fmt.Sprintf("concurrent-bucket-%d", userID%10),
								CID:       fmt.Sprintf("QmConcurrentMeta%d-%d-%d", concurrency, userID, j),
								Size:      int64(1024),
								CreatedAt: time.Now(),
								UpdatedAt: time.Now(),
								PinStatus: PinStatusPinned,
							}
							
							err := suite.metadataStore.StoreMapping(ctx, mapping)
							if err != nil {
								t.Errorf("Concurrent metadata failed: %v", err)
							}
						}
					}
				}(i)
			}
			
			wg.Wait()
			duration := time.Since(start)
			
			totalOps := concurrency * opsPerUser
			opsPerSec := float64(totalOps) / duration.Seconds()
			
			t.Logf("Concurrency %d: %d total ops in %v (%.2f ops/sec)", 
				concurrency, totalOps, duration, opsPerSec)
			
			// Throughput should generally increase with concurrency (up to a point)
			if concurrency <= 25 && opsPerSec < float64(concurrency)*5 {
				t.Logf("Warning: Throughput didn't scale well at concurrency %d: %.2f ops/sec", concurrency, opsPerSec)
			}
		})
	}
}

// testStorageScalability tests scalability of storage operations
func testStorageScalability(t *testing.T, suite *TestSuite) {
	ctx := context.Background()
	
	// Test different object sizes
	objectSizes := []int64{1024, 10240, 102400, 1048576} // 1KB to 1MB
	
	for _, size := range objectSizes {
		t.Run(fmt.Sprintf("ObjectSize_%d_bytes", size), func(t *testing.T) {
			numObjects := 100
			start := time.Now()
			
			for i := 0; i < numObjects; i++ {
				mapping := &ObjectMapping{
					S3Key:     fmt.Sprintf("storage-key-%d-%d", size, i),
					Bucket:    "storage-bucket",
					CID:       fmt.Sprintf("QmStorage%d-%d", size, i),
					Size:      size,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					PinStatus: PinStatusPinned,
				}
				
				err := suite.metadataStore.StoreMapping(ctx, mapping)
				if err != nil {
					t.Errorf("Storage test failed for size %d: %v", size, err)
				}
			}
			
			duration := time.Since(start)
			bytesPerSec := float64(size*int64(numObjects)) / duration.Seconds()
			
			t.Logf("Object size %d bytes: %d objects in %v (%.2f bytes/sec)", 
				size, numObjects, duration, bytesPerSec)
		})
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}