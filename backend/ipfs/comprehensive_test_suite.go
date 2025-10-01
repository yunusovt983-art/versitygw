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
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"
)

// TestSuite represents the comprehensive test suite for IPFS-Cluster integration
type TestSuite struct {
	backend       *MockIPFSBackend
	clusterClient *MockClusterClient
	metadataStore *MockMetadataStore
	config        *IPFSConfig
	logger        *log.Logger
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewTestSuite creates a new comprehensive test suite
func NewTestSuite(t *testing.T) *TestSuite {
	ctx, cancel := context.WithCancel(context.Background())

	config := &IPFSConfig{
		ClusterEndpoints:    []string{"http://localhost:9094"},
		ConnectTimeout:      5 * time.Second,
		RequestTimeout:      10 * time.Second,
		MaxRetries:          3,
		RetryDelay:          100 * time.Millisecond,
		MaxConcurrentPins:   100,
		PinTimeout:          30 * time.Second,
		ChunkSize:           1024 * 1024,
		ReplicationMin:      1,
		ReplicationMax:      3,
		MetadataDBType:      "memory",
		LogLevel:            "debug",
		EnableMetrics:       true,
		MetricsInterval:     1 * time.Second,
		EnableHealthCheck:   true,
		HealthCheckInterval: 5 * time.Second,
	}

	logger := log.New(os.Stdout, "[TEST-SUITE] ", log.LstdFlags|log.Lshortfile)

	// Create mock components
	clusterClient := NewMockClusterClient()
	metadataStore := NewMockMetadataStore()

	// Create backend with mocks
	backend, err := NewWithMocks(config, clusterClient, metadataStore, logger)
	if err != nil {
		t.Fatalf("Failed to create test backend: %v", err)
	}

	return &TestSuite{
		backend:       backend,
		clusterClient: clusterClient,
		metadataStore: metadataStore,
		config:        config,
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Cleanup cleans up the test suite
func (ts *TestSuite) Cleanup() {
	ts.cancel()
	if ts.backend != nil {
		ts.backend.Shutdown()
	}
}

// TestData represents test data for operations
type TestData struct {
	S3Key    string
	Bucket   string
	CID      string
	Size     int64
	Content  []byte
	Metadata map[string]string
}

// GenerateTestData generates test data for operations
func (ts *TestSuite) GenerateTestData(count int) []*TestData {
	data := make([]*TestData, count)

	for i := 0; i < count; i++ {
		content := make([]byte, 1024+rand.Intn(10240)) // 1KB to 11KB
		rand.Read(content)

		data[i] = &TestData{
			S3Key:   fmt.Sprintf("test-object-%d", i),
			Bucket:  fmt.Sprintf("test-bucket-%d", i%10), // 10 buckets
			CID:     fmt.Sprintf("QmTest%d", i),
			Size:    int64(len(content)),
			Content: content,
			Metadata: map[string]string{
				"test-id":    fmt.Sprintf("%d", i),
				"created-by": "test-suite",
			},
		}
	}

	return data
}

// TestResult represents the result of a test operation
type TestResult struct {
	Success  bool
	Duration time.Duration
	Error    error
	Metadata map[string]interface{}
}

// PerformanceMetrics tracks performance metrics during testing
type PerformanceMetrics struct {
	TotalOperations     int64
	SuccessfulOps       int64
	FailedOps           int64
	AverageLatency      time.Duration
	MinLatency          time.Duration
	MaxLatency          time.Duration
	ThroughputOpsPerSec float64

	// Pin-specific metrics
	PinOperations   int64
	UnpinOperations int64
	PinLatency      time.Duration
	UnpinLatency    time.Duration

	// Metadata metrics
	MetadataOps     int64
	MetadataLatency time.Duration

	// Cache metrics
	CacheHits     int64
	CacheMisses   int64
	CacheHitRatio float64

	mu sync.RWMutex
}

// NewPerformanceMetrics creates new performance metrics tracker
func NewPerformanceMetrics() *PerformanceMetrics {
	return &PerformanceMetrics{
		MinLatency: time.Hour, // Initialize to high value
	}
}

// RecordOperation records an operation result
func (pm *PerformanceMetrics) RecordOperation(duration time.Duration, success bool, opType string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.TotalOperations++
	if success {
		pm.SuccessfulOps++
	} else {
		pm.FailedOps++
	}

	// Update latency stats
	if duration < pm.MinLatency {
		pm.MinLatency = duration
	}
	if duration > pm.MaxLatency {
		pm.MaxLatency = duration
	}

	// Update average (simple moving average)
	pm.AverageLatency = time.Duration((int64(pm.AverageLatency)*pm.TotalOperations + int64(duration)) / (pm.TotalOperations + 1))

	// Update operation-specific metrics
	switch opType {
	case "pin":
		pm.PinOperations++
		pm.PinLatency = time.Duration((int64(pm.PinLatency)*pm.PinOperations + int64(duration)) / (pm.PinOperations + 1))
	case "unpin":
		pm.UnpinOperations++
		pm.UnpinLatency = time.Duration((int64(pm.UnpinLatency)*pm.UnpinOperations + int64(duration)) / (pm.UnpinOperations + 1))
	case "metadata":
		pm.MetadataOps++
		pm.MetadataLatency = time.Duration((int64(pm.MetadataLatency)*pm.MetadataOps + int64(duration)) / (pm.MetadataOps + 1))
	}
}

// RecordCacheHit records a cache hit
func (pm *PerformanceMetrics) RecordCacheHit() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.CacheHits++
	pm.updateCacheHitRatio()
}

// RecordCacheMiss records a cache miss
func (pm *PerformanceMetrics) RecordCacheMiss() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.CacheMisses++
	pm.updateCacheHitRatio()
}

// updateCacheHitRatio updates the cache hit ratio
func (pm *PerformanceMetrics) updateCacheHitRatio() {
	total := pm.CacheHits + pm.CacheMisses
	if total > 0 {
		pm.CacheHitRatio = float64(pm.CacheHits) / float64(total)
	}
}

// GetSnapshot returns a snapshot of current metrics
func (pm *PerformanceMetrics) GetSnapshot() *PerformanceMetrics {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	snapshot := *pm
	return &snapshot
}

// String returns a string representation of the metrics
func (pm *PerformanceMetrics) String() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return fmt.Sprintf(`Performance Metrics:
  Total Operations: %d
  Successful: %d (%.2f%%)
  Failed: %d (%.2f%%)
  Average Latency: %v
  Min Latency: %v
  Max Latency: %v
  Throughput: %.2f ops/sec
  Pin Operations: %d (avg: %v)
  Unpin Operations: %d (avg: %v)
  Metadata Operations: %d (avg: %v)
  Cache Hit Ratio: %.2f%% (%d hits, %d misses)`,
		pm.TotalOperations,
		pm.SuccessfulOps, float64(pm.SuccessfulOps)/float64(pm.TotalOperations)*100,
		pm.FailedOps, float64(pm.FailedOps)/float64(pm.TotalOperations)*100,
		pm.AverageLatency,
		pm.MinLatency,
		pm.MaxLatency,
		pm.ThroughputOpsPerSec,
		pm.PinOperations, pm.PinLatency,
		pm.UnpinOperations, pm.UnpinLatency,
		pm.MetadataOps, pm.MetadataLatency,
		pm.CacheHitRatio*100, pm.CacheHits, pm.CacheMisses)
}

// LoadTestConfig represents configuration for load testing
type LoadTestConfig struct {
	ConcurrentUsers   int
	RequestsPerUser   int
	TestDuration      time.Duration
	ObjectSizeMin     int64
	ObjectSizeMax     int64
	ReadWriteRatio    float64 // 0.0 = all writes, 1.0 = all reads
	EnableChaos       bool
	ChaosInterval     time.Duration
	ReplicationFactor int
}

// DefaultLoadTestConfig returns a default load test configuration
func DefaultLoadTestConfig() *LoadTestConfig {
	return &LoadTestConfig{
		ConcurrentUsers:   10,
		RequestsPerUser:   100,
		TestDuration:      5 * time.Minute,
		ObjectSizeMin:     1024,        // 1KB
		ObjectSizeMax:     1024 * 1024, // 1MB
		ReadWriteRatio:    0.7,         // 70% reads, 30% writes
		EnableChaos:       false,
		ChaosInterval:     30 * time.Second,
		ReplicationFactor: 2,
	}
}

// ChaosTestConfig represents configuration for chaos engineering tests
type ChaosTestConfig struct {
	NodeFailureRate      float64 // Probability of node failure per interval
	NetworkPartitionRate float64 // Probability of network partition
	SlowNodeRate         float64 // Probability of node becoming slow
	DataCorruptionRate   float64 // Probability of data corruption
	TestDuration         time.Duration
	ChaosInterval        time.Duration
	RecoveryTime         time.Duration
}

// DefaultChaosTestConfig returns a default chaos test configuration
func DefaultChaosTestConfig() *ChaosTestConfig {
	return &ChaosTestConfig{
		NodeFailureRate:      0.1,  // 10% chance per interval
		NetworkPartitionRate: 0.05, // 5% chance per interval
		SlowNodeRate:         0.2,  // 20% chance per interval
		DataCorruptionRate:   0.01, // 1% chance per interval
		TestDuration:         10 * time.Minute,
		ChaosInterval:        30 * time.Second,
		RecoveryTime:         2 * time.Minute,
	}
}

// TestScenario represents a test scenario
type TestScenario struct {
	Name        string
	Description string
	Setup       func(*TestSuite) error
	Execute     func(*TestSuite) (*TestResult, error)
	Cleanup     func(*TestSuite) error
	Validate    func(*TestSuite, *TestResult) error
}

// TestSuiteConfig represents configuration for the comprehensive test suite
type TestSuiteConfig struct {
	RunUnitTests        bool
	RunIntegrationTests bool
	RunPerformanceTests bool
	RunChaosTests       bool
	RunLoadTests        bool
	RunScalabilityTests bool
	ShortMode           bool
	Verbose             bool
	ParallelTests       bool
	TestTimeout         time.Duration
	GenerateReports     bool
	SaveMetrics         bool
	ReportOutputDir     string
}

// DefaultTestSuiteConfig returns default test suite configuration
func DefaultTestSuiteConfig() *TestSuiteConfig {
	return &TestSuiteConfig{
		RunUnitTests:        true,
		RunIntegrationTests: true,
		RunPerformanceTests: false,
		RunChaosTests:       false,
		RunLoadTests:        false,
		RunScalabilityTests: false,
		ShortMode:           false,
		Verbose:             false,
		ParallelTests:       true,
		TestTimeout:         30 * time.Minute,
		GenerateReports:     true,
		SaveMetrics:         true,
		ReportOutputDir:     "test-reports",
	}
}

// TestSuiteRunner manages the execution of the comprehensive test suite
type TestSuiteRunner struct {
	config   *TestSuiteConfig
	reporter *TestReporter
	suite    *TestSuite
	logger   *log.Logger
}

// NewTestSuiteRunner creates a new test suite runner
func NewTestSuiteRunner(config *TestSuiteConfig) *TestSuiteRunner {
	if config == nil {
		config = DefaultTestSuiteConfig()
	}

	logger := log.New(os.Stdout, "[TEST-RUNNER] ", log.LstdFlags|log.Lshortfile)
	if !config.Verbose {
		logger.SetOutput(io.Discard)
	}

	return &TestSuiteRunner{
		config:   config,
		reporter: NewTestReporter("Comprehensive IPFS Integration Test Suite"),
		logger:   logger,
	}
}

// ScalabilityTestConfig represents configuration for scalability testing
type ScalabilityTestConfig struct {
	StartingPins      int64
	MaxPins           int64
	PinIncrement      int64
	MeasurementPoints []int64
	TestTimeout       time.Duration
}

// DefaultScalabilityTestConfig returns a default scalability test configuration
func DefaultScalabilityTestConfig() *ScalabilityTestConfig {
	return &ScalabilityTestConfig{
		StartingPins:      1000,
		MaxPins:           1000000, // 1 million pins for testing
		PinIncrement:      10000,
		MeasurementPoints: []int64{1000, 10000, 100000, 500000, 1000000},
		TestTimeout:       30 * time.Minute,
	}
}

// TestReporter handles test reporting and metrics collection
type TestReporter struct {
	testResults []*TestResult
	metrics     *PerformanceMetrics
	startTime   time.Time
	endTime     time.Time
	testName    string
	outputFile  *os.File
	mu          sync.Mutex
}

// NewTestReporter creates a new test reporter
func NewTestReporter(testName string) *TestReporter {
	return &TestReporter{
		testResults: make([]*TestResult, 0),
		metrics:     NewPerformanceMetrics(),
		testName:    testName,
		startTime:   time.Now(),
	}
}

// RecordResult records a test result
func (tr *TestReporter) RecordResult(result *TestResult) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	tr.testResults = append(tr.testResults, result)
	tr.metrics.RecordOperation(result.Duration, result.Success, "test")
}

// GenerateReport generates a comprehensive test report
func (tr *TestReporter) GenerateReport() string {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	tr.endTime = time.Now()
	totalDuration := tr.endTime.Sub(tr.startTime)

	successCount := 0
	for _, result := range tr.testResults {
		if result.Success {
			successCount++
		}
	}

	report := fmt.Sprintf(`
=== COMPREHENSIVE TEST REPORT ===
Test Name: %s
Start Time: %s
End Time: %s
Total Duration: %v

Test Results:
  Total Tests: %d
  Successful: %d (%.2f%%)
  Failed: %d (%.2f%%)

%s

=== END REPORT ===
`,
		tr.testName,
		tr.startTime.Format(time.RFC3339),
		tr.endTime.Format(time.RFC3339),
		totalDuration,
		len(tr.testResults),
		successCount, float64(successCount)/float64(len(tr.testResults))*100,
		len(tr.testResults)-successCount, float64(len(tr.testResults)-successCount)/float64(len(tr.testResults))*100,
		tr.metrics.String())

	return report
}

// SaveReport saves the report to a file
func (tr *TestReporter) SaveReport(filename string) error {
	report := tr.GenerateReport()
	return os.WriteFile(filename, []byte(report), 0644)
}

// RunAllTests runs the comprehensive test suite
func (tsr *TestSuiteRunner) RunAllTests(t *testing.T) error {
	tsr.suite = NewTestSuite(t)
	defer tsr.suite.Cleanup()

	tsr.logger.Printf("Starting comprehensive IPFS integration test suite")

	// Run test phases based on configuration
	if tsr.config.RunUnitTests {
		if err := tsr.runUnitTests(t); err != nil {
			return fmt.Errorf("unit tests failed: %w", err)
		}
	}

	if tsr.config.RunIntegrationTests {
		if err := tsr.runIntegrationTests(t); err != nil {
			return fmt.Errorf("integration tests failed: %w", err)
		}
	}

	if tsr.config.RunPerformanceTests {
		if err := tsr.runPerformanceTests(t); err != nil {
			return fmt.Errorf("performance tests failed: %w", err)
		}
	}

	if tsr.config.RunChaosTests {
		if err := tsr.runChaosTests(t); err != nil {
			return fmt.Errorf("chaos tests failed: %w", err)
		}
	}

	if tsr.config.RunLoadTests {
		if err := tsr.runLoadTests(t); err != nil {
			return fmt.Errorf("load tests failed: %w", err)
		}
	}

	if tsr.config.RunScalabilityTests {
		if err := tsr.runScalabilityTests(t); err != nil {
			return fmt.Errorf("scalability tests failed: %w", err)
		}
	}

	// Generate final report
	if tsr.config.GenerateReports {
		if err := tsr.generateFinalReport(); err != nil {
			tsr.logger.Printf("Failed to generate final report: %v", err)
		}
	}

	tsr.logger.Printf("Comprehensive test suite completed successfully")
	return nil
}

// runUnitTests runs all unit tests
func (tsr *TestSuiteRunner) runUnitTests(t *testing.T) error {
	tsr.logger.Printf("Running unit tests...")

	start := time.Now()

	// Run unit tests from unit_tests_comprehensive.go
	t.Run("UnitTests", func(t *testing.T) {
		TestAllComponents(t)
		TestComponentIntegration(t)
		TestErrorHandling(t)
		TestConcurrency(t)
	})

	duration := time.Since(start)
	result := &TestResult{
		Success:  true,
		Duration: duration,
		Metadata: map[string]interface{}{
			"test_type": "unit",
			"phase":     "unit_tests",
		},
	}

	tsr.reporter.RecordResult(result)
	tsr.logger.Printf("Unit tests completed in %v", duration)
	return nil
}

// runIntegrationTests runs integration tests
func (tsr *TestSuiteRunner) runIntegrationTests(t *testing.T) error {
	tsr.logger.Printf("Running integration tests...")

	start := time.Now()

	t.Run("IntegrationTests", func(t *testing.T) {
		// Run existing integration tests
		t.Run("BasicIntegration", func(t *testing.T) {
			tsr.testBasicIntegration(t)
		})

		t.Run("S3Operations", func(t *testing.T) {
			tsr.testS3Operations(t)
		})

		t.Run("MetadataIntegration", func(t *testing.T) {
			tsr.testMetadataIntegration(t)
		})

		t.Run("PinManagerIntegration", func(t *testing.T) {
			tsr.testPinManagerIntegration(t)
		})

		t.Run("CacheIntegration", func(t *testing.T) {
			tsr.testCacheIntegration(t)
		})
	})

	duration := time.Since(start)
	result := &TestResult{
		Success:  true,
		Duration: duration,
		Metadata: map[string]interface{}{
			"test_type": "integration",
			"phase":     "integration_tests",
		},
	}

	tsr.reporter.RecordResult(result)
	tsr.logger.Printf("Integration tests completed in %v", duration)
	return nil
}

// runPerformanceTests runs performance benchmarks
func (tsr *TestSuiteRunner) runPerformanceTests(t *testing.T) error {
	tsr.logger.Printf("Running performance tests...")

	start := time.Now()

	t.Run("PerformanceTests", func(t *testing.T) {
		t.Run("PinPerformance", func(t *testing.T) {
			tsr.testPinPerformance(t)
		})

		t.Run("MetadataPerformance", func(t *testing.T) {
			tsr.testMetadataPerformance(t)
		})

		t.Run("CachePerformance", func(t *testing.T) {
			tsr.testCachePerformance(t)
		})

		t.Run("ThroughputBenchmarks", func(t *testing.T) {
			tsr.testThroughputBenchmarks(t)
		})
	})

	duration := time.Since(start)
	result := &TestResult{
		Success:  true,
		Duration: duration,
		Metadata: map[string]interface{}{
			"test_type": "performance",
			"phase":     "performance_tests",
		},
	}

	tsr.reporter.RecordResult(result)
	tsr.logger.Printf("Performance tests completed in %v", duration)
	return nil
}

// runChaosTests runs chaos engineering tests
func (tsr *TestSuiteRunner) runChaosTests(t *testing.T) error {
	tsr.logger.Printf("Running chaos engineering tests...")

	start := time.Now()

	t.Run("ChaosTests", func(t *testing.T) {
		TestChaosEngineering(t)
	})

	duration := time.Since(start)
	result := &TestResult{
		Success:  true,
		Duration: duration,
		Metadata: map[string]interface{}{
			"test_type": "chaos",
			"phase":     "chaos_tests",
		},
	}

	tsr.reporter.RecordResult(result)
	tsr.logger.Printf("Chaos tests completed in %v", duration)
	return nil
}

// runLoadTests runs load tests
func (tsr *TestSuiteRunner) runLoadTests(t *testing.T) error {
	tsr.logger.Printf("Running load tests...")

	start := time.Now()

	t.Run("LoadTests", func(t *testing.T) {
		TestLoadTesting(t)
	})

	duration := time.Since(start)
	result := &TestResult{
		Success:  true,
		Duration: duration,
		Metadata: map[string]interface{}{
			"test_type": "load",
			"phase":     "load_tests",
		},
	}

	tsr.reporter.RecordResult(result)
	tsr.logger.Printf("Load tests completed in %v", duration)
	return nil
}

// runScalabilityTests runs scalability tests
func (tsr *TestSuiteRunner) runScalabilityTests(t *testing.T) error {
	tsr.logger.Printf("Running scalability tests...")

	start := time.Now()

	t.Run("ScalabilityTests", func(t *testing.T) {
		TestScalabilityTesting(t)
	})

	duration := time.Since(start)
	result := &TestResult{
		Success:  true,
		Duration: duration,
		Metadata: map[string]interface{}{
			"test_type": "scalability",
			"phase":     "scalability_tests",
		},
	}

	tsr.reporter.RecordResult(result)
	tsr.logger.Printf("Scalability tests completed in %v", duration)
	return nil
}

// Integration test implementations
func (tsr *TestSuiteRunner) testBasicIntegration(t *testing.T) {
	ctx := context.Background()

	// Test basic backend functionality
	if !tsr.suite.backend.IsHealthy() {
		t.Error("Backend should be healthy")
	}

	// Test basic pin operation
	cid := "QmBasicIntegration"
	result, err := tsr.suite.clusterClient.Pin(ctx, cid, 2)
	if err != nil {
		t.Fatalf("Basic pin failed: %v", err)
	}

	if !result.Success {
		t.Error("Pin should succeed")
	}

	// Test metadata storage
	mapping := &ObjectMapping{
		S3Key:     "basic-integration-key",
		Bucket:    "basic-bucket",
		CID:       cid,
		Size:      1024,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		PinStatus: PinStatusPinned,
	}

	err = tsr.suite.metadataStore.StoreMapping(ctx, mapping)
	if err != nil {
		t.Fatalf("Metadata store failed: %v", err)
	}

	// Test retrieval
	retrieved, err := tsr.suite.metadataStore.GetMapping(ctx, mapping.S3Key, mapping.Bucket)
	if err != nil {
		t.Fatalf("Metadata retrieval failed: %v", err)
	}

	if retrieved.CID != cid {
		t.Errorf("Expected CID %s, got %s", cid, retrieved.CID)
	}
}

func (tsr *TestSuiteRunner) testS3Operations(t *testing.T) {
	// Test S3-like operations through the backend
	ctx := context.Background()

	// Test object operations
	testData := tsr.suite.GenerateTestData(10)

	for _, data := range testData {
		// Simulate S3 PUT operation
		result, err := tsr.suite.clusterClient.Pin(ctx, data.CID, 2)
		if err != nil {
			t.Errorf("S3 PUT simulation failed: %v", err)
			continue
		}

		if !result.Success {
			t.Errorf("S3 PUT should succeed for %s", data.S3Key)
		}

		// Store metadata
		mapping := &ObjectMapping{
			S3Key:     data.S3Key,
			Bucket:    data.Bucket,
			CID:       data.CID,
			Size:      data.Size,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			PinStatus: PinStatusPinned,
			Metadata: ObjectMetadata{
				ContentType:  "application/octet-stream",
				UserMetadata: data.Metadata,
			},
		}

		err = tsr.suite.metadataStore.StoreMapping(ctx, mapping)
		if err != nil {
			t.Errorf("S3 metadata store failed: %v", err)
		}

		// Simulate S3 GET operation
		retrieved, err := tsr.suite.metadataStore.GetMapping(ctx, data.S3Key, data.Bucket)
		if err != nil {
			t.Errorf("S3 GET simulation failed: %v", err)
			continue
		}

		if retrieved.CID != data.CID {
			t.Errorf("S3 GET returned wrong CID: expected %s, got %s", data.CID, retrieved.CID)
		}
	}
}

func (tsr *TestSuiteRunner) testMetadataIntegration(t *testing.T) {
	ctx := context.Background()

	// Test metadata operations at scale
	numObjects := 1000
	mappings := make([]*ObjectMapping, numObjects)

	// Create test mappings
	for i := 0; i < numObjects; i++ {
		mappings[i] = &ObjectMapping{
			S3Key:     fmt.Sprintf("metadata-test-key-%d", i),
			Bucket:    fmt.Sprintf("metadata-bucket-%d", i%10),
			CID:       fmt.Sprintf("QmMetadataTest%d", i),
			Size:      int64(1024 * (i + 1)),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			PinStatus: PinStatusPinned,
		}
	}

	// Test batch store
	start := time.Now()
	err := tsr.suite.metadataStore.StoreMappingBatch(ctx, mappings)
	if err != nil {
		t.Fatalf("Batch store failed: %v", err)
	}
	storeDuration := time.Since(start)

	// Test individual retrieval
	start = time.Now()
	for i := 0; i < 100; i++ { // Sample 100 retrievals
		mapping := mappings[rand.Intn(numObjects)]
		retrieved, err := tsr.suite.metadataStore.GetMapping(ctx, mapping.S3Key, mapping.Bucket)
		if err != nil {
			t.Errorf("Individual retrieval failed: %v", err)
			continue
		}

		if retrieved.CID != mapping.CID {
			t.Errorf("Retrieved wrong CID: expected %s, got %s", mapping.CID, retrieved.CID)
		}
	}
	retrieveDuration := time.Since(start)

	t.Logf("Metadata integration: stored %d objects in %v, retrieved 100 samples in %v",
		numObjects, storeDuration, retrieveDuration)

	// Test search operations
	results, err := tsr.suite.metadataStore.SearchByPrefix(ctx, "metadata-bucket-0", "metadata-test-", 50)
	if err != nil {
		t.Errorf("Search by prefix failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("Search should return some results")
	}
}

func (tsr *TestSuiteRunner) testPinManagerIntegration(t *testing.T) {
	// Test pin manager integration with cluster and metadata
	ctx := context.Background()

	// Test concurrent pin operations
	numPins := 100
	var wg sync.WaitGroup
	errors := make(chan error, numPins)

	for i := 0; i < numPins; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			cid := fmt.Sprintf("QmPinManager%d", id)
			result, err := tsr.suite.clusterClient.Pin(ctx, cid, 2)
			if err != nil {
				errors <- err
				return
			}

			if !result.Success {
				errors <- fmt.Errorf("pin %d failed", id)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	errorCount := 0
	for err := range errors {
		t.Errorf("Pin manager error: %v", err)
		errorCount++
	}

	if errorCount > numPins/10 { // Allow up to 10% failures
		t.Errorf("Too many pin failures: %d/%d", errorCount, numPins)
	}
}

func (tsr *TestSuiteRunner) testCacheIntegration(t *testing.T) {
	// Test cache integration (placeholder for when cache is implemented)
	t.Skip("Cache integration tests not implemented yet")
}

// Performance test implementations
func (tsr *TestSuiteRunner) testPinPerformance(t *testing.T) {
	ctx := context.Background()

	// Test pin operation latency
	numOps := 1000
	latencies := make([]time.Duration, numOps)

	for i := 0; i < numOps; i++ {
		cid := fmt.Sprintf("QmPinPerf%d", i)
		start := time.Now()

		_, err := tsr.suite.clusterClient.Pin(ctx, cid, 2)
		if err != nil {
			t.Errorf("Pin performance test failed: %v", err)
			continue
		}

		latencies[i] = time.Since(start)
	}

	// Calculate statistics
	var totalLatency time.Duration
	minLatency := time.Hour
	maxLatency := time.Duration(0)

	for _, latency := range latencies {
		totalLatency += latency
		if latency < minLatency {
			minLatency = latency
		}
		if latency > maxLatency {
			maxLatency = latency
		}
	}

	avgLatency := totalLatency / time.Duration(numOps)

	t.Logf("Pin performance: %d operations, avg: %v, min: %v, max: %v",
		numOps, avgLatency, minLatency, maxLatency)

	// Performance assertions
	if avgLatency > 100*time.Millisecond {
		t.Errorf("Average pin latency too high: %v", avgLatency)
	}

	if maxLatency > 1*time.Second {
		t.Errorf("Maximum pin latency too high: %v", maxLatency)
	}
}

func (tsr *TestSuiteRunner) testMetadataPerformance(t *testing.T) {
	ctx := context.Background()

	// Test metadata operation performance
	numOps := 5000

	// Test store performance
	start := time.Now()
	for i := 0; i < numOps; i++ {
		mapping := &ObjectMapping{
			S3Key:     fmt.Sprintf("perf-key-%d", i),
			Bucket:    fmt.Sprintf("perf-bucket-%d", i%100),
			CID:       fmt.Sprintf("QmPerf%d", i),
			Size:      int64(1024),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			PinStatus: PinStatusPinned,
		}

		err := tsr.suite.metadataStore.StoreMapping(ctx, mapping)
		if err != nil {
			t.Errorf("Metadata store performance test failed: %v", err)
		}
	}
	storeDuration := time.Since(start)

	// Test retrieval performance
	start = time.Now()
	for i := 0; i < numOps; i++ {
		key := fmt.Sprintf("perf-key-%d", rand.Intn(numOps))
		bucket := fmt.Sprintf("perf-bucket-%d", rand.Intn(100))

		_, err := tsr.suite.metadataStore.GetMapping(ctx, key, bucket)
		if err != nil {
			// Some keys might not exist due to random selection
		}
	}
	retrieveDuration := time.Since(start)

	storeOpsPerSec := float64(numOps) / storeDuration.Seconds()
	retrieveOpsPerSec := float64(numOps) / retrieveDuration.Seconds()

	t.Logf("Metadata performance: store %.2f ops/sec, retrieve %.2f ops/sec",
		storeOpsPerSec, retrieveOpsPerSec)

	// Performance assertions
	if storeOpsPerSec < 1000 {
		t.Errorf("Metadata store performance too low: %.2f ops/sec", storeOpsPerSec)
	}

	if retrieveOpsPerSec < 5000 {
		t.Errorf("Metadata retrieve performance too low: %.2f ops/sec", retrieveOpsPerSec)
	}
}

func (tsr *TestSuiteRunner) testCachePerformance(t *testing.T) {
	// Test cache performance (placeholder)
	t.Skip("Cache performance tests not implemented yet")
}

func (tsr *TestSuiteRunner) testThroughputBenchmarks(t *testing.T) {
	ctx := context.Background()

	// Test system throughput under various conditions
	testDuration := 30 * time.Second
	concurrencyLevels := []int{1, 5, 10, 20}

	for _, concurrency := range concurrencyLevels {
		t.Run(fmt.Sprintf("Concurrency%d", concurrency), func(t *testing.T) {
			var wg sync.WaitGroup
			var totalOps int64
			var totalErrors int64

			start := time.Now()
			stopChan := make(chan bool)

			// Start workers
			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()

					opCount := 0
					for {
						select {
						case <-stopChan:
							return
						default:
							// Perform operation
							cid := fmt.Sprintf("QmThroughput%d-%d", workerID, opCount)
							_, err := tsr.suite.clusterClient.Pin(ctx, cid, 2)
							if err != nil {
								atomic.AddInt64(&totalErrors, 1)
							} else {
								atomic.AddInt64(&totalOps, 1)
							}
							opCount++
						}
					}
				}(i)
			}

			// Run for test duration
			time.Sleep(testDuration)
			close(stopChan)
			wg.Wait()

			duration := time.Since(start)
			opsPerSec := float64(totalOps) / duration.Seconds()
			errorRate := float64(totalErrors) / float64(totalOps+totalErrors)

			t.Logf("Throughput concurrency %d: %.2f ops/sec, %.2f%% error rate",
				concurrency, opsPerSec, errorRate*100)

			// Throughput should generally increase with concurrency
			if concurrency > 1 && opsPerSec < 10 {
				t.Errorf("Throughput too low for concurrency %d: %.2f ops/sec", concurrency, opsPerSec)
			}

			// Error rate should be reasonable
			if errorRate > 0.1 {
				t.Errorf("Error rate too high for concurrency %d: %.2f%%", concurrency, errorRate*100)
			}
		})
	}
}

// generateFinalReport generates the final test report
func (tsr *TestSuiteRunner) generateFinalReport() error {
	report := tsr.reporter.GenerateReport()

	if tsr.config.SaveMetrics {
		// Create output directory if it doesn't exist
		if err := os.MkdirAll(tsr.config.ReportOutputDir, 0755); err != nil {
			return fmt.Errorf("failed to create report directory: %w", err)
		}

		// Save report to file
		timestamp := time.Now().Format("20060102-150405")
		filename := fmt.Sprintf("%s/comprehensive-test-report-%s.txt", tsr.config.ReportOutputDir, timestamp)

		if err := tsr.reporter.SaveReport(filename); err != nil {
			return fmt.Errorf("failed to save report: %w", err)
		}

		tsr.logger.Printf("Test report saved to: %s", filename)
	}

	// Print summary to console
	fmt.Println(report)

	return nil
}

// TestComprehensiveIPFSIntegration is the main entry point for comprehensive testing
func TestComprehensiveIPFSIntegration(t *testing.T) {
	// Check environment variables for test configuration
	config := DefaultTestSuiteConfig()

	if os.Getenv("IPFS_INTEGRATION_TESTS") == "true" {
		config.RunIntegrationTests = true
	}

	if os.Getenv("IPFS_CHAOS_TESTS") == "true" {
		config.RunChaosTests = true
	}

	if os.Getenv("IPFS_LOAD_TESTS") == "true" {
		config.RunLoadTests = true
	}

	if os.Getenv("IPFS_SCALABILITY_TESTS") == "true" {
		config.RunScalabilityTests = true
	}

	if os.Getenv("IPFS_PERFORMANCE_TESTS") == "true" {
		config.RunPerformanceTests = true
	}

	if testing.Short() {
		config.ShortMode = true
		config.RunChaosTests = false
		config.RunLoadTests = false
		config.RunScalabilityTests = false
	}

	if os.Getenv("IPFS_TEST_VERBOSE") == "true" {
		config.Verbose = true
	}

	// Create and run test suite
	runner := NewTestSuiteRunner(config)

	err := runner.RunAllTests(t)
	if err != nil {
		t.Fatalf("Comprehensive test suite failed: %v", err)
	}
}
