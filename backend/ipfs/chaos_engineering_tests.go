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
	"math/rand"
	"sync"
	"testing"
	"time"
)

// ChaosTestRunner manages chaos engineering tests
type ChaosTestRunner struct {
	suite          *TestSuite
	config         *ChaosTestConfig
	activeFailures map[string]*ChaosFailure
	metrics        *ChaosMetrics
	stopChan       chan bool
	wg             sync.WaitGroup
	mu             sync.RWMutex
}

// ChaosFailure represents an active failure injection
type ChaosFailure struct {
	Type        ChaosFailureType
	Target      string
	StartTime   time.Time
	Duration    time.Duration
	Severity    float64
	Description string
}

// ChaosFailureType represents different types of failures
type ChaosFailureType int

const (
	ChaosNodeFailure ChaosFailureType = iota
	ChaosNetworkPartition
	ChaosSlowNode
	ChaosDataCorruption
	ChaosHighLatency
	ChaosMemoryPressure
	ChaosDiskFull
	ChaosConnectionLoss
)

// String returns string representation of chaos failure type
func (cft ChaosFailureType) String() string {
	switch cft {
	case ChaosNodeFailure:
		return "NodeFailure"
	case ChaosNetworkPartition:
		return "NetworkPartition"
	case ChaosSlowNode:
		return "SlowNode"
	case ChaosDataCorruption:
		return "DataCorruption"
	case ChaosHighLatency:
		return "HighLatency"
	case ChaosMemoryPressure:
		return "MemoryPressure"
	case ChaosDiskFull:
		return "DiskFull"
	case ChaosConnectionLoss:
		return "ConnectionLoss"
	default:
		return "Unknown"
	}
}

// ChaosMetrics tracks metrics during chaos testing
type ChaosMetrics struct {
	TotalFailures       int64
	ActiveFailures      int64
	RecoveredFailures   int64
	FailedRecoveries    int64
	SystemDowntime      time.Duration
	OperationFailures   int64
	OperationSuccesses  int64
	AverageRecoveryTime time.Duration
	
	// Per-failure-type metrics
	FailureTypeMetrics map[ChaosFailureType]*FailureTypeMetrics
	
	mu sync.RWMutex
}

// FailureTypeMetrics tracks metrics for specific failure types
type FailureTypeMetrics struct {
	Count           int64
	TotalDuration   time.Duration
	AverageDuration time.Duration
	RecoveryCount   int64
	FailedRecovery  int64
}

// NewChaosTestRunner creates a new chaos test runner
func NewChaosTestRunner(suite *TestSuite, config *ChaosTestConfig) *ChaosTestRunner {
	return &ChaosTestRunner{
		suite:          suite,
		config:         config,
		activeFailures: make(map[string]*ChaosFailure),
		metrics: &ChaosMetrics{
			FailureTypeMetrics: make(map[ChaosFailureType]*FailureTypeMetrics),
		},
		stopChan: make(chan bool),
	}
}

// Start starts the chaos testing
func (ctr *ChaosTestRunner) Start() {
	ctr.wg.Add(1)
	go ctr.chaosLoop()
}

// Stop stops the chaos testing
func (ctr *ChaosTestRunner) Stop() {
	close(ctr.stopChan)
	ctr.wg.Wait()
	ctr.recoverAllFailures()
}

// chaosLoop runs the main chaos engineering loop
func (ctr *ChaosTestRunner) chaosLoop() {
	defer ctr.wg.Done()
	
	ticker := time.NewTicker(ctr.config.ChaosInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctr.stopChan:
			return
		case <-ticker.C:
			ctr.injectRandomFailure()
			ctr.recoverExpiredFailures()
		}
	}
}

// injectRandomFailure injects a random failure based on configuration
func (ctr *ChaosTestRunner) injectRandomFailure() {
	ctr.mu.Lock()
	defer ctr.mu.Unlock()
	
	// Decide which type of failure to inject
	failureType := ctr.selectFailureType()
	if failureType == -1 {
		return // No failure selected
	}
	
	// Create failure
	failure := &ChaosFailure{
		Type:        failureType,
		Target:      ctr.selectTarget(failureType),
		StartTime:   time.Now(),
		Duration:    ctr.selectDuration(failureType),
		Severity:    rand.Float64(),
		Description: fmt.Sprintf("%s on %s", failureType.String(), ctr.selectTarget(failureType)),
	}
	
	// Inject failure
	err := ctr.injectFailure(failure)
	if err != nil {
		ctr.suite.logger.Printf("Failed to inject chaos failure: %v", err)
		return
	}
	
	// Track failure
	failureID := fmt.Sprintf("%s-%d", failure.Type.String(), time.Now().UnixNano())
	ctr.activeFailures[failureID] = failure
	
	// Update metrics
	ctr.metrics.TotalFailures++
	ctr.metrics.ActiveFailures++
	
	if ctr.metrics.FailureTypeMetrics[failureType] == nil {
		ctr.metrics.FailureTypeMetrics[failureType] = &FailureTypeMetrics{}
	}
	ctr.metrics.FailureTypeMetrics[failureType].Count++
	
	ctr.suite.logger.Printf("Injected chaos failure: %s", failure.Description)
}

// selectFailureType selects a failure type based on configuration probabilities
func (ctr *ChaosTestRunner) selectFailureType() ChaosFailureType {
	r := rand.Float64()
	
	if r < ctr.config.NodeFailureRate {
		return ChaosNodeFailure
	}
	r -= ctr.config.NodeFailureRate
	
	if r < ctr.config.NetworkPartitionRate {
		return ChaosNetworkPartition
	}
	r -= ctr.config.NetworkPartitionRate
	
	if r < ctr.config.SlowNodeRate {
		return ChaosSlowNode
	}
	r -= ctr.config.SlowNodeRate
	
	if r < ctr.config.DataCorruptionRate {
		return ChaosDataCorruption
	}
	
	return -1 // No failure
}

// selectTarget selects a target for the failure
func (ctr *ChaosTestRunner) selectTarget(failureType ChaosFailureType) string {
	switch failureType {
	case ChaosNodeFailure, ChaosSlowNode, ChaosMemoryPressure, ChaosDiskFull:
		// Select a cluster node
		nodes := ctr.suite.clusterClient.GetNodeStatus()
		if len(nodes) > 0 {
			return nodes[rand.Intn(len(nodes))].Endpoint
		}
		return "node-1"
	case ChaosNetworkPartition, ChaosConnectionLoss:
		return "network"
	case ChaosDataCorruption:
		return fmt.Sprintf("data-store-%d", rand.Intn(3))
	default:
		return "system"
	}
}

// selectDuration selects a duration for the failure
func (ctr *ChaosTestRunner) selectDuration(failureType ChaosFailureType) time.Duration {
	base := ctr.config.ChaosInterval
	
	switch failureType {
	case ChaosNodeFailure:
		return base + time.Duration(rand.Intn(int(base.Seconds())))*time.Second
	case ChaosNetworkPartition:
		return base/2 + time.Duration(rand.Intn(int(base.Seconds()/2)))*time.Second
	case ChaosSlowNode:
		return base*2 + time.Duration(rand.Intn(int(base.Seconds())))*time.Second
	case ChaosDataCorruption:
		return base/4 + time.Duration(rand.Intn(int(base.Seconds()/4)))*time.Second
	default:
		return base + time.Duration(rand.Intn(int(base.Seconds())))*time.Second
	}
}

// injectFailure injects the specified failure
func (ctr *ChaosTestRunner) injectFailure(failure *ChaosFailure) error {
	switch failure.Type {
	case ChaosNodeFailure:
		return ctr.injectNodeFailure(failure)
	case ChaosNetworkPartition:
		return ctr.injectNetworkPartition(failure)
	case ChaosSlowNode:
		return ctr.injectSlowNode(failure)
	case ChaosDataCorruption:
		return ctr.injectDataCorruption(failure)
	case ChaosHighLatency:
		return ctr.injectHighLatency(failure)
	case ChaosMemoryPressure:
		return ctr.injectMemoryPressure(failure)
	case ChaosDiskFull:
		return ctr.injectDiskFull(failure)
	case ChaosConnectionLoss:
		return ctr.injectConnectionLoss(failure)
	default:
		return fmt.Errorf("unknown failure type: %v", failure.Type)
	}
}

// injectNodeFailure simulates node failure
func (ctr *ChaosTestRunner) injectNodeFailure(failure *ChaosFailure) error {
	// Simulate node failure by making cluster operations fail
	ctr.suite.clusterClient.SetFailPin(true)
	return nil
}

// injectNetworkPartition simulates network partition
func (ctr *ChaosTestRunner) injectNetworkPartition(failure *ChaosFailure) error {
	// Simulate network partition by introducing delays and failures
	// This is a simplified simulation
	return nil
}

// injectSlowNode simulates slow node performance
func (ctr *ChaosTestRunner) injectSlowNode(failure *ChaosFailure) error {
	// Simulate slow node by adding delays to operations
	// This would require modifying the mock client to add delays
	return nil
}

// injectDataCorruption simulates data corruption
func (ctr *ChaosTestRunner) injectDataCorruption(failure *ChaosFailure) error {
	// Simulate data corruption by making metadata operations fail
	ctr.suite.metadataStore.SetFailOps(true)
	return nil
}

// injectHighLatency simulates high network latency
func (ctr *ChaosTestRunner) injectHighLatency(failure *ChaosFailure) error {
	// Simulate high latency - would require network simulation
	return nil
}

// injectMemoryPressure simulates memory pressure
func (ctr *ChaosTestRunner) injectMemoryPressure(failure *ChaosFailure) error {
	// Simulate memory pressure - would require memory allocation
	return nil
}

// injectDiskFull simulates disk full condition
func (ctr *ChaosTestRunner) injectDiskFull(failure *ChaosFailure) error {
	// Simulate disk full - would require storage simulation
	return nil
}

// injectConnectionLoss simulates connection loss
func (ctr *ChaosTestRunner) injectConnectionLoss(failure *ChaosFailure) error {
	// Simulate connection loss by making operations timeout
	return nil
}

// recoverExpiredFailures recovers failures that have expired
func (ctr *ChaosTestRunner) recoverExpiredFailures() {
	ctr.mu.Lock()
	defer ctr.mu.Unlock()
	
	now := time.Now()
	for id, failure := range ctr.activeFailures {
		if now.Sub(failure.StartTime) >= failure.Duration {
			err := ctr.recoverFailure(failure)
			if err != nil {
				ctr.suite.logger.Printf("Failed to recover from chaos failure %s: %v", id, err)
				ctr.metrics.FailedRecoveries++
			} else {
				ctr.suite.logger.Printf("Recovered from chaos failure: %s", failure.Description)
				ctr.metrics.RecoveredFailures++
				
				// Update recovery metrics
				if typeMetrics := ctr.metrics.FailureTypeMetrics[failure.Type]; typeMetrics != nil {
					typeMetrics.RecoveryCount++
					typeMetrics.TotalDuration += failure.Duration
					typeMetrics.AverageDuration = typeMetrics.TotalDuration / time.Duration(typeMetrics.Count)
				}
			}
			
			delete(ctr.activeFailures, id)
			ctr.metrics.ActiveFailures--
		}
	}
}

// recoverFailure recovers from the specified failure
func (ctr *ChaosTestRunner) recoverFailure(failure *ChaosFailure) error {
	switch failure.Type {
	case ChaosNodeFailure:
		ctr.suite.clusterClient.SetFailPin(false)
	case ChaosDataCorruption:
		ctr.suite.metadataStore.SetFailOps(false)
	case ChaosNetworkPartition, ChaosSlowNode, ChaosHighLatency, ChaosMemoryPressure, ChaosDiskFull, ChaosConnectionLoss:
		// These would require specific recovery logic
	}
	return nil
}

// recoverAllFailures recovers from all active failures
func (ctr *ChaosTestRunner) recoverAllFailures() {
	ctr.mu.Lock()
	defer ctr.mu.Unlock()
	
	for id, failure := range ctr.activeFailures {
		err := ctr.recoverFailure(failure)
		if err != nil {
			ctr.suite.logger.Printf("Failed to recover from chaos failure %s during shutdown: %v", id, err)
		}
	}
	
	ctr.activeFailures = make(map[string]*ChaosFailure)
	ctr.metrics.ActiveFailures = 0
}

// GetMetrics returns current chaos metrics
func (ctr *ChaosTestRunner) GetMetrics() *ChaosMetrics {
	ctr.metrics.mu.RLock()
	defer ctr.metrics.mu.RUnlock()
	
	// Create a copy of metrics
	metrics := &ChaosMetrics{
		TotalFailures:       ctr.metrics.TotalFailures,
		ActiveFailures:      ctr.metrics.ActiveFailures,
		RecoveredFailures:   ctr.metrics.RecoveredFailures,
		FailedRecoveries:    ctr.metrics.FailedRecoveries,
		SystemDowntime:      ctr.metrics.SystemDowntime,
		OperationFailures:   ctr.metrics.OperationFailures,
		OperationSuccesses:  ctr.metrics.OperationSuccesses,
		AverageRecoveryTime: ctr.metrics.AverageRecoveryTime,
		FailureTypeMetrics:  make(map[ChaosFailureType]*FailureTypeMetrics),
	}
	
	for k, v := range ctr.metrics.FailureTypeMetrics {
		metrics.FailureTypeMetrics[k] = &FailureTypeMetrics{
			Count:           v.Count,
			TotalDuration:   v.TotalDuration,
			AverageDuration: v.AverageDuration,
			RecoveryCount:   v.RecoveryCount,
			FailedRecovery:  v.FailedRecovery,
		}
	}
	
	return metrics
}

// TestChaosEngineering runs comprehensive chaos engineering tests
func TestChaosEngineering(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping chaos engineering tests in short mode")
	}
	
	suite := NewTestSuite(t)
	defer suite.Cleanup()
	
	t.Run("BasicChaosTest", func(t *testing.T) {
		testBasicChaos(t, suite)
	})
	
	t.Run("NodeFailureResilience", func(t *testing.T) {
		testNodeFailureResilience(t, suite)
	})
	
	t.Run("NetworkPartitionResilience", func(t *testing.T) {
		testNetworkPartitionResilience(t, suite)
	})
	
	t.Run("DataCorruptionResilience", func(t *testing.T) {
		testDataCorruptionResilience(t, suite)
	})
	
	t.Run("CascadingFailures", func(t *testing.T) {
		testCascadingFailures(t, suite)
	})
	
	t.Run("RecoveryTesting", func(t *testing.T) {
		testRecoveryScenarios(t, suite)
	})
}

// testBasicChaos tests basic chaos engineering functionality
func testBasicChaos(t *testing.T, suite *TestSuite) {
	config := &ChaosTestConfig{
		NodeFailureRate:     0.3,
		NetworkPartitionRate: 0.2,
		SlowNodeRate:        0.3,
		DataCorruptionRate:  0.1,
		TestDuration:        30 * time.Second,
		ChaosInterval:       5 * time.Second,
		RecoveryTime:        2 * time.Second,
	}
	
	chaosRunner := NewChaosTestRunner(suite, config)
	chaosRunner.Start()
	
	ctx := context.Background()
	
	// Run operations while chaos is happening
	var wg sync.WaitGroup
	numWorkers := 5
	operationsPerWorker := 20
	
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerWorker; j++ {
				// Try pin operation
				cid := fmt.Sprintf("QmChaos%d-%d", workerID, j)
				result, err := suite.clusterClient.Pin(ctx, cid, 2)
				
				if err != nil {
					chaosRunner.metrics.OperationFailures++
					t.Logf("Pin operation failed during chaos (expected): %v", err)
				} else if result.Success {
					chaosRunner.metrics.OperationSuccesses++
				}
				
				// Try metadata operation
				mapping := &ObjectMapping{
					S3Key:     fmt.Sprintf("chaos-key-%d-%d", workerID, j),
					Bucket:    "chaos-bucket",
					CID:       cid,
					Size:      1024,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					PinStatus: PinStatusPinned,
				}
				
				err = suite.metadataStore.StoreMapping(ctx, mapping)
				if err != nil {
					chaosRunner.metrics.OperationFailures++
					t.Logf("Metadata operation failed during chaos (expected): %v", err)
				} else {
					chaosRunner.metrics.OperationSuccesses++
				}
				
				time.Sleep(100 * time.Millisecond)
			}
		}(i)
	}
	
	// Wait for test duration
	time.Sleep(config.TestDuration)
	
	// Stop chaos
	chaosRunner.Stop()
	
	// Wait for workers to complete
	wg.Wait()
	
	// Check metrics
	metrics := chaosRunner.GetMetrics()
	
	t.Logf("Chaos test results:")
	t.Logf("  Total failures injected: %d", metrics.TotalFailures)
	t.Logf("  Recovered failures: %d", metrics.RecoveredFailures)
	t.Logf("  Failed recoveries: %d", metrics.FailedRecoveries)
	t.Logf("  Operation successes: %d", metrics.OperationSuccesses)
	t.Logf("  Operation failures: %d", metrics.OperationFailures)
	
	if metrics.TotalFailures == 0 {
		t.Error("Should have injected some failures")
	}
	
	if metrics.RecoveredFailures == 0 && metrics.TotalFailures > 0 {
		t.Error("Should have recovered from some failures")
	}
	
	// System should have some successful operations even during chaos
	if metrics.OperationSuccesses == 0 {
		t.Error("Should have some successful operations during chaos")
	}
}

// testNodeFailureResilience tests resilience to node failures
func testNodeFailureResilience(t *testing.T, suite *TestSuite) {
	ctx := context.Background()
	
	// Store some initial data
	initialMappings := make([]*ObjectMapping, 10)
	for i := 0; i < 10; i++ {
		mapping := &ObjectMapping{
			S3Key:     fmt.Sprintf("resilience-key-%d", i),
			Bucket:    "resilience-bucket",
			CID:       fmt.Sprintf("QmResilience%d", i),
			Size:      1024,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			PinStatus: PinStatusPinned,
		}
		
		err := suite.metadataStore.StoreMapping(ctx, mapping)
		if err != nil {
			t.Fatalf("Failed to store initial mapping: %v", err)
		}
		
		initialMappings[i] = mapping
	}
	
	// Simulate node failure
	suite.clusterClient.SetFailPin(true)
	
	// Try to access existing data - should still work from metadata
	for _, mapping := range initialMappings {
		retrieved, err := suite.metadataStore.GetMapping(ctx, mapping.S3Key, mapping.Bucket)
		if err != nil {
			t.Errorf("Should be able to retrieve metadata during node failure: %v", err)
		}
		
		if retrieved == nil {
			t.Error("Retrieved mapping should not be nil")
		}
	}
	
	// Try to pin new data - should fail gracefully
	_, err := suite.clusterClient.Pin(ctx, "QmNewDuringFailure", 2)
	if err == nil {
		t.Error("Pin should fail during node failure")
	}
	
	// Recover from failure
	suite.clusterClient.SetFailPin(false)
	
	// Operations should work again
	result, err := suite.clusterClient.Pin(ctx, "QmAfterRecovery", 2)
	if err != nil {
		t.Errorf("Pin should work after recovery: %v", err)
	}
	
	if !result.Success {
		t.Error("Pin should succeed after recovery")
	}
}

// testNetworkPartitionResilience tests resilience to network partitions
func testNetworkPartitionResilience(t *testing.T, suite *TestSuite) {
	ctx := context.Background()
	
	// This test simulates network partition by introducing timeouts
	shortCtx, cancel := context.WithTimeout(ctx, 1*time.Millisecond)
	defer cancel()
	
	// Operations should timeout during network partition
	_, err := suite.clusterClient.Pin(shortCtx, "QmNetworkPartition", 2)
	if err == nil {
		t.Error("Should timeout during network partition simulation")
	}
	
	// Operations should work with normal context
	result, err := suite.clusterClient.Pin(ctx, "QmAfterPartition", 2)
	if err != nil {
		t.Errorf("Should work after network partition: %v", err)
	}
	
	if !result.Success {
		t.Error("Pin should succeed after network partition")
	}
}

// testDataCorruptionResilience tests resilience to data corruption
func testDataCorruptionResilience(t *testing.T, suite *TestSuite) {
	ctx := context.Background()
	
	// Store some data first
	mapping := &ObjectMapping{
		S3Key:     "corruption-test-key",
		Bucket:    "corruption-bucket",
		CID:       "QmCorruptionTest",
		Size:      1024,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		PinStatus: PinStatusPinned,
	}
	
	err := suite.metadataStore.StoreMapping(ctx, mapping)
	if err != nil {
		t.Fatalf("Failed to store initial mapping: %v", err)
	}
	
	// Simulate data corruption
	suite.metadataStore.SetFailOps(true)
	
	// Operations should fail during corruption
	_, err = suite.metadataStore.GetMapping(ctx, mapping.S3Key, mapping.Bucket)
	if err == nil {
		t.Error("Should fail during data corruption")
	}
	
	// Recover from corruption
	suite.metadataStore.SetFailOps(false)
	
	// Operations should work again
	retrieved, err := suite.metadataStore.GetMapping(ctx, mapping.S3Key, mapping.Bucket)
	if err != nil {
		t.Errorf("Should work after corruption recovery: %v", err)
	}
	
	if retrieved == nil {
		t.Error("Should retrieve mapping after recovery")
	}
}

// testCascadingFailures tests system behavior under cascading failures
func testCascadingFailures(t *testing.T, suite *TestSuite) {
	ctx := context.Background()
	
	// Inject multiple failures simultaneously
	suite.clusterClient.SetFailPin(true)
	suite.metadataStore.SetFailOps(true)
	
	// System should handle multiple failures gracefully
	_, err1 := suite.clusterClient.Pin(ctx, "QmCascade1", 2)
	_, err2 := suite.metadataStore.GetMapping(ctx, "nonexistent", "bucket")
	
	if err1 == nil {
		t.Error("Cluster operation should fail")
	}
	
	if err2 == nil {
		t.Error("Metadata operation should fail")
	}
	
	// Recover gradually
	suite.clusterClient.SetFailPin(false)
	
	// Cluster should work, metadata should still fail
	result, err := suite.clusterClient.Pin(ctx, "QmPartialRecovery", 2)
	if err != nil {
		t.Errorf("Cluster should work after partial recovery: %v", err)
	}
	
	if !result.Success {
		t.Error("Pin should succeed after cluster recovery")
	}
	
	_, err = suite.metadataStore.GetMapping(ctx, "still-failing", "bucket")
	if err == nil {
		t.Error("Metadata should still fail")
	}
	
	// Full recovery
	suite.metadataStore.SetFailOps(false)
	
	// Everything should work
	mapping := &ObjectMapping{
		S3Key:     "full-recovery-key",
		Bucket:    "recovery-bucket",
		CID:       "QmFullRecovery",
		Size:      1024,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		PinStatus: PinStatusPinned,
	}
	
	err = suite.metadataStore.StoreMapping(ctx, mapping)
	if err != nil {
		t.Errorf("Should work after full recovery: %v", err)
	}
}

// testRecoveryScenarios tests various recovery scenarios
func testRecoveryScenarios(t *testing.T, suite *TestSuite) {
	ctx := context.Background()
	
	t.Run("ImmediateRecovery", func(t *testing.T) {
		// Inject failure and recover immediately
		suite.clusterClient.SetFailPin(true)
		suite.clusterClient.SetFailPin(false)
		
		result, err := suite.clusterClient.Pin(ctx, "QmImmediateRecovery", 2)
		if err != nil {
			t.Errorf("Should recover immediately: %v", err)
		}
		
		if !result.Success {
			t.Error("Pin should succeed after immediate recovery")
		}
	})
	
	t.Run("DelayedRecovery", func(t *testing.T) {
		// Inject failure, wait, then recover
		suite.metadataStore.SetFailOps(true)
		
		// Should fail
		err := suite.metadataStore.StoreMapping(ctx, &ObjectMapping{
			S3Key:  "delayed-test",
			Bucket: "delayed-bucket",
			CID:    "QmDelayed",
		})
		if err == nil {
			t.Error("Should fail before recovery")
		}
		
		// Wait and recover
		time.Sleep(100 * time.Millisecond)
		suite.metadataStore.SetFailOps(false)
		
		// Should work now
		err = suite.metadataStore.StoreMapping(ctx, &ObjectMapping{
			S3Key:     "delayed-recovery-key",
			Bucket:    "delayed-bucket",
			CID:       "QmDelayedRecovery",
			Size:      1024,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			PinStatus: PinStatusPinned,
		})
		if err != nil {
			t.Errorf("Should work after delayed recovery: %v", err)
		}
	})
	
	t.Run("PartialRecovery", func(t *testing.T) {
		// Test recovery when only some components recover
		suite.clusterClient.SetFailPin(true)
		suite.metadataStore.SetFailOps(true)
		
		// Recover only cluster
		suite.clusterClient.SetFailPin(false)
		
		// Cluster should work
		result, err := suite.clusterClient.Pin(ctx, "QmPartialRecoveryCluster", 2)
		if err != nil {
			t.Errorf("Cluster should work: %v", err)
		}
		
		if !result.Success {
			t.Error("Cluster pin should succeed")
		}
		
		// Metadata should still fail
		err = suite.metadataStore.StoreMapping(ctx, &ObjectMapping{
			S3Key:  "partial-test",
			Bucket: "partial-bucket",
			CID:    "QmPartial",
		})
		if err == nil {
			t.Error("Metadata should still fail")
		}
		
		// Full recovery
		suite.metadataStore.SetFailOps(false)
		
		err = suite.metadataStore.StoreMapping(ctx, &ObjectMapping{
			S3Key:     "partial-recovery-key",
			Bucket:    "partial-bucket",
			CID:       "QmPartialRecovery",
			Size:      1024,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			PinStatus: PinStatusPinned,
		})
		if err != nil {
			t.Errorf("Should work after full recovery: %v", err)
		}
	})
}

// TestChaosMetrics tests chaos metrics collection
func TestChaosMetrics(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()
	
	config := DefaultChaosTestConfig()
	config.TestDuration = 5 * time.Second
	config.ChaosInterval = 1 * time.Second
	
	chaosRunner := NewChaosTestRunner(suite, config)
	
	// Test initial metrics
	metrics := chaosRunner.GetMetrics()
	if metrics.TotalFailures != 0 {
		t.Error("Initial total failures should be 0")
	}
	
	if metrics.ActiveFailures != 0 {
		t.Error("Initial active failures should be 0")
	}
	
	// Run chaos for a short time
	chaosRunner.Start()
	time.Sleep(config.TestDuration)
	chaosRunner.Stop()
	
	// Check final metrics
	finalMetrics := chaosRunner.GetMetrics()
	
	t.Logf("Final chaos metrics:")
	t.Logf("  Total failures: %d", finalMetrics.TotalFailures)
	t.Logf("  Recovered failures: %d", finalMetrics.RecoveredFailures)
	t.Logf("  Failed recoveries: %d", finalMetrics.FailedRecoveries)
	t.Logf("  Active failures: %d", finalMetrics.ActiveFailures)
	
	// Should have no active failures after stop
	if finalMetrics.ActiveFailures != 0 {
		t.Errorf("Should have no active failures after stop, got %d", finalMetrics.ActiveFailures)
	}
	
	// Should have attempted some failures
	if finalMetrics.TotalFailures == 0 {
		t.Log("No failures were injected during short test (this may be normal)")
	}
}