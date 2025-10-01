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
	"sync"
	"testing"
	"time"
)

// MockClusterClient implements a mock cluster client for testing
type MockClusterClient struct {
	pins        map[string]*MockPin
	mu          sync.RWMutex
	failPin     bool
	failUnpin   bool
	pinDelay    time.Duration
	unpinDelay  time.Duration
	nodeStatus  []*NodeStatus
	clusterInfo *ClusterInfo
	metrics     *ClusterMetrics
}

// Ensure MockClusterClient implements ClusterClientInterface
var _ ClusterClientInterface = (*MockClusterClient)(nil)

// MockPin represents a mock pin in the cluster
type MockPin struct {
	CID       string
	Nodes     []string
	Status    string
	CreatedAt time.Time
}

// NewMockClusterClient creates a new mock cluster client
func NewMockClusterClient() *MockClusterClient {
	return &MockClusterClient{
		pins:       make(map[string]*MockPin),
		pinDelay:   100 * time.Millisecond,
		unpinDelay: 50 * time.Millisecond,
		nodeStatus: []*NodeStatus{
			{Endpoint: "node1", Healthy: true},
			{Endpoint: "node2", Healthy: true},
			{Endpoint: "node3", Healthy: true},
		},
		clusterInfo: &ClusterInfo{
			ID:      "test-cluster",
			Version: "1.0.0",
			Peers:   3,
		},
		metrics: &ClusterMetrics{
			TotalRequests:  0,
			SuccessfulReqs: 0,
			FailedRequests: 0,
		},
	}
}

// Pin simulates pinning a CID
func (m *MockClusterClient) Pin(ctx context.Context, cid string, replicationFactor int) (*ClusterPinResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.failPin {
		m.metrics.FailedRequests++
		return nil, fmt.Errorf("mock pin failure")
	}
	
	// Simulate delay
	select {
	case <-time.After(m.pinDelay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	
	nodes := []string{"node1", "node2", "node3"}
	if replicationFactor < len(nodes) {
		nodes = nodes[:replicationFactor]
	}
	
	m.pins[cid] = &MockPin{
		CID:       cid,
		Nodes:     nodes,
		Status:    "pinned",
		CreatedAt: time.Now(),
	}
	
	m.metrics.SuccessfulReqs++
	m.metrics.TotalRequests++
	
	return &ClusterPinResult{
		CID:       cid,
		NodesUsed: nodes,
	}, nil
}

// Unpin simulates unpinning a CID
func (m *MockClusterClient) Unpin(ctx context.Context, cid string) (*ClusterUnpinResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.failUnpin {
		m.metrics.FailedRequests++
		return nil, fmt.Errorf("mock unpin failure")
	}
	
	// Simulate delay
	select {
	case <-time.After(m.unpinDelay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	
	pin, exists := m.pins[cid]
	if !exists {
		return nil, fmt.Errorf("CID not found")
	}
	
	nodes := pin.Nodes
	delete(m.pins, cid)
	
	m.metrics.SuccessfulReqs++
	m.metrics.TotalRequests++
	
	return &ClusterUnpinResult{
		CID:       cid,
		NodesUsed: nodes,
	}, nil
}

// GetNodeStatus returns mock node status
func (m *MockClusterClient) GetNodeStatus() []*NodeStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.nodeStatus
}

// GetClusterInfo returns mock cluster info
func (m *MockClusterClient) GetClusterInfo() (*ClusterInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clusterInfo, nil
}

// GetMetrics returns mock metrics
func (m *MockClusterClient) GetMetrics() *ClusterMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metrics
}

// SetFailPin sets whether pin operations should fail
func (m *MockClusterClient) SetFailPin(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failPin = fail
}

// SetFailUnpin sets whether unpin operations should fail
func (m *MockClusterClient) SetFailUnpin(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failUnpin = fail
}

// GetPins returns all current pins
func (m *MockClusterClient) GetPins() map[string]*MockPin {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	pins := make(map[string]*MockPin)
	for k, v := range m.pins {
		pins[k] = v
	}
	return pins
}

// StoreMapping stores an object mapping (duplicate - using fault_tolerance_test.go version)
/*func (m *MockMetadataStore) StoreMapping(ctx context.Context, mapping *ObjectMapping) error {
	if m.failOps {
		return fmt.Errorf("mock store failure")
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	key := mapping.GetPrimaryKey()
	m.mappings[key] = mapping.Clone()
	return nil
}

// GetMapping retrieves an object mapping (duplicate - using fault_tolerance_test.go version)
/*func (m *MockMetadataStore) GetMapping(ctx context.Context, s3Key, bucket string) (*ObjectMapping, error) {
	if m.failOps {
		return nil, fmt.Errorf("mock get failure")
	}
	
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	key := fmt.Sprintf("%s/%s", bucket, s3Key)
	mapping, exists := m.mappings[key]
	if !exists {
		return nil, nil
	}
	
	return mapping.Clone(), nil
}*/

// UpdateMapping updates an object mapping
func (m *MockMetadataStore) UpdateMapping(ctx context.Context, mapping *ObjectMapping) error {
	if m.failOps {
		return fmt.Errorf("mock update failure")
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	key := mapping.GetPrimaryKey()
	m.mappings[key] = mapping.Clone()
	return nil
}

// DeleteMapping deletes an object mapping
func (m *MockMetadataStore) DeleteMapping(ctx context.Context, s3Key, bucket string) error {
	if m.failOps {
		return fmt.Errorf("mock delete failure")
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	key := fmt.Sprintf("%s/%s", bucket, s3Key)
	delete(m.mappings, key)
	return nil
}

// SearchByCID searches for mappings by CID
func (m *MockMetadataStore) SearchByCID(ctx context.Context, cid string) ([]*ObjectMapping, error) {
	if m.failOps {
		return nil, fmt.Errorf("mock search failure")
	}
	
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var results []*ObjectMapping
	for _, mapping := range m.mappings {
		if mapping.CID == cid {
			results = append(results, mapping.Clone())
		}
	}
	
	return results, nil
}

// SetFailOps sets whether operations should fail
func (m *MockMetadataStore) SetFailOps(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failOps = fail
}

// GetMappings returns all mappings
func (m *MockMetadataStore) GetMappings() map[string]*ObjectMapping {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	mappings := make(map[string]*ObjectMapping)
	for k, v := range m.mappings {
		mappings[k] = v.Clone()
	}
	return mappings
}

// Test helper functions

func createTestPinManager(t *testing.T) (*PinManager, *MockClusterClient, *MockMetadataStore) {
	// For testing, we'll create a simplified pin manager that doesn't require the full cluster client
	// This is a test-specific implementation
	config := &PinManagerConfig{
		PinWorkerCount:     2,
		UnpinWorkerCount:   1,
		PinQueueSize:       100,
		UnpinQueueSize:     50,
		RetryQueueSize:     25,
		PinTimeout:         5 * time.Second,
		UnpinTimeout:       3 * time.Second,
		MaxRetries:         2,
		InitialRetryDelay:  100 * time.Millisecond,
		MaxRetryDelay:      1 * time.Second,
		RetryBackoffFactor: 2.0,
		MetricsEnabled:     true,
		MetricsInterval:    1 * time.Second,
	}
	
	mockCluster := NewMockClusterClient()
	mockMetadata := NewMockMetadataStore()
	logger := log.New(log.Writer(), "[TEST] ", log.LstdFlags)
	
	pm, err := NewPinManager(config, mockCluster, mockMetadata, logger)
	if err != nil {
		t.Fatalf("Failed to create pin manager: %v", err)
	}
	
	return pm, mockCluster, mockMetadata
}

// Test cases

func TestPinManager_Creation(t *testing.T) {
	pm, _, _ := createTestPinManager(t)
	
	if pm == nil {
		t.Fatal("Pin manager should not be nil")
	}
	
	if pm.config.PinWorkerCount != 2 {
		t.Errorf("Expected 2 pin workers, got %d", pm.config.PinWorkerCount)
	}
	
	if pm.config.UnpinWorkerCount != 1 {
		t.Errorf("Expected 1 unpin worker, got %d", pm.config.UnpinWorkerCount)
	}
}

func TestPinManager_StartStop(t *testing.T) {
	pm, _, _ := createTestPinManager(t)
	
	// Test start
	err := pm.Start()
	if err != nil {
		t.Fatalf("Failed to start pin manager: %v", err)
	}
	
	if !pm.isRunning() {
		t.Error("Pin manager should be running after start")
	}
	
	// Test double start
	err = pm.Start()
	if err == nil {
		t.Error("Expected error when starting already running pin manager")
	}
	
	// Test stop
	err = pm.Stop()
	if err != nil {
		t.Fatalf("Failed to stop pin manager: %v", err)
	}
	
	if pm.isRunning() {
		t.Error("Pin manager should not be running after stop")
	}
}

func TestPinManager_PinOperation(t *testing.T) {
	pm, mockCluster, mockMetadata := createTestPinManager(t)
	
	err := pm.Start()
	if err != nil {
		t.Fatalf("Failed to start pin manager: %v", err)
	}
	defer pm.Stop()
	
	ctx := context.Background()
	cid := "QmTest123"
	s3Key := "test-key"
	bucket := "test-bucket"
	size := int64(1024)
	replicationFactor := 2
	
	// Test successful pin
	result, err := pm.Pin(ctx, cid, s3Key, bucket, size, replicationFactor, PinPriorityNormal)
	if err != nil {
		t.Fatalf("Pin operation failed: %v", err)
	}
	
	if !result.Success {
		t.Errorf("Pin should have succeeded, got error: %v", result.Error)
	}
	
	if result.CID != cid {
		t.Errorf("Expected CID %s, got %s", cid, result.CID)
	}
	
	if len(result.NodesUsed) != replicationFactor {
		t.Errorf("Expected %d nodes used, got %d", replicationFactor, len(result.NodesUsed))
	}
	
	// Verify pin was created in cluster
	pins := mockCluster.GetPins()
	if _, exists := pins[cid]; !exists {
		t.Error("Pin should exist in cluster")
	}
	
	// Verify metadata was updated
	mapping, err := mockMetadata.GetMapping(ctx, s3Key, bucket)
	if err != nil {
		t.Fatalf("Failed to get mapping: %v", err)
	}
	
	if mapping == nil {
		t.Fatal("Mapping should exist")
	}
	
	if mapping.PinStatus != PinStatusPinned {
		t.Errorf("Expected pin status %v, got %v", PinStatusPinned, mapping.PinStatus)
	}
}

func TestPinManager_UnpinOperation(t *testing.T) {
	pm, mockCluster, mockMetadata := createTestPinManager(t)
	
	err := pm.Start()
	if err != nil {
		t.Fatalf("Failed to start pin manager: %v", err)
	}
	defer pm.Stop()
	
	ctx := context.Background()
	cid := "QmTest456"
	s3Key := "test-key-2"
	bucket := "test-bucket"
	size := int64(2048)
	replicationFactor := 3
	
	// First pin the object
	_, err = pm.Pin(ctx, cid, s3Key, bucket, size, replicationFactor, PinPriorityNormal)
	if err != nil {
		t.Fatalf("Pin operation failed: %v", err)
	}
	
	// Now unpin it
	result, err := pm.Unpin(ctx, cid, s3Key, bucket, false, PinPriorityNormal)
	if err != nil {
		t.Fatalf("Unpin operation failed: %v", err)
	}
	
	if !result.Success {
		t.Errorf("Unpin should have succeeded, got error: %v", result.Error)
	}
	
	if result.CID != cid {
		t.Errorf("Expected CID %s, got %s", cid, result.CID)
	}
	
	// Verify pin was removed from cluster
	pins := mockCluster.GetPins()
	if _, exists := pins[cid]; exists {
		t.Error("Pin should not exist in cluster after unpin")
	}
	
	// Verify metadata was updated
	mapping, err := mockMetadata.GetMapping(ctx, s3Key, bucket)
	if err != nil {
		t.Fatalf("Failed to get mapping: %v", err)
	}
	
	if mapping == nil {
		t.Fatal("Mapping should exist")
	}
	
	if mapping.PinStatus != PinStatusUnpinned {
		t.Errorf("Expected pin status %v, got %v", PinStatusUnpinned, mapping.PinStatus)
	}
}

func TestPinManager_AsyncOperations(t *testing.T) {
	pm, _, _ := createTestPinManager(t)
	
	err := pm.Start()
	if err != nil {
		t.Fatalf("Failed to start pin manager: %v", err)
	}
	defer pm.Stop()
	
	ctx := context.Background()
	
	// Test async pin
	requestID, err := pm.PinAsync(ctx, "QmAsync123", "async-key", "async-bucket", 1024, 2, PinPriorityBackground)
	if err != nil {
		t.Fatalf("Async pin failed: %v", err)
	}
	
	if requestID == "" {
		t.Error("Request ID should not be empty")
	}
	
	// Test async unpin
	requestID2, err := pm.UnpinAsync(ctx, "QmAsync456", "async-key-2", "async-bucket", false, PinPriorityBackground)
	if err != nil {
		t.Fatalf("Async unpin failed: %v", err)
	}
	
	if requestID2 == "" {
		t.Error("Request ID should not be empty")
	}
	
	if requestID == requestID2 {
		t.Error("Request IDs should be unique")
	}
}

func TestPinManager_PriorityHandling(t *testing.T) {
	pm, _, _ := createTestPinManager(t)
	
	err := pm.Start()
	if err != nil {
		t.Fatalf("Failed to start pin manager: %v", err)
	}
	defer pm.Stop()
	
	ctx := context.Background()
	
	// Submit pins with different priorities
	priorities := []PinPriority{PinPriorityCritical, PinPriorityNormal, PinPriorityBackground}
	
	for i, priority := range priorities {
		cid := fmt.Sprintf("QmPriority%d", i)
		s3Key := fmt.Sprintf("priority-key-%d", i)
		
		result, err := pm.Pin(ctx, cid, s3Key, "priority-bucket", 1024, 2, priority)
		if err != nil {
			t.Fatalf("Pin with priority %v failed: %v", priority, err)
		}
		
		if !result.Success {
			t.Errorf("Pin with priority %v should have succeeded", priority)
		}
	}
	
	// Check metrics for priority counts
	metrics := pm.GetMetrics()
	if metrics.CriticalPins == 0 {
		t.Error("Should have critical pins in metrics")
	}
	if metrics.NormalPins == 0 {
		t.Error("Should have normal pins in metrics")
	}
	if metrics.BackgroundPins == 0 {
		t.Error("Should have background pins in metrics")
	}
}

func TestPinManager_RetryMechanism(t *testing.T) {
	pm, mockCluster, _ := createTestPinManager(t)
	
	err := pm.Start()
	if err != nil {
		t.Fatalf("Failed to start pin manager: %v", err)
	}
	defer pm.Stop()
	
	ctx := context.Background()
	
	// Make cluster operations fail
	mockCluster.SetFailPin(true)
	
	// Submit a pin request that will fail
	result, err := pm.Pin(ctx, "QmRetryTest", "retry-key", "retry-bucket", 1024, 2, PinPriorityNormal)
	
	// The operation should eventually fail after retries
	if err == nil && result.Success {
		t.Error("Pin should have failed due to cluster failure")
	}
	
	// Wait a bit for retries to be processed
	time.Sleep(500 * time.Millisecond)
	
	// Check that retries were attempted
	metrics := pm.GetMetrics()
	if metrics.TotalRetries == 0 {
		t.Error("Should have attempted retries")
	}
}

func TestPinManager_Metrics(t *testing.T) {
	pm, _, _ := createTestPinManager(t)
	
	err := pm.Start()
	if err != nil {
		t.Fatalf("Failed to start pin manager: %v", err)
	}
	defer pm.Stop()
	
	ctx := context.Background()
	
	// Perform some operations
	_, _ = pm.Pin(ctx, "QmMetrics1", "metrics-key-1", "metrics-bucket", 1024, 2, PinPriorityNormal)
	_, _ = pm.Pin(ctx, "QmMetrics2", "metrics-key-2", "metrics-bucket", 2048, 3, PinPriorityCritical)
	
	// Get metrics
	metrics := pm.GetMetrics()
	
	if metrics.TotalPinRequests < 2 {
		t.Errorf("Expected at least 2 pin requests, got %d", metrics.TotalPinRequests)
	}
	
	if metrics.SuccessfulPins < 2 {
		t.Errorf("Expected at least 2 successful pins, got %d", metrics.SuccessfulPins)
	}
	
	if metrics.ActivePinWorkers != 2 {
		t.Errorf("Expected 2 active pin workers, got %d", metrics.ActivePinWorkers)
	}
	
	if metrics.ActiveUnpinWorkers != 1 {
		t.Errorf("Expected 1 active unpin worker, got %d", metrics.ActiveUnpinWorkers)
	}
}

func TestPinManager_QueueStats(t *testing.T) {
	pm, _, _ := createTestPinManager(t)
	
	stats := pm.GetQueueStats()
	
	if stats.PinQueueCapacity != 100 {
		t.Errorf("Expected pin queue capacity 100, got %d", stats.PinQueueCapacity)
	}
	
	if stats.UnpinQueueCapacity != 50 {
		t.Errorf("Expected unpin queue capacity 50, got %d", stats.UnpinQueueCapacity)
	}
	
	if stats.RetryQueueCapacity != 25 {
		t.Errorf("Expected retry queue capacity 25, got %d", stats.RetryQueueCapacity)
	}
}

func TestPinManager_HealthCheck(t *testing.T) {
	pm, _, _ := createTestPinManager(t)
	
	// Should not be healthy when not running
	if pm.IsHealthy() {
		t.Error("Pin manager should not be healthy when not running")
	}
	
	err := pm.Start()
	if err != nil {
		t.Fatalf("Failed to start pin manager: %v", err)
	}
	defer pm.Stop()
	
	// Should be healthy when running
	if !pm.IsHealthy() {
		t.Error("Pin manager should be healthy when running")
	}
}

func TestPinManager_ConcurrentOperations(t *testing.T) {
	pm, _, _ := createTestPinManager(t)
	
	err := pm.Start()
	if err != nil {
		t.Fatalf("Failed to start pin manager: %v", err)
	}
	defer pm.Stop()
	
	ctx := context.Background()
	numOperations := 10
	
	var wg sync.WaitGroup
	errors := make(chan error, numOperations*2)
	
	// Concurrent pin operations
	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			
			cid := fmt.Sprintf("QmConcurrent%d", i)
			s3Key := fmt.Sprintf("concurrent-key-%d", i)
			
			result, err := pm.Pin(ctx, cid, s3Key, "concurrent-bucket", 1024, 2, PinPriorityNormal)
			if err != nil {
				errors <- err
				return
			}
			
			if !result.Success {
				errors <- fmt.Errorf("pin failed for %s: %v", cid, result.Error)
			}
		}(i)
	}
	
	// Concurrent unpin operations
	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			
			// First pin, then unpin
			cid := fmt.Sprintf("QmConcurrentUnpin%d", i)
			s3Key := fmt.Sprintf("concurrent-unpin-key-%d", i)
			
			_, err := pm.Pin(ctx, cid, s3Key, "concurrent-bucket", 1024, 2, PinPriorityNormal)
			if err != nil {
				errors <- err
				return
			}
			
			result, err := pm.Unpin(ctx, cid, s3Key, "concurrent-bucket", false, PinPriorityNormal)
			if err != nil {
				errors <- err
				return
			}
			
			if !result.Success {
				errors <- fmt.Errorf("unpin failed for %s: %v", cid, result.Error)
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}
	
	// Verify metrics
	metrics := pm.GetMetrics()
	expectedPins := int64(numOperations * 2) // pins + pins before unpins
	if metrics.TotalPinRequests < expectedPins {
		t.Errorf("Expected at least %d pin requests, got %d", expectedPins, metrics.TotalPinRequests)
	}
}

// Benchmark tests

func BenchmarkPinManager_PinOperation(b *testing.B) {
	pm, _, _ := createTestPinManager(&testing.T{})
	
	err := pm.Start()
	if err != nil {
		b.Fatalf("Failed to start pin manager: %v", err)
	}
	defer pm.Stop()
	
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cid := fmt.Sprintf("QmBench%d", i)
			s3Key := fmt.Sprintf("bench-key-%d", i)
			
			_, err := pm.Pin(ctx, cid, s3Key, "bench-bucket", 1024, 2, PinPriorityNormal)
			if err != nil {
				b.Errorf("Pin operation failed: %v", err)
			}
			i++
		}
	})
}

func BenchmarkPinManager_AsyncPinOperation(b *testing.B) {
	pm, _, _ := createTestPinManager(&testing.T{})
	
	err := pm.Start()
	if err != nil {
		b.Fatalf("Failed to start pin manager: %v", err)
	}
	defer pm.Stop()
	
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cid := fmt.Sprintf("QmAsyncBench%d", i)
			s3Key := fmt.Sprintf("async-bench-key-%d", i)
			
			_, err := pm.PinAsync(ctx, cid, s3Key, "async-bench-bucket", 1024, 2, PinPriorityBackground)
			if err != nil {
				b.Errorf("Async pin operation failed: %v", err)
			}
			i++
		}
	})
}

// StoreMappingBatch stores multiple object mappings
func (m *MockMetadataStore) StoreMappingBatch(ctx context.Context, mappings []*ObjectMapping) error {
	if m.failOps {
		return fmt.Errorf("mock batch store failure")
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for _, mapping := range mappings {
		key := mapping.GetPrimaryKey()
		m.mappings[key] = mapping.Clone()
	}
	return nil
}

// GetMappingBatch retrieves multiple object mappings
func (m *MockMetadataStore) GetMappingBatch(ctx context.Context, keys []*S3Key) ([]*ObjectMapping, error) {
	if m.failOps {
		return nil, fmt.Errorf("mock batch get failure")
	}
	
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var results []*ObjectMapping
	for _, key := range keys {
		mapKey := fmt.Sprintf("%s/%s", key.Bucket, key.Key)
		if mapping, exists := m.mappings[mapKey]; exists {
			results = append(results, mapping.Clone())
		}
	}
	
	return results, nil
}

// DeleteMappingBatch deletes multiple object mappings
func (m *MockMetadataStore) DeleteMappingBatch(ctx context.Context, keys []*S3Key) error {
	if m.failOps {
		return fmt.Errorf("mock batch delete failure")
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for _, key := range keys {
		mapKey := fmt.Sprintf("%s/%s", key.Bucket, key.Key)
		delete(m.mappings, mapKey)
	}
	return nil
}

// SearchByPrefix searches for mappings by prefix
func (m *MockMetadataStore) SearchByPrefix(ctx context.Context, bucket, prefix string, limit int) ([]*ObjectMapping, error) {
	if m.failOps {
		return nil, fmt.Errorf("mock search by prefix failure")
	}
	
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var results []*ObjectMapping
	count := 0
	for _, mapping := range m.mappings {
		if mapping.Bucket == bucket && (prefix == "" || len(mapping.S3Key) >= len(prefix) && mapping.S3Key[:len(prefix)] == prefix) {
			results = append(results, mapping.Clone())
			count++
			if limit > 0 && count >= limit {
				break
			}
		}
	}
	
	return results, nil
}

// ListObjectsInBucket lists objects in a bucket
func (m *MockMetadataStore) ListObjectsInBucket(ctx context.Context, bucket string, marker string, limit int) ([]*ObjectMapping, error) {
	if m.failOps {
		return nil, fmt.Errorf("mock list objects failure")
	}
	
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var results []*ObjectMapping
	count := 0
	for _, mapping := range m.mappings {
		if mapping.Bucket == bucket && (marker == "" || mapping.S3Key > marker) {
			results = append(results, mapping.Clone())
			count++
			if limit > 0 && count >= limit {
				break
			}
		}
	}
	
	return results, nil
}

// CreateBucket creates bucket metadata
func (m *MockMetadataStore) CreateBucket(ctx context.Context, bucket string, metadata *BucketMetadata) error {
	if m.failOps {
		return fmt.Errorf("mock create bucket failure")
	}
	return nil
}

// GetBucket retrieves bucket metadata
func (m *MockMetadataStore) GetBucket(ctx context.Context, bucket string) (*BucketMetadata, error) {
	if m.failOps {
		return nil, fmt.Errorf("mock get bucket failure")
	}
	return NewBucketMetadata(bucket, "test-owner"), nil
}

// DeleteBucket deletes bucket metadata
func (m *MockMetadataStore) DeleteBucket(ctx context.Context, bucket string) error {
	if m.failOps {
		return fmt.Errorf("mock delete bucket failure")
	}
	return nil
}

// ListBuckets lists all buckets
func (m *MockMetadataStore) ListBuckets(ctx context.Context) ([]*BucketMetadata, error) {
	if m.failOps {
		return nil, fmt.Errorf("mock list buckets failure")
	}
	return []*BucketMetadata{}, nil
}

// GetStats returns metadata store statistics
func (m *MockMetadataStore) GetStats(ctx context.Context) (*MetadataStats, error) {
	if m.failOps {
		return nil, fmt.Errorf("mock get stats failure")
	}
	
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	return &MetadataStats{
		TotalObjects: int64(len(m.mappings)),
		TotalBuckets: 1,
		HealthScore:  100.0,
	}, nil
}

// GetBucketStats returns statistics for a specific bucket
func (m *MockMetadataStore) GetBucketStats(ctx context.Context, bucket string) (*BucketStats, error) {
	if m.failOps {
		return nil, fmt.Errorf("mock get bucket stats failure")
	}
	
	return &BucketStats{
		BucketName:  bucket,
		ObjectCount: 0,
		TotalSize:   0,
	}, nil
}

// Compact performs compaction
func (m *MockMetadataStore) Compact(ctx context.Context) error {
	if m.failOps {
		return fmt.Errorf("mock compact failure")
	}
	return nil
}

// Backup creates a backup
func (m *MockMetadataStore) Backup(ctx context.Context, path string) error {
	if m.failOps {
		return fmt.Errorf("mock backup failure")
	}
	return nil
}

// Restore restores from backup
func (m *MockMetadataStore) Restore(ctx context.Context, path string) error {
	if m.failOps {
		return fmt.Errorf("mock restore failure")
	}
	return nil
}

// Initialize initializes the store
func (m *MockMetadataStore) Initialize(ctx context.Context) error {
	if m.failOps {
		return fmt.Errorf("mock initialize failure")
	}
	return nil
}

// Shutdown shuts down the store
func (m *MockMetadataStore) Shutdown(ctx context.Context) error {
	if m.failOps {
		return fmt.Errorf("mock shutdown failure")
	}
	return nil
}

// HealthCheck performs a health check
func (m *MockMetadataStore) HealthCheck(ctx context.Context) error {
	if m.failOps {
		return fmt.Errorf("mock health check failure")
	}
	return nil
}

// EnableHealthChecking enables or disables health checking
func (m *MockClusterClient) EnableHealthChecking(enabled bool) {
	// Mock implementation - no-op
}

// ForceHealthCheck triggers an immediate health check
func (m *MockClusterClient) ForceHealthCheck() {
	// Mock implementation - no-op
}

// Shutdown shuts down the cluster client
func (m *MockClusterClient) Shutdown() {
	// Mock implementation - no-op
}

// GetNodeStatusByID returns node status by ID
func (m *MockClusterClient) GetNodeStatusByID(ctx context.Context, nodeID string) (*NodeStatusInfo, error) {
	// Mock implementation
	return &NodeStatusInfo{
		IsHealthy: true,
		Metadata: map[string]interface{}{
			"node_id": nodeID,
		},
	}, nil
}

// GetPeers returns mock peer information
func (m *MockClusterClient) GetPeers() ([]PeerInfo, error) {
	return []PeerInfo{
		{ID: "node1", Connected: true, LastSeen: time.Now()},
		{ID: "node2", Connected: true, LastSeen: time.Now()},
		{ID: "node3", Connected: true, LastSeen: time.Now()},
	}, nil
}