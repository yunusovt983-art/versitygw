package ipfs

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing

type MockClusterClientInterface struct {
	mock.Mock
}

func (m *MockClusterClientInterface) GetPinStatus(cid string) (map[string]PinStatusInfo, error) {
	args := m.Called(cid)
	return args.Get(0).(map[string]PinStatusInfo), args.Error(1)
}

func (m *MockClusterClientInterface) GetPeers() ([]PeerInfo, error) {
	args := m.Called()
	return args.Get(0).([]PeerInfo), args.Error(1)
}

func (m *MockClusterClientInterface) VerifyPin(nodeID, cid string) error {
	args := m.Called(nodeID, cid)
	return args.Error(0)
}

func (m *MockClusterClientInterface) PinOnNode(nodeID, cid string) error {
	args := m.Called(nodeID, cid)
	return args.Error(0)
}

func (m *MockClusterClientInterface) UnpinFromNode(nodeID, cid string) error {
	args := m.Called(nodeID, cid)
	return args.Error(0)
}

func (m *MockClusterClientInterface) PingNode(ctx context.Context, nodeID string) error {
	args := m.Called(ctx, nodeID)
	return args.Error(0)
}

func (m *MockClusterClientInterface) GetNodeStatus(ctx context.Context, nodeID string) (*NodeStatusInfo, error) {
	args := m.Called(ctx, nodeID)
	return args.Get(0).(*NodeStatusInfo), args.Error(1)
}

type MockMetadataStore struct {
	mock.Mock
}

func (m *MockMetadataStore) GetMappingByCID(cid string) (*ObjectMapping, error) {
	args := m.Called(cid)
	return args.Get(0).(*ObjectMapping), args.Error(1)
}

func (m *MockMetadataStore) GetMapping(s3Key, bucket string) (*ObjectMapping, error) {
	args := m.Called(s3Key, bucket)
	return args.Get(0).(*ObjectMapping), args.Error(1)
}

func (m *MockMetadataStore) StoreMapping(mapping *ObjectMapping) error {
	args := m.Called(mapping)
	return args.Error(0)
}

func (m *MockMetadataStore) GetPinsByNodes(nodeIDs []string) ([]PinInfo, error) {
	args := m.Called(nodeIDs)
	return args.Get(0).([]PinInfo), args.Error(1)
}

func (m *MockMetadataStore) GetAllMappings(ctx context.Context) ([]*ObjectMapping, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*ObjectMapping), args.Error(1)
}

func (m *MockMetadataStore) GetMappingsModifiedSince(ctx context.Context, since time.Time) ([]*ObjectMapping, error) {
	args := m.Called(ctx, since)
	return args.Get(0).([]*ObjectMapping), args.Error(1)
}

type MockPinManager struct {
	mock.Mock
}

// Test FaultToleranceManager

func TestNewFaultToleranceManager(t *testing.T) {
	mockCluster := &MockClusterClientInterface{}
	mockMetadata := &MockMetadataStore{}
	mockPinManager := &MockPinManager{}
	logger := logrus.New()

	ftm := NewFaultToleranceManager(mockCluster, mockMetadata, mockPinManager, nil, logger)

	assert.NotNil(t, ftm)
	assert.Equal(t, mockCluster, ftm.clusterClient)
	assert.Equal(t, mockMetadata, ftm.metadataStore)
	assert.Equal(t, mockPinManager, ftm.pinManager)
	assert.NotNil(t, ftm.config)
	assert.NotNil(t, ftm.recoveryQueue)
	assert.NotNil(t, ftm.activeRecovery)
	assert.Len(t, ftm.workers, ftm.config.MaxRecoveryWorkers)
}

func TestFaultToleranceManager_ScheduleRecovery(t *testing.T) {
	mockCluster := &MockClusterClientInterface{}
	mockMetadata := &MockMetadataStore{}
	mockPinManager := &MockPinManager{}
	logger := logrus.New()

	ftm := NewFaultToleranceManager(mockCluster, mockMetadata, mockPinManager, nil, logger)

	task := RecoveryTask{
		Type:     RecoveryTypePinFailure,
		CID:      "QmTest123",
		S3Key:    "test-key",
		Bucket:   "test-bucket",
		Priority: RecoveryPriorityHigh,
	}

	err := ftm.ScheduleRecovery(task)
	assert.NoError(t, err)

	// Verify task was queued
	select {
	case queuedTask := <-ftm.recoveryQueue:
		assert.Equal(t, task.Type, queuedTask.Type)
		assert.Equal(t, task.CID, queuedTask.CID)
		assert.Equal(t, task.S3Key, queuedTask.S3Key)
		assert.Equal(t, task.Bucket, queuedTask.Bucket)
		assert.Equal(t, task.Priority, queuedTask.Priority)
	case <-time.After(1 * time.Second):
		t.Fatal("Task was not queued within timeout")
	}
}

func TestFaultToleranceManager_RecoverFromNodeFailure(t *testing.T) {
	mockCluster := &MockClusterClientInterface{}
	mockMetadata := &MockMetadataStore{}
	mockPinManager := &MockPinManager{}
	logger := logrus.New()

	ftm := NewFaultToleranceManager(mockCluster, mockMetadata, mockPinManager, nil, logger)

	failedNodes := []string{"node1", "node2"}
	affectedPins := []PinInfo{
		{
			CID:         "QmTest123",
			S3Key:       "test-key-1",
			Bucket:      "test-bucket",
			AccessCount: 100,
		},
		{
			CID:         "QmTest456",
			S3Key:       "test-key-2",
			Bucket:      "test-bucket",
			AccessCount: 50,
		},
	}

	mockMetadata.On("GetPinsByNodes", failedNodes).Return(affectedPins, nil)

	err := ftm.RecoverFromNodeFailure(failedNodes)
	assert.NoError(t, err)

	// Verify recovery tasks were scheduled
	tasksScheduled := 0
	timeout := time.After(2 * time.Second)
	for tasksScheduled < len(affectedPins) {
		select {
		case task := <-ftm.recoveryQueue:
			assert.Equal(t, RecoveryTypeNodeFailure, task.Type)
			assert.Contains(t, []string{"QmTest123", "QmTest456"}, task.CID)
			assert.Equal(t, failedNodes, task.FailedNodes)
			tasksScheduled++
		case <-timeout:
			t.Fatalf("Only %d out of %d tasks were scheduled", tasksScheduled, len(affectedPins))
		}
	}

	mockMetadata.AssertExpectations(t)
}

func TestFaultToleranceManager_CheckDataIntegrity(t *testing.T) {
	mockCluster := &MockClusterClientInterface{}
	mockMetadata := &MockMetadataStore{}
	mockPinManager := &MockPinManager{}
	logger := logrus.New()

	ftm := NewFaultToleranceManager(mockCluster, mockMetadata, mockPinManager, nil, logger)

	cid := "QmTest123"
	pinStatus := map[string]PinStatusInfo{
		"node1": {Status: "pinned"},
		"node2": {Status: "pinned"},
		"node3": {Status: "pinned"},
	}

	mapping := &ObjectMapping{
		S3Key:  "test-key",
		Bucket: "test-bucket",
		CID:    cid,
	}

	mockCluster.On("GetPinStatus", cid).Return(pinStatus, nil)
	mockCluster.On("VerifyPin", "node1", cid).Return(nil)
	mockCluster.On("VerifyPin", "node2", cid).Return(assert.AnError) // Corrupted
	mockCluster.On("VerifyPin", "node3", cid).Return(nil)
	mockMetadata.On("GetMappingByCID", cid).Return(mapping, nil)

	err := ftm.CheckDataIntegrity(cid)
	assert.NoError(t, err)

	// Verify recovery task was scheduled for corrupted node
	select {
	case task := <-ftm.recoveryQueue:
		assert.Equal(t, RecoveryTypeDataCorruption, task.Type)
		assert.Equal(t, cid, task.CID)
		assert.Equal(t, []string{"node2"}, task.FailedNodes)
		assert.Equal(t, RecoveryPriorityHigh, task.Priority)
	case <-time.After(1 * time.Second):
		t.Fatal("Recovery task was not scheduled")
	}

	mockCluster.AssertExpectations(t)
	mockMetadata.AssertExpectations(t)
}

func TestFaultToleranceManager_GracefulShutdown(t *testing.T) {
	mockCluster := &MockClusterClientInterface{}
	mockMetadata := &MockMetadataStore{}
	mockPinManager := &MockPinManager{}
	logger := logrus.New()

	config := &FaultToleranceConfig{
		MaxRecoveryWorkers:      2,
		GracefulShutdownTimeout: 1 * time.Second,
	}

	ftm := NewFaultToleranceManager(mockCluster, mockMetadata, mockPinManager, config, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the fault tolerance manager
	err := ftm.Start(ctx)
	assert.NoError(t, err)

	// Stop gracefully
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	err = ftm.Stop(shutdownCtx)
	assert.NoError(t, err)

	// Verify shutdown state
	ftm.mu.RLock()
	assert.True(t, ftm.isShuttingDown)
	ftm.mu.RUnlock()
}

// Test RecoveryWorker

func TestRecoveryWorker_ProcessPinFailureTask(t *testing.T) {
	mockCluster := &MockClusterClientInterface{}
	mockMetadata := &MockMetadataStore{}
	mockPinManager := &MockPinManager{}
	logger := logrus.New()

	config := &FaultToleranceConfig{
		RecoveryTimeout: 30 * time.Second,
	}

	taskQueue := make(chan RecoveryTask, 10)
	worker := NewRecoveryWorker(1, taskQueue, mockCluster, mockMetadata, mockPinManager, config, logger)

	task := RecoveryTask{
		Type:   RecoveryTypePinFailure,
		CID:    "QmTest123",
		S3Key:  "test-key",
		Bucket: "test-bucket",
	}

	pinStatus := map[string]PinStatusInfo{
		"node1": {Status: "pinned"},
		"node2": {Status: "failed"},
	}

	mapping := &ObjectMapping{
		S3Key:             "test-key",
		Bucket:            "test-bucket",
		CID:               "QmTest123",
		ReplicationFactor: 3,
	}

	peers := []PeerInfo{
		{ID: "node1", Connected: true},
		{ID: "node2", Connected: true},
		{ID: "node3", Connected: true},
	}

	mockCluster.On("GetPinStatus", "QmTest123").Return(pinStatus, nil)
	mockMetadata.On("GetMapping", "test-key", "test-bucket").Return(mapping, nil)
	mockCluster.On("GetPeers").Return(peers, nil)
	mockCluster.On("PinOnNode", "node3", "QmTest123").Return(nil)

	ctx := context.Background()
	worker.processTask(ctx, task)

	assert.Equal(t, int64(1), worker.tasksProcessed)
	assert.Equal(t, int64(1), worker.tasksSucceeded)
	assert.Equal(t, int64(0), worker.tasksFailed)

	mockCluster.AssertExpectations(t)
	mockMetadata.AssertExpectations(t)
}

func TestRecoveryWorker_ProcessDataCorruptionTask(t *testing.T) {
	mockCluster := &MockClusterClientInterface{}
	mockMetadata := &MockMetadataStore{}
	mockPinManager := &MockPinManager{}
	logger := logrus.New()

	config := &FaultToleranceConfig{
		RecoveryTimeout: 30 * time.Second,
	}

	taskQueue := make(chan RecoveryTask, 10)
	worker := NewRecoveryWorker(1, taskQueue, mockCluster, mockMetadata, mockPinManager, config, logger)

	task := RecoveryTask{
		Type:        RecoveryTypeDataCorruption,
		CID:         "QmTest123",
		S3Key:       "test-key",
		Bucket:      "test-bucket",
		FailedNodes: []string{"node2"},
	}

	pinStatus := map[string]PinStatusInfo{
		"node1": {Status: "pinned"},
		"node2": {Status: "pinned"}, // Corrupted but still shows as pinned
		"node3": {Status: "pinned"},
	}

	peers := []PeerInfo{
		{ID: "node1", Connected: true},
		{ID: "node2", Connected: true},
		{ID: "node3", Connected: true},
		{ID: "node4", Connected: true},
	}

	mockCluster.On("GetPinStatus", "QmTest123").Return(pinStatus, nil)
	mockCluster.On("VerifyPin", "node1", "QmTest123").Return(nil)
	mockCluster.On("VerifyPin", "node3", "QmTest123").Return(nil)
	mockCluster.On("UnpinFromNode", "node2", "QmTest123").Return(nil)
	mockCluster.On("GetPeers").Return(peers, nil)
	mockCluster.On("PinOnNode", "node4", "QmTest123").Return(nil)

	ctx := context.Background()
	worker.processTask(ctx, task)

	assert.Equal(t, int64(1), worker.tasksProcessed)
	assert.Equal(t, int64(1), worker.tasksSucceeded)
	assert.Equal(t, int64(0), worker.tasksFailed)

	mockCluster.AssertExpectations(t)
}

// Test HealthChecker

func TestHealthChecker_NodeHealthTracking(t *testing.T) {
	mockCluster := &MockClusterClientInterface{}
	logger := logrus.New()

	hc := NewHealthChecker(mockCluster, 1*time.Second, logger)

	peers := []PeerInfo{
		{ID: "node1", Connected: true},
		{ID: "node2", Connected: true},
	}

	mockCluster.On("GetPeers").Return(peers, nil)
	mockCluster.On("PingNode", mock.Anything, "node1").Return(nil)
	mockCluster.On("GetNodeStatus", mock.Anything, "node1").Return(&NodeStatusInfo{IsHealthy: true}, nil)
	mockCluster.On("PingNode", mock.Anything, "node2").Return(assert.AnError)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Perform health check
	hc.performHealthCheck(ctx)

	// Check node health
	node1Health, exists := hc.GetNodeHealth("node1")
	require.True(t, exists)
	assert.True(t, node1Health.IsHealthy)
	assert.Equal(t, NodeStatusHealthy, node1Health.Status)

	node2Health, exists := hc.GetNodeHealth("node2")
	require.True(t, exists)
	assert.False(t, node2Health.IsHealthy)
	assert.Equal(t, 1, node2Health.ConsecutiveFails)

	mockCluster.AssertExpectations(t)
}

func TestHealthChecker_ClusterHealthSummary(t *testing.T) {
	mockCluster := &MockClusterClientInterface{}
	logger := logrus.New()

	hc := NewHealthChecker(mockCluster, 1*time.Second, logger)

	// Manually set node health for testing
	hc.mu.Lock()
	hc.nodeHealth["node1"] = &NodeHealth{
		NodeID:    "node1",
		IsHealthy: true,
		Status:    NodeStatusHealthy,
	}
	hc.nodeHealth["node2"] = &NodeHealth{
		NodeID:    "node2",
		IsHealthy: false,
		Status:    NodeStatusUnhealthy,
	}
	hc.nodeHealth["node3"] = &NodeHealth{
		NodeID:    "node3",
		IsHealthy: true,
		Status:    NodeStatusDegraded,
	}
	hc.mu.Unlock()

	clusterHealth := hc.GetClusterHealth()

	assert.Equal(t, 3, clusterHealth.TotalNodes)
	assert.Equal(t, 1, clusterHealth.HealthyNodes)
	assert.Equal(t, 1, clusterHealth.UnhealthyNodes)
	assert.Equal(t, 1, clusterHealth.DegradedNodes)
	assert.Equal(t, 0, clusterHealth.UnknownNodes)
	assert.InDelta(t, 33.33, clusterHealth.HealthPercentage, 0.01)
	assert.Equal(t, ClusterStatusUnhealthy, clusterHealth.OverallStatus)
}

// Benchmark tests

func BenchmarkFaultToleranceManager_ScheduleRecovery(b *testing.B) {
	mockCluster := &MockClusterClientInterface{}
	mockMetadata := &MockMetadataStore{}
	mockPinManager := &MockPinManager{}
	logger := logrus.New()

	ftm := NewFaultToleranceManager(mockCluster, mockMetadata, mockPinManager, nil, logger)

	task := RecoveryTask{
		Type:     RecoveryTypePinFailure,
		CID:      "QmTest123",
		S3Key:    "test-key",
		Bucket:   "test-bucket",
		Priority: RecoveryPriorityNormal,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := ftm.ScheduleRecovery(task)
		if err != nil {
			b.Fatal(err)
		}
		// Drain the queue to prevent blocking
		select {
		case <-ftm.recoveryQueue:
		default:
		}
	}
}

func BenchmarkHealthChecker_GetClusterHealth(b *testing.B) {
	mockCluster := &MockClusterClientInterface{}
	logger := logrus.New()

	hc := NewHealthChecker(mockCluster, 1*time.Second, logger)

	// Set up test data
	hc.mu.Lock()
	for i := 0; i < 1000; i++ {
		nodeID := fmt.Sprintf("node%d", i)
		hc.nodeHealth[nodeID] = &NodeHealth{
			NodeID:    nodeID,
			IsHealthy: i%2 == 0,
			Status:    NodeStatusHealthy,
		}
	}
	hc.mu.Unlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hc.GetClusterHealth()
	}
}

// Helper types for testing