package ipfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// FaultToleranceIntegrationTestSuite tests the complete fault tolerance system
type FaultToleranceIntegrationTestSuite struct {
	suite.Suite
	tempDir           string
	mockCluster       *MockClusterClientInterface
	mockMetadata      *MockMetadataStore
	mockPinManager    *MockPinManager
	ftManager         *FaultToleranceManager
	backupManager     *BackupRestoreManager
	healthChecker     *HealthChecker
	logger            *logrus.Logger
}

func (suite *FaultToleranceIntegrationTestSuite) SetupSuite() {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "fault_tolerance_integration")
	require.NoError(suite.T(), err)
	suite.tempDir = tempDir

	// Initialize mocks
	suite.mockCluster = &MockClusterClientInterface{}
	suite.mockMetadata = &MockMetadataStore{}
	suite.mockPinManager = &MockPinManager{}
	suite.logger = logrus.New()
	suite.logger.SetLevel(logrus.DebugLevel)

	// Initialize fault tolerance manager
	ftConfig := &FaultToleranceConfig{
		MaxRecoveryWorkers:      2,
		RecoveryTimeout:         10 * time.Second,
		HealthCheckInterval:     1 * time.Second,
		IntegrityCheckInterval:  5 * time.Second,
		MaxRetryAttempts:        3,
		BackoffMultiplier:       2.0,
		SplitBrainThreshold:     2,
		GracefulShutdownTimeout: 5 * time.Second,
	}

	suite.ftManager = NewFaultToleranceManager(
		suite.mockCluster,
		suite.mockMetadata,
		suite.mockPinManager,
		ftConfig,
		suite.logger,
	)

	// Initialize backup manager
	backupConfig := &BackupConfig{
		BackupDirectory:    filepath.Join(suite.tempDir, "backups"),
		BackupInterval:     1 * time.Hour,
		RetentionPeriod:    24 * time.Hour,
		CompressionEnabled: true,
		IncrementalBackup:  true,
		VerifyBackup:       true,
	}

	suite.backupManager = NewBackupRestoreManager(
		suite.mockMetadata,
		backupConfig,
		suite.logger,
	)

	// Initialize health checker
	suite.healthChecker = NewHealthChecker(
		suite.mockCluster,
		1*time.Second,
		suite.logger,
	)
}

func (suite *FaultToleranceIntegrationTestSuite) TearDownSuite() {
	os.RemoveAll(suite.tempDir)
}

func (suite *FaultToleranceIntegrationTestSuite) TestCompleteNodeFailureRecoveryScenario() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Setup: 3-node cluster with replicated data
	initialPeers := []PeerInfo{
		{ID: "node1", Connected: true},
		{ID: "node2", Connected: true},
		{ID: "node3", Connected: true},
	}

	testCID := "QmTestFailureRecovery123"
	testMapping := &ObjectMapping{
		S3Key:             "test-failure-key",
		Bucket:            "test-bucket",
		CID:               testCID,
		ReplicationFactor: 3,
		Size:              1024,
	}

	// Initial pin status - all nodes have the pin
	initialPinStatus := map[string]PinStatusInfo{
		"node1": {Status: "pinned"},
		"node2": {Status: "pinned"},
		"node3": {Status: "pinned"},
	}

	// Setup mock expectations for initial state
	suite.mockCluster.On("GetPeers").Return(initialPeers, nil).Times(3)
	suite.mockCluster.On("PingNode", mock.Anything, "node1").Return(nil).Times(3)
	suite.mockCluster.On("PingNode", mock.Anything, "node2").Return(nil).Times(3)
	suite.mockCluster.On("PingNode", mock.Anything, "node3").Return(nil).Times(3)
	suite.mockCluster.On("GetNodeStatus", mock.Anything, mock.Anything).Return(&NodeStatusInfo{IsHealthy: true}, nil).Times(9)

	// Start fault tolerance system
	err := suite.ftManager.Start(ctx)
	require.NoError(suite.T(), err)

	// Wait for initial health check
	time.Sleep(2 * time.Second)

	// Verify all nodes are initially healthy
	clusterHealth := suite.ftManager.healthChecker.GetClusterHealth()
	assert.Equal(suite.T(), 3, clusterHealth.TotalNodes)
	assert.Equal(suite.T(), 3, clusterHealth.HealthyNodes)

	// Simulate node2 failure
	failedPeers := []PeerInfo{
		{ID: "node1", Connected: true},
		{ID: "node3", Connected: true},
	}

	// Update mock expectations for node failure
	suite.mockCluster.ExpectedCalls = nil // Clear previous expectations
	suite.mockCluster.On("GetPeers").Return(failedPeers, nil)
	suite.mockCluster.On("PingNode", mock.Anything, "node1").Return(nil)
	suite.mockCluster.On("PingNode", mock.Anything, "node3").Return(nil)
	suite.mockCluster.On("GetNodeStatus", mock.Anything, "node1").Return(&NodeStatusInfo{IsHealthy: true}, nil)
	suite.mockCluster.On("GetNodeStatus", mock.Anything, "node3").Return(&NodeStatusInfo{IsHealthy: true}, nil)

	// Setup recovery expectations
	affectedPins := []PinInfo{
		{
			CID:         testCID,
			S3Key:       testMapping.S3Key,
			Bucket:      testMapping.Bucket,
			AccessCount: 100,
		},
	}

	suite.mockMetadata.On("GetPinsByNodes", []string{"node2"}).Return(affectedPins, nil)
	suite.mockCluster.On("GetPinStatus", testCID).Return(map[string]PinStatusInfo{
		"node1": {Status: "pinned"},
		"node3": {Status: "pinned"},
	}, nil)
	suite.mockMetadata.On("GetMapping", testMapping.S3Key, testMapping.Bucket).Return(testMapping, nil)
	suite.mockCluster.On("GetPeers").Return(failedPeers, nil)
	suite.mockCluster.On("PinOnNode", mock.Anything, testCID).Return(nil)

	// Trigger node failure recovery
	err = suite.ftManager.RecoverFromNodeFailure([]string{"node2"})
	assert.NoError(suite.T(), err)

	// Wait for recovery to process
	time.Sleep(3 * time.Second)

	// Verify recovery task was processed
	stats := suite.ftManager.workers[0].GetStatistics()
	assert.Greater(suite.T(), stats.TasksProcessed, int64(0))

	// Stop fault tolerance system
	err = suite.ftManager.Stop(ctx)
	assert.NoError(suite.T(), err)
}

func (suite *FaultToleranceIntegrationTestSuite) TestDataCorruptionDetectionAndRecovery() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	testCID := "QmTestCorruption456"
	testMapping := &ObjectMapping{
		S3Key:  "corrupted-key",
		Bucket: "test-bucket",
		CID:    testCID,
	}

	// Setup pin status with one corrupted node
	pinStatus := map[string]PinStatusInfo{
		"node1": {Status: "pinned"},
		"node2": {Status: "pinned"}, // This will be corrupted
		"node3": {Status: "pinned"},
	}

	peers := []PeerInfo{
		{ID: "node1", Connected: true},
		{ID: "node2", Connected: true},
		{ID: "node3", Connected: true},
		{ID: "node4", Connected: true}, // Available for re-pinning
	}

	// Setup mock expectations
	suite.mockCluster.On("GetPinStatus", testCID).Return(pinStatus, nil)
	suite.mockCluster.On("VerifyPin", "node1", testCID).Return(nil)
	suite.mockCluster.On("VerifyPin", "node2", testCID).Return(assert.AnError) // Corrupted
	suite.mockCluster.On("VerifyPin", "node3", testCID).Return(nil)
	suite.mockMetadata.On("GetMappingByCID", testCID).Return(testMapping, nil)
	suite.mockCluster.On("UnpinFromNode", "node2", testCID).Return(nil)
	suite.mockCluster.On("GetPeers").Return(peers, nil)
	suite.mockCluster.On("PinOnNode", "node4", testCID).Return(nil)

	// Start fault tolerance system
	err := suite.ftManager.Start(ctx)
	require.NoError(suite.T(), err)

	// Check data integrity
	err = suite.ftManager.CheckDataIntegrity(testCID)
	assert.NoError(suite.T(), err)

	// Wait for recovery to process
	time.Sleep(2 * time.Second)

	// Stop system
	err = suite.ftManager.Stop(ctx)
	assert.NoError(suite.T(), err)

	// Verify recovery was attempted
	suite.mockCluster.AssertCalled(suite.T(), "UnpinFromNode", "node2", testCID)
	suite.mockCluster.AssertCalled(suite.T(), "PinOnNode", "node4", testCID)
}

func (suite *FaultToleranceIntegrationTestSuite) TestBackupAndRestoreIntegration() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Create test metadata
	testMappings := []*ObjectMapping{
		{
			S3Key:       "backup-key-1",
			Bucket:      "backup-bucket",
			CID:         "QmBackup123",
			Size:        1024,
			ContentType: "text/plain",
			CreatedAt:   time.Now(),
		},
		{
			S3Key:       "backup-key-2",
			Bucket:      "backup-bucket",
			CID:         "QmBackup456",
			Size:        2048,
			ContentType: "application/json",
			CreatedAt:   time.Now(),
		},
	}

	// Setup backup expectations
	suite.mockMetadata.On("GetAllMappings", mock.Anything).Return(testMappings, nil)

	// Start backup manager
	err := suite.backupManager.Start(ctx)
	require.NoError(suite.T(), err)

	// Create backup
	err = suite.backupManager.CreateBackup(ctx, BackupTypeFull)
	assert.NoError(suite.T(), err)

	// Verify backup was created
	backups, err := suite.backupManager.ListBackups()
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), backups, 1)
	assert.Equal(suite.T(), BackupTypeFull, backups[0].Type)
	assert.Equal(suite.T(), int64(2), backups[0].RecordCount)

	// Setup restore expectations
	suite.mockMetadata.On("GetMapping", "backup-key-1", "backup-bucket").Return(nil, assert.AnError)
	suite.mockMetadata.On("GetMapping", "backup-key-2", "backup-bucket").Return(nil, assert.AnError)
	suite.mockMetadata.On("StoreMapping", mock.MatchedBy(func(mapping *ObjectMapping) bool {
		return mapping.S3Key == "backup-key-1" || mapping.S3Key == "backup-key-2"
	})).Return(nil).Times(2)

	// Restore from backup
	restoreOptions := &RestoreOptions{
		BackupPath:        backups[0].Path,
		VerifyIntegrity:   true,
		DryRun:            false,
		OverwriteExisting: false,
	}

	err = suite.backupManager.RestoreBackup(ctx, restoreOptions)
	assert.NoError(suite.T(), err)

	// Stop backup manager
	err = suite.backupManager.Stop(ctx)
	assert.NoError(suite.T(), err)

	// Verify statistics
	stats := suite.backupManager.GetBackupStatistics()
	assert.Equal(suite.T(), int64(1), stats.TotalBackups)
	assert.Equal(suite.T(), int64(1), stats.SuccessfulBackups)
	assert.Equal(suite.T(), int64(0), stats.FailedBackups)
}

func (suite *FaultToleranceIntegrationTestSuite) TestHealthMonitoringWithCallbacks() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Track callback invocations
	nodeFailures := make([]string, 0)
	nodeRecoveries := make([]string, 0)

	suite.healthChecker.SetNodeFailureCallback(func(nodeID string, health *NodeHealth) {
		nodeFailures = append(nodeFailures, nodeID)
	})

	suite.healthChecker.SetNodeRecoveryCallback(func(nodeID string, health *NodeHealth) {
		nodeRecoveries = append(nodeRecoveries, nodeID)
	})

	// Initial healthy state
	healthyPeers := []PeerInfo{
		{ID: "node1", Connected: true},
		{ID: "node2", Connected: true},
	}

	suite.mockCluster.On("GetPeers").Return(healthyPeers, nil).Once()
	suite.mockCluster.On("PingNode", mock.Anything, "node1").Return(nil).Once()
	suite.mockCluster.On("PingNode", mock.Anything, "node2").Return(nil).Once()
	suite.mockCluster.On("GetNodeStatus", mock.Anything, "node1").Return(&NodeStatusInfo{IsHealthy: true}, nil).Once()
	suite.mockCluster.On("GetNodeStatus", mock.Anything, "node2").Return(&NodeStatusInfo{IsHealthy: true}, nil).Once()

	// Start health checker
	go suite.healthChecker.Start(ctx)

	// Wait for initial health check
	time.Sleep(2 * time.Second)

	// Simulate node2 failure
	suite.mockCluster.On("GetPeers").Return(healthyPeers, nil).Once()
	suite.mockCluster.On("PingNode", mock.Anything, "node1").Return(nil).Once()
	suite.mockCluster.On("PingNode", mock.Anything, "node2").Return(assert.AnError).Once() // Failed
	suite.mockCluster.On("GetNodeStatus", mock.Anything, "node1").Return(&NodeStatusInfo{IsHealthy: true}, nil).Once()

	// Wait for failure detection
	time.Sleep(2 * time.Second)

	// Simulate node2 recovery
	suite.mockCluster.On("GetPeers").Return(healthyPeers, nil).Once()
	suite.mockCluster.On("PingNode", mock.Anything, "node1").Return(nil).Once()
	suite.mockCluster.On("PingNode", mock.Anything, "node2").Return(nil).Once() // Recovered
	suite.mockCluster.On("GetNodeStatus", mock.Anything, "node1").Return(&NodeStatusInfo{IsHealthy: true}, nil).Once()
	suite.mockCluster.On("GetNodeStatus", mock.Anything, "node2").Return(&NodeStatusInfo{IsHealthy: true}, nil).Once()

	// Wait for recovery detection
	time.Sleep(2 * time.Second)

	suite.healthChecker.Stop()

	// Verify callbacks were invoked
	assert.Contains(suite.T(), nodeFailures, "node2")
	assert.Contains(suite.T(), nodeRecoveries, "node2")
}

func (suite *FaultToleranceIntegrationTestSuite) TestGracefulShutdownWithActiveRecoveries() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start fault tolerance system
	err := suite.ftManager.Start(ctx)
	require.NoError(suite.T(), err)

	// Schedule multiple recovery tasks
	for i := 0; i < 5; i++ {
		task := RecoveryTask{
			Type:     RecoveryTypePinFailure,
			CID:      fmt.Sprintf("QmTest%d", i),
			S3Key:    fmt.Sprintf("test-key-%d", i),
			Bucket:   "test-bucket",
			Priority: RecoveryPriorityNormal,
		}

		err := suite.ftManager.ScheduleRecovery(task)
		assert.NoError(suite.T(), err)
	}

	// Give some time for tasks to start processing
	time.Sleep(1 * time.Second)

	// Initiate graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	err = suite.ftManager.Stop(shutdownCtx)
	assert.NoError(suite.T(), err)

	// Verify system shut down gracefully
	suite.ftManager.mu.RLock()
	assert.True(suite.T(), suite.ftManager.isShuttingDown)
	suite.ftManager.mu.RUnlock()
}

func (suite *FaultToleranceIntegrationTestSuite) TestEndToEndDisasterRecovery() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Scenario: Complete cluster failure, restore from backup
	
	// 1. Create initial backup
	testMappings := []*ObjectMapping{
		{
			S3Key:  "disaster-key-1",
			Bucket: "disaster-bucket",
			CID:    "QmDisaster123",
			Size:   1024,
		},
		{
			S3Key:  "disaster-key-2",
			Bucket: "disaster-bucket",
			CID:    "QmDisaster456",
			Size:   2048,
		},
	}

	suite.mockMetadata.On("GetAllMappings", mock.Anything).Return(testMappings, nil)

	err := suite.backupManager.Start(ctx)
	require.NoError(suite.T(), err)

	err = suite.backupManager.CreateBackup(ctx, BackupTypeFull)
	assert.NoError(suite.T(), err)

	// 2. Simulate complete cluster failure (no peers available)
	suite.mockCluster.On("GetPeers").Return([]PeerInfo{}, nil)

	err = suite.ftManager.Start(ctx)
	require.NoError(suite.T(), err)

	// Wait for health check to detect no peers
	time.Sleep(2 * time.Second)

	clusterHealth := suite.ftManager.healthChecker.GetClusterHealth()
	assert.Equal(suite.T(), 0, clusterHealth.TotalNodes)

	// 3. Restore from backup after cluster recovery
	suite.mockMetadata.On("GetMapping", "disaster-key-1", "disaster-bucket").Return(nil, assert.AnError)
	suite.mockMetadata.On("GetMapping", "disaster-key-2", "disaster-bucket").Return(nil, assert.AnError)
	suite.mockMetadata.On("StoreMapping", mock.MatchedBy(func(mapping *ObjectMapping) bool {
		return mapping.S3Key == "disaster-key-1" || mapping.S3Key == "disaster-key-2"
	})).Return(nil).Times(2)

	backups, err := suite.backupManager.ListBackups()
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), backups, 1)

	restoreOptions := &RestoreOptions{
		BackupPath:        backups[0].Path,
		VerifyIntegrity:   true,
		DryRun:            false,
		OverwriteExisting: true,
	}

	err = suite.backupManager.RestoreBackup(ctx, restoreOptions)
	assert.NoError(suite.T(), err)

	// 4. Cleanup
	err = suite.ftManager.Stop(ctx)
	assert.NoError(suite.T(), err)

	err = suite.backupManager.Stop(ctx)
	assert.NoError(suite.T(), err)

	// Verify disaster recovery completed successfully
	suite.mockMetadata.AssertCalled(suite.T(), "StoreMapping", mock.Anything)
}

// Run the integration test suite
func TestFaultToleranceIntegrationSuite(t *testing.T) {
	suite.Run(t, new(FaultToleranceIntegrationTestSuite))
}

// Additional helper functions for integration testing

func createTestClusterState(nodeCount int, healthyCount int) ([]PeerInfo, map[string]*NodeHealth) {
	peers := make([]PeerInfo, nodeCount)
	health := make(map[string]*NodeHealth)

	for i := 0; i < nodeCount; i++ {
		nodeID := fmt.Sprintf("node%d", i+1)
		isHealthy := i < healthyCount

		peers[i] = PeerInfo{
			ID:        nodeID,
			Connected: isHealthy,
			LastSeen:  time.Now(),
		}

		status := NodeStatusUnhealthy
		if isHealthy {
			status = NodeStatusHealthy
		}

		health[nodeID] = &NodeHealth{
			NodeID:          nodeID,
			IsHealthy:       isHealthy,
			LastSeen:        time.Now(),
			LastHealthCheck: time.Now(),
			Status:          status,
		}
	}

	return peers, health
}

func simulateNetworkPartition(totalNodes int, partition1Size int) ([]PeerInfo, []PeerInfo) {
	partition1 := make([]PeerInfo, partition1Size)
	partition2 := make([]PeerInfo, totalNodes-partition1Size)

	for i := 0; i < partition1Size; i++ {
		partition1[i] = PeerInfo{
			ID:        fmt.Sprintf("node%d", i+1),
			Connected: true,
			LastSeen:  time.Now(),
		}
	}

	for i := 0; i < totalNodes-partition1Size; i++ {
		partition2[i] = PeerInfo{
			ID:        fmt.Sprintf("node%d", partition1Size+i+1),
			Connected: true,
			LastSeen:  time.Now(),
		}
	}

	return partition1, partition2
}