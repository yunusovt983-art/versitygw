package ipfs

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// IntelligentReplicationIntegrationTestSuite tests the complete intelligent replication system
type IntelligentReplicationIntegrationTestSuite struct {
	suite.Suite
	
	// System components
	replicaManager   *ReplicaManager
	accessAnalyzer   *AccessPatternAnalyzer
	geoManager       *GeographicManager
	policyEngine     *ReplicationPolicyEngine
	rebalancer       *ReplicationRebalancer
	optimizer        *ReplicationOptimizer
	
	// Mock dependencies
	mockClusterClient *MockClusterClient
	
	// Test configuration
	config           *ReplicaConfig
}

// SetupSuite initializes the test suite
func (suite *IntelligentReplicationIntegrationTestSuite) SetupSuite() {
	// Create test configuration
	suite.config = &ReplicaConfig{
		MinReplicas:                 2,
		MaxReplicas:                 10,
		DefaultReplicas:             3,
		AnalysisInterval:            1 * time.Second,  // Fast for testing
		RebalanceInterval:           2 * time.Second,  // Fast for testing
		HighAccessThreshold:         1000,
		LowAccessThreshold:          10,
		GeographicSpreadFactor:      0.2,
		MaxConcurrentRebalance:      3,
		RebalanceBatchSize:          100,
	}
	
	// Create mock cluster client
	suite.mockClusterClient = &MockClusterClient{}
	
	// Initialize system components
	suite.replicaManager = NewReplicaManager(suite.mockClusterClient, suite.config)
	suite.accessAnalyzer = suite.replicaManager.accessAnalyzer
	suite.geoManager = suite.replicaManager.geoManager
	suite.policyEngine = suite.replicaManager.policyEngine
	suite.rebalancer = suite.replicaManager.rebalancer
	suite.optimizer = NewReplicationOptimizer(
		suite.replicaManager,
		suite.accessAnalyzer,
		suite.geoManager,
		suite.policyEngine,
	)
	
	// Setup mock cluster state
	suite.setupMockClusterState()
	
	// Setup geographic data
	suite.setupGeographicData()
}

// TearDownSuite cleans up the test suite
func (suite *IntelligentReplicationIntegrationTestSuite) TearDownSuite() {
	if suite.replicaManager != nil {
		suite.replicaManager.Shutdown()
	}
	if suite.optimizer != nil {
		// Optimizer doesn't have shutdown method in this implementation
	}
}

// setupMockClusterState sets up the mock cluster state
func (suite *IntelligentReplicationIntegrationTestSuite) setupMockClusterState() {
	clusterState := &cluster.ClusterState{
		Peers: map[string]*cluster.PeerInfo{
			"peer-us-east-1":  {ID: "peer-us-east-1", Region: "us-east"},
			"peer-us-east-2":  {ID: "peer-us-east-2", Region: "us-east"},
			"peer-us-west-1":  {ID: "peer-us-west-1", Region: "us-west"},
			"peer-us-west-2":  {ID: "peer-us-west-2", Region: "us-west"},
			"peer-eu-west-1":  {ID: "peer-eu-west-1", Region: "eu-west"},
			"peer-eu-west-2":  {ID: "peer-eu-west-2", Region: "eu-west"},
			"peer-asia-pac-1": {ID: "peer-asia-pac-1", Region: "asia-pacific"},
		},
		AvailableRegions: []string{"us-east", "us-west", "eu-west", "asia-pacific"},
	}
	
	suite.mockClusterClient.On("GetClusterState").Return(clusterState, nil)
}

// setupGeographicData sets up geographic location data for nodes
func (suite *IntelligentReplicationIntegrationTestSuite) setupGeographicData() {
	locations := map[string]*NodeLocation{
		"peer-us-east-1": {
			NodeID:          "peer-us-east-1",
			Region:          "us-east",
			Country:         "US",
			City:            "New York",
			Latitude:        40.7128,
			Longitude:       -74.0060,
			Latency:         10 * time.Millisecond,
			Bandwidth:       1000.0,
			StorageCapacity: 1000 * 1024 * 1024 * 1024, // 1TB
			StorageUsed:     100 * 1024 * 1024 * 1024,  // 100GB
			CPULoad:         0.3,
			NetworkLoad:     0.2,
			Uptime:          0.999,
			LastSeen:        time.Now(),
			IsHealthy:       true,
		},
		"peer-us-east-2": {
			NodeID:          "peer-us-east-2",
			Region:          "us-east",
			Country:         "US",
			City:            "Boston",
			Latitude:        42.3601,
			Longitude:       -71.0589,
			Latency:         12 * time.Millisecond,
			Bandwidth:       800.0,
			StorageCapacity: 1000 * 1024 * 1024 * 1024,
			StorageUsed:     200 * 1024 * 1024 * 1024,
			CPULoad:         0.4,
			NetworkLoad:     0.3,
			Uptime:          0.998,
			LastSeen:        time.Now(),
			IsHealthy:       true,
		},
		"peer-us-west-1": {
			NodeID:          "peer-us-west-1",
			Region:          "us-west",
			Country:         "US",
			City:            "San Francisco",
			Latitude:        37.7749,
			Longitude:       -122.4194,
			Latency:         15 * time.Millisecond,
			Bandwidth:       1200.0,
			StorageCapacity: 2000 * 1024 * 1024 * 1024,
			StorageUsed:     300 * 1024 * 1024 * 1024,
			CPULoad:         0.2,
			NetworkLoad:     0.1,
			Uptime:          0.9995,
			LastSeen:        time.Now(),
			IsHealthy:       true,
		},
		"peer-us-west-2": {
			NodeID:          "peer-us-west-2",
			Region:          "us-west",
			Country:         "US",
			City:            "Los Angeles",
			Latitude:        34.0522,
			Longitude:       -118.2437,
			Latency:         18 * time.Millisecond,
			Bandwidth:       900.0,
			StorageCapacity: 1500 * 1024 * 1024 * 1024,
			StorageUsed:     400 * 1024 * 1024 * 1024,
			CPULoad:         0.5,
			NetworkLoad:     0.4,
			Uptime:          0.997,
			LastSeen:        time.Now(),
			IsHealthy:       true,
		},
		"peer-eu-west-1": {
			NodeID:          "peer-eu-west-1",
			Region:          "eu-west",
			Country:         "UK",
			City:            "London",
			Latitude:        51.5074,
			Longitude:       -0.1278,
			Latency:         25 * time.Millisecond,
			Bandwidth:       800.0,
			StorageCapacity: 1200 * 1024 * 1024 * 1024,
			StorageUsed:     250 * 1024 * 1024 * 1024,
			CPULoad:         0.35,
			NetworkLoad:     0.25,
			Uptime:          0.998,
			LastSeen:        time.Now(),
			IsHealthy:       true,
		},
		"peer-eu-west-2": {
			NodeID:          "peer-eu-west-2",
			Region:          "eu-west",
			Country:         "Germany",
			City:            "Frankfurt",
			Latitude:        50.1109,
			Longitude:       8.6821,
			Latency:         22 * time.Millisecond,
			Bandwidth:       1000.0,
			StorageCapacity: 1800 * 1024 * 1024 * 1024,
			StorageUsed:     350 * 1024 * 1024 * 1024,
			CPULoad:         0.25,
			NetworkLoad:     0.15,
			Uptime:          0.9992,
			LastSeen:        time.Now(),
			IsHealthy:       true,
		},
		"peer-asia-pac-1": {
			NodeID:          "peer-asia-pac-1",
			Region:          "asia-pacific",
			Country:         "Japan",
			City:            "Tokyo",
			Latitude:        35.6762,
			Longitude:       139.6503,
			Latency:         35 * time.Millisecond,
			Bandwidth:       700.0,
			StorageCapacity: 1000 * 1024 * 1024 * 1024,
			StorageUsed:     150 * 1024 * 1024 * 1024,
			CPULoad:         0.3,
			NetworkLoad:     0.2,
			Uptime:          0.996,
			LastSeen:        time.Now(),
			IsHealthy:       true,
		},
	}
	
	for nodeID, location := range locations {
		suite.geoManager.UpdateNodeLocation(nodeID, location)
	}
}

// TestCompleteReplicationWorkflow tests the complete intelligent replication workflow
func (suite *IntelligentReplicationIntegrationTestSuite) TestCompleteReplicationWorkflow() {
	// Test CID
	testCID := "QmTestCIDForIntelligentReplication123456789"
	
	// Step 1: Simulate access patterns over time
	suite.simulateAccessPatterns(testCID)
	
	// Step 2: Analyze access patterns
	accessStats, err := suite.accessAnalyzer.GetAccessStats(testCID)
	suite.Require().NoError(err)
	suite.Assert().NotNil(accessStats)
	suite.Assert().Equal(testCID, accessStats.CID)
	suite.Assert().Greater(accessStats.TotalAccesses, int64(0))
	
	// Step 3: Perform analysis and optimization
	err = suite.replicaManager.AnalyzeAndOptimize(testCID, accessStats)
	suite.Require().NoError(err)
	
	// Step 4: Verify replication state was created
	replicationState, err := suite.replicaManager.GetReplicationState(testCID)
	suite.Require().NoError(err)
	suite.Assert().Equal(testCID, replicationState.CID)
	suite.Assert().NotNil(replicationState.AccessPattern)
	suite.Assert().GreaterOrEqual(replicationState.OptimalReplicas, suite.config.MinReplicas)
	suite.Assert().LessOrEqual(replicationState.OptimalReplicas, suite.config.MaxReplicas)
	
	// Step 5: Test geographic distribution optimization
	suite.testGeographicOptimization(testCID, replicationState)
	
	// Step 6: Test policy-based optimization
	suite.testPolicyBasedOptimization(testCID)
	
	// Step 7: Test rebalancing
	suite.testRebalancing(testCID)
	
	// Step 8: Test full optimization
	suite.testFullOptimization(testCID)
}

// simulateAccessPatterns simulates realistic access patterns
func (suite *IntelligentReplicationIntegrationTestSuite) simulateAccessPatterns(cid string) {
	// Simulate access from different regions over time
	accessEvents := []struct {
		peerID       string
		region       string
		count        int
		latency      time.Duration
		transferSize int64
	}{
		{"peer-us-east-1", "us-east", 50, 10 * time.Millisecond, 1024 * 1024},
		{"peer-us-east-2", "us-east", 30, 12 * time.Millisecond, 1024 * 1024},
		{"peer-us-west-1", "us-west", 40, 15 * time.Millisecond, 1024 * 1024},
		{"peer-us-west-2", "us-west", 25, 18 * time.Millisecond, 1024 * 1024},
		{"peer-eu-west-1", "eu-west", 35, 25 * time.Millisecond, 1024 * 1024},
		{"peer-eu-west-2", "eu-west", 20, 22 * time.Millisecond, 1024 * 1024},
		{"peer-asia-pac-1", "asia-pacific", 15, 35 * time.Millisecond, 1024 * 1024},
	}
	
	for _, event := range accessEvents {
		for i := 0; i < event.count; i++ {
			suite.accessAnalyzer.RecordAccess(
				cid,
				event.peerID,
				event.region,
				event.latency,
				event.transferSize,
				true, // success
			)
		}
	}
}

// testGeographicOptimization tests geographic distribution optimization
func (suite *IntelligentReplicationIntegrationTestSuite) testGeographicOptimization(cid string, state *ReplicationState) {
	// Test optimal node selection for different strategies
	strategies := []PlacementStrategy{
		PlacementBalanced,
		PlacementLatency,
		PlacementCapacity,
		PlacementCustom,
	}
	
	for _, strategy := range strategies {
		optimalNodes, err := suite.geoManager.GetOptimalNodes(
			state.AccessPattern,
			state.OptimalReplicas,
			strategy,
		)
		
		suite.Assert().NoError(err)
		suite.Assert().LessOrEqual(len(optimalNodes), state.OptimalReplicas)
		suite.Assert().Greater(len(optimalNodes), 0)
		
		// Validate placement
		validation, err := suite.geoManager.ValidatePlacement(optimalNodes)
		suite.Assert().NoError(err)
		suite.Assert().NotNil(validation)
		
		// For balanced strategy, we should have good geographic distribution
		if strategy == PlacementBalanced {
			suite.Assert().GreaterOrEqual(validation.Metrics["unique_regions"], 2.0)
		}
	}
}

// testPolicyBasedOptimization tests policy-based optimization
func (suite *IntelligentReplicationIntegrationTestSuite) testPolicyBasedOptimization(cid string) {
	// Test different object types and their policy matching
	testCases := []struct {
		bucket      string
		key         string
		contentType string
		size        int64
		metadata    map[string]string
		tags        map[string]string
		expectedPolicy string
	}{
		{
			bucket:      "critical-data",
			key:         "important-file.jpg",
			contentType: "image/jpeg",
			size:        5 * 1024 * 1024,
			metadata:    map[string]string{"importance": "high"},
			tags:        map[string]string{"backup": "required"},
			expectedPolicy: "default", // No specific matcher configured
		},
		{
			bucket:      "archive",
			key:         "old-data.txt",
			contentType: "text/plain",
			size:        1024,
			metadata:    nil,
			tags:        nil,
			expectedPolicy: "default",
		},
	}
	
	for _, tc := range testCases {
		policy := suite.policyEngine.MatchPolicy(
			tc.bucket,
			tc.key,
			tc.contentType,
			tc.size,
			tc.metadata,
			tc.tags,
		)
		
		suite.Assert().NotNil(policy)
		// Note: Since we haven't configured specific matchers in this test,
		// all should return default policy
		suite.Assert().Equal("default", policy.Name)
	}
	
	// Test policy recommendations
	accessPattern := &AccessPattern{
		RecentAccesses: 500,
		GeographicAccess: map[string]int64{
			"us-east": 200,
			"us-west": 200,
			"eu-west": 100,
		},
	}
	
	recommendation := suite.policyEngine.GetPolicyRecommendation(
		"media",
		"popular-video.mp4",
		"video/mp4",
		100*1024*1024,
		accessPattern,
	)
	
	suite.Assert().Equal("high-availability", recommendation)
}

// testRebalancing tests the rebalancing functionality
func (suite *IntelligentReplicationIntegrationTestSuite) testRebalancing(cid string) {
	// Create a rebalancing task
	task := &RebalanceTask{
		CID:             cid,
		CurrentReplicas: 3,
		TargetReplicas:  5,
		CurrentDistribution: map[string]int{
			"us-east": 3,
		},
		TargetDistribution: map[string]int{
			"us-east": 2,
			"us-west": 2,
			"eu-west": 1,
		},
		Priority:    PriorityMedium,
		ScheduledAt: time.Now(),
	}
	
	// Mock pin status for rebalancing
	pinStatus := &cluster.PinStatus{
		PeerMap: map[string]*cluster.PinInfo{
			"peer-us-east-1": {Status: cluster.TrackerStatusPinned},
			"peer-us-east-2": {Status: cluster.TrackerStatusPinned},
			"peer-us-west-1": {Status: cluster.TrackerStatusPinned},
		},
	}
	suite.mockClusterClient.On("GetPinStatus", cid).Return(pinStatus, nil)
	suite.mockClusterClient.On("PinAdd", mock.AnythingOfType("string"), mock.AnythingOfType("cluster.PinOptions")).Return(nil)
	suite.mockClusterClient.On("UnpinFromNode", mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(nil)
	
	// Schedule rebalancing
	err := suite.rebalancer.ScheduleRebalance(task)
	suite.Assert().NoError(err)
	
	// Process rebalancing
	err = suite.rebalancer.ProcessPendingRebalances(1)
	suite.Assert().NoError(err)
	
	// Check metrics
	metrics := suite.rebalancer.GetMetrics()
	suite.Assert().NotNil(metrics)
	suite.Assert().GreaterOrEqual(metrics.TotalTasks, int64(1))
}

// testFullOptimization tests the complete optimization process
func (suite *IntelligentReplicationIntegrationTestSuite) testFullOptimization(cid string) {
	// Run full optimization
	result, err := suite.optimizer.OptimizeReplication(cid)
	suite.Assert().NoError(err)
	suite.Assert().NotNil(result)
	suite.Assert().Equal(cid, result.CID)
	suite.Assert().True(result.Success)
	
	// Verify optimization metrics
	suite.Assert().GreaterOrEqual(result.NewReplicas, suite.config.MinReplicas)
	suite.Assert().LessOrEqual(result.NewReplicas, suite.config.MaxReplicas)
	suite.Assert().NotEmpty(result.OptimizationReason)
	suite.Assert().NotEmpty(result.AppliedPolicy)
	
	// Check optimizer metrics
	optimizerMetrics := suite.optimizer.GetMetrics()
	suite.Assert().NotNil(optimizerMetrics)
	suite.Assert().GreaterOrEqual(optimizerMetrics.TotalOptimizations, int64(1))
	suite.Assert().GreaterOrEqual(optimizerMetrics.SuccessfulOptimizations, int64(1))
}

// TestHighAccessScenario tests the system behavior under high access load
func (suite *IntelligentReplicationIntegrationTestSuite) TestHighAccessScenario() {
	testCID := "QmHighAccessTestCID123456789"
	
	// Simulate very high access from multiple regions
	regions := []string{"us-east", "us-west", "eu-west", "asia-pacific"}
	peersPerRegion := map[string][]string{
		"us-east":      {"peer-us-east-1", "peer-us-east-2"},
		"us-west":      {"peer-us-west-1", "peer-us-west-2"},
		"eu-west":      {"peer-eu-west-1", "peer-eu-west-2"},
		"asia-pacific": {"peer-asia-pac-1"},
	}
	
	// Generate high access pattern
	for _, region := range regions {
		peers := peersPerRegion[region]
		for _, peerID := range peers {
			for i := 0; i < 200; i++ { // High access count
				suite.accessAnalyzer.RecordAccess(
					testCID,
					peerID,
					region,
					20*time.Millisecond,
					2*1024*1024,
					true,
				)
			}
		}
	}
	
	// Analyze and optimize
	accessStats, err := suite.accessAnalyzer.GetAccessStats(testCID)
	suite.Require().NoError(err)
	
	err = suite.replicaManager.AnalyzeAndOptimize(testCID, accessStats)
	suite.Require().NoError(err)
	
	// Verify high access resulted in more replicas
	state, err := suite.replicaManager.GetReplicationState(testCID)
	suite.Require().NoError(err)
	
	// High access should result in more replicas than default
	suite.Assert().Greater(state.OptimalReplicas, suite.config.DefaultReplicas)
	
	// Should have good geographic distribution
	suite.Assert().GreaterOrEqual(len(state.GeographicDistribution), 3)
}

// TestLowAccessScenario tests the system behavior under low access load
func (suite *IntelligentReplicationIntegrationTestSuite) TestLowAccessScenario() {
	testCID := "QmLowAccessTestCID123456789"
	
	// Simulate very low access from single region
	for i := 0; i < 5; i++ { // Low access count
		suite.accessAnalyzer.RecordAccess(
			testCID,
			"peer-us-east-1",
			"us-east",
			10*time.Millisecond,
			1024*1024,
			true,
		)
	}
	
	// Analyze and optimize
	accessStats, err := suite.accessAnalyzer.GetAccessStats(testCID)
	suite.Require().NoError(err)
	
	err = suite.replicaManager.AnalyzeAndOptimize(testCID, accessStats)
	suite.Require().NoError(err)
	
	// Verify low access resulted in minimum replicas
	state, err := suite.replicaManager.GetReplicationState(testCID)
	suite.Require().NoError(err)
	
	// Low access should result in minimum replicas
	suite.Assert().Equal(suite.config.MinReplicas, state.OptimalReplicas)
	
	// Should have minimal geographic distribution
	suite.Assert().LessOrEqual(len(state.GeographicDistribution), 2)
}

// TestAccessTrendDetection tests access trend detection
func (suite *IntelligentReplicationIntegrationTestSuite) TestAccessTrendDetection() {
	testCID := "QmTrendTestCID123456789"
	
	// Simulate increasing access trend
	baseTime := time.Now().Add(-24 * time.Hour)
	for hour := 0; hour < 24; hour++ {
		accessCount := hour * 5 // Increasing trend
		for i := 0; i < accessCount; i++ {
			// Simulate access at different times
			suite.accessAnalyzer.RecordAccess(
				testCID,
				"peer-us-east-1",
				"us-east",
				10*time.Millisecond,
				1024*1024,
				true,
			)
		}
	}
	
	// Analyze pattern
	accessStats, err := suite.accessAnalyzer.GetAccessStats(testCID)
	suite.Require().NoError(err)
	
	pattern, err := suite.accessAnalyzer.AnalyzePattern(testCID, accessStats)
	suite.Require().NoError(err)
	
	// Should detect increasing trend
	suite.Assert().Equal(TrendIncreasing, pattern.AccessTrend)
	
	// Predicted accesses should be higher than recent
	suite.Assert().Greater(pattern.PredictedAccesses, pattern.RecentAccesses)
}

// TestGeographicDistanceCalculation tests geographic distance calculations
func (suite *IntelligentReplicationIntegrationTestSuite) TestGeographicDistanceCalculation() {
	// Test distance calculation between known cities
	distance := suite.geoManager.haversineDistance(
		40.7128, -74.0060, // New York
		37.7749, -122.4194, // San Francisco
	)
	
	// Distance between NYC and SF should be approximately 4,000 km
	suite.Assert().InDelta(4000, distance, 500) // Allow 500km tolerance
	
	// Test region distance calculation
	regionDistance := suite.geoManager.calculateRegionDistance("us-east", "us-west")
	suite.Assert().Greater(regionDistance, 0.0)
	suite.Assert().Less(regionDistance, 10000.0) // Should be reasonable
}

// TestPolicyEngineIntegration tests policy engine integration
func (suite *IntelligentReplicationIntegrationTestSuite) TestPolicyEngineIntegration() {
	// Add a custom policy matcher
	matcher := &PolicyMatcher{
		Name:               "high-priority-media",
		PolicyName:         "high-availability",
		Priority:           100,
		ContentTypePattern: "image/.*|video/.*",
		SizeMin:            1024 * 1024, // 1MB
		MetadataMatchers: map[string]string{
			"priority": "high",
		},
		Enabled: true,
	}
	
	err := suite.policyEngine.AddPolicyMatcher(matcher)
	suite.Require().NoError(err)
	
	// Test policy matching
	policy := suite.policyEngine.MatchPolicy(
		"media-bucket",
		"important-video.mp4",
		"video/mp4",
		10*1024*1024,
		map[string]string{"priority": "high"},
		nil,
	)
	
	suite.Assert().Equal("high-availability", policy.Name)
	
	// Test with non-matching criteria
	policy = suite.policyEngine.MatchPolicy(
		"media-bucket",
		"small-image.jpg",
		"image/jpeg",
		512, // Too small
		map[string]string{"priority": "high"},
		nil,
	)
	
	suite.Assert().Equal("default", policy.Name)
}

// TestSystemMetrics tests system-wide metrics collection
func (suite *IntelligentReplicationIntegrationTestSuite) TestSystemMetrics() {
	// Generate some activity
	testCID := "QmMetricsTestCID123456789"
	suite.simulateAccessPatterns(testCID)
	
	accessStats, err := suite.accessAnalyzer.GetAccessStats(testCID)
	suite.Require().NoError(err)
	
	err = suite.replicaManager.AnalyzeAndOptimize(testCID, accessStats)
	suite.Require().NoError(err)
	
	// Check replica manager metrics
	replicaMetrics := suite.replicaManager.GetMetrics()
	suite.Assert().NotNil(replicaMetrics)
	
	// Check access analyzer metrics
	analyticsSummary := suite.accessAnalyzer.GetAnalyticsSummary()
	suite.Assert().NotNil(analyticsSummary)
	suite.Assert().Greater(analyticsSummary.TotalObjects, 0)
	suite.Assert().Greater(analyticsSummary.TotalAccesses, int64(0))
	suite.Assert().Greater(len(analyticsSummary.UniqueRegions), 0)
	
	// Check geographic manager metrics
	regionInfo := suite.geoManager.GetRegionInfo()
	suite.Assert().NotNil(regionInfo)
	suite.Assert().Greater(len(regionInfo), 0)
	
	for region, info := range regionInfo {
		suite.Assert().NotEmpty(region)
		suite.Assert().Greater(len(info.Nodes), 0)
		suite.Assert().Greater(info.TotalCapacity, int64(0))
	}
}

// TestConcurrentOperations tests concurrent operations
func (suite *IntelligentReplicationIntegrationTestSuite) TestConcurrentOperations() {
	// Test concurrent access recording and analysis
	testCIDs := []string{
		"QmConcurrent1",
		"QmConcurrent2",
		"QmConcurrent3",
		"QmConcurrent4",
		"QmConcurrent5",
	}
	
	// Simulate concurrent access recording
	done := make(chan bool, len(testCIDs))
	
	for _, cid := range testCIDs {
		go func(testCID string) {
			defer func() { done <- true }()
			
			// Record access patterns
			for i := 0; i < 50; i++ {
				suite.accessAnalyzer.RecordAccess(
					testCID,
					"peer-us-east-1",
					"us-east",
					10*time.Millisecond,
					1024*1024,
					true,
				)
			}
			
			// Analyze and optimize
			accessStats, err := suite.accessAnalyzer.GetAccessStats(testCID)
			if err == nil {
				suite.replicaManager.AnalyzeAndOptimize(testCID, accessStats)
			}
		}(cid)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < len(testCIDs); i++ {
		<-done
	}
	
	// Verify all CIDs were processed
	for _, cid := range testCIDs {
		state, err := suite.replicaManager.GetReplicationState(cid)
		suite.Assert().NoError(err)
		suite.Assert().Equal(cid, state.CID)
	}
}

// Run the integration test suite
func TestIntelligentReplicationIntegrationSuite(t *testing.T) {
	suite.Run(t, new(IntelligentReplicationIntegrationTestSuite))
}

// BenchmarkCompleteReplicationWorkflow benchmarks the complete workflow
func BenchmarkCompleteReplicationWorkflow(b *testing.B) {
	// Setup
	config := &ReplicaConfig{
		MinReplicas:                 2,
		MaxReplicas:                 10,
		DefaultReplicas:             3,
		AnalysisInterval:            1 * time.Hour,
		RebalanceInterval:           2 * time.Hour,
		HighAccessThreshold:         1000,
		LowAccessThreshold:          10,
		GeographicSpreadFactor:      0.2,
		MaxConcurrentRebalance:      3,
		RebalanceBatchSize:          100,
	}
	
	mockClient := &MockClusterClient{}
	clusterState := &cluster.ClusterState{
		Peers: map[string]*cluster.PeerInfo{
			"peer1": {ID: "peer1", Region: "us-east"},
			"peer2": {ID: "peer2", Region: "us-west"},
			"peer3": {ID: "peer3", Region: "eu-west"},
		},
		AvailableRegions: []string{"us-east", "us-west", "eu-west"},
	}
	mockClient.On("GetClusterState").Return(clusterState, nil)
	
	replicaManager := NewReplicaManager(mockClient, config)
	defer replicaManager.Shutdown()
	
	accessStats := &AccessStats{
		CID:           "benchmark-cid",
		TotalAccesses: 500,
		GeographicAccess: map[string]int64{
			"us-east": 200,
			"us-west": 200,
			"eu-west": 100,
		},
		RecentAccesses: 50,
		LastUpdated:    time.Now(),
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		cid := "benchmark-cid-" + string(rune(i))
		err := replicaManager.AnalyzeAndOptimize(cid, accessStats)
		if err != nil {
			b.Fatal(err)
		}
	}
}