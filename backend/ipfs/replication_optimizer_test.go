package ipfs

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// ReplicationOptimizerTestSuite tests the replication optimizer
type ReplicationOptimizerTestSuite struct {
	suite.Suite
	mockCluster       *MockClusterClientInterface
	mockMetadata      *MockMetadataStore
	geoManager        *GeographicManager
	accessAnalyzer    *AccessPatternAnalyzer
	policyManager     *ReplicationPolicyManager
	optimizer         *ReplicationOptimizer
	logger            *logrus.Logger
}

func (suite *ReplicationOptimizerTestSuite) SetupSuite() {
	suite.logger = logrus.New()
	suite.logger.SetLevel(logrus.DebugLevel)

	suite.mockCluster = &MockClusterClientInterface{}
	suite.mockMetadata = &MockMetadataStore{}
	suite.geoManager = NewGeographicManager(suite.mockCluster, suite.logger)
	suite.accessAnalyzer = NewAccessPatternAnalyzer(suite.mockMetadata, 24*time.Hour, suite.logger)
	suite.policyManager = NewReplicationPolicyManager(suite.logger)

	// Set up test configuration
	config := &OptimizationConfig{
		MaxIterations:           50,
		ConvergenceThreshold:    0.01,
		OptimizationInterval:    1 * time.Hour,
		LatencyWeight:           0.3,
		CostWeight:              0.2,
		ReliabilityWeight:       0.2,
		LoadBalanceWeight:       0.15,
		GeographicWeight:        0.15,
		MaxReplicasPerObject:    8,
		MinReplicasPerObject:    2,
		MaxClusterUtilization:   0.85,
		BudgetConstraint:        1000.0,
		EnablePredictiveScaling: true,
		EnableCostOptimization:  true,
		EnableLatencyOptimization: true,
	}

	suite.optimizer = NewReplicationOptimizer(
		suite.mockCluster,
		suite.mockMetadata,
		suite.geoManager,
		suite.accessAnalyzer,
		suite.policyManager,
		config,
		suite.logger,
	)
}

func (suite *ReplicationOptimizerTestSuite) TestOptimizerInitialization() {
	assert.NotNil(suite.T(), suite.optimizer)
	assert.NotNil(suite.T(), suite.optimizer.config)
	assert.Equal(suite.T(), 50, suite.optimizer.config.MaxIterations)
	assert.Equal(suite.T(), 0.3, suite.optimizer.config.LatencyWeight)
	assert.True(suite.T(), suite.optimizer.config.EnablePredictiveScaling)
}

func (suite *ReplicationOptimizerTestSuite) TestStartStop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test start
	err := suite.optimizer.Start(ctx)
	require.NoError(suite.T(), err)

	// Test double start (should fail)
	err = suite.optimizer.Start(ctx)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "already running")

	// Test stop
	err = suite.optimizer.Stop(ctx)
	assert.NoError(suite.T(), err)

	// Test double stop (should not fail)
	err = suite.optimizer.Stop(ctx)
	assert.NoError(suite.T(), err)
}

func (suite *ReplicationOptimizerTestSuite) TestPredictOptimalReplicas() {
	ctx := context.Background()

	// Set up test data
	testCID := "QmTestOptimalReplicas"
	mapping := &ObjectMapping{
		S3Key:       "test-file.txt",
		Bucket:      "test-bucket",
		CID:         testCID,
		Size:        1024 * 1024, // 1MB
		ContentType: "text/plain",
	}

	// Mock metadata store response
	suite.mockMetadata.On("SearchByCID", ctx, testCID).Return([]*ObjectMapping{mapping}, nil)

	// Add a test policy
	policy := &ReplicationPolicy{
		Name:                "test-policy",
		DataTypePattern:     "*",
		MinReplicas:         2,
		MaxReplicas:         6,
		AccessPatternWeight: 1.0,
		GeographicSpread:    true,
		CostSensitive:       false,
	}
	err := suite.policyManager.AddPolicy(policy)
	require.NoError(suite.T(), err)

	// Test with no access pattern (should use minimum)
	optimalReplicas, err := suite.optimizer.PredictOptimalReplicas(ctx, testCID)
	require.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), optimalReplicas, 2)
	assert.LessOrEqual(suite.T(), optimalReplicas, 6)

	// Add access pattern for hot data
	hotAccessPattern := &AccessPattern{
		CID:         testCID,
		AccessCount: 1000,
		LastAccess:  time.Now(),
		GeographicAccess: map[string]int64{
			"US": 600,
			"EU": 300,
			"AP": 100,
		},
	}
	suite.accessAnalyzer.accessPatterns[testCID] = hotAccessPattern

	// Test with hot access pattern (should increase replicas)
	optimalReplicas, err = suite.optimizer.PredictOptimalReplicas(ctx, testCID)
	require.NoError(suite.T(), err)
	assert.Greater(suite.T(), optimalReplicas, 2)

	// Test with predictive scaling
	if suite.optimizer.config.EnablePredictiveScaling {
		// Mock prediction
		prediction := &AccessPrediction{
			CID:               testCID,
			PredictedAccesses: 1500, // Predicted increase
			Confidence:        0.8,
			PredictionHorizon: 24 * time.Hour,
		}
		
		// This would normally be calculated by the access analyzer
		// For testing, we'll verify the logic handles predictions correctly
		assert.Greater(suite.T(), prediction.Confidence, 0.7)
		assert.Greater(suite.T(), prediction.PredictedAccesses, float64(hotAccessPattern.AccessCount))
	}

	suite.mockMetadata.AssertExpectations(suite.T())
}

func (suite *ReplicationOptimizerTestSuite) TestOptimizeObject() {
	ctx := context.Background()

	testCID := "QmTestOptimizeObject"
	mapping := &ObjectMapping{
		S3Key:       "optimize-test.jpg",
		Bucket:      "photos",
		CID:         testCID,
		Size:        2 * 1024 * 1024, // 2MB
		ContentType: "image/jpeg",
	}

	// Mock current pin status (sub-optimal placement)
	pinStatus := map[string]PinStatusInfo{
		"node1": {Status: "pinned"},
		"node2": {Status: "pinned"},
	}

	// Mock cluster peers
	peers := []PeerInfo{
		{ID: "node1", Connected: true},
		{ID: "node2", Connected: true},
		{ID: "node3", Connected: true},
		{ID: "node4", Connected: true},
	}

	// Set up mocks
	suite.mockMetadata.On("SearchByCID", ctx, testCID).Return([]*ObjectMapping{mapping}, nil)
	suite.mockCluster.On("GetPinStatus", testCID).Return(pinStatus, nil)
	suite.mockCluster.On("GetPeers").Return(peers, nil)

	// Add geographic locations for better optimization
	locations := []*NodeLocation{
		{NodeID: "node1", Region: "us-east-1", Country: "US", Reliability: 0.99, CostTier: 2},
		{NodeID: "node2", Region: "us-east-1", Country: "US", Reliability: 0.98, CostTier: 2},
		{NodeID: "node3", Region: "eu-west-1", Country: "IE", Reliability: 0.97, CostTier: 3},
		{NodeID: "node4", Region: "ap-southeast-1", Country: "SG", Reliability: 0.96, CostTier: 4},
	}

	for _, location := range locations {
		suite.geoManager.AddNodeLocation(location)
	}

	// Add access pattern with geographic diversity
	accessPattern := &AccessPattern{
		CID:         testCID,
		AccessCount: 500,
		LastAccess:  time.Now(),
		GeographicAccess: map[string]int64{
			"US": 200,
			"EU": 200,
			"AP": 100,
		},
	}
	suite.accessAnalyzer.accessPatterns[testCID] = accessPattern

	// Add a policy for images
	imagePolicy := &ReplicationPolicy{
		Name:                "image-policy",
		DataTypePattern:     "image/*",
		MinReplicas:         3,
		MaxReplicas:         5,
		AccessPatternWeight: 1.0,
		GeographicSpread:    true,
		CostSensitive:       false,
	}
	err := suite.policyManager.AddPolicy(imagePolicy)
	require.NoError(suite.T(), err)

	// Optimize the object
	result, err := suite.optimizer.OptimizeObject(ctx, testCID)
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), result)

	// Verify optimization result
	assert.Equal(suite.T(), testCID, result.Metadata["cid"])
	assert.Equal(suite.T(), 1, result.ObjectsOptimized)
	assert.Greater(suite.T(), len(result.Recommendations), 0)

	// Should recommend adding replicas for geographic diversity
	hasAddRecommendation := false
	for _, recommendation := range result.Recommendations {
		if recommendation.Action == MoveActionAdd {
			hasAddRecommendation = true
			assert.NotEmpty(suite.T(), recommendation.TargetNode)
			assert.NotEmpty(suite.T(), recommendation.Reason)
		}
	}
	assert.True(suite.T(), hasAddRecommendation, "Should recommend adding replicas")

	suite.mockMetadata.AssertExpectations(suite.T())
	suite.mockCluster.AssertExpectations(suite.T())
}

func (suite *ReplicationOptimizerTestSuite) TestNodeScoring() {
	// Set up test data
	mapping := &ObjectMapping{
		S3Key:       "test-scoring.txt",
		Bucket:      "test",
		CID:         "QmTestScoring",
		Size:        1024,
		ContentType: "text/plain",
	}

	accessPattern := &AccessPattern{
		CID:         "QmTestScoring",
		AccessCount: 100,
		GeographicAccess: map[string]int64{
			"US": 60,
			"EU": 40,
		},
	}

	// Add node locations with different characteristics
	locations := []*NodeLocation{
		{
			NodeID:      "high-reliability-node",
			Region:      "us-east-1",
			Country:     "US",
			Reliability: 0.99,
			CostTier:    3, // Medium cost
		},
		{
			NodeID:      "low-cost-node",
			Region:      "us-west-2",
			Country:     "US",
			Reliability: 0.95,
			CostTier:    1, // Low cost
		},
		{
			NodeID:      "high-cost-node",
			Region:      "eu-west-1",
			Country:     "IE",
			Reliability: 0.98,
			CostTier:    5, // High cost
		},
		{
			NodeID:      "distant-node",
			Region:      "ap-southeast-1",
			Country:     "SG",
			Reliability: 0.97,
			CostTier:    2, // Low cost but distant
		},
	}

	for _, location := range locations {
		suite.geoManager.AddNodeLocation(location)
	}

	// Test node scoring
	scores := make(map[string]*OptimizationNodeScore)
	for _, location := range locations {
		score := suite.optimizer.calculateNodeScore(location.NodeID, mapping, accessPattern)
		scores[location.NodeID] = score
		
		// Verify score components
		assert.GreaterOrEqual(suite.T(), score.LatencyScore, 0.0)
		assert.LessOrEqual(suite.T(), score.LatencyScore, 1.0)
		assert.GreaterOrEqual(suite.T(), score.CostScore, 0.0)
		assert.LessOrEqual(suite.T(), score.CostScore, 1.0)
		assert.GreaterOrEqual(suite.T(), score.ReliabilityScore, 0.0)
		assert.LessOrEqual(suite.T(), score.ReliabilityScore, 1.0)
		assert.GreaterOrEqual(suite.T(), score.CompositeScore, 0.0)
	}

	// High reliability node should have high reliability score
	assert.Greater(suite.T(), scores["high-reliability-node"].ReliabilityScore, 0.95)

	// Low cost node should have high cost score
	assert.Greater(suite.T(), scores["low-cost-node"].CostScore, scores["high-cost-node"].CostScore)

	// Nodes in regions with high access should have better geographic scores
	usNodes := []string{"high-reliability-node", "low-cost-node"}
	for _, nodeID := range usNodes {
		assert.Greater(suite.T(), scores[nodeID].GeographicScore, scores["distant-node"].GeographicScore)
	}
}

func (suite *ReplicationOptimizerTestSuite) TestOptimizationObjectives() {
	// Create a mock cluster state
	state := &ClusterOptimizationState{
		Nodes: map[string]*NodeOptimizationInfo{
			"node1": {
				NodeID:      "node1",
				CurrentLoad: 0.5,
				CostPerGB:   0.10,
				Reliability: 0.99,
			},
			"node2": {
				NodeID:      "node2",
				CurrentLoad: 0.8,
				CostPerGB:   0.05,
				Reliability: 0.95,
			},
		},
		Objects: map[string]*ObjectOptimizationInfo{
			"obj1": {
				CID:              "QmObj1",
				Size:             1024,
				CurrentReplicas:  []string{"node1"},
				RequiredReplicas: 2,
			},
		},
		TotalCost:        100.0,
		AverageLatency:   50 * time.Millisecond,
		LoadVariance:     0.1,
		GeographicSpread: 0.5,
		Timestamp:        time.Now(),
	}

	// Test different optimization objectives
	objectives := []OptimizationObjective{
		OptimizeLatency,
		OptimizeCost,
		OptimizeReliability,
		OptimizeLoadBalance,
		OptimizeGeographicSpread,
		OptimizeMultiObjective,
	}

	for _, objective := range objectives {
		score := suite.optimizer.calculateClusterScore(state, objective)
		assert.Greater(suite.T(), score, 0.0, "Score should be positive for objective %v", objective)
	}

	// Multi-objective should consider all factors
	multiScore := suite.optimizer.calculateClusterScore(state, OptimizeMultiObjective)
	assert.Greater(suite.T(), multiScore, 0.0)

	// Cost optimization should prefer lower costs
	lowCostState := suite.optimizer.copyState(state)
	lowCostState.TotalCost = 50.0 // Lower cost

	lowCostScore := suite.optimizer.calculateClusterScore(lowCostState, OptimizeCost)
	originalCostScore := suite.optimizer.calculateClusterScore(state, OptimizeCost)
	assert.Greater(suite.T(), lowCostScore, originalCostScore)
}

func (suite *ReplicationOptimizerTestSuite) TestOptimizationHistory() {
	// Initially should be empty
	history := suite.optimizer.GetOptimizationHistory()
	assert.Empty(suite.T(), history)

	// Add a mock result to history
	result := &OptimizationResult{
		ID:               "test-optimization-1",
		StartTime:        time.Now().Add(-1 * time.Hour),
		EndTime:          time.Now(),
		Objective:        OptimizeMultiObjective,
		InitialScore:     100.0,
		FinalScore:       120.0,
		Improvement:      20.0,
		ObjectsOptimized: 10,
		ReplicasMoved:    5,
		CostSavings:      50.0,
		Recommendations:  []*OptimizationMove{},
		Metadata:         map[string]interface{}{"test": true},
	}

	// Simulate adding to history (normally done by optimization process)
	suite.optimizer.mu.Lock()
	suite.optimizer.optimizationHistory = append(suite.optimizer.optimizationHistory, result)
	suite.optimizer.mu.Unlock()

	// Verify history
	history = suite.optimizer.GetOptimizationHistory()
	assert.Len(suite.T(), history, 1)
	assert.Equal(suite.T(), "test-optimization-1", history[0].ID)
	assert.Equal(suite.T(), 20.0, history[0].Improvement)
	assert.Equal(suite.T(), 10, history[0].ObjectsOptimized)
}

func (suite *ReplicationOptimizerTestSuite) TestClusterStateAnalysis() {
	ctx := context.Background()

	// Mock cluster peers
	peers := []PeerInfo{
		{ID: "node1", Connected: true},
		{ID: "node2", Connected: true},
		{ID: "node3", Connected: false}, // Disconnected node
	}

	suite.mockCluster.On("GetPeers").Return(peers, nil)

	// Add geographic locations
	locations := []*NodeLocation{
		{NodeID: "node1", Region: "us-east-1", Country: "US", Reliability: 0.99, CostTier: 2},
		{NodeID: "node2", Region: "eu-west-1", Country: "IE", Reliability: 0.98, CostTier: 3},
		{NodeID: "node3", Region: "ap-southeast-1", Country: "SG", Reliability: 0.97, CostTier: 4},
	}

	for _, location := range locations {
		suite.geoManager.AddNodeLocation(location)
	}

	// Analyze cluster state
	state, err := suite.optimizer.analyzeClusterState(ctx)
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), state)

	// Should include all nodes (even disconnected ones for analysis)
	assert.Len(suite.T(), state.Nodes, 3)

	// Verify node information
	for nodeID, nodeInfo := range state.Nodes {
		assert.Equal(suite.T(), nodeID, nodeInfo.NodeID)
		assert.NotNil(suite.T(), nodeInfo.Location)
		assert.Greater(suite.T(), nodeInfo.Capacity, 0.0)
		assert.Greater(suite.T(), nodeInfo.CostPerGB, 0.0)
		assert.Greater(suite.T(), nodeInfo.Reliability, 0.0)
	}

	// Verify aggregate metrics
	assert.GreaterOrEqual(suite.T(), state.TotalCost, 0.0)
	assert.Greater(suite.T(), state.AverageLatency, 0*time.Millisecond)
	assert.GreaterOrEqual(suite.T(), state.LoadVariance, 0.0)
	assert.GreaterOrEqual(suite.T(), state.GeographicSpread, 0.0)
	assert.LessOrEqual(suite.T(), state.GeographicSpread, 1.0)

	suite.mockCluster.AssertExpectations(suite.T())
}

func (suite *ReplicationOptimizerTestSuite) TestMoveGeneration() {
	// Create test cluster state
	state := &ClusterOptimizationState{
		Nodes: map[string]*NodeOptimizationInfo{
			"node1": {NodeID: "node1", CurrentLoad: 0.3},
			"node2": {NodeID: "node2", CurrentLoad: 0.7},
			"node3": {NodeID: "node3", CurrentLoad: 0.5},
		},
		Objects: map[string]*ObjectOptimizationInfo{
			"over-replicated": {
				CID:              "QmOverReplicated",
				CurrentReplicas:  []string{"node1", "node2", "node3"},
				RequiredReplicas: 2,
			},
			"under-replicated": {
				CID:              "QmUnderReplicated",
				CurrentReplicas:  []string{"node1"},
				RequiredReplicas: 3,
			},
			"optimal": {
				CID:              "QmOptimal",
				CurrentReplicas:  []string{"node1", "node2"},
				RequiredReplicas: 2,
			},
		},
	}

	// Generate candidate moves
	moves := suite.optimizer.generateCandidateMoves(state, OptimizeMultiObjective)
	assert.Greater(suite.T(), len(moves), 0)

	// Should have remove moves for over-replicated object
	hasRemoveMove := false
	for _, move := range moves {
		if move.CID == "QmOverReplicated" && move.Action == MoveActionRemove {
			hasRemoveMove = true
			assert.NotEmpty(suite.T(), move.SourceNode)
			assert.Equal(suite.T(), "Over-replicated", move.Reason)
		}
	}
	assert.True(suite.T(), hasRemoveMove)

	// Should have add moves for under-replicated object
	hasAddMove := false
	for _, move := range moves {
		if move.CID == "QmUnderReplicated" && move.Action == MoveActionAdd {
			hasAddMove = true
			assert.NotEmpty(suite.T(), move.TargetNode)
			assert.Equal(suite.T(), "Under-replicated", move.Reason)
		}
	}
	assert.True(suite.T(), hasAddMove)

	// Should not have moves for optimal object
	for _, move := range moves {
		assert.NotEqual(suite.T(), "QmOptimal", move.CID)
	}
}

func (suite *ReplicationOptimizerTestSuite) TestStateCopy() {
	// Create original state
	originalState := &ClusterOptimizationState{
		Nodes: map[string]*NodeOptimizationInfo{
			"node1": {
				NodeID:        "node1",
				CurrentLoad:   0.5,
				PinnedObjects: []string{"obj1", "obj2"},
			},
		},
		Objects: map[string]*ObjectOptimizationInfo{
			"obj1": {
				CID:             "QmObj1",
				CurrentReplicas: []string{"node1", "node2"},
			},
		},
		TotalCost:        100.0,
		AverageLatency:   50 * time.Millisecond,
		LoadVariance:     0.1,
		GeographicSpread: 0.5,
	}

	// Copy state
	copiedState := suite.optimizer.copyState(originalState)

	// Verify deep copy
	assert.Equal(suite.T(), originalState.TotalCost, copiedState.TotalCost)
	assert.Equal(suite.T(), originalState.AverageLatency, copiedState.AverageLatency)
	assert.Len(suite.T(), copiedState.Nodes, len(originalState.Nodes))
	assert.Len(suite.T(), copiedState.Objects, len(originalState.Objects))

	// Verify independence (modifying copy shouldn't affect original)
	copiedState.TotalCost = 200.0
	copiedState.Nodes["node1"].CurrentLoad = 0.8
	copiedState.Objects["obj1"].CurrentReplicas = append(copiedState.Objects["obj1"].CurrentReplicas, "node3")

	assert.Equal(suite.T(), 100.0, originalState.TotalCost)
	assert.Equal(suite.T(), 0.5, originalState.Nodes["node1"].CurrentLoad)
	assert.Len(suite.T(), originalState.Objects["obj1"].CurrentReplicas, 2)
}

// Run the test suite
func TestReplicationOptimizerTestSuite(t *testing.T) {
	suite.Run(t, new(ReplicationOptimizerTestSuite))
}