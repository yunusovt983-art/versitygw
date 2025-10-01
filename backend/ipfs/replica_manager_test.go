package ipfs

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockClusterClient is a mock implementation of ClusterClientInterface
type MockClusterClient struct {
	mock.Mock
}

func (m *MockClusterClient) GetClusterState() (*cluster.ClusterState, error) {
	args := m.Called()
	return args.Get(0).(*cluster.ClusterState), args.Error(1)
}

func (m *MockClusterClient) GetPinStatus(cid string) (*cluster.PinStatus, error) {
	args := m.Called(cid)
	return args.Get(0).(*cluster.PinStatus), args.Error(1)
}

func (m *MockClusterClient) PinAdd(cid string, options cluster.PinOptions) error {
	args := m.Called(cid, options)
	return args.Error(0)
}

func (m *MockClusterClient) UnpinFromNode(cid, nodeID string) error {
	args := m.Called(cid, nodeID)
	return args.Error(0)
}

// TestReplicaManager_NewReplicaManager tests the creation of a new replica manager
func TestReplicaManager_NewReplicaManager(t *testing.T) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
		AnalysisInterval: 15 * time.Minute,
		RebalanceInterval: 1 * time.Hour,
		HighAccessThreshold: 1000,
		LowAccessThreshold:  10,
		GeographicSpreadFactor: 0.2,
		MaxConcurrentRebalance: 5,
		RebalanceBatchSize:     100,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	assert.NotNil(t, rm)
	assert.Equal(t, config, rm.config)
	assert.NotNil(t, rm.accessAnalyzer)
	assert.NotNil(t, rm.geoManager)
	assert.NotNil(t, rm.rebalancer)
	assert.NotNil(t, rm.policyEngine)
	assert.NotNil(t, rm.metrics)
	assert.NotNil(t, rm.replicationState)
}

// TestReplicaManager_AnalyzeAndOptimize tests the analysis and optimization process
func TestReplicaManager_AnalyzeAndOptimize(t *testing.T) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
		AnalysisInterval: 15 * time.Minute,
		RebalanceInterval: 1 * time.Hour,
		HighAccessThreshold: 1000,
		LowAccessThreshold:  10,
		GeographicSpreadFactor: 0.2,
		MaxConcurrentRebalance: 5,
		RebalanceBatchSize:     100,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	// Mock cluster state
	clusterState := &cluster.ClusterState{
		Peers: map[string]*cluster.PeerInfo{
			"peer1": {ID: "peer1", Region: "us-east"},
			"peer2": {ID: "peer2", Region: "us-west"},
			"peer3": {ID: "peer3", Region: "eu-west"},
		},
	}
	mockClient.On("GetClusterState").Return(clusterState, nil)
	
	// Create test access stats
	accessStats := &AccessStats{
		CID:           "test-cid",
		TotalAccesses: 500,
		GeographicAccess: map[string]int64{
			"us-east": 200,
			"us-west": 200,
			"eu-west": 100,
		},
		RecentAccesses: 50,
		LastUpdated:    time.Now(),
	}
	
	// Test analysis and optimization
	err := rm.AnalyzeAndOptimize("test-cid", accessStats)
	assert.NoError(t, err)
	
	// Verify replication state was created
	state, err := rm.GetReplicationState("test-cid")
	assert.NoError(t, err)
	assert.NotNil(t, state)
	assert.Equal(t, "test-cid", state.CID)
	assert.NotNil(t, state.AccessPattern)
	assert.True(t, state.OptimalReplicas >= config.MinReplicas)
	assert.True(t, state.OptimalReplicas <= config.MaxReplicas)
}

// TestReplicaManager_CalculateOptimalReplicas tests optimal replica calculation
func TestReplicaManager_CalculateOptimalReplicas(t *testing.T) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
		HighAccessThreshold: 1000,
		LowAccessThreshold:  10,
		GeographicSpreadFactor: 0.2,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	tests := []struct {
		name           string
		pattern        *AccessPattern
		expectedMin    int
		expectedMax    int
		description    string
	}{
		{
			name: "High access pattern",
			pattern: &AccessPattern{
				RecentAccesses: 1500,
				AccessTrend:    TrendIncreasing,
				GeographicAccess: map[string]int64{
					"us-east": 500,
					"us-west": 500,
					"eu-west": 500,
				},
			},
			expectedMin: 4,
			expectedMax: 10,
			description: "High access should increase replicas",
		},
		{
			name: "Low access pattern",
			pattern: &AccessPattern{
				RecentAccesses: 5,
				AccessTrend:    TrendDecreasing,
				GeographicAccess: map[string]int64{
					"us-east": 5,
				},
			},
			expectedMin: 2,
			expectedMax: 3,
			description: "Low access should use minimum replicas",
		},
		{
			name: "Geographic spread pattern",
			pattern: &AccessPattern{
				RecentAccesses: 100,
				AccessTrend:    TrendStable,
				GeographicAccess: map[string]int64{
					"us-east":      25,
					"us-west":      25,
					"eu-west":      25,
					"asia-pacific": 25,
				},
			},
			expectedMin: 3,
			expectedMax: 6,
			description: "Geographic spread should increase replicas",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &ReplicationState{
				CID:             "test-cid",
				ReplicationPolicy: "default",
			}
			
			optimal := rm.calculateOptimalReplicas(tt.pattern, state)
			
			assert.GreaterOrEqual(t, optimal, tt.expectedMin, tt.description)
			assert.LessOrEqual(t, optimal, tt.expectedMax, tt.description)
			assert.GreaterOrEqual(t, optimal, config.MinReplicas, "Should respect minimum replicas")
			assert.LessOrEqual(t, optimal, config.MaxReplicas, "Should respect maximum replicas")
		})
	}
}

// TestReplicaManager_AccessMultiplier tests access multiplier calculation
func TestReplicaManager_AccessMultiplier(t *testing.T) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		HighAccessThreshold: 1000,
		LowAccessThreshold:  10,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	tests := []struct {
		name           string
		recentAccesses int64
		expectedMin    float64
		expectedMax    float64
	}{
		{
			name:           "Very high access",
			recentAccesses: 10000,
			expectedMin:    1.5,
			expectedMax:    3.0,
		},
		{
			name:           "High access",
			recentAccesses: 1000,
			expectedMin:    1.5,
			expectedMax:    2.0,
		},
		{
			name:           "Medium access",
			recentAccesses: 100,
			expectedMin:    0.9,
			expectedMax:    1.1,
		},
		{
			name:           "Low access",
			recentAccesses: 5,
			expectedMin:    0.6,
			expectedMax:    0.8,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := &AccessPattern{
				RecentAccesses: tt.recentAccesses,
			}
			
			multiplier := rm.calculateAccessMultiplier(pattern)
			
			assert.GreaterOrEqual(t, multiplier, tt.expectedMin)
			assert.LessOrEqual(t, multiplier, tt.expectedMax)
		})
	}
}

// TestReplicaManager_GeographicMultiplier tests geographic multiplier calculation
func TestReplicaManager_GeographicMultiplier(t *testing.T) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		GeographicSpreadFactor: 0.2,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	tests := []struct {
		name               string
		geographicAccess   map[string]int64
		expectedMultiplier float64
	}{
		{
			name: "Single region",
			geographicAccess: map[string]int64{
				"us-east": 100,
			},
			expectedMultiplier: 1.0,
		},
		{
			name: "Two regions",
			geographicAccess: map[string]int64{
				"us-east": 50,
				"us-west": 50,
			},
			expectedMultiplier: 1.2,
		},
		{
			name: "Four regions",
			geographicAccess: map[string]int64{
				"us-east":      25,
				"us-west":      25,
				"eu-west":      25,
				"asia-pacific": 25,
			},
			expectedMultiplier: 1.6,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := &AccessPattern{
				GeographicAccess: tt.geographicAccess,
			}
			
			multiplier := rm.calculateGeographicMultiplier(pattern)
			
			assert.InDelta(t, tt.expectedMultiplier, multiplier, 0.01)
		})
	}
}

// TestReplicaManager_TrendMultiplier tests trend multiplier calculation
func TestReplicaManager_TrendMultiplier(t *testing.T) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{}
	
	rm := NewReplicaManager(mockClient, config)
	
	tests := []struct {
		name               string
		trend              AccessTrend
		expectedMultiplier float64
	}{
		{
			name:               "Increasing trend",
			trend:              TrendIncreasing,
			expectedMultiplier: 1.3,
		},
		{
			name:               "Decreasing trend",
			trend:              TrendDecreasing,
			expectedMultiplier: 0.8,
		},
		{
			name:               "Spiky trend",
			trend:              TrendSpiky,
			expectedMultiplier: 1.2,
		},
		{
			name:               "Seasonal trend",
			trend:              TrendSeasonal,
			expectedMultiplier: 1.1,
		},
		{
			name:               "Stable trend",
			trend:              TrendStable,
			expectedMultiplier: 1.0,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := &AccessPattern{
				AccessTrend: tt.trend,
			}
			
			multiplier := rm.calculateTrendMultiplier(pattern)
			
			assert.Equal(t, tt.expectedMultiplier, multiplier)
		})
	}
}

// TestReplicaManager_NeedsRebalancing tests rebalancing decision logic
func TestReplicaManager_NeedsRebalancing(t *testing.T) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		RebalanceInterval: 1 * time.Hour,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	tests := []struct {
		name                 string
		currentReplicas      int
		optimalReplicas      int
		currentDistribution  map[string]int
		optimalDistribution  map[string]int
		lastRebalanced       time.Time
		expectedRebalance    bool
	}{
		{
			name:            "Replica count mismatch",
			currentReplicas: 3,
			optimalReplicas: 5,
			currentDistribution: map[string]int{
				"us-east": 3,
			},
			optimalDistribution: map[string]int{
				"us-east": 5,
			},
			lastRebalanced:    time.Now().Add(-30 * time.Minute),
			expectedRebalance: true,
		},
		{
			name:            "Geographic distribution mismatch",
			currentReplicas: 3,
			optimalReplicas: 3,
			currentDistribution: map[string]int{
				"us-east": 3,
			},
			optimalDistribution: map[string]int{
				"us-east": 2,
				"us-west": 1,
			},
			lastRebalanced:    time.Now().Add(-30 * time.Minute),
			expectedRebalance: true,
		},
		{
			name:            "Too long since last rebalance",
			currentReplicas: 3,
			optimalReplicas: 3,
			currentDistribution: map[string]int{
				"us-east": 3,
			},
			optimalDistribution: map[string]int{
				"us-east": 3,
			},
			lastRebalanced:    time.Now().Add(-3 * time.Hour),
			expectedRebalance: true,
		},
		{
			name:            "No rebalancing needed",
			currentReplicas: 3,
			optimalReplicas: 3,
			currentDistribution: map[string]int{
				"us-east": 2,
				"us-west": 1,
			},
			optimalDistribution: map[string]int{
				"us-east": 2,
				"us-west": 1,
			},
			lastRebalanced:    time.Now().Add(-30 * time.Minute),
			expectedRebalance: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &ReplicationState{
				CurrentReplicas:        tt.currentReplicas,
				OptimalReplicas:        tt.optimalReplicas,
				GeographicDistribution: tt.currentDistribution,
				LastRebalanced:         tt.lastRebalanced,
			}
			
			needsRebalancing := rm.needsRebalancing(state, tt.optimalDistribution)
			
			assert.Equal(t, tt.expectedRebalance, needsRebalancing)
		})
	}
}

// TestReplicaManager_RebalancePriority tests rebalance priority calculation
func TestReplicaManager_RebalancePriority(t *testing.T) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		HighAccessThreshold: 1000,
		LowAccessThreshold:  10,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	tests := []struct {
		name             string
		recentAccesses   int64
		currentReplicas  int
		optimalReplicas  int
		expectedPriority RebalancePriority
	}{
		{
			name:             "High access, under-replicated",
			recentAccesses:   1500,
			currentReplicas:  2,
			optimalReplicas:  5,
			expectedPriority: PriorityHigh,
		},
		{
			name:             "High access, over-replicated",
			recentAccesses:   1500,
			currentReplicas:  5,
			optimalReplicas:  3,
			expectedPriority: PriorityMedium,
		},
		{
			name:             "Medium access",
			recentAccesses:   100,
			currentReplicas:  3,
			optimalReplicas:  4,
			expectedPriority: PriorityMedium,
		},
		{
			name:             "Low access",
			recentAccesses:   5,
			currentReplicas:  3,
			optimalReplicas:  2,
			expectedPriority: PriorityLow,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &ReplicationState{
				CurrentReplicas: tt.currentReplicas,
				OptimalReplicas: tt.optimalReplicas,
				AccessPattern: &AccessPattern{
					RecentAccesses: tt.recentAccesses,
				},
			}
			
			priority := rm.calculateRebalancePriority(state)
			
			assert.Equal(t, tt.expectedPriority, priority)
		})
	}
}

// TestReplicaManager_DefaultDistribution tests default distribution calculation
func TestReplicaManager_DefaultDistribution(t *testing.T) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		DefaultReplicas: 6,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	clusterState := &cluster.ClusterState{
		Peers: map[string]*cluster.PeerInfo{
			"peer1": {ID: "peer1", Region: "us-east"},
			"peer2": {ID: "peer2", Region: "us-west"},
			"peer3": {ID: "peer3", Region: "eu-west"},
		},
	}
	
	// Mock GetAvailableRegions method
	clusterState.AvailableRegions = []string{"us-east", "us-west", "eu-west"}
	
	distribution := rm.getDefaultDistribution(clusterState)
	
	// Should distribute 6 replicas across 3 regions (2 each)
	assert.Equal(t, 3, len(distribution))
	
	totalReplicas := 0
	for _, count := range distribution {
		totalReplicas += count
		assert.GreaterOrEqual(t, count, 1) // Each region should have at least 1
		assert.LessOrEqual(t, count, 3)    // No region should have more than 3
	}
	
	assert.Equal(t, config.DefaultReplicas, totalReplicas)
}

// TestReplicaManager_UpdateReplicationState tests state updates
func TestReplicaManager_UpdateReplicationState(t *testing.T) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		DefaultReplicas: 3,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	state := &ReplicationState{
		CID:             "test-cid",
		CurrentReplicas: 3,
		OptimalReplicas: 5,
		GeographicDistribution: map[string]int{
			"us-east": 2,
			"us-west": 1,
		},
		ReplicationPolicy: "high-availability",
		LastAnalyzed:      time.Now(),
	}
	
	err := rm.UpdateReplicationState("test-cid", state)
	assert.NoError(t, err)
	
	// Verify state was stored
	retrievedState, err := rm.GetReplicationState("test-cid")
	assert.NoError(t, err)
	assert.Equal(t, state.CID, retrievedState.CID)
	assert.Equal(t, state.CurrentReplicas, retrievedState.CurrentReplicas)
	assert.Equal(t, state.OptimalReplicas, retrievedState.OptimalReplicas)
	assert.Equal(t, state.ReplicationPolicy, retrievedState.ReplicationPolicy)
}

// TestReplicaManager_GetReplicationState_NotFound tests getting non-existent state
func TestReplicaManager_GetReplicationState_NotFound(t *testing.T) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		DefaultReplicas: 3,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	_, err := rm.GetReplicationState("non-existent-cid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no replication state found")
}

// TestReplicaManager_Shutdown tests graceful shutdown
func TestReplicaManager_Shutdown(t *testing.T) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		DefaultReplicas:   3,
		AnalysisInterval:  100 * time.Millisecond,
		RebalanceInterval: 200 * time.Millisecond,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	// Let it run for a short time
	time.Sleep(50 * time.Millisecond)
	
	// Shutdown should complete without error
	err := rm.Shutdown()
	assert.NoError(t, err)
}

// BenchmarkReplicaManager_AnalyzeAndOptimize benchmarks the analysis process
func BenchmarkReplicaManager_AnalyzeAndOptimize(b *testing.B) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
		HighAccessThreshold: 1000,
		LowAccessThreshold:  10,
		GeographicSpreadFactor: 0.2,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	// Mock cluster state
	clusterState := &cluster.ClusterState{
		Peers: map[string]*cluster.PeerInfo{
			"peer1": {ID: "peer1", Region: "us-east"},
			"peer2": {ID: "peer2", Region: "us-west"},
			"peer3": {ID: "peer3", Region: "eu-west"},
		},
	}
	mockClient.On("GetClusterState").Return(clusterState, nil)
	
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
		err := rm.AnalyzeAndOptimize(cid, accessStats)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReplicaManager_CalculateOptimalReplicas benchmarks replica calculation
func BenchmarkReplicaManager_CalculateOptimalReplicas(b *testing.B) {
	mockClient := &MockClusterClient{}
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
		HighAccessThreshold: 1000,
		LowAccessThreshold:  10,
		GeographicSpreadFactor: 0.2,
	}
	
	rm := NewReplicaManager(mockClient, config)
	
	pattern := &AccessPattern{
		RecentAccesses: 500,
		AccessTrend:    TrendIncreasing,
		GeographicAccess: map[string]int64{
			"us-east": 200,
			"us-west": 200,
			"eu-west": 100,
		},
	}
	
	state := &ReplicationState{
		CID:               "benchmark-cid",
		ReplicationPolicy: "default",
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		rm.calculateOptimalReplicas(pattern, state)
	}
}