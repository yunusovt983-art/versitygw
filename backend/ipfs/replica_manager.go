package ipfs

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// ReplicaManager manages intelligent replication of objects in IPFS cluster
type ReplicaManager struct {
	clusterClient    ClusterClientInterface
	accessAnalyzer   *AccessPatternAnalyzer
	geoManager       *GeographicManager
	rebalancer       *ReplicationRebalancer
	policyEngine     *ReplicationPolicyEngine
	
	// Configuration
	config           *ReplicaConfig
	
	// State management
	replicationState map[string]*ReplicationState
	stateMutex       sync.RWMutex
	
	// Background workers
	analysisWorker   *AnalysisWorker
	rebalanceWorker  *RebalanceWorker
	
	// Metrics and monitoring
	metrics          *ReplicationMetrics
	
	// Shutdown coordination
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
}

// ReplicaConfig holds configuration for replica management
type ReplicaConfig struct {
	// Replication bounds
	MinReplicas      int           `json:"min_replicas"`
	MaxReplicas      int           `json:"max_replicas"`
	DefaultReplicas  int           `json:"default_replicas"`
	
	// Analysis intervals
	AnalysisInterval time.Duration `json:"analysis_interval"`
	RebalanceInterval time.Duration `json:"rebalance_interval"`
	
	// Thresholds for replication decisions
	HighAccessThreshold    int64   `json:"high_access_threshold"`
	LowAccessThreshold     int64   `json:"low_access_threshold"`
	GeographicSpreadFactor float64 `json:"geographic_spread_factor"`
	
	// Performance tuning
	MaxConcurrentRebalance int `json:"max_concurrent_rebalance"`
	RebalanceBatchSize     int `json:"rebalance_batch_size"`
}

// ReplicationState tracks the current replication state of an object
type ReplicationState struct {
	CID                string                 `json:"cid"`
	CurrentReplicas    int                    `json:"current_replicas"`
	OptimalReplicas    int                    `json:"optimal_replicas"`
	ReplicaNodes       []string               `json:"replica_nodes"`
	GeographicDistribution map[string]int     `json:"geographic_distribution"`
	LastAnalyzed       time.Time              `json:"last_analyzed"`
	LastRebalanced     time.Time              `json:"last_rebalanced"`
	AccessPattern      *AccessPattern         `json:"access_pattern"`
	ReplicationPolicy  string                 `json:"replication_policy"`
}

// AccessPattern represents the access pattern analysis for an object
type AccessPattern struct {
	TotalAccesses      int64                  `json:"total_accesses"`
	RecentAccesses     int64                  `json:"recent_accesses"`
	AccessFrequency    float64                `json:"access_frequency"`
	GeographicAccess   map[string]int64       `json:"geographic_access"`
	PeerAccess         map[string]int64       `json:"peer_access"`
	TimePattern        map[int]int64          `json:"time_pattern"` // hour of day -> access count
	AccessTrend        AccessTrend            `json:"access_trend"`
	PredictedAccesses  int64                  `json:"predicted_accesses"`
}

// AccessTrend indicates the trend in access patterns
type AccessTrend int

const (
	TrendStable AccessTrend = iota
	TrendIncreasing
	TrendDecreasing
	TrendSpiky
	TrendSeasonal
)

// NewReplicaManager creates a new replica manager instance
func NewReplicaManager(clusterClient ClusterClientInterface, metadataStore MetadataStore, config *ReplicationConfig, logger interface{}) *ReplicaManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	rm := &ReplicaManager{
		clusterClient:    clusterClient,
		config:           config,
		replicationState: make(map[string]*ReplicationState),
		ctx:              ctx,
		cancel:           cancel,
		metrics:          NewReplicationMetrics(),
	}
	
	// Initialize components
	rm.accessAnalyzer = NewAccessPatternAnalyzer(config)
	rm.geoManager = NewGeographicManager(clusterClient)
	rm.rebalancer = NewReplicationRebalancer(clusterClient, config)
	rm.policyEngine = NewReplicationPolicyEngine(config)
	
	// Start background workers
	rm.startBackgroundWorkers()
	
	return rm
}

// AnalyzeAndOptimize performs analysis and optimization for a specific object
func (rm *ReplicaManager) AnalyzeAndOptimize(cid string, accessStats *AccessStats) error {
	rm.stateMutex.Lock()
	defer rm.stateMutex.Unlock()
	
	// Get or create replication state
	state, exists := rm.replicationState[cid]
	if !exists {
		state = &ReplicationState{
			CID:                    cid,
			CurrentReplicas:        rm.config.DefaultReplicas,
			ReplicaNodes:           []string{},
			GeographicDistribution: make(map[string]int),
			ReplicationPolicy:      "default",
		}
		rm.replicationState[cid] = state
	}
	
	// Analyze access patterns
	pattern, err := rm.accessAnalyzer.AnalyzePattern(cid, accessStats)
	if err != nil {
		return fmt.Errorf("failed to analyze access pattern: %w", err)
	}
	state.AccessPattern = pattern
	
	// Determine optimal replica count
	optimalReplicas := rm.calculateOptimalReplicas(pattern, state)
	state.OptimalReplicas = optimalReplicas
	
	// Get current cluster state
	clusterState, err := rm.clusterClient.GetClusterState()
	if err != nil {
		return fmt.Errorf("failed to get cluster state: %w", err)
	}
	
	// Determine optimal geographic distribution
	optimalDistribution := rm.calculateOptimalDistribution(pattern, clusterState)
	
	// Check if rebalancing is needed
	if rm.needsRebalancing(state, optimalDistribution) {
		err = rm.scheduleRebalancing(cid, state, optimalDistribution)
		if err != nil {
			return fmt.Errorf("failed to schedule rebalancing: %w", err)
		}
	}
	
	state.LastAnalyzed = time.Now()
	rm.metrics.RecordAnalysis(cid, pattern, optimalReplicas)
	
	return nil
}

// calculateOptimalReplicas determines the optimal number of replicas based on access patterns
func (rm *ReplicaManager) calculateOptimalReplicas(pattern *AccessPattern, state *ReplicationState) int {
	// Base replica count from policy
	policy := rm.policyEngine.GetPolicy(state.ReplicationPolicy)
	baseReplicas := policy.BaseReplicas
	
	// Adjust based on access frequency
	accessMultiplier := rm.calculateAccessMultiplier(pattern)
	
	// Adjust based on geographic spread
	geoMultiplier := rm.calculateGeographicMultiplier(pattern)
	
	// Adjust based on access trend
	trendMultiplier := rm.calculateTrendMultiplier(pattern)
	
	// Calculate optimal replicas
	optimal := float64(baseReplicas) * accessMultiplier * geoMultiplier * trendMultiplier
	
	// Apply bounds
	optimalInt := int(math.Round(optimal))
	if optimalInt < rm.config.MinReplicas {
		optimalInt = rm.config.MinReplicas
	}
	if optimalInt > rm.config.MaxReplicas {
		optimalInt = rm.config.MaxReplicas
	}
	
	return optimalInt
}

// calculateAccessMultiplier calculates multiplier based on access frequency
func (rm *ReplicaManager) calculateAccessMultiplier(pattern *AccessPattern) float64 {
	if pattern.RecentAccesses >= rm.config.HighAccessThreshold {
		// High access objects need more replicas
		return 1.5 + math.Log10(float64(pattern.RecentAccesses)/float64(rm.config.HighAccessThreshold))
	} else if pattern.RecentAccesses <= rm.config.LowAccessThreshold {
		// Low access objects need fewer replicas
		return 0.7
	}
	
	// Medium access objects use default
	return 1.0
}

// calculateGeographicMultiplier calculates multiplier based on geographic spread
func (rm *ReplicaManager) calculateGeographicMultiplier(pattern *AccessPattern) float64 {
	uniqueRegions := len(pattern.GeographicAccess)
	if uniqueRegions <= 1 {
		return 1.0
	}
	
	// More geographic spread requires more replicas
	return 1.0 + (float64(uniqueRegions-1) * rm.config.GeographicSpreadFactor)
}

// calculateTrendMultiplier calculates multiplier based on access trend
func (rm *ReplicaManager) calculateTrendMultiplier(pattern *AccessPattern) float64 {
	switch pattern.AccessTrend {
	case TrendIncreasing:
		return 1.3 // Anticipate higher demand
	case TrendDecreasing:
		return 0.8 // Reduce replicas for declining demand
	case TrendSpiky:
		return 1.2 // Handle spikes better
	case TrendSeasonal:
		return 1.1 // Slight increase for seasonal patterns
	default:
		return 1.0 // Stable trend
	}
}

// calculateOptimalDistribution determines optimal geographic distribution
func (rm *ReplicaManager) calculateOptimalDistribution(pattern *AccessPattern, clusterState *cluster.ClusterState) map[string]int {
	distribution := make(map[string]int)
	
	// Get total access count
	totalAccess := int64(0)
	for _, count := range pattern.GeographicAccess {
		totalAccess += count
	}
	
	if totalAccess == 0 {
		// No geographic data, use default distribution
		return rm.getDefaultDistribution(clusterState)
	}
	
	// Calculate replicas per region based on access patterns
	totalReplicas := rm.replicationState[pattern.CID].OptimalReplicas
	
	for region, accessCount := range pattern.GeographicAccess {
		// Calculate proportion of access from this region
		proportion := float64(accessCount) / float64(totalAccess)
		
		// Allocate replicas proportionally, with minimum of 1 if there's any access
		replicas := int(math.Ceil(proportion * float64(totalReplicas)))
		if replicas > 0 && accessCount > 0 {
			distribution[region] = replicas
		}
	}
	
	// Ensure we don't exceed total replicas
	totalAllocated := 0
	for _, count := range distribution {
		totalAllocated += count
	}
	
	if totalAllocated > totalReplicas {
		// Scale down proportionally
		scale := float64(totalReplicas) / float64(totalAllocated)
		for region := range distribution {
			distribution[region] = int(math.Floor(float64(distribution[region]) * scale))
		}
	}
	
	return distribution
}

// needsRebalancing checks if rebalancing is needed
func (rm *ReplicaManager) needsRebalancing(state *ReplicationState, optimalDistribution map[string]int) bool {
	// Check if replica count needs adjustment
	if state.CurrentReplicas != state.OptimalReplicas {
		return true
	}
	
	// Check if geographic distribution needs adjustment
	for region, optimal := range optimalDistribution {
		current, exists := state.GeographicDistribution[region]
		if !exists || current != optimal {
			return true
		}
	}
	
	// Check if it's been too long since last rebalance
	if time.Since(state.LastRebalanced) > rm.config.RebalanceInterval*2 {
		return true
	}
	
	return false
}

// scheduleRebalancing schedules a rebalancing operation
func (rm *ReplicaManager) scheduleRebalancing(cid string, state *ReplicationState, optimalDistribution map[string]int) error {
	rebalanceTask := &RebalanceTask{
		CID:                    cid,
		CurrentReplicas:        state.CurrentReplicas,
		TargetReplicas:         state.OptimalReplicas,
		CurrentDistribution:    state.GeographicDistribution,
		TargetDistribution:     optimalDistribution,
		Priority:               rm.calculateRebalancePriority(state),
		ScheduledAt:            time.Now(),
	}
	
	return rm.rebalancer.ScheduleRebalance(rebalanceTask)
}

// calculateRebalancePriority calculates priority for rebalancing task
func (rm *ReplicaManager) calculateRebalancePriority(state *ReplicationState) RebalancePriority {
	// High priority for objects with high access and suboptimal replication
	if state.AccessPattern.RecentAccesses >= rm.config.HighAccessThreshold {
		if state.CurrentReplicas < state.OptimalReplicas {
			return PriorityHigh
		}
	}
	
	// Medium priority for objects with medium access
	if state.AccessPattern.RecentAccesses > rm.config.LowAccessThreshold {
		return PriorityMedium
	}
	
	// Low priority for low access objects
	return PriorityLow
}

// getDefaultDistribution returns default geographic distribution
func (rm *ReplicaManager) getDefaultDistribution(clusterState *cluster.ClusterState) map[string]int {
	distribution := make(map[string]int)
	
	// Distribute evenly across available regions
	regions := clusterState.GetAvailableRegions()
	if len(regions) == 0 {
		return distribution
	}
	
	replicasPerRegion := rm.config.DefaultReplicas / len(regions)
	remainder := rm.config.DefaultReplicas % len(regions)
	
	for i, region := range regions {
		distribution[region] = replicasPerRegion
		if i < remainder {
			distribution[region]++
		}
	}
	
	return distribution
}

// startBackgroundWorkers starts background analysis and rebalancing workers
func (rm *ReplicaManager) startBackgroundWorkers() {
	// Start analysis worker
	rm.wg.Add(1)
	go func() {
		defer rm.wg.Done()
		rm.runAnalysisWorker()
	}()
	
	// Start rebalance worker
	rm.wg.Add(1)
	go func() {
		defer rm.wg.Done()
		rm.runRebalanceWorker()
	}()
}

// runAnalysisWorker runs periodic analysis of all objects
func (rm *ReplicaManager) runAnalysisWorker() {
	ticker := time.NewTicker(rm.config.AnalysisInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			rm.performPeriodicAnalysis()
		}
	}
}

// runRebalanceWorker runs periodic rebalancing operations
func (rm *ReplicaManager) runRebalanceWorker() {
	ticker := time.NewTicker(rm.config.RebalanceInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			rm.performPeriodicRebalancing()
		}
	}
}

// performPeriodicAnalysis performs periodic analysis of all tracked objects
func (rm *ReplicaManager) performPeriodicAnalysis() {
	rm.stateMutex.RLock()
	cids := make([]string, 0, len(rm.replicationState))
	for cid := range rm.replicationState {
		cids = append(cids, cid)
	}
	rm.stateMutex.RUnlock()
	
	// Process in batches to avoid overwhelming the system
	batchSize := 1000
	for i := 0; i < len(cids); i += batchSize {
		end := i + batchSize
		if end > len(cids) {
			end = len(cids)
		}
		
		batch := cids[i:end]
		rm.processBatchAnalysis(batch)
		
		// Small delay between batches
		select {
		case <-rm.ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// processBatchAnalysis processes a batch of objects for analysis
func (rm *ReplicaManager) processBatchAnalysis(cids []string) {
	for _, cid := range cids {
		select {
		case <-rm.ctx.Done():
			return
		default:
			// Get access stats for this CID
			accessStats, err := rm.accessAnalyzer.GetAccessStats(cid)
			if err != nil {
				continue // Skip objects with no access stats
			}
			
			// Perform analysis and optimization
			err = rm.AnalyzeAndOptimize(cid, accessStats)
			if err != nil {
				// Log error but continue processing
				continue
			}
		}
	}
}

// performPeriodicRebalancing performs periodic rebalancing operations
func (rm *ReplicaManager) performPeriodicRebalancing() {
	err := rm.rebalancer.ProcessPendingRebalances(rm.config.MaxConcurrentRebalance)
	if err != nil {
		// Log error but continue
		return
	}
}

// GetReplicationState returns the current replication state for an object
func (rm *ReplicaManager) GetReplicationState(cid string) (*ReplicationState, error) {
	rm.stateMutex.RLock()
	defer rm.stateMutex.RUnlock()
	
	state, exists := rm.replicationState[cid]
	if !exists {
		return nil, fmt.Errorf("no replication state found for CID: %s", cid)
	}
	
	// Return a copy to avoid race conditions
	stateCopy := *state
	return &stateCopy, nil
}

// UpdateReplicationState updates the replication state for an object
func (rm *ReplicaManager) UpdateReplicationState(cid string, state *ReplicationState) error {
	rm.stateMutex.Lock()
	defer rm.stateMutex.Unlock()
	
	rm.replicationState[cid] = state
	return nil
}

// GetMetrics returns current replication metrics
func (rm *ReplicaManager) GetMetrics() *ReplicationMetrics {
	return rm.metrics
}

// Shutdown gracefully shuts down the replica manager
func (rm *ReplicaManager) Shutdown() error {
	rm.cancel()
	rm.wg.Wait()
	
	return nil
}