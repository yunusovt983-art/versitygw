package ipfs

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// HealthChecker monitors the health of IPFS cluster nodes
type HealthChecker struct {
	clusterClient ClusterClientInterface
	interval      time.Duration
	logger        *logrus.Logger
	
	// State management
	mu          sync.RWMutex
	nodeHealth  map[string]*NodeHealth
	isRunning   bool
	stopChan    chan struct{}
	
	// Callbacks
	onNodeFailure  func(nodeID string, health *NodeHealth)
	onNodeRecovery func(nodeID string, health *NodeHealth)
}

type NodeHealth struct {
	NodeID           string        `json:"node_id"`
	IsHealthy        bool          `json:"is_healthy"`
	LastSeen         time.Time     `json:"last_seen"`
	LastHealthCheck  time.Time     `json:"last_health_check"`
	ConsecutiveFails int           `json:"consecutive_fails"`
	ResponseTime     time.Duration `json:"response_time"`
	ErrorCount       int64         `json:"error_count"`
	Status           HealthNodeStatus    `json:"status"`
	Metadata         map[string]interface{} `json:"metadata"`
}

type HealthNodeStatus int

const (
	HealthNodeStatusHealthy HealthNodeStatus = iota
	HealthNodeStatusDegraded
	HealthNodeStatusUnhealthy
	HealthNodeStatusUnknown
)

// NewHealthChecker creates a new health checker
func NewHealthChecker(
	clusterClient ClusterClientInterface,
	interval time.Duration,
	logger *logrus.Logger,
) *HealthChecker {
	return &HealthChecker{
		clusterClient: clusterClient,
		interval:      interval,
		logger:        logger,
		nodeHealth:    make(map[string]*NodeHealth),
		stopChan:      make(chan struct{}),
	}
}

// Start begins health monitoring
func (hc *HealthChecker) Start(ctx context.Context) {
	hc.mu.Lock()
	if hc.isRunning {
		hc.mu.Unlock()
		return
	}
	hc.isRunning = true
	hc.mu.Unlock()

	hc.logger.Info("Starting health checker")

	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	// Initial health check
	hc.performHealthCheck(ctx)

	for {
		select {
		case <-ctx.Done():
			hc.logger.Info("Health checker stopping due to context cancellation")
			return
		case <-hc.stopChan:
			hc.logger.Info("Health checker stopping")
			return
		case <-ticker.C:
			hc.performHealthCheck(ctx)
		}
	}
}

// Stop stops the health checker
func (hc *HealthChecker) Stop() {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if !hc.isRunning {
		return
	}

	hc.isRunning = false
	close(hc.stopChan)
}

// SetNodeFailureCallback sets the callback for node failures
func (hc *HealthChecker) SetNodeFailureCallback(callback func(nodeID string, health *NodeHealth)) {
	hc.onNodeFailure = callback
}

// SetNodeRecoveryCallback sets the callback for node recoveries
func (hc *HealthChecker) SetNodeRecoveryCallback(callback func(nodeID string, health *NodeHealth)) {
	hc.onNodeRecovery = callback
}

// performHealthCheck performs a health check on all cluster nodes
func (hc *HealthChecker) performHealthCheck(ctx context.Context) {
	hc.logger.Debug("Performing health check")

	// Get cluster peers
	peers, err := hc.clusterClient.GetPeers()
	if err != nil {
		hc.logger.WithError(err).Error("Failed to get cluster peers")
		return
	}

	// Check each peer
	for _, peer := range peers {
		hc.checkNodeHealth(ctx, peer.ID)
	}

	// Clean up health records for nodes that are no longer in the cluster
	hc.cleanupStaleNodes(peers)
}

// checkNodeHealth checks the health of a specific node
func (hc *HealthChecker) checkNodeHealth(ctx context.Context, nodeID string) {
	startTime := time.Now()
	
	// Perform health check
	isHealthy, err := hc.performNodeHealthCheck(ctx, nodeID)
	responseTime := time.Since(startTime)

	hc.mu.Lock()
	defer hc.mu.Unlock()

	// Get or create node health record
	health, exists := hc.nodeHealth[nodeID]
	if !exists {
		health = &NodeHealth{
			NodeID:   nodeID,
			Metadata: make(map[string]interface{}),
		}
		hc.nodeHealth[nodeID] = health
	}

	// Update health record
	previouslyHealthy := health.IsHealthy
	health.LastHealthCheck = time.Now()
	health.ResponseTime = responseTime

	if err != nil {
		health.ConsecutiveFails++
		health.ErrorCount++
		health.IsHealthy = false
		
		// Determine status based on consecutive failures
		if health.ConsecutiveFails >= 5 {
			health.Status = HealthNodeStatusUnhealthy
		} else if health.ConsecutiveFails >= 2 {
			health.Status = HealthNodeStatusDegraded
		}

		hc.logger.WithFields(logrus.Fields{
			"node_id":          nodeID,
			"consecutive_fails": health.ConsecutiveFails,
			"error":            err,
		}).Warn("Node health check failed")
	} else {
		if isHealthy {
			health.ConsecutiveFails = 0
			health.IsHealthy = true
			health.LastSeen = time.Now()
			health.Status = HealthNodeStatusHealthy
		} else {
			health.ConsecutiveFails++
			health.IsHealthy = false
			health.Status = HealthNodeStatusDegraded
		}
	}

	// Trigger callbacks for state changes
	if previouslyHealthy && !health.IsHealthy && hc.onNodeFailure != nil {
		go hc.onNodeFailure(nodeID, health)
	} else if !previouslyHealthy && health.IsHealthy && hc.onNodeRecovery != nil {
		go hc.onNodeRecovery(nodeID, health)
	}
}

// performNodeHealthCheck performs the actual health check on a node
func (hc *HealthChecker) performNodeHealthCheck(ctx context.Context, nodeID string) (bool, error) {
	// Create a timeout context for the health check
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Check if node is reachable
	if err := hc.clusterClient.PingNode(checkCtx, nodeID); err != nil {
		return false, err
	}

	// Check node status
	status, err := hc.clusterClient.GetNodeStatusByID(checkCtx, nodeID)
	if err != nil {
		return false, err
	}

	// Node is healthy if it's reachable and in good status
	return status.IsHealthy, nil
}

// cleanupStaleNodes removes health records for nodes no longer in cluster
func (hc *HealthChecker) cleanupStaleNodes(currentPeers []PeerInfo) {
	currentNodeIDs := make(map[string]bool)
	for _, peer := range currentPeers {
		currentNodeIDs[peer.ID] = true
	}

	// Remove health records for nodes not in current peer list
	for nodeID := range hc.nodeHealth {
		if !currentNodeIDs[nodeID] {
			delete(hc.nodeHealth, nodeID)
			hc.logger.WithField("node_id", nodeID).Info("Removed stale node health record")
		}
	}
}

// GetNodeHealth returns the health status of a specific node
func (hc *HealthChecker) GetNodeHealth(nodeID string) (*NodeHealth, bool) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	health, exists := hc.nodeHealth[nodeID]
	if !exists {
		return nil, false
	}
	
	// Return a copy to avoid race conditions
	healthCopy := *health
	return &healthCopy, true
}

// GetAllNodeHealth returns health status of all nodes
func (hc *HealthChecker) GetAllNodeHealth() map[string]*NodeHealth {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	result := make(map[string]*NodeHealth)
	for nodeID, health := range hc.nodeHealth {
		healthCopy := *health
		result[nodeID] = &healthCopy
	}
	
	return result
}

// GetHealthyNodes returns a list of healthy node IDs
func (hc *HealthChecker) GetHealthyNodes() []string {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	healthyNodes := make([]string, 0)
	for nodeID, health := range hc.nodeHealth {
		if health.IsHealthy {
			healthyNodes = append(healthyNodes, nodeID)
		}
	}
	
	return healthyNodes
}

// GetUnhealthyNodes returns a list of unhealthy node IDs
func (hc *HealthChecker) GetUnhealthyNodes() []string {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	unhealthyNodes := make([]string, 0)
	for nodeID, health := range hc.nodeHealth {
		if !health.IsHealthy {
			unhealthyNodes = append(unhealthyNodes, nodeID)
		}
	}
	
	return unhealthyNodes
}

// GetClusterHealth returns overall cluster health statistics
func (hc *HealthChecker) GetClusterHealth() *ClusterHealth {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	clusterHealth := &ClusterHealth{
		TotalNodes:     len(hc.nodeHealth),
		HealthyNodes:   0,
		UnhealthyNodes: 0,
		DegradedNodes:  0,
		UnknownNodes:   0,
		LastCheck:      time.Now(),
	}
	
	for _, health := range hc.nodeHealth {
		switch health.Status {
		case HealthNodeStatusHealthy:
			clusterHealth.HealthyNodes++
		case HealthNodeStatusDegraded:
			clusterHealth.DegradedNodes++
		case HealthNodeStatusUnhealthy:
			clusterHealth.UnhealthyNodes++
		case HealthNodeStatusUnknown:
			clusterHealth.UnknownNodes++
		}
	}
	
	// Calculate health percentage
	if clusterHealth.TotalNodes > 0 {
		clusterHealth.HealthPercentage = float64(clusterHealth.HealthyNodes) / float64(clusterHealth.TotalNodes) * 100
	}
	
	// Determine overall status
	if clusterHealth.HealthPercentage >= 90 {
		clusterHealth.OverallStatus = ClusterStatusHealthy
	} else if clusterHealth.HealthPercentage >= 70 {
		clusterHealth.OverallStatus = ClusterStatusDegraded
	} else {
		clusterHealth.OverallStatus = ClusterStatusUnhealthy
	}
	
	return clusterHealth
}

// ClusterHealth represents overall cluster health
type ClusterHealth struct {
	TotalNodes       int           `json:"total_nodes"`
	HealthyNodes     int           `json:"healthy_nodes"`
	UnhealthyNodes   int           `json:"unhealthy_nodes"`
	DegradedNodes    int           `json:"degraded_nodes"`
	UnknownNodes     int           `json:"unknown_nodes"`
	HealthPercentage float64       `json:"health_percentage"`
	OverallStatus    ClusterStatus `json:"overall_status"`
	LastCheck        time.Time     `json:"last_check"`
}

type ClusterStatus int

const (
	ClusterStatusHealthy ClusterStatus = iota
	ClusterStatusDegraded
	ClusterStatusUnhealthy
	ClusterStatusUnknown
)

// HealthNodeStatusInfo represents detailed node status information for health checking
type HealthNodeStatusInfo struct {
	IsHealthy bool                   `json:"is_healthy"`
	Metadata  map[string]interface{} `json:"metadata"`
}