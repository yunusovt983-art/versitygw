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

package auth

import (
	"context"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net/http"
	"sort"
	"sync"
	"time"
)

// LoadBalancerSupport provides load balancing capabilities for authentication services
type LoadBalancerSupport interface {
	// Node selection
	SelectNode(sessionID string) (*NodeInfo, error)
	SelectNodeForUser(userID string) (*NodeInfo, error)
	GetHealthyNodes() []*NodeInfo
	
	// Session affinity
	SetSessionAffinity(sessionID, nodeID string) error
	GetSessionAffinity(sessionID string) (string, error)
	RemoveSessionAffinity(sessionID string) error
	
	// Health monitoring
	UpdateNodeHealth(nodeID string, health *NodeHealth) error
	GetNodeLoad(nodeID string) (*NodeLoad, error)
	
	// Load balancing strategies
	SetStrategy(strategy LoadBalancingStrategy) error
	GetStrategy() LoadBalancingStrategy
	
	// Lifecycle
	Start() error
	Stop() error
}

// LoadBalancingStrategy defines different load balancing strategies
type LoadBalancingStrategy int

const (
	RoundRobin LoadBalancingStrategy = iota
	LeastConnections
	WeightedRoundRobin
	ConsistentHashing
	IPHash
	SessionAffinity
)

// String returns string representation of LoadBalancingStrategy
func (s LoadBalancingStrategy) String() string {
	switch s {
	case RoundRobin:
		return "round_robin"
	case LeastConnections:
		return "least_connections"
	case WeightedRoundRobin:
		return "weighted_round_robin"
	case ConsistentHashing:
		return "consistent_hashing"
	case IPHash:
		return "ip_hash"
	case SessionAffinity:
		return "session_affinity"
	default:
		return "unknown"
	}
}

// NodeLoad represents the current load on a node
type NodeLoad struct {
	NodeID           string    `json:"node_id"`
	ActiveSessions   int       `json:"active_sessions"`
	CPUUsage         float64   `json:"cpu_usage"`
	MemoryUsage      float64   `json:"memory_usage"`
	RequestsPerSecond float64  `json:"requests_per_second"`
	ResponseTime     time.Duration `json:"response_time"`
	Weight           int       `json:"weight"`
	LastUpdate       time.Time `json:"last_update"`
}

// LoadBalancerConfig holds configuration for load balancer
type LoadBalancerConfig struct {
	Strategy              LoadBalancingStrategy `json:"strategy"`
	HealthCheckInterval   time.Duration         `json:"health_check_interval"`
	UnhealthyThreshold    int                   `json:"unhealthy_threshold"`
	HealthyThreshold      int                   `json:"healthy_threshold"`
	SessionAffinityTTL    time.Duration         `json:"session_affinity_ttl"`
	EnableStickySessions  bool                  `json:"enable_sticky_sessions"`
	MaxRetries            int                   `json:"max_retries"`
}

// DefaultLoadBalancerConfig returns default load balancer configuration
func DefaultLoadBalancerConfig() *LoadBalancerConfig {
	return &LoadBalancerConfig{
		Strategy:              RoundRobin,
		HealthCheckInterval:   30 * time.Second,
		UnhealthyThreshold:    3,
		HealthyThreshold:      2,
		SessionAffinityTTL:    1 * time.Hour,
		EnableStickySessions:  true,
		MaxRetries:            3,
	}
}

// loadBalancerImpl implements LoadBalancerSupport
type loadBalancerImpl struct {
	config          *LoadBalancerConfig
	clusterManager  ClusterManager
	nodes           map[string]*NodeInfo
	nodeLoads       map[string]*NodeLoad
	sessionAffinity map[string]string // sessionID -> nodeID
	mu              sync.RWMutex
	
	// Round robin state
	roundRobinIndex int
	
	// Consistent hashing
	hashRing *ConsistentHashRing
	
	// Background processes
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
}

// NewLoadBalancerSupport creates a new load balancer support instance
func NewLoadBalancerSupport(config *LoadBalancerConfig, clusterManager ClusterManager) LoadBalancerSupport {
	if config == nil {
		config = DefaultLoadBalancerConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	lb := &loadBalancerImpl{
		config:          config,
		clusterManager:  clusterManager,
		nodes:           make(map[string]*NodeInfo),
		nodeLoads:       make(map[string]*NodeLoad),
		sessionAffinity: make(map[string]string),
		hashRing:        NewConsistentHashRing(),
		ctx:             ctx,
		cancel:          cancel,
	}
	
	return lb
}

// SelectNode selects a node based on the configured strategy
func (lb *loadBalancerImpl) SelectNode(sessionID string) (*NodeInfo, error) {
	// Check session affinity first if enabled
	if lb.config.EnableStickySessions && sessionID != "" {
		if nodeID, err := lb.GetSessionAffinity(sessionID); err == nil && nodeID != "" {
			if node, err := lb.getNode(nodeID); err == nil && lb.isNodeHealthy(node) {
				return node, nil
			}
			// Remove stale affinity
			lb.RemoveSessionAffinity(sessionID)
		}
	}
	
	healthyNodes := lb.GetHealthyNodes()
	if len(healthyNodes) == 0 {
		return nil, fmt.Errorf("no healthy nodes available")
	}
	
	var selectedNode *NodeInfo
	var err error
	
	switch lb.config.Strategy {
	case RoundRobin:
		selectedNode, err = lb.selectRoundRobin(healthyNodes)
	case LeastConnections:
		selectedNode, err = lb.selectLeastConnections(healthyNodes)
	case WeightedRoundRobin:
		selectedNode, err = lb.selectWeightedRoundRobin(healthyNodes)
	case ConsistentHashing:
		selectedNode, err = lb.selectConsistentHash(sessionID, healthyNodes)
	case IPHash:
		selectedNode, err = lb.selectIPHash(sessionID, healthyNodes)
	default:
		selectedNode, err = lb.selectRoundRobin(healthyNodes)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Set session affinity if enabled
	if lb.config.EnableStickySessions && sessionID != "" && selectedNode != nil {
		lb.SetSessionAffinity(sessionID, selectedNode.ID)
	}
	
	return selectedNode, nil
}

// SelectNodeForUser selects a node for a specific user
func (lb *loadBalancerImpl) SelectNodeForUser(userID string) (*NodeInfo, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}
	
	// Use consistent hashing for user-based selection
	healthyNodes := lb.GetHealthyNodes()
	if len(healthyNodes) == 0 {
		return nil, fmt.Errorf("no healthy nodes available")
	}
	
	return lb.selectConsistentHash(userID, healthyNodes)
}

// GetHealthyNodes returns all healthy nodes
func (lb *loadBalancerImpl) GetHealthyNodes() []*NodeInfo {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	var healthyNodes []*NodeInfo
	for _, node := range lb.nodes {
		if lb.isNodeHealthy(node) {
			healthyNodes = append(healthyNodes, node)
		}
	}
	
	return healthyNodes
}

// SetSessionAffinity sets session affinity to a specific node
func (lb *loadBalancerImpl) SetSessionAffinity(sessionID, nodeID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}
	if nodeID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}
	
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	lb.sessionAffinity[sessionID] = nodeID
	
	// Set expiration (simplified - in practice would use a proper TTL mechanism)
	go func() {
		time.Sleep(lb.config.SessionAffinityTTL)
		lb.RemoveSessionAffinity(sessionID)
	}()
	
	return nil
}

// GetSessionAffinity gets the node affinity for a session
func (lb *loadBalancerImpl) GetSessionAffinity(sessionID string) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("session ID cannot be empty")
	}
	
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	nodeID, exists := lb.sessionAffinity[sessionID]
	if !exists {
		return "", fmt.Errorf("no affinity found for session: %s", sessionID)
	}
	
	return nodeID, nil
}

// RemoveSessionAffinity removes session affinity
func (lb *loadBalancerImpl) RemoveSessionAffinity(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}
	
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	delete(lb.sessionAffinity, sessionID)
	return nil
}

// UpdateNodeHealth updates the health information for a node
func (lb *loadBalancerImpl) UpdateNodeHealth(nodeID string, health *NodeHealth) error {
	if nodeID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}
	if health == nil {
		return fmt.Errorf("health cannot be nil")
	}
	
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	// Update node status
	if node, exists := lb.nodes[nodeID]; exists {
		node.Status = health.Status
		node.LastSeen = health.LastHealthCheck
	}
	
	// Update or create node load information
	if load, exists := lb.nodeLoads[nodeID]; exists {
		load.ActiveSessions = health.ActiveSessions
		load.CPUUsage = health.CPUUsage
		load.MemoryUsage = health.MemoryUsage
		load.ResponseTime = health.ResponseTime
		load.LastUpdate = time.Now()
	} else {
		lb.nodeLoads[nodeID] = &NodeLoad{
			NodeID:         nodeID,
			ActiveSessions: health.ActiveSessions,
			CPUUsage:       health.CPUUsage,
			MemoryUsage:    health.MemoryUsage,
			ResponseTime:   health.ResponseTime,
			Weight:         1, // Default weight
			LastUpdate:     time.Now(),
		}
	}
	
	return nil
}

// GetNodeLoad returns the current load for a node
func (lb *loadBalancerImpl) GetNodeLoad(nodeID string) (*NodeLoad, error) {
	if nodeID == "" {
		return nil, fmt.Errorf("node ID cannot be empty")
	}
	
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	load, exists := lb.nodeLoads[nodeID]
	if !exists {
		return nil, fmt.Errorf("no load information for node: %s", nodeID)
	}
	
	// Return copy to avoid race conditions
	loadCopy := *load
	return &loadCopy, nil
}

// SetStrategy sets the load balancing strategy
func (lb *loadBalancerImpl) SetStrategy(strategy LoadBalancingStrategy) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	lb.config.Strategy = strategy
	
	// Reset strategy-specific state
	if strategy == ConsistentHashing {
		lb.rebuildHashRing()
	}
	
	return nil
}

// GetStrategy returns the current load balancing strategy
func (lb *loadBalancerImpl) GetStrategy() LoadBalancingStrategy {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	return lb.config.Strategy
}

// Start starts the load balancer
func (lb *loadBalancerImpl) Start() error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	if lb.running {
		return nil
	}
	
	// Initialize nodes from cluster manager
	if lb.clusterManager != nil {
		nodes := lb.clusterManager.GetNodes()
		for _, node := range nodes {
			lb.nodes[node.ID] = node
			lb.nodeLoads[node.ID] = &NodeLoad{
				NodeID:     node.ID,
				Weight:     1,
				LastUpdate: time.Now(),
			}
		}
		
		// Build hash ring for consistent hashing
		lb.rebuildHashRing()
	}
	
	// Start background health monitoring
	go lb.healthMonitorLoop()
	
	lb.running = true
	return nil
}

// Stop stops the load balancer
func (lb *loadBalancerImpl) Stop() error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	if !lb.running {
		return nil
	}
	
	if lb.cancel != nil {
		lb.cancel()
	}
	
	lb.running = false
	return nil
}

// Load balancing strategy implementations

// selectRoundRobin selects a node using round-robin strategy
func (lb *loadBalancerImpl) selectRoundRobin(nodes []*NodeInfo) (*NodeInfo, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes available")
	}
	
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	if lb.roundRobinIndex >= len(nodes) {
		lb.roundRobinIndex = 0
	}
	
	selectedNode := nodes[lb.roundRobinIndex]
	lb.roundRobinIndex++
	
	return selectedNode, nil
}

// selectLeastConnections selects the node with least connections
func (lb *loadBalancerImpl) selectLeastConnections(nodes []*NodeInfo) (*NodeInfo, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes available")
	}
	
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	var selectedNode *NodeInfo
	minConnections := -1
	
	for _, node := range nodes {
		if load, exists := lb.nodeLoads[node.ID]; exists {
			if minConnections == -1 || load.ActiveSessions < minConnections {
				minConnections = load.ActiveSessions
				selectedNode = node
			}
		} else {
			// Node with no load info is preferred
			selectedNode = node
			break
		}
	}
	
	if selectedNode == nil {
		selectedNode = nodes[0] // Fallback
	}
	
	return selectedNode, nil
}

// selectWeightedRoundRobin selects a node using weighted round-robin
func (lb *loadBalancerImpl) selectWeightedRoundRobin(nodes []*NodeInfo) (*NodeInfo, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes available")
	}
	
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	// Calculate total weight
	totalWeight := 0
	for _, node := range nodes {
		if load, exists := lb.nodeLoads[node.ID]; exists {
			totalWeight += load.Weight
		} else {
			totalWeight += 1 // Default weight
		}
	}
	
	if totalWeight == 0 {
		return nodes[0], nil // Fallback
	}
	
	// Select based on weight
	target := rand.Intn(totalWeight)
	currentWeight := 0
	
	for _, node := range nodes {
		weight := 1
		if load, exists := lb.nodeLoads[node.ID]; exists {
			weight = load.Weight
		}
		
		currentWeight += weight
		if currentWeight > target {
			return node, nil
		}
	}
	
	return nodes[0], nil // Fallback
}

// selectConsistentHash selects a node using consistent hashing
func (lb *loadBalancerImpl) selectConsistentHash(key string, nodes []*NodeInfo) (*NodeInfo, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes available")
	}
	
	if key == "" {
		// Fallback to round robin if no key
		return lb.selectRoundRobin(nodes)
	}
	
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	nodeID := lb.hashRing.GetNode(key)
	if nodeID == "" {
		return nodes[0], nil // Fallback
	}
	
	// Find the node
	for _, node := range nodes {
		if node.ID == nodeID {
			return node, nil
		}
	}
	
	return nodes[0], nil // Fallback
}

// selectIPHash selects a node based on IP hash
func (lb *loadBalancerImpl) selectIPHash(key string, nodes []*NodeInfo) (*NodeInfo, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes available")
	}
	
	if key == "" {
		return lb.selectRoundRobin(nodes)
	}
	
	// Hash the key
	h := fnv.New32a()
	h.Write([]byte(key))
	hash := h.Sum32()
	
	// Select node based on hash
	index := int(hash) % len(nodes)
	return nodes[index], nil
}

// Helper methods

// getNode retrieves a node by ID
func (lb *loadBalancerImpl) getNode(nodeID string) (*NodeInfo, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	node, exists := lb.nodes[nodeID]
	if !exists {
		return nil, fmt.Errorf("node not found: %s", nodeID)
	}
	
	return node, nil
}

// isNodeHealthy checks if a node is healthy
func (lb *loadBalancerImpl) isNodeHealthy(node *NodeInfo) bool {
	return node.Status == NodeStatusHealthy || node.Status == NodeStatusDegraded
}

// rebuildHashRing rebuilds the consistent hash ring
func (lb *loadBalancerImpl) rebuildHashRing() {
	lb.hashRing = NewConsistentHashRing()
	for nodeID := range lb.nodes {
		lb.hashRing.AddNode(nodeID)
	}
}

// healthMonitorLoop monitors node health
func (lb *loadBalancerImpl) healthMonitorLoop() {
	ticker := time.NewTicker(lb.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-lb.ctx.Done():
			return
		case <-ticker.C:
			lb.updateNodesFromCluster()
		}
	}
}

// updateNodesFromCluster updates node information from cluster manager
func (lb *loadBalancerImpl) updateNodesFromCluster() {
	if lb.clusterManager == nil {
		return
	}
	
	nodes := lb.clusterManager.GetNodes()
	clusterHealth := lb.clusterManager.GetClusterHealth()
	
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	// Update nodes
	newNodes := make(map[string]*NodeInfo)
	for _, node := range nodes {
		newNodes[node.ID] = node
		
		// Update health if available
		if nodeHealth, exists := clusterHealth.NodeHealths[node.ID]; exists {
			lb.UpdateNodeHealth(node.ID, nodeHealth)
		}
	}
	
	// Check for removed nodes
	for nodeID := range lb.nodes {
		if _, exists := newNodes[nodeID]; !exists {
			delete(lb.nodes, nodeID)
			delete(lb.nodeLoads, nodeID)
		}
	}
	
	lb.nodes = newNodes
	
	// Rebuild hash ring if using consistent hashing
	if lb.config.Strategy == ConsistentHashing {
		lb.rebuildHashRing()
	}
}

// ConsistentHashRing implements consistent hashing
type ConsistentHashRing struct {
	nodes    map[uint32]string
	sortedHashes []uint32
	mu       sync.RWMutex
}

// NewConsistentHashRing creates a new consistent hash ring
func NewConsistentHashRing() *ConsistentHashRing {
	return &ConsistentHashRing{
		nodes: make(map[uint32]string),
	}
}

// AddNode adds a node to the hash ring
func (c *ConsistentHashRing) AddNode(nodeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Add multiple virtual nodes for better distribution
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("%s:%d", nodeID, i)
		hash := c.hash(key)
		c.nodes[hash] = nodeID
		c.sortedHashes = append(c.sortedHashes, hash)
	}
	
	sort.Slice(c.sortedHashes, func(i, j int) bool {
		return c.sortedHashes[i] < c.sortedHashes[j]
	})
}

// RemoveNode removes a node from the hash ring
func (c *ConsistentHashRing) RemoveNode(nodeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Remove all virtual nodes
	var newHashes []uint32
	for _, hash := range c.sortedHashes {
		if c.nodes[hash] != nodeID {
			newHashes = append(newHashes, hash)
		} else {
			delete(c.nodes, hash)
		}
	}
	
	c.sortedHashes = newHashes
}

// GetNode gets the node for a given key
func (c *ConsistentHashRing) GetNode(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if len(c.sortedHashes) == 0 {
		return ""
	}
	
	hash := c.hash(key)
	
	// Find the first node with hash >= key hash
	idx := sort.Search(len(c.sortedHashes), func(i int) bool {
		return c.sortedHashes[i] >= hash
	})
	
	// Wrap around if necessary
	if idx == len(c.sortedHashes) {
		idx = 0
	}
	
	return c.nodes[c.sortedHashes[idx]]
}

// hash computes hash for a key
func (c *ConsistentHashRing) hash(key string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key))
	return h.Sum32()
}

// LoadBalancerMiddleware provides HTTP middleware for load balancing
func LoadBalancerMiddleware(lb LoadBalancerSupport) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract session ID from request (from cookie, header, etc.)
			sessionID := extractSessionID(r)
			
			// Select appropriate node
			node, err := lb.SelectNode(sessionID)
			if err != nil {
				http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
				return
			}
			
			// Add node information to request context
			ctx := context.WithValue(r.Context(), "selected_node", node)
			r = r.WithContext(ctx)
			
			next.ServeHTTP(w, r)
		})
	}
}

// extractSessionID extracts session ID from HTTP request
func extractSessionID(r *http.Request) string {
	// Try to get from Authorization header
	if auth := r.Header.Get("Authorization"); auth != "" {
		// Extract session ID from bearer token or similar
		// This is simplified - actual implementation would parse the token
		return auth
	}
	
	// Try to get from cookie
	if cookie, err := r.Cookie("session_id"); err == nil {
		return cookie.Value
	}
	
	// Try to get from query parameter
	if sessionID := r.URL.Query().Get("session_id"); sessionID != "" {
		return sessionID
	}
	
	// Fallback to IP address for IP-based load balancing
	return r.RemoteAddr
}