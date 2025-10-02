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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// ClusterManager manages cluster communication and node discovery
type ClusterManager interface {
	// Node management
	RegisterNode(nodeInfo *NodeInfo) error
	UnregisterNode(nodeID string) error
	GetNodes() []*NodeInfo
	GetNode(nodeID string) (*NodeInfo, error)
	
	// Communication
	Broadcast(messageType string, data []byte) error
	SendToNode(nodeID, messageType string, data []byte) error
	
	// Health monitoring
	CheckNodeHealth(nodeID string) (*NodeHealth, error)
	GetClusterHealth() *ClusterHealth
	
	// Event handling
	RegisterEventHandler(messageType string, handler EventHandler) error
	UnregisterEventHandler(messageType string) error
	
	// Lifecycle
	Start() error
	Stop() error
	IsRunning() bool
}

// NodeInfo represents information about a cluster node
type NodeInfo struct {
	ID          string            `json:"id"`
	Address     string            `json:"address"`
	Port        int               `json:"port"`
	Status      NodeStatus        `json:"status"`
	LastSeen    time.Time         `json:"last_seen"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Capabilities []string         `json:"capabilities,omitempty"`
}

// NodeStatus represents the status of a cluster node
type NodeStatus int

const (
	NodeStatusUnknown NodeStatus = iota
	NodeStatusHealthy
	NodeStatusDegraded
	NodeStatusUnhealthy
	NodeStatusOffline
)

// String returns string representation of NodeStatus
func (s NodeStatus) String() string {
	switch s {
	case NodeStatusHealthy:
		return "healthy"
	case NodeStatusDegraded:
		return "degraded"
	case NodeStatusUnhealthy:
		return "unhealthy"
	case NodeStatusOffline:
		return "offline"
	default:
		return "unknown"
	}
}

// NodeHealth represents health information for a node
type NodeHealth struct {
	NodeID           string        `json:"node_id"`
	Status           NodeStatus    `json:"status"`
	LastHealthCheck  time.Time     `json:"last_health_check"`
	ResponseTime     time.Duration `json:"response_time"`
	ErrorCount       int           `json:"error_count"`
	MemoryUsage      float64       `json:"memory_usage"`
	CPUUsage         float64       `json:"cpu_usage"`
	ActiveSessions   int           `json:"active_sessions"`
	Details          map[string]interface{} `json:"details,omitempty"`
}

// ClusterHealth represents overall cluster health
type ClusterHealth struct {
	TotalNodes      int                    `json:"total_nodes"`
	HealthyNodes    int                    `json:"healthy_nodes"`
	DegradedNodes   int                    `json:"degraded_nodes"`
	UnhealthyNodes  int                    `json:"unhealthy_nodes"`
	OfflineNodes    int                    `json:"offline_nodes"`
	LastUpdate      time.Time              `json:"last_update"`
	NodeHealths     map[string]*NodeHealth `json:"node_healths"`
}

// EventHandler handles cluster events
type EventHandler func(nodeID string, messageType string, data []byte) error

// ClusterMessage represents a message sent between cluster nodes
type ClusterMessage struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	SourceNode  string            `json:"source_node"`
	TargetNode  string            `json:"target_node,omitempty"` // Empty for broadcast
	Timestamp   time.Time         `json:"timestamp"`
	Data        json.RawMessage   `json:"data"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// ClusterConfig holds configuration for cluster management
type ClusterConfig struct {
	NodeID              string        `json:"node_id"`
	ListenAddress       string        `json:"listen_address"`
	ListenPort          int           `json:"listen_port"`
	DiscoveryMethod     string        `json:"discovery_method"` // "static", "dns", "consul"
	StaticNodes         []string      `json:"static_nodes,omitempty"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	NodeTimeout         time.Duration `json:"node_timeout"`
	RetryAttempts       int           `json:"retry_attempts"`
	EnableEncryption    bool          `json:"enable_encryption"`
	EnableCompression   bool          `json:"enable_compression"`
}

// DefaultClusterConfig returns default cluster configuration
func DefaultClusterConfig() *ClusterConfig {
	return &ClusterConfig{
		NodeID:              generateNodeID(),
		ListenAddress:       "0.0.0.0",
		ListenPort:          8080,
		DiscoveryMethod:     "static",
		HealthCheckInterval: 30 * time.Second,
		NodeTimeout:         10 * time.Second,
		RetryAttempts:       3,
		EnableEncryption:    true,
		EnableCompression:   true,
	}
}

// clusterManagerImpl implements ClusterManager
type clusterManagerImpl struct {
	config       *ClusterConfig
	nodes        map[string]*NodeInfo
	nodeHealths  map[string]*NodeHealth
	eventHandlers map[string]EventHandler
	mu           sync.RWMutex
	
	// HTTP server for cluster communication
	server   *http.Server
	client   *http.Client
	
	// Background processes
	ctx      context.Context
	cancel   context.CancelFunc
	running  bool
}

// NewClusterManager creates a new cluster manager
func NewClusterManager(config *ClusterConfig) ClusterManager {
	if config == nil {
		config = DefaultClusterConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	cm := &clusterManagerImpl{
		config:        config,
		nodes:         make(map[string]*NodeInfo),
		nodeHealths:   make(map[string]*NodeHealth),
		eventHandlers: make(map[string]EventHandler),
		client: &http.Client{
			Timeout: config.NodeTimeout,
		},
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Set up HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/cluster/message", cm.handleClusterMessage)
	mux.HandleFunc("/cluster/health", cm.handleHealthCheck)
	mux.HandleFunc("/cluster/nodes", cm.handleNodeList)
	
	cm.server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort),
		Handler: mux,
	}
	
	return cm
}

// RegisterNode registers a node in the cluster
func (cm *clusterManagerImpl) RegisterNode(nodeInfo *NodeInfo) error {
	if nodeInfo == nil {
		return fmt.Errorf("node info cannot be nil")
	}
	
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	nodeInfo.LastSeen = time.Now()
	nodeInfo.Status = NodeStatusHealthy
	
	cm.nodes[nodeInfo.ID] = nodeInfo
	
	// Initialize health info
	cm.nodeHealths[nodeInfo.ID] = &NodeHealth{
		NodeID:          nodeInfo.ID,
		Status:          NodeStatusHealthy,
		LastHealthCheck: time.Now(),
	}
	
	return nil
}

// UnregisterNode removes a node from the cluster
func (cm *clusterManagerImpl) UnregisterNode(nodeID string) error {
	if nodeID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}
	
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	delete(cm.nodes, nodeID)
	delete(cm.nodeHealths, nodeID)
	
	return nil
}

// GetNodes returns all registered nodes
func (cm *clusterManagerImpl) GetNodes() []*NodeInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	nodes := make([]*NodeInfo, 0, len(cm.nodes))
	for _, node := range cm.nodes {
		// Create copy to avoid race conditions
		nodeCopy := *node
		nodes = append(nodes, &nodeCopy)
	}
	
	return nodes
}

// GetNode returns information about a specific node
func (cm *clusterManagerImpl) GetNode(nodeID string) (*NodeInfo, error) {
	if nodeID == "" {
		return nil, fmt.Errorf("node ID cannot be empty")
	}
	
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	node, exists := cm.nodes[nodeID]
	if !exists {
		return nil, fmt.Errorf("node not found: %s", nodeID)
	}
	
	// Return copy to avoid race conditions
	nodeCopy := *node
	return &nodeCopy, nil
}

// Broadcast sends a message to all nodes in the cluster
func (cm *clusterManagerImpl) Broadcast(messageType string, data []byte) error {
	if messageType == "" {
		return fmt.Errorf("message type cannot be empty")
	}
	
	cm.mu.RLock()
	nodes := make([]*NodeInfo, 0, len(cm.nodes))
	for _, node := range cm.nodes {
		if node.ID != cm.config.NodeID {
			nodes = append(nodes, node)
		}
	}
	cm.mu.RUnlock()
	
	var errors []error
	for _, node := range nodes {
		if err := cm.SendToNode(node.ID, messageType, data); err != nil {
			errors = append(errors, fmt.Errorf("failed to send to node %s: %w", node.ID, err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("broadcast failed to %d nodes: %v", len(errors), errors)
	}
	
	return nil
}

// SendToNode sends a message to a specific node
func (cm *clusterManagerImpl) SendToNode(nodeID, messageType string, data []byte) error {
	if nodeID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}
	if messageType == "" {
		return fmt.Errorf("message type cannot be empty")
	}
	
	cm.mu.RLock()
	node, exists := cm.nodes[nodeID]
	cm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("node not found: %s", nodeID)
	}
	
	message := &ClusterMessage{
		ID:         generateMessageID(),
		Type:       messageType,
		SourceNode: cm.config.NodeID,
		TargetNode: nodeID,
		Timestamp:  time.Now(),
		Data:       json.RawMessage(data),
	}
	
	return cm.sendMessage(node, message)
}

// CheckNodeHealth checks the health of a specific node
func (cm *clusterManagerImpl) CheckNodeHealth(nodeID string) (*NodeHealth, error) {
	if nodeID == "" {
		return nil, fmt.Errorf("node ID cannot be empty")
	}
	
	cm.mu.RLock()
	node, exists := cm.nodes[nodeID]
	cm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("node not found: %s", nodeID)
	}
	
	start := time.Now()
	
	// Send health check request
	url := fmt.Sprintf("http://%s:%d/cluster/health", node.Address, node.Port)
	resp, err := cm.client.Get(url)
	
	responseTime := time.Since(start)
	
	health := &NodeHealth{
		NodeID:          nodeID,
		LastHealthCheck: time.Now(),
		ResponseTime:    responseTime,
	}
	
	if err != nil {
		health.Status = NodeStatusOffline
		health.ErrorCount++
		
		cm.mu.Lock()
		cm.nodeHealths[nodeID] = health
		cm.nodes[nodeID].Status = NodeStatusOffline
		cm.mu.Unlock()
		
		return health, err
	}
	
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		health.Status = NodeStatusHealthy
		
		// Try to decode health details
		var healthDetails map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&healthDetails); err == nil {
			health.Details = healthDetails
			
			// Extract specific metrics if available
			if memUsage, ok := healthDetails["memory_usage"].(float64); ok {
				health.MemoryUsage = memUsage
			}
			if cpuUsage, ok := healthDetails["cpu_usage"].(float64); ok {
				health.CPUUsage = cpuUsage
			}
			if activeSessions, ok := healthDetails["active_sessions"].(float64); ok {
				health.ActiveSessions = int(activeSessions)
			}
		}
	} else {
		health.Status = NodeStatusUnhealthy
		health.ErrorCount++
	}
	
	cm.mu.Lock()
	cm.nodeHealths[nodeID] = health
	cm.nodes[nodeID].Status = health.Status
	cm.nodes[nodeID].LastSeen = time.Now()
	cm.mu.Unlock()
	
	return health, nil
}

// GetClusterHealth returns overall cluster health
func (cm *clusterManagerImpl) GetClusterHealth() *ClusterHealth {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	health := &ClusterHealth{
		TotalNodes:  len(cm.nodes),
		LastUpdate:  time.Now(),
		NodeHealths: make(map[string]*NodeHealth),
	}
	
	for nodeID, nodeHealth := range cm.nodeHealths {
		// Copy health info
		healthCopy := *nodeHealth
		health.NodeHealths[nodeID] = &healthCopy
		
		// Count by status
		switch nodeHealth.Status {
		case NodeStatusHealthy:
			health.HealthyNodes++
		case NodeStatusDegraded:
			health.DegradedNodes++
		case NodeStatusUnhealthy:
			health.UnhealthyNodes++
		case NodeStatusOffline:
			health.OfflineNodes++
		}
	}
	
	return health
}

// RegisterEventHandler registers a handler for cluster events
func (cm *clusterManagerImpl) RegisterEventHandler(messageType string, handler EventHandler) error {
	if messageType == "" {
		return fmt.Errorf("message type cannot be empty")
	}
	if handler == nil {
		return fmt.Errorf("handler cannot be nil")
	}
	
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	cm.eventHandlers[messageType] = handler
	return nil
}

// UnregisterEventHandler removes a handler for cluster events
func (cm *clusterManagerImpl) UnregisterEventHandler(messageType string) error {
	if messageType == "" {
		return fmt.Errorf("message type cannot be empty")
	}
	
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	delete(cm.eventHandlers, messageType)
	return nil
}

// Start starts the cluster manager
func (cm *clusterManagerImpl) Start() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if cm.running {
		return nil
	}
	
	// Start HTTP server
	go func() {
		if err := cm.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log error but don't fail startup
		}
	}()
	
	// Register self as a node
	selfNode := &NodeInfo{
		ID:      cm.config.NodeID,
		Address: cm.getLocalIP(),
		Port:    cm.config.ListenPort,
		Status:  NodeStatusHealthy,
		Capabilities: []string{"session_management", "authentication"},
	}
	
	cm.nodes[cm.config.NodeID] = selfNode
	
	// Discover and register static nodes
	if cm.config.DiscoveryMethod == "static" {
		for _, nodeAddr := range cm.config.StaticNodes {
			// Parse node address and register
			// This is simplified - in practice would need proper parsing
			nodeID := fmt.Sprintf("node-%s", nodeAddr)
			nodeInfo := &NodeInfo{
				ID:      nodeID,
				Address: nodeAddr,
				Port:    cm.config.ListenPort,
				Status:  NodeStatusUnknown,
			}
			cm.nodes[nodeID] = nodeInfo
		}
	}
	
	// Start background health checks
	go cm.healthCheckLoop()
	
	cm.running = true
	return nil
}

// Stop stops the cluster manager
func (cm *clusterManagerImpl) Stop() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if !cm.running {
		return nil
	}
	
	// Cancel background processes
	if cm.cancel != nil {
		cm.cancel()
	}
	
	// Shutdown HTTP server
	if cm.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cm.server.Shutdown(ctx)
	}
	
	cm.running = false
	return nil
}

// IsRunning returns whether the cluster manager is running
func (cm *clusterManagerImpl) IsRunning() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.running
}

// HTTP handlers

// handleClusterMessage handles incoming cluster messages
func (cm *clusterManagerImpl) handleClusterMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var message ClusterMessage
	if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
		http.Error(w, "Invalid message format", http.StatusBadRequest)
		return
	}
	
	// Handle the message
	cm.mu.RLock()
	handler, exists := cm.eventHandlers[message.Type]
	cm.mu.RUnlock()
	
	if exists {
		if err := handler(message.SourceNode, message.Type, message.Data); err != nil {
			http.Error(w, "Handler error", http.StatusInternalServerError)
			return
		}
	}
	
	w.WriteHeader(http.StatusOK)
}

// handleHealthCheck handles health check requests
func (cm *clusterManagerImpl) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Return basic health information
	health := map[string]interface{}{
		"status":          "healthy",
		"node_id":         cm.config.NodeID,
		"timestamp":       time.Now(),
		"active_sessions": 0, // Would be populated from session manager
		"memory_usage":    0.0, // Would be populated from system metrics
		"cpu_usage":       0.0, // Would be populated from system metrics
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// handleNodeList handles node list requests
func (cm *clusterManagerImpl) handleNodeList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	nodes := cm.GetNodes()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodes)
}

// Helper methods

// sendMessage sends a message to a specific node
func (cm *clusterManagerImpl) sendMessage(node *NodeInfo, message *ClusterMessage) error {
	url := fmt.Sprintf("http://%s:%d/cluster/message", node.Address, node.Port)
	
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}
	
	resp, err := cm.client.Post(url, "application/json", nil)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("message rejected with status: %d", resp.StatusCode)
	}
	
	return nil
}

// healthCheckLoop performs periodic health checks
func (cm *clusterManagerImpl) healthCheckLoop() {
	ticker := time.NewTicker(cm.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-cm.ctx.Done():
			return
		case <-ticker.C:
			cm.performHealthChecks()
		}
	}
}

// performHealthChecks checks health of all nodes
func (cm *clusterManagerImpl) performHealthChecks() {
	cm.mu.RLock()
	nodeIDs := make([]string, 0, len(cm.nodes))
	for nodeID := range cm.nodes {
		if nodeID != cm.config.NodeID {
			nodeIDs = append(nodeIDs, nodeID)
		}
	}
	cm.mu.RUnlock()
	
	for _, nodeID := range nodeIDs {
		go func(id string) {
			cm.CheckNodeHealth(id)
		}(nodeID)
	}
}

// getLocalIP returns the local IP address
func (cm *clusterManagerImpl) getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// generateMessageID generates a unique message ID
func generateMessageID() string {
	return fmt.Sprintf("msg-%d", time.Now().UnixNano())
}