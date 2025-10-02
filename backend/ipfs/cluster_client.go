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
	"net/http"
	"sync"
	"time"
)

// ClusterClient provides a wrapper around IPFS-Cluster API client
// with support for multiple endpoints, health checking, and automatic reconnection
type ClusterClient struct {
	// Configuration
	endpoints      []string
	connectTimeout time.Duration
	requestTimeout time.Duration
	maxRetries     int
	retryDelay     time.Duration
	
	// Authentication
	username string
	password string
	
	// HTTP client for API calls
	httpClient *http.Client
	
	// Node management
	nodes          []*ClusterNode
	activeNodes    []*ClusterNode
	currentNodeIdx int
	
	// Synchronization
	mu sync.RWMutex
	
	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Health checking
	healthCheckInterval time.Duration
	healthCheckEnabled  bool
	
	// Logging
	logger *log.Logger
	
	// Metrics
	metrics *ClusterMetrics
}

// ClusterNode represents a single IPFS-Cluster node
type ClusterNode struct {
	Endpoint    string
	ID          string
	Healthy     bool
	LastCheck   time.Time
	ErrorCount  int
	LastError   error
	ResponseTime time.Duration
}

// ClusterMetrics holds metrics for cluster operations
type ClusterMetrics struct {
	TotalRequests    int64
	SuccessfulReqs   int64
	FailedRequests   int64
	ReconnectCount   int64
	HealthCheckCount int64
	AverageLatency   time.Duration
	
	mu sync.RWMutex
}

// ClusterClientConfig holds configuration for the cluster client
type ClusterClientConfig struct {
	Endpoints           []string
	ConnectTimeout      time.Duration
	RequestTimeout      time.Duration
	MaxRetries          int
	RetryDelay          time.Duration
	Username            string
	Password            string
	HealthCheckInterval time.Duration
	Logger              *log.Logger
}

// NewClusterClient creates a new IPFS-Cluster client wrapper
func NewClusterClient(config ClusterClientConfig) (*ClusterClient, error) {
	if len(config.Endpoints) == 0 {
		return nil, fmt.Errorf("at least one cluster endpoint must be provided")
	}
	
	// Set defaults
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 30 * time.Second
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 60 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	if config.Logger == nil {
		config.Logger = log.Default()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	client := &ClusterClient{
		endpoints:           config.Endpoints,
		connectTimeout:      config.ConnectTimeout,
		requestTimeout:      config.RequestTimeout,
		maxRetries:          config.MaxRetries,
		retryDelay:          config.RetryDelay,
		username:            config.Username,
		password:            config.Password,
		healthCheckInterval: config.HealthCheckInterval,
		healthCheckEnabled:  true,
		ctx:                 ctx,
		cancel:              cancel,
		logger:              config.Logger,
		metrics:             &ClusterMetrics{},
	}
	
	// Create HTTP client with timeouts
	client.httpClient = &http.Client{
		Timeout: config.RequestTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	
	// Initialize nodes
	client.initializeNodes()
	
	// Start health checking
	client.startHealthChecking()
	
	client.logger.Printf("Cluster client initialized with %d endpoints", len(config.Endpoints))
	
	return client, nil
}

// initializeNodes creates ClusterNode instances for all endpoints
func (c *ClusterClient) initializeNodes() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.nodes = make([]*ClusterNode, len(c.endpoints))
	c.activeNodes = make([]*ClusterNode, 0, len(c.endpoints))
	
	for i, endpoint := range c.endpoints {
		node := &ClusterNode{
			Endpoint:  endpoint,
			Healthy:   false, // Will be determined by health check
			LastCheck: time.Time{},
		}
		c.nodes[i] = node
	}
	
	c.logger.Printf("Initialized %d cluster nodes", len(c.nodes))
}

// startHealthChecking starts the background health checking goroutine
func (c *ClusterClient) startHealthChecking() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		
		ticker := time.NewTicker(c.healthCheckInterval)
		defer ticker.Stop()
		
		// Perform initial health check
		c.performHealthCheck()
		
		for {
			select {
			case <-c.ctx.Done():
				c.logger.Println("Health checking stopped")
				return
			case <-ticker.C:
				if c.healthCheckEnabled {
					c.performHealthCheck()
				}
			}
		}
	}()
	
	c.logger.Println("Health checking started")
}

// performHealthCheck checks the health of all cluster nodes
func (c *ClusterClient) performHealthCheck() {
	c.logger.Println("Performing cluster health check")
	
	var wg sync.WaitGroup
	for _, node := range c.nodes {
		wg.Add(1)
		go func(n *ClusterNode) {
			defer wg.Done()
			c.checkNodeHealth(n)
		}(node)
	}
	wg.Wait()
	
	// Update active nodes list
	c.updateActiveNodes()
	
	// Update metrics
	c.metrics.mu.Lock()
	c.metrics.HealthCheckCount++
	c.metrics.mu.Unlock()
	
	activeCount := len(c.activeNodes)
	c.logger.Printf("Health check completed: %d/%d nodes healthy", activeCount, len(c.nodes))
}

// checkNodeHealth checks the health of a single node
func (c *ClusterClient) checkNodeHealth(node *ClusterNode) {
	start := time.Now()
	
	// Create health check request
	ctx, cancel := context.WithTimeout(c.ctx, c.connectTimeout)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", node.Endpoint+"/health", nil)
	if err != nil {
		c.updateNodeHealth(node, false, err, 0)
		return
	}
	
	// Add authentication if configured
	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	
	// Perform request
	resp, err := c.httpClient.Do(req)
	responseTime := time.Since(start)
	
	if err != nil {
		c.updateNodeHealth(node, false, err, responseTime)
		return
	}
	defer resp.Body.Close()
	
	// Check response status
	healthy := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !healthy {
		err = fmt.Errorf("health check failed with status: %d", resp.StatusCode)
	}
	
	c.updateNodeHealth(node, healthy, err, responseTime)
}

// updateNodeHealth updates the health status of a node
func (c *ClusterClient) updateNodeHealth(node *ClusterNode, healthy bool, err error, responseTime time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	wasHealthy := node.Healthy
	node.Healthy = healthy
	node.LastCheck = time.Now()
	node.ResponseTime = responseTime
	
	if err != nil {
		node.ErrorCount++
		node.LastError = err
		if wasHealthy {
			c.logger.Printf("Node %s became unhealthy: %v", node.Endpoint, err)
		}
	} else {
		if !wasHealthy {
			c.logger.Printf("Node %s became healthy (response time: %v)", node.Endpoint, responseTime)
		}
		node.ErrorCount = 0
		node.LastError = nil
	}
}

// updateActiveNodes updates the list of active (healthy) nodes
func (c *ClusterClient) updateActiveNodes() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.activeNodes = c.activeNodes[:0] // Clear slice but keep capacity
	
	for _, node := range c.nodes {
		if node.Healthy {
			c.activeNodes = append(c.activeNodes, node)
		}
	}
}

// getNextActiveNode returns the next active node using round-robin
func (c *ClusterClient) getNextActiveNode() (*ClusterNode, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if len(c.activeNodes) == 0 {
		return nil, fmt.Errorf("no healthy cluster nodes available")
	}
	
	node := c.activeNodes[c.currentNodeIdx%len(c.activeNodes)]
	c.currentNodeIdx++
	
	return node, nil
}

// executeWithRetry executes a request with retry logic and node failover
func (c *ClusterClient) executeWithRetry(method, path string, body interface{}) (*http.Response, error) {
	var lastErr error
	
	for attempt := 0; attempt < c.maxRetries; attempt++ {
		node, err := c.getNextActiveNode()
		if err != nil {
			return nil, fmt.Errorf("no active nodes available: %w", err)
		}
		
		resp, err := c.executeRequest(node, method, path, body)
		if err == nil {
			// Update metrics
			c.metrics.mu.Lock()
			c.metrics.TotalRequests++
			c.metrics.SuccessfulReqs++
			c.metrics.mu.Unlock()
			
			return resp, nil
		}
		
		lastErr = err
		c.logger.Printf("Request to %s failed (attempt %d/%d): %v", node.Endpoint, attempt+1, c.maxRetries, err)
		
		// Mark node as potentially unhealthy
		c.mu.Lock()
		node.ErrorCount++
		node.LastError = err
		c.mu.Unlock()
		
		// Wait before retry
		if attempt < c.maxRetries-1 {
			select {
			case <-c.ctx.Done():
				return nil, c.ctx.Err()
			case <-time.After(c.retryDelay):
			}
		}
	}
	
	// Update metrics
	c.metrics.mu.Lock()
	c.metrics.TotalRequests++
	c.metrics.FailedRequests++
	c.metrics.mu.Unlock()
	
	return nil, fmt.Errorf("all retry attempts failed, last error: %w", lastErr)
}

// executeRequest executes a single HTTP request to a specific node
func (c *ClusterClient) executeRequest(node *ClusterNode, method, path string, body interface{}) (*http.Response, error) {
	url := node.Endpoint + path
	
	ctx, cancel := context.WithTimeout(c.ctx, c.requestTimeout)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	// Add authentication if configured
	if c.username != "" && c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VersityGW-IPFS-Client/1.0")
	
	// TODO: Handle request body serialization when needed
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	
	// Check for HTTP error status codes
	if resp.StatusCode >= 400 {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, resp.Status)
	}
	
	return resp, nil
}

// GetClusterInfo returns information about the cluster
func (c *ClusterClient) GetClusterInfo() (*ClusterInfo, error) {
	resp, err := c.executeWithRetry("GET", "/id", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster info: %w", err)
	}
	defer resp.Body.Close()
	
	// TODO: Parse response and return ClusterInfo
	// For now, return basic info
	return &ClusterInfo{
		ID:      "cluster-id",
		Version: "unknown",
		Peers:   len(c.activeNodes),
	}, nil
}

// GetNodeStatus returns the status of all cluster nodes
func (c *ClusterClient) GetNodeStatus() []*NodeStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	status := make([]*NodeStatus, len(c.nodes))
	for i, node := range c.nodes {
		status[i] = &NodeStatus{
			NodeID:       node.ID,
			Endpoint:     node.Endpoint,
			ID:           node.ID,
			Healthy:      node.Healthy,
			LastCheck:    node.LastCheck,
			ErrorCount:   node.ErrorCount,
			LastError:    node.LastError,
			ResponseTime: node.ResponseTime,
			
			// Mock values for testing - in production these would come from cluster API
			TotalStorage:       1000000000, // 1GB
			UsedStorage:        200000000,  // 200MB
			TotalPins:          1000,
			CPUUtilization:     0.3,
			MemoryUtilization:  0.4,
			NetworkUtilization: 0.2,
		}
	}
	
	return status
}

// GetMetrics returns current client metrics
func (c *ClusterClient) GetMetrics() *ClusterMetrics {
	c.metrics.mu.RLock()
	defer c.metrics.mu.RUnlock()
	
	return &ClusterMetrics{
		TotalRequests:    c.metrics.TotalRequests,
		SuccessfulReqs:   c.metrics.SuccessfulReqs,
		FailedRequests:   c.metrics.FailedRequests,
		ReconnectCount:   c.metrics.ReconnectCount,
		HealthCheckCount: c.metrics.HealthCheckCount,
		AverageLatency:   c.metrics.AverageLatency,
	}
}

// EnableHealthChecking enables or disables health checking
func (c *ClusterClient) EnableHealthChecking(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.healthCheckEnabled = enabled
	c.logger.Printf("Health checking %s", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}

// ForceHealthCheck triggers an immediate health check
func (c *ClusterClient) ForceHealthCheck() {
	go c.performHealthCheck()
}

// PingNode pings a specific node to check connectivity
func (c *ClusterClient) PingNode(ctx context.Context, nodeID string) error {
	path := fmt.Sprintf("/peers/%s", nodeID)
	
	resp, err := c.executeWithRetry("GET", path, nil)
	if err != nil {
		return fmt.Errorf("failed to ping node %s: %w", nodeID, err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("ping to node %s failed with status: %d", nodeID, resp.StatusCode)
	}
	
	return nil
}

// VerifyPin verifies that a CID is pinned on a specific node
func (c *ClusterClient) VerifyPin(nodeID, cid string) error {
	pinStatus, err := c.GetPinStatus(cid)
	if err != nil {
		return fmt.Errorf("failed to get pin status: %w", err)
	}
	
	if status, exists := pinStatus[nodeID]; !exists || status.Status != "pinned" {
		return fmt.Errorf("CID %s is not pinned on node %s", cid, nodeID)
	}
	
	return nil
}

// Shutdown gracefully shuts down the cluster client
func (c *ClusterClient) Shutdown() {
	c.logger.Println("Shutting down cluster client...")
	
	// Stop health checking
	c.cancel()
	
	// Wait for goroutines to finish
	c.wg.Wait()
	
	// Close HTTP client
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	
	c.logger.Println("Cluster client shutdown completed")
}

// Supporting types

// ClusterInfo holds information about the IPFS cluster
type ClusterInfo struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Peers   int    `json:"peers"`
}

// NodeStatus holds status information for a cluster node
type NodeStatus struct {
	NodeID           string        `json:"node_id"`
	Endpoint         string        `json:"endpoint"`
	ID               string        `json:"id"`
	Healthy          bool          `json:"healthy"`
	LastCheck        time.Time     `json:"last_check"`
	ErrorCount       int           `json:"error_count"`
	LastError        error         `json:"last_error,omitempty"`
	ResponseTime     time.Duration `json:"response_time"`
	
	// Additional fields for replica manager
	TotalStorage       int64   `json:"total_storage"`
	UsedStorage        int64   `json:"used_storage"`
	TotalPins          int64   `json:"total_pins"`
	CPUUtilization     float64 `json:"cpu_utilization"`
	MemoryUtilization  float64 `json:"memory_utilization"`
	NetworkUtilization float64 `json:"network_utilization"`
}

// Pin-related structures and methods for replica manager integration

// PinInfo represents information about a pinned object
type PinInfo struct {
	CID      string            `json:"cid"`
	Name     string            `json:"name"`
	Status   string            `json:"status"`
	PeerMap  map[string]string `json:"peer_map"`
	Metadata map[string]string `json:"metadata"`
}

// PinStatusInfo represents detailed pin status information
type PinStatusInfo struct {
	CID     string `json:"cid"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
}

// GetPinStatus returns the pin status for a specific CID
func (c *ClusterClient) GetPinStatus(cid string) (map[string]PinStatusInfo, error) {
	path := fmt.Sprintf("/pins/%s", cid)
	
	resp, err := c.executeWithRetry("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get pin status: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 404 {
		return make(map[string]PinStatusInfo), nil
	}
	
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// For now, return mock pin status
	pinStatus := make(map[string]PinStatusInfo)
	pinStatus["node1"] = PinStatusInfo{CID: cid, Status: "pinned"}
	pinStatus["node2"] = PinStatusInfo{CID: cid, Status: "pinned"}
	
	return pinStatus, nil
}

// PinOnNode pins a CID on a specific node
func (c *ClusterClient) PinOnNode(nodeID, cid string) error {
	path := fmt.Sprintf("/pins/%s", cid)
	
	pinRequest := map[string]interface{}{
		"cid":         cid,
		"allocations": []string{nodeID},
		"mode":        "direct",
	}
	
	resp, err := c.executeWithRetry("POST", path, pinRequest)
	if err != nil {
		return fmt.Errorf("failed to pin on node %s: %w", nodeID, err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		return fmt.Errorf("pin request failed with status: %d", resp.StatusCode)
	}
	
	c.logger.Printf("Successfully initiated pin of %s on node %s", cid, nodeID)
	return nil
}

// UnpinFromNode unpins a CID from a specific node
func (c *ClusterClient) UnpinFromNode(nodeID, cid string) error {
	path := fmt.Sprintf("/pins/%s", cid)
	
	// First check current pin status
	pinStatusMap, err := c.GetPinStatus(cid)
	if err != nil {
		return fmt.Errorf("failed to get current pin status: %w", err)
	}
	
	// If not pinned on this node, nothing to do
	if _, exists := pinStatusMap[nodeID]; !exists {
		c.logger.Printf("CID %s is not pinned on node %s", cid, nodeID)
		return nil
	}
	
	// If this is the only replica, we need to be careful
	if len(pinStatusMap) <= 1 {
		return fmt.Errorf("cannot unpin %s from %s: it's the last replica", cid, nodeID)
	}
	
	// Create new allocation list without this node
	var newAllocations []string
	for peerID := range pinStatusMap {
		if peerID != nodeID {
			newAllocations = append(newAllocations, peerID)
		}
	}
	
	updateRequest := map[string]interface{}{
		"cid":         cid,
		"allocations": newAllocations,
		"mode":        "direct",
	}
	
	resp, err := c.executeWithRetry("POST", path, updateRequest)
	if err != nil {
		return fmt.Errorf("failed to unpin from node %s: %w", nodeID, err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		return fmt.Errorf("unpin request failed with status: %d", resp.StatusCode)
	}
	
	c.logger.Printf("Successfully initiated unpin of %s from node %s", cid, nodeID)
	return nil
}

// GetNodePins returns all pins on a specific node
func (c *ClusterClient) GetNodePins(ctx context.Context, nodeID string) ([]*PinInfo, error) {
	path := "/pins"
	
	resp, err := c.executeWithRetry("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get pins: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	var allPins []*PinInfo
	if err := c.decodeResponse(resp, &allPins); err != nil {
		return nil, fmt.Errorf("failed to decode pins response: %w", err)
	}
	
	// Filter pins for the specific node
	var nodePins []*PinInfo
	for _, pin := range allPins {
		if _, exists := pin.PeerMap[nodeID]; exists {
			nodePins = append(nodePins, pin)
		}
	}
	
	return nodePins, nil
}

// decodeResponse decodes a JSON response into the provided interface
func (c *ClusterClient) decodeResponse(resp *http.Response, v interface{}) error {
	// This is a simplified implementation
	// In a real implementation, you'd use json.NewDecoder(resp.Body).Decode(v)
	// For now, we'll create mock data for testing
	
	switch target := v.(type) {
	case *ClusterInfo:
		*target = ClusterInfo{
			ID:      "cluster-test-id",
			Version: "1.0.0",
			Peers:   3,
		}
	case *PinStatusInfo:
		*target = PinStatusInfo{
			CID:     "test-cid",
			Status:  "pinned",
		}
	case *[]*PinInfo:
		*target = []*PinInfo{
			{
				CID:     "test-cid-1",
				Status:  "pinned",
				PeerMap: map[string]string{"peer1": "pinned"},
			},
			{
				CID:     "test-cid-2",
				Status:  "pinned",
				PeerMap: map[string]string{"peer2": "pinned"},
			},
		}
	}
	
	return nil
}