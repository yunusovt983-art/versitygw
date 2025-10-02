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
	"sync/atomic"
	"time"
)

// ConnectionPool manages a pool of HTTP connections to IPFS-Cluster nodes
type ConnectionPool struct {
	// Configuration
	config *ConnectionPoolConfig
	
	// Connection pools per endpoint
	pools map[string]*EndpointPool
	
	// Load balancing
	loadBalancer *LoadBalancer
	
	// Health monitoring
	healthMonitor *HealthMonitor
	
	// Metrics
	metrics *ConnectionPoolMetrics
	
	// Synchronization
	mu sync.RWMutex
	
	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Logging
	logger *log.Logger
}

// ConnectionPoolConfig holds configuration for the connection pool
type ConnectionPoolConfig struct {
	// Pool size configuration
	MaxConnectionsPerEndpoint int `json:"max_connections_per_endpoint"` // Max connections per endpoint
	MinConnectionsPerEndpoint int `json:"min_connections_per_endpoint"` // Min connections per endpoint
	InitialPoolSize          int `json:"initial_pool_size"`            // Initial pool size
	
	// Connection settings
	ConnectTimeout       time.Duration `json:"connect_timeout"`        // Connection timeout
	RequestTimeout       time.Duration `json:"request_timeout"`        // Request timeout
	IdleTimeout          time.Duration `json:"idle_timeout"`           // Idle connection timeout
	KeepAliveTimeout     time.Duration `json:"keep_alive_timeout"`     // Keep-alive timeout
	MaxIdleTime          time.Duration `json:"max_idle_time"`          // Max time connection can be idle
	
	// Pool management
	PoolGrowthFactor     float64       `json:"pool_growth_factor"`     // Factor to grow pool by
	PoolShrinkThreshold  float64       `json:"pool_shrink_threshold"`  // Utilization threshold to shrink
	PoolGrowthThreshold  float64       `json:"pool_growth_threshold"`  // Utilization threshold to grow
	PoolCleanupInterval  time.Duration `json:"pool_cleanup_interval"`  // Interval to cleanup idle connections
	
	// Load balancing
	LoadBalancingStrategy LoadBalancingStrategy `json:"load_balancing_strategy"`
	HealthCheckInterval   time.Duration         `json:"health_check_interval"`
	FailureThreshold      int                   `json:"failure_threshold"`
	RecoveryThreshold     int                   `json:"recovery_threshold"`
	
	// Circuit breaker
	CircuitBreakerEnabled    bool          `json:"circuit_breaker_enabled"`
	CircuitBreakerThreshold  int           `json:"circuit_breaker_threshold"`
	CircuitBreakerTimeout    time.Duration `json:"circuit_breaker_timeout"`
	CircuitBreakerResetTime  time.Duration `json:"circuit_breaker_reset_time"`
	
	// Retry configuration
	MaxRetries           int           `json:"max_retries"`
	RetryDelay           time.Duration `json:"retry_delay"`
	RetryBackoffFactor   float64       `json:"retry_backoff_factor"`
	
	// Monitoring
	MetricsEnabled       bool          `json:"metrics_enabled"`
	MetricsInterval      time.Duration `json:"metrics_interval"`
}

// EndpointPool manages connections to a specific endpoint
type EndpointPool struct {
	endpoint     string
	config       *ConnectionPoolConfig
	
	// Connection management
	connections  []*PooledConnection
	available    chan *PooledConnection
	inUse        map[*PooledConnection]bool
	
	// Pool statistics
	totalConnections    int32
	activeConnections   int32
	idleConnections     int32
	
	// Circuit breaker
	circuitBreaker *CircuitBreaker
	
	// Synchronization
	mu sync.RWMutex
	
	// Logging
	logger *log.Logger
}

// PooledConnection represents a connection in the pool
type PooledConnection struct {
	client       *http.Client
	endpoint     string
	createdAt    time.Time
	lastUsed     time.Time
	usageCount   int64
	isHealthy    bool
	inUse        bool
	
	// Connection-specific metrics
	totalRequests    int64
	successfulReqs   int64
	failedRequests   int64
	averageLatency   time.Duration
	
	// Synchronization
	mu sync.RWMutex
}

// LoadBalancer handles load balancing across endpoints
type LoadBalancer struct {
	strategy   LoadBalancingStrategy
	endpoints  []string
	weights    map[string]int
	current    int32
	
	// Health-aware balancing
	healthyEndpoints []string
	
	// Synchronization
	mu sync.RWMutex
}

// LoadBalancingStrategy defines load balancing strategies
type LoadBalancingStrategy int

const (
	LoadBalancingRoundRobin LoadBalancingStrategy = iota
	LoadBalancingWeighted
	LoadBalancingLeastConnections
	LoadBalancingHealthAware
	LoadBalancingLatencyBased
)

// HealthMonitor monitors the health of endpoints
type HealthMonitor struct {
	config     *ConnectionPoolConfig
	endpoints  []string
	health     map[string]*EndpointHealth
	
	// Synchronization
	mu sync.RWMutex
	
	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Logging
	logger *log.Logger
}

// EndpointHealth tracks health information for an endpoint
type EndpointHealth struct {
	endpoint         string
	healthy          bool
	lastCheck        time.Time
	consecutiveFailures int
	consecutiveSuccesses int
	responseTime     time.Duration
	errorRate        float64
}

// CircuitBreaker implements circuit breaker pattern for endpoints
type CircuitBreaker struct {
	config       *ConnectionPoolConfig
	state        CircuitBreakerState
	failures     int32
	lastFailure  time.Time
	nextAttempt  time.Time
	
	// Synchronization
	mu sync.RWMutex
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int

const (
	CircuitBreakerClosed CircuitBreakerState = iota
	CircuitBreakerOpen
	CircuitBreakerHalfOpen
)

// ConnectionPoolMetrics holds metrics for the connection pool
type ConnectionPoolMetrics struct {
	// Pool statistics
	TotalPools           int32 `json:"total_pools"`
	TotalConnections     int32 `json:"total_connections"`
	ActiveConnections    int32 `json:"active_connections"`
	IdleConnections      int32 `json:"idle_connections"`
	
	// Usage statistics
	TotalRequests        int64         `json:"total_requests"`
	SuccessfulRequests   int64         `json:"successful_requests"`
	FailedRequests       int64         `json:"failed_requests"`
	AverageLatency       time.Duration `json:"average_latency"`
	
	// Pool efficiency
	PoolUtilization      float64 `json:"pool_utilization"`
	ConnectionReuse      float64 `json:"connection_reuse"`
	PoolHitRatio         float64 `json:"pool_hit_ratio"`
	
	// Health statistics
	HealthyEndpoints     int32 `json:"healthy_endpoints"`
	UnhealthyEndpoints   int32 `json:"unhealthy_endpoints"`
	CircuitBreakersOpen  int32 `json:"circuit_breakers_open"`
	
	// Synchronization
	mu sync.RWMutex
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(config *ConnectionPoolConfig, endpoints []string, logger *log.Logger) *ConnectionPool {
	if config == nil {
		config = getDefaultConnectionPoolConfig()
	}
	
	if logger == nil {
		logger = log.Default()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pool := &ConnectionPool{
		config:        config,
		pools:         make(map[string]*EndpointPool),
		metrics:       &ConnectionPoolMetrics{},
		ctx:           ctx,
		cancel:        cancel,
		logger:        logger,
	}
	
	// Initialize endpoint pools
	for _, endpoint := range endpoints {
		pool.pools[endpoint] = NewEndpointPool(endpoint, config, logger)
	}
	
	// Initialize load balancer
	pool.loadBalancer = NewLoadBalancer(config.LoadBalancingStrategy, endpoints)
	
	// Initialize health monitor
	pool.healthMonitor = NewHealthMonitor(config, endpoints, logger)
	
	return pool
}

// getDefaultConnectionPoolConfig returns default connection pool configuration
func getDefaultConnectionPoolConfig() *ConnectionPoolConfig {
	return &ConnectionPoolConfig{
		MaxConnectionsPerEndpoint: 50,
		MinConnectionsPerEndpoint: 5,
		InitialPoolSize:          10,
		ConnectTimeout:           30 * time.Second,
		RequestTimeout:           60 * time.Second,
		IdleTimeout:             300 * time.Second,
		KeepAliveTimeout:        30 * time.Second,
		MaxIdleTime:             600 * time.Second,
		PoolGrowthFactor:        1.5,
		PoolShrinkThreshold:     0.3,
		PoolGrowthThreshold:     0.8,
		PoolCleanupInterval:     60 * time.Second,
		LoadBalancingStrategy:   LoadBalancingRoundRobin,
		HealthCheckInterval:     30 * time.Second,
		FailureThreshold:        3,
		RecoveryThreshold:       2,
		CircuitBreakerEnabled:   true,
		CircuitBreakerThreshold: 5,
		CircuitBreakerTimeout:   60 * time.Second,
		CircuitBreakerResetTime: 300 * time.Second,
		MaxRetries:             3,
		RetryDelay:             1 * time.Second,
		RetryBackoffFactor:     2.0,
		MetricsEnabled:         true,
		MetricsInterval:        30 * time.Second,
	}
}

// NewEndpointPool creates a new endpoint pool
func NewEndpointPool(endpoint string, config *ConnectionPoolConfig, logger *log.Logger) *EndpointPool {
	pool := &EndpointPool{
		endpoint:    endpoint,
		config:      config,
		connections: make([]*PooledConnection, 0, config.MaxConnectionsPerEndpoint),
		available:   make(chan *PooledConnection, config.MaxConnectionsPerEndpoint),
		inUse:       make(map[*PooledConnection]bool),
		logger:      logger,
	}
	
	// Initialize circuit breaker if enabled
	if config.CircuitBreakerEnabled {
		pool.circuitBreaker = NewCircuitBreaker(config)
	}
	
	// Pre-populate pool with initial connections
	for i := 0; i < config.InitialPoolSize; i++ {
		conn := pool.createConnection()
		if conn != nil {
			pool.connections = append(pool.connections, conn)
			pool.available <- conn
			atomic.AddInt32(&pool.totalConnections, 1)
			atomic.AddInt32(&pool.idleConnections, 1)
		}
	}
	
	return pool
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(strategy LoadBalancingStrategy, endpoints []string) *LoadBalancer {
	return &LoadBalancer{
		strategy:         strategy,
		endpoints:        endpoints,
		weights:          make(map[string]int),
		healthyEndpoints: make([]string, len(endpoints)),
	}
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor(config *ConnectionPoolConfig, endpoints []string, logger *log.Logger) *HealthMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	
	monitor := &HealthMonitor{
		config:    config,
		endpoints: endpoints,
		health:    make(map[string]*EndpointHealth),
		ctx:       ctx,
		cancel:    cancel,
		logger:    logger,
	}
	
	// Initialize health status for all endpoints
	for _, endpoint := range endpoints {
		monitor.health[endpoint] = &EndpointHealth{
			endpoint:  endpoint,
			healthy:   true, // Assume healthy initially
			lastCheck: time.Now(),
		}
	}
	
	return monitor
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config *ConnectionPoolConfig) *CircuitBreaker {
	return &CircuitBreaker{
		config: config,
		state:  CircuitBreakerClosed,
	}
}

// Start starts the connection pool and its components
func (cp *ConnectionPool) Start() error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	// Start health monitor
	if err := cp.healthMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start health monitor: %w", err)
	}
	
	// Start pool cleanup routine
	cp.wg.Add(1)
	go cp.poolCleanupRoutine()
	
	// Start metrics collection if enabled
	if cp.config.MetricsEnabled {
		cp.wg.Add(1)
		go cp.metricsCollectionRoutine()
	}
	
	cp.logger.Printf("Connection pool started with %d endpoints", len(cp.pools))
	return nil
}

// Stop stops the connection pool and its components
func (cp *ConnectionPool) Stop() error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	cp.cancel()
	cp.wg.Wait()
	
	// Stop health monitor
	if err := cp.healthMonitor.Stop(); err != nil {
		cp.logger.Printf("Error stopping health monitor: %v", err)
	}
	
	// Close all connections
	for _, pool := range cp.pools {
		pool.closeAllConnections()
	}
	
	cp.logger.Println("Connection pool stopped")
	return nil
}

// GetConnection gets a connection from the pool
func (cp *ConnectionPool) GetConnection(ctx context.Context) (*PooledConnection, error) {
	// Select endpoint using load balancer
	endpoint, err := cp.loadBalancer.SelectEndpoint()
	if err != nil {
		return nil, fmt.Errorf("failed to select endpoint: %w", err)
	}
	
	// Get pool for endpoint
	cp.mu.RLock()
	pool, exists := cp.pools[endpoint]
	cp.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("no pool found for endpoint: %s", endpoint)
	}
	
	// Check circuit breaker
	if pool.circuitBreaker != nil && !pool.circuitBreaker.CanExecute() {
		return nil, fmt.Errorf("circuit breaker open for endpoint: %s", endpoint)
	}
	
	// Get connection from pool
	return pool.getConnection(ctx)
}

// ReturnConnection returns a connection to the pool
func (cp *ConnectionPool) ReturnConnection(conn *PooledConnection) {
	if conn == nil {
		return
	}
	
	cp.mu.RLock()
	pool, exists := cp.pools[conn.endpoint]
	cp.mu.RUnlock()
	
	if exists {
		pool.returnConnection(conn)
	}
}

// getConnection gets a connection from an endpoint pool
func (ep *EndpointPool) getConnection(ctx context.Context) (*PooledConnection, error) {
	// Try to get an available connection
	select {
	case conn := <-ep.available:
		if ep.isConnectionValid(conn) {
			ep.markConnectionInUse(conn)
			return conn, nil
		}
		// Connection is invalid, create a new one
		ep.removeConnection(conn)
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// No available connections, try to create a new one
	}
	
	// Create new connection if under limit
	if atomic.LoadInt32(&ep.totalConnections) < int32(ep.config.MaxConnectionsPerEndpoint) {
		conn := ep.createConnection()
		if conn != nil {
			ep.markConnectionInUse(conn)
			return conn, nil
		}
	}
	
	// Wait for an available connection with timeout
	select {
	case conn := <-ep.available:
		if ep.isConnectionValid(conn) {
			ep.markConnectionInUse(conn)
			return conn, nil
		}
		ep.removeConnection(conn)
		return nil, fmt.Errorf("no valid connections available")
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(ep.config.ConnectTimeout):
		return nil, fmt.Errorf("timeout waiting for connection")
	}
}

// returnConnection returns a connection to the pool
func (ep *EndpointPool) returnConnection(conn *PooledConnection) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	
	// Mark connection as not in use
	delete(ep.inUse, conn)
	conn.inUse = false
	conn.lastUsed = time.Now()
	
	atomic.AddInt32(&ep.activeConnections, -1)
	atomic.AddInt32(&ep.idleConnections, 1)
	
	// Return to available pool if still valid
	if ep.isConnectionValid(conn) {
		select {
		case ep.available <- conn:
			// Successfully returned to pool
		default:
			// Pool is full, close the connection
			ep.closeConnection(conn)
		}
	} else {
		ep.closeConnection(conn)
	}
}

// createConnection creates a new pooled connection
func (ep *EndpointPool) createConnection() *PooledConnection {
	client := &http.Client{
		Timeout: ep.config.RequestTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     ep.config.IdleTimeout,
			DisableKeepAlives:   false,
		},
	}
	
	conn := &PooledConnection{
		client:    client,
		endpoint:  ep.endpoint,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
		isHealthy: true,
	}
	
	ep.mu.Lock()
	ep.connections = append(ep.connections, conn)
	ep.mu.Unlock()
	
	atomic.AddInt32(&ep.totalConnections, 1)
	
	return conn
}

// isConnectionValid checks if a connection is still valid
func (ep *EndpointPool) isConnectionValid(conn *PooledConnection) bool {
	if conn == nil {
		return false
	}
	
	// Check if connection has been idle too long
	if time.Since(conn.lastUsed) > ep.config.MaxIdleTime {
		return false
	}
	
	// Check if connection is healthy
	return conn.isHealthy
}

// markConnectionInUse marks a connection as in use
func (ep *EndpointPool) markConnectionInUse(conn *PooledConnection) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	
	ep.inUse[conn] = true
	conn.inUse = true
	conn.lastUsed = time.Now()
	atomic.AddInt64(&conn.usageCount, 1)
	
	atomic.AddInt32(&ep.activeConnections, 1)
	atomic.AddInt32(&ep.idleConnections, -1)
}

// removeConnection removes a connection from the pool
func (ep *EndpointPool) removeConnection(conn *PooledConnection) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	
	// Remove from connections slice
	for i, c := range ep.connections {
		if c == conn {
			ep.connections = append(ep.connections[:i], ep.connections[i+1:]...)
			break
		}
	}
	
	// Remove from in-use map
	delete(ep.inUse, conn)
	
	ep.closeConnection(conn)
	atomic.AddInt32(&ep.totalConnections, -1)
}

// closeConnection closes a connection
func (ep *EndpointPool) closeConnection(conn *PooledConnection) {
	if conn.client != nil {
		conn.client.CloseIdleConnections()
	}
}

// closeAllConnections closes all connections in the pool
func (ep *EndpointPool) closeAllConnections() {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	
	for _, conn := range ep.connections {
		ep.closeConnection(conn)
	}
	
	ep.connections = ep.connections[:0]
	ep.inUse = make(map[*PooledConnection]bool)
	
	// Drain available channel
	for {
		select {
		case <-ep.available:
		default:
			return
		}
	}
}

// SelectEndpoint selects an endpoint using the configured strategy
func (lb *LoadBalancer) SelectEndpoint() (string, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	if len(lb.healthyEndpoints) == 0 {
		return "", fmt.Errorf("no healthy endpoints available")
	}
	
	switch lb.strategy {
	case LoadBalancingRoundRobin:
		return lb.selectRoundRobin()
	case LoadBalancingWeighted:
		return lb.selectWeighted()
	case LoadBalancingLeastConnections:
		return lb.selectLeastConnections()
	case LoadBalancingHealthAware:
		return lb.selectHealthAware()
	case LoadBalancingLatencyBased:
		return lb.selectLatencyBased()
	default:
		return lb.selectRoundRobin()
	}
}

// selectRoundRobin selects endpoint using round-robin
func (lb *LoadBalancer) selectRoundRobin() (string, error) {
	if len(lb.healthyEndpoints) == 0 {
		return "", fmt.Errorf("no healthy endpoints")
	}
	
	index := atomic.AddInt32(&lb.current, 1) % int32(len(lb.healthyEndpoints))
	return lb.healthyEndpoints[index], nil
}

// selectWeighted selects endpoint using weighted round-robin
func (lb *LoadBalancer) selectWeighted() (string, error) {
	// Simplified implementation - in production would use proper weighted selection
	return lb.selectRoundRobin()
}

// selectLeastConnections selects endpoint with least connections
func (lb *LoadBalancer) selectLeastConnections() (string, error) {
	// Simplified implementation - in production would track connection counts
	return lb.selectRoundRobin()
}

// selectHealthAware selects endpoint based on health metrics
func (lb *LoadBalancer) selectHealthAware() (string, error) {
	// Simplified implementation - in production would consider health scores
	return lb.selectRoundRobin()
}

// selectLatencyBased selects endpoint with lowest latency
func (lb *LoadBalancer) selectLatencyBased() (string, error) {
	// Simplified implementation - in production would track latencies
	return lb.selectRoundRobin()
}

// UpdateHealthyEndpoints updates the list of healthy endpoints
func (lb *LoadBalancer) UpdateHealthyEndpoints(endpoints []string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	lb.healthyEndpoints = make([]string, len(endpoints))
	copy(lb.healthyEndpoints, endpoints)
}

// Start starts the health monitor
func (hm *HealthMonitor) Start() error {
	hm.wg.Add(1)
	go hm.healthCheckRoutine()
	
	hm.logger.Printf("Health monitor started for %d endpoints", len(hm.endpoints))
	return nil
}

// Stop stops the health monitor
func (hm *HealthMonitor) Stop() error {
	hm.cancel()
	hm.wg.Wait()
	
	hm.logger.Println("Health monitor stopped")
	return nil
}

// healthCheckRoutine performs periodic health checks
func (hm *HealthMonitor) healthCheckRoutine() {
	defer hm.wg.Done()
	
	ticker := time.NewTicker(hm.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-hm.ctx.Done():
			return
		case <-ticker.C:
			hm.performHealthChecks()
		}
	}
}

// performHealthChecks performs health checks on all endpoints
func (hm *HealthMonitor) performHealthChecks() {
	var wg sync.WaitGroup
	
	for _, endpoint := range hm.endpoints {
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()
			hm.checkEndpointHealth(ep)
		}(endpoint)
	}
	
	wg.Wait()
}

// checkEndpointHealth checks the health of a specific endpoint
func (hm *HealthMonitor) checkEndpointHealth(endpoint string) {
	start := time.Now()
	
	// Perform health check (simplified)
	ctx, cancel := context.WithTimeout(hm.ctx, hm.config.ConnectTimeout)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"/health", nil)
	if err != nil {
		hm.updateEndpointHealth(endpoint, false, time.Since(start))
		return
	}
	
	client := &http.Client{Timeout: hm.config.RequestTimeout}
	resp, err := client.Do(req)
	responseTime := time.Since(start)
	
	healthy := err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300
	if resp != nil {
		resp.Body.Close()
	}
	
	hm.updateEndpointHealth(endpoint, healthy, responseTime)
}

// updateEndpointHealth updates the health status of an endpoint
func (hm *HealthMonitor) updateEndpointHealth(endpoint string, healthy bool, responseTime time.Duration) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	health, exists := hm.health[endpoint]
	if !exists {
		health = &EndpointHealth{endpoint: endpoint}
		hm.health[endpoint] = health
	}
	
	health.lastCheck = time.Now()
	health.responseTime = responseTime
	
	if healthy {
		health.consecutiveSuccesses++
		health.consecutiveFailures = 0
		
		// Mark as healthy if we have enough consecutive successes
		if health.consecutiveSuccesses >= hm.config.RecoveryThreshold {
			health.healthy = true
		}
	} else {
		health.consecutiveFailures++
		health.consecutiveSuccesses = 0
		
		// Mark as unhealthy if we have too many consecutive failures
		if health.consecutiveFailures >= hm.config.FailureThreshold {
			health.healthy = false
		}
	}
}

// GetHealthyEndpoints returns a list of healthy endpoints
func (hm *HealthMonitor) GetHealthyEndpoints() []string {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	var healthy []string
	for endpoint, health := range hm.health {
		if health.healthy {
			healthy = append(healthy, endpoint)
		}
	}
	
	return healthy
}

// CanExecute checks if the circuit breaker allows execution
func (cb *CircuitBreaker) CanExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	switch cb.state {
	case CircuitBreakerClosed:
		return true
	case CircuitBreakerOpen:
		return time.Now().After(cb.nextAttempt)
	case CircuitBreakerHalfOpen:
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful operation
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	cb.failures = 0
	
	if cb.state == CircuitBreakerHalfOpen {
		cb.state = CircuitBreakerClosed
	}
}

// RecordFailure records a failed operation
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	cb.failures++
	cb.lastFailure = time.Now()
	
	if cb.failures >= int32(cb.config.CircuitBreakerThreshold) {
		cb.state = CircuitBreakerOpen
		cb.nextAttempt = time.Now().Add(cb.config.CircuitBreakerResetTime)
	}
}

// poolCleanupRoutine performs periodic cleanup of idle connections
func (cp *ConnectionPool) poolCleanupRoutine() {
	defer cp.wg.Done()
	
	ticker := time.NewTicker(cp.config.PoolCleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-cp.ctx.Done():
			return
		case <-ticker.C:
			cp.cleanupIdleConnections()
		}
	}
}

// cleanupIdleConnections removes idle connections from all pools
func (cp *ConnectionPool) cleanupIdleConnections() {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	
	for _, pool := range cp.pools {
		pool.cleanupIdleConnections()
	}
}

// cleanupIdleConnections removes idle connections from the endpoint pool
func (ep *EndpointPool) cleanupIdleConnections() {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	
	now := time.Now()
	var toRemove []*PooledConnection
	
	for _, conn := range ep.connections {
		if !conn.inUse && now.Sub(conn.lastUsed) > ep.config.MaxIdleTime {
			toRemove = append(toRemove, conn)
		}
	}
	
	for _, conn := range toRemove {
		ep.removeConnection(conn)
	}
}

// metricsCollectionRoutine collects metrics periodically
func (cp *ConnectionPool) metricsCollectionRoutine() {
	defer cp.wg.Done()
	
	ticker := time.NewTicker(cp.config.MetricsInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-cp.ctx.Done():
			return
		case <-ticker.C:
			cp.collectMetrics()
		}
	}
}

// collectMetrics collects current metrics from all pools
func (cp *ConnectionPool) collectMetrics() {
	cp.metrics.mu.Lock()
	defer cp.metrics.mu.Unlock()
	
	var totalConns, activeConns, idleConns int32
	
	cp.mu.RLock()
	cp.metrics.TotalPools = int32(len(cp.pools))
	
	for _, pool := range cp.pools {
		totalConns += atomic.LoadInt32(&pool.totalConnections)
		activeConns += atomic.LoadInt32(&pool.activeConnections)
		idleConns += atomic.LoadInt32(&pool.idleConnections)
	}
	cp.mu.RUnlock()
	
	cp.metrics.TotalConnections = totalConns
	cp.metrics.ActiveConnections = activeConns
	cp.metrics.IdleConnections = idleConns
	
	// Calculate utilization
	if totalConns > 0 {
		cp.metrics.PoolUtilization = float64(activeConns) / float64(totalConns)
	}
	
	// Update healthy endpoints count
	healthyEndpoints := cp.healthMonitor.GetHealthyEndpoints()
	cp.metrics.HealthyEndpoints = int32(len(healthyEndpoints))
	cp.metrics.UnhealthyEndpoints = int32(len(cp.healthMonitor.endpoints)) - cp.metrics.HealthyEndpoints
	
	// Update load balancer with healthy endpoints
	cp.loadBalancer.UpdateHealthyEndpoints(healthyEndpoints)
}

// GetMetrics returns current connection pool metrics
func (cp *ConnectionPool) GetMetrics() *ConnectionPoolMetrics {
	cp.metrics.mu.RLock()
	defer cp.metrics.mu.RUnlock()
	
	return &ConnectionPoolMetrics{
		TotalPools:           cp.metrics.TotalPools,
		TotalConnections:     cp.metrics.TotalConnections,
		ActiveConnections:    cp.metrics.ActiveConnections,
		IdleConnections:      cp.metrics.IdleConnections,
		TotalRequests:        cp.metrics.TotalRequests,
		SuccessfulRequests:   cp.metrics.SuccessfulRequests,
		FailedRequests:       cp.metrics.FailedRequests,
		AverageLatency:       cp.metrics.AverageLatency,
		PoolUtilization:      cp.metrics.PoolUtilization,
		ConnectionReuse:      cp.metrics.ConnectionReuse,
		PoolHitRatio:         cp.metrics.PoolHitRatio,
		HealthyEndpoints:     cp.metrics.HealthyEndpoints,
		UnhealthyEndpoints:   cp.metrics.UnhealthyEndpoints,
		CircuitBreakersOpen:  cp.metrics.CircuitBreakersOpen,
	}
}