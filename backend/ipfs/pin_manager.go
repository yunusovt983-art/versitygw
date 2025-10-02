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
	"sync"
	"sync/atomic"
	"time"
)

// PinManager manages pin operations for IPFS-Cluster with support for
// asynchronous queues, worker pools, prioritization, and retry mechanisms
type PinManager struct {
	// Configuration
	config *PinManagerConfig
	
	// Core dependencies
	clusterClient ClusterClientInterface
	metadataStore MetadataStore
	
	// Queues for async operations
	pinQueue   chan *PinRequest
	unpinQueue chan *UnpinRequest
	
	// Worker pools
	pinWorkers   []*PinWorker
	unpinWorkers []*UnpinWorker
	
	// Retry management
	retryQueue chan *RetryRequest
	retryWorker *RetryWorker
	
	// Monitoring and metrics
	metrics *PinMetrics
	
	// Synchronization
	mu sync.RWMutex
	
	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// State management
	running bool
	
	// Logging
	logger *log.Logger
}

// PinManagerConfig holds configuration for the pin manager
type PinManagerConfig struct {
	// Worker pool configuration
	PinWorkerCount   int `json:"pin_worker_count"`
	UnpinWorkerCount int `json:"unpin_worker_count"`
	
	// Queue configuration
	PinQueueSize   int `json:"pin_queue_size"`
	UnpinQueueSize int `json:"unpin_queue_size"`
	RetryQueueSize int `json:"retry_queue_size"`
	
	// Timeout configuration
	PinTimeout   time.Duration `json:"pin_timeout"`
	UnpinTimeout time.Duration `json:"unpin_timeout"`
	
	// Retry configuration
	MaxRetries        int           `json:"max_retries"`
	InitialRetryDelay time.Duration `json:"initial_retry_delay"`
	MaxRetryDelay     time.Duration `json:"max_retry_delay"`
	RetryBackoffFactor float64      `json:"retry_backoff_factor"`
	
	// Batch processing
	BatchSize        int           `json:"batch_size"`
	BatchTimeout     time.Duration `json:"batch_timeout"`
	BatchingEnabled  bool          `json:"batching_enabled"`
	
	// Monitoring
	MetricsEnabled     bool          `json:"metrics_enabled"`
	MetricsInterval    time.Duration `json:"metrics_interval"`
	HealthCheckEnabled bool          `json:"health_check_enabled"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
}

// PinRequest represents a request to pin an object
type PinRequest struct {
	// Request identification
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	
	// Object information
	CID    string `json:"cid"`
	S3Key  string `json:"s3_key"`
	Bucket string `json:"bucket"`
	Size   int64  `json:"size"`
	
	// Pin configuration
	ReplicationFactor int      `json:"replication_factor"`
	PreferredNodes    []string `json:"preferred_nodes"`
	Priority          PinPriority `json:"priority"`
	
	// Metadata
	Metadata map[string]string `json:"metadata"`
	
	// Callback for completion notification
	ResultChan chan *PinResult `json:"-"`
	
	// Context for cancellation
	Context context.Context `json:"-"`
	
	// Retry information
	RetryCount int       `json:"retry_count"`
	LastError  error     `json:"last_error,omitempty"`
	NextRetry  time.Time `json:"next_retry,omitempty"`
}

// UnpinRequest represents a request to unpin an object
type UnpinRequest struct {
	// Request identification
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	
	// Object information
	CID    string `json:"cid"`
	S3Key  string `json:"s3_key"`
	Bucket string `json:"bucket"`
	
	// Unpin configuration
	Force    bool     `json:"force"`
	Priority PinPriority `json:"priority"`
	
	// Callback for completion notification
	ResultChan chan *UnpinResult `json:"-"`
	
	// Context for cancellation
	Context context.Context `json:"-"`
	
	// Retry information
	RetryCount int       `json:"retry_count"`
	LastError  error     `json:"last_error,omitempty"`
	NextRetry  time.Time `json:"next_retry,omitempty"`
}

// RetryRequest represents a request that needs to be retried
type RetryRequest struct {
	Type      RetryType   `json:"type"`
	PinReq    *PinRequest `json:"pin_request,omitempty"`
	UnpinReq  *UnpinRequest `json:"unpin_request,omitempty"`
	ScheduledAt time.Time `json:"scheduled_at"`
}

// PinPriority defines the priority levels for pin operations
type PinPriority int

const (
	PinPriorityBackground PinPriority = iota // Background/batch operations
	PinPriorityNormal                        // Normal user operations
	PinPriorityCritical                      // Critical/real-time operations
)

// String returns the string representation of PinPriority
func (pp PinPriority) String() string {
	switch pp {
	case PinPriorityBackground:
		return "background"
	case PinPriorityNormal:
		return "normal"
	case PinPriorityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// RetryType defines the type of operation to retry
type RetryType int

const (
	RetryTypePin RetryType = iota
	RetryTypeUnpin
)

// PinResult represents the result of a pin operation
type PinResult struct {
	RequestID   string        `json:"request_id"`
	CID         string        `json:"cid"`
	Success     bool          `json:"success"`
	Error       error         `json:"error,omitempty"`
	Duration    time.Duration `json:"duration"`
	NodesUsed   []string      `json:"nodes_used"`
	RetryCount  int           `json:"retry_count"`
	Timestamp   time.Time     `json:"timestamp"`
}

// UnpinResult represents the result of an unpin operation
type UnpinResult struct {
	RequestID   string        `json:"request_id"`
	CID         string        `json:"cid"`
	Success     bool          `json:"success"`
	Error       error         `json:"error,omitempty"`
	Duration    time.Duration `json:"duration"`
	NodesUsed   []string      `json:"nodes_used"`
	RetryCount  int           `json:"retry_count"`
	Timestamp   time.Time     `json:"timestamp"`
}

// PinWorker handles pin operations
type PinWorker struct {
	id            int
	manager       *PinManager
	clusterClient ClusterClientInterface
	metadataStore MetadataStore
	requestChan   chan *PinRequest
	logger        *log.Logger
	
	// Worker state
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Metrics
	processedCount int64
	errorCount     int64
	lastActivity   time.Time
}

// UnpinWorker handles unpin operations
type UnpinWorker struct {
	id            int
	manager       *PinManager
	clusterClient ClusterClientInterface
	metadataStore MetadataStore
	requestChan   chan *UnpinRequest
	logger        *log.Logger
	
	// Worker state
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Metrics
	processedCount int64
	errorCount     int64
	lastActivity   time.Time
}

// RetryWorker handles retry operations
type RetryWorker struct {
	manager     *PinManager
	requestChan chan *RetryRequest
	logger      *log.Logger
	
	// Worker state
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Metrics
	processedCount int64
	errorCount     int64
}

// PinMetrics holds metrics for pin operations
type PinMetrics struct {
	// Operation counters
	TotalPinRequests   int64 `json:"total_pin_requests"`
	TotalUnpinRequests int64 `json:"total_unpin_requests"`
	SuccessfulPins     int64 `json:"successful_pins"`
	SuccessfulUnpins   int64 `json:"successful_unpins"`
	FailedPins         int64 `json:"failed_pins"`
	FailedUnpins       int64 `json:"failed_unpins"`
	
	// Queue metrics
	PinQueueSize   int64 `json:"pin_queue_size"`
	UnpinQueueSize int64 `json:"unpin_queue_size"`
	RetryQueueSize int64 `json:"retry_queue_size"`
	
	// Performance metrics
	AveragePinLatency   time.Duration `json:"average_pin_latency"`
	AverageUnpinLatency time.Duration `json:"average_unpin_latency"`
	PinThroughput       float64       `json:"pin_throughput"`
	UnpinThroughput     float64       `json:"unpin_throughput"`
	
	// Priority metrics
	CriticalPins    int64 `json:"critical_pins"`
	NormalPins      int64 `json:"normal_pins"`
	BackgroundPins  int64 `json:"background_pins"`
	
	// Retry metrics
	TotalRetries    int64 `json:"total_retries"`
	MaxRetryReached int64 `json:"max_retry_reached"`
	
	// Worker metrics
	ActivePinWorkers   int `json:"active_pin_workers"`
	ActiveUnpinWorkers int `json:"active_unpin_workers"`
	
	// Health metrics
	HealthScore    float64   `json:"health_score"`
	LastHealthCheck time.Time `json:"last_health_check"`
	
	// Synchronization
	mu sync.RWMutex
}

// NewPinManager creates a new pin manager instance
func NewPinManager(config *PinManagerConfig, clusterClient ClusterClientInterface, metadataStore MetadataStore, logger *log.Logger) (*PinManager, error) {
	if config == nil {
		return nil, fmt.Errorf("pin manager config cannot be nil")
	}
	if clusterClient == nil {
		return nil, fmt.Errorf("cluster client cannot be nil")
	}
	if metadataStore == nil {
		return nil, fmt.Errorf("metadata store cannot be nil")
	}
	
	// Set defaults
	setConfigDefaults(config)
	
	// Validate configuration
	if err := validatePinManagerConfig(config); err != nil {
		return nil, fmt.Errorf("invalid pin manager config: %w", err)
	}
	
	if logger == nil {
		logger = log.Default()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pm := &PinManager{
		config:        config,
		clusterClient: clusterClient,
		metadataStore: metadataStore,
		ctx:           ctx,
		cancel:        cancel,
		logger:        logger,
		metrics:       &PinMetrics{},
		running:       false,
	}
	
	// Initialize queues
	pm.pinQueue = make(chan *PinRequest, config.PinQueueSize)
	pm.unpinQueue = make(chan *UnpinRequest, config.UnpinQueueSize)
	pm.retryQueue = make(chan *RetryRequest, config.RetryQueueSize)
	
	logger.Printf("Pin manager created with %d pin workers, %d unpin workers", 
		config.PinWorkerCount, config.UnpinWorkerCount)
	
	return pm, nil
}

// setConfigDefaults sets default values for pin manager configuration
func setConfigDefaults(config *PinManagerConfig) {
	if config.PinWorkerCount == 0 {
		config.PinWorkerCount = 10
	}
	if config.UnpinWorkerCount == 0 {
		config.UnpinWorkerCount = 5
	}
	if config.PinQueueSize == 0 {
		config.PinQueueSize = 10000
	}
	if config.UnpinQueueSize == 0 {
		config.UnpinQueueSize = 5000
	}
	if config.RetryQueueSize == 0 {
		config.RetryQueueSize = 1000
	}
	if config.PinTimeout == 0 {
		config.PinTimeout = 5 * time.Minute
	}
	if config.UnpinTimeout == 0 {
		config.UnpinTimeout = 2 * time.Minute
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.InitialRetryDelay == 0 {
		config.InitialRetryDelay = 1 * time.Second
	}
	if config.MaxRetryDelay == 0 {
		config.MaxRetryDelay = 5 * time.Minute
	}
	if config.RetryBackoffFactor == 0 {
		config.RetryBackoffFactor = 2.0
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.BatchTimeout == 0 {
		config.BatchTimeout = 10 * time.Second
	}
	if config.MetricsInterval == 0 {
		config.MetricsInterval = 30 * time.Second
	}
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 1 * time.Minute
	}
}

// validatePinManagerConfig validates the pin manager configuration
func validatePinManagerConfig(config *PinManagerConfig) error {
	if config.PinWorkerCount <= 0 {
		return fmt.Errorf("pin worker count must be positive")
	}
	if config.UnpinWorkerCount <= 0 {
		return fmt.Errorf("unpin worker count must be positive")
	}
	if config.PinQueueSize <= 0 {
		return fmt.Errorf("pin queue size must be positive")
	}
	if config.UnpinQueueSize <= 0 {
		return fmt.Errorf("unpin queue size must be positive")
	}
	if config.RetryQueueSize <= 0 {
		return fmt.Errorf("retry queue size must be positive")
	}
	if config.MaxRetries < 0 {
		return fmt.Errorf("max retries cannot be negative")
	}
	if config.RetryBackoffFactor <= 1.0 {
		return fmt.Errorf("retry backoff factor must be greater than 1.0")
	}
	return nil
}

// Start starts the pin manager and all its workers
func (pm *PinManager) Start() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if pm.running {
		return fmt.Errorf("pin manager is already running")
	}
	
	pm.logger.Println("Starting pin manager...")
	
	// Start pin workers
	pm.pinWorkers = make([]*PinWorker, pm.config.PinWorkerCount)
	for i := 0; i < pm.config.PinWorkerCount; i++ {
		worker := pm.createPinWorker(i)
		pm.pinWorkers[i] = worker
		worker.start()
	}
	
	// Start unpin workers
	pm.unpinWorkers = make([]*UnpinWorker, pm.config.UnpinWorkerCount)
	for i := 0; i < pm.config.UnpinWorkerCount; i++ {
		worker := pm.createUnpinWorker(i)
		pm.unpinWorkers[i] = worker
		worker.start()
	}
	
	// Start retry worker
	pm.retryWorker = pm.createRetryWorker()
	pm.retryWorker.start()
	
	// Start metrics collection if enabled
	if pm.config.MetricsEnabled {
		pm.startMetricsCollection()
	}
	
	// Start health checking if enabled
	if pm.config.HealthCheckEnabled {
		pm.startHealthChecking()
	}
	
	pm.running = true
	pm.logger.Printf("Pin manager started with %d pin workers and %d unpin workers", 
		pm.config.PinWorkerCount, pm.config.UnpinWorkerCount)
	
	return nil
}

// Stop stops the pin manager and all its workers
func (pm *PinManager) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if !pm.running {
		return fmt.Errorf("pin manager is not running")
	}
	
	pm.logger.Println("Stopping pin manager...")
	
	// Cancel context to signal shutdown
	pm.cancel()
	
	// Close queues to stop accepting new requests
	close(pm.pinQueue)
	close(pm.unpinQueue)
	close(pm.retryQueue)
	
	// Wait for all workers to finish
	pm.wg.Wait()
	
	pm.running = false
	pm.logger.Println("Pin manager stopped")
	
	return nil
}

// createPinWorker creates a new pin worker
func (pm *PinManager) createPinWorker(id int) *PinWorker {
	ctx, cancel := context.WithCancel(pm.ctx)
	
	return &PinWorker{
		id:            id,
		manager:       pm,
		clusterClient: pm.clusterClient,
		metadataStore: pm.metadataStore,
		requestChan:   pm.pinQueue,
		logger:        pm.logger,
		ctx:           ctx,
		cancel:        cancel,
		lastActivity:  time.Now(),
	}
}

// createUnpinWorker creates a new unpin worker
func (pm *PinManager) createUnpinWorker(id int) *UnpinWorker {
	ctx, cancel := context.WithCancel(pm.ctx)
	
	return &UnpinWorker{
		id:            id,
		manager:       pm,
		clusterClient: pm.clusterClient,
		metadataStore: pm.metadataStore,
		requestChan:   pm.unpinQueue,
		logger:        pm.logger,
		ctx:           ctx,
		cancel:        cancel,
		lastActivity:  time.Now(),
	}
}

// createRetryWorker creates a new retry worker
func (pm *PinManager) createRetryWorker() *RetryWorker {
	ctx, cancel := context.WithCancel(pm.ctx)
	
	return &RetryWorker{
		manager:     pm,
		requestChan: pm.retryQueue,
		logger:      pm.logger,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Pin submits a pin request with the specified priority
func (pm *PinManager) Pin(ctx context.Context, cid, s3Key, bucket string, size int64, replicationFactor int, priority PinPriority) (*PinResult, error) {
	if !pm.isRunning() {
		return nil, fmt.Errorf("pin manager is not running")
	}
	
	// Create pin request
	request := &PinRequest{
		ID:                generateRequestID(),
		Timestamp:         time.Now(),
		CID:               cid,
		S3Key:             s3Key,
		Bucket:            bucket,
		Size:              size,
		ReplicationFactor: replicationFactor,
		Priority:          priority,
		Metadata:          make(map[string]string),
		ResultChan:        make(chan *PinResult, 1),
		Context:           ctx,
		RetryCount:        0,
	}
	
	// Submit request based on priority
	select {
	case pm.pinQueue <- request:
		// Update metrics
		atomic.AddInt64(&pm.metrics.TotalPinRequests, 1)
		pm.updatePriorityMetrics(priority, true)
		
		pm.logger.Printf("Pin request submitted: CID=%s, Priority=%s, ID=%s", cid, priority.String(), request.ID)
		
		// Wait for result
		select {
		case result := <-request.ResultChan:
			return result, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-pm.ctx.Done():
			return nil, fmt.Errorf("pin manager is shutting down")
		}
		
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-pm.ctx.Done():
		return nil, fmt.Errorf("pin manager is shutting down")
	default:
		return nil, fmt.Errorf("pin queue is full")
	}
}

// PinAsync submits a pin request asynchronously
func (pm *PinManager) PinAsync(ctx context.Context, cid, s3Key, bucket string, size int64, replicationFactor int, priority PinPriority) (string, error) {
	if !pm.isRunning() {
		return "", fmt.Errorf("pin manager is not running")
	}
	
	// Create pin request
	request := &PinRequest{
		ID:                generateRequestID(),
		Timestamp:         time.Now(),
		CID:               cid,
		S3Key:             s3Key,
		Bucket:            bucket,
		Size:              size,
		ReplicationFactor: replicationFactor,
		Priority:          priority,
		Metadata:          make(map[string]string),
		Context:           ctx,
		RetryCount:        0,
	}
	
	// Submit request
	select {
	case pm.pinQueue <- request:
		// Update metrics
		atomic.AddInt64(&pm.metrics.TotalPinRequests, 1)
		pm.updatePriorityMetrics(priority, true)
		
		pm.logger.Printf("Async pin request submitted: CID=%s, Priority=%s, ID=%s", cid, priority.String(), request.ID)
		return request.ID, nil
		
	case <-ctx.Done():
		return "", ctx.Err()
	case <-pm.ctx.Done():
		return "", fmt.Errorf("pin manager is shutting down")
	default:
		return "", fmt.Errorf("pin queue is full")
	}
}

// Unpin submits an unpin request
func (pm *PinManager) Unpin(ctx context.Context, cid, s3Key, bucket string, force bool, priority PinPriority) (*UnpinResult, error) {
	if !pm.isRunning() {
		return nil, fmt.Errorf("pin manager is not running")
	}
	
	// Create unpin request
	request := &UnpinRequest{
		ID:         generateRequestID(),
		Timestamp:  time.Now(),
		CID:        cid,
		S3Key:      s3Key,
		Bucket:     bucket,
		Force:      force,
		Priority:   priority,
		ResultChan: make(chan *UnpinResult, 1),
		Context:    ctx,
		RetryCount: 0,
	}
	
	// Submit request
	select {
	case pm.unpinQueue <- request:
		// Update metrics
		atomic.AddInt64(&pm.metrics.TotalUnpinRequests, 1)
		
		pm.logger.Printf("Unpin request submitted: CID=%s, Priority=%s, ID=%s", cid, priority.String(), request.ID)
		
		// Wait for result
		select {
		case result := <-request.ResultChan:
			return result, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-pm.ctx.Done():
			return nil, fmt.Errorf("pin manager is shutting down")
		}
		
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-pm.ctx.Done():
		return nil, fmt.Errorf("pin manager is shutting down")
	default:
		return nil, fmt.Errorf("unpin queue is full")
	}
}

// UnpinAsync submits an unpin request asynchronously
func (pm *PinManager) UnpinAsync(ctx context.Context, cid, s3Key, bucket string, force bool, priority PinPriority) (string, error) {
	if !pm.isRunning() {
		return "", fmt.Errorf("pin manager is not running")
	}
	
	// Create unpin request
	request := &UnpinRequest{
		ID:        generateRequestID(),
		Timestamp: time.Now(),
		CID:       cid,
		S3Key:     s3Key,
		Bucket:    bucket,
		Force:     force,
		Priority:  priority,
		Context:   ctx,
		RetryCount: 0,
	}
	
	// Submit request
	select {
	case pm.unpinQueue <- request:
		// Update metrics
		atomic.AddInt64(&pm.metrics.TotalUnpinRequests, 1)
		
		pm.logger.Printf("Async unpin request submitted: CID=%s, Priority=%s, ID=%s", cid, priority.String(), request.ID)
		return request.ID, nil
		
	case <-ctx.Done():
		return "", ctx.Err()
	case <-pm.ctx.Done():
		return "", fmt.Errorf("pin manager is shutting down")
	default:
		return "", fmt.Errorf("unpin queue is full")
	}
}

// GetPinStatus returns the current pin status for a CID
func (pm *PinManager) GetPinStatus(ctx context.Context, cid string) (*PinStatusInfo, error) {
	if !pm.isRunning() {
		return nil, fmt.Errorf("pin manager is not running")
	}
	
	// Get status from metadata store
	mappings, err := pm.metadataStore.SearchByCID(ctx, cid)
	if err != nil {
		return nil, fmt.Errorf("failed to search for CID: %w", err)
	}
	
	if len(mappings) == 0 {
		return &PinStatusInfo{
			CID:    cid,
			Status: "unknown",
		}, nil
	}
	
	// Use the first mapping (they should all have the same pin status for the same CID)
	mapping := mappings[0]
	
	return &PinStatusInfo{
		CID:    cid,
		Status: mapping.PinStatus.String(),
	}, nil
}

// GetMetrics returns current pin manager metrics
func (pm *PinManager) GetMetrics() *PinMetrics {
	pm.metrics.mu.RLock()
	defer pm.metrics.mu.RUnlock()
	
	// Update queue sizes
	pm.metrics.PinQueueSize = int64(len(pm.pinQueue))
	pm.metrics.UnpinQueueSize = int64(len(pm.unpinQueue))
	pm.metrics.RetryQueueSize = int64(len(pm.retryQueue))
	
	// Update worker counts
	pm.metrics.ActivePinWorkers = len(pm.pinWorkers)
	pm.metrics.ActiveUnpinWorkers = len(pm.unpinWorkers)
	
	// Create a copy to return
	metrics := *pm.metrics
	return &metrics
}

// GetQueueStats returns current queue statistics
func (pm *PinManager) GetQueueStats() *QueueStats {
	return &QueueStats{
		PinQueueSize:     len(pm.pinQueue),
		PinQueueCapacity: cap(pm.pinQueue),
		UnpinQueueSize:   len(pm.unpinQueue),
		UnpinQueueCapacity: cap(pm.unpinQueue),
		RetryQueueSize:   len(pm.retryQueue),
		RetryQueueCapacity: cap(pm.retryQueue),
	}
}

// IsHealthy returns true if the pin manager is healthy
func (pm *PinManager) IsHealthy() bool {
	if !pm.isRunning() {
		return false
	}
	
	// Check if queues are not completely full
	queueStats := pm.GetQueueStats()
	if queueStats.PinQueueSize >= queueStats.PinQueueCapacity {
		return false
	}
	if queueStats.UnpinQueueSize >= queueStats.UnpinQueueCapacity {
		return false
	}
	
	// Check if workers are responsive
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	now := time.Now()
	for _, worker := range pm.pinWorkers {
		if now.Sub(worker.lastActivity) > 5*time.Minute {
			return false
		}
	}
	
	for _, worker := range pm.unpinWorkers {
		if now.Sub(worker.lastActivity) > 5*time.Minute {
			return false
		}
	}
	
	return true
}

// isRunning returns true if the pin manager is currently running
func (pm *PinManager) isRunning() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.running
}

// updatePriorityMetrics updates metrics based on priority
func (pm *PinManager) updatePriorityMetrics(priority PinPriority, isPin bool) {
	if !isPin {
		return
	}
	
	pm.metrics.mu.Lock()
	defer pm.metrics.mu.Unlock()
	
	switch priority {
	case PinPriorityCritical:
		pm.metrics.CriticalPins++
	case PinPriorityNormal:
		pm.metrics.NormalPins++
	case PinPriorityBackground:
		pm.metrics.BackgroundPins++
	}
}

// startMetricsCollection starts the metrics collection goroutine
func (pm *PinManager) startMetricsCollection() {
	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		
		ticker := time.NewTicker(pm.config.MetricsInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-pm.ctx.Done():
				return
			case <-ticker.C:
				pm.collectMetrics()
			}
		}
	}()
}

// startHealthChecking starts the health checking goroutine
func (pm *PinManager) startHealthChecking() {
	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		
		ticker := time.NewTicker(pm.config.HealthCheckInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-pm.ctx.Done():
				return
			case <-ticker.C:
				pm.performHealthCheck()
			}
		}
	}()
}

// collectMetrics collects and updates metrics
func (pm *PinManager) collectMetrics() {
	pm.metrics.mu.Lock()
	defer pm.metrics.mu.Unlock()
	
	// Calculate throughput
	totalOps := pm.metrics.SuccessfulPins + pm.metrics.SuccessfulUnpins
	if totalOps > 0 {
		elapsed := time.Since(pm.metrics.LastHealthCheck)
		if elapsed > 0 {
			pm.metrics.PinThroughput = float64(pm.metrics.SuccessfulPins) / elapsed.Seconds()
			pm.metrics.UnpinThroughput = float64(pm.metrics.SuccessfulUnpins) / elapsed.Seconds()
		}
	}
	
	// Calculate health score
	pm.calculateHealthScore()
}

// performHealthCheck performs a health check of the pin manager
func (pm *PinManager) performHealthCheck() {
	pm.metrics.mu.Lock()
	defer pm.metrics.mu.Unlock()
	
	pm.metrics.LastHealthCheck = time.Now()
	
	// Check worker health
	healthyWorkers := 0
	totalWorkers := len(pm.pinWorkers) + len(pm.unpinWorkers)
	
	now := time.Now()
	for _, worker := range pm.pinWorkers {
		if now.Sub(worker.lastActivity) < 5*time.Minute {
			healthyWorkers++
		}
	}
	
	for _, worker := range pm.unpinWorkers {
		if now.Sub(worker.lastActivity) < 5*time.Minute {
			healthyWorkers++
		}
	}
	
	// Update health score based on worker health
	if totalWorkers > 0 {
		workerHealthRatio := float64(healthyWorkers) / float64(totalWorkers)
		pm.metrics.HealthScore = workerHealthRatio * 100
	}
}

// calculateHealthScore calculates the overall health score
func (pm *PinManager) calculateHealthScore() {
	// Base score on success rate
	totalRequests := pm.metrics.TotalPinRequests + pm.metrics.TotalUnpinRequests
	successfulRequests := pm.metrics.SuccessfulPins + pm.metrics.SuccessfulUnpins
	
	if totalRequests > 0 {
		successRate := float64(successfulRequests) / float64(totalRequests)
		pm.metrics.HealthScore = successRate * 100
	} else {
		pm.metrics.HealthScore = 100 // No requests yet, assume healthy
	}
	
	// Adjust based on queue utilization
	queueStats := pm.GetQueueStats()
	pinUtilization := float64(queueStats.PinQueueSize) / float64(queueStats.PinQueueCapacity)
	unpinUtilization := float64(queueStats.UnpinQueueSize) / float64(queueStats.UnpinQueueCapacity)
	
	avgUtilization := (pinUtilization + unpinUtilization) / 2
	if avgUtilization > 0.8 {
		pm.metrics.HealthScore *= 0.8 // Reduce score if queues are too full
	}
}

// Supporting types


// QueueStats holds statistics about the queues
type QueueStats struct {
	PinQueueSize       int `json:"pin_queue_size"`
	PinQueueCapacity   int `json:"pin_queue_capacity"`
	UnpinQueueSize     int `json:"unpin_queue_size"`
	UnpinQueueCapacity int `json:"unpin_queue_capacity"`
	RetryQueueSize     int `json:"retry_queue_size"`
	RetryQueueCapacity int `json:"retry_queue_capacity"`
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond())
}