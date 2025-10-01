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

// BatchAPI provides high-performance batch operations for mass pin/unpin operations
type BatchAPI struct {
	// Configuration
	config *BatchConfig
	
	// Dependencies
	clusterClient ClusterClientInterface
	metadataStore MetadataStore
	pinManager    *PinManager
	
	// Batch processing
	batchProcessor *BatchProcessor
	
	// Metrics and monitoring
	metrics *BatchMetrics
	
	// Synchronization
	mu sync.RWMutex
	
	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Logging
	logger *log.Logger
}

// BatchConfig holds configuration for batch operations
type BatchConfig struct {
	// Batch size limits
	MaxBatchSize        int `json:"max_batch_size"`         // Maximum items per batch
	DefaultBatchSize    int `json:"default_batch_size"`     // Default batch size
	MinBatchSize        int `json:"min_batch_size"`         // Minimum batch size
	
	// Timing configuration
	BatchTimeout        time.Duration `json:"batch_timeout"`         // Max time to wait for batch to fill
	ProcessingTimeout   time.Duration `json:"processing_timeout"`    // Max time to process a batch
	RetryDelay          time.Duration `json:"retry_delay"`           // Delay between retries
	
	// Concurrency settings
	MaxConcurrentBatches int `json:"max_concurrent_batches"` // Max batches processing simultaneously
	WorkerPoolSize       int `json:"worker_pool_size"`       // Number of worker goroutines
	
	// Retry configuration
	MaxRetries          int     `json:"max_retries"`           // Max retry attempts per batch
	RetryBackoffFactor  float64 `json:"retry_backoff_factor"`  // Exponential backoff factor
	
	// Performance optimization
	PipeliningEnabled   bool `json:"pipelining_enabled"`     // Enable request pipelining
	CompressionEnabled  bool `json:"compression_enabled"`    // Enable batch compression
	
	// Monitoring
	MetricsEnabled      bool          `json:"metrics_enabled"`
	MetricsInterval     time.Duration `json:"metrics_interval"`
}

// BatchRequest represents a batch operation request
type BatchRequest struct {
	ID          string                 `json:"id"`
	Type        BatchOperationType     `json:"type"`
	Items       []*BatchItem          `json:"items"`
	Priority    BatchPriority         `json:"priority"`
	Metadata    map[string]string     `json:"metadata"`
	CreatedAt   time.Time             `json:"created_at"`
	Timeout     time.Duration         `json:"timeout"`
	Callback    BatchCompletionCallback `json:"-"`
}

// BatchItem represents a single item in a batch operation
type BatchItem struct {
	CID              string            `json:"cid"`
	S3Key            string            `json:"s3_key"`
	Bucket           string            `json:"bucket"`
	Size             int64             `json:"size"`
	ReplicationFactor int              `json:"replication_factor"`
	Metadata         map[string]string `json:"metadata"`
	Priority         PinPriority       `json:"priority"`
}

// BatchResult represents the result of a batch operation
type BatchResult struct {
	RequestID     string                    `json:"request_id"`
	Type          BatchOperationType        `json:"type"`
	TotalItems    int                       `json:"total_items"`
	SuccessCount  int                       `json:"success_count"`
	FailureCount  int                       `json:"failure_count"`
	ItemResults   []*BatchItemResult        `json:"item_results"`
	StartTime     time.Time                 `json:"start_time"`
	EndTime       time.Time                 `json:"end_time"`
	Duration      time.Duration             `json:"duration"`
	Error         error                     `json:"error,omitempty"`
}

// BatchItemResult represents the result of processing a single batch item
type BatchItemResult struct {
	CID       string    `json:"cid"`
	S3Key     string    `json:"s3_key"`
	Bucket    string    `json:"bucket"`
	Success   bool      `json:"success"`
	Error     error     `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
	Retries   int       `json:"retries"`
}

// BatchOperationType defines the type of batch operation
type BatchOperationType int

const (
	BatchOperationPin BatchOperationType = iota
	BatchOperationUnpin
	BatchOperationRepin
	BatchOperationVerify
	BatchOperationMigrate
)

// String returns the string representation of BatchOperationType
func (bot BatchOperationType) String() string {
	switch bot {
	case BatchOperationPin:
		return "pin"
	case BatchOperationUnpin:
		return "unpin"
	case BatchOperationRepin:
		return "repin"
	case BatchOperationVerify:
		return "verify"
	case BatchOperationMigrate:
		return "migrate"
	default:
		return "unknown"
	}
}

// BatchPriority defines the priority of batch operations
type BatchPriority int

const (
	BatchPriorityLow BatchPriority = iota
	BatchPriorityNormal
	BatchPriorityHigh
	BatchPriorityCritical
)

// BatchCompletionCallback is called when a batch operation completes
type BatchCompletionCallback func(*BatchResult)

// BatchProcessor handles the processing of batch requests
type BatchProcessor struct {
	// Configuration
	config *BatchConfig
	
	// Processing queues by priority
	criticalQueue chan *BatchRequest
	highQueue     chan *BatchRequest
	normalQueue   chan *BatchRequest
	lowQueue      chan *BatchRequest
	
	// Worker pool
	workers []*BatchWorker
	
	// Active batches tracking
	activeBatches map[string]*BatchRequest
	batchesMu     sync.RWMutex
	
	// Metrics
	metrics *BatchMetrics
	
	// Synchronization
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Logging
	logger *log.Logger
}

// BatchWorker processes batch requests
type BatchWorker struct {
	id            int
	processor     *BatchProcessor
	clusterClient ClusterClientInterface
	metadataStore MetadataStore
	logger        *log.Logger
}

// BatchMetrics holds metrics for batch operations
type BatchMetrics struct {
	// Operation counts
	TotalBatches        int64 `json:"total_batches"`
	SuccessfulBatches   int64 `json:"successful_batches"`
	FailedBatches       int64 `json:"failed_batches"`
	
	// Item counts
	TotalItems          int64 `json:"total_items"`
	SuccessfulItems     int64 `json:"successful_items"`
	FailedItems         int64 `json:"failed_items"`
	
	// Performance metrics
	AverageBatchSize    float64       `json:"average_batch_size"`
	AverageProcessingTime time.Duration `json:"average_processing_time"`
	TotalProcessingTime time.Duration `json:"total_processing_time"`
	Throughput          float64       `json:"throughput"` // Items per second
	
	// Queue metrics
	QueueSizes          map[string]int `json:"queue_sizes"`
	AverageQueueTime    time.Duration  `json:"average_queue_time"`
	
	// Retry metrics
	TotalRetries        int64 `json:"total_retries"`
	AverageRetries      float64 `json:"average_retries"`
	
	// Synchronization
	mu sync.RWMutex
}

// NewBatchAPI creates a new batch API instance
func NewBatchAPI(config *BatchConfig, clusterClient ClusterClientInterface, metadataStore MetadataStore, pinManager *PinManager, logger *log.Logger) *BatchAPI {
	if config == nil {
		config = getDefaultBatchConfig()
	}
	
	if logger == nil {
		logger = log.Default()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	api := &BatchAPI{
		config:        config,
		clusterClient: clusterClient,
		metadataStore: metadataStore,
		pinManager:    pinManager,
		metrics:       &BatchMetrics{QueueSizes: make(map[string]int)},
		ctx:           ctx,
		cancel:        cancel,
		logger:        logger,
	}
	
	// Initialize batch processor
	api.batchProcessor = NewBatchProcessor(config, clusterClient, metadataStore, api.metrics, logger)
	
	return api
}

// getDefaultBatchConfig returns default batch configuration
func getDefaultBatchConfig() *BatchConfig {
	return &BatchConfig{
		MaxBatchSize:         10000,              // 10K items per batch
		DefaultBatchSize:     1000,               // 1K items default
		MinBatchSize:         10,                 // 10 items minimum
		BatchTimeout:         30 * time.Second,   // 30 seconds to fill batch
		ProcessingTimeout:    5 * time.Minute,    // 5 minutes to process
		RetryDelay:          1 * time.Second,     // 1 second retry delay
		MaxConcurrentBatches: 10,                 // 10 concurrent batches
		WorkerPoolSize:       5,                  // 5 workers
		MaxRetries:          3,                   // 3 retry attempts
		RetryBackoffFactor:  2.0,                 // 2x backoff
		PipeliningEnabled:   true,
		CompressionEnabled:  false,               // Disable for simplicity
		MetricsEnabled:      true,
		MetricsInterval:     30 * time.Second,
	}
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(config *BatchConfig, clusterClient ClusterClientInterface, metadataStore MetadataStore, metrics *BatchMetrics, logger *log.Logger) *BatchProcessor {
	ctx, cancel := context.WithCancel(context.Background())
	
	processor := &BatchProcessor{
		config:        config,
		criticalQueue: make(chan *BatchRequest, 100),
		highQueue:     make(chan *BatchRequest, 500),
		normalQueue:   make(chan *BatchRequest, 1000),
		lowQueue:      make(chan *BatchRequest, 2000),
		activeBatches: make(map[string]*BatchRequest),
		metrics:       metrics,
		ctx:           ctx,
		cancel:        cancel,
		logger:        logger,
	}
	
	// Create worker pool
	processor.workers = make([]*BatchWorker, config.WorkerPoolSize)
	for i := 0; i < config.WorkerPoolSize; i++ {
		processor.workers[i] = &BatchWorker{
			id:            i,
			processor:     processor,
			clusterClient: clusterClient,
			metadataStore: metadataStore,
			logger:        logger,
		}
	}
	
	return processor
}

// Start starts the batch API and its components
func (ba *BatchAPI) Start() error {
	ba.mu.Lock()
	defer ba.mu.Unlock()
	
	// Start batch processor
	if err := ba.batchProcessor.Start(); err != nil {
		return fmt.Errorf("failed to start batch processor: %w", err)
	}
	
	ba.logger.Println("Batch API started successfully")
	return nil
}

// Stop stops the batch API and its components
func (ba *BatchAPI) Stop() error {
	ba.mu.Lock()
	defer ba.mu.Unlock()
	
	ba.cancel()
	ba.wg.Wait()
	
	// Stop batch processor
	if err := ba.batchProcessor.Stop(); err != nil {
		return fmt.Errorf("failed to stop batch processor: %w", err)
	}
	
	ba.logger.Println("Batch API stopped successfully")
	return nil
}

// SubmitBatch submits a batch request for processing
func (ba *BatchAPI) SubmitBatch(ctx context.Context, request *BatchRequest) (*BatchResult, error) {
	if request == nil {
		return nil, fmt.Errorf("batch request cannot be nil")
	}
	
	// Validate batch request
	if err := ba.validateBatchRequest(request); err != nil {
		return nil, fmt.Errorf("invalid batch request: %w", err)
	}
	
	// Set default values
	if request.ID == "" {
		request.ID = generateBatchID()
	}
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now()
	}
	if request.Timeout == 0 {
		request.Timeout = ba.config.ProcessingTimeout
	}
	
	ba.logger.Printf("Submitting batch request %s with %d items (type: %s, priority: %d)", 
		request.ID, len(request.Items), request.Type.String(), request.Priority)
	
	// Submit to processor
	return ba.batchProcessor.ProcessBatch(ctx, request)
}

// SubmitBatchAsync submits a batch request for asynchronous processing
func (ba *BatchAPI) SubmitBatchAsync(ctx context.Context, request *BatchRequest) error {
	if request == nil {
		return fmt.Errorf("batch request cannot be nil")
	}
	
	// Validate batch request
	if err := ba.validateBatchRequest(request); err != nil {
		return fmt.Errorf("invalid batch request: %w", err)
	}
	
	// Set default values
	if request.ID == "" {
		request.ID = generateBatchID()
	}
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now()
	}
	
	ba.logger.Printf("Submitting async batch request %s with %d items", request.ID, len(request.Items))
	
	// Submit to appropriate queue based on priority
	return ba.batchProcessor.EnqueueBatch(request)
}

// BatchPin performs a batch pin operation
func (ba *BatchAPI) BatchPin(ctx context.Context, items []*BatchItem, priority BatchPriority) (*BatchResult, error) {
	request := &BatchRequest{
		Type:     BatchOperationPin,
		Items:    items,
		Priority: priority,
	}
	
	return ba.SubmitBatch(ctx, request)
}

// BatchUnpin performs a batch unpin operation
func (ba *BatchAPI) BatchUnpin(ctx context.Context, items []*BatchItem, priority BatchPriority) (*BatchResult, error) {
	request := &BatchRequest{
		Type:     BatchOperationUnpin,
		Items:    items,
		Priority: priority,
	}
	
	return ba.SubmitBatch(ctx, request)
}

// BatchVerify performs a batch verification operation
func (ba *BatchAPI) BatchVerify(ctx context.Context, items []*BatchItem, priority BatchPriority) (*BatchResult, error) {
	request := &BatchRequest{
		Type:     BatchOperationVerify,
		Items:    items,
		Priority: priority,
	}
	
	return ba.SubmitBatch(ctx, request)
}

// validateBatchRequest validates a batch request
func (ba *BatchAPI) validateBatchRequest(request *BatchRequest) error {
	if len(request.Items) == 0 {
		return fmt.Errorf("batch request must contain at least one item")
	}
	
	if len(request.Items) > ba.config.MaxBatchSize {
		return fmt.Errorf("batch size %d exceeds maximum %d", len(request.Items), ba.config.MaxBatchSize)
	}
	
	// Validate each item
	for i, item := range request.Items {
		if item.CID == "" {
			return fmt.Errorf("item %d: CID cannot be empty", i)
		}
		if item.S3Key == "" {
			return fmt.Errorf("item %d: S3Key cannot be empty", i)
		}
		if item.Bucket == "" {
			return fmt.Errorf("item %d: Bucket cannot be empty", i)
		}
	}
	
	return nil
}

// Start starts the batch processor
func (bp *BatchProcessor) Start() error {
	// Start workers
	for _, worker := range bp.workers {
		bp.wg.Add(1)
		go worker.run(bp.ctx, &bp.wg)
	}
	
	bp.logger.Printf("Started %d batch workers", len(bp.workers))
	return nil
}

// Stop stops the batch processor
func (bp *BatchProcessor) Stop() error {
	bp.cancel()
	bp.wg.Wait()
	
	bp.logger.Println("Batch processor stopped")
	return nil
}

// ProcessBatch processes a batch request synchronously
func (bp *BatchProcessor) ProcessBatch(ctx context.Context, request *BatchRequest) (*BatchResult, error) {
	startTime := time.Now()
	
	// Track active batch
	bp.batchesMu.Lock()
	bp.activeBatches[request.ID] = request
	bp.batchesMu.Unlock()
	
	defer func() {
		bp.batchesMu.Lock()
		delete(bp.activeBatches, request.ID)
		bp.batchesMu.Unlock()
	}()
	
	// Process items
	result := &BatchResult{
		RequestID:    request.ID,
		Type:         request.Type,
		TotalItems:   len(request.Items),
		ItemResults:  make([]*BatchItemResult, len(request.Items)),
		StartTime:    startTime,
	}
	
	// Process items concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, bp.config.MaxConcurrentBatches)
	
	for i, item := range request.Items {
		wg.Add(1)
		go func(index int, batchItem *BatchItem) {
			defer wg.Done()
			
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			itemResult := bp.processItem(ctx, request.Type, batchItem)
			result.ItemResults[index] = itemResult
			
			if itemResult.Success {
				atomic.AddInt64(&bp.metrics.SuccessfulItems, 1)
				result.SuccessCount++
			} else {
				atomic.AddInt64(&bp.metrics.FailedItems, 1)
				result.FailureCount++
			}
		}(i, item)
	}
	
	wg.Wait()
	
	// Finalize result
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	
	// Update metrics
	bp.updateBatchMetrics(result)
	
	bp.logger.Printf("Completed batch %s: %d/%d items successful in %v", 
		request.ID, result.SuccessCount, result.TotalItems, result.Duration)
	
	return result, nil
}

// EnqueueBatch enqueues a batch request for asynchronous processing
func (bp *BatchProcessor) EnqueueBatch(request *BatchRequest) error {
	var queue chan *BatchRequest
	
	switch request.Priority {
	case BatchPriorityCritical:
		queue = bp.criticalQueue
	case BatchPriorityHigh:
		queue = bp.highQueue
	case BatchPriorityNormal:
		queue = bp.normalQueue
	case BatchPriorityLow:
		queue = bp.lowQueue
	default:
		queue = bp.normalQueue
	}
	
	select {
	case queue <- request:
		return nil
	case <-bp.ctx.Done():
		return bp.ctx.Err()
	default:
		return fmt.Errorf("queue full for priority %d", request.Priority)
	}
}

// processItem processes a single batch item
func (bp *BatchProcessor) processItem(ctx context.Context, opType BatchOperationType, item *BatchItem) *BatchItemResult {
	startTime := time.Now()
	
	result := &BatchItemResult{
		CID:    item.CID,
		S3Key:  item.S3Key,
		Bucket: item.Bucket,
	}
	
	var err error
	
	switch opType {
	case BatchOperationPin:
		err = bp.pinItem(ctx, item)
	case BatchOperationUnpin:
		err = bp.unpinItem(ctx, item)
	case BatchOperationVerify:
		err = bp.verifyItem(ctx, item)
	default:
		err = fmt.Errorf("unsupported operation type: %s", opType.String())
	}
	
	result.Duration = time.Since(startTime)
	result.Success = err == nil
	result.Error = err
	
	return result
}

// pinItem pins a single item
func (bp *BatchProcessor) pinItem(ctx context.Context, item *BatchItem) error {
	// This is a simplified implementation
	// In production, this would use the actual cluster client
	bp.logger.Printf("Pinning item: %s (CID: %s)", item.S3Key, item.CID)
	
	// Simulate pin operation
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Millisecond):
		return nil // Success
	}
}

// unpinItem unpins a single item
func (bp *BatchProcessor) unpinItem(ctx context.Context, item *BatchItem) error {
	bp.logger.Printf("Unpinning item: %s (CID: %s)", item.S3Key, item.CID)
	
	// Simulate unpin operation
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Millisecond):
		return nil // Success
	}
}

// verifyItem verifies a single item
func (bp *BatchProcessor) verifyItem(ctx context.Context, item *BatchItem) error {
	bp.logger.Printf("Verifying item: %s (CID: %s)", item.S3Key, item.CID)
	
	// Simulate verify operation
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Millisecond):
		return nil // Success
	}
}

// run runs a batch worker
func (bw *BatchWorker) run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	
	bw.logger.Printf("Batch worker %d started", bw.id)
	defer bw.logger.Printf("Batch worker %d stopped", bw.id)
	
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-bw.processor.criticalQueue:
			bw.processBatchRequest(ctx, request)
		case request := <-bw.processor.highQueue:
			bw.processBatchRequest(ctx, request)
		case request := <-bw.processor.normalQueue:
			bw.processBatchRequest(ctx, request)
		case request := <-bw.processor.lowQueue:
			bw.processBatchRequest(ctx, request)
		}
	}
}

// processBatchRequest processes a batch request asynchronously
func (bw *BatchWorker) processBatchRequest(ctx context.Context, request *BatchRequest) {
	result, err := bw.processor.ProcessBatch(ctx, request)
	if err != nil {
		bw.logger.Printf("Worker %d failed to process batch %s: %v", bw.id, request.ID, err)
		return
	}
	
	// Call completion callback if provided
	if request.Callback != nil {
		request.Callback(result)
	}
}

// updateBatchMetrics updates batch processing metrics
func (bp *BatchProcessor) updateBatchMetrics(result *BatchResult) {
	bp.metrics.mu.Lock()
	defer bp.metrics.mu.Unlock()
	
	bp.metrics.TotalBatches++
	bp.metrics.TotalItems += int64(result.TotalItems)
	bp.metrics.TotalProcessingTime += result.Duration
	
	if result.FailureCount == 0 {
		bp.metrics.SuccessfulBatches++
	} else {
		bp.metrics.FailedBatches++
	}
	
	// Calculate averages
	if bp.metrics.TotalBatches > 0 {
		bp.metrics.AverageBatchSize = float64(bp.metrics.TotalItems) / float64(bp.metrics.TotalBatches)
		bp.metrics.AverageProcessingTime = bp.metrics.TotalProcessingTime / time.Duration(bp.metrics.TotalBatches)
	}
	
	// Calculate throughput
	if result.Duration > 0 {
		bp.metrics.Throughput = float64(result.TotalItems) / result.Duration.Seconds()
	}
}

// GetMetrics returns current batch metrics
func (ba *BatchAPI) GetMetrics() *BatchMetrics {
	ba.metrics.mu.RLock()
	defer ba.metrics.mu.RUnlock()
	
	// Return a copy of the metrics
	return &BatchMetrics{
		TotalBatches:          ba.metrics.TotalBatches,
		SuccessfulBatches:     ba.metrics.SuccessfulBatches,
		FailedBatches:         ba.metrics.FailedBatches,
		TotalItems:            ba.metrics.TotalItems,
		SuccessfulItems:       ba.metrics.SuccessfulItems,
		FailedItems:           ba.metrics.FailedItems,
		AverageBatchSize:      ba.metrics.AverageBatchSize,
		AverageProcessingTime: ba.metrics.AverageProcessingTime,
		TotalProcessingTime:   ba.metrics.TotalProcessingTime,
		Throughput:            ba.metrics.Throughput,
		QueueSizes:            make(map[string]int),
		AverageQueueTime:      ba.metrics.AverageQueueTime,
		TotalRetries:          ba.metrics.TotalRetries,
		AverageRetries:        ba.metrics.AverageRetries,
	}
}

// generateBatchID generates a unique batch ID
func generateBatchID() string {
	return fmt.Sprintf("batch_%d", time.Now().UnixNano())
}