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
	"sync/atomic"
	"time"
)

// start starts the pin worker
func (pw *PinWorker) start() {
	pw.wg.Add(1)
	go pw.run()
}

// stop stops the pin worker
func (pw *PinWorker) stop() {
	pw.cancel()
	pw.wg.Wait()
}

// run is the main worker loop for processing pin requests
func (pw *PinWorker) run() {
	defer pw.wg.Done()
	
	pw.logger.Printf("Pin worker %d started", pw.id)
	
	for {
		select {
		case <-pw.ctx.Done():
			pw.logger.Printf("Pin worker %d stopping", pw.id)
			return
			
		case request, ok := <-pw.requestChan:
			if !ok {
				pw.logger.Printf("Pin worker %d: request channel closed", pw.id)
				return
			}
			
			pw.processRequest(request)
		}
	}
}

// processRequest processes a single pin request
func (pw *PinWorker) processRequest(request *PinRequest) {
	start := time.Now()
	pw.lastActivity = start
	atomic.AddInt64(&pw.processedCount, 1)
	
	pw.logger.Printf("Pin worker %d processing request: ID=%s, CID=%s, Priority=%s", 
		pw.id, request.ID, request.CID, request.Priority.String())
	
	// Create timeout context for the pin operation
	ctx, cancel := context.WithTimeout(request.Context, pw.manager.config.PinTimeout)
	defer cancel()
	
	// Perform the pin operation
	result := pw.performPin(ctx, request)
	result.Duration = time.Since(start)
	result.RequestID = request.ID
	result.CID = request.CID
	result.Timestamp = time.Now()
	result.RetryCount = request.RetryCount
	
	// Update metrics
	if result.Success {
		atomic.AddInt64(&pw.manager.metrics.SuccessfulPins, 1)
		pw.logger.Printf("Pin worker %d: successful pin for CID=%s (duration=%v)", 
			pw.id, request.CID, result.Duration)
	} else {
		atomic.AddInt64(&pw.manager.metrics.FailedPins, 1)
		atomic.AddInt64(&pw.errorCount, 1)
		pw.logger.Printf("Pin worker %d: failed pin for CID=%s (error=%v, duration=%v)", 
			pw.id, request.CID, result.Error, result.Duration)
		
		// Schedule retry if applicable
		if pw.shouldRetry(request, result.Error) {
			pw.scheduleRetry(request, result.Error)
		}
	}
	
	// Send result if there's a result channel
	if request.ResultChan != nil {
		select {
		case request.ResultChan <- result:
		case <-time.After(1 * time.Second):
			pw.logger.Printf("Pin worker %d: timeout sending result for request %s", pw.id, request.ID)
		}
	}
}

// performPin performs the actual pin operation
func (pw *PinWorker) performPin(ctx context.Context, request *PinRequest) *PinResult {
	result := &PinResult{
		Success: false,
	}
	
	// Update metadata store to mark pin as pending
	mapping := &ObjectMapping{
		Bucket:           request.Bucket,
		S3Key:            request.S3Key,
		CID:              request.CID,
		Size:             request.Size,
		PinStatus:        PinStatusPending,
		ReplicationCount: 0,
		PinnedNodes:      []string{},
		UpdatedAt:        time.Now(),
	}
	
	if err := pw.metadataStore.UpdateMapping(ctx, mapping); err != nil {
		result.Error = fmt.Errorf("failed to update metadata for pending pin: %w", err)
		return result
	}
	
	// Perform the actual pin operation via cluster client
	pinResult, err := pw.performClusterPin(ctx, request)
	if err != nil {
		result.Error = err
		
		// Update metadata store to mark pin as failed
		mapping.PinStatus = PinStatusFailed
		mapping.UpdatedAt = time.Now()
		if updateErr := pw.metadataStore.UpdateMapping(ctx, mapping); updateErr != nil {
			pw.logger.Printf("Pin worker %d: failed to update metadata for failed pin: %v", pw.id, updateErr)
		}
		
		return result
	}
	
	// Update metadata store with successful pin information
	mapping.PinStatus = PinStatusPinned
	mapping.ReplicationCount = len(pinResult.NodesUsed)
	mapping.PinnedNodes = pinResult.NodesUsed
	mapping.UpdatedAt = time.Now()
	
	if err := pw.metadataStore.UpdateMapping(ctx, mapping); err != nil {
		result.Error = fmt.Errorf("failed to update metadata for successful pin: %w", err)
		return result
	}
	
	result.Success = true
	result.NodesUsed = pinResult.NodesUsed
	
	return result
}

// performClusterPin performs the pin operation via the cluster client
func (pw *PinWorker) performClusterPin(ctx context.Context, request *PinRequest) (*ClusterPinResult, error) {
	// Call the actual cluster client
	return pw.clusterClient.Pin(ctx, request.CID, request.ReplicationFactor)
}

// shouldRetry determines if a failed pin request should be retried
func (pw *PinWorker) shouldRetry(request *PinRequest, err error) bool {
	if request.RetryCount >= pw.manager.config.MaxRetries {
		return false
	}
	
	// Don't retry context cancellation errors
	if err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}
	
	// Retry other errors
	return true
}

// scheduleRetry schedules a retry for a failed pin request
func (pw *PinWorker) scheduleRetry(request *PinRequest, err error) {
	request.RetryCount++
	request.LastError = err
	
	// Calculate retry delay with exponential backoff
	delay := pw.calculateRetryDelay(request.RetryCount)
	request.NextRetry = time.Now().Add(delay)
	
	// Create retry request
	retryReq := &RetryRequest{
		Type:        RetryTypePin,
		PinReq:      request,
		ScheduledAt: request.NextRetry,
	}
	
	// Submit to retry queue
	select {
	case pw.manager.retryQueue <- retryReq:
		atomic.AddInt64(&pw.manager.metrics.TotalRetries, 1)
		pw.logger.Printf("Pin worker %d: scheduled retry %d for request %s (delay=%v)", 
			pw.id, request.RetryCount, request.ID, delay)
	case <-pw.ctx.Done():
		// Manager is shutting down, don't retry
		pw.logger.Printf("Pin worker %d: manager shutting down, dropping retry for request %s", 
			pw.id, request.ID)
	default:
		atomic.AddInt64(&pw.manager.metrics.MaxRetryReached, 1)
		pw.logger.Printf("Pin worker %d: retry queue full, dropping retry for request %s", 
			pw.id, request.ID)
	}
}

// calculateRetryDelay calculates the delay for a retry attempt
func (pw *PinWorker) calculateRetryDelay(retryCount int) time.Duration {
	delay := pw.manager.config.InitialRetryDelay
	
	// Apply exponential backoff
	for i := 1; i < retryCount; i++ {
		delay = time.Duration(float64(delay) * pw.manager.config.RetryBackoffFactor)
		if delay > pw.manager.config.MaxRetryDelay {
			delay = pw.manager.config.MaxRetryDelay
			break
		}
	}
	
	return delay
}

// start starts the unpin worker
func (uw *UnpinWorker) start() {
	uw.wg.Add(1)
	go uw.run()
}

// stop stops the unpin worker
func (uw *UnpinWorker) stop() {
	uw.cancel()
	uw.wg.Wait()
}

// run is the main worker loop for processing unpin requests
func (uw *UnpinWorker) run() {
	defer uw.wg.Done()
	
	uw.logger.Printf("Unpin worker %d started", uw.id)
	
	for {
		select {
		case <-uw.ctx.Done():
			uw.logger.Printf("Unpin worker %d stopping", uw.id)
			return
			
		case request, ok := <-uw.requestChan:
			if !ok {
				uw.logger.Printf("Unpin worker %d: request channel closed", uw.id)
				return
			}
			
			uw.processRequest(request)
		}
	}
}

// processRequest processes a single unpin request
func (uw *UnpinWorker) processRequest(request *UnpinRequest) {
	start := time.Now()
	uw.lastActivity = start
	atomic.AddInt64(&uw.processedCount, 1)
	
	uw.logger.Printf("Unpin worker %d processing request: ID=%s, CID=%s, Priority=%s", 
		uw.id, request.ID, request.CID, request.Priority.String())
	
	// Create timeout context for the unpin operation
	ctx, cancel := context.WithTimeout(request.Context, uw.manager.config.UnpinTimeout)
	defer cancel()
	
	// Perform the unpin operation
	result := uw.performUnpin(ctx, request)
	result.Duration = time.Since(start)
	result.RequestID = request.ID
	result.CID = request.CID
	result.Timestamp = time.Now()
	result.RetryCount = request.RetryCount
	
	// Update metrics
	if result.Success {
		atomic.AddInt64(&uw.manager.metrics.SuccessfulUnpins, 1)
		uw.logger.Printf("Unpin worker %d: successful unpin for CID=%s (duration=%v)", 
			uw.id, request.CID, result.Duration)
	} else {
		atomic.AddInt64(&uw.manager.metrics.FailedUnpins, 1)
		atomic.AddInt64(&uw.errorCount, 1)
		uw.logger.Printf("Unpin worker %d: failed unpin for CID=%s (error=%v, duration=%v)", 
			uw.id, request.CID, result.Error, result.Duration)
		
		// Schedule retry if applicable
		if uw.shouldRetry(request, result.Error) {
			uw.scheduleRetry(request, result.Error)
		}
	}
	
	// Send result if there's a result channel
	if request.ResultChan != nil {
		select {
		case request.ResultChan <- result:
		case <-time.After(1 * time.Second):
			uw.logger.Printf("Unpin worker %d: timeout sending result for request %s", uw.id, request.ID)
		}
	}
}

// performUnpin performs the actual unpin operation
func (uw *UnpinWorker) performUnpin(ctx context.Context, request *UnpinRequest) *UnpinResult {
	result := &UnpinResult{
		Success: false,
	}
	
	// Get current mapping to check pin status
	mapping, err := uw.metadataStore.GetMapping(ctx, request.S3Key, request.Bucket)
	if err != nil {
		result.Error = fmt.Errorf("failed to get object mapping: %w", err)
		return result
	}
	
	if mapping == nil {
		result.Error = fmt.Errorf("object mapping not found")
		return result
	}
	
	// Update metadata store to mark unpin as in progress
	mapping.PinStatus = PinStatusUnpinning
	mapping.UpdatedAt = time.Now()
	
	if err := uw.metadataStore.UpdateMapping(ctx, mapping); err != nil {
		result.Error = fmt.Errorf("failed to update metadata for unpinning: %w", err)
		return result
	}
	
	// Perform the actual unpin operation via cluster client
	unpinResult, err := uw.performClusterUnpin(ctx, request)
	if err != nil {
		result.Error = err
		
		// Revert metadata store status on failure
		mapping.PinStatus = PinStatusPinned // Assume it was pinned before
		mapping.UpdatedAt = time.Now()
		if updateErr := uw.metadataStore.UpdateMapping(ctx, mapping); updateErr != nil {
			uw.logger.Printf("Unpin worker %d: failed to revert metadata for failed unpin: %v", uw.id, updateErr)
		}
		
		return result
	}
	
	// Update metadata store with successful unpin information
	mapping.PinStatus = PinStatusUnpinned
	mapping.ReplicationCount = 0
	mapping.PinnedNodes = []string{}
	mapping.UpdatedAt = time.Now()
	
	if err := uw.metadataStore.UpdateMapping(ctx, mapping); err != nil {
		result.Error = fmt.Errorf("failed to update metadata for successful unpin: %w", err)
		return result
	}
	
	result.Success = true
	result.NodesUsed = unpinResult.NodesUsed
	
	return result
}

// performClusterUnpin performs the unpin operation via the cluster client
func (uw *UnpinWorker) performClusterUnpin(ctx context.Context, request *UnpinRequest) (*ClusterUnpinResult, error) {
	// Call the actual cluster client
	return uw.clusterClient.Unpin(ctx, request.CID)
}

// shouldRetry determines if a failed unpin request should be retried
func (uw *UnpinWorker) shouldRetry(request *UnpinRequest, err error) bool {
	if request.RetryCount >= uw.manager.config.MaxRetries {
		return false
	}
	
	// Don't retry context cancellation errors
	if err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}
	
	// Retry other errors
	return true
}

// scheduleRetry schedules a retry for a failed unpin request
func (uw *UnpinWorker) scheduleRetry(request *UnpinRequest, err error) {
	request.RetryCount++
	request.LastError = err
	
	// Calculate retry delay with exponential backoff
	delay := uw.calculateRetryDelay(request.RetryCount)
	request.NextRetry = time.Now().Add(delay)
	
	// Create retry request
	retryReq := &RetryRequest{
		Type:        RetryTypeUnpin,
		UnpinReq:    request,
		ScheduledAt: request.NextRetry,
	}
	
	// Submit to retry queue
	select {
	case uw.manager.retryQueue <- retryReq:
		atomic.AddInt64(&uw.manager.metrics.TotalRetries, 1)
		uw.logger.Printf("Unpin worker %d: scheduled retry %d for request %s (delay=%v)", 
			uw.id, request.RetryCount, request.ID, delay)
	case <-uw.ctx.Done():
		// Manager is shutting down, don't retry
		uw.logger.Printf("Unpin worker %d: manager shutting down, dropping retry for request %s", 
			uw.id, request.ID)
	default:
		atomic.AddInt64(&uw.manager.metrics.MaxRetryReached, 1)
		uw.logger.Printf("Unpin worker %d: retry queue full, dropping retry for request %s", 
			uw.id, request.ID)
	}
}

// calculateRetryDelay calculates the delay for a retry attempt
func (uw *UnpinWorker) calculateRetryDelay(retryCount int) time.Duration {
	delay := uw.manager.config.InitialRetryDelay
	
	// Apply exponential backoff
	for i := 1; i < retryCount; i++ {
		delay = time.Duration(float64(delay) * uw.manager.config.RetryBackoffFactor)
		if delay > uw.manager.config.MaxRetryDelay {
			delay = uw.manager.config.MaxRetryDelay
			break
		}
	}
	
	return delay
}

// start starts the retry worker
func (rw *RetryWorker) start() {
	rw.wg.Add(1)
	go rw.run()
}

// stop stops the retry worker
func (rw *RetryWorker) stop() {
	rw.cancel()
	rw.wg.Wait()
}

// run is the main worker loop for processing retry requests
func (rw *RetryWorker) run() {
	defer rw.wg.Done()
	
	rw.logger.Println("Retry worker started")
	
	for {
		select {
		case <-rw.ctx.Done():
			rw.logger.Println("Retry worker stopping")
			return
			
		case request, ok := <-rw.requestChan:
			if !ok {
				rw.logger.Println("Retry worker: request channel closed")
				return
			}
			
			rw.processRetryRequest(request)
		}
	}
}

// processRetryRequest processes a retry request
func (rw *RetryWorker) processRetryRequest(request *RetryRequest) {
	atomic.AddInt64(&rw.processedCount, 1)
	
	// Wait until the scheduled time
	now := time.Now()
	if request.ScheduledAt.After(now) {
		delay := request.ScheduledAt.Sub(now)
		rw.logger.Printf("Retry worker: waiting %v before retrying", delay)
		
		select {
		case <-time.After(delay):
			// Continue with retry
		case <-rw.ctx.Done():
			return
		}
	}
	
	// Process the retry based on type
	switch request.Type {
	case RetryTypePin:
		if request.PinReq != nil {
			rw.logger.Printf("Retry worker: retrying pin request %s (attempt %d)", 
				request.PinReq.ID, request.PinReq.RetryCount)
			
			// Resubmit to pin queue
			select {
			case rw.manager.pinQueue <- request.PinReq:
				rw.logger.Printf("Retry worker: resubmitted pin request %s", request.PinReq.ID)
			case <-rw.ctx.Done():
				return
			default:
				atomic.AddInt64(&rw.errorCount, 1)
				rw.logger.Printf("Retry worker: failed to resubmit pin request %s (queue full)", request.PinReq.ID)
			}
		}
		
	case RetryTypeUnpin:
		if request.UnpinReq != nil {
			rw.logger.Printf("Retry worker: retrying unpin request %s (attempt %d)", 
				request.UnpinReq.ID, request.UnpinReq.RetryCount)
			
			// Resubmit to unpin queue
			select {
			case rw.manager.unpinQueue <- request.UnpinReq:
				rw.logger.Printf("Retry worker: resubmitted unpin request %s", request.UnpinReq.ID)
			case <-rw.ctx.Done():
				return
			default:
				atomic.AddInt64(&rw.errorCount, 1)
				rw.logger.Printf("Retry worker: failed to resubmit unpin request %s (queue full)", request.UnpinReq.ID)
			}
		}
	}
}

// Supporting types for cluster operations

// ClusterPinResult represents the result of a cluster pin operation
type ClusterPinResult struct {
	CID       string   `json:"cid"`
	NodesUsed []string `json:"nodes_used"`
}

// ClusterUnpinResult represents the result of a cluster unpin operation
type ClusterUnpinResult struct {
	CID       string   `json:"cid"`
	NodesUsed []string `json:"nodes_used"`
}