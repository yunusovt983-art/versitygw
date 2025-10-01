package ipfs

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ReplicationRebalancer handles automatic rebalancing of pins when load changes
type ReplicationRebalancer struct {
	clusterClient ClusterClientInterface
	config        *ReplicaConfig
	
	// Rebalancing queues
	pendingTasks  []*RebalanceTask
	activeTasks   map[string]*RebalanceTask
	taskMutex     sync.RWMutex
	
	// Worker management
	workers       []*RebalanceWorker
	workerPool    chan *RebalanceWorker
	
	// Metrics and monitoring
	metrics       *RebalanceMetrics
	
	// Shutdown coordination
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

// RebalanceTask represents a rebalancing operation
type RebalanceTask struct {
	ID                  string                `json:"id"`
	CID                 string                `json:"cid"`
	CurrentReplicas     int                   `json:"current_replicas"`
	TargetReplicas      int                   `json:"target_replicas"`
	CurrentDistribution map[string]int        `json:"current_distribution"`
	TargetDistribution  map[string]int        `json:"target_distribution"`
	Priority            RebalancePriority     `json:"priority"`
	Status              RebalanceStatus       `json:"status"`
	ScheduledAt         time.Time             `json:"scheduled_at"`
	StartedAt           time.Time             `json:"started_at"`
	CompletedAt         time.Time             `json:"completed_at"`
	Error               string                `json:"error,omitempty"`
	Progress            *RebalanceProgress    `json:"progress"`
}

// RebalancePriority defines the priority of rebalancing tasks
type RebalancePriority int

const (
	PriorityLow RebalancePriority = iota
	PriorityMedium
	PriorityHigh
	PriorityCritical
)

// RebalanceStatus defines the status of a rebalancing task
type RebalanceStatus int

const (
	StatusPending RebalanceStatus = iota
	StatusRunning
	StatusCompleted
	StatusFailed
	StatusCancelled
)

// RebalanceProgress tracks the progress of a rebalancing operation
type RebalanceProgress struct {
	Phase           RebalancePhase `json:"phase"`
	TotalSteps      int            `json:"total_steps"`
	CompletedSteps  int            `json:"completed_steps"`
	CurrentStep     string         `json:"current_step"`
	EstimatedTimeRemaining time.Duration `json:"estimated_time_remaining"`
}

// RebalancePhase defines the current phase of rebalancing
type RebalancePhase int

const (
	PhaseAnalysis RebalancePhase = iota
	PhaseAddingReplicas
	PhaseRemovingReplicas
	PhaseVerification
	PhaseCompleted
)

// RebalanceWorker handles individual rebalancing tasks
type RebalanceWorker struct {
	id            int
	rebalancer    *ReplicationRebalancer
	clusterClient ClusterClientInterface
	currentTask   *RebalanceTask
	taskChan      chan *RebalanceTask
	stopChan      chan struct{}
}

// RebalanceMetrics tracks rebalancing performance metrics
type RebalanceMetrics struct {
	TotalTasks        int64         `json:"total_tasks"`
	CompletedTasks    int64         `json:"completed_tasks"`
	FailedTasks       int64         `json:"failed_tasks"`
	AverageTime       time.Duration `json:"average_time"`
	TotalDataMoved    int64         `json:"total_data_moved"`
	ActiveWorkers     int           `json:"active_workers"`
	QueueLength       int           `json:"queue_length"`
	
	// Performance by priority
	HighPriorityTime  time.Duration `json:"high_priority_time"`
	MediumPriorityTime time.Duration `json:"medium_priority_time"`
	LowPriorityTime   time.Duration `json:"low_priority_time"`
	
	mutex sync.RWMutex
}

// NewReplicationRebalancer creates a new replication rebalancer
func NewReplicationRebalancer(clusterClient ClusterClientInterface, config *ReplicaConfig) *ReplicationRebalancer {
	ctx, cancel := context.WithCancel(context.Background())
	
	rb := &ReplicationRebalancer{
		clusterClient: clusterClient,
		config:        config,
		pendingTasks:  make([]*RebalanceTask, 0),
		activeTasks:   make(map[string]*RebalanceTask),
		workerPool:    make(chan *RebalanceWorker, config.MaxConcurrentRebalance),
		metrics:       &RebalanceMetrics{},
		ctx:           ctx,
		cancel:        cancel,
	}
	
	// Initialize workers
	rb.initializeWorkers()
	
	return rb
}

// initializeWorkers creates and starts rebalancing workers
func (rb *ReplicationRebalancer) initializeWorkers() {
	rb.workers = make([]*RebalanceWorker, rb.config.MaxConcurrentRebalance)
	
	for i := 0; i < rb.config.MaxConcurrentRebalance; i++ {
		worker := &RebalanceWorker{
			id:            i,
			rebalancer:    rb,
			clusterClient: rb.clusterClient,
			taskChan:      make(chan *RebalanceTask, 1),
			stopChan:      make(chan struct{}),
		}
		
		rb.workers[i] = worker
		rb.workerPool <- worker
		
		// Start worker goroutine
		rb.wg.Add(1)
		go func(w *RebalanceWorker) {
			defer rb.wg.Done()
			w.run()
		}(worker)
	}
}

// ScheduleRebalance schedules a new rebalancing task
func (rb *ReplicationRebalancer) ScheduleRebalance(task *RebalanceTask) error {
	rb.taskMutex.Lock()
	defer rb.taskMutex.Unlock()
	
	// Generate task ID if not provided
	if task.ID == "" {
		task.ID = fmt.Sprintf("rebalance-%s-%d", task.CID, time.Now().UnixNano())
	}
	
	// Set initial status
	task.Status = StatusPending
	task.Progress = &RebalanceProgress{
		Phase:      PhaseAnalysis,
		TotalSteps: rb.calculateTotalSteps(task),
	}
	
	// Add to pending tasks
	rb.pendingTasks = append(rb.pendingTasks, task)
	
	// Sort by priority
	rb.sortPendingTasks()
	
	// Update metrics
	rb.metrics.mutex.Lock()
	rb.metrics.TotalTasks++
	rb.metrics.QueueLength = len(rb.pendingTasks)
	rb.metrics.mutex.Unlock()
	
	return nil
}

// ProcessPendingRebalances processes pending rebalancing tasks
func (rb *ReplicationRebalancer) ProcessPendingRebalances(maxConcurrent int) error {
	rb.taskMutex.Lock()
	defer rb.taskMutex.Unlock()
	
	// Process tasks up to the concurrency limit
	processed := 0
	for len(rb.pendingTasks) > 0 && processed < maxConcurrent {
		// Get next task
		task := rb.pendingTasks[0]
		rb.pendingTasks = rb.pendingTasks[1:]
		
		// Try to get a worker
		select {
		case worker := <-rb.workerPool:
			// Assign task to worker
			rb.activeTasks[task.ID] = task
			task.Status = StatusRunning
			task.StartedAt = time.Now()
			
			// Send task to worker
			select {
			case worker.taskChan <- task:
				processed++
			default:
				// Worker channel full, put task back
				rb.pendingTasks = append([]*RebalanceTask{task}, rb.pendingTasks...)
				rb.workerPool <- worker
				break
			}
		default:
			// No workers available
			break
		}
	}
	
	// Update metrics
	rb.metrics.mutex.Lock()
	rb.metrics.QueueLength = len(rb.pendingTasks)
	rb.metrics.ActiveWorkers = len(rb.activeTasks)
	rb.metrics.mutex.Unlock()
	
	return nil
}

// sortPendingTasks sorts pending tasks by priority and age
func (rb *ReplicationRebalancer) sortPendingTasks() {
	sort.Slice(rb.pendingTasks, func(i, j int) bool {
		taskI := rb.pendingTasks[i]
		taskJ := rb.pendingTasks[j]
		
		// First sort by priority
		if taskI.Priority != taskJ.Priority {
			return taskI.Priority > taskJ.Priority
		}
		
		// Then by age (older tasks first)
		return taskI.ScheduledAt.Before(taskJ.ScheduledAt)
	})
}

// calculateTotalSteps calculates the total number of steps for a rebalancing task
func (rb *ReplicationRebalancer) calculateTotalSteps(task *RebalanceTask) int {
	steps := 1 // Analysis phase
	
	// Add steps for adding replicas
	if task.TargetReplicas > task.CurrentReplicas {
		steps += task.TargetReplicas - task.CurrentReplicas
	}
	
	// Add steps for removing replicas
	if task.CurrentReplicas > task.TargetReplicas {
		steps += task.CurrentReplicas - task.TargetReplicas
	}
	
	// Add steps for geographic redistribution
	for region, targetCount := range task.TargetDistribution {
		currentCount := task.CurrentDistribution[region]
		if targetCount != currentCount {
			steps++
		}
	}
	
	steps++ // Verification phase
	
	return steps
}

// run executes the worker's main loop
func (w *RebalanceWorker) run() {
	for {
		select {
		case <-w.stopChan:
			return
		case task := <-w.taskChan:
			w.currentTask = task
			w.executeTask(task)
			w.currentTask = nil
			
			// Return worker to pool
			w.rebalancer.workerPool <- w
		}
	}
}

// executeTask executes a rebalancing task
func (w *RebalanceWorker) executeTask(task *RebalanceTask) {
	defer func() {
		// Clean up task from active tasks
		w.rebalancer.taskMutex.Lock()
		delete(w.rebalancer.activeTasks, task.ID)
		w.rebalancer.taskMutex.Unlock()
		
		// Update completion time
		task.CompletedAt = time.Now()
		
		// Update metrics
		w.rebalancer.updateTaskMetrics(task)
	}()
	
	// Phase 1: Analysis
	err := w.executeAnalysisPhase(task)
	if err != nil {
		w.failTask(task, fmt.Sprintf("Analysis phase failed: %v", err))
		return
	}
	
	// Phase 2: Add replicas if needed
	if task.TargetReplicas > task.CurrentReplicas {
		err = w.executeAddReplicasPhase(task)
		if err != nil {
			w.failTask(task, fmt.Sprintf("Add replicas phase failed: %v", err))
			return
		}
	}
	
	// Phase 3: Remove replicas if needed
	if task.CurrentReplicas > task.TargetReplicas {
		err = w.executeRemoveReplicasPhase(task)
		if err != nil {
			w.failTask(task, fmt.Sprintf("Remove replicas phase failed: %v", err))
			return
		}
	}
	
	// Phase 4: Redistribute geographically
	err = w.executeRedistributionPhase(task)
	if err != nil {
		w.failTask(task, fmt.Sprintf("Redistribution phase failed: %v", err))
		return
	}
	
	// Phase 5: Verification
	err = w.executeVerificationPhase(task)
	if err != nil {
		w.failTask(task, fmt.Sprintf("Verification phase failed: %v", err))
		return
	}
	
	// Mark task as completed
	task.Status = StatusCompleted
	task.Progress.Phase = PhaseCompleted
	task.Progress.CompletedSteps = task.Progress.TotalSteps
}

// executeAnalysisPhase analyzes the current state and plans the rebalancing
func (w *RebalanceWorker) executeAnalysisPhase(task *RebalanceTask) error {
	task.Progress.Phase = PhaseAnalysis
	task.Progress.CurrentStep = "Analyzing current pin distribution"
	
	// Get current pin status from cluster
	pinStatus, err := w.clusterClient.GetPinStatus(task.CID)
	if err != nil {
		return fmt.Errorf("failed to get pin status: %w", err)
	}
	
	// Update current state based on actual cluster state
	task.CurrentReplicas = len(pinStatus.PeerMap)
	
	// Analyze current geographic distribution
	currentDistribution := make(map[string]int)
	for peerID := range pinStatus.PeerMap {
		// Get peer location (this would need to be implemented)
		region := w.getPeerRegion(peerID)
		currentDistribution[region]++
	}
	task.CurrentDistribution = currentDistribution
	
	task.Progress.CompletedSteps++
	return nil
}

// executeAddReplicasPhase adds additional replicas
func (w *RebalanceWorker) executeAddReplicasPhase(task *RebalanceTask) error {
	task.Progress.Phase = PhaseAddingReplicas
	
	replicasToAdd := task.TargetReplicas - task.CurrentReplicas
	
	for i := 0; i < replicasToAdd; i++ {
		task.Progress.CurrentStep = fmt.Sprintf("Adding replica %d of %d", i+1, replicasToAdd)
		
		// Find optimal node for new replica
		optimalNode, err := w.findOptimalNodeForReplica(task)
		if err != nil {
			return fmt.Errorf("failed to find optimal node: %w", err)
		}
		
		// Add pin to the selected node
		err = w.clusterClient.PinAdd(task.CID, cluster.PinOptions{
			ReplicationFactorMin: 1,
			ReplicationFactorMax: 1,
			Name:                 fmt.Sprintf("rebalance-%s", task.ID),
			UserAllocations:      []string{optimalNode},
		})
		if err != nil {
			return fmt.Errorf("failed to add pin to node %s: %w", optimalNode, err)
		}
		
		task.Progress.CompletedSteps++
		
		// Small delay to avoid overwhelming the cluster
		time.Sleep(100 * time.Millisecond)
	}
	
	return nil
}

// executeRemoveReplicasPhase removes excess replicas
func (w *RebalanceWorker) executeRemoveReplicasPhase(task *RebalanceTask) error {
	task.Progress.Phase = PhaseRemovingReplicas
	
	replicasToRemove := task.CurrentReplicas - task.TargetReplicas
	
	// Get current pin status to identify which replicas to remove
	pinStatus, err := w.clusterClient.GetPinStatus(task.CID)
	if err != nil {
		return fmt.Errorf("failed to get pin status: %w", err)
	}
	
	// Select replicas to remove (prefer nodes with high load or poor performance)
	nodesToRemove := w.selectNodesToRemove(pinStatus, replicasToRemove)
	
	for i, nodeID := range nodesToRemove {
		task.Progress.CurrentStep = fmt.Sprintf("Removing replica %d of %d from node %s", i+1, replicasToRemove, nodeID)
		
		// Remove pin from the selected node
		err = w.clusterClient.UnpinFromNode(task.CID, nodeID)
		if err != nil {
			return fmt.Errorf("failed to remove pin from node %s: %w", nodeID, err)
		}
		
		task.Progress.CompletedSteps++
		
		// Small delay to avoid overwhelming the cluster
		time.Sleep(100 * time.Millisecond)
	}
	
	return nil
}

// executeRedistributionPhase redistributes replicas geographically
func (w *RebalanceWorker) executeRedistributionPhase(task *RebalanceTask) error {
	// Get current distribution
	pinStatus, err := w.clusterClient.GetPinStatus(task.CID)
	if err != nil {
		return fmt.Errorf("failed to get pin status: %w", err)
	}
	
	currentDistribution := make(map[string][]string)
	for peerID := range pinStatus.PeerMap {
		region := w.getPeerRegion(peerID)
		currentDistribution[region] = append(currentDistribution[region], peerID)
	}
	
	// Plan redistribution moves
	moves := w.planRedistributionMoves(currentDistribution, task.TargetDistribution)
	
	// Execute moves
	for i, move := range moves {
		task.Progress.CurrentStep = fmt.Sprintf("Redistributing replica %d of %d", i+1, len(moves))
		
		// Remove from source
		err = w.clusterClient.UnpinFromNode(task.CID, move.SourceNode)
		if err != nil {
			return fmt.Errorf("failed to remove pin from source node %s: %w", move.SourceNode, err)
		}
		
		// Add to destination
		err = w.clusterClient.PinAdd(task.CID, cluster.PinOptions{
			ReplicationFactorMin: 1,
			ReplicationFactorMax: 1,
			Name:                 fmt.Sprintf("rebalance-%s", task.ID),
			UserAllocations:      []string{move.DestinationNode},
		})
		if err != nil {
			return fmt.Errorf("failed to add pin to destination node %s: %w", move.DestinationNode, err)
		}
		
		task.Progress.CompletedSteps++
		
		// Delay between moves
		time.Sleep(200 * time.Millisecond)
	}
	
	return nil
}

// executeVerificationPhase verifies that the rebalancing was successful
func (w *RebalanceWorker) executeVerificationPhase(task *RebalanceTask) error {
	task.Progress.Phase = PhaseVerification
	task.Progress.CurrentStep = "Verifying final pin distribution"
	
	// Wait a bit for the cluster to stabilize
	time.Sleep(2 * time.Second)
	
	// Get final pin status
	pinStatus, err := w.clusterClient.GetPinStatus(task.CID)
	if err != nil {
		return fmt.Errorf("failed to get final pin status: %w", err)
	}
	
	// Verify replica count
	actualReplicas := len(pinStatus.PeerMap)
	if actualReplicas != task.TargetReplicas {
		return fmt.Errorf("replica count mismatch: expected %d, got %d", task.TargetReplicas, actualReplicas)
	}
	
	// Verify geographic distribution
	actualDistribution := make(map[string]int)
	for peerID := range pinStatus.PeerMap {
		region := w.getPeerRegion(peerID)
		actualDistribution[region]++
	}
	
	for region, expectedCount := range task.TargetDistribution {
		actualCount := actualDistribution[region]
		if actualCount != expectedCount {
			return fmt.Errorf("distribution mismatch in region %s: expected %d, got %d", region, expectedCount, actualCount)
		}
	}
	
	task.Progress.CompletedSteps++
	return nil
}

// Helper methods

func (w *RebalanceWorker) failTask(task *RebalanceTask, errorMsg string) {
	task.Status = StatusFailed
	task.Error = errorMsg
}

func (w *RebalanceWorker) getPeerRegion(peerID string) string {
	// This would need to be implemented to get the region of a peer
	// For now, return a default region
	return "unknown"
}

func (w *RebalanceWorker) findOptimalNodeForReplica(task *RebalanceTask) (string, error) {
	// This would implement logic to find the best node for a new replica
	// considering current distribution, node capacity, and performance
	return "optimal-node-id", nil
}

func (w *RebalanceWorker) selectNodesToRemove(pinStatus *cluster.PinStatus, count int) []string {
	// This would implement logic to select which nodes to remove replicas from
	// considering node performance, load, and geographic distribution
	nodes := make([]string, 0, count)
	i := 0
	for peerID := range pinStatus.PeerMap {
		if i >= count {
			break
		}
		nodes = append(nodes, peerID)
		i++
	}
	return nodes
}

type RedistributionMove struct {
	SourceNode      string
	DestinationNode string
	SourceRegion    string
	DestinationRegion string
}

func (w *RebalanceWorker) planRedistributionMoves(current map[string][]string, target map[string]int) []RedistributionMove {
	moves := make([]RedistributionMove, 0)
	
	// Simple redistribution logic - this would be more sophisticated in practice
	for region, targetCount := range target {
		currentCount := len(current[region])
		if currentCount > targetCount {
			// Need to move replicas out of this region
			excess := currentCount - targetCount
			for i := 0; i < excess; i++ {
				if len(current[region]) > 0 {
					sourceNode := current[region][0]
					current[region] = current[region][1:]
					
					// Find destination region that needs more replicas
					for destRegion, destTarget := range target {
						if len(current[destRegion]) < destTarget {
							moves = append(moves, RedistributionMove{
								SourceNode:        sourceNode,
								DestinationNode:   "dest-node", // Would be determined by optimal placement
								SourceRegion:      region,
								DestinationRegion: destRegion,
							})
							break
						}
					}
				}
			}
		}
	}
	
	return moves
}

func (rb *ReplicationRebalancer) updateTaskMetrics(task *RebalanceTask) {
	rb.metrics.mutex.Lock()
	defer rb.metrics.mutex.Unlock()
	
	if task.Status == StatusCompleted {
		rb.metrics.CompletedTasks++
		
		// Update average time
		duration := task.CompletedAt.Sub(task.StartedAt)
		if rb.metrics.CompletedTasks == 1 {
			rb.metrics.AverageTime = duration
		} else {
			// Running average
			rb.metrics.AverageTime = (rb.metrics.AverageTime*time.Duration(rb.metrics.CompletedTasks-1) + duration) / time.Duration(rb.metrics.CompletedTasks)
		}
		
		// Update priority-specific metrics
		switch task.Priority {
		case PriorityHigh, PriorityCritical:
			rb.metrics.HighPriorityTime = (rb.metrics.HighPriorityTime + duration) / 2
		case PriorityMedium:
			rb.metrics.MediumPriorityTime = (rb.metrics.MediumPriorityTime + duration) / 2
		case PriorityLow:
			rb.metrics.LowPriorityTime = (rb.metrics.LowPriorityTime + duration) / 2
		}
	} else if task.Status == StatusFailed {
		rb.metrics.FailedTasks++
	}
}

// GetMetrics returns current rebalancing metrics
func (rb *ReplicationRebalancer) GetMetrics() *RebalanceMetrics {
	rb.metrics.mutex.RLock()
	defer rb.metrics.mutex.RUnlock()
	
	// Return a copy
	metrics := *rb.metrics
	return &metrics
}

// GetTaskStatus returns the status of a specific task
func (rb *ReplicationRebalancer) GetTaskStatus(taskID string) (*RebalanceTask, error) {
	rb.taskMutex.RLock()
	defer rb.taskMutex.RUnlock()
	
	if task, exists := rb.activeTasks[taskID]; exists {
		// Return a copy
		taskCopy := *task
		return &taskCopy, nil
	}
	
	// Check pending tasks
	for _, task := range rb.pendingTasks {
		if task.ID == taskID {
			taskCopy := *task
			return &taskCopy, nil
		}
	}
	
	return nil, fmt.Errorf("task not found: %s", taskID)
}

// CancelTask cancels a pending or running task
func (rb *ReplicationRebalancer) CancelTask(taskID string) error {
	rb.taskMutex.Lock()
	defer rb.taskMutex.Unlock()
	
	// Check active tasks
	if task, exists := rb.activeTasks[taskID]; exists {
		task.Status = StatusCancelled
		// Note: This is a simplified cancellation - in practice, you'd need to
		// signal the worker to stop and clean up any partial changes
		return nil
	}
	
	// Check pending tasks
	for i, task := range rb.pendingTasks {
		if task.ID == taskID {
			task.Status = StatusCancelled
			// Remove from pending queue
			rb.pendingTasks = append(rb.pendingTasks[:i], rb.pendingTasks[i+1:]...)
			return nil
		}
	}
	
	return fmt.Errorf("task not found: %s", taskID)
}

// Shutdown gracefully shuts down the rebalancer
func (rb *ReplicationRebalancer) Shutdown() error {
	rb.cancel()
	
	// Stop all workers
	for _, worker := range rb.workers {
		close(worker.stopChan)
	}
	
	rb.wg.Wait()
	return nil
}