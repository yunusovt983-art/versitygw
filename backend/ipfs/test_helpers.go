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
	"time"
)

// NewWithMocks creates an IPFS backend with mock components for testing
func NewWithMocks(config *IPFSConfig, clusterClient ClusterClientInterface, metadataStore MetadataStoreInterface, logger *log.Logger) (*IPFSBackend, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	
	backend := &IPFSBackend{
		config:        config,
		clusterClient: clusterClient,
		metadataStore: metadataStore,
		logger:        logger,
		isHealthy:     true,
		stats:         make(map[string]interface{}),
		mu:            sync.RWMutex{},
	}
	
	// Initialize stats
	backend.stats["backend_type"] = "ipfs-cluster"
	backend.stats["cluster_nodes"] = len(config.ClusterEndpoints)
	backend.stats["total_pins"] = int64(0)
	backend.stats["healthy_nodes"] = len(config.ClusterEndpoints)
	
	return backend, nil
}

// ClusterClientInterface defines the interface for cluster clients
type ClusterClientInterface interface {
	Pin(ctx context.Context, cid string, replicationFactor int) (*ClusterPinResult, error)
	Unpin(ctx context.Context, cid string) (*ClusterUnpinResult, error)
	GetNodeStatus() []*NodeStatus
	GetClusterInfo() (*ClusterInfo, error)
	GetMetrics() *ClusterMetrics
	EnableHealthChecking(enabled bool)
	ForceHealthCheck()
	Shutdown()
	SetFailPin(fail bool)
	SetFailUnpin(fail bool)
	GetPins() map[string]*MockPin
	GetNodeStatusByID(ctx context.Context, nodeID string) (*NodeStatusInfo, error)
	GetPeers() ([]PeerInfo, error)
}

// MetadataStoreInterface defines the interface for metadata stores
type MetadataStoreInterface interface {
	// Basic operations
	StoreMapping(ctx context.Context, mapping *ObjectMapping) error
	GetMapping(ctx context.Context, s3Key, bucket string) (*ObjectMapping, error)
	UpdateMapping(ctx context.Context, mapping *ObjectMapping) error
	DeleteMapping(ctx context.Context, s3Key, bucket string) error
	
	// Batch operations
	StoreMappingBatch(ctx context.Context, mappings []*ObjectMapping) error
	GetMappingBatch(ctx context.Context, keys []*S3Key) ([]*ObjectMapping, error)
	DeleteMappingBatch(ctx context.Context, keys []*S3Key) error
	
	// Search operations
	SearchByCID(ctx context.Context, cid string) ([]*ObjectMapping, error)
	SearchByPrefix(ctx context.Context, bucket, prefix string, limit int) ([]*ObjectMapping, error)
	ListObjectsInBucket(ctx context.Context, bucket string, marker string, limit int) ([]*ObjectMapping, error)
	
	// Bucket operations
	CreateBucket(ctx context.Context, bucket string, metadata *BucketMetadata) error
	GetBucket(ctx context.Context, bucket string) (*BucketMetadata, error)
	DeleteBucket(ctx context.Context, bucket string) error
	ListBuckets(ctx context.Context) ([]*BucketMetadata, error)
	
	// Statistics and health
	GetStats(ctx context.Context) (*MetadataStats, error)
	GetBucketStats(ctx context.Context, bucket string) (*BucketStats, error)
	HealthCheck(ctx context.Context) error
	
	// Maintenance operations
	Compact(ctx context.Context) error
	Backup(ctx context.Context, path string) error
	Restore(ctx context.Context, path string) error
	Initialize(ctx context.Context) error
	Shutdown(ctx context.Context) error
	
	// Test helpers
	SetFailOps(fail bool)
	GetMappings() map[string]*ObjectMapping
}

// ClusterPinResult represents the result of a pin operation
type ClusterPinResult struct {
	CID       string
	NodesUsed []string
	Success   bool
	Error     error
}

// ClusterUnpinResult represents the result of an unpin operation
type ClusterUnpinResult struct {
	CID       string
	NodesUsed []string
	Success   bool
	Error     error
}

// NodeStatus represents the status of a cluster node
type NodeStatus struct {
	Endpoint string
	Healthy  bool
	LastSeen time.Time
	Error    error
}

// ClusterInfo represents information about the cluster
type ClusterInfo struct {
	ID      string
	Version string
	Peers   int
}

// ClusterMetrics represents metrics from the cluster
type ClusterMetrics struct {
	TotalRequests    int64
	SuccessfulReqs   int64
	FailedRequests   int64
	HealthCheckCount int64
}

// NodeStatusInfo represents detailed node status information
type NodeStatusInfo struct {
	IsHealthy bool
	Metadata  map[string]interface{}
}

// PeerInfo represents information about a cluster peer
type PeerInfo struct {
	ID        string
	Connected bool
	LastSeen  time.Time
}

// S3Key represents an S3 key for batch operations
type S3Key struct {
	Key    string
	Bucket string
}

// ObjectMapping represents the mapping between S3 keys and IPFS CIDs
type ObjectMapping struct {
	S3Key     string
	Bucket    string
	CID       string
	Size      int64
	CreatedAt time.Time
	UpdatedAt time.Time
	AccessedAt time.Time
	PinStatus PinStatus
	Metadata  ObjectMetadata
}

// GetPrimaryKey returns the primary key for the mapping
func (om *ObjectMapping) GetPrimaryKey() string {
	return fmt.Sprintf("%s/%s", om.Bucket, om.S3Key)
}

// Clone creates a deep copy of the object mapping
func (om *ObjectMapping) Clone() *ObjectMapping {
	clone := &ObjectMapping{
		S3Key:      om.S3Key,
		Bucket:     om.Bucket,
		CID:        om.CID,
		Size:       om.Size,
		CreatedAt:  om.CreatedAt,
		UpdatedAt:  om.UpdatedAt,
		AccessedAt: om.AccessedAt,
		PinStatus:  om.PinStatus,
		Metadata: ObjectMetadata{
			ContentType:     om.Metadata.ContentType,
			ContentEncoding: om.Metadata.ContentEncoding,
			UserMetadata:    make(map[string]string),
			Tags:           make(map[string]string),
			ACL:            om.Metadata.ACL,
		},
	}
	
	// Deep copy maps
	for k, v := range om.Metadata.UserMetadata {
		clone.Metadata.UserMetadata[k] = v
	}
	for k, v := range om.Metadata.Tags {
		clone.Metadata.Tags[k] = v
	}
	
	return clone
}

// ObjectMetadata represents metadata for an object
type ObjectMetadata struct {
	ContentType     string
	ContentEncoding string
	UserMetadata    map[string]string
	Tags           map[string]string
	ACL            string
}

// PinStatus represents the status of a pin
type PinStatus int

const (
	PinStatusPending PinStatus = iota
	PinStatusPinned
	PinStatusFailed
	PinStatusUnpinning
	PinStatusUnpinned
)

// String returns string representation of pin status
func (ps PinStatus) String() string {
	switch ps {
	case PinStatusPending:
		return "pending"
	case PinStatusPinned:
		return "pinned"
	case PinStatusFailed:
		return "failed"
	case PinStatusUnpinning:
		return "unpinning"
	case PinStatusUnpinned:
		return "unpinned"
	default:
		return "unknown"
	}
}

// BucketMetadata represents metadata for a bucket
type BucketMetadata struct {
	Name      string
	Owner     string
	CreatedAt time.Time
	UpdatedAt time.Time
	ACL       string
	Tags      map[string]string
}

// NewBucketMetadata creates new bucket metadata
func NewBucketMetadata(name, owner string) *BucketMetadata {
	return &BucketMetadata{
		Name:      name,
		Owner:     owner,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Tags:      make(map[string]string),
	}
}

// MetadataStats represents statistics from the metadata store
type MetadataStats struct {
	TotalObjects int64
	TotalBuckets int64
	HealthScore  float64
}

// BucketStats represents statistics for a specific bucket
type BucketStats struct {
	BucketName  string
	ObjectCount int64
	TotalSize   int64
}

// MockMetadataStore implements MetadataStoreInterface for testing
type MockMetadataStore struct {
	mappings map[string]*ObjectMapping
	failOps  bool
	mu       sync.RWMutex
}

// NewMockMetadataStore creates a new mock metadata store
func NewMockMetadataStore() *MockMetadataStore {
	return &MockMetadataStore{
		mappings: make(map[string]*ObjectMapping),
		failOps:  false,
	}
}

// StoreMapping stores an object mapping
func (m *MockMetadataStore) StoreMapping(ctx context.Context, mapping *ObjectMapping) error {
	if m.failOps {
		return fmt.Errorf("mock store failure")
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	key := mapping.GetPrimaryKey()
	m.mappings[key] = mapping.Clone()
	return nil
}

// GetMapping retrieves an object mapping
func (m *MockMetadataStore) GetMapping(ctx context.Context, s3Key, bucket string) (*ObjectMapping, error) {
	if m.failOps {
		return nil, fmt.Errorf("mock get failure")
	}
	
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	key := fmt.Sprintf("%s/%s", bucket, s3Key)
	mapping, exists := m.mappings[key]
	if !exists {
		return nil, nil
	}
	
	return mapping.Clone(), nil
}

// IPFSBackend represents the IPFS backend implementation
type IPFSBackend struct {
	config        *IPFSConfig
	clusterClient ClusterClientInterface
	metadataStore MetadataStoreInterface
	logger        *log.Logger
	isHealthy     bool
	stats         map[string]interface{}
	mu            sync.RWMutex
}

// String returns the backend type
func (b *IPFSBackend) String() string {
	return "IPFS-Cluster"
}

// IsHealthy returns whether the backend is healthy
func (b *IPFSBackend) IsHealthy() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.isHealthy
}

// GetStats returns backend statistics
func (b *IPFSBackend) GetStats() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	stats := make(map[string]interface{})
	for k, v := range b.stats {
		stats[k] = v
	}
	return stats
}

// GetConfig returns the backend configuration
func (b *IPFSBackend) GetConfig() *IPFSConfig {
	return b.config
}

// GetHealthStatus returns detailed health status
func (b *IPFSBackend) GetHealthStatus() *HealthStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	return &HealthStatus{
		Overall:       b.isHealthy,
		ClusterHealth: true,
		MetadataHealth: true,
		Components: map[string]bool{
			"cluster":  true,
			"metadata": true,
		},
	}
}

// Shutdown shuts down the backend
func (b *IPFSBackend) Shutdown() {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	b.isHealthy = false
	
	if b.clusterClient != nil {
		b.clusterClient.Shutdown()
	}
}

// HealthStatus represents the health status of the backend
type HealthStatus struct {
	Overall        bool
	ClusterHealth  bool
	MetadataHealth bool
	Components     map[string]bool
}

// PinManagerConfig represents configuration for the pin manager
type PinManagerConfig struct {
	PinWorkerCount     int
	UnpinWorkerCount   int
	PinQueueSize       int
	UnpinQueueSize     int
	RetryQueueSize     int
	PinTimeout         time.Duration
	UnpinTimeout       time.Duration
	MaxRetries         int
	InitialRetryDelay  time.Duration
	MaxRetryDelay      time.Duration
	RetryBackoffFactor float64
	MetricsEnabled     bool
	MetricsInterval    time.Duration
}

// PinManager manages pin operations
type PinManager struct {
	config        *PinManagerConfig
	clusterClient ClusterClientInterface
	metadataStore MetadataStoreInterface
	logger        *log.Logger
	running       bool
	mu            sync.RWMutex
}

// NewPinManager creates a new pin manager
func NewPinManager(config *PinManagerConfig, clusterClient ClusterClientInterface, metadataStore MetadataStoreInterface, logger *log.Logger) (*PinManager, error) {
	return &PinManager{
		config:        config,
		clusterClient: clusterClient,
		metadataStore: metadataStore,
		logger:        logger,
		running:       false,
	}, nil
}

// Start starts the pin manager
func (pm *PinManager) Start() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if pm.running {
		return fmt.Errorf("pin manager already running")
	}
	
	pm.running = true
	return nil
}

// Stop stops the pin manager
func (pm *PinManager) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if !pm.running {
		return fmt.Errorf("pin manager not running")
	}
	
	pm.running = false
	return nil
}

// isRunning returns whether the pin manager is running
func (pm *PinManager) isRunning() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.running
}

// Pin pins an object synchronously
func (pm *PinManager) Pin(ctx context.Context, cid, s3Key, bucket string, size int64, replicationFactor int, priority PinPriority) (*PinResult, error) {
	result, err := pm.clusterClient.Pin(ctx, cid, replicationFactor)
	if err != nil {
		return &PinResult{
			CID:     cid,
			Success: false,
			Error:   err,
		}, err
	}
	
	// Update metadata
	mapping := &ObjectMapping{
		S3Key:     s3Key,
		Bucket:    bucket,
		CID:       cid,
		Size:      size,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		PinStatus: PinStatusPinned,
	}
	
	err = pm.metadataStore.StoreMapping(ctx, mapping)
	if err != nil {
		pm.logger.Printf("Failed to store metadata for pin %s: %v", cid, err)
	}
	
	return &PinResult{
		CID:       result.CID,
		Success:   result.Success,
		NodesUsed: result.NodesUsed,
		Error:     result.Error,
	}, nil
}

// Unpin unpins an object synchronously
func (pm *PinManager) Unpin(ctx context.Context, cid, s3Key, bucket string, force bool, priority PinPriority) (*UnpinResult, error) {
	result, err := pm.clusterClient.Unpin(ctx, cid)
	if err != nil {
		return &UnpinResult{
			CID:     cid,
			Success: false,
			Error:   err,
		}, err
	}
	
	// Update metadata
	mapping, err := pm.metadataStore.GetMapping(ctx, s3Key, bucket)
	if err == nil && mapping != nil {
		mapping.PinStatus = PinStatusUnpinned
		mapping.UpdatedAt = time.Now()
		err = pm.metadataStore.UpdateMapping(ctx, mapping)
		if err != nil {
			pm.logger.Printf("Failed to update metadata for unpin %s: %v", cid, err)
		}
	}
	
	return &UnpinResult{
		CID:       result.CID,
		Success:   result.Success,
		NodesUsed: result.NodesUsed,
		Error:     result.Error,
	}, nil
}

// PinAsync pins an object asynchronously
func (pm *PinManager) PinAsync(ctx context.Context, cid, s3Key, bucket string, size int64, replicationFactor int, priority PinPriority) (string, error) {
	requestID := fmt.Sprintf("pin-%d", time.Now().UnixNano())
	
	// For mock implementation, just return request ID
	// In real implementation, this would queue the operation
	
	return requestID, nil
}

// UnpinAsync unpins an object asynchronously
func (pm *PinManager) UnpinAsync(ctx context.Context, cid, s3Key, bucket string, force bool, priority PinPriority) (string, error) {
	requestID := fmt.Sprintf("unpin-%d", time.Now().UnixNano())
	
	// For mock implementation, just return request ID
	// In real implementation, this would queue the operation
	
	return requestID, nil
}

// GetMetrics returns pin manager metrics
func (pm *PinManager) GetMetrics() *PinManagerMetrics {
	return &PinManagerMetrics{
		TotalPinRequests:   0,
		SuccessfulPins:     0,
		FailedPins:         0,
		TotalUnpinRequests: 0,
		SuccessfulUnpins:   0,
		FailedUnpins:       0,
		ActivePinWorkers:   pm.config.PinWorkerCount,
		ActiveUnpinWorkers: pm.config.UnpinWorkerCount,
		CriticalPins:       0,
		NormalPins:         0,
		BackgroundPins:     0,
		TotalRetries:       0,
	}
}

// GetQueueStats returns queue statistics
func (pm *PinManager) GetQueueStats() *QueueStats {
	return &QueueStats{
		PinQueueSize:       0,
		PinQueueCapacity:   pm.config.PinQueueSize,
		UnpinQueueSize:     0,
		UnpinQueueCapacity: pm.config.UnpinQueueSize,
		RetryQueueSize:     0,
		RetryQueueCapacity: pm.config.RetryQueueSize,
	}
}

// IsHealthy returns whether the pin manager is healthy
func (pm *PinManager) IsHealthy() bool {
	return pm.isRunning()
}

// PinPriority represents the priority of a pin operation
type PinPriority int

const (
	PinPriorityBackground PinPriority = iota
	PinPriorityNormal
	PinPriorityCritical
)

// PinResult represents the result of a pin operation
type PinResult struct {
	CID       string
	Success   bool
	NodesUsed []string
	Error     error
}

// UnpinResult represents the result of an unpin operation
type UnpinResult struct {
	CID       string
	Success   bool
	NodesUsed []string
	Error     error
}

// PinManagerMetrics represents metrics from the pin manager
type PinManagerMetrics struct {
	TotalPinRequests   int64
	SuccessfulPins     int64
	FailedPins         int64
	TotalUnpinRequests int64
	SuccessfulUnpins   int64
	FailedUnpins       int64
	ActivePinWorkers   int
	ActiveUnpinWorkers int
	CriticalPins       int64
	NormalPins         int64
	BackgroundPins     int64
	TotalRetries       int64
}

// QueueStats represents queue statistics
type QueueStats struct {
	PinQueueSize       int
	PinQueueCapacity   int
	UnpinQueueSize     int
	UnpinQueueCapacity int
	RetryQueueSize     int
	RetryQueueCapacity int
}