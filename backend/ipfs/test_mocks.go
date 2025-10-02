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

// MockClusterClient implements a mock IPFS cluster client for testing
type MockClusterClient struct {
	pins            map[string]*PinInfo
	nodes           []*NodeStatus
	failPin         bool
	failGet         bool
	failRate        float64
	retryEnabled    bool
	simulatedLatency time.Duration
	metrics         *ClusterMetrics
	mu              sync.RWMutex
}

// PinInfo represents information about a pinned object
type PinInfo struct {
	CID               string
	ReplicationFactor int
	NodesUsed         []string
	PinnedAt          time.Time
	Status            PinStatus
}

// NodeStatus represents the status of a cluster node
type NodeStatus struct {
	Endpoint string
	Healthy  bool
	ID       string
}

// ClusterInfo represents cluster information
type ClusterInfo struct {
	ID    string
	Peers int
}

// ClusterMetrics represents cluster metrics
type ClusterMetrics struct {
	TotalRequests   int64
	SuccessfulPins  int64
	FailedPins      int64
	TotalPins       int64
	AverageLatency  time.Duration
}

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

// NewMockClusterClient creates a new mock cluster client
func NewMockClusterClient() *MockClusterClient {
	return &MockClusterClient{
		pins: make(map[string]*PinInfo),
		nodes: []*NodeStatus{
			{Endpoint: "http://localhost:9094", Healthy: true, ID: "node1"},
			{Endpoint: "http://localhost:9095", Healthy: true, ID: "node2"},
			{Endpoint: "http://localhost:9096", Healthy: true, ID: "node3"},
		},
		metrics: &ClusterMetrics{},
	}
}

// Pin pins an object in the mock cluster
func (mcc *MockClusterClient) Pin(ctx context.Context, cid string, replicationFactor int) (*PinResult, error) {
	mcc.mu.Lock()
	defer mcc.mu.Unlock()
	
	mcc.metrics.TotalRequests++
	
	// Simulate latency
	if mcc.simulatedLatency > 0 {
		mcc.mu.Unlock()
		select {
		case <-ctx.Done():
			mcc.mu.Lock()
			return nil, ctx.Err()
		case <-time.After(mcc.simulatedLatency):
		}
		mcc.mu.Lock()
	}
	
	// Check for random failures based on fail rate
	if mcc.failRate > 0 && rand.Float64() < mcc.failRate {
		mcc.metrics.FailedPins++
		return &PinResult{
			CID:     cid,
			Success: false,
			Error:   fmt.Errorf("mock random pin failure"),
		}, fmt.Errorf("mock random pin failure")
	}
	
	if mcc.failPin {
		mcc.metrics.FailedPins++
		return &PinResult{
			CID:     cid,
			Success: false,
			Error:   fmt.Errorf("mock pin failure"),
		}, fmt.Errorf("mock pin failure")
	}
	
	// Simulate pin operation
	nodesUsed := make([]string, min(replicationFactor, len(mcc.nodes)))
	for i := 0; i < len(nodesUsed); i++ {
		nodesUsed[i] = mcc.nodes[i].ID
	}
	
	mcc.pins[cid] = &PinInfo{
		CID:               cid,
		ReplicationFactor: replicationFactor,
		NodesUsed:         nodesUsed,
		PinnedAt:          time.Now(),
		Status:            PinStatusPinned,
	}
	
	mcc.metrics.SuccessfulPins++
	mcc.metrics.TotalPins++
	
	return &PinResult{
		CID:       cid,
		Success:   true,
		NodesUsed: nodesUsed,
	}, nil
}

// Unpin unpins an object from the mock cluster
func (mcc *MockClusterClient) Unpin(ctx context.Context, cid string) (*UnpinResult, error) {
	mcc.mu.Lock()
	defer mcc.mu.Unlock()
	
	mcc.metrics.TotalRequests++
	
	pinInfo, exists := mcc.pins[cid]
	if !exists {
		return &UnpinResult{
			CID:     cid,
			Success: false,
			Error:   fmt.Errorf("CID not pinned"),
		}, fmt.Errorf("CID not pinned")
	}
	
	nodesUsed := pinInfo.NodesUsed
	delete(mcc.pins, cid)
	mcc.metrics.TotalPins--
	
	return &UnpinResult{
		CID:       cid,
		Success:   true,
		NodesUsed: nodesUsed,
	}, nil
}

// GetNodeStatus returns the status of cluster nodes
func (mcc *MockClusterClient) GetNodeStatus() []*NodeStatus {
	mcc.mu.RLock()
	defer mcc.mu.RUnlock()
	
	return mcc.nodes
}

// GetClusterInfo returns cluster information
func (mcc *MockClusterClient) GetClusterInfo() (*ClusterInfo, error) {
	mcc.mu.RLock()
	defer mcc.mu.RUnlock()
	
	return &ClusterInfo{
		ID:    "mock-cluster-id",
		Peers: len(mcc.nodes),
	}, nil
}

// GetMetrics returns cluster metrics
func (mcc *MockClusterClient) GetMetrics() *ClusterMetrics {
	mcc.mu.RLock()
	defer mcc.mu.RUnlock()
	
	return &ClusterMetrics{
		TotalRequests:   mcc.metrics.TotalRequests,
		SuccessfulPins:  mcc.metrics.SuccessfulPins,
		FailedPins:      mcc.metrics.FailedPins,
		TotalPins:       mcc.metrics.TotalPins,
		AverageLatency:  mcc.metrics.AverageLatency,
	}
}

// SetFailPin sets whether pin operations should fail
func (mcc *MockClusterClient) SetFailPin(fail bool) {
	mcc.mu.Lock()
	defer mcc.mu.Unlock()
	mcc.failPin = fail
}

// SetFailGet sets whether get operations should fail
func (mcc *MockClusterClient) SetFailGet(fail bool) {
	mcc.mu.Lock()
	defer mcc.mu.Unlock()
	mcc.failGet = fail
}

// SetFailRate sets the failure rate for operations (0.0 to 1.0)
func (mcc *MockClusterClient) SetFailRate(rate float64) {
	mcc.mu.Lock()
	defer mcc.mu.Unlock()
	mcc.failRate = rate
}

// SetRetryEnabled sets whether retries are enabled
func (mcc *MockClusterClient) SetRetryEnabled(enabled bool) {
	mcc.mu.Lock()
	defer mcc.mu.Unlock()
	mcc.retryEnabled = enabled
}

// SetSimulatedLatency sets simulated network latency
func (mcc *MockClusterClient) SetSimulatedLatency(latency time.Duration) {
	mcc.mu.Lock()
	defer mcc.mu.Unlock()
	mcc.simulatedLatency = latency
}

// GetPinStatus returns the status of a pin
func (mcc *MockClusterClient) GetPinStatus(ctx context.Context, cid string) (string, error) {
	mcc.mu.RLock()
	defer mcc.mu.RUnlock()
	
	// Simulate latency
	if mcc.simulatedLatency > 0 {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(mcc.simulatedLatency):
		}
	}
	
	if pin, exists := mcc.pins[cid]; exists {
		switch pin.Status {
		case PinStatusPinned:
			return "pinned", nil
		case PinStatusPending:
			return "pending", nil
		case PinStatusFailed:
			return "failed", nil
		default:
			return "unknown", nil
		}
	}
	
	return "not_found", nil
}

// MockMetadataStore implements a mock metadata store for testing
type MockMetadataStore struct {
	mappings  map[string]*ObjectMapping
	buckets   map[string]*BucketMetadata
	failOps   bool
	stats     *MetadataStats
	mu        sync.RWMutex
}

// S3Key represents an S3 key
type S3Key struct {
	Key    string
	Bucket string
}

// BucketMetadata represents bucket metadata
type BucketMetadata struct {
	Name      string
	Owner     string
	CreatedAt time.Time
	ACL       string
}

// BucketStats represents bucket statistics
type BucketStats struct {
	BucketName   string
	ObjectCount  int64
	TotalSize    int64
	LastModified time.Time
}

// MetadataStats represents metadata store statistics
type MetadataStats struct {
	TotalMappings   int64
	TotalBuckets    int64
	HealthScore     float64
	LastUpdated     time.Time
}

// NewBucketMetadata creates new bucket metadata
func NewBucketMetadata(name, owner string) *BucketMetadata {
	return &BucketMetadata{
		Name:      name,
		Owner:     owner,
		CreatedAt: time.Now(),
		ACL:       "private",
	}
}

// NewMockMetadataStore creates a new mock metadata store
func NewMockMetadataStore() *MockMetadataStore {
	return &MockMetadataStore{
		mappings: make(map[string]*ObjectMapping),
		buckets:  make(map[string]*BucketMetadata),
		stats: &MetadataStats{
			HealthScore: 100.0,
			LastUpdated: time.Now(),
		},
	}
}

// StoreMapping stores an object mapping
func (mms *MockMetadataStore) StoreMapping(ctx context.Context, mapping *ObjectMapping) error {
	mms.mu.Lock()
	defer mms.mu.Unlock()
	
	if mms.failOps {
		return fmt.Errorf("mock metadata store failure")
	}
	
	key := fmt.Sprintf("%s:%s", mapping.Bucket, mapping.S3Key)
	mms.mappings[key] = mapping
	mms.stats.TotalMappings++
	mms.stats.LastUpdated = time.Now()
	
	return nil
}

// GetMapping retrieves an object mapping
func (mms *MockMetadataStore) GetMapping(ctx context.Context, s3Key, bucket string) (*ObjectMapping, error) {
	mms.mu.RLock()
	defer mms.mu.RUnlock()
	
	if mms.failOps {
		return nil, fmt.Errorf("mock metadata store failure")
	}
	
	key := fmt.Sprintf("%s:%s", bucket, s3Key)
	mapping, exists := mms.mappings[key]
	if !exists {
		return nil, nil
	}
	
	return mapping, nil
}

// UpdateMapping updates an object mapping
func (mms *MockMetadataStore) UpdateMapping(ctx context.Context, mapping *ObjectMapping) error {
	mms.mu.Lock()
	defer mms.mu.Unlock()
	
	if mms.failOps {
		return fmt.Errorf("mock metadata store failure")
	}
	
	key := fmt.Sprintf("%s:%s", mapping.Bucket, mapping.S3Key)
	if _, exists := mms.mappings[key]; !exists {
		return fmt.Errorf("mapping not found")
	}
	
	mapping.UpdatedAt = time.Now()
	mms.mappings[key] = mapping
	mms.stats.LastUpdated = time.Now()
	
	return nil
}

// DeleteMapping deletes an object mapping
func (mms *MockMetadataStore) DeleteMapping(ctx context.Context, s3Key, bucket string) error {
	mms.mu.Lock()
	defer mms.mu.Unlock()
	
	if mms.failOps {
		return fmt.Errorf("mock metadata store failure")
	}
	
	key := fmt.Sprintf("%s:%s", bucket, s3Key)
	if _, exists := mms.mappings[key]; !exists {
		return fmt.Errorf("mapping not found")
	}
	
	delete(mms.mappings, key)
	mms.stats.TotalMappings--
	mms.stats.LastUpdated = time.Now()
	
	return nil
}

// StoreMappingBatch stores multiple object mappings
func (mms *MockMetadataStore) StoreMappingBatch(ctx context.Context, mappings []*ObjectMapping) error {
	mms.mu.Lock()
	defer mms.mu.Unlock()
	
	if mms.failOps {
		return fmt.Errorf("mock metadata store failure")
	}
	
	for _, mapping := range mappings {
		key := fmt.Sprintf("%s:%s", mapping.Bucket, mapping.S3Key)
		mms.mappings[key] = mapping
		mms.stats.TotalMappings++
	}
	
	mms.stats.LastUpdated = time.Now()
	return nil
}

// GetMappingBatch retrieves multiple object mappings
func (mms *MockMetadataStore) GetMappingBatch(ctx context.Context, keys []*S3Key) ([]*ObjectMapping, error) {
	mms.mu.RLock()
	defer mms.mu.RUnlock()
	
	if mms.failOps {
		return nil, fmt.Errorf("mock metadata store failure")
	}
	
	var results []*ObjectMapping
	for _, s3Key := range keys {
		key := fmt.Sprintf("%s:%s", s3Key.Bucket, s3Key.Key)
		if mapping, exists := mms.mappings[key]; exists {
			results = append(results, mapping)
		}
	}
	
	return results, nil
}

// SearchByCID searches for mappings by CID
func (mms *MockMetadataStore) SearchByCID(ctx context.Context, cid string) ([]*ObjectMapping, error) {
	mms.mu.RLock()
	defer mms.mu.RUnlock()
	
	if mms.failOps {
		return nil, fmt.Errorf("mock metadata store failure")
	}
	
	var results []*ObjectMapping
	for _, mapping := range mms.mappings {
		if mapping.CID == cid {
			results = append(results, mapping)
		}
	}
	
	return results, nil
}

// SearchByPrefix searches for mappings by key prefix
func (mms *MockMetadataStore) SearchByPrefix(ctx context.Context, bucket, prefix string, limit int) ([]*ObjectMapping, error) {
	mms.mu.RLock()
	defer mms.mu.RUnlock()
	
	if mms.failOps {
		return nil, fmt.Errorf("mock metadata store failure")
	}
	
	var results []*ObjectMapping
	count := 0
	
	for _, mapping := range mms.mappings {
		if mapping.Bucket == bucket && len(mapping.S3Key) >= len(prefix) && mapping.S3Key[:len(prefix)] == prefix {
			results = append(results, mapping)
			count++
			if count >= limit {
				break
			}
		}
	}
	
	return results, nil
}

// CreateBucket creates a bucket
func (mms *MockMetadataStore) CreateBucket(ctx context.Context, name string, metadata *BucketMetadata) error {
	mms.mu.Lock()
	defer mms.mu.Unlock()
	
	if mms.failOps {
		return fmt.Errorf("mock metadata store failure")
	}
	
	if _, exists := mms.buckets[name]; exists {
		return fmt.Errorf("bucket already exists")
	}
	
	mms.buckets[name] = metadata
	mms.stats.TotalBuckets++
	mms.stats.LastUpdated = time.Now()
	
	return nil
}

// GetBucket retrieves bucket metadata
func (mms *MockMetadataStore) GetBucket(ctx context.Context, name string) (*BucketMetadata, error) {
	mms.mu.RLock()
	defer mms.mu.RUnlock()
	
	if mms.failOps {
		return nil, fmt.Errorf("mock metadata store failure")
	}
	
	bucket, exists := mms.buckets[name]
	if !exists {
		return nil, fmt.Errorf("bucket not found")
	}
	
	return bucket, nil
}

// ListBuckets lists all buckets
func (mms *MockMetadataStore) ListBuckets(ctx context.Context) ([]*BucketMetadata, error) {
	mms.mu.RLock()
	defer mms.mu.RUnlock()
	
	if mms.failOps {
		return nil, fmt.Errorf("mock metadata store failure")
	}
	
	var buckets []*BucketMetadata
	for _, bucket := range mms.buckets {
		buckets = append(buckets, bucket)
	}
	
	return buckets, nil
}

// DeleteBucket deletes a bucket
func (mms *MockMetadataStore) DeleteBucket(ctx context.Context, name string) error {
	mms.mu.Lock()
	defer mms.mu.Unlock()
	
	if mms.failOps {
		return fmt.Errorf("mock metadata store failure")
	}
	
	if _, exists := mms.buckets[name]; !exists {
		return fmt.Errorf("bucket not found")
	}
	
	// Check if bucket has objects
	for _, mapping := range mms.mappings {
		if mapping.Bucket == name {
			return fmt.Errorf("bucket not empty")
		}
	}
	
	delete(mms.buckets, name)
	mms.stats.TotalBuckets--
	mms.stats.LastUpdated = time.Now()
	
	return nil
}

// ListObjectsInBucket lists objects in a bucket
func (mms *MockMetadataStore) ListObjectsInBucket(ctx context.Context, bucket, prefix string, limit int) ([]*ObjectMapping, error) {
	mms.mu.RLock()
	defer mms.mu.RUnlock()
	
	if mms.failOps {
		return nil, fmt.Errorf("mock metadata store failure")
	}
	
	var results []*ObjectMapping
	count := 0
	
	for _, mapping := range mms.mappings {
		if mapping.Bucket == bucket {
			if prefix == "" || (len(mapping.S3Key) >= len(prefix) && mapping.S3Key[:len(prefix)] == prefix) {
				results = append(results, mapping)
				count++
				if count >= limit {
					break
				}
			}
		}
	}
	
	return results, nil
}

// GetBucketStats returns bucket statistics
func (mms *MockMetadataStore) GetBucketStats(ctx context.Context, bucket string) (*BucketStats, error) {
	mms.mu.RLock()
	defer mms.mu.RUnlock()
	
	if mms.failOps {
		return nil, fmt.Errorf("mock metadata store failure")
	}
	
	var objectCount int64
	var totalSize int64
	var lastModified time.Time
	
	for _, mapping := range mms.mappings {
		if mapping.Bucket == bucket {
			objectCount++
			totalSize += mapping.Size
			if mapping.UpdatedAt.After(lastModified) {
				lastModified = mapping.UpdatedAt
			}
		}
	}
	
	return &BucketStats{
		BucketName:   bucket,
		ObjectCount:  objectCount,
		TotalSize:    totalSize,
		LastModified: lastModified,
	}, nil
}

// GetStats returns metadata store statistics
func (mms *MockMetadataStore) GetStats(ctx context.Context) (*MetadataStats, error) {
	mms.mu.RLock()
	defer mms.mu.RUnlock()
	
	if mms.failOps {
		return nil, fmt.Errorf("mock metadata store failure")
	}
	
	return &MetadataStats{
		TotalMappings: mms.stats.TotalMappings,
		TotalBuckets:  mms.stats.TotalBuckets,
		HealthScore:   mms.stats.HealthScore,
		LastUpdated:   mms.stats.LastUpdated,
	}, nil
}

// SetFailOps sets whether operations should fail
func (mms *MockMetadataStore) SetFailOps(fail bool) {
	mms.mu.Lock()
	defer mms.mu.Unlock()
	mms.failOps = fail
}

// MockIPFSBackend represents a mock IPFS backend for testing
type MockIPFSBackend struct {
	clusterClient *MockClusterClient
	metadataStore *MockMetadataStore
	config        *IPFSConfig
	healthy       bool
	stats         map[string]interface{}
	mu            sync.RWMutex
}

// IPFSConfig represents IPFS backend configuration
type IPFSConfig struct {
	ClusterEndpoints    []string
	ConnectTimeout      time.Duration
	RequestTimeout      time.Duration
	MaxRetries          int
	RetryDelay          time.Duration
	MaxConcurrentPins   int
	PinTimeout          time.Duration
	ChunkSize           int64
	ReplicationMin      int
	ReplicationMax      int
	MetadataDBType      string
	LogLevel            string
	EnableMetrics       bool
	MetricsInterval     time.Duration
	EnableHealthCheck   bool
	HealthCheckInterval time.Duration
}

// HealthStatus represents health status
type HealthStatus struct {
	Overall         bool
	ClusterHealthy  bool
	MetadataHealthy bool
	Details         map[string]interface{}
}

// NewWithMocks creates a new IPFS backend with mock components
func NewWithMocks(config *IPFSConfig, clusterClient *MockClusterClient, metadataStore *MockMetadataStore, logger *log.Logger) (*MockIPFSBackend, error) {
	return &MockIPFSBackend{
		clusterClient: clusterClient,
		metadataStore: metadataStore,
		config:        config,
		healthy:       true,
		stats: map[string]interface{}{
			"backend_type":   "ipfs-cluster",
			"cluster_nodes":  3,
			"total_pins":     0,
			"healthy_nodes":  3,
		},
	}, nil
}

// String returns the backend type
func (mib *MockIPFSBackend) String() string {
	return "IPFS-Cluster"
}

// GetConfig returns the backend configuration
func (mib *MockIPFSBackend) GetConfig() *IPFSConfig {
	mib.mu.RLock()
	defer mib.mu.RUnlock()
	return mib.config
}

// IsHealthy returns whether the backend is healthy
func (mib *MockIPFSBackend) IsHealthy() bool {
	mib.mu.RLock()
	defer mib.mu.RUnlock()
	return mib.healthy
}

// GetHealthStatus returns detailed health status
func (mib *MockIPFSBackend) GetHealthStatus() *HealthStatus {
	mib.mu.RLock()
	defer mib.mu.RUnlock()
	
	return &HealthStatus{
		Overall:         mib.healthy,
		ClusterHealthy:  true,
		MetadataHealthy: true,
		Details: map[string]interface{}{
			"cluster_nodes": 3,
			"healthy_nodes": 3,
		},
	}
}

// GetStats returns backend statistics
func (mib *MockIPFSBackend) GetStats() map[string]interface{} {
	mib.mu.RLock()
	defer mib.mu.RUnlock()
	
	// Update stats
	stats := make(map[string]interface{})
	for k, v := range mib.stats {
		stats[k] = v
	}
	
	// Update pin count from cluster client
	metrics := mib.clusterClient.GetMetrics()
	stats["total_pins"] = metrics.TotalPins
	
	return stats
}

// Shutdown shuts down the backend
func (mib *MockIPFSBackend) Shutdown() {
	mib.mu.Lock()
	defer mib.mu.Unlock()
	mib.healthy = false
}

// ClusterClientConfig represents cluster client configuration
type ClusterClientConfig struct {
	Endpoints      []string
	ConnectTimeout time.Duration
	RequestTimeout time.Duration
	MaxRetries     int
	RetryDelay     time.Duration
	Logger         *log.Logger
}

// NewClusterClient creates a new cluster client (mock implementation)
func NewClusterClient(config ClusterClientConfig) (*MockClusterClient, error) {
	return NewMockClusterClient(), nil
}

// Shutdown shuts down the cluster client
func (mcc *MockClusterClient) Shutdown() {
	// Mock implementation - nothing to do
}