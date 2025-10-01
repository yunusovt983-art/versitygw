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
	"sort"
	"strings"
	"sync"
	"time"
)

// MemoryMetadataStore implements MetadataStore interface using in-memory storage
// This is primarily for testing and development purposes
type MemoryMetadataStore struct {
	// Object mappings storage
	objects map[string]*ObjectMapping // key: bucket/s3key
	
	// Bucket metadata storage
	buckets map[string]*BucketMetadata // key: bucket name
	
	// Indexes for fast lookups
	cidIndex    map[string][]*ObjectMapping // CID -> objects
	bucketIndex map[string][]*ObjectMapping // bucket -> objects
	
	// Statistics
	stats *MetadataStats
	
	// Configuration
	config *MetadataStoreConfig
	
	// Synchronization
	mu sync.RWMutex
	
	// Lifecycle
	initialized bool
	shutdown    bool
}

// NewMemoryMetadataStore creates a new in-memory metadata store
func NewMemoryMetadataStore(config *MetadataStoreConfig) *MemoryMetadataStore {
	if config == nil {
		config = &MetadataStoreConfig{
			Type:         "memory",
			BatchSize:    1000,
			QueryTimeout: 30 * time.Second,
		}
	}
	
	return &MemoryMetadataStore{
		objects:     make(map[string]*ObjectMapping),
		buckets:     make(map[string]*BucketMetadata),
		cidIndex:    make(map[string][]*ObjectMapping),
		bucketIndex: make(map[string][]*ObjectMapping),
		config:      config,
		stats: &MetadataStats{
			LastHealthCheck: time.Now(),
			HealthScore:     1.0,
		},
	}
}

// Initialize initializes the memory metadata store
func (m *MemoryMetadataStore) Initialize(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.initialized {
		return fmt.Errorf("metadata store already initialized")
	}
	
	m.initialized = true
	m.shutdown = false
	
	// Initialize statistics
	m.updateStats()
	
	return nil
}

// Shutdown shuts down the memory metadata store
func (m *MemoryMetadataStore) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.shutdown {
		return nil
	}
	
	m.shutdown = true
	m.initialized = false
	
	// Clear all data
	m.objects = make(map[string]*ObjectMapping)
	m.buckets = make(map[string]*BucketMetadata)
	m.cidIndex = make(map[string][]*ObjectMapping)
	m.bucketIndex = make(map[string][]*ObjectMapping)
	
	return nil
}

// HealthCheck performs a health check on the metadata store
func (m *MemoryMetadataStore) HealthCheck(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	if !m.initialized {
		return fmt.Errorf("metadata store not initialized")
	}
	
	// Update health check timestamp
	m.stats.LastHealthCheck = time.Now()
	m.stats.HealthScore = 1.0 // Memory store is always healthy when running
	
	return nil
}

// StoreMapping stores a single object mapping
func (m *MemoryMetadataStore) StoreMapping(ctx context.Context, mapping *ObjectMapping) error {
	if err := mapping.Validate(); err != nil {
		return fmt.Errorf("invalid mapping: %w", err)
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	key := m.getObjectKey(mapping.Bucket, mapping.S3Key)
	
	// Store the mapping
	m.objects[key] = mapping.Clone()
	
	// Update indexes
	m.updateIndexes(mapping)
	
	// Update bucket statistics
	m.updateBucketStats(mapping.Bucket, 1, mapping.Size)
	
	// Update global statistics
	m.stats.TotalQueries++
	m.updateStats()
	
	return nil
}

// GetMapping retrieves a single object mapping
func (m *MemoryMetadataStore) GetMapping(ctx context.Context, s3Key, bucket string) (*ObjectMapping, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	key := m.getObjectKey(bucket, s3Key)
	mapping, exists := m.objects[key]
	if !exists {
		return nil, fmt.Errorf("object not found: %s/%s", bucket, s3Key)
	}
	
	// Update access statistics
	clone := mapping.Clone()
	clone.AccessCount++
	clone.AccessedAt = time.Now()
	m.objects[key] = clone
	
	// Update global statistics
	m.stats.TotalQueries++
	
	return clone, nil
}

// DeleteMapping deletes a single object mapping
func (m *MemoryMetadataStore) DeleteMapping(ctx context.Context, s3Key, bucket string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	key := m.getObjectKey(bucket, s3Key)
	mapping, exists := m.objects[key]
	if !exists {
		return fmt.Errorf("object not found: %s/%s", bucket, s3Key)
	}
	
	// Remove from main storage
	delete(m.objects, key)
	
	// Remove from indexes
	m.removeFromIndexes(mapping)
	
	// Update bucket statistics
	m.updateBucketStats(bucket, -1, -mapping.Size)
	
	// Update global statistics
	m.stats.TotalQueries++
	m.updateStats()
	
	return nil
}

// UpdateMapping updates an existing object mapping
func (m *MemoryMetadataStore) UpdateMapping(ctx context.Context, mapping *ObjectMapping) error {
	if err := mapping.Validate(); err != nil {
		return fmt.Errorf("invalid mapping: %w", err)
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	key := m.getObjectKey(mapping.Bucket, mapping.S3Key)
	existing, exists := m.objects[key]
	if !exists {
		return fmt.Errorf("object not found: %s/%s", mapping.Bucket, mapping.S3Key)
	}
	
	// Remove old mapping from indexes
	m.removeFromIndexes(existing)
	
	// Update the mapping
	mapping.UpdatedAt = time.Now()
	m.objects[key] = mapping.Clone()
	
	// Update indexes with new mapping
	m.updateIndexes(mapping)
	
	// Update bucket statistics if size changed
	sizeDiff := mapping.Size - existing.Size
	if sizeDiff != 0 {
		m.updateBucketStats(mapping.Bucket, 0, sizeDiff)
	}
	
	// Update global statistics
	m.stats.TotalQueries++
	m.updateStats()
	
	return nil
}

// StoreMappingBatch stores multiple object mappings in a batch
func (m *MemoryMetadataStore) StoreMappingBatch(ctx context.Context, mappings []*ObjectMapping) error {
	if len(mappings) == 0 {
		return nil
	}
	
	// Validate all mappings first
	for i, mapping := range mappings {
		if err := mapping.Validate(); err != nil {
			return fmt.Errorf("invalid mapping at index %d: %w", i, err)
		}
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	// Store all mappings
	bucketStats := make(map[string]struct{ count, size int64 })
	
	for _, mapping := range mappings {
		key := m.getObjectKey(mapping.Bucket, mapping.S3Key)
		m.objects[key] = mapping.Clone()
		m.updateIndexes(mapping)
		
		// Accumulate bucket statistics
		stats := bucketStats[mapping.Bucket]
		stats.count++
		stats.size += mapping.Size
		bucketStats[mapping.Bucket] = stats
	}
	
	// Update bucket statistics
	for bucket, stats := range bucketStats {
		m.updateBucketStats(bucket, stats.count, stats.size)
	}
	
	// Update global statistics
	m.stats.TotalQueries++
	m.updateStats()
	
	return nil
}

// GetMappingBatch retrieves multiple object mappings
func (m *MemoryMetadataStore) GetMappingBatch(ctx context.Context, keys []*S3Key) ([]*ObjectMapping, error) {
	if len(keys) == 0 {
		return []*ObjectMapping{}, nil
	}
	
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	results := make([]*ObjectMapping, 0, len(keys))
	
	for _, s3Key := range keys {
		key := m.getObjectKey(s3Key.Bucket, s3Key.Key)
		if mapping, exists := m.objects[key]; exists {
			clone := mapping.Clone()
			clone.AccessCount++
			clone.AccessedAt = time.Now()
			m.objects[key] = clone
			results = append(results, clone)
		}
	}
	
	// Update global statistics
	m.stats.TotalQueries++
	
	return results, nil
}

// DeleteMappingBatch deletes multiple object mappings
func (m *MemoryMetadataStore) DeleteMappingBatch(ctx context.Context, keys []*S3Key) error {
	if len(keys) == 0 {
		return nil
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	bucketStats := make(map[string]struct{ count, size int64 })
	
	for _, s3Key := range keys {
		key := m.getObjectKey(s3Key.Bucket, s3Key.Key)
		if mapping, exists := m.objects[key]; exists {
			delete(m.objects, key)
			m.removeFromIndexes(mapping)
			
			// Accumulate bucket statistics
			stats := bucketStats[mapping.Bucket]
			stats.count--
			stats.size -= mapping.Size
			bucketStats[mapping.Bucket] = stats
		}
	}
	
	// Update bucket statistics
	for bucket, stats := range bucketStats {
		m.updateBucketStats(bucket, stats.count, stats.size)
	}
	
	// Update global statistics
	m.stats.TotalQueries++
	m.updateStats()
	
	return nil
}

// SearchByCID searches for objects by CID
func (m *MemoryMetadataStore) SearchByCID(ctx context.Context, cid string) ([]*ObjectMapping, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	mappings, exists := m.cidIndex[cid]
	if !exists {
		return []*ObjectMapping{}, nil
	}
	
	// Clone all mappings
	results := make([]*ObjectMapping, len(mappings))
	for i, mapping := range mappings {
		results[i] = mapping.Clone()
	}
	
	// Update global statistics
	m.stats.TotalQueries++
	
	return results, nil
}

// SearchByPrefix searches for objects by bucket and key prefix
func (m *MemoryMetadataStore) SearchByPrefix(ctx context.Context, bucket, prefix string, limit int) ([]*ObjectMapping, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	bucketObjects, exists := m.bucketIndex[bucket]
	if !exists {
		return []*ObjectMapping{}, nil
	}
	
	results := make([]*ObjectMapping, 0)
	
	for _, mapping := range bucketObjects {
		if strings.HasPrefix(mapping.S3Key, prefix) {
			results = append(results, mapping.Clone())
			if limit > 0 && len(results) >= limit {
				break
			}
		}
	}
	
	// Sort results by S3Key for consistent ordering
	sort.Slice(results, func(i, j int) bool {
		return results[i].S3Key < results[j].S3Key
	})
	
	// Update global statistics
	m.stats.TotalQueries++
	
	return results, nil
}

// ListObjectsInBucket lists objects in a bucket with pagination
func (m *MemoryMetadataStore) ListObjectsInBucket(ctx context.Context, bucket string, marker string, limit int) ([]*ObjectMapping, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	bucketObjects, exists := m.bucketIndex[bucket]
	if !exists {
		return []*ObjectMapping{}, nil
	}
	
	// Sort objects by S3Key
	sortedObjects := make([]*ObjectMapping, len(bucketObjects))
	copy(sortedObjects, bucketObjects)
	sort.Slice(sortedObjects, func(i, j int) bool {
		return sortedObjects[i].S3Key < sortedObjects[j].S3Key
	})
	
	results := make([]*ObjectMapping, 0)
	startIndex := 0
	
	// Find starting position if marker is provided
	if marker != "" {
		for i, mapping := range sortedObjects {
			if mapping.S3Key > marker {
				startIndex = i
				break
			}
		}
	}
	
	// Collect results up to limit
	for i := startIndex; i < len(sortedObjects); i++ {
		results = append(results, sortedObjects[i].Clone())
		if limit > 0 && len(results) >= limit {
			break
		}
	}
	
	// Update global statistics
	m.stats.TotalQueries++
	
	return results, nil
}

// CreateBucket creates a new bucket
func (m *MemoryMetadataStore) CreateBucket(ctx context.Context, bucket string, metadata *BucketMetadata) error {
	if err := metadata.Validate(); err != nil {
		return fmt.Errorf("invalid bucket metadata: %w", err)
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	if _, exists := m.buckets[bucket]; exists {
		return fmt.Errorf("bucket already exists: %s", bucket)
	}
	
	m.buckets[bucket] = metadata
	m.bucketIndex[bucket] = make([]*ObjectMapping, 0)
	
	// Update global statistics
	m.stats.TotalBuckets++
	m.updateStats()
	
	return nil
}

// GetBucket retrieves bucket metadata
func (m *MemoryMetadataStore) GetBucket(ctx context.Context, bucket string) (*BucketMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	metadata, exists := m.buckets[bucket]
	if !exists {
		return nil, fmt.Errorf("bucket not found: %s", bucket)
	}
	
	// Clone the metadata
	clone := *metadata
	if metadata.Tags != nil {
		clone.Tags = make(map[string]string)
		for k, v := range metadata.Tags {
			clone.Tags[k] = v
		}
	}
	
	return &clone, nil
}

// DeleteBucket deletes a bucket
func (m *MemoryMetadataStore) DeleteBucket(ctx context.Context, bucket string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	if _, exists := m.buckets[bucket]; !exists {
		return fmt.Errorf("bucket not found: %s", bucket)
	}
	
	// Check if bucket is empty
	if bucketObjects, exists := m.bucketIndex[bucket]; exists && len(bucketObjects) > 0 {
		return fmt.Errorf("bucket not empty: %s", bucket)
	}
	
	delete(m.buckets, bucket)
	delete(m.bucketIndex, bucket)
	
	// Update global statistics
	m.stats.TotalBuckets--
	m.updateStats()
	
	return nil
}

// ListBuckets lists all buckets
func (m *MemoryMetadataStore) ListBuckets(ctx context.Context) ([]*BucketMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	results := make([]*BucketMetadata, 0, len(m.buckets))
	
	for _, metadata := range m.buckets {
		// Clone the metadata
		clone := *metadata
		if metadata.Tags != nil {
			clone.Tags = make(map[string]string)
			for k, v := range metadata.Tags {
				clone.Tags[k] = v
			}
		}
		results = append(results, &clone)
	}
	
	// Sort by bucket name
	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})
	
	return results, nil
}

// GetStats returns metadata store statistics
func (m *MemoryMetadataStore) GetStats(ctx context.Context) (*MetadataStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	m.updateStats()
	
	// Clone stats
	stats := *m.stats
	return &stats, nil
}

// GetBucketStats returns statistics for a specific bucket
func (m *MemoryMetadataStore) GetBucketStats(ctx context.Context, bucket string) (*BucketStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	bucketMeta, exists := m.buckets[bucket]
	if !exists {
		return nil, fmt.Errorf("bucket not found: %s", bucket)
	}
	
	bucketObjects, exists := m.bucketIndex[bucket]
	if !exists {
		bucketObjects = []*ObjectMapping{}
	}
	
	stats := &BucketStats{
		BucketName:  bucket,
		ObjectCount: int64(len(bucketObjects)),
		CreatedAt:   bucketMeta.CreatedAt,
	}
	
	// Calculate statistics
	var totalSize int64
	var totalAccesses int64
	var pinnedObjects int64
	var pendingPins int64
	var failedPins int64
	
	for _, obj := range bucketObjects {
		totalSize += obj.Size
		totalAccesses += obj.AccessCount
		
		switch obj.PinStatus {
		case PinStatusPinned:
			pinnedObjects++
		case PinStatusPending:
			pendingPins++
		case PinStatusFailed:
			failedPins++
		}
		
		if stats.LastAccess.Before(obj.AccessedAt) {
			stats.LastAccess = obj.AccessedAt
		}
	}
	
	stats.TotalSize = totalSize
	stats.TotalAccesses = totalAccesses
	stats.PinnedObjects = pinnedObjects
	stats.PendingPins = pendingPins
	stats.FailedPins = failedPins
	
	if stats.ObjectCount > 0 {
		stats.AverageSize = float64(totalSize) / float64(stats.ObjectCount)
	}
	
	return stats, nil
}

// Compact performs compaction (no-op for memory store)
func (m *MemoryMetadataStore) Compact(ctx context.Context) error {
	// No-op for memory store
	return nil
}

// Backup creates a backup (no-op for memory store)
func (m *MemoryMetadataStore) Backup(ctx context.Context, path string) error {
	// TODO: Implement JSON export for memory store
	return fmt.Errorf("backup not implemented for memory store")
}

// Restore restores from backup (no-op for memory store)
func (m *MemoryMetadataStore) Restore(ctx context.Context, path string) error {
	// TODO: Implement JSON import for memory store
	return fmt.Errorf("restore not implemented for memory store")
}

// Helper methods

// getObjectKey creates a composite key for object storage
func (m *MemoryMetadataStore) getObjectKey(bucket, s3Key string) string {
	return fmt.Sprintf("%s/%s", bucket, s3Key)
}

// updateIndexes updates all indexes for a mapping
func (m *MemoryMetadataStore) updateIndexes(mapping *ObjectMapping) {
	// Update CID index
	if mappings, exists := m.cidIndex[mapping.CID]; exists {
		// Check if mapping already exists
		found := false
		for i, existing := range mappings {
			if existing.Bucket == mapping.Bucket && existing.S3Key == mapping.S3Key {
				mappings[i] = mapping
				found = true
				break
			}
		}
		if !found {
			m.cidIndex[mapping.CID] = append(mappings, mapping)
		}
	} else {
		m.cidIndex[mapping.CID] = []*ObjectMapping{mapping}
	}
	
	// Update bucket index
	if mappings, exists := m.bucketIndex[mapping.Bucket]; exists {
		// Check if mapping already exists
		found := false
		for i, existing := range mappings {
			if existing.S3Key == mapping.S3Key {
				mappings[i] = mapping
				found = true
				break
			}
		}
		if !found {
			m.bucketIndex[mapping.Bucket] = append(mappings, mapping)
		}
	} else {
		m.bucketIndex[mapping.Bucket] = []*ObjectMapping{mapping}
	}
}

// removeFromIndexes removes a mapping from all indexes
func (m *MemoryMetadataStore) removeFromIndexes(mapping *ObjectMapping) {
	// Remove from CID index
	if mappings, exists := m.cidIndex[mapping.CID]; exists {
		for i, existing := range mappings {
			if existing.Bucket == mapping.Bucket && existing.S3Key == mapping.S3Key {
				m.cidIndex[mapping.CID] = append(mappings[:i], mappings[i+1:]...)
				if len(m.cidIndex[mapping.CID]) == 0 {
					delete(m.cidIndex, mapping.CID)
				}
				break
			}
		}
	}
	
	// Remove from bucket index
	if mappings, exists := m.bucketIndex[mapping.Bucket]; exists {
		for i, existing := range mappings {
			if existing.S3Key == mapping.S3Key {
				m.bucketIndex[mapping.Bucket] = append(mappings[:i], mappings[i+1:]...)
				break
			}
		}
	}
}

// updateBucketStats updates bucket statistics
func (m *MemoryMetadataStore) updateBucketStats(bucket string, countDelta, sizeDelta int64) {
	if bucketMeta, exists := m.buckets[bucket]; exists {
		bucketMeta.ObjectCount += countDelta
		bucketMeta.TotalSize += sizeDelta
		bucketMeta.UpdatedAt = time.Now()
	}
}

// updateStats updates global statistics
func (m *MemoryMetadataStore) updateStats() {
	m.stats.TotalObjects = int64(len(m.objects))
	m.stats.TotalBuckets = int64(len(m.buckets))
	
	var totalSize int64
	var pinnedObjects int64
	var pendingPins int64
	var failedPins int64
	
	for _, mapping := range m.objects {
		totalSize += mapping.Size
		
		switch mapping.PinStatus {
		case PinStatusPinned:
			pinnedObjects++
		case PinStatusPending:
			pendingPins++
		case PinStatusFailed:
			failedPins++
		}
	}
	
	m.stats.TotalSize = totalSize
	m.stats.PinnedObjects = pinnedObjects
	m.stats.PendingPins = pendingPins
	m.stats.FailedPins = failedPins
	
	if m.stats.TotalObjects > 0 {
		m.stats.AverageObjectSize = float64(totalSize) / float64(m.stats.TotalObjects)
	}
	
	// Memory store specific stats
	m.stats.DatabaseSize = int64(len(m.objects)*1024 + len(m.buckets)*512) // Rough estimate
	m.stats.IndexSize = int64(len(m.cidIndex)*64 + len(m.bucketIndex)*64)  // Rough estimate
	m.stats.CompressionRatio = 1.0                                         // No compression
	m.stats.FragmentationRatio = 0.0                                       // No fragmentation
	m.stats.CacheHitRatio = 1.0                                            // Always in memory
	m.stats.IndexEfficiency = 1.0                                          // Perfect indexes
	m.stats.HealthScore = 1.0                                              // Always healthy
	m.stats.ErrorRate = 0.0                                                // No errors in memory
}

// GetMappingByCID returns a mapping by CID
func (m *MemoryMetadataStore) GetMappingByCID(cid string) (*ObjectMapping, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	for _, mapping := range m.objects {
		if mapping.CID == cid {
			// Clone the mapping to avoid race conditions
			clone := *mapping
			if mapping.UserMetadata != nil {
				clone.UserMetadata = make(map[string]string)
				for k, v := range mapping.UserMetadata {
					clone.UserMetadata[k] = v
				}
			}
			return &clone, nil
		}
	}
	
	return nil, fmt.Errorf("mapping not found for CID: %s", cid)
}

// GetPinsByNodes returns pins for specific nodes
func (m *MemoryMetadataStore) GetPinsByNodes(nodeIDs []string) ([]PinInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	var pins []PinInfo
	nodeSet := make(map[string]bool)
	for _, nodeID := range nodeIDs {
		nodeSet[nodeID] = true
	}
	
	for _, mapping := range m.objects {
		if mapping.PinStatus == PinStatusPinned {
			// Check if any of the pinned nodes match our requested nodes
			for _, pinnedNode := range mapping.PinnedNodes {
				if nodeSet[pinnedNode] {
					pin := PinInfo{
						CID:    mapping.CID,
						Name:   mapping.S3Key,
						Status: "pinned",
						PeerMap: map[string]string{
							pinnedNode: "pinned",
						},
						Metadata: map[string]string{
							"bucket": mapping.Bucket,
							"s3_key": mapping.S3Key,
						},
					}
					pins = append(pins, pin)
					break // Only add once per mapping
				}
			}
		}
	}
	
	return pins, nil
}

// GetAllMappings returns all object mappings
func (m *MemoryMetadataStore) GetAllMappings(ctx context.Context) ([]*ObjectMapping, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	mappings := make([]*ObjectMapping, 0, len(m.objects))
	for _, mapping := range m.objects {
		// Clone the mapping to avoid race conditions
		clone := *mapping
		if mapping.UserMetadata != nil {
			clone.UserMetadata = make(map[string]string)
			for k, v := range mapping.UserMetadata {
				clone.UserMetadata[k] = v
			}
		}
		mappings = append(mappings, &clone)
	}
	
	return mappings, nil
}

// GetMappingsModifiedSince returns mappings modified since the given time
func (m *MemoryMetadataStore) GetMappingsModifiedSince(ctx context.Context, since time.Time) ([]*ObjectMapping, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	var mappings []*ObjectMapping
	for _, mapping := range m.objects {
		if mapping.UpdatedAt.After(since) {
			// Clone the mapping to avoid race conditions
			clone := *mapping
			if mapping.UserMetadata != nil {
				clone.UserMetadata = make(map[string]string)
				for k, v := range mapping.UserMetadata {
					clone.UserMetadata[k] = v
				}
			}
			mappings = append(mappings, &clone)
		}
	}
	
	return mappings, nil
}

// GetTotalPinCount returns the total number of pins across all objects
func (m *MemoryMetadataStore) GetTotalPinCount() (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.shutdown {
		return 0, fmt.Errorf("metadata store is shutdown")
	}
	
	var totalPins int64
	for _, mapping := range m.objects {
		totalPins += int64(mapping.ReplicationCount)
	}
	
	return totalPins, nil
}