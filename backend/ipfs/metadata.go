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
	"encoding/json"
	"fmt"
	"time"
)

// MetadataStore defines the interface for storing and retrieving S3 to IPFS mappings
type MetadataStore interface {
	// Object mapping operations
	StoreMapping(ctx context.Context, mapping *ObjectMapping) error
	GetMapping(ctx context.Context, s3Key, bucket string) (*ObjectMapping, error)
	DeleteMapping(ctx context.Context, s3Key, bucket string) error
	UpdateMapping(ctx context.Context, mapping *ObjectMapping) error
	
	// Batch operations for performance
	StoreMappingBatch(ctx context.Context, mappings []*ObjectMapping) error
	GetMappingBatch(ctx context.Context, keys []*S3Key) ([]*ObjectMapping, error)
	DeleteMappingBatch(ctx context.Context, keys []*S3Key) error
	
	// Search and indexing operations
	SearchByCID(ctx context.Context, cid string) ([]*ObjectMapping, error)
	SearchByPrefix(ctx context.Context, bucket, prefix string, limit int) ([]*ObjectMapping, error)
	ListObjectsInBucket(ctx context.Context, bucket string, marker string, limit int) ([]*ObjectMapping, error)
	
	// Bucket operations
	CreateBucket(ctx context.Context, bucket string, metadata *BucketMetadata) error
	GetBucket(ctx context.Context, bucket string) (*BucketMetadata, error)
	DeleteBucket(ctx context.Context, bucket string) error
	ListBuckets(ctx context.Context) ([]*BucketMetadata, error)
	
	// Statistics and monitoring
	GetStats(ctx context.Context) (*MetadataStats, error)
	GetBucketStats(ctx context.Context, bucket string) (*BucketStats, error)
	GetTotalPinCount() (int64, error)
	
	// Fault tolerance operations
	GetMappingByCID(cid string) (*ObjectMapping, error)
	GetPinsByNodes(nodeIDs []string) ([]PinInfo, error)
	GetAllMappings(ctx context.Context) ([]*ObjectMapping, error)
	GetMappingsModifiedSince(ctx context.Context, since time.Time) ([]*ObjectMapping, error)
	
	// Maintenance operations
	Compact(ctx context.Context) error
	Backup(ctx context.Context, path string) error
	Restore(ctx context.Context, path string) error
	
	// Lifecycle management
	Initialize(ctx context.Context) error
	Shutdown(ctx context.Context) error
	HealthCheck(ctx context.Context) error
}

// ObjectMapping represents the mapping between S3 objects and IPFS CIDs
type ObjectMapping struct {
	// Primary key components
	S3Key  string `json:"s3_key" db:"s3_key"`
	Bucket string `json:"bucket" db:"bucket"`
	
	// IPFS data
	CID  string `json:"cid" db:"cid"`
	Size int64  `json:"size" db:"size"`
	
	// S3 metadata
	ContentType     string            `json:"content_type" db:"content_type"`
	ContentEncoding string            `json:"content_encoding" db:"content_encoding"`
	ContentLanguage string            `json:"content_language" db:"content_language"`
	CacheControl    string            `json:"cache_control" db:"cache_control"`
	Expires         *time.Time        `json:"expires,omitempty" db:"expires"`
	UserMetadata    map[string]string `json:"user_metadata" db:"user_metadata"`
	Tags            map[string]string `json:"tags" db:"tags"`
	
	// Object versioning
	VersionID    string `json:"version_id" db:"version_id"`
	IsLatest     bool   `json:"is_latest" db:"is_latest"`
	DeleteMarker bool   `json:"delete_marker" db:"delete_marker"`
	
	// Pin information
	PinStatus        PinStatus `json:"pin_status" db:"pin_status"`
	ReplicationCount int       `json:"replication_count" db:"replication_count"`
	PinnedNodes      []string  `json:"pinned_nodes" db:"pinned_nodes"`
	
	// Access control
	ACL   string `json:"acl" db:"acl"`
	Owner string `json:"owner" db:"owner"`
	
	// Timestamps
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
	AccessedAt time.Time  `json:"accessed_at" db:"accessed_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	
	// Analytics data
	AccessCount      int64             `json:"access_count" db:"access_count"`
	TransferCount    int64             `json:"transfer_count" db:"transfer_count"`
	LastAccessIP     string            `json:"last_access_ip" db:"last_access_ip"`
	GeographicAccess map[string]int64  `json:"geographic_access" db:"geographic_access"`
	
	// Checksum and integrity
	ETag     string `json:"etag" db:"etag"`
	MD5Hash  string `json:"md5_hash" db:"md5_hash"`
	SHA256   string `json:"sha256" db:"sha256"`
	Checksum string `json:"checksum" db:"checksum"`
}

// BucketMetadata represents metadata for S3 buckets
type BucketMetadata struct {
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	
	// Bucket configuration
	Region           string `json:"region" db:"region"`
	StorageClass     string `json:"storage_class" db:"storage_class"`
	VersioningStatus string `json:"versioning_status" db:"versioning_status"`
	
	// Access control
	ACL   string `json:"acl" db:"acl"`
	Owner string `json:"owner" db:"owner"`
	
	// Policies and configuration
	Policy                 string            `json:"policy" db:"policy"`
	CORS                   string            `json:"cors" db:"cors"`
	LifecycleConfiguration string            `json:"lifecycle_config" db:"lifecycle_config"`
	Tags                   map[string]string `json:"tags" db:"tags"`
	
	// Statistics
	ObjectCount int64 `json:"object_count" db:"object_count"`
	TotalSize   int64 `json:"total_size" db:"total_size"`
	
	// Replication settings
	DefaultReplicationMin int `json:"default_replication_min" db:"default_replication_min"`
	DefaultReplicationMax int `json:"default_replication_max" db:"default_replication_max"`
}

// S3Key represents a composite key for S3 objects
type S3Key struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
}

// PinStatus represents the status of a pin operation
type PinStatus int

const (
	PinStatusUnknown PinStatus = iota
	PinStatusPending
	PinStatusPinned
	PinStatusFailed
	PinStatusUnpinning
	PinStatusUnpinned
	PinStatusError
)

// String returns the string representation of PinStatus
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
	case PinStatusError:
		return "error"
	default:
		return "unknown"
	}
}

// parsePinStatus converts a string to PinStatus
func parsePinStatus(s string) PinStatus {
	switch s {
	case "pending":
		return PinStatusPending
	case "pinned":
		return PinStatusPinned
	case "failed":
		return PinStatusFailed
	case "unpinning":
		return PinStatusUnpinning
	case "unpinned":
		return PinStatusUnpinned
	case "error":
		return PinStatusError
	default:
		return PinStatusUnknown
	}
}

// MetadataStats represents statistics about the metadata store
type MetadataStats struct {
	// Object statistics
	TotalObjects     int64 `json:"total_objects"`
	TotalBuckets     int64 `json:"total_buckets"`
	TotalSize        int64 `json:"total_size"`
	AverageObjectSize float64 `json:"average_object_size"`
	
	// Pin statistics
	PinnedObjects   int64 `json:"pinned_objects"`
	PendingPins     int64 `json:"pending_pins"`
	FailedPins      int64 `json:"failed_pins"`
	TotalPinCount   int64 `json:"total_pin_count"`
	
	// Performance statistics
	AverageQueryTime    time.Duration `json:"average_query_time"`
	TotalQueries        int64         `json:"total_queries"`
	CacheHitRatio       float64       `json:"cache_hit_ratio"`
	IndexEfficiency     float64       `json:"index_efficiency"`
	
	// Storage statistics
	DatabaseSize        int64   `json:"database_size"`
	IndexSize           int64   `json:"index_size"`
	CompressionRatio    float64 `json:"compression_ratio"`
	FragmentationRatio  float64 `json:"fragmentation_ratio"`
	
	// Replication statistics
	AverageReplication  float64 `json:"average_replication"`
	UnderReplicated     int64   `json:"under_replicated"`
	OverReplicated      int64   `json:"over_replicated"`
	
	// Time-based statistics
	ObjectsCreatedToday int64     `json:"objects_created_today"`
	LastBackup          time.Time `json:"last_backup"`
	LastCompaction      time.Time `json:"last_compaction"`
	
	// Health indicators
	HealthScore         float64   `json:"health_score"`
	LastHealthCheck     time.Time `json:"last_health_check"`
	ErrorRate           float64   `json:"error_rate"`
}

// BucketStats represents statistics for a specific bucket
type BucketStats struct {
	BucketName   string `json:"bucket_name"`
	ObjectCount  int64  `json:"object_count"`
	TotalSize    int64  `json:"total_size"`
	AverageSize  float64 `json:"average_size"`
	
	// Pin statistics
	PinnedObjects int64 `json:"pinned_objects"`
	PendingPins   int64 `json:"pending_pins"`
	FailedPins    int64 `json:"failed_pins"`
	
	// Access statistics
	TotalAccesses     int64     `json:"total_accesses"`
	LastAccess        time.Time `json:"last_access"`
	PopularObjects    []string  `json:"popular_objects"`
	
	// Storage distribution
	StorageClasses    map[string]int64 `json:"storage_classes"`
	ReplicationLevels map[int]int64    `json:"replication_levels"`
	
	// Time-based statistics
	CreatedAt        time.Time `json:"created_at"`
	LastModified     time.Time `json:"last_modified"`
	ObjectsThisWeek  int64     `json:"objects_this_week"`
	ObjectsThisMonth int64     `json:"objects_this_month"`
}

// MetadataStoreConfig holds configuration for metadata store implementations
type MetadataStoreConfig struct {
	// Database type and connection
	Type      string   `json:"type"`
	Endpoints []string `json:"endpoints"`
	Database  string   `json:"database"`
	Keyspace  string   `json:"keyspace"`
	
	// Authentication
	Username string `json:"username"`
	Password string `json:"password"`
	
	// Connection settings
	ConnectTimeout    time.Duration `json:"connect_timeout"`
	RequestTimeout    time.Duration `json:"request_timeout"`
	MaxConnections    int           `json:"max_connections"`
	MaxIdleConns      int           `json:"max_idle_conns"`
	ConnMaxLifetime   time.Duration `json:"conn_max_lifetime"`
	
	// Performance settings
	BatchSize         int           `json:"batch_size"`
	QueryTimeout      time.Duration `json:"query_timeout"`
	BulkInsertSize    int           `json:"bulk_insert_size"`
	IndexCacheSize    int64         `json:"index_cache_size"`
	
	// Consistency settings
	ConsistencyLevel  string `json:"consistency_level"`
	ReplicationFactor int    `json:"replication_factor"`
	
	// Compression and optimization
	CompressionEnabled bool   `json:"compression_enabled"`
	CompressionType    string `json:"compression_type"`
	
	// Backup and maintenance
	BackupEnabled     bool          `json:"backup_enabled"`
	BackupInterval    time.Duration `json:"backup_interval"`
	CompactionEnabled bool          `json:"compaction_enabled"`
	CompactionInterval time.Duration `json:"compaction_interval"`
	
	// Monitoring
	MetricsEnabled bool `json:"metrics_enabled"`
	LogLevel       string `json:"log_level"`
}

// NewObjectMapping creates a new ObjectMapping with default values
func NewObjectMapping(bucket, s3Key, cid string, size int64) *ObjectMapping {
	now := time.Now()
	return &ObjectMapping{
		Bucket:           bucket,
		S3Key:            s3Key,
		CID:              cid,
		Size:             size,
		PinStatus:        PinStatusPending,
		ReplicationCount: 0,
		PinnedNodes:      []string{},
		UserMetadata:     make(map[string]string),
		Tags:             make(map[string]string),
		GeographicAccess: make(map[string]int64),
		CreatedAt:        now,
		UpdatedAt:        now,
		AccessedAt:       now,
		IsLatest:         true,
		DeleteMarker:     false,
		AccessCount:      0,
		TransferCount:    0,
	}
}

// NewBucketMetadata creates a new BucketMetadata with default values
func NewBucketMetadata(name, owner string) *BucketMetadata {
	now := time.Now()
	return &BucketMetadata{
		Name:                  name,
		Owner:                 owner,
		CreatedAt:             now,
		UpdatedAt:             now,
		Region:                "us-east-1",
		StorageClass:          "STANDARD",
		VersioningStatus:      "Suspended",
		ACL:                   "private",
		Tags:                  make(map[string]string),
		ObjectCount:           0,
		TotalSize:             0,
		DefaultReplicationMin: 1,
		DefaultReplicationMax: 3,
	}
}

// Validate validates the ObjectMapping for consistency
func (om *ObjectMapping) Validate() error {
	if om.Bucket == "" {
		return fmt.Errorf("bucket name cannot be empty")
	}
	if om.S3Key == "" {
		return fmt.Errorf("S3 key cannot be empty")
	}
	if om.CID == "" {
		return fmt.Errorf("CID cannot be empty")
	}
	if om.Size < 0 {
		return fmt.Errorf("size cannot be negative")
	}
	if om.ReplicationCount < 0 {
		return fmt.Errorf("replication count cannot be negative")
	}
	if om.AccessCount < 0 {
		return fmt.Errorf("access count cannot be negative")
	}
	return nil
}

// Validate validates the BucketMetadata for consistency
func (bm *BucketMetadata) Validate() error {
	if bm.Name == "" {
		return fmt.Errorf("bucket name cannot be empty")
	}
	if bm.Owner == "" {
		return fmt.Errorf("bucket owner cannot be empty")
	}
	if bm.ObjectCount < 0 {
		return fmt.Errorf("object count cannot be negative")
	}
	if bm.TotalSize < 0 {
		return fmt.Errorf("total size cannot be negative")
	}
	if bm.DefaultReplicationMin <= 0 {
		return fmt.Errorf("default replication min must be positive")
	}
	if bm.DefaultReplicationMax < bm.DefaultReplicationMin {
		return fmt.Errorf("default replication max must be >= min")
	}
	return nil
}

// ToJSON converts ObjectMapping to JSON
func (om *ObjectMapping) ToJSON() ([]byte, error) {
	return json.Marshal(om)
}

// FromJSON populates ObjectMapping from JSON
func (om *ObjectMapping) FromJSON(data []byte) error {
	return json.Unmarshal(data, om)
}

// ToJSON converts BucketMetadata to JSON
func (bm *BucketMetadata) ToJSON() ([]byte, error) {
	return json.Marshal(bm)
}

// FromJSON populates BucketMetadata from JSON
func (bm *BucketMetadata) FromJSON(data []byte) error {
	return json.Unmarshal(data, bm)
}

// Clone creates a deep copy of ObjectMapping
func (om *ObjectMapping) Clone() *ObjectMapping {
	clone := *om
	
	// Deep copy maps
	if om.UserMetadata != nil {
		clone.UserMetadata = make(map[string]string)
		for k, v := range om.UserMetadata {
			clone.UserMetadata[k] = v
		}
	}
	
	if om.Tags != nil {
		clone.Tags = make(map[string]string)
		for k, v := range om.Tags {
			clone.Tags[k] = v
		}
	}
	
	if om.GeographicAccess != nil {
		clone.GeographicAccess = make(map[string]int64)
		for k, v := range om.GeographicAccess {
			clone.GeographicAccess[k] = v
		}
	}
	
	// Deep copy slices
	if om.PinnedNodes != nil {
		clone.PinnedNodes = make([]string, len(om.PinnedNodes))
		copy(clone.PinnedNodes, om.PinnedNodes)
	}
	
	return &clone
}

// UpdateAccessStats updates access-related statistics
func (om *ObjectMapping) UpdateAccessStats(clientIP, region string) {
	now := time.Now()
	om.AccessedAt = now
	om.UpdatedAt = now
	om.AccessCount++
	om.LastAccessIP = clientIP
	
	if om.GeographicAccess == nil {
		om.GeographicAccess = make(map[string]int64)
	}
	om.GeographicAccess[region]++
}

// UpdatePinStatus updates the pin status and related metadata
func (om *ObjectMapping) UpdatePinStatus(status PinStatus, nodes []string) {
	om.PinStatus = status
	om.UpdatedAt = time.Now()
	
	if nodes != nil {
		om.PinnedNodes = make([]string, len(nodes))
		copy(om.PinnedNodes, nodes)
		om.ReplicationCount = len(nodes)
	}
}

// IsExpired checks if the object has expired based on ExpiresAt
func (om *ObjectMapping) IsExpired() bool {
	if om.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*om.ExpiresAt)
}

// GetPrimaryKey returns the primary key for the object mapping
func (om *ObjectMapping) GetPrimaryKey() string {
	return fmt.Sprintf("%s/%s", om.Bucket, om.S3Key)
}

// GetShardKey returns a shard key for distributing data across partitions
func (om *ObjectMapping) GetShardKey() string {
	// Use bucket name for sharding to keep bucket objects together
	return om.Bucket
}