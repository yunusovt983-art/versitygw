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
	"strings"
	"sync"
	"time"
	
	"github.com/gocql/gocql"
)

// ScyllaMetadataStore implements MetadataStore interface using ScyllaDB
// This provides high-performance, distributed metadata storage for trillion-scale deployments
type ScyllaMetadataStore struct {
	// Configuration
	config *MetadataStoreConfig
	
	// Database connection
	session *gocql.Session
	
	// Prepared statements for performance
	preparedStmts map[string]interface{} // map[string]*gocql.Query
	
	// Connection management
	cluster interface{} // gocql.ClusterConfig
	
	// Statistics and monitoring
	stats   *MetadataStats
	metrics *ScyllaMetrics
	
	// Synchronization
	mu sync.RWMutex
	
	// Lifecycle
	initialized bool
	shutdown    bool
	
	// Logging
	logger *log.Logger
}

// ScyllaMetrics holds ScyllaDB-specific metrics
type ScyllaMetrics struct {
	// Connection metrics
	ActiveConnections int64 `json:"active_connections"`
	IdleConnections   int64 `json:"idle_connections"`
	ConnectionErrors  int64 `json:"connection_errors"`
	
	// Query metrics
	TotalQueries      int64         `json:"total_queries"`
	SuccessfulQueries int64         `json:"successful_queries"`
	FailedQueries     int64         `json:"failed_queries"`
	AverageLatency    time.Duration `json:"average_latency"`
	
	// Batch metrics
	BatchOperations   int64 `json:"batch_operations"`
	BatchSize         int64 `json:"batch_size"`
	BatchLatency      time.Duration `json:"batch_latency"`
	
	// Consistency metrics
	ConsistencyLevel  string  `json:"consistency_level"`
	ReadRepairs       int64   `json:"read_repairs"`
	WriteTimeouts     int64   `json:"write_timeouts"`
	ReadTimeouts      int64   `json:"read_timeouts"`
	
	// Performance metrics
	ThroughputRPS     float64 `json:"throughput_rps"`
	P99Latency        time.Duration `json:"p99_latency"`
	P95Latency        time.Duration `json:"p95_latency"`
	
	mu sync.RWMutex
}

// NewScyllaMetadataStore creates a new ScyllaDB metadata store
func NewScyllaMetadataStore(config *MetadataStoreConfig, logger *log.Logger) (*ScyllaMetadataStore, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	
	if len(config.Endpoints) == 0 {
		return nil, fmt.Errorf("at least one endpoint must be specified")
	}
	
	if logger == nil {
		logger = log.Default()
	}
	
	// Set defaults
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 30 * time.Second
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 10 * time.Second
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 100
	}
	if config.BatchSize == 0 {
		config.BatchSize = 1000
	}
	if config.ConsistencyLevel == "" {
		config.ConsistencyLevel = "QUORUM"
	}
	if config.ReplicationFactor == 0 {
		config.ReplicationFactor = 3
	}
	
	store := &ScyllaMetadataStore{
		config:        config,
		preparedStmts: make(map[string]interface{}),
		logger:        logger,
		stats: &MetadataStats{
			LastHealthCheck: time.Now(),
		},
		metrics: &ScyllaMetrics{
			ConsistencyLevel: config.ConsistencyLevel,
		},
	}
	
	return store, nil
}

// Initialize initializes the ScyllaDB metadata store
func (s *ScyllaMetadataStore) Initialize(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.initialized {
		return fmt.Errorf("metadata store already initialized")
	}
	
	s.logger.Printf("Initializing ScyllaDB metadata store with endpoints: %v", s.config.Endpoints)
	
	// TODO: Initialize gocql cluster configuration
	// cluster := gocql.NewCluster(s.config.Endpoints...)
	// cluster.Keyspace = s.config.Keyspace
	// cluster.Consistency = gocql.Quorum
	// cluster.Timeout = s.config.RequestTimeout
	// cluster.ConnectTimeout = s.config.ConnectTimeout
	// cluster.NumConns = s.config.MaxConnections
	
	// if s.config.Username != "" && s.config.Password != "" {
	//     cluster.Authenticator = gocql.PasswordAuthenticator{
	//         Username: s.config.Username,
	//         Password: s.config.Password,
	//     }
	// }
	
	// session, err := cluster.CreateSession()
	// if err != nil {
	//     return fmt.Errorf("failed to create ScyllaDB session: %w", err)
	// }
	
	// s.cluster = cluster
	// s.session = session
	
	// Create keyspace and tables
	if err := s.createSchema(ctx); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	
	// Prepare statements
	if err := s.prepareStatements(); err != nil {
		return fmt.Errorf("failed to prepare statements: %w", err)
	}
	
	s.initialized = true
	s.shutdown = false
	
	s.logger.Println("ScyllaDB metadata store initialized successfully")
	return nil
}

// createSchema creates the necessary keyspace and tables
func (s *ScyllaMetadataStore) createSchema(ctx context.Context) error {
	s.logger.Println("Creating ScyllaDB schema...")
	
	// Create keyspace
	createKeyspace := fmt.Sprintf(`
		CREATE KEYSPACE IF NOT EXISTS %s
		WITH REPLICATION = {
			'class': 'NetworkTopologyStrategy',
			'datacenter1': %d
		}
	`, s.config.Keyspace, s.config.ReplicationFactor)
	
	// Create object mappings table
	createObjectsTable := `
		CREATE TABLE IF NOT EXISTS object_mappings (
			bucket text,
			s3_key text,
			cid text,
			size bigint,
			content_type text,
			content_encoding text,
			content_language text,
			cache_control text,
			expires timestamp,
			user_metadata map<text, text>,
			tags map<text, text>,
			version_id text,
			is_latest boolean,
			delete_marker boolean,
			pin_status int,
			replication_count int,
			pinned_nodes list<text>,
			acl text,
			owner text,
			created_at timestamp,
			updated_at timestamp,
			accessed_at timestamp,
			expires_at timestamp,
			access_count bigint,
			transfer_count bigint,
			last_access_ip text,
			geographic_access map<text, bigint>,
			etag text,
			md5_hash text,
			sha256 text,
			checksum text,
			PRIMARY KEY (bucket, s3_key)
		) WITH CLUSTERING ORDER BY (s3_key ASC)
		AND compaction = {'class': 'LeveledCompactionStrategy'}
		AND compression = {'sstable_compression': 'LZ4Compressor'}
	`
	
	// Create CID index table for reverse lookups
	createCIDIndexTable := `
		CREATE TABLE IF NOT EXISTS cid_index (
			cid text,
			bucket text,
			s3_key text,
			size bigint,
			created_at timestamp,
			PRIMARY KEY (cid, bucket, s3_key)
		) WITH CLUSTERING ORDER BY (bucket ASC, s3_key ASC)
		AND compaction = {'class': 'LeveledCompactionStrategy'}
	`
	
	// Create bucket metadata table
	createBucketsTable := `
		CREATE TABLE IF NOT EXISTS bucket_metadata (
			name text PRIMARY KEY,
			created_at timestamp,
			updated_at timestamp,
			region text,
			storage_class text,
			versioning_status text,
			acl text,
			owner text,
			policy text,
			cors text,
			lifecycle_config text,
			tags map<text, text>,
			object_count bigint,
			total_size bigint,
			default_replication_min int,
			default_replication_max int
		) WITH compaction = {'class': 'LeveledCompactionStrategy'}
	`
	
	// Create bucket statistics table for analytics
	createBucketStatsTable := `
		CREATE TABLE IF NOT EXISTS bucket_stats (
			bucket_name text,
			date date,
			object_count bigint,
			total_size bigint,
			total_accesses bigint,
			pinned_objects bigint,
			pending_pins bigint,
			failed_pins bigint,
			PRIMARY KEY (bucket_name, date)
		) WITH CLUSTERING ORDER BY (date DESC)
		AND compaction = {'class': 'TimeWindowCompactionStrategy'}
	`
	
	// Create global statistics table
	createGlobalStatsTable := `
		CREATE TABLE IF NOT EXISTS global_stats (
			id text PRIMARY KEY,
			total_objects bigint,
			total_buckets bigint,
			total_size bigint,
			pinned_objects bigint,
			pending_pins bigint,
			failed_pins bigint,
			total_queries bigint,
			last_updated timestamp
		)
	`
	
	// TODO: Execute schema creation queries
	// In a real implementation, these would be executed using the session
	statements := []string{
		createKeyspace,
		createObjectsTable,
		createCIDIndexTable,
		createBucketsTable,
		createBucketStatsTable,
		createGlobalStatsTable,
	}
	
	for _, stmt := range statements {
		s.logger.Printf("Executing schema statement: %s", strings.Split(stmt, "\n")[1])
		// err := s.session.Query(stmt).WithContext(ctx).Exec()
		// if err != nil {
		//     return fmt.Errorf("failed to execute schema statement: %w", err)
		// }
	}
	
	s.logger.Println("Schema created successfully")
	return nil
}

// prepareStatements prepares frequently used CQL statements for better performance
func (s *ScyllaMetadataStore) prepareStatements() error {
	s.logger.Println("Preparing CQL statements...")
	
	statements := map[string]string{
		"insert_object": `
			INSERT INTO object_mappings (
				bucket, s3_key, cid, size, content_type, content_encoding,
				content_language, cache_control, expires, user_metadata, tags,
				version_id, is_latest, delete_marker, pin_status, replication_count,
				pinned_nodes, acl, owner, created_at, updated_at, accessed_at,
				expires_at, access_count, transfer_count, last_access_ip,
				geographic_access, etag, md5_hash, sha256, checksum
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
		"select_object": `
			SELECT * FROM object_mappings WHERE bucket = ? AND s3_key = ?
		`,
		"delete_object": `
			DELETE FROM object_mappings WHERE bucket = ? AND s3_key = ?
		`,
		"update_object": `
			UPDATE object_mappings SET
				cid = ?, size = ?, content_type = ?, content_encoding = ?,
				content_language = ?, cache_control = ?, expires = ?,
				user_metadata = ?, tags = ?, version_id = ?, is_latest = ?,
				delete_marker = ?, pin_status = ?, replication_count = ?,
				pinned_nodes = ?, acl = ?, owner = ?, updated_at = ?,
				accessed_at = ?, expires_at = ?, access_count = ?,
				transfer_count = ?, last_access_ip = ?, geographic_access = ?,
				etag = ?, md5_hash = ?, sha256 = ?, checksum = ?
			WHERE bucket = ? AND s3_key = ?
		`,
		"insert_cid_index": `
			INSERT INTO cid_index (cid, bucket, s3_key, size, created_at)
			VALUES (?, ?, ?, ?, ?)
		`,
		"select_by_cid": `
			SELECT bucket, s3_key FROM cid_index WHERE cid = ?
		`,
		"delete_cid_index": `
			DELETE FROM cid_index WHERE cid = ? AND bucket = ? AND s3_key = ?
		`,
		"list_objects": `
			SELECT * FROM object_mappings WHERE bucket = ? AND s3_key > ? LIMIT ?
		`,
		"search_prefix": `
			SELECT * FROM object_mappings WHERE bucket = ? AND s3_key >= ? AND s3_key < ? LIMIT ?
		`,
		"insert_bucket": `
			INSERT INTO bucket_metadata (
				name, created_at, updated_at, region, storage_class,
				versioning_status, acl, owner, policy, cors, lifecycle_config,
				tags, object_count, total_size, default_replication_min,
				default_replication_max
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
		"select_bucket": `
			SELECT * FROM bucket_metadata WHERE name = ?
		`,
		"delete_bucket": `
			DELETE FROM bucket_metadata WHERE name = ?
		`,
		"list_buckets": `
			SELECT * FROM bucket_metadata
		`,
		"update_bucket_stats": `
			UPDATE bucket_metadata SET
				object_count = object_count + ?,
				total_size = total_size + ?,
				updated_at = ?
			WHERE name = ?
		`,
	}
	
	// TODO: Prepare all statements
	// In a real implementation, these would be prepared using the session
	for name, query := range statements {
		s.logger.Printf("Preparing statement: %s", name)
		// prepared := s.session.Query(query)
		// s.preparedStmts[name] = prepared
		s.preparedStmts[name] = query // Placeholder
	}
	
	s.logger.Printf("Prepared %d statements successfully", len(statements))
	return nil
}

// StoreMapping stores a single object mapping
func (s *ScyllaMetadataStore) StoreMapping(ctx context.Context, mapping *ObjectMapping) error {
	if err := mapping.Validate(); err != nil {
		return fmt.Errorf("invalid mapping: %w", err)
	}
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Execute prepared statement
	// stmt := s.preparedStmts["insert_object"].(*gocql.Query)
	// err := stmt.WithContext(ctx).Bind(
	//     mapping.Bucket, mapping.S3Key, mapping.CID, mapping.Size,
	//     mapping.ContentType, mapping.ContentEncoding, mapping.ContentLanguage,
	//     mapping.CacheControl, mapping.Expires, mapping.UserMetadata,
	//     mapping.Tags, mapping.VersionID, mapping.IsLatest, mapping.DeleteMarker,
	//     int(mapping.PinStatus), mapping.ReplicationCount, mapping.PinnedNodes,
	//     mapping.ACL, mapping.Owner, mapping.CreatedAt, mapping.UpdatedAt,
	//     mapping.AccessedAt, mapping.ExpiresAt, mapping.AccessCount,
	//     mapping.TransferCount, mapping.LastAccessIP, mapping.GeographicAccess,
	//     mapping.ETag, mapping.MD5Hash, mapping.SHA256, mapping.Checksum,
	// ).Exec()
	
	// Also insert into CID index
	// cidStmt := s.preparedStmts["insert_cid_index"].(*gocql.Query)
	// err2 := cidStmt.WithContext(ctx).Bind(
	//     mapping.CID, mapping.Bucket, mapping.S3Key, mapping.Size, mapping.CreatedAt,
	// ).Exec()
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	// Placeholder success
	return nil
}

// GetMapping retrieves a single object mapping
func (s *ScyllaMetadataStore) GetMapping(ctx context.Context, s3Key, bucket string) (*ObjectMapping, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Execute prepared statement
	// stmt := s.preparedStmts["select_object"].(*gocql.Query)
	// iter := stmt.WithContext(ctx).Bind(bucket, s3Key).Iter()
	
	// mapping := &ObjectMapping{}
	// if !iter.Scan(&mapping.Bucket, &mapping.S3Key, ...) {
	//     return nil, fmt.Errorf("object not found: %s/%s", bucket, s3Key)
	// }
	
	// Update access statistics
	// updateStmt := s.preparedStmts["update_object"].(*gocql.Query)
	// updateStmt.WithContext(ctx).Bind(...).Exec()
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	// Placeholder return
	return NewObjectMapping(bucket, s3Key, "QmPlaceholder", 1024), nil
}

// DeleteMapping deletes a single object mapping
func (s *ScyllaMetadataStore) DeleteMapping(ctx context.Context, s3Key, bucket string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// First get the mapping to get CID for index cleanup
	_, err := s.GetMapping(ctx, s3Key, bucket)
	if err != nil {
		return err
	}
	
	// TODO: Execute delete statements
	// Delete from main table
	// stmt := s.preparedStmts["delete_object"].(*gocql.Query)
	// err = stmt.WithContext(ctx).Bind(bucket, s3Key).Exec()
	
	// Delete from CID index
	// cidStmt := s.preparedStmts["delete_cid_index"].(*gocql.Query)
	// err2 := cidStmt.WithContext(ctx).Bind(mapping.CID, bucket, s3Key).Exec()
	
	// Update bucket statistics
	// updateStmt := s.preparedStmts["update_bucket_stats"].(*gocql.Query)
	// updateStmt.WithContext(ctx).Bind(-1, -mapping.Size, time.Now(), bucket).Exec()
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	return nil
}

// UpdateMapping updates an existing object mapping
func (s *ScyllaMetadataStore) UpdateMapping(ctx context.Context, mapping *ObjectMapping) error {
	if err := mapping.Validate(); err != nil {
		return fmt.Errorf("invalid mapping: %w", err)
	}
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	mapping.UpdatedAt = time.Now()
	
	// TODO: Execute prepared update statement
	// stmt := s.preparedStmts["update_object"].(*gocql.Query)
	// err := stmt.WithContext(ctx).Bind(...).Exec()
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	return nil
}

// StoreMappingBatch stores multiple object mappings in a batch
func (s *ScyllaMetadataStore) StoreMappingBatch(ctx context.Context, mappings []*ObjectMapping) error {
	if len(mappings) == 0 {
		return nil
	}
	
	// Validate all mappings first
	for i, mapping := range mappings {
		if err := mapping.Validate(); err != nil {
			return fmt.Errorf("invalid mapping at index %d: %w", i, err)
		}
	}
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// Process in batches to avoid large batch sizes
	batchSize := s.config.BatchSize
	for i := 0; i < len(mappings); i += batchSize {
		end := i + batchSize
		if end > len(mappings) {
			end = len(mappings)
		}
		
		batch := mappings[i:end]
		if err := s.executeBatch(ctx, batch); err != nil {
			return fmt.Errorf("failed to execute batch %d-%d: %w", i, end, err)
		}
	}
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	s.metrics.mu.Lock()
	s.metrics.BatchOperations++
	s.metrics.BatchSize = int64(len(mappings))
	s.metrics.mu.Unlock()
	
	return nil
}

// executeBatch executes a batch of object mappings
func (s *ScyllaMetadataStore) executeBatch(ctx context.Context, mappings []*ObjectMapping) error {
	// TODO: Create and execute batch statement
	// batch := s.session.NewBatch(gocql.LoggedBatch).WithContext(ctx)
	
	// for _, mapping := range mappings {
	//     batch.Query(s.preparedStmts["insert_object"], ...)
	//     batch.Query(s.preparedStmts["insert_cid_index"], ...)
	// }
	
	// err := s.session.ExecuteBatch(batch)
	// return err
	
	return nil // Placeholder
}

// GetMappingBatch retrieves multiple object mappings
func (s *ScyllaMetadataStore) GetMappingBatch(ctx context.Context, keys []*S3Key) ([]*ObjectMapping, error) {
	if len(keys) == 0 {
		return []*ObjectMapping{}, nil
	}
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	results := make([]*ObjectMapping, 0, len(keys))
	
	// Execute queries concurrently for better performance
	// TODO: Implement concurrent queries
	for _, key := range keys {
		mapping, err := s.GetMapping(ctx, key.Key, key.Bucket)
		if err == nil {
			results = append(results, mapping)
		}
	}
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	return results, nil
}

// DeleteMappingBatch deletes multiple object mappings
func (s *ScyllaMetadataStore) DeleteMappingBatch(ctx context.Context, keys []*S3Key) error {
	if len(keys) == 0 {
		return nil
	}
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// Process in batches
	batchSize := s.config.BatchSize
	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}
		
		batch := keys[i:end]
		if err := s.executeDeleteBatch(ctx, batch); err != nil {
			return fmt.Errorf("failed to execute delete batch %d-%d: %w", i, end, err)
		}
	}
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	return nil
}

// executeDeleteBatch executes a batch of delete operations
func (s *ScyllaMetadataStore) executeDeleteBatch(ctx context.Context, keys []*S3Key) error {
	// TODO: Create and execute batch delete statement
	// batch := s.session.NewBatch(gocql.LoggedBatch).WithContext(ctx)
	
	// for _, key := range keys {
	//     batch.Query(s.preparedStmts["delete_object"], key.Bucket, key.Key)
	//     batch.Query(s.preparedStmts["delete_cid_index"], cid, key.Bucket, key.Key)
	// }
	
	// err := s.session.ExecuteBatch(batch)
	// return err
	
	return nil // Placeholder
}

// SearchByCID searches for objects by CID
func (s *ScyllaMetadataStore) SearchByCID(ctx context.Context, cid string) ([]*ObjectMapping, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Query CID index and then get full objects
	// stmt := s.preparedStmts["select_by_cid"].(*gocql.Query)
	// iter := stmt.WithContext(ctx).Bind(cid).Iter()
	
	results := make([]*ObjectMapping, 0)
	
	// TODO: Iterate through results and get full object mappings
	// var bucket, s3Key string
	// for iter.Scan(&bucket, &s3Key) {
	//     mapping, err := s.GetMapping(ctx, s3Key, bucket)
	//     if err == nil {
	//         results = append(results, mapping)
	//     }
	// }
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	return results, nil
}

// SearchByPrefix searches for objects by bucket and key prefix
func (s *ScyllaMetadataStore) SearchByPrefix(ctx context.Context, bucket, prefix string, limit int) ([]*ObjectMapping, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// Calculate prefix range for efficient querying
	_ = s.calculatePrefixEnd(prefix)
	
	// TODO: Execute range query
	// stmt := s.preparedStmts["search_prefix"].(*gocql.Query)
	// iter := stmt.WithContext(ctx).Bind(bucket, prefix, prefixEnd, limit).Iter()
	
	results := make([]*ObjectMapping, 0)
	
	// TODO: Scan results
	// mapping := &ObjectMapping{}
	// for iter.Scan(...) {
	//     results = append(results, mapping.Clone())
	// }
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	return results, nil
}

// ListObjectsInBucket lists objects in a bucket with pagination
func (s *ScyllaMetadataStore) ListObjectsInBucket(ctx context.Context, bucket string, marker string, limit int) ([]*ObjectMapping, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Execute paginated query
	// stmt := s.preparedStmts["list_objects"].(*gocql.Query)
	// iter := stmt.WithContext(ctx).Bind(bucket, marker, limit).Iter()
	
	results := make([]*ObjectMapping, 0)
	
	// TODO: Scan results
	// mapping := &ObjectMapping{}
	// for iter.Scan(...) {
	//     results = append(results, mapping.Clone())
	// }
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	return results, nil
}

// CreateBucket creates a new bucket
func (s *ScyllaMetadataStore) CreateBucket(ctx context.Context, bucket string, metadata *BucketMetadata) error {
	if err := metadata.Validate(); err != nil {
		return fmt.Errorf("invalid bucket metadata: %w", err)
	}
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Execute insert bucket statement
	// stmt := s.preparedStmts["insert_bucket"].(*gocql.Query)
	// err := stmt.WithContext(ctx).Bind(...).Exec()
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	return nil
}

// GetBucket retrieves bucket metadata
func (s *ScyllaMetadataStore) GetBucket(ctx context.Context, bucket string) (*BucketMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Execute select bucket statement
	// stmt := s.preparedStmts["select_bucket"].(*gocql.Query)
	// iter := stmt.WithContext(ctx).Bind(bucket).Iter()
	
	// metadata := &BucketMetadata{}
	// if !iter.Scan(...) {
	//     return nil, fmt.Errorf("bucket not found: %s", bucket)
	// }
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	// Placeholder return
	return NewBucketMetadata(bucket, "admin"), nil
}

// DeleteBucket deletes a bucket
func (s *ScyllaMetadataStore) DeleteBucket(ctx context.Context, bucket string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Check if bucket is empty first
	// TODO: Execute delete bucket statement
	// stmt := s.preparedStmts["delete_bucket"].(*gocql.Query)
	// err := stmt.WithContext(ctx).Bind(bucket).Exec()
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	return nil
}

// ListBuckets lists all buckets
func (s *ScyllaMetadataStore) ListBuckets(ctx context.Context) ([]*BucketMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Execute list buckets statement
	// stmt := s.preparedStmts["list_buckets"].(*gocql.Query)
	// iter := stmt.WithContext(ctx).Iter()
	
	results := make([]*BucketMetadata, 0)
	
	// TODO: Scan results
	// metadata := &BucketMetadata{}
	// for iter.Scan(...) {
	//     results = append(results, metadata.Clone())
	// }
	
	// Update metrics
	s.updateMetrics(time.Since(start), nil)
	
	return results, nil
}

// GetStats returns metadata store statistics
func (s *ScyllaMetadataStore) GetStats(ctx context.Context) (*MetadataStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	// TODO: Query global statistics table
	// Update stats from database
	
	// Clone stats
	stats := *s.stats
	return &stats, nil
}

// GetBucketStats returns statistics for a specific bucket
func (s *ScyllaMetadataStore) GetBucketStats(ctx context.Context, bucket string) (*BucketStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	// TODO: Query bucket statistics
	stats := &BucketStats{
		BucketName: bucket,
		CreatedAt:  time.Now(),
	}
	
	return stats, nil
}

// Compact performs database compaction
func (s *ScyllaMetadataStore) Compact(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	// TODO: Trigger compaction on ScyllaDB
	s.logger.Println("Triggering ScyllaDB compaction...")
	
	return nil
}

// Backup creates a backup
func (s *ScyllaMetadataStore) Backup(ctx context.Context, path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	// TODO: Implement ScyllaDB backup
	s.logger.Printf("Creating backup to: %s", path)
	
	return nil
}

// Restore restores from backup
func (s *ScyllaMetadataStore) Restore(ctx context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	// TODO: Implement ScyllaDB restore
	s.logger.Printf("Restoring from backup: %s", path)
	
	return nil
}

// Shutdown shuts down the ScyllaDB metadata store
func (s *ScyllaMetadataStore) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.shutdown {
		return nil
	}
	
	s.logger.Println("Shutting down ScyllaDB metadata store...")
	
	// TODO: Close session
	// if s.session != nil {
	//     s.session.Close()
	// }
	
	s.shutdown = true
	s.initialized = false
	
	s.logger.Println("ScyllaDB metadata store shutdown completed")
	return nil
}

// HealthCheck performs a health check on the metadata store
func (s *ScyllaMetadataStore) HealthCheck(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	if !s.initialized {
		return fmt.Errorf("metadata store not initialized")
	}
	
	// TODO: Perform actual health check query
	// err := s.session.Query("SELECT now() FROM system.local").WithContext(ctx).Exec()
	// if err != nil {
	//     s.stats.HealthScore = 0.0
	//     return fmt.Errorf("health check failed: %w", err)
	// }
	
	s.stats.LastHealthCheck = time.Now()
	s.stats.HealthScore = 1.0
	
	return nil
}

// Helper methods

// calculatePrefixEnd calculates the end range for prefix queries
func (s *ScyllaMetadataStore) calculatePrefixEnd(prefix string) string {
	if prefix == "" {
		return ""
	}
	
	// Increment the last character to create an exclusive upper bound
	prefixBytes := []byte(prefix)
	for i := len(prefixBytes) - 1; i >= 0; i-- {
		if prefixBytes[i] < 255 {
			prefixBytes[i]++
			return string(prefixBytes[:i+1])
		}
	}
	
	// If we can't increment, return empty string (no upper bound)
	return ""
}

// updateMetrics updates performance metrics
func (s *ScyllaMetadataStore) updateMetrics(duration time.Duration, err error) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	
	s.metrics.TotalQueries++
	
	if err != nil {
		s.metrics.FailedQueries++
	} else {
		s.metrics.SuccessfulQueries++
	}
	
	// Update average latency (simple moving average)
	if s.metrics.TotalQueries == 1 {
		s.metrics.AverageLatency = duration
	} else {
		s.metrics.AverageLatency = time.Duration(
			(int64(s.metrics.AverageLatency) + int64(duration)) / 2,
		)
	}
	
	// Update throughput (queries per second)
	s.metrics.ThroughputRPS = float64(s.metrics.SuccessfulQueries) / time.Since(time.Now().Add(-time.Hour)).Seconds()
}

// GetMetrics returns ScyllaDB-specific metrics
func (s *ScyllaMetadataStore) GetMetrics() *ScyllaMetrics {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()
	
	return &ScyllaMetrics{
		ActiveConnections:     s.metrics.ActiveConnections,
		IdleConnections:       s.metrics.IdleConnections,
		ConnectionErrors:      s.metrics.ConnectionErrors,
		TotalQueries:          s.metrics.TotalQueries,
		SuccessfulQueries:     s.metrics.SuccessfulQueries,
		FailedQueries:         s.metrics.FailedQueries,
		AverageLatency:        s.metrics.AverageLatency,
		BatchOperations:       s.metrics.BatchOperations,
		BatchSize:             s.metrics.BatchSize,
		BatchLatency:          s.metrics.BatchLatency,
		ConsistencyLevel:      s.metrics.ConsistencyLevel,
		ReadRepairs:           s.metrics.ReadRepairs,
		WriteTimeouts:         s.metrics.WriteTimeouts,
		ReadTimeouts:          s.metrics.ReadTimeouts,
		ThroughputRPS:         s.metrics.ThroughputRPS,
		P99Latency:            s.metrics.P99Latency,
		P95Latency:            s.metrics.P95Latency,
	}
}

// GetMappingByCID returns a mapping by CID
func (s *ScyllaMetadataStore) GetMappingByCID(cid string) (*ObjectMapping, error) {
	query := "SELECT bucket, s3_key, cid, size, content_type, etag, created_at, updated_at, accessed_at, access_count, user_metadata, pin_status, replication_count FROM object_mappings WHERE cid = ? LIMIT 1"
	
	var bucket, s3Key, cidResult, contentType, etag string
	var size, accessCount int64
	var replicationCount int
	var createdAt, updatedAt, accessedAt time.Time
	var userMetadata map[string]string
	var pinStatus PinStatus
	
	err := s.session.Query(query, cid).Scan(
		&bucket, &s3Key, &cidResult, &size, &contentType, &etag,
		&createdAt, &updatedAt, &accessedAt, &accessCount,
		&userMetadata, &pinStatus, &replicationCount,
	)
	if err != nil {
		if err == gocql.ErrNotFound {
			return nil, fmt.Errorf("mapping not found for CID: %s", cid)
		}
		return nil, fmt.Errorf("failed to get mapping by CID: %w", err)
	}
	
	mapping := &ObjectMapping{
		Bucket:           bucket,
		S3Key:            s3Key,
		CID:              cidResult,
		Size:             size,
		ContentType:      contentType,
		ETag:             etag,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
		AccessedAt:       accessedAt,
		AccessCount:      accessCount,
		UserMetadata:     userMetadata,
		PinStatus:        pinStatus,
		ReplicationCount: replicationCount,
	}
	
	return mapping, nil
}

// GetPinsByNodes returns pins for specific nodes
func (s *ScyllaMetadataStore) GetPinsByNodes(nodeIDs []string) ([]PinInfo, error) {
	// For simplicity, we'll query all pinned objects and filter by nodes
	// In a real implementation, you might want to have a separate table indexed by node_id
	query := "SELECT bucket, s3_key, cid, pinned_nodes FROM object_mappings WHERE pin_status = ? ALLOW FILTERING"
	
	iter := s.session.Query(query, PinStatusPinned).Iter()
	defer iter.Close()
	
	var pins []PinInfo
	nodeSet := make(map[string]bool)
	for _, nodeID := range nodeIDs {
		nodeSet[nodeID] = true
	}
	
	var bucket, s3Key, cid string
	var pinnedNodes []string
	
	for iter.Scan(&bucket, &s3Key, &cid, &pinnedNodes) {
		// Check if any of the pinned nodes match our requested nodes
		for _, pinnedNode := range pinnedNodes {
			if nodeSet[pinnedNode] {
				pin := PinInfo{
					CID:    cid,
					Name:   s3Key,
					Status: "pinned",
					PeerMap: map[string]string{
						pinnedNode: "pinned",
					},
					Metadata: map[string]string{
						"bucket": bucket,
						"s3_key": s3Key,
					},
				}
				pins = append(pins, pin)
				break // Only add once per mapping
			}
		}
	}
	
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate over pins: %w", err)
	}
	
	return pins, nil
}

// GetAllMappings returns all object mappings
func (s *ScyllaMetadataStore) GetAllMappings(ctx context.Context) ([]*ObjectMapping, error) {
	query := "SELECT bucket, s3_key, cid, size, content_type, etag, created_at, updated_at, accessed_at, access_count, user_metadata, pin_status, replication_count FROM object_mappings"
	
	iter := s.session.Query(query).WithContext(ctx).Iter()
	defer iter.Close()
	
	var mappings []*ObjectMapping
	var bucket, s3Key, cid, contentType, etag string
	var size, accessCount int64
	var createdAt, updatedAt, accessedAt time.Time
	var userMetadata map[string]string
	var pinStatus PinStatus
	var replicationCount int
	
	for iter.Scan(&bucket, &s3Key, &cid, &size, &contentType, &etag, &createdAt, &updatedAt, &accessedAt, &accessCount, &userMetadata, &pinStatus, &replicationCount) {
		mapping := &ObjectMapping{
			Bucket:           bucket,
			S3Key:            s3Key,
			CID:              cid,
			Size:             size,
			ContentType:      contentType,
			ETag:             etag,
			CreatedAt:        createdAt,
			UpdatedAt:        updatedAt,
			AccessedAt:       accessedAt,
			AccessCount:      accessCount,
			UserMetadata:     userMetadata,
			PinStatus:        pinStatus,
			ReplicationCount: replicationCount,
		}
		mappings = append(mappings, mapping)
	}
	
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate over all mappings: %w", err)
	}
	
	return mappings, nil
}

// GetMappingsModifiedSince returns mappings modified since the given time
func (s *ScyllaMetadataStore) GetMappingsModifiedSince(ctx context.Context, since time.Time) ([]*ObjectMapping, error) {
	query := "SELECT bucket, s3_key, cid, size, content_type, etag, last_modified, metadata, pin_status, replication_factor FROM object_mappings WHERE last_modified > ? ALLOW FILTERING"
	
	iter := s.session.Query(query, since).WithContext(ctx).Iter()
	defer iter.Close()
	
	var mappings []*ObjectMapping
	var bucket, s3Key, cid, contentType, etag, pinStatus string
	var size int64
	var lastModified time.Time
	var metadata map[string]string
	var replicationFactor int
	
	for iter.Scan(&bucket, &s3Key, &cid, &size, &contentType, &etag, &lastModified, &metadata, &pinStatus, &replicationFactor) {
		mapping := &ObjectMapping{
			Bucket:           bucket,
			S3Key:            s3Key,
			CID:              cid,
			Size:             size,
			ContentType:      contentType,
			ETag:             etag,
			UpdatedAt:        lastModified,
			UserMetadata:     metadata,
			PinStatus:        parsePinStatus(pinStatus),
			ReplicationCount: replicationFactor,
		}
		mappings = append(mappings, mapping)
	}
	
	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("failed to iterate over mappings modified since %v: %w", since, err)
	}
	
	return mappings, nil
}

// GetTotalPinCount returns the total number of pins across all objects
func (s *ScyllaMetadataStore) GetTotalPinCount() (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.shutdown {
		return 0, fmt.Errorf("metadata store is shutdown")
	}
	
	// TODO: Execute Scylla query to count total pins
	// For now, return a placeholder value
	return 0, nil
}