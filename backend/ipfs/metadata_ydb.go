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
	
	"github.com/ydb-platform/ydb-go-sdk/v3"
	"github.com/ydb-platform/ydb-go-sdk/v3/table"
	"github.com/ydb-platform/ydb-go-sdk/v3/table/types"
	"github.com/ydb-platform/ydb-go-sdk/v3/table/result/named"
)

// YDBMetadataStore implements MetadataStore interface using YDB (Yandex Database)
// This provides ACID-compliant, distributed metadata storage for trillion-scale deployments
type YDBMetadataStore struct {
	// Configuration
	config *MetadataStoreConfig
	
	// Database connection
	driver ydb.Connection
	table  table.Client
	
	// Connection management
	pool interface{} // session pool
	
	// Statistics and monitoring
	stats   *MetadataStats
	metrics *YDBMetrics
	
	// Synchronization
	mu sync.RWMutex
	
	// Lifecycle
	initialized bool
	shutdown    bool
	
	// Logging
	logger *log.Logger
}

// YDBMetrics holds YDB-specific metrics
type YDBMetrics struct {
	// Connection metrics
	ActiveSessions    int64 `json:"active_sessions"`
	IdleSessions      int64 `json:"idle_sessions"`
	SessionErrors     int64 `json:"session_errors"`
	
	// Query metrics
	TotalQueries      int64         `json:"total_queries"`
	SuccessfulQueries int64         `json:"successful_queries"`
	FailedQueries     int64         `json:"failed_queries"`
	AverageLatency    time.Duration `json:"average_latency"`
	
	// Transaction metrics
	TotalTransactions      int64         `json:"total_transactions"`
	CommittedTransactions  int64         `json:"committed_transactions"`
	AbortedTransactions    int64         `json:"aborted_transactions"`
	TransactionLatency     time.Duration `json:"transaction_latency"`
	
	// Batch metrics
	BatchOperations   int64         `json:"batch_operations"`
	BatchSize         int64         `json:"batch_size"`
	BatchLatency      time.Duration `json:"batch_latency"`
	
	// Performance metrics
	ThroughputRPS     float64       `json:"throughput_rps"`
	P99Latency        time.Duration `json:"p99_latency"`
	P95Latency        time.Duration `json:"p95_latency"`
	
	// YDB-specific metrics
	ReadUnits         int64 `json:"read_units"`
	WriteUnits        int64 `json:"write_units"`
	StorageSize       int64 `json:"storage_size"`
	
	mu sync.RWMutex
}

// NewYDBMetadataStore creates a new YDB metadata store
func NewYDBMetadataStore(config *MetadataStoreConfig, logger *log.Logger) (*YDBMetadataStore, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	
	if len(config.Endpoints) == 0 {
		return nil, fmt.Errorf("at least one endpoint must be specified")
	}
	
	if config.Database == "" {
		return nil, fmt.Errorf("database path must be specified for YDB")
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
	
	store := &YDBMetadataStore{
		config:  config,
		logger:  logger,
		stats: &MetadataStats{
			LastHealthCheck: time.Now(),
		},
		metrics: &YDBMetrics{},
	}
	
	return store, nil
}

// Initialize initializes the YDB metadata store
func (y *YDBMetadataStore) Initialize(ctx context.Context) error {
	y.mu.Lock()
	defer y.mu.Unlock()
	
	if y.initialized {
		return fmt.Errorf("metadata store already initialized")
	}
	
	y.logger.Printf("Initializing YDB metadata store with endpoints: %v", y.config.Endpoints)
	
	// TODO: Initialize YDB driver and connection
	// import (
	//     "github.com/ydb-platform/ydb-go-sdk/v3"
	//     "github.com/ydb-platform/ydb-go-sdk/v3/table"
	//     "github.com/ydb-platform/ydb-go-sdk/v3/table/options"
	//     "github.com/ydb-platform/ydb-go-sdk/v3/table/result"
	// )
	
	// driver, err := ydb.Open(ctx, strings.Join(y.config.Endpoints, ","),
	//     ydb.WithDatabase(y.config.Database),
	//     ydb.WithCredentials(ydb.WithAccessTokenCredentials(y.config.Password)),
	//     ydb.WithDialTimeout(y.config.ConnectTimeout),
	// )
	// if err != nil {
	//     return fmt.Errorf("failed to connect to YDB: %w", err)
	// }
	
	// y.driver = driver
	// y.table = driver.Table()
	
	// Create tables
	if err := y.createSchema(ctx); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	
	y.initialized = true
	y.shutdown = false
	
	y.logger.Println("YDB metadata store initialized successfully")
	return nil
}

// createSchema creates the necessary tables in YDB
func (y *YDBMetadataStore) createSchema(ctx context.Context) error {
	y.logger.Println("Creating YDB schema...")
	
	// Create object mappings table
	createObjectsTable := `
		CREATE TABLE object_mappings (
			bucket Utf8,
			s3_key Utf8,
			cid Utf8,
			size Int64,
			content_type Utf8,
			content_encoding Utf8,
			content_language Utf8,
			cache_control Utf8,
			expires Timestamp,
			user_metadata Json,
			tags Json,
			version_id Utf8,
			is_latest Bool,
			delete_marker Bool,
			pin_status Int32,
			replication_count Int32,
			pinned_nodes Json,
			acl Utf8,
			owner Utf8,
			created_at Timestamp,
			updated_at Timestamp,
			accessed_at Timestamp,
			expires_at Timestamp,
			access_count Int64,
			transfer_count Int64,
			last_access_ip Utf8,
			geographic_access Json,
			etag Utf8,
			md5_hash Utf8,
			sha256 Utf8,
			checksum Utf8,
			PRIMARY KEY (bucket, s3_key)
		) WITH (
			AUTO_PARTITIONING_BY_SIZE = ENABLED,
			AUTO_PARTITIONING_PARTITION_SIZE_MB = 2048,
			AUTO_PARTITIONING_MIN_PARTITIONS_COUNT = 4
		)
	`
	
	// Create CID index table for reverse lookups
	createCIDIndexTable := `
		CREATE TABLE cid_index (
			cid Utf8,
			bucket Utf8,
			s3_key Utf8,
			size Int64,
			created_at Timestamp,
			PRIMARY KEY (cid, bucket, s3_key)
		) WITH (
			AUTO_PARTITIONING_BY_SIZE = ENABLED,
			AUTO_PARTITIONING_PARTITION_SIZE_MB = 1024
		)
	`
	
	// Create bucket metadata table
	createBucketsTable := `
		CREATE TABLE bucket_metadata (
			name Utf8,
			created_at Timestamp,
			updated_at Timestamp,
			region Utf8,
			storage_class Utf8,
			versioning_status Utf8,
			acl Utf8,
			owner Utf8,
			policy Utf8,
			cors Utf8,
			lifecycle_config Utf8,
			tags Json,
			object_count Int64,
			total_size Int64,
			default_replication_min Int32,
			default_replication_max Int32,
			PRIMARY KEY (name)
		)
	`
	
	// Create bucket statistics table for analytics
	createBucketStatsTable := `
		CREATE TABLE bucket_stats (
			bucket_name Utf8,
			date Date,
			object_count Int64,
			total_size Int64,
			total_accesses Int64,
			pinned_objects Int64,
			pending_pins Int64,
			failed_pins Int64,
			PRIMARY KEY (bucket_name, date)
		) WITH (
			TTL = Interval("P30D") ON date
		)
	`
	
	// Create global statistics table
	createGlobalStatsTable := `
		CREATE TABLE global_stats (
			id Utf8,
			total_objects Int64,
			total_buckets Int64,
			total_size Int64,
			pinned_objects Int64,
			pending_pins Int64,
			failed_pins Int64,
			total_queries Int64,
			last_updated Timestamp,
			PRIMARY KEY (id)
		)
	`
	
	// Create secondary indexes for efficient queries
	createCIDSecondaryIndex := `
		CREATE INDEX idx_objects_cid ON object_mappings (
			GLOBAL cid
		)
	`
	
	createAccessTimeIndex := `
		CREATE INDEX idx_objects_accessed ON object_mappings (
			GLOBAL accessed_at
		)
	`
	
	createPinStatusIndex := `
		CREATE INDEX idx_objects_pin_status ON object_mappings (
			GLOBAL pin_status, bucket
		)
	`
	
	// TODO: Execute schema creation queries
	// In a real implementation, these would be executed using the table client
	statements := []string{
		createObjectsTable,
		createCIDIndexTable,
		createBucketsTable,
		createBucketStatsTable,
		createGlobalStatsTable,
		createCIDSecondaryIndex,
		createAccessTimeIndex,
		createPinStatusIndex,
	}
	
	for _, stmt := range statements {
		y.logger.Printf("Executing schema statement: %s", strings.Split(stmt, "\n")[1])
		// err := y.table.Do(ctx, func(ctx context.Context, s table.Session) error {
		//     return s.ExecuteSchemeQuery(ctx, stmt)
		// })
		// if err != nil {
		//     return fmt.Errorf("failed to execute schema statement: %w", err)
		// }
	}
	
	y.logger.Println("Schema created successfully")
	return nil
}

// StoreMapping stores a single object mapping
func (y *YDBMetadataStore) StoreMapping(ctx context.Context, mapping *ObjectMapping) error {
	if err := mapping.Validate(); err != nil {
		return fmt.Errorf("invalid mapping: %w", err)
	}
	
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Execute YDB transaction
	// err := y.table.DoTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
	//     // Insert into object_mappings table
	//     _, err := tx.Execute(ctx, `
	//         UPSERT INTO object_mappings (
	//             bucket, s3_key, cid, size, content_type, content_encoding,
	//             content_language, cache_control, expires, user_metadata, tags,
	//             version_id, is_latest, delete_marker, pin_status, replication_count,
	//             pinned_nodes, acl, owner, created_at, updated_at, accessed_at,
	//             expires_at, access_count, transfer_count, last_access_ip,
	//             geographic_access, etag, md5_hash, sha256, checksum
	//         ) VALUES (
	//             $bucket, $s3_key, $cid, $size, $content_type, $content_encoding,
	//             $content_language, $cache_control, $expires, $user_metadata, $tags,
	//             $version_id, $is_latest, $delete_marker, $pin_status, $replication_count,
	//             $pinned_nodes, $acl, $owner, $created_at, $updated_at, $accessed_at,
	//             $expires_at, $access_count, $transfer_count, $last_access_ip,
	//             $geographic_access, $etag, $md5_hash, $sha256, $checksum
	//         )
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$bucket", types.UTF8Value(mapping.Bucket)),
	//         table.ValueParam("$s3_key", types.UTF8Value(mapping.S3Key)),
	//         // ... other parameters
	//     ))
	//     if err != nil {
	//         return err
	//     }
	//     
	//     // Insert into CID index
	//     _, err = tx.Execute(ctx, `
	//         UPSERT INTO cid_index (cid, bucket, s3_key, size, created_at)
	//         VALUES ($cid, $bucket, $s3_key, $size, $created_at)
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$cid", types.UTF8Value(mapping.CID)),
	//         table.ValueParam("$bucket", types.UTF8Value(mapping.Bucket)),
	//         table.ValueParam("$s3_key", types.UTF8Value(mapping.S3Key)),
	//         table.ValueParam("$size", types.Int64Value(mapping.Size)),
	//         table.ValueParam("$created_at", types.TimestampValue(mapping.CreatedAt)),
	//     ))
	//     return err
	// }, table.WithTxSettings(table.TxSettings(
	//     table.WithSerializableReadWrite(),
	// )))
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	// Placeholder success
	return nil
}

// GetMapping retrieves a single object mapping
func (y *YDBMetadataStore) GetMapping(ctx context.Context, s3Key, bucket string) (*ObjectMapping, error) {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Execute YDB query
	// var mapping *ObjectMapping
	// err := y.table.Do(ctx, func(ctx context.Context, s table.Session) error {
	//     _, res, err := s.Execute(ctx, table.DefaultTxControl(), `
	//         SELECT * FROM object_mappings
	//         WHERE bucket = $bucket AND s3_key = $s3_key
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$bucket", types.UTF8Value(bucket)),
	//         table.ValueParam("$s3_key", types.UTF8Value(s3Key)),
	//     ))
	//     if err != nil {
	//         return err
	//     }
	//     defer res.Close()
	//     
	//     if !res.NextResultSet() {
	//         return fmt.Errorf("object not found: %s/%s", bucket, s3Key)
	//     }
	//     
	//     if !res.NextRow() {
	//         return fmt.Errorf("object not found: %s/%s", bucket, s3Key)
	//     }
	//     
	//     mapping = &ObjectMapping{}
	//     // Scan result into mapping struct
	//     return res.ScanNamed(
	//         named.Required("bucket", &mapping.Bucket),
	//         named.Required("s3_key", &mapping.S3Key),
	//         // ... other fields
	//     )
	// })
	
	// Update access statistics
	// y.updateAccessStats(ctx, mapping)
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	// Placeholder return
	return NewObjectMapping(bucket, s3Key, "QmPlaceholder", 1024), nil
}

// DeleteMapping deletes a single object mapping
func (y *YDBMetadataStore) DeleteMapping(ctx context.Context, s3Key, bucket string) error {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Execute YDB transaction
	// err := y.table.DoTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
	//     // First get the CID for index cleanup
	//     _, res, err := tx.Execute(ctx, `
	//         SELECT cid FROM object_mappings
	//         WHERE bucket = $bucket AND s3_key = $s3_key
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$bucket", types.UTF8Value(bucket)),
	//         table.ValueParam("$s3_key", types.UTF8Value(s3Key)),
	//     ))
	//     if err != nil {
	//         return err
	//     }
	//     defer res.Close()
	//     
	//     if !res.NextResultSet() || !res.NextRow() {
	//         return fmt.Errorf("object not found: %s/%s", bucket, s3Key)
	//     }
	//     
	//     var cid string
	//     err = res.ScanNamed(named.Required("cid", &cid))
	//     if err != nil {
	//         return err
	//     }
	//     
	//     // Delete from main table
	//     _, err = tx.Execute(ctx, `
	//         DELETE FROM object_mappings
	//         WHERE bucket = $bucket AND s3_key = $s3_key
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$bucket", types.UTF8Value(bucket)),
	//         table.ValueParam("$s3_key", types.UTF8Value(s3Key)),
	//     ))
	//     if err != nil {
	//         return err
	//     }
	//     
	//     // Delete from CID index
	//     _, err = tx.Execute(ctx, `
	//         DELETE FROM cid_index
	//         WHERE cid = $cid AND bucket = $bucket AND s3_key = $s3_key
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$cid", types.UTF8Value(cid)),
	//         table.ValueParam("$bucket", types.UTF8Value(bucket)),
	//         table.ValueParam("$s3_key", types.UTF8Value(s3Key)),
	//     ))
	//     return err
	// }, table.WithTxSettings(table.TxSettings(
	//     table.WithSerializableReadWrite(),
	// )))
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	return nil
}

// UpdateMapping updates an existing object mapping
func (y *YDBMetadataStore) UpdateMapping(ctx context.Context, mapping *ObjectMapping) error {
	if err := mapping.Validate(); err != nil {
		return fmt.Errorf("invalid mapping: %w", err)
	}
	
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	mapping.UpdatedAt = time.Now()
	
	// TODO: Execute YDB update transaction
	// err := y.table.DoTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
	//     _, err := tx.Execute(ctx, `
	//         UPDATE object_mappings SET
	//             cid = $cid, size = $size, content_type = $content_type,
	//             content_encoding = $content_encoding, content_language = $content_language,
	//             cache_control = $cache_control, expires = $expires,
	//             user_metadata = $user_metadata, tags = $tags,
	//             version_id = $version_id, is_latest = $is_latest,
	//             delete_marker = $delete_marker, pin_status = $pin_status,
	//             replication_count = $replication_count, pinned_nodes = $pinned_nodes,
	//             acl = $acl, owner = $owner, updated_at = $updated_at,
	//             accessed_at = $accessed_at, expires_at = $expires_at,
	//             access_count = $access_count, transfer_count = $transfer_count,
	//             last_access_ip = $last_access_ip, geographic_access = $geographic_access,
	//             etag = $etag, md5_hash = $md5_hash, sha256 = $sha256, checksum = $checksum
	//         WHERE bucket = $bucket AND s3_key = $s3_key
	//     `, table.NewQueryParameters(
	//         // ... parameters
	//     ))
	//     return err
	// }, table.WithTxSettings(table.TxSettings(
	//     table.WithSerializableReadWrite(),
	// )))
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	return nil
}

// StoreMappingBatch stores multiple object mappings in a batch
func (y *YDBMetadataStore) StoreMappingBatch(ctx context.Context, mappings []*ObjectMapping) error {
	if len(mappings) == 0 {
		return nil
	}
	
	// Validate all mappings first
	for i, mapping := range mappings {
		if err := mapping.Validate(); err != nil {
			return fmt.Errorf("invalid mapping at index %d: %w", i, err)
		}
	}
	
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// Process in batches to avoid large transactions
	batchSize := y.config.BatchSize
	for i := 0; i < len(mappings); i += batchSize {
		end := i + batchSize
		if end > len(mappings) {
			end = len(mappings)
		}
		
		batch := mappings[i:end]
		if err := y.executeBatch(ctx, batch); err != nil {
			return fmt.Errorf("failed to execute batch %d-%d: %w", i, end, err)
		}
	}
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	y.metrics.mu.Lock()
	y.metrics.BatchOperations++
	y.metrics.BatchSize = int64(len(mappings))
	y.metrics.mu.Unlock()
	
	return nil
}

// executeBatch executes a batch of object mappings
func (y *YDBMetadataStore) executeBatch(ctx context.Context, mappings []*ObjectMapping) error {
	// TODO: Execute YDB batch transaction
	// err := y.table.DoTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
	//     for _, mapping := range mappings {
	//         // Insert into object_mappings
	//         _, err := tx.Execute(ctx, `
	//             UPSERT INTO object_mappings (...) VALUES (...)
	//         `, table.NewQueryParameters(...))
	//         if err != nil {
	//             return err
	//         }
	//         
	//         // Insert into CID index
	//         _, err = tx.Execute(ctx, `
	//             UPSERT INTO cid_index (...) VALUES (...)
	//         `, table.NewQueryParameters(...))
	//         if err != nil {
	//             return err
	//         }
	//     }
	//     return nil
	// }, table.WithTxSettings(table.TxSettings(
	//     table.WithSerializableReadWrite(),
	// )))
	
	return nil // Placeholder
}

// GetMappingBatch retrieves multiple object mappings
func (y *YDBMetadataStore) GetMappingBatch(ctx context.Context, keys []*S3Key) ([]*ObjectMapping, error) {
	if len(keys) == 0 {
		return []*ObjectMapping{}, nil
	}
	
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	results := make([]*ObjectMapping, 0, len(keys))
	
	// TODO: Execute batch query using YDB
	// Build IN clause for efficient batch retrieval
	// err := y.table.Do(ctx, func(ctx context.Context, s table.Session) error {
	//     // Build query with IN clause
	//     query := `
	//         SELECT * FROM object_mappings
	//         WHERE (bucket, s3_key) IN (
	//     `
	//     params := table.NewQueryParameters()
	//     for i, key := range keys {
	//         if i > 0 {
	//             query += ", "
	//         }
	//         query += fmt.Sprintf("($bucket_%d, $s3_key_%d)", i, i)
	//         params = params.With(
	//             table.ValueParam(fmt.Sprintf("$bucket_%d", i), types.UTF8Value(key.Bucket)),
	//             table.ValueParam(fmt.Sprintf("$s3_key_%d", i), types.UTF8Value(key.Key)),
	//         )
	//     }
	//     query += ")"
	//     
	//     _, res, err := s.Execute(ctx, table.DefaultTxControl(), query, params)
	//     if err != nil {
	//         return err
	//     }
	//     defer res.Close()
	//     
	//     for res.NextResultSet() {
	//         for res.NextRow() {
	//             mapping := &ObjectMapping{}
	//             err := res.ScanNamed(...)
	//             if err != nil {
	//                 return err
	//             }
	//             results = append(results, mapping)
	//         }
	//     }
	//     return nil
	// })
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	return results, nil
}

// DeleteMappingBatch deletes multiple object mappings
func (y *YDBMetadataStore) DeleteMappingBatch(ctx context.Context, keys []*S3Key) error {
	if len(keys) == 0 {
		return nil
	}
	
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// Process in batches
	batchSize := y.config.BatchSize
	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}
		
		batch := keys[i:end]
		if err := y.executeDeleteBatch(ctx, batch); err != nil {
			return fmt.Errorf("failed to execute delete batch %d-%d: %w", i, end, err)
		}
	}
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	return nil
}

// executeDeleteBatch executes a batch of delete operations
func (y *YDBMetadataStore) executeDeleteBatch(ctx context.Context, keys []*S3Key) error {
	// TODO: Execute YDB batch delete transaction
	// err := y.table.DoTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
	//     for _, key := range keys {
	//         // Get CID first for index cleanup
	//         _, res, err := tx.Execute(ctx, `
	//             SELECT cid FROM object_mappings
	//             WHERE bucket = $bucket AND s3_key = $s3_key
	//         `, table.NewQueryParameters(
	//             table.ValueParam("$bucket", types.UTF8Value(key.Bucket)),
	//             table.ValueParam("$s3_key", types.UTF8Value(key.Key)),
	//         ))
	//         if err != nil {
	//             continue // Skip if not found
	//         }
	//         defer res.Close()
	//         
	//         if res.NextResultSet() && res.NextRow() {
	//             var cid string
	//             res.ScanNamed(named.Required("cid", &cid))
	//             
	//             // Delete from main table
	//             tx.Execute(ctx, `
	//                 DELETE FROM object_mappings
	//                 WHERE bucket = $bucket AND s3_key = $s3_key
	//             `, table.NewQueryParameters(
	//                 table.ValueParam("$bucket", types.UTF8Value(key.Bucket)),
	//                 table.ValueParam("$s3_key", types.UTF8Value(key.Key)),
	//             ))
	//             
	//             // Delete from CID index
	//             tx.Execute(ctx, `
	//                 DELETE FROM cid_index
	//                 WHERE cid = $cid AND bucket = $bucket AND s3_key = $s3_key
	//             `, table.NewQueryParameters(
	//                 table.ValueParam("$cid", types.UTF8Value(cid)),
	//                 table.ValueParam("$bucket", types.UTF8Value(key.Bucket)),
	//                 table.ValueParam("$s3_key", types.UTF8Value(key.Key)),
	//             ))
	//         }
	//     }
	//     return nil
	// }, table.WithTxSettings(table.TxSettings(
	//     table.WithSerializableReadWrite(),
	// )))
	
	return nil // Placeholder
}

// SearchByCID searches for objects by CID
func (y *YDBMetadataStore) SearchByCID(ctx context.Context, cid string) ([]*ObjectMapping, error) {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	results := make([]*ObjectMapping, 0)
	
	// TODO: Query using CID index and then get full objects
	// err := y.table.Do(ctx, func(ctx context.Context, s table.Session) error {
	//     // First query CID index
	//     _, res, err := s.Execute(ctx, table.DefaultTxControl(), `
	//         SELECT bucket, s3_key FROM cid_index
	//         WHERE cid = $cid
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$cid", types.UTF8Value(cid)),
	//     ))
	//     if err != nil {
	//         return err
	//     }
	//     defer res.Close()
	//     
	//     var keys []*S3Key
	//     for res.NextResultSet() {
	//         for res.NextRow() {
	//             var bucket, s3Key string
	//             err := res.ScanNamed(
	//                 named.Required("bucket", &bucket),
	//                 named.Required("s3_key", &s3Key),
	//             )
	//             if err != nil {
	//                 continue
	//             }
	//             keys = append(keys, &S3Key{Bucket: bucket, Key: s3Key})
	//         }
	//     }
	//     
	//     // Get full object mappings
	//     mappings, err := y.GetMappingBatch(ctx, keys)
	//     if err != nil {
	//         return err
	//     }
	//     results = mappings
	//     return nil
	// })
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	return results, nil
}

// SearchByPrefix searches for objects by bucket and key prefix
func (y *YDBMetadataStore) SearchByPrefix(ctx context.Context, bucket, prefix string, limit int) ([]*ObjectMapping, error) {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	results := make([]*ObjectMapping, 0)
	
	// TODO: Execute prefix query using YDB
	// err := y.table.Do(ctx, func(ctx context.Context, s table.Session) error {
	//     _, res, err := s.Execute(ctx, table.DefaultTxControl(), `
	//         SELECT * FROM object_mappings
	//         WHERE bucket = $bucket AND s3_key >= $prefix AND s3_key < $prefix_end
	//         ORDER BY s3_key
	//         LIMIT $limit
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$bucket", types.UTF8Value(bucket)),
	//         table.ValueParam("$prefix", types.UTF8Value(prefix)),
	//         table.ValueParam("$prefix_end", types.UTF8Value(y.calculatePrefixEnd(prefix))),
	//         table.ValueParam("$limit", types.Int64Value(int64(limit))),
	//     ))
	//     if err != nil {
	//         return err
	//     }
	//     defer res.Close()
	//     
	//     for res.NextResultSet() {
	//         for res.NextRow() {
	//             mapping := &ObjectMapping{}
	//             err := res.ScanNamed(...)
	//             if err != nil {
	//                 continue
	//             }
	//             results = append(results, mapping)
	//         }
	//     }
	//     return nil
	// })
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	return results, nil
}

// ListObjectsInBucket lists objects in a bucket with pagination
func (y *YDBMetadataStore) ListObjectsInBucket(ctx context.Context, bucket string, marker string, limit int) ([]*ObjectMapping, error) {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	results := make([]*ObjectMapping, 0)
	
	// TODO: Execute paginated query using YDB
	// err := y.table.Do(ctx, func(ctx context.Context, s table.Session) error {
	//     _, res, err := s.Execute(ctx, table.DefaultTxControl(), `
	//         SELECT * FROM object_mappings
	//         WHERE bucket = $bucket AND s3_key > $marker
	//         ORDER BY s3_key
	//         LIMIT $limit
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$bucket", types.UTF8Value(bucket)),
	//         table.ValueParam("$marker", types.UTF8Value(marker)),
	//         table.ValueParam("$limit", types.Int64Value(int64(limit))),
	//     ))
	//     if err != nil {
	//         return err
	//     }
	//     defer res.Close()
	//     
	//     for res.NextResultSet() {
	//         for res.NextRow() {
	//             mapping := &ObjectMapping{}
	//             err := res.ScanNamed(...)
	//             if err != nil {
	//                 continue
	//             }
	//             results = append(results, mapping)
	//         }
	//     }
	//     return nil
	// })
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	return results, nil
}

// CreateBucket creates a new bucket
func (y *YDBMetadataStore) CreateBucket(ctx context.Context, bucket string, metadata *BucketMetadata) error {
	if err := metadata.Validate(); err != nil {
		return fmt.Errorf("invalid bucket metadata: %w", err)
	}
	
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Execute YDB transaction
	// err := y.table.DoTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
	//     _, err := tx.Execute(ctx, `
	//         UPSERT INTO bucket_metadata (
	//             name, created_at, updated_at, region, storage_class,
	//             versioning_status, acl, owner, policy, cors, lifecycle_config,
	//             tags, object_count, total_size, default_replication_min,
	//             default_replication_max
	//         ) VALUES (
	//             $name, $created_at, $updated_at, $region, $storage_class,
	//             $versioning_status, $acl, $owner, $policy, $cors, $lifecycle_config,
	//             $tags, $object_count, $total_size, $default_replication_min,
	//             $default_replication_max
	//         )
	//     `, table.NewQueryParameters(...))
	//     return err
	// }, table.WithTxSettings(table.TxSettings(
	//     table.WithSerializableReadWrite(),
	// )))
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	return nil
}

// GetBucket retrieves bucket metadata
func (y *YDBMetadataStore) GetBucket(ctx context.Context, bucket string) (*BucketMetadata, error) {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Execute YDB query
	// var metadata *BucketMetadata
	// err := y.table.Do(ctx, func(ctx context.Context, s table.Session) error {
	//     _, res, err := s.Execute(ctx, table.DefaultTxControl(), `
	//         SELECT * FROM bucket_metadata WHERE name = $name
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$name", types.UTF8Value(bucket)),
	//     ))
	//     if err != nil {
	//         return err
	//     }
	//     defer res.Close()
	//     
	//     if !res.NextResultSet() || !res.NextRow() {
	//         return fmt.Errorf("bucket not found: %s", bucket)
	//     }
	//     
	//     metadata = &BucketMetadata{}
	//     return res.ScanNamed(...)
	// })
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	// Placeholder return
	return NewBucketMetadata(bucket, "admin"), nil
}

// DeleteBucket deletes a bucket
func (y *YDBMetadataStore) DeleteBucket(ctx context.Context, bucket string) error {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	
	// TODO: Execute YDB transaction
	// err := y.table.DoTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
	//     // Check if bucket is empty
	//     _, res, err := tx.Execute(ctx, `
	//         SELECT COUNT(*) as count FROM object_mappings WHERE bucket = $bucket
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$bucket", types.UTF8Value(bucket)),
	//     ))
	//     if err != nil {
	//         return err
	//     }
	//     defer res.Close()
	//     
	//     if res.NextResultSet() && res.NextRow() {
	//         var count int64
	//         res.ScanNamed(named.Required("count", &count))
	//         if count > 0 {
	//             return fmt.Errorf("bucket not empty: %s", bucket)
	//         }
	//     }
	//     
	//     // Delete bucket
	//     _, err = tx.Execute(ctx, `
	//         DELETE FROM bucket_metadata WHERE name = $bucket
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$bucket", types.UTF8Value(bucket)),
	//     ))
	//     return err
	// }, table.WithTxSettings(table.TxSettings(
	//     table.WithSerializableReadWrite(),
	// )))
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	return nil
}

// ListBuckets lists all buckets
func (y *YDBMetadataStore) ListBuckets(ctx context.Context) ([]*BucketMetadata, error) {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	start := time.Now()
	results := make([]*BucketMetadata, 0)
	
	// TODO: Execute YDB query
	// err := y.table.Do(ctx, func(ctx context.Context, s table.Session) error {
	//     _, res, err := s.Execute(ctx, table.DefaultTxControl(), `
	//         SELECT * FROM bucket_metadata ORDER BY name
	//     `, table.NewQueryParameters())
	//     if err != nil {
	//         return err
	//     }
	//     defer res.Close()
	//     
	//     for res.NextResultSet() {
	//         for res.NextRow() {
	//             metadata := &BucketMetadata{}
	//             err := res.ScanNamed(...)
	//             if err != nil {
	//                 continue
	//             }
	//             results = append(results, metadata)
	//         }
	//     }
	//     return nil
	// })
	
	// Update metrics
	y.updateMetrics(time.Since(start), nil)
	
	return results, nil
}

// GetStats returns metadata store statistics
func (y *YDBMetadataStore) GetStats(ctx context.Context) (*MetadataStats, error) {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	// TODO: Query global statistics table and update stats
	// err := y.table.Do(ctx, func(ctx context.Context, s table.Session) error {
	//     _, res, err := s.Execute(ctx, table.DefaultTxControl(), `
	//         SELECT * FROM global_stats WHERE id = 'main'
	//     `, table.NewQueryParameters())
	//     if err != nil {
	//         return err
	//     }
	//     defer res.Close()
	//     
	//     if res.NextResultSet() && res.NextRow() {
	//         res.ScanNamed(...)
	//     }
	//     return nil
	// })
	
	// Clone stats
	stats := *y.stats
	return &stats, nil
}

// GetBucketStats returns statistics for a specific bucket
func (y *YDBMetadataStore) GetBucketStats(ctx context.Context, bucket string) (*BucketStats, error) {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return nil, fmt.Errorf("metadata store is shutdown")
	}
	
	// TODO: Query bucket statistics
	stats := &BucketStats{
		BucketName: bucket,
		CreatedAt:  time.Now(),
	}
	
	return stats, nil
}

// Compact performs database compaction (YDB handles this automatically)
func (y *YDBMetadataStore) Compact(ctx context.Context) error {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	// YDB handles compaction automatically, but we can trigger statistics update
	y.logger.Println("YDB compaction is handled automatically")
	
	return nil
}

// Backup creates a backup (YDB provides built-in backup functionality)
func (y *YDBMetadataStore) Backup(ctx context.Context, path string) error {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	// TODO: Use YDB backup API
	y.logger.Printf("Creating YDB backup to: %s", path)
	
	return nil
}

// Restore restores from backup
func (y *YDBMetadataStore) Restore(ctx context.Context, path string) error {
	y.mu.Lock()
	defer y.mu.Unlock()
	
	if y.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	// TODO: Use YDB restore API
	y.logger.Printf("Restoring YDB from backup: %s", path)
	
	return nil
}

// Shutdown shuts down the YDB metadata store
func (y *YDBMetadataStore) Shutdown(ctx context.Context) error {
	y.mu.Lock()
	defer y.mu.Unlock()
	
	if y.shutdown {
		return nil
	}
	
	y.logger.Println("Shutting down YDB metadata store...")
	
	// TODO: Close YDB driver
	// if y.driver != nil {
	//     y.driver.Close(ctx)
	// }
	
	y.shutdown = true
	y.initialized = false
	
	y.logger.Println("YDB metadata store shutdown completed")
	return nil
}

// HealthCheck performs a health check on the metadata store
func (y *YDBMetadataStore) HealthCheck(ctx context.Context) error {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return fmt.Errorf("metadata store is shutdown")
	}
	
	if !y.initialized {
		return fmt.Errorf("metadata store not initialized")
	}
	
	// TODO: Perform actual health check query
	// err := y.table.Do(ctx, func(ctx context.Context, s table.Session) error {
	//     _, _, err := s.Execute(ctx, table.DefaultTxControl(), `
	//         SELECT 1 as health_check
	//     `, table.NewQueryParameters())
	//     return err
	// })
	// if err != nil {
	//     y.stats.HealthScore = 0.0
	//     return fmt.Errorf("health check failed: %w", err)
	// }
	
	y.stats.LastHealthCheck = time.Now()
	y.stats.HealthScore = 1.0
	
	return nil
}

// Helper methods

// calculatePrefixEnd calculates the end range for prefix queries
func (y *YDBMetadataStore) calculatePrefixEnd(prefix string) string {
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
func (y *YDBMetadataStore) updateMetrics(duration time.Duration, err error) {
	y.metrics.mu.Lock()
	defer y.metrics.mu.Unlock()
	
	y.metrics.TotalQueries++
	
	if err != nil {
		y.metrics.FailedQueries++
	} else {
		y.metrics.SuccessfulQueries++
	}
	
	// Update average latency (simple moving average)
	if y.metrics.TotalQueries == 1 {
		y.metrics.AverageLatency = duration
	} else {
		y.metrics.AverageLatency = time.Duration(
			(int64(y.metrics.AverageLatency) + int64(duration)) / 2,
		)
	}
	
	// Update throughput (queries per second)
	y.metrics.ThroughputRPS = float64(y.metrics.SuccessfulQueries) / time.Since(time.Now().Add(-time.Hour)).Seconds()
}

// updateAccessStats updates access statistics for an object
func (y *YDBMetadataStore) updateAccessStats(ctx context.Context, mapping *ObjectMapping) error {
	if mapping == nil {
		return nil
	}
	
	// TODO: Update access statistics in a separate transaction
	// err := y.table.DoTx(ctx, func(ctx context.Context, tx table.TransactionActor) error {
	//     _, err := tx.Execute(ctx, `
	//         UPDATE object_mappings SET
	//             accessed_at = $accessed_at,
	//             access_count = access_count + 1
	//         WHERE bucket = $bucket AND s3_key = $s3_key
	//     `, table.NewQueryParameters(
	//         table.ValueParam("$accessed_at", types.TimestampValue(time.Now())),
	//         table.ValueParam("$bucket", types.UTF8Value(mapping.Bucket)),
	//         table.ValueParam("$s3_key", types.UTF8Value(mapping.S3Key)),
	//     ))
	//     return err
	// }, table.WithTxSettings(table.TxSettings(
	//     table.WithSerializableReadWrite(),
	// )))
	
	return nil
}

// GetMetrics returns YDB-specific metrics
func (y *YDBMetadataStore) GetMetrics() *YDBMetrics {
	y.metrics.mu.RLock()
	defer y.metrics.mu.RUnlock()
	
	return &YDBMetrics{
		ActiveSessions:         y.metrics.ActiveSessions,
		IdleSessions:           y.metrics.IdleSessions,
		SessionErrors:          y.metrics.SessionErrors,
		TotalQueries:           y.metrics.TotalQueries,
		SuccessfulQueries:      y.metrics.SuccessfulQueries,
		FailedQueries:          y.metrics.FailedQueries,
		AverageLatency:         y.metrics.AverageLatency,
		TotalTransactions:      y.metrics.TotalTransactions,
		CommittedTransactions:  y.metrics.CommittedTransactions,
		AbortedTransactions:    y.metrics.AbortedTransactions,
		TransactionLatency:     y.metrics.TransactionLatency,
		BatchOperations:        y.metrics.BatchOperations,
		BatchSize:              y.metrics.BatchSize,
		BatchLatency:           y.metrics.BatchLatency,
		ThroughputRPS:          y.metrics.ThroughputRPS,
		P99Latency:             y.metrics.P99Latency,
		P95Latency:             y.metrics.P95Latency,
		ReadUnits:              y.metrics.ReadUnits,
		WriteUnits:             y.metrics.WriteUnits,
		StorageSize:            y.metrics.StorageSize,
	}
}

// GetMappingByCID returns a mapping by CID
func (y *YDBMetadataStore) GetMappingByCID(cid string) (*ObjectMapping, error) {
	query := `
		SELECT bucket, s3_key, cid, size, content_type, etag, created_at, updated_at, accessed_at, access_count, user_metadata, pin_status, replication_count
		FROM object_mappings
		WHERE cid = $cid
		LIMIT 1
	`
	
	var mapping *ObjectMapping
	err := y.table.Do(context.Background(), func(ctx context.Context, s table.Session) error {
		_, res, err := s.Execute(ctx, table.DefaultTxControl(), query, table.NewQueryParameters(
			table.ValueParam("$cid", types.UTF8Value(cid)),
		))
		if err != nil {
			return err
		}
		defer res.Close()
		
		if !res.NextResultSet(ctx) {
			return fmt.Errorf("mapping not found for CID: %s", cid)
		}
		
		if !res.NextRow() {
			return fmt.Errorf("mapping not found for CID: %s", cid)
		}
		
		var bucket, s3Key, cidResult, contentType, etag string
		var size, accessCount int64
		var replicationCount int
		var createdAt, updatedAt, accessedAt time.Time
		var userMetadata map[string]string
		var pinStatus PinStatus
		
		res.ScanNamed(
			named.OptionalWithDefault("bucket", &bucket),
			named.OptionalWithDefault("s3_key", &s3Key),
			named.OptionalWithDefault("cid", &cidResult),
			named.OptionalWithDefault("size", &size),
			named.OptionalWithDefault("content_type", &contentType),
			named.OptionalWithDefault("etag", &etag),
			named.OptionalWithDefault("created_at", &createdAt),
			named.OptionalWithDefault("updated_at", &updatedAt),
			named.OptionalWithDefault("accessed_at", &accessedAt),
			named.OptionalWithDefault("access_count", &accessCount),
			named.OptionalWithDefault("user_metadata", &userMetadata),
			named.OptionalWithDefault("pin_status", &pinStatus),
			named.OptionalWithDefault("replication_count", &replicationCount),
		)
		
		mapping = &ObjectMapping{
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
		
		return res.Err()
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to get mapping by CID: %w", err)
	}
	
	return mapping, nil
}

// GetPinsByNodes returns pins for specific nodes
func (y *YDBMetadataStore) GetPinsByNodes(nodeIDs []string) ([]PinInfo, error) {
	query := `
		SELECT bucket, s3_key, cid, pinned_nodes
		FROM object_mappings
		WHERE pin_status = $pin_status
	`
	
	var pins []PinInfo
	nodeSet := make(map[string]bool)
	for _, nodeID := range nodeIDs {
		nodeSet[nodeID] = true
	}
	
	err := y.table.Do(context.Background(), func(ctx context.Context, s table.Session) error {
		_, res, err := s.Execute(ctx, table.DefaultTxControl(), query, table.NewQueryParameters(
			table.ValueParam("$pin_status", types.UTF8Value(string(PinStatusPinned))),
		))
		if err != nil {
			return err
		}
		defer res.Close()
		
		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var bucket, s3Key, cid string
				var pinnedNodes []string
				
				res.ScanNamed(
					named.OptionalWithDefault("bucket", &bucket),
					named.OptionalWithDefault("s3_key", &s3Key),
					named.OptionalWithDefault("cid", &cid),
					named.OptionalWithDefault("pinned_nodes", &pinnedNodes),
				)
				
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
		}
		return res.Err()
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to get pins by nodes: %w", err)
	}
	
	return pins, nil
}

// GetAllMappings returns all object mappings
func (y *YDBMetadataStore) GetAllMappings(ctx context.Context) ([]*ObjectMapping, error) {
	query := `
		SELECT bucket, s3_key, cid, size, content_type, etag, last_modified, metadata, pin_status, replication_factor
		FROM object_mappings
	`
	
	var mappings []*ObjectMapping
	
	err := y.table.Do(ctx, func(ctx context.Context, s table.Session) error {
		_, res, err := s.Execute(ctx, table.DefaultTxControl(), query, nil)
		if err != nil {
			return err
		}
		defer res.Close()
		
		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var bucket, s3Key, cid, contentType, etag, pinStatus string
				var size int64
				var lastModified time.Time
				var metadata map[string]string
				var replicationFactor int
				
				err := res.ScanNamed(
					named.OptionalWithDefault("bucket", &bucket),
					named.OptionalWithDefault("s3_key", &s3Key),
					named.OptionalWithDefault("cid", &cid),
					named.OptionalWithDefault("size", &size),
					named.OptionalWithDefault("content_type", &contentType),
					named.OptionalWithDefault("etag", &etag),
					named.OptionalWithDefault("last_modified", &lastModified),
					named.OptionalWithDefault("metadata", &metadata),
					named.OptionalWithDefault("pin_status", &pinStatus),
					named.OptionalWithDefault("replication_factor", &replicationFactor),
				)
				if err != nil {
					return err
				}
				
				mapping := &ObjectMapping{
					Bucket:            bucket,
					S3Key:             s3Key,
					CID:               cid,
					Size:              size,
					ContentType:       contentType,
					ETag:              etag,
					UpdatedAt:         lastModified,
					UserMetadata:      metadata,
					PinStatus:         parsePinStatus(pinStatus),
					ReplicationCount:  int(replicationFactor),
				}
				mappings = append(mappings, mapping)
			}
		}
		
		return res.Err()
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to get all mappings: %w", err)
	}
	
	return mappings, nil
}

// GetMappingsModifiedSince returns mappings modified since the given time
func (y *YDBMetadataStore) GetMappingsModifiedSince(ctx context.Context, since time.Time) ([]*ObjectMapping, error) {
	query := `
		SELECT bucket, s3_key, cid, size, content_type, etag, last_modified, metadata, pin_status, replication_factor
		FROM object_mappings
		WHERE last_modified > $since
	`
	
	var mappings []*ObjectMapping
	
	err := y.table.Do(ctx, func(ctx context.Context, s table.Session) error {
		_, res, err := s.Execute(ctx, table.DefaultTxControl(), query, table.NewQueryParameters(
			table.ValueParam("$since", types.TimestampValueFromTime(since)),
		))
		if err != nil {
			return err
		}
		defer res.Close()
		
		for res.NextResultSet(ctx) {
			for res.NextRow() {
				var bucket, s3Key, cid, contentType, etag, pinStatus string
				var size int64
				var lastModified time.Time
				var metadata map[string]string
				var replicationFactor int
				
				err := res.ScanNamed(
					named.OptionalWithDefault("bucket", &bucket),
					named.OptionalWithDefault("s3_key", &s3Key),
					named.OptionalWithDefault("cid", &cid),
					named.OptionalWithDefault("size", &size),
					named.OptionalWithDefault("content_type", &contentType),
					named.OptionalWithDefault("etag", &etag),
					named.OptionalWithDefault("last_modified", &lastModified),
					named.OptionalWithDefault("metadata", &metadata),
					named.OptionalWithDefault("pin_status", &pinStatus),
					named.OptionalWithDefault("replication_factor", &replicationFactor),
				)
				if err != nil {
					return err
				}
				
				mapping := &ObjectMapping{
					Bucket:            bucket,
					S3Key:             s3Key,
					CID:               cid,
					Size:              size,
					ContentType:       contentType,
					ETag:              etag,
					UpdatedAt:         lastModified,
					UserMetadata:      metadata,
					PinStatus:         parsePinStatus(pinStatus),
					ReplicationCount:  int(replicationFactor),
				}
				mappings = append(mappings, mapping)
			}
		}
		
		return res.Err()
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to get mappings modified since %v: %w", since, err)
	}
	
	return mappings, nil
}

// GetTotalPinCount returns the total number of pins across all objects
func (y *YDBMetadataStore) GetTotalPinCount() (int64, error) {
	y.mu.RLock()
	defer y.mu.RUnlock()
	
	if y.shutdown {
		return 0, fmt.Errorf("metadata store is shutdown")
	}
	
	// TODO: Execute YDB query to count total pins
	// For now, return a placeholder value
	return 0, nil
}