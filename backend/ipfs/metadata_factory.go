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
	"time"
)

// MetadataStoreType represents the type of metadata store
type MetadataStoreType string

const (
	MetadataStoreTypeMemory  MetadataStoreType = "memory"
	MetadataStoreTypeScylla  MetadataStoreType = "scylla"
	MetadataStoreTypeScyllaDB MetadataStoreType = "scylladb"
	MetadataStoreTypeYDB     MetadataStoreType = "ydb"
	MetadataStoreTypeCassandra MetadataStoreType = "cassandra"
	MetadataStoreTypePostgres MetadataStoreType = "postgres"
	MetadataStoreTypeMongoDB  MetadataStoreType = "mongodb"
)

// MetadataStoreFactory creates metadata store instances
type MetadataStoreFactory struct {
	logger *log.Logger
}

// NewMetadataStoreFactory creates a new metadata store factory
func NewMetadataStoreFactory(logger *log.Logger) *MetadataStoreFactory {
	if logger == nil {
		logger = log.Default()
	}
	
	return &MetadataStoreFactory{
		logger: logger,
	}
}

// CreateMetadataStore creates a metadata store instance based on configuration
func (f *MetadataStoreFactory) CreateMetadataStore(config *MetadataStoreConfig) (MetadataStore, error) {
	if config == nil {
		return nil, fmt.Errorf("metadata store config cannot be nil")
	}
	
	storeType := MetadataStoreType(strings.ToLower(config.Type))
	
	f.logger.Printf("Creating metadata store of type: %s", storeType)
	
	switch storeType {
	case MetadataStoreTypeMemory:
		return f.createMemoryStore(config)
	case MetadataStoreTypeScylla, MetadataStoreTypeScyllaDB:
		return f.createScyllaStore(config)
	case MetadataStoreTypeYDB:
		return f.createYDBStore(config)
	case MetadataStoreTypeCassandra:
		return f.createCassandraStore(config)
	case MetadataStoreTypePostgres:
		return f.createPostgresStore(config)
	case MetadataStoreTypeMongoDB:
		return f.createMongoDBStore(config)
	default:
		return nil, fmt.Errorf("unsupported metadata store type: %s", config.Type)
	}
}

// createMemoryStore creates an in-memory metadata store
func (f *MetadataStoreFactory) createMemoryStore(config *MetadataStoreConfig) (MetadataStore, error) {
	f.logger.Println("Creating in-memory metadata store")
	
	store := NewMemoryMetadataStore(config)
	
	// Initialize the store
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := store.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize memory metadata store: %w", err)
	}
	
	f.logger.Println("In-memory metadata store created successfully")
	return store, nil
}

// createScyllaStore creates a ScyllaDB metadata store
func (f *MetadataStoreFactory) createScyllaStore(config *MetadataStoreConfig) (MetadataStore, error) {
	f.logger.Printf("Creating ScyllaDB metadata store with endpoints: %v", config.Endpoints)
	
	// Validate ScyllaDB-specific configuration
	if err := f.validateScyllaConfig(config); err != nil {
		return nil, fmt.Errorf("invalid ScyllaDB configuration: %w", err)
	}
	
	store, err := NewScyllaMetadataStore(config, f.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create ScyllaDB metadata store: %w", err)
	}
	
	// Initialize the store
	ctx, cancel := context.WithTimeout(context.Background(), config.ConnectTimeout)
	defer cancel()
	
	if err := store.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize ScyllaDB metadata store: %w", err)
	}
	
	f.logger.Println("ScyllaDB metadata store created successfully")
	return store, nil
}

// createYDBStore creates a YDB metadata store
func (f *MetadataStoreFactory) createYDBStore(config *MetadataStoreConfig) (MetadataStore, error) {
	f.logger.Printf("Creating YDB metadata store with endpoints: %v", config.Endpoints)
	
	// Validate YDB-specific configuration
	if err := f.validateYDBConfig(config); err != nil {
		return nil, fmt.Errorf("invalid YDB configuration: %w", err)
	}
	
	store, err := NewYDBMetadataStore(config, f.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create YDB metadata store: %w", err)
	}
	
	// Initialize the store
	ctx, cancel := context.WithTimeout(context.Background(), config.ConnectTimeout)
	defer cancel()
	
	if err := store.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize YDB metadata store: %w", err)
	}
	
	f.logger.Println("YDB metadata store created successfully")
	return store, nil
}

// createCassandraStore creates a Cassandra metadata store
func (f *MetadataStoreFactory) createCassandraStore(config *MetadataStoreConfig) (MetadataStore, error) {
	f.logger.Printf("Creating Cassandra metadata store with endpoints: %v", config.Endpoints)
	
	// TODO: Implement Cassandra metadata store (similar to ScyllaDB)
	// For now, delegate to ScyllaDB implementation as they're compatible
	return f.createScyllaStore(config)
}

// createPostgresStore creates a PostgreSQL metadata store
func (f *MetadataStoreFactory) createPostgresStore(config *MetadataStoreConfig) (MetadataStore, error) {
	f.logger.Printf("Creating PostgreSQL metadata store with endpoints: %v", config.Endpoints)
	
	// TODO: Implement PostgreSQL metadata store
	return nil, fmt.Errorf("PostgreSQL metadata store not yet implemented")
}

// createMongoDBStore creates a MongoDB metadata store
func (f *MetadataStoreFactory) createMongoDBStore(config *MetadataStoreConfig) (MetadataStore, error) {
	f.logger.Printf("Creating MongoDB metadata store with endpoints: %v", config.Endpoints)
	
	// TODO: Implement MongoDB metadata store
	return nil, fmt.Errorf("MongoDB metadata store not yet implemented")
}

// validateScyllaConfig validates ScyllaDB-specific configuration
func (f *MetadataStoreFactory) validateScyllaConfig(config *MetadataStoreConfig) error {
	if len(config.Endpoints) == 0 {
		return fmt.Errorf("at least one endpoint must be specified")
	}
	
	if config.Keyspace == "" {
		config.Keyspace = "versitygw_ipfs" // Default keyspace
	}
	
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
	
	// Validate consistency level
	validConsistencyLevels := map[string]bool{
		"ANY":         true,
		"ONE":         true,
		"TWO":         true,
		"THREE":       true,
		"QUORUM":      true,
		"ALL":         true,
		"LOCAL_QUORUM": true,
		"EACH_QUORUM": true,
		"LOCAL_ONE":   true,
	}
	
	if !validConsistencyLevels[config.ConsistencyLevel] {
		return fmt.Errorf("invalid consistency level: %s", config.ConsistencyLevel)
	}
	
	return nil
}

// GetSupportedStoreTypes returns a list of supported metadata store types
func (f *MetadataStoreFactory) GetSupportedStoreTypes() []MetadataStoreType {
	return []MetadataStoreType{
		MetadataStoreTypeMemory,
		MetadataStoreTypeScylla,
		MetadataStoreTypeScyllaDB,
		MetadataStoreTypeYDB,
		MetadataStoreTypeCassandra,
		MetadataStoreTypePostgres,
		MetadataStoreTypeMongoDB,
	}
}

// GetImplementedStoreTypes returns a list of currently implemented metadata store types
func (f *MetadataStoreFactory) GetImplementedStoreTypes() []MetadataStoreType {
	return []MetadataStoreType{
		MetadataStoreTypeMemory,
		MetadataStoreTypeScylla,
		MetadataStoreTypeScyllaDB,
		MetadataStoreTypeYDB,
		MetadataStoreTypeCassandra, // Uses ScyllaDB implementation
	}
}

// IsStoreTypeSupported checks if a store type is supported
func (f *MetadataStoreFactory) IsStoreTypeSupported(storeType string) bool {
	supportedTypes := f.GetSupportedStoreTypes()
	for _, supported := range supportedTypes {
		if string(supported) == strings.ToLower(storeType) {
			return true
		}
	}
	return false
}

// IsStoreTypeImplemented checks if a store type is implemented
func (f *MetadataStoreFactory) IsStoreTypeImplemented(storeType string) bool {
	implementedTypes := f.GetImplementedStoreTypes()
	for _, implemented := range implementedTypes {
		if string(implemented) == strings.ToLower(storeType) {
			return true
		}
	}
	return false
}

// CreateDefaultConfig creates a default configuration for a given store type
func (f *MetadataStoreFactory) CreateDefaultConfig(storeType string) *MetadataStoreConfig {
	switch MetadataStoreType(strings.ToLower(storeType)) {
	case MetadataStoreTypeMemory:
		return &MetadataStoreConfig{
			Type:               "memory",
			BatchSize:          1000,
			QueryTimeout:       30 * time.Second,
			MetricsEnabled:     true,
			LogLevel:           "info",
		}
	
	case MetadataStoreTypeScylla, MetadataStoreTypeScyllaDB:
		return &MetadataStoreConfig{
			Type:               "scylla",
			Endpoints:          []string{"localhost:9042"},
			Keyspace:           "versitygw_ipfs",
			ConnectTimeout:     30 * time.Second,
			RequestTimeout:     10 * time.Second,
			MaxConnections:     100,
			MaxIdleConns:       10,
			ConnMaxLifetime:    time.Hour,
			BatchSize:          1000,
			QueryTimeout:       30 * time.Second,
			BulkInsertSize:     10000,
			IndexCacheSize:     100 * 1024 * 1024, // 100MB
			ConsistencyLevel:   "QUORUM",
			ReplicationFactor:  3,
			CompressionEnabled: true,
			CompressionType:    "LZ4",
			BackupEnabled:      false,
			BackupInterval:     24 * time.Hour,
			CompactionEnabled:  true,
			CompactionInterval: 7 * 24 * time.Hour,
			MetricsEnabled:     true,
			LogLevel:           "info",
		}
	
	case MetadataStoreTypeYDB:
		return &MetadataStoreConfig{
			Type:               "ydb",
			Endpoints:          []string{"grpc://localhost:2136"},
			Database:           "/local",
			ConnectTimeout:     30 * time.Second,
			RequestTimeout:     10 * time.Second,
			MaxConnections:     100,
			BatchSize:          1000,
			QueryTimeout:       30 * time.Second,
			MetricsEnabled:     true,
			LogLevel:           "info",
		}
	
	case MetadataStoreTypePostgres:
		return &MetadataStoreConfig{
			Type:               "postgres",
			Endpoints:          []string{"localhost:5432"},
			Database:           "versitygw_ipfs",
			Username:           "postgres",
			ConnectTimeout:     30 * time.Second,
			RequestTimeout:     10 * time.Second,
			MaxConnections:     100,
			MaxIdleConns:       10,
			ConnMaxLifetime:    time.Hour,
			BatchSize:          1000,
			QueryTimeout:       30 * time.Second,
			MetricsEnabled:     true,
			LogLevel:           "info",
		}
	
	case MetadataStoreTypeMongoDB:
		return &MetadataStoreConfig{
			Type:               "mongodb",
			Endpoints:          []string{"localhost:27017"},
			Database:           "versitygw_ipfs",
			ConnectTimeout:     30 * time.Second,
			RequestTimeout:     10 * time.Second,
			MaxConnections:     100,
			BatchSize:          1000,
			QueryTimeout:       30 * time.Second,
			MetricsEnabled:     true,
			LogLevel:           "info",
		}
	
	default:
		return &MetadataStoreConfig{
			Type:           "memory",
			BatchSize:      1000,
			QueryTimeout:   30 * time.Second,
			MetricsEnabled: true,
			LogLevel:       "info",
		}
	}
}

// ValidateConfig validates a metadata store configuration
func (f *MetadataStoreFactory) ValidateConfig(config *MetadataStoreConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	if config.Type == "" {
		return fmt.Errorf("store type must be specified")
	}
	
	if !f.IsStoreTypeSupported(config.Type) {
		return fmt.Errorf("unsupported store type: %s", config.Type)
	}
	
	storeType := MetadataStoreType(strings.ToLower(config.Type))
	
	switch storeType {
	case MetadataStoreTypeMemory:
		return f.validateMemoryConfig(config)
	case MetadataStoreTypeScylla, MetadataStoreTypeScyllaDB, MetadataStoreTypeCassandra:
		return f.validateScyllaConfig(config)
	case MetadataStoreTypeYDB:
		return f.validateYDBConfig(config)
	case MetadataStoreTypePostgres:
		return f.validatePostgresConfig(config)
	case MetadataStoreTypeMongoDB:
		return f.validateMongoDBConfig(config)
	default:
		return fmt.Errorf("validation not implemented for store type: %s", config.Type)
	}
}

// validateMemoryConfig validates memory store configuration
func (f *MetadataStoreFactory) validateMemoryConfig(config *MetadataStoreConfig) error {
	// Memory store has minimal configuration requirements
	if config.BatchSize <= 0 {
		config.BatchSize = 1000
	}
	
	if config.QueryTimeout <= 0 {
		config.QueryTimeout = 30 * time.Second
	}
	
	return nil
}

// validateYDBConfig validates YDB configuration
func (f *MetadataStoreFactory) validateYDBConfig(config *MetadataStoreConfig) error {
	if len(config.Endpoints) == 0 {
		return fmt.Errorf("at least one endpoint must be specified")
	}
	
	if config.Database == "" {
		return fmt.Errorf("database must be specified for YDB")
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
	
	return nil
}

// validatePostgresConfig validates PostgreSQL configuration
func (f *MetadataStoreFactory) validatePostgresConfig(config *MetadataStoreConfig) error {
	if len(config.Endpoints) == 0 {
		return fmt.Errorf("at least one endpoint must be specified")
	}
	
	if config.Database == "" {
		return fmt.Errorf("database must be specified for PostgreSQL")
	}
	
	if config.Username == "" {
		return fmt.Errorf("username must be specified for PostgreSQL")
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
	
	return nil
}

// validateMongoDBConfig validates MongoDB configuration
func (f *MetadataStoreFactory) validateMongoDBConfig(config *MetadataStoreConfig) error {
	if len(config.Endpoints) == 0 {
		return fmt.Errorf("at least one endpoint must be specified")
	}
	
	if config.Database == "" {
		return fmt.Errorf("database must be specified for MongoDB")
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
	
	return nil
}

// TestConnection tests the connection to a metadata store
func (f *MetadataStoreFactory) TestConnection(config *MetadataStoreConfig) error {
	f.logger.Printf("Testing connection to %s metadata store", config.Type)
	
	// Create a temporary store instance
	store, err := f.CreateMetadataStore(config)
	if err != nil {
		return fmt.Errorf("failed to create store for connection test: %w", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		store.Shutdown(ctx)
	}()
	
	// Perform health check
	ctx, cancel := context.WithTimeout(context.Background(), config.ConnectTimeout)
	defer cancel()
	
	if err := store.HealthCheck(ctx); err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	
	f.logger.Printf("Connection test successful for %s metadata store", config.Type)
	return nil
}