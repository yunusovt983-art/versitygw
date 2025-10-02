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
	"log"
	"os"
	"testing"
	"time"
)

// TestYDBMetadataStore tests the YDB metadata store implementation
func TestYDBMetadataStore(t *testing.T) {
	// Skip if YDB is not available
	if testing.Short() {
		t.Skip("Skipping YDB tests in short mode")
	}
	
	logger := log.New(os.Stdout, "ydb-test: ", log.LstdFlags)
	
	config := &MetadataStoreConfig{
		Type:           "ydb",
		Endpoints:      []string{"grpc://localhost:2136"},
		Database:       "/local",
		ConnectTimeout: 30 * time.Second,
		RequestTimeout: 10 * time.Second,
		MaxConnections: 10,
		BatchSize:      100,
		QueryTimeout:   30 * time.Second,
		MetricsEnabled: true,
		LogLevel:       "info",
	}
	
	store, err := NewYDBMetadataStore(config, logger)
	if err != nil {
		t.Fatalf("Failed to create YDB metadata store: %v", err)
	}
	
	ctx := context.Background()
	
	// Note: These tests will fail without a real YDB instance
	// but we can test the store creation and basic structure
	
	t.Run("Initialize", func(t *testing.T) {
		// This will fail without a real YDB instance
		err := store.Initialize(ctx)
		if err != nil {
			t.Logf("Initialize failed as expected without YDB instance: %v", err)
		} else {
			t.Log("Initialize succeeded (unexpected in test environment)")
			// If it succeeds, clean up
			defer store.Shutdown(ctx)
		}
	})
	
	t.Run("Configuration", func(t *testing.T) {
		if store.config.Type != "ydb" {
			t.Errorf("Expected type ydb, got %s", store.config.Type)
		}
		if len(store.config.Endpoints) == 0 {
			t.Error("Expected at least one endpoint")
		}
		if store.config.Database == "" {
			t.Error("Expected database to be set")
		}
		if store.config.ConnectTimeout == 0 {
			t.Error("Expected connect timeout to be set")
		}
		if store.config.BatchSize == 0 {
			t.Error("Expected batch size to be set")
		}
	})
	
	t.Run("Metrics", func(t *testing.T) {
		metrics := store.GetMetrics()
		if metrics == nil {
			t.Fatal("Expected non-nil metrics")
		}
		
		// Initial metrics should be zero
		if metrics.TotalQueries != 0 {
			t.Errorf("Expected initial total queries to be 0, got %d", metrics.TotalQueries)
		}
		if metrics.SuccessfulQueries != 0 {
			t.Errorf("Expected initial successful queries to be 0, got %d", metrics.SuccessfulQueries)
		}
		if metrics.FailedQueries != 0 {
			t.Errorf("Expected initial failed queries to be 0, got %d", metrics.FailedQueries)
		}
	})
	
	t.Run("HealthCheck", func(t *testing.T) {
		// This will fail without initialization
		err := store.HealthCheck(ctx)
		if err == nil {
			t.Error("Expected health check to fail without initialization")
		}
	})
	
	t.Run("StoreMapping", func(t *testing.T) {
		mapping := NewObjectMapping("test-bucket", "test/object.txt", "QmTestCID", 1024)
		
		// This will fail without initialization
		err := store.StoreMapping(ctx, mapping)
		if err == nil {
			t.Error("Expected store mapping to fail without initialization")
		}
	})
	
	t.Run("GetMapping", func(t *testing.T) {
		// This will fail without initialization
		_, err := store.GetMapping(ctx, "test/object.txt", "test-bucket")
		if err == nil {
			t.Error("Expected get mapping to fail without initialization")
		}
	})
	
	t.Run("BatchOperations", func(t *testing.T) {
		mappings := []*ObjectMapping{
			NewObjectMapping("bucket1", "key1", "cid1", 1024),
			NewObjectMapping("bucket1", "key2", "cid2", 2048),
			NewObjectMapping("bucket2", "key3", "cid3", 4096),
		}
		
		// This will fail without initialization
		err := store.StoreMappingBatch(ctx, mappings)
		if err == nil {
			t.Error("Expected batch store to fail without initialization")
		}
		
		keys := []*S3Key{
			{Bucket: "bucket1", Key: "key1"},
			{Bucket: "bucket1", Key: "key2"},
		}
		
		// This will fail without initialization
		_, err = store.GetMappingBatch(ctx, keys)
		if err == nil {
			t.Error("Expected batch get to fail without initialization")
		}
		
		// This will fail without initialization
		err = store.DeleteMappingBatch(ctx, keys)
		if err == nil {
			t.Error("Expected batch delete to fail without initialization")
		}
	})
	
	t.Run("SearchOperations", func(t *testing.T) {
		// This will fail without initialization
		_, err := store.SearchByCID(ctx, "QmTestCID")
		if err == nil {
			t.Error("Expected search by CID to fail without initialization")
		}
		
		// This will fail without initialization
		_, err = store.SearchByPrefix(ctx, "test-bucket", "test/", 10)
		if err == nil {
			t.Error("Expected search by prefix to fail without initialization")
		}
		
		// This will fail without initialization
		_, err = store.ListObjectsInBucket(ctx, "test-bucket", "", 10)
		if err == nil {
			t.Error("Expected list objects to fail without initialization")
		}
	})
	
	t.Run("BucketOperations", func(t *testing.T) {
		bucketMetadata := NewBucketMetadata("test-bucket", "test-owner")
		
		// This will fail without initialization
		err := store.CreateBucket(ctx, "test-bucket", bucketMetadata)
		if err == nil {
			t.Error("Expected create bucket to fail without initialization")
		}
		
		// This will fail without initialization
		_, err = store.GetBucket(ctx, "test-bucket")
		if err == nil {
			t.Error("Expected get bucket to fail without initialization")
		}
		
		// This will fail without initialization
		_, err = store.ListBuckets(ctx)
		if err == nil {
			t.Error("Expected list buckets to fail without initialization")
		}
		
		// This will fail without initialization
		err = store.DeleteBucket(ctx, "test-bucket")
		if err == nil {
			t.Error("Expected delete bucket to fail without initialization")
		}
	})
	
	t.Run("StatisticsOperations", func(t *testing.T) {
		// This will fail without initialization
		_, err := store.GetStats(ctx)
		if err == nil {
			t.Error("Expected get stats to fail without initialization")
		}
		
		// This will fail without initialization
		_, err = store.GetBucketStats(ctx, "test-bucket")
		if err == nil {
			t.Error("Expected get bucket stats to fail without initialization")
		}
	})
	
	t.Run("MaintenanceOperations", func(t *testing.T) {
		// This will fail without initialization
		err := store.Compact(ctx)
		if err == nil {
			t.Error("Expected compact to fail without initialization")
		}
		
		// This will fail without initialization
		err = store.Backup(ctx, "/tmp/backup")
		if err == nil {
			t.Error("Expected backup to fail without initialization")
		}
		
		// This will fail without initialization
		err = store.Restore(ctx, "/tmp/backup")
		if err == nil {
			t.Error("Expected restore to fail without initialization")
		}
	})
	
	t.Run("Shutdown", func(t *testing.T) {
		// Shutdown should work even without initialization
		err := store.Shutdown(ctx)
		if err != nil {
			t.Errorf("Unexpected error during shutdown: %v", err)
		}
		
		// Operations after shutdown should fail
		err = store.HealthCheck(ctx)
		if err == nil {
			t.Error("Expected operations to fail after shutdown")
		}
	})
}

// TestYDBMetadataStoreConfig tests YDB-specific configuration
func TestYDBMetadataStoreConfig(t *testing.T) {
	logger := log.New(os.Stdout, "ydb-config-test: ", log.LstdFlags)
	
	t.Run("ValidConfig", func(t *testing.T) {
		config := &MetadataStoreConfig{
			Type:           "ydb",
			Endpoints:      []string{"grpc://localhost:2136"},
			Database:       "/local",
			ConnectTimeout: 30 * time.Second,
			RequestTimeout: 10 * time.Second,
			MaxConnections: 10,
			BatchSize:      100,
		}
		
		store, err := NewYDBMetadataStore(config, logger)
		if err != nil {
			t.Fatalf("Failed to create YDB store with valid config: %v", err)
		}
		
		if store == nil {
			t.Fatal("Expected non-nil store")
		}
	})
	
	t.Run("InvalidConfigs", func(t *testing.T) {
		testCases := []struct {
			name   string
			config *MetadataStoreConfig
		}{
			{
				name:   "nil config",
				config: nil,
			},
			{
				name: "empty endpoints",
				config: &MetadataStoreConfig{
					Type:     "ydb",
					Database: "/local",
				},
			},
			{
				name: "empty database",
				config: &MetadataStoreConfig{
					Type:      "ydb",
					Endpoints: []string{"grpc://localhost:2136"},
				},
			},
		}
		
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := NewYDBMetadataStore(tc.config, logger)
				if err == nil {
					t.Error("Expected error for invalid config")
				}
			})
		}
	})
	
	t.Run("DefaultValues", func(t *testing.T) {
		config := &MetadataStoreConfig{
			Type:      "ydb",
			Endpoints: []string{"grpc://localhost:2136"},
			Database:  "/local",
		}
		
		store, err := NewYDBMetadataStore(config, logger)
		if err != nil {
			t.Fatalf("Failed to create YDB store: %v", err)
		}
		
		// Check that defaults were set
		if store.config.ConnectTimeout == 0 {
			t.Error("Expected default connect timeout to be set")
		}
		if store.config.RequestTimeout == 0 {
			t.Error("Expected default request timeout to be set")
		}
		if store.config.MaxConnections == 0 {
			t.Error("Expected default max connections to be set")
		}
		if store.config.BatchSize == 0 {
			t.Error("Expected default batch size to be set")
		}
	})
}

// TestYDBHelperMethods tests YDB-specific helper methods
func TestYDBHelperMethods(t *testing.T) {
	logger := log.New(os.Stdout, "ydb-helper-test: ", log.LstdFlags)
	
	config := &MetadataStoreConfig{
		Type:      "ydb",
		Endpoints: []string{"grpc://localhost:2136"},
		Database:  "/local",
	}
	
	store, err := NewYDBMetadataStore(config, logger)
	if err != nil {
		t.Fatalf("Failed to create YDB store: %v", err)
	}
	
	t.Run("calculatePrefixEnd", func(t *testing.T) {
		testCases := []struct {
			prefix   string
			expected string
		}{
			{"", ""},
			{"a", "b"},
			{"test", "tesu"},
			{"test/", "test0"},
			{"prefix-", "prefix."},
		}
		
		for _, tc := range testCases {
			t.Run(tc.prefix, func(t *testing.T) {
				result := store.calculatePrefixEnd(tc.prefix)
				if result != tc.expected {
					t.Errorf("Expected %s, got %s", tc.expected, result)
				}
			})
		}
	})
	
	t.Run("updateMetrics", func(t *testing.T) {
		initialMetrics := store.GetMetrics()
		initialTotal := initialMetrics.TotalQueries
		initialSuccessful := initialMetrics.SuccessfulQueries
		
		// Update metrics with successful operation
		store.updateMetrics(100*time.Millisecond, nil)
		
		updatedMetrics := store.GetMetrics()
		if updatedMetrics.TotalQueries != initialTotal+1 {
			t.Errorf("Expected total queries to increment by 1, got %d", updatedMetrics.TotalQueries)
		}
		if updatedMetrics.SuccessfulQueries != initialSuccessful+1 {
			t.Errorf("Expected successful queries to increment by 1, got %d", updatedMetrics.SuccessfulQueries)
		}
		if updatedMetrics.AverageLatency == 0 {
			t.Error("Expected average latency to be updated")
		}
	})
}

// BenchmarkYDBMetadataStore benchmarks YDB metadata store operations
func BenchmarkYDBMetadataStore(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping YDB benchmarks in short mode")
	}
	
	logger := log.New(os.Stdout, "ydb-bench: ", log.LstdFlags)
	
	config := &MetadataStoreConfig{
		Type:      "ydb",
		Endpoints: []string{"grpc://localhost:2136"},
		Database:  "/local",
		BatchSize: 1000,
	}
	
	store, err := NewYDBMetadataStore(config, logger)
	if err != nil {
		b.Fatalf("Failed to create YDB store: %v", err)
	}
	
	b.Run("NewYDBMetadataStore", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = NewYDBMetadataStore(config, logger)
		}
	})
	
	b.Run("GetMetrics", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = store.GetMetrics()
		}
	})
	
	b.Run("calculatePrefixEnd", func(b *testing.B) {
		prefix := "test/prefix/path"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = store.calculatePrefixEnd(prefix)
		}
	})
	
	b.Run("updateMetrics", func(b *testing.B) {
		duration := 100 * time.Millisecond
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			store.updateMetrics(duration, nil)
		}
	})
}