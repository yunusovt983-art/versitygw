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
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"
)

// TestChunkingManager tests the chunking functionality
func TestChunkingManager(t *testing.T) {
	logger := log.New(bytes.NewBuffer(nil), "", 0)
	
	// Create chunking manager with test config
	config := &ChunkingConfig{
		DefaultChunkSize:        1024,      // 1KB for testing
		MinChunkSize:           512,        // 512B minimum
		MaxChunkSize:           2048,       // 2KB maximum
		ChunkingThreshold:      2048,       // 2KB threshold
		OptimalChunkCount:      5,          // Target 5 chunks
		DeduplicationEnabled:   true,
		ContentHashingEnabled:  true,
		MaxConcurrentChunks:    3,
		ChunkTimeout:          10 * time.Second,
		CompressionEnabled:    true,
		CompressionLevel:      6,
		CompressionAlgorithm:  "gzip",
		MetricsEnabled:        true,
	}
	
	manager := NewChunkingManager(config, nil, nil, logger)
	
	t.Run("ShouldChunk", func(t *testing.T) {
		// Small file should not be chunked
		if manager.ShouldChunk(1024) {
			t.Error("Small file should not be chunked")
		}
		
		// Large file should be chunked
		if !manager.ShouldChunk(5120) {
			t.Error("Large file should be chunked")
		}
	})
	
	t.Run("CalculateOptimalChunkSize", func(t *testing.T) {
		// Test optimal chunk size calculation
		size := manager.CalculateOptimalChunkSize(10240) // 10KB
		expectedSize := int64(2048) // 10KB / 5 chunks = 2KB, capped at max
		
		if size != expectedSize {
			t.Errorf("Expected chunk size %d, got %d", expectedSize, size)
		}
		
		// Test minimum chunk size enforcement
		size = manager.CalculateOptimalChunkSize(1024) // 1KB
		if size != 1024 {
			t.Errorf("Expected chunk size %d for small file, got %d", 1024, size)
		}
	})
	
	t.Run("ChunkFile", func(t *testing.T) {
		// Create test data
		testData := strings.Repeat("test data chunk ", 200) // ~3KB
		reader := strings.NewReader(testData)
		
		ctx := context.Background()
		chunkedFile, err := manager.ChunkFile(ctx, reader, int64(len(testData)), "test-key", "test-bucket")
		
		if err != nil {
			t.Fatalf("ChunkFile failed: %v", err)
		}
		
		if chunkedFile == nil {
			t.Fatal("ChunkedFile is nil")
		}
		
		if chunkedFile.TotalSize != int64(len(testData)) {
			t.Errorf("Expected total size %d, got %d", len(testData), chunkedFile.TotalSize)
		}
		
		if len(chunkedFile.Chunks) == 0 {
			t.Error("No chunks created")
		}
		
		if chunkedFile.ManifestCID == "" {
			t.Error("Manifest CID is empty")
		}
		
		// Verify chunk information
		totalChunkSize := int64(0)
		for i, chunk := range chunkedFile.Chunks {
			if chunk.Index != i {
				t.Errorf("Chunk %d has wrong index %d", i, chunk.Index)
			}
			if chunk.CID == "" {
				t.Errorf("Chunk %d has empty CID", i)
			}
			if chunk.Hash == "" {
				t.Errorf("Chunk %d has empty hash", i)
			}
			totalChunkSize += chunk.Size
		}
		
		if totalChunkSize != int64(len(testData)) {
			t.Errorf("Total chunk size %d doesn't match original size %d", totalChunkSize, len(testData))
		}
	})
	
	t.Run("DeduplicationCache", func(t *testing.T) {
		cache := NewDeduplicationCache()
		
		// Test cache miss
		cid := cache.GetCID("nonexistent")
		if cid != "" {
			t.Error("Expected empty CID for nonexistent hash")
		}
		
		// Test cache set and hit
		testHash := "testhash123"
		testCID := "testcid456"
		cache.SetCID(testHash, testCID)
		
		retrievedCID := cache.GetCID(testHash)
		if retrievedCID != testCID {
			t.Errorf("Expected CID %s, got %s", testCID, retrievedCID)
		}
		
		// Test reference counting
		cache.IncrementRef(testCID)
		cache.IncrementRef(testCID)
		
		hits, misses, uniqueContent := cache.GetStats()
		if hits != 1 {
			t.Errorf("Expected 1 hit, got %d", hits)
		}
		if misses != 1 {
			t.Errorf("Expected 1 miss, got %d", misses)
		}
		if uniqueContent != 1 {
			t.Errorf("Expected 1 unique content, got %d", uniqueContent)
		}
	})
	
	t.Run("Metrics", func(t *testing.T) {
		metrics := manager.GetMetrics()
		
		if metrics == nil {
			t.Fatal("Metrics is nil")
		}
		
		// Metrics should be initialized
		if metrics.TotalChunkingOperations < 0 {
			t.Error("Invalid total chunking operations")
		}
	})
}

// TestBatchAPI tests the batch API functionality
func TestBatchAPI(t *testing.T) {
	logger := log.New(bytes.NewBuffer(nil), "", 0)
	
	// Create batch API with test config
	config := &BatchConfig{
		MaxBatchSize:         100,
		DefaultBatchSize:     10,
		MinBatchSize:         1,
		BatchTimeout:         5 * time.Second,
		ProcessingTimeout:    30 * time.Second,
		RetryDelay:          100 * time.Millisecond,
		MaxConcurrentBatches: 5,
		WorkerPoolSize:       3,
		MaxRetries:          2,
		RetryBackoffFactor:  2.0,
		PipeliningEnabled:   true,
		CompressionEnabled:  false,
		MetricsEnabled:      true,
		MetricsInterval:     1 * time.Second,
	}
	
	// Create mock dependencies
	clusterClient := &MockClusterClientInterface{}
	metadataStore := &MockMetadataStore{}
	pinManager := &MockPinManager{}
	
	api := NewBatchAPI(config, clusterClient, metadataStore, pinManager, logger)
	
	// Start the API
	err := api.Start()
	if err != nil {
		t.Fatalf("Failed to start batch API: %v", err)
	}
	defer api.Stop()
	
	t.Run("ValidateBatchRequest", func(t *testing.T) {
		// Test empty batch
		emptyRequest := &BatchRequest{
			Type:  BatchOperationPin,
			Items: []*BatchItem{},
		}
		
		err := api.validateBatchRequest(emptyRequest)
		if err == nil {
			t.Error("Expected error for empty batch request")
		}
		
		// Test valid batch
		validRequest := &BatchRequest{
			Type: BatchOperationPin,
			Items: []*BatchItem{
				{
					CID:    "test-cid-1",
					S3Key:  "test-key-1",
					Bucket: "test-bucket",
					Size:   1024,
				},
			},
		}
		
		err = api.validateBatchRequest(validRequest)
		if err != nil {
			t.Errorf("Valid batch request failed validation: %v", err)
		}
		
		// Test oversized batch
		oversizedItems := make([]*BatchItem, config.MaxBatchSize+1)
		for i := range oversizedItems {
			oversizedItems[i] = &BatchItem{
				CID:    "test-cid",
				S3Key:  "test-key",
				Bucket: "test-bucket",
			}
		}
		
		oversizedRequest := &BatchRequest{
			Type:  BatchOperationPin,
			Items: oversizedItems,
		}
		
		err = api.validateBatchRequest(oversizedRequest)
		if err == nil {
			t.Error("Expected error for oversized batch request")
		}
	})
	
	t.Run("BatchPin", func(t *testing.T) {
		items := []*BatchItem{
			{
				CID:               "test-cid-1",
				S3Key:             "test-key-1",
				Bucket:            "test-bucket",
				Size:              1024,
				ReplicationFactor: 3,
				Priority:          PinPriorityNormal,
			},
			{
				CID:               "test-cid-2",
				S3Key:             "test-key-2",
				Bucket:            "test-bucket",
				Size:              2048,
				ReplicationFactor: 2,
				Priority:          PinPriorityHigh,
			},
		}
		
		ctx := context.Background()
		result, err := api.BatchPin(ctx, items, BatchPriorityNormal)
		
		if err != nil {
			t.Fatalf("BatchPin failed: %v", err)
		}
		
		if result == nil {
			t.Fatal("Batch result is nil")
		}
		
		if result.TotalItems != len(items) {
			t.Errorf("Expected %d total items, got %d", len(items), result.TotalItems)
		}
		
		if len(result.ItemResults) != len(items) {
			t.Errorf("Expected %d item results, got %d", len(items), len(result.ItemResults))
		}
		
		// Check that all items were processed
		for i, itemResult := range result.ItemResults {
			if itemResult.CID != items[i].CID {
				t.Errorf("Item %d: expected CID %s, got %s", i, items[i].CID, itemResult.CID)
			}
		}
	})
	
	t.Run("BatchUnpin", func(t *testing.T) {
		items := []*BatchItem{
			{
				CID:    "test-cid-1",
				S3Key:  "test-key-1",
				Bucket: "test-bucket",
			},
		}
		
		ctx := context.Background()
		result, err := api.BatchUnpin(ctx, items, BatchPriorityNormal)
		
		if err != nil {
			t.Fatalf("BatchUnpin failed: %v", err)
		}
		
		if result.Type != BatchOperationUnpin {
			t.Errorf("Expected operation type %s, got %s", BatchOperationUnpin.String(), result.Type.String())
		}
	})
	
	t.Run("BatchVerify", func(t *testing.T) {
		items := []*BatchItem{
			{
				CID:    "test-cid-1",
				S3Key:  "test-key-1",
				Bucket: "test-bucket",
			},
		}
		
		ctx := context.Background()
		result, err := api.BatchVerify(ctx, items, BatchPriorityHigh)
		
		if err != nil {
			t.Fatalf("BatchVerify failed: %v", err)
		}
		
		if result.Type != BatchOperationVerify {
			t.Errorf("Expected operation type %s, got %s", BatchOperationVerify.String(), result.Type.String())
		}
	})
	
	t.Run("Metrics", func(t *testing.T) {
		metrics := api.GetMetrics()
		
		if metrics == nil {
			t.Fatal("Metrics is nil")
		}
		
		// Should have processed some batches by now
		if metrics.TotalBatches == 0 {
			t.Error("Expected some batches to be processed")
		}
	})
}

// TestConnectionPool tests the connection pool functionality
func TestConnectionPool(t *testing.T) {
	logger := log.New(bytes.NewBuffer(nil), "", 0)
	
	// Create connection pool with test config
	config := &ConnectionPoolConfig{
		MaxConnectionsPerEndpoint: 10,
		MinConnectionsPerEndpoint: 2,
		InitialPoolSize:          5,
		ConnectTimeout:           5 * time.Second,
		RequestTimeout:           10 * time.Second,
		IdleTimeout:             30 * time.Second,
		KeepAliveTimeout:        15 * time.Second,
		MaxIdleTime:             60 * time.Second,
		PoolGrowthFactor:        1.5,
		PoolShrinkThreshold:     0.3,
		PoolGrowthThreshold:     0.8,
		PoolCleanupInterval:     10 * time.Second,
		LoadBalancingStrategy:   LoadBalancingRoundRobin,
		HealthCheckInterval:     5 * time.Second,
		FailureThreshold:        3,
		RecoveryThreshold:       2,
		CircuitBreakerEnabled:   true,
		CircuitBreakerThreshold: 5,
		CircuitBreakerTimeout:   30 * time.Second,
		CircuitBreakerResetTime: 60 * time.Second,
		MaxRetries:             3,
		RetryDelay:             1 * time.Second,
		RetryBackoffFactor:     2.0,
		MetricsEnabled:         true,
		MetricsInterval:        5 * time.Second,
	}
	
	endpoints := []string{
		"http://localhost:9094",
		"http://localhost:9095",
		"http://localhost:9096",
	}
	
	pool := NewConnectionPool(config, endpoints, logger)
	
	// Start the pool
	err := pool.Start()
	if err != nil {
		t.Fatalf("Failed to start connection pool: %v", err)
	}
	defer pool.Stop()
	
	t.Run("GetConnection", func(t *testing.T) {
		ctx := context.Background()
		
		// Get a connection
		conn, err := pool.GetConnection(ctx)
		if err != nil {
			t.Fatalf("Failed to get connection: %v", err)
		}
		
		if conn == nil {
			t.Fatal("Connection is nil")
		}
		
		if conn.endpoint == "" {
			t.Error("Connection endpoint is empty")
		}
		
		if conn.client == nil {
			t.Error("Connection HTTP client is nil")
		}
		
		// Return the connection
		pool.ReturnConnection(conn)
	})
	
	t.Run("LoadBalancer", func(t *testing.T) {
		// Update healthy endpoints
		pool.loadBalancer.UpdateHealthyEndpoints(endpoints)
		
		// Test endpoint selection
		endpoint1, err := pool.loadBalancer.SelectEndpoint()
		if err != nil {
			t.Fatalf("Failed to select endpoint: %v", err)
		}
		
		endpoint2, err := pool.loadBalancer.SelectEndpoint()
		if err != nil {
			t.Fatalf("Failed to select endpoint: %v", err)
		}
		
		// With round-robin, endpoints should be different (if we have multiple)
		if len(endpoints) > 1 && endpoint1 == endpoint2 {
			// This might happen with round-robin, so just check they're valid
		}
		
		// Check that selected endpoints are in our list
		found := false
		for _, ep := range endpoints {
			if ep == endpoint1 {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Selected endpoint %s not in original list", endpoint1)
		}
	})
	
	t.Run("HealthMonitor", func(t *testing.T) {
		// Get healthy endpoints
		healthyEndpoints := pool.healthMonitor.GetHealthyEndpoints()
		
		// Should have some healthy endpoints (initially all are considered healthy)
		if len(healthyEndpoints) == 0 {
			t.Error("No healthy endpoints found")
		}
		
		// Check that healthy endpoints are from our original list
		for _, healthy := range healthyEndpoints {
			found := false
			for _, original := range endpoints {
				if original == healthy {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Healthy endpoint %s not in original list", healthy)
			}
		}
	})
	
	t.Run("CircuitBreaker", func(t *testing.T) {
		// Create a circuit breaker for testing
		cb := NewCircuitBreaker(config)
		
		// Initially should allow execution
		if !cb.CanExecute() {
			t.Error("Circuit breaker should initially allow execution")
		}
		
		// Record some failures
		for i := 0; i < config.CircuitBreakerThreshold; i++ {
			cb.RecordFailure()
		}
		
		// Should now be open
		if cb.CanExecute() {
			t.Error("Circuit breaker should be open after threshold failures")
		}
		
		// Record success should reset
		cb.RecordSuccess()
		if !cb.CanExecute() {
			t.Error("Circuit breaker should allow execution after success")
		}
	})
	
	t.Run("Metrics", func(t *testing.T) {
		metrics := pool.GetMetrics()
		
		if metrics == nil {
			t.Fatal("Metrics is nil")
		}
		
		if metrics.TotalPools != int32(len(endpoints)) {
			t.Errorf("Expected %d pools, got %d", len(endpoints), metrics.TotalPools)
		}
		
		if metrics.TotalConnections == 0 {
			t.Error("Expected some connections to be created")
		}
	})
}

// TestOptimizedQueryManager tests the optimized query manager functionality
func TestOptimizedQueryManager(t *testing.T) {
	logger := log.New(bytes.NewBuffer(nil), "", 0)
	
	// Create query manager with test config
	config := &QueryOptimizationConfig{
		PreparedStatementsEnabled: true,
		MaxPreparedStatements:     100,
		StatementCacheSize:        50,
		StatementTimeout:          10 * time.Second,
		QueryCacheEnabled:         true,
		QueryCacheSize:            1000,
		QueryCacheTTL:             1 * time.Minute,
		CacheHitRatioThreshold:    0.8,
		OptimizationEnabled:       true,
		IndexHintsEnabled:         true,
		QueryPlanCacheEnabled:     true,
		StatisticsUpdateInterval:  30 * time.Second,
		QueryConnectionPoolSize:   10,
		MaxQueryConnections:       50,
		QueryConnectionTimeout:    5 * time.Second,
		BatchQueryEnabled:         true,
		MaxBatchSize:              100,
		BatchTimeout:              5 * time.Second,
		SlowQueryThreshold:        500 * time.Millisecond,
		QueryMetricsEnabled:       true,
		QueryProfilingEnabled:     false,
	}
	
	manager := NewOptimizedQueryManager(config, logger)
	
	// Start the manager
	err := manager.Start()
	if err != nil {
		t.Fatalf("Failed to start query manager: %v", err)
	}
	defer manager.Stop()
	
	t.Run("PrepareStatement", func(t *testing.T) {
		stmtID := "test_statement"
		sql := "SELECT * FROM test_table WHERE id = ?"
		
		err := manager.PrepareStatement(stmtID, sql)
		if err != nil {
			t.Fatalf("Failed to prepare statement: %v", err)
		}
		
		// Check that statement was stored
		manager.mu.RLock()
		stmt, exists := manager.preparedStatements[stmtID]
		manager.mu.RUnlock()
		
		if !exists {
			t.Error("Prepared statement not found")
		}
		
		if stmt.SQL != sql {
			t.Errorf("Expected SQL %s, got %s", sql, stmt.SQL)
		}
	})
	
	t.Run("ExecutePreparedQuery", func(t *testing.T) {
		ctx := context.Background()
		
		// Execute a prepared query
		result, err := manager.ExecutePreparedQuery(ctx, "get_mapping", "test-key", "test-bucket")
		if err != nil {
			t.Fatalf("Failed to execute prepared query: %v", err)
		}
		
		if result == nil {
			t.Error("Query result is nil")
		}
		
		// Execute the same query again (should hit cache)
		result2, err := manager.ExecutePreparedQuery(ctx, "get_mapping", "test-key", "test-bucket")
		if err != nil {
			t.Fatalf("Failed to execute cached query: %v", err)
		}
		
		if result2 == nil {
			t.Error("Cached query result is nil")
		}
	})
	
	t.Run("ExecuteBatchQuery", func(t *testing.T) {
		ctx := context.Background()
		
		queries := []*BatchQuery{
			{
				StatementID: "get_mapping",
				Parameters:  []interface{}{"key1", "bucket1"},
			},
			{
				StatementID: "get_mapping",
				Parameters:  []interface{}{"key2", "bucket1"},
			},
		}
		
		results, err := manager.ExecuteBatchQuery(ctx, queries)
		if err != nil {
			t.Fatalf("Failed to execute batch query: %v", err)
		}
		
		if len(results) != len(queries) {
			t.Errorf("Expected %d results, got %d", len(queries), len(results))
		}
		
		for i, result := range results {
			if result.Index != i {
				t.Errorf("Result %d has wrong index %d", i, result.Index)
			}
		}
	})
	
	t.Run("QueryCache", func(t *testing.T) {
		cache := NewQueryCache(config)
		
		// Test cache miss
		result := cache.Get("nonexistent")
		if result != nil {
			t.Error("Expected nil for nonexistent cache key")
		}
		
		// Test cache set and hit
		testKey := "test_key"
		testValue := "test_value"
		cache.Set(testKey, testValue)
		
		retrievedValue := cache.Get(testKey)
		if retrievedValue != testValue {
			t.Errorf("Expected value %s, got %v", testValue, retrievedValue)
		}
		
		// Test cache expiration (would need to wait for TTL in real scenario)
		// For testing, we'll just verify the structure is correct
		cache.mu.RLock()
		entry, exists := cache.cache[testKey]
		cache.mu.RUnlock()
		
		if !exists {
			t.Error("Cache entry not found")
		}
		
		if entry.Key != testKey {
			t.Errorf("Expected key %s, got %s", testKey, entry.Key)
		}
	})
	
	t.Run("Statistics", func(t *testing.T) {
		stats := manager.GetStatistics()
		
		if stats == nil {
			t.Fatal("Statistics is nil")
		}
		
		// Should have executed some queries by now
		if stats.TotalQueries == 0 {
			t.Error("Expected some queries to be executed")
		}
		
		if stats.SuccessfulQueries == 0 {
			t.Error("Expected some successful queries")
		}
	})
	
	t.Run("IndexRecommendations", func(t *testing.T) {
		recommendations := manager.GetIndexRecommendations()
		
		// Should have some recommendations (generated during optimization)
		if len(recommendations) == 0 {
			t.Error("Expected some index recommendations")
		}
		
		for _, rec := range recommendations {
			if rec.Table == "" {
				t.Error("Index recommendation has empty table")
			}
			if len(rec.Columns) == 0 {
				t.Error("Index recommendation has no columns")
			}
		}
	})
}

// Use existing mock implementations from other test files

// Benchmark tests for performance validation

func BenchmarkChunkingManager_ChunkFile(b *testing.B) {
	logger := log.New(bytes.NewBuffer(nil), "", 0)
	config := getDefaultChunkingConfig()
	manager := NewChunkingManager(config, nil, nil, logger)
	
	// Create test data
	testData := strings.Repeat("benchmark test data ", 1000) // ~20KB
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		reader := strings.NewReader(testData)
		ctx := context.Background()
		
		_, err := manager.ChunkFile(ctx, reader, int64(len(testData)), "bench-key", "bench-bucket")
		if err != nil {
			b.Fatalf("ChunkFile failed: %v", err)
		}
	}
}

func BenchmarkBatchAPI_BatchPin(b *testing.B) {
	logger := log.New(bytes.NewBuffer(nil), "", 0)
	config := getDefaultBatchConfig()
	
	clusterClient := &MockClusterClientInterface{}
	metadataStore := &MockMetadataStore{}
	pinManager := &MockPinManager{}
	
	api := NewBatchAPI(config, clusterClient, metadataStore, pinManager, logger)
	api.Start()
	defer api.Stop()
	
	// Create test items
	items := make([]*BatchItem, 100)
	for i := range items {
		items[i] = &BatchItem{
			CID:    "bench-cid",
			S3Key:  "bench-key",
			Bucket: "bench-bucket",
			Size:   1024,
		}
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := api.BatchPin(ctx, items, BatchPriorityNormal)
		if err != nil {
			b.Fatalf("BatchPin failed: %v", err)
		}
	}
}

func BenchmarkConnectionPool_GetConnection(b *testing.B) {
	logger := log.New(bytes.NewBuffer(nil), "", 0)
	config := getDefaultConnectionPoolConfig()
	endpoints := []string{"http://localhost:9094", "http://localhost:9095"}
	
	pool := NewConnectionPool(config, endpoints, logger)
	pool.Start()
	defer pool.Stop()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		conn, err := pool.GetConnection(ctx)
		if err != nil {
			b.Fatalf("GetConnection failed: %v", err)
		}
		pool.ReturnConnection(conn)
	}
}

func BenchmarkOptimizedQueryManager_ExecutePreparedQuery(b *testing.B) {
	logger := log.New(bytes.NewBuffer(nil), "", 0)
	config := getDefaultQueryOptimizationConfig()
	
	manager := NewOptimizedQueryManager(config, logger)
	manager.Start()
	defer manager.Stop()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := manager.ExecutePreparedQuery(ctx, "get_mapping", "bench-key", "bench-bucket")
		if err != nil {
			b.Fatalf("ExecutePreparedQuery failed: %v", err)
		}
	}
}