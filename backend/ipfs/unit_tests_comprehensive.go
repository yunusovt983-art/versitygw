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
	"sync"
	"testing"
	"time"
)

// TestAllComponents runs comprehensive unit tests for all major components
func TestAllComponents(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()
	
	t.Run("IPFSBackend", func(t *testing.T) {
		testIPFSBackendUnit(t, suite)
	})
	
	t.Run("ClusterClient", func(t *testing.T) {
		testClusterClientUnit(t, suite)
	})
	
	t.Run("PinManager", func(t *testing.T) {
		testPinManagerUnit(t, suite)
	})
	
	t.Run("MetadataStore", func(t *testing.T) {
		testMetadataStoreUnit(t, suite)
	})
	
	t.Run("CacheLayer", func(t *testing.T) {
		testCacheLayerUnit(t, suite)
	})
	
	t.Run("ReplicaManager", func(t *testing.T) {
		testReplicaManagerUnit(t, suite)
	})
	
	t.Run("SecurityComponents", func(t *testing.T) {
		testSecurityComponentsUnit(t, suite)
	})
}

// testIPFSBackendUnit tests the IPFS backend component
func testIPFSBackendUnit(t *testing.T, suite *TestSuite) {
	t.Run("Initialization", func(t *testing.T) {
		if suite.backend == nil {
			t.Fatal("Backend should not be nil")
		}
		
		if suite.backend.String() != "IPFS-Cluster" {
			t.Errorf("Expected backend type 'IPFS-Cluster', got '%s'", suite.backend.String())
		}
	})
	
	t.Run("Configuration", func(t *testing.T) {
		config := suite.backend.GetConfig()
		if config == nil {
			t.Fatal("Config should not be nil")
		}
		
		if len(config.ClusterEndpoints) == 0 {
			t.Error("Should have cluster endpoints")
		}
		
		if config.ReplicationMin > config.ReplicationMax {
			t.Error("ReplicationMin should not be greater than ReplicationMax")
		}
	})
	
	t.Run("HealthCheck", func(t *testing.T) {
		// Backend should be healthy when properly initialized
		if !suite.backend.IsHealthy() {
			t.Error("Backend should be healthy")
		}
		
		// Test health check components
		healthStatus := suite.backend.GetHealthStatus()
		if healthStatus == nil {
			t.Error("Health status should not be nil")
		}
		
		if !healthStatus.Overall {
			t.Error("Overall health should be true")
		}
	})
	
	t.Run("Statistics", func(t *testing.T) {
		stats := suite.backend.GetStats()
		if stats == nil {
			t.Error("Stats should not be nil")
		}
		
		if stats["backend_type"] != "ipfs-cluster" {
			t.Error("Backend type should be 'ipfs-cluster'")
		}
		
		// Should have basic stats
		expectedKeys := []string{"backend_type", "cluster_nodes", "total_pins", "healthy_nodes"}
		for _, key := range expectedKeys {
			if _, exists := stats[key]; !exists {
				t.Errorf("Stats should contain key '%s'", key)
			}
		}
	})
	
	t.Run("Shutdown", func(t *testing.T) {
		// Create a separate backend for shutdown testing
		testBackend, err := NewWithMocks(suite.config, NewMockClusterClient(), NewMockMetadataStore(), suite.logger)
		if err != nil {
			t.Fatalf("Failed to create test backend: %v", err)
		}
		
		// Should be healthy initially
		if !testBackend.IsHealthy() {
			t.Error("Test backend should be healthy initially")
		}
		
		// Shutdown should work without error
		testBackend.Shutdown()
		
		// Should not be healthy after shutdown
		if testBackend.IsHealthy() {
			t.Error("Backend should not be healthy after shutdown")
		}
	})
}

// testClusterClientUnit tests the cluster client component
func testClusterClientUnit(t *testing.T, suite *TestSuite) {
	client := suite.clusterClient
	
	t.Run("NodeStatus", func(t *testing.T) {
		status := client.GetNodeStatus()
		if len(status) == 0 {
			t.Error("Should have at least one node")
		}
		
		for _, node := range status {
			if node.Endpoint == "" {
				t.Error("Node endpoint should not be empty")
			}
		}
	})
	
	t.Run("ClusterInfo", func(t *testing.T) {
		info, err := client.GetClusterInfo()
		if err != nil {
			t.Fatalf("Failed to get cluster info: %v", err)
		}
		
		if info.ID == "" {
			t.Error("Cluster ID should not be empty")
		}
		
		if info.Peers <= 0 {
			t.Error("Should have at least one peer")
		}
	})
	
	t.Run("Metrics", func(t *testing.T) {
		metrics := client.GetMetrics()
		if metrics == nil {
			t.Error("Metrics should not be nil")
		}
		
		// Metrics should be initialized
		if metrics.TotalRequests < 0 {
			t.Error("Total requests should not be negative")
		}
	})
	
	t.Run("PinOperations", func(t *testing.T) {
		ctx := context.Background()
		cid := "QmUnitTest123"
		
		// Test pin
		result, err := client.Pin(ctx, cid, 2)
		if err != nil {
			t.Fatalf("Pin operation failed: %v", err)
		}
		
		if result.CID != cid {
			t.Errorf("Expected CID %s, got %s", cid, result.CID)
		}
		
		if len(result.NodesUsed) == 0 {
			t.Error("Should have nodes used for pin")
		}
		
		// Test unpin
		unpinResult, err := client.Unpin(ctx, cid)
		if err != nil {
			t.Fatalf("Unpin operation failed: %v", err)
		}
		
		if unpinResult.CID != cid {
			t.Errorf("Expected CID %s, got %s", cid, unpinResult.CID)
		}
	})
	
	t.Run("ErrorHandling", func(t *testing.T) {
		ctx := context.Background()
		
		// Test with invalid CID
		_, err := client.Pin(ctx, "", 1)
		if err == nil {
			t.Error("Should fail with empty CID")
		}
		
		// Test with invalid replication factor
		_, err = client.Pin(ctx, "QmTest", 0)
		if err == nil {
			t.Error("Should fail with zero replication factor")
		}
	})
}

// testPinManagerUnit tests the pin manager component
func testPinManagerUnit(t *testing.T, suite *TestSuite) {
	// Create a dedicated pin manager for testing
	config := &PinManagerConfig{
		PinWorkerCount:     2,
		UnpinWorkerCount:   1,
		PinQueueSize:       100,
		UnpinQueueSize:     50,
		RetryQueueSize:     25,
		PinTimeout:         5 * time.Second,
		UnpinTimeout:       3 * time.Second,
		MaxRetries:         2,
		InitialRetryDelay:  100 * time.Millisecond,
		MaxRetryDelay:      1 * time.Second,
		RetryBackoffFactor: 2.0,
		MetricsEnabled:     true,
		MetricsInterval:    1 * time.Second,
	}
	
	mockCluster := NewMockClusterClient()
	mockMetadata := NewMockMetadataStore()
	
	pm, err := NewPinManager(config, mockCluster, mockMetadata, suite.logger)
	if err != nil {
		t.Fatalf("Failed to create pin manager: %v", err)
	}
	
	t.Run("Initialization", func(t *testing.T) {
		if pm == nil {
			t.Fatal("Pin manager should not be nil")
		}
		
		if pm.config.PinWorkerCount != 2 {
			t.Errorf("Expected 2 pin workers, got %d", pm.config.PinWorkerCount)
		}
	})
	
	t.Run("StartStop", func(t *testing.T) {
		// Should not be running initially
		if pm.isRunning() {
			t.Error("Pin manager should not be running initially")
		}
		
		// Start should work
		err := pm.Start()
		if err != nil {
			t.Fatalf("Failed to start pin manager: %v", err)
		}
		
		if !pm.isRunning() {
			t.Error("Pin manager should be running after start")
		}
		
		// Stop should work
		err = pm.Stop()
		if err != nil {
			t.Fatalf("Failed to stop pin manager: %v", err)
		}
		
		if pm.isRunning() {
			t.Error("Pin manager should not be running after stop")
		}
	})
	
	t.Run("PinOperations", func(t *testing.T) {
		err := pm.Start()
		if err != nil {
			t.Fatalf("Failed to start pin manager: %v", err)
		}
		defer pm.Stop()
		
		ctx := context.Background()
		cid := "QmPinTest123"
		s3Key := "test-key"
		bucket := "test-bucket"
		size := int64(1024)
		replicationFactor := 2
		
		// Test synchronous pin
		result, err := pm.Pin(ctx, cid, s3Key, bucket, size, replicationFactor, PinPriorityNormal)
		if err != nil {
			t.Fatalf("Pin operation failed: %v", err)
		}
		
		if !result.Success {
			t.Errorf("Pin should have succeeded: %v", result.Error)
		}
		
		// Test asynchronous pin
		requestID, err := pm.PinAsync(ctx, "QmAsyncPin", "async-key", bucket, size, replicationFactor, PinPriorityBackground)
		if err != nil {
			t.Fatalf("Async pin failed: %v", err)
		}
		
		if requestID == "" {
			t.Error("Request ID should not be empty")
		}
	})
	
	t.Run("Metrics", func(t *testing.T) {
		err := pm.Start()
		if err != nil {
			t.Fatalf("Failed to start pin manager: %v", err)
		}
		defer pm.Stop()
		
		metrics := pm.GetMetrics()
		if metrics == nil {
			t.Error("Metrics should not be nil")
		}
		
		// Should have worker counts
		if metrics.ActivePinWorkers != 2 {
			t.Errorf("Expected 2 active pin workers, got %d", metrics.ActivePinWorkers)
		}
		
		if metrics.ActiveUnpinWorkers != 1 {
			t.Errorf("Expected 1 active unpin worker, got %d", metrics.ActiveUnpinWorkers)
		}
	})
	
	t.Run("QueueStats", func(t *testing.T) {
		stats := pm.GetQueueStats()
		if stats == nil {
			t.Error("Queue stats should not be nil")
		}
		
		if stats.PinQueueCapacity != 100 {
			t.Errorf("Expected pin queue capacity 100, got %d", stats.PinQueueCapacity)
		}
		
		if stats.UnpinQueueCapacity != 50 {
			t.Errorf("Expected unpin queue capacity 50, got %d", stats.UnpinQueueCapacity)
		}
	})
}

// testMetadataStoreUnit tests the metadata store component
func testMetadataStoreUnit(t *testing.T, suite *TestSuite) {
	store := suite.metadataStore
	ctx := context.Background()
	
	t.Run("BasicOperations", func(t *testing.T) {
		mapping := &ObjectMapping{
			S3Key:     "test-key",
			Bucket:    "test-bucket",
			CID:       "QmTest123",
			Size:      1024,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			PinStatus: PinStatusPinned,
		}
		
		// Test store
		err := store.StoreMapping(ctx, mapping)
		if err != nil {
			t.Fatalf("Failed to store mapping: %v", err)
		}
		
		// Test get
		retrieved, err := store.GetMapping(ctx, mapping.S3Key, mapping.Bucket)
		if err != nil {
			t.Fatalf("Failed to get mapping: %v", err)
		}
		
		if retrieved == nil {
			t.Fatal("Retrieved mapping should not be nil")
		}
		
		if retrieved.CID != mapping.CID {
			t.Errorf("Expected CID %s, got %s", mapping.CID, retrieved.CID)
		}
		
		// Test update
		retrieved.PinStatus = PinStatusUnpinned
		err = store.UpdateMapping(ctx, retrieved)
		if err != nil {
			t.Fatalf("Failed to update mapping: %v", err)
		}
		
		// Test delete
		err = store.DeleteMapping(ctx, mapping.S3Key, mapping.Bucket)
		if err != nil {
			t.Fatalf("Failed to delete mapping: %v", err)
		}
		
		// Should not exist after delete
		deleted, err := store.GetMapping(ctx, mapping.S3Key, mapping.Bucket)
		if err != nil {
			t.Fatalf("Error getting deleted mapping: %v", err)
		}
		
		if deleted != nil {
			t.Error("Mapping should not exist after delete")
		}
	})
	
	t.Run("BatchOperations", func(t *testing.T) {
		mappings := make([]*ObjectMapping, 10)
		for i := 0; i < 10; i++ {
			mappings[i] = &ObjectMapping{
				S3Key:     fmt.Sprintf("batch-key-%d", i),
				Bucket:    "batch-bucket",
				CID:       fmt.Sprintf("QmBatch%d", i),
				Size:      int64(1024 * (i + 1)),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}
		}
		
		// Test batch store
		err := store.StoreMappingBatch(ctx, mappings)
		if err != nil {
			t.Fatalf("Failed to store batch mappings: %v", err)
		}
		
		// Test batch get
		keys := make([]*S3Key, len(mappings))
		for i, mapping := range mappings {
			keys[i] = &S3Key{
				Key:    mapping.S3Key,
				Bucket: mapping.Bucket,
			}
		}
		
		retrieved, err := store.GetMappingBatch(ctx, keys)
		if err != nil {
			t.Fatalf("Failed to get batch mappings: %v", err)
		}
		
		if len(retrieved) != len(mappings) {
			t.Errorf("Expected %d mappings, got %d", len(mappings), len(retrieved))
		}
	})
	
	t.Run("SearchOperations", func(t *testing.T) {
		// Store some test data
		testMappings := []*ObjectMapping{
			{S3Key: "search-1", Bucket: "search-bucket", CID: "QmSearch1", Size: 1024, PinStatus: PinStatusPinned},
			{S3Key: "search-2", Bucket: "search-bucket", CID: "QmSearch2", Size: 2048, PinStatus: PinStatusPinned},
			{S3Key: "other-1", Bucket: "search-bucket", CID: "QmOther1", Size: 512, PinStatus: PinStatusPinned},
		}
		
		for _, mapping := range testMappings {
			mapping.CreatedAt = time.Now()
			mapping.UpdatedAt = time.Now()
			err := store.StoreMapping(ctx, mapping)
			if err != nil {
				t.Fatalf("Failed to store test mapping: %v", err)
			}
		}
		
		// Test search by CID
		results, err := store.SearchByCID(ctx, "QmSearch1")
		if err != nil {
			t.Fatalf("Failed to search by CID: %v", err)
		}
		
		if len(results) != 1 {
			t.Errorf("Expected 1 result, got %d", len(results))
		}
		
		// Test search by prefix
		prefixResults, err := store.SearchByPrefix(ctx, "search-bucket", "search-", 10)
		if err != nil {
			t.Fatalf("Failed to search by prefix: %v", err)
		}
		
		if len(prefixResults) != 2 {
			t.Errorf("Expected 2 results for prefix search, got %d", len(prefixResults))
		}
	})
	
	t.Run("BucketOperations", func(t *testing.T) {
		bucketName := "unit-test-bucket"
		metadata := NewBucketMetadata(bucketName, "test-owner")
		
		// Test create bucket
		err := store.CreateBucket(ctx, bucketName, metadata)
		if err != nil {
			t.Fatalf("Failed to create bucket: %v", err)
		}
		
		// Test get bucket
		retrieved, err := store.GetBucket(ctx, bucketName)
		if err != nil {
			t.Fatalf("Failed to get bucket: %v", err)
		}
		
		if retrieved == nil {
			t.Fatal("Retrieved bucket should not be nil")
		}
		
		if retrieved.Name != bucketName {
			t.Errorf("Expected bucket name %s, got %s", bucketName, retrieved.Name)
		}
		
		// Test list buckets
		buckets, err := store.ListBuckets(ctx)
		if err != nil {
			t.Fatalf("Failed to list buckets: %v", err)
		}
		
		if len(buckets) == 0 {
			t.Error("Should have at least one bucket")
		}
		
		// Test delete bucket
		err = store.DeleteBucket(ctx, bucketName)
		if err != nil {
			t.Fatalf("Failed to delete bucket: %v", err)
		}
	})
	
	t.Run("Statistics", func(t *testing.T) {
		stats, err := store.GetStats(ctx)
		if err != nil {
			t.Fatalf("Failed to get stats: %v", err)
		}
		
		if stats == nil {
			t.Error("Stats should not be nil")
		}
		
		if stats.HealthScore < 0 || stats.HealthScore > 100 {
			t.Errorf("Health score should be between 0 and 100, got %.2f", stats.HealthScore)
		}
	})
}

// testCacheLayerUnit tests the cache layer component
func testCacheLayerUnit(t *testing.T, suite *TestSuite) {
	// This would test the cache layer if it was implemented
	// For now, we'll create a basic test structure
	
	t.Run("CacheInterface", func(t *testing.T) {
		// Test that cache interface is properly defined
		// This is a placeholder for actual cache testing
		t.Skip("Cache layer unit tests not implemented yet")
	})
}

// testReplicaManagerUnit tests the replica manager component
func testReplicaManagerUnit(t *testing.T, suite *TestSuite) {
	t.Run("ReplicationPolicies", func(t *testing.T) {
		// Test replication policy logic
		// This is a placeholder for actual replica manager testing
		t.Skip("Replica manager unit tests not implemented yet")
	})
}

// testSecurityComponentsUnit tests security-related components
func testSecurityComponentsUnit(t *testing.T, suite *TestSuite) {
	t.Run("AccessControl", func(t *testing.T) {
		// Test access control mechanisms
		// This is a placeholder for actual security testing
		t.Skip("Security component unit tests not implemented yet")
	})
	
	t.Run("Encryption", func(t *testing.T) {
		// Test encryption/decryption
		// This is a placeholder for actual encryption testing
		t.Skip("Encryption unit tests not implemented yet")
	})
}

// TestComponentIntegration tests integration between components
func TestComponentIntegration(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()
	
	t.Run("BackendPinManagerIntegration", func(t *testing.T) {
		testBackendPinManagerIntegration(t, suite)
	})
	
	t.Run("PinManagerMetadataIntegration", func(t *testing.T) {
		testPinManagerMetadataIntegration(t, suite)
	})
	
	t.Run("ClusterClientPinManagerIntegration", func(t *testing.T) {
		testClusterClientPinManagerIntegration(t, suite)
	})
}

// testBackendPinManagerIntegration tests integration between backend and pin manager
func testBackendPinManagerIntegration(t *testing.T, suite *TestSuite) {
	ctx := context.Background()
	
	// Test that backend properly delegates to pin manager
	testData := suite.GenerateTestData(1)[0]
	
	// This would test actual S3 operations that use the pin manager
	// For now, we'll test the basic integration
	if suite.backend == nil {
		t.Fatal("Backend should not be nil")
	}
	
	// Test health check integration
	if !suite.backend.IsHealthy() {
		t.Error("Backend should be healthy when pin manager is healthy")
	}
	
	_ = ctx
	_ = testData
}

// testPinManagerMetadataIntegration tests integration between pin manager and metadata store
func testPinManagerMetadataIntegration(t *testing.T, suite *TestSuite) {
	// Test that pin operations properly update metadata
	// This is a placeholder for actual integration testing
	t.Skip("Pin manager metadata integration tests not fully implemented yet")
}

// testClusterClientPinManagerIntegration tests integration between cluster client and pin manager
func testClusterClientPinManagerIntegration(t *testing.T, suite *TestSuite) {
	// Test that pin manager properly uses cluster client
	// This is a placeholder for actual integration testing
	t.Skip("Cluster client pin manager integration tests not fully implemented yet")
}

// TestErrorHandling tests comprehensive error handling across components
func TestErrorHandling(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()
	
	t.Run("ClusterFailure", func(t *testing.T) {
		// Test behavior when cluster operations fail
		suite.clusterClient.SetFailPin(true)
		
		// Operations should handle failures gracefully
		ctx := context.Background()
		_, err := suite.clusterClient.Pin(ctx, "QmErrorTest", 2)
		if err == nil {
			t.Error("Should fail when cluster pin is set to fail")
		}
		
		// Reset for other tests
		suite.clusterClient.SetFailPin(false)
	})
	
	t.Run("MetadataFailure", func(t *testing.T) {
		// Test behavior when metadata operations fail
		suite.metadataStore.SetFailOps(true)
		
		ctx := context.Background()
		mapping := &ObjectMapping{
			S3Key:  "error-test",
			Bucket: "error-bucket",
			CID:    "QmErrorTest",
		}
		
		err := suite.metadataStore.StoreMapping(ctx, mapping)
		if err == nil {
			t.Error("Should fail when metadata ops are set to fail")
		}
		
		// Reset for other tests
		suite.metadataStore.SetFailOps(false)
	})
	
	t.Run("TimeoutHandling", func(t *testing.T) {
		// Test timeout handling
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()
		
		// This should timeout quickly
		_, err := suite.clusterClient.Pin(ctx, "QmTimeoutTest", 2)
		if err == nil {
			t.Error("Should timeout with very short context")
		}
	})
}

// TestConcurrency tests concurrent operations
func TestConcurrency(t *testing.T) {
	suite := NewTestSuite(t)
	defer suite.Cleanup()
	
	t.Run("ConcurrentPins", func(t *testing.T) {
		ctx := context.Background()
		numGoroutines := 10
		numOpsPerGoroutine := 10
		
		var wg sync.WaitGroup
		errors := make(chan error, numGoroutines*numOpsPerGoroutine)
		
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				
				for j := 0; j < numOpsPerGoroutine; j++ {
					cid := fmt.Sprintf("QmConcurrent%d-%d", goroutineID, j)
					_, err := suite.clusterClient.Pin(ctx, cid, 2)
					if err != nil {
						errors <- err
					}
				}
			}(i)
		}
		
		wg.Wait()
		close(errors)
		
		// Check for errors
		errorCount := 0
		for err := range errors {
			t.Errorf("Concurrent operation error: %v", err)
			errorCount++
		}
		
		if errorCount > 0 {
			t.Errorf("Had %d errors in concurrent operations", errorCount)
		}
	})
	
	t.Run("ConcurrentMetadataOps", func(t *testing.T) {
		ctx := context.Background()
		numGoroutines := 5
		numOpsPerGoroutine := 20
		
		var wg sync.WaitGroup
		errors := make(chan error, numGoroutines*numOpsPerGoroutine)
		
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				
				for j := 0; j < numOpsPerGoroutine; j++ {
					mapping := &ObjectMapping{
						S3Key:     fmt.Sprintf("concurrent-%d-%d", goroutineID, j),
						Bucket:    fmt.Sprintf("bucket-%d", goroutineID),
						CID:       fmt.Sprintf("QmConcurrentMeta%d-%d", goroutineID, j),
						Size:      int64(1024 * (j + 1)),
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
						PinStatus: PinStatusPinned,
					}
					
					err := suite.metadataStore.StoreMapping(ctx, mapping)
					if err != nil {
						errors <- err
					}
				}
			}(i)
		}
		
		wg.Wait()
		close(errors)
		
		// Check for errors
		errorCount := 0
		for err := range errors {
			t.Errorf("Concurrent metadata operation error: %v", err)
			errorCount++
		}
		
		if errorCount > 0 {
			t.Errorf("Had %d errors in concurrent metadata operations", errorCount)
		}
	})
}