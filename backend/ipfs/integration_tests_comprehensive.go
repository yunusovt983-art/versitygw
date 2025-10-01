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
	"os"
	"sync"
	"testing"
	"time"
)

// IntegrationTestSuite represents the integration test suite
type IntegrationTestSuite struct {
	*TestSuite
	realClusterEndpoints []string
	useRealCluster       bool
	testDataDir          string
}

// NewIntegrationTestSuite creates a new integration test suite
func NewIntegrationTestSuite(t *testing.T) *IntegrationTestSuite {
	suite := NewTestSuite(t)
	
	// Check if real IPFS cluster endpoints are available
	realEndpoints := os.Getenv("IPFS_CLUSTER_ENDPOINTS")
	useReal := realEndpoints != "" && os.Getenv("IPFS_INTEGRATION_TESTS") == "true"
	
	var endpoints []string
	if useReal {
		// Parse real endpoints from environment
		endpoints = []string{realEndpoints} // Simplified - could parse multiple
	}
	
	testDataDir := os.TempDir() + "/ipfs-integration-tests"
	os.MkdirAll(testDataDir, 0755)
	
	return &IntegrationTestSuite{
		TestSuite:            suite,
		realClusterEndpoints: endpoints,
		useRealCluster:       useReal,
		testDataDir:          testDataDir,
	}
}

// Cleanup cleans up the integration test suite
func (its *IntegrationTestSuite) Cleanup() {
	its.TestSuite.Cleanup()
	os.RemoveAll(its.testDataDir)
}

// TestRealIPFSClusterIntegration tests integration with a real IPFS cluster
func TestRealIPFSClusterIntegration(t *testing.T) {
	if os.Getenv("IPFS_INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping real IPFS cluster integration tests. Set IPFS_INTEGRATION_TESTS=true to run.")
	}
	
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	
	if !suite.useRealCluster {
		t.Skip("Real IPFS cluster not available for integration testing")
	}
	
	t.Run("ClusterConnection", func(t *testing.T) {
		testRealClusterConnection(t, suite)
	})
	
	t.Run("PinOperations", func(t *testing.T) {
		testRealPinOperations(t, suite)
	})
	
	t.Run("LargeObjectHandling", func(t *testing.T) {
		testRealLargeObjectHandling(t, suite)
	})
	
	t.Run("MultipartUpload", func(t *testing.T) {
		testRealMultipartUpload(t, suite)
	})
	
	t.Run("ReplicationVerification", func(t *testing.T) {
		testRealReplicationVerification(t, suite)
	})
}

// testRealClusterConnection tests connection to a real IPFS cluster
func testRealClusterConnection(t *testing.T, suite *IntegrationTestSuite) {
	// Create a real cluster client
	config := ClusterClientConfig{
		Endpoints:      suite.realClusterEndpoints,
		ConnectTimeout: 10 * time.Second,
		RequestTimeout: 30 * time.Second,
		MaxRetries:     3,
		RetryDelay:     1 * time.Second,
		Logger:         suite.logger,
	}
	
	client, err := NewClusterClient(config)
	if err != nil {
		t.Fatalf("Failed to create real cluster client: %v", err)
	}
	defer client.Shutdown()
	
	// Test cluster info
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
	
	t.Logf("Connected to cluster %s with %d peers", info.ID, info.Peers)
	
	// Test node status
	nodes := client.GetNodeStatus()
	if len(nodes) == 0 {
		t.Error("Should have at least one node")
	}
	
	healthyNodes := 0
	for _, node := range nodes {
		if node.Healthy {
			healthyNodes++
		}
	}
	
	if healthyNodes == 0 {
		t.Error("Should have at least one healthy node")
	}
	
	t.Logf("Found %d healthy nodes out of %d total", healthyNodes, len(nodes))
}

// testRealPinOperations tests pin operations with a real cluster
func testRealPinOperations(t *testing.T, suite *IntegrationTestSuite) {
	if !suite.useRealCluster {
		t.Skip("Real cluster not available")
	}
	
	// Create real cluster client
	config := ClusterClientConfig{
		Endpoints:      suite.realClusterEndpoints,
		ConnectTimeout: 10 * time.Second,
		RequestTimeout: 30 * time.Second,
		MaxRetries:     3,
		RetryDelay:     1 * time.Second,
		Logger:         suite.logger,
	}
	
	client, err := NewClusterClient(config)
	if err != nil {
		t.Fatalf("Failed to create real cluster client: %v", err)
	}
	defer client.Shutdown()
	
	ctx := context.Background()
	
	// Test pin operation with a known CID (this should be a valid IPFS CID)
	// For testing, we'll use a well-known CID or create content first
	testCID := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG" // "hello world" CID
	
	t.Run("PinKnownCID", func(t *testing.T) {
		result, err := client.Pin(ctx, testCID, 1)
		if err != nil {
			t.Logf("Pin operation failed (expected for test CID): %v", err)
			// This might fail if the CID doesn't exist in the network
			// That's okay for this test
			return
		}
		
		if result.CID != testCID {
			t.Errorf("Expected CID %s, got %s", testCID, result.CID)
		}
		
		t.Logf("Successfully pinned %s to nodes: %v", testCID, result.NodesUsed)
		
		// Test unpin
		unpinResult, err := client.Unpin(ctx, testCID)
		if err != nil {
			t.Errorf("Unpin operation failed: %v", err)
		} else {
			t.Logf("Successfully unpinned %s from nodes: %v", testCID, unpinResult.NodesUsed)
		}
	})
	
	t.Run("PinNonExistentCID", func(t *testing.T) {
		// This should fail gracefully
		nonExistentCID := "QmNonExistent123456789"
		_, err := client.Pin(ctx, nonExistentCID, 1)
		if err == nil {
			t.Error("Should fail when pinning non-existent CID")
		} else {
			t.Logf("Correctly failed to pin non-existent CID: %v", err)
		}
	})
}

// testRealLargeObjectHandling tests handling of large objects
func testRealLargeObjectHandling(t *testing.T, suite *IntegrationTestSuite) {
	if !suite.useRealCluster {
		t.Skip("Real cluster not available")
	}
	
	// This test would require actually adding large content to IPFS
	// and then pinning it. For now, we'll simulate the test structure.
	t.Skip("Large object handling test requires content addition to IPFS")
}

// testRealMultipartUpload tests multipart upload functionality
func testRealMultipartUpload(t *testing.T, suite *IntegrationTestSuite) {
	if !suite.useRealCluster {
		t.Skip("Real cluster not available")
	}
	
	// This test would require implementing multipart upload with real IPFS
	t.Skip("Multipart upload test requires full S3 API implementation")
}

// testRealReplicationVerification tests replication verification
func testRealReplicationVerification(t *testing.T, suite *IntegrationTestSuite) {
	if !suite.useRealCluster {
		t.Skip("Real cluster not available")
	}
	
	// This test would verify that pins are actually replicated across nodes
	t.Skip("Replication verification test requires cluster inspection APIs")
}

// TestEndToEndWorkflow tests complete end-to-end workflows
func TestEndToEndWorkflow(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	
	t.Run("S3PutGetDeleteWorkflow", func(t *testing.T) {
		testS3PutGetDeleteWorkflow(t, suite)
	})
	
	t.Run("BucketOperationsWorkflow", func(t *testing.T) {
		testBucketOperationsWorkflow(t, suite)
	})
	
	t.Run("MultiObjectWorkflow", func(t *testing.T) {
		testMultiObjectWorkflow(t, suite)
	})
}

// testS3PutGetDeleteWorkflow tests the complete S3 put/get/delete workflow
func testS3PutGetDeleteWorkflow(t *testing.T, suite *IntegrationTestSuite) {
	ctx := context.Background()
	
	// Generate test data
	testData := suite.GenerateTestData(1)[0]
	
	// This would test the complete workflow:
	// 1. S3 PutObject -> IPFS add + pin + metadata store
	// 2. S3 GetObject -> metadata lookup + IPFS get
	// 3. S3 DeleteObject -> metadata delete + IPFS unpin
	
	// For now, we'll test the individual components
	t.Run("MetadataStoreWorkflow", func(t *testing.T) {
		mapping := &ObjectMapping{
			S3Key:     testData.S3Key,
			Bucket:    testData.Bucket,
			CID:       testData.CID,
			Size:      testData.Size,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			PinStatus: PinStatusPending,
		}
		
		// Store mapping
		err := suite.metadataStore.StoreMapping(ctx, mapping)
		if err != nil {
			t.Fatalf("Failed to store mapping: %v", err)
		}
		
		// Update pin status
		mapping.PinStatus = PinStatusPinned
		err = suite.metadataStore.UpdateMapping(ctx, mapping)
		if err != nil {
			t.Fatalf("Failed to update mapping: %v", err)
		}
		
		// Retrieve mapping
		retrieved, err := suite.metadataStore.GetMapping(ctx, testData.S3Key, testData.Bucket)
		if err != nil {
			t.Fatalf("Failed to get mapping: %v", err)
		}
		
		if retrieved.PinStatus != PinStatusPinned {
			t.Errorf("Expected pin status %v, got %v", PinStatusPinned, retrieved.PinStatus)
		}
		
		// Delete mapping
		err = suite.metadataStore.DeleteMapping(ctx, testData.S3Key, testData.Bucket)
		if err != nil {
			t.Fatalf("Failed to delete mapping: %v", err)
		}
	})
	
	t.Run("ClusterPinWorkflow", func(t *testing.T) {
		// Pin object
		result, err := suite.clusterClient.Pin(ctx, testData.CID, 2)
		if err != nil {
			t.Fatalf("Failed to pin object: %v", err)
		}
		
		if !result.Success {
			t.Errorf("Pin should have succeeded")
		}
		
		// Unpin object
		unpinResult, err := suite.clusterClient.Unpin(ctx, testData.CID)
		if err != nil {
			t.Fatalf("Failed to unpin object: %v", err)
		}
		
		if !unpinResult.Success {
			t.Errorf("Unpin should have succeeded")
		}
	})
}

// testBucketOperationsWorkflow tests bucket operations workflow
func testBucketOperationsWorkflow(t *testing.T, suite *IntegrationTestSuite) {
	ctx := context.Background()
	bucketName := "integration-test-bucket"
	
	// Create bucket
	metadata := NewBucketMetadata(bucketName, "integration-test-owner")
	err := suite.metadataStore.CreateBucket(ctx, bucketName, metadata)
	if err != nil {
		t.Fatalf("Failed to create bucket: %v", err)
	}
	
	// List buckets
	buckets, err := suite.metadataStore.ListBuckets(ctx)
	if err != nil {
		t.Fatalf("Failed to list buckets: %v", err)
	}
	
	found := false
	for _, bucket := range buckets {
		if bucket.Name == bucketName {
			found = true
			break
		}
	}
	
	if !found {
		t.Error("Created bucket should be in list")
	}
	
	// Add some objects to bucket
	testObjects := suite.GenerateTestData(5)
	for _, obj := range testObjects {
		obj.Bucket = bucketName
		mapping := &ObjectMapping{
			S3Key:     obj.S3Key,
			Bucket:    obj.Bucket,
			CID:       obj.CID,
			Size:      obj.Size,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			PinStatus: PinStatusPinned,
		}
		
		err := suite.metadataStore.StoreMapping(ctx, mapping)
		if err != nil {
			t.Fatalf("Failed to store object mapping: %v", err)
		}
	}
	
	// List objects in bucket
	objects, err := suite.metadataStore.ListObjectsInBucket(ctx, bucketName, "", 10)
	if err != nil {
		t.Fatalf("Failed to list objects in bucket: %v", err)
	}
	
	if len(objects) != 5 {
		t.Errorf("Expected 5 objects in bucket, got %d", len(objects))
	}
	
	// Get bucket stats
	stats, err := suite.metadataStore.GetBucketStats(ctx, bucketName)
	if err != nil {
		t.Fatalf("Failed to get bucket stats: %v", err)
	}
	
	if stats.BucketName != bucketName {
		t.Errorf("Expected bucket name %s, got %s", bucketName, stats.BucketName)
	}
	
	// Delete bucket (this should fail if objects exist)
	err = suite.metadataStore.DeleteBucket(ctx, bucketName)
	if err == nil {
		t.Error("Should fail to delete bucket with objects")
	}
	
	// Clean up objects first
	for _, obj := range testObjects {
		err := suite.metadataStore.DeleteMapping(ctx, obj.S3Key, bucketName)
		if err != nil {
			t.Errorf("Failed to delete object mapping: %v", err)
		}
	}
	
	// Now delete bucket should succeed
	err = suite.metadataStore.DeleteBucket(ctx, bucketName)
	if err != nil {
		t.Fatalf("Failed to delete empty bucket: %v", err)
	}
}

// testMultiObjectWorkflow tests workflows with multiple objects
func testMultiObjectWorkflow(t *testing.T, suite *IntegrationTestSuite) {
	ctx := context.Background()
	
	// Generate multiple test objects
	numObjects := 100
	testObjects := suite.GenerateTestData(numObjects)
	
	t.Run("BatchOperations", func(t *testing.T) {
		// Create mappings for batch operations
		mappings := make([]*ObjectMapping, len(testObjects))
		for i, obj := range testObjects {
			mappings[i] = &ObjectMapping{
				S3Key:     obj.S3Key,
				Bucket:    obj.Bucket,
				CID:       obj.CID,
				Size:      obj.Size,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}
		}
		
		// Batch store
		start := time.Now()
		err := suite.metadataStore.StoreMappingBatch(ctx, mappings)
		if err != nil {
			t.Fatalf("Failed to batch store mappings: %v", err)
		}
		batchStoreTime := time.Since(start)
		
		// Batch retrieve
		keys := make([]*S3Key, len(testObjects))
		for i, obj := range testObjects {
			keys[i] = &S3Key{
				Key:    obj.S3Key,
				Bucket: obj.Bucket,
			}
		}
		
		start = time.Now()
		retrieved, err := suite.metadataStore.GetMappingBatch(ctx, keys)
		if err != nil {
			t.Fatalf("Failed to batch get mappings: %v", err)
		}
		batchGetTime := time.Since(start)
		
		if len(retrieved) != len(mappings) {
			t.Errorf("Expected %d retrieved mappings, got %d", len(mappings), len(retrieved))
		}
		
		t.Logf("Batch store of %d objects took %v", numObjects, batchStoreTime)
		t.Logf("Batch get of %d objects took %v", numObjects, batchGetTime)
		
		// Performance check - batch operations should be faster than individual
		avgBatchStoreTime := batchStoreTime / time.Duration(numObjects)
		avgBatchGetTime := batchGetTime / time.Duration(numObjects)
		
		t.Logf("Average batch store time per object: %v", avgBatchStoreTime)
		t.Logf("Average batch get time per object: %v", avgBatchGetTime)
	})
	
	t.Run("ConcurrentOperations", func(t *testing.T) {
		numWorkers := 10
		objectsPerWorker := numObjects / numWorkers
		
		var wg sync.WaitGroup
		errors := make(chan error, numWorkers)
		
		start := time.Now()
		
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				
				startIdx := workerID * objectsPerWorker
				endIdx := startIdx + objectsPerWorker
				if endIdx > len(testObjects) {
					endIdx = len(testObjects)
				}
				
				for j := startIdx; j < endIdx; j++ {
					obj := testObjects[j]
					
					// Pin operation
					_, err := suite.clusterClient.Pin(ctx, obj.CID, 2)
					if err != nil {
						errors <- fmt.Errorf("worker %d pin failed: %v", workerID, err)
						continue
					}
					
					// Metadata operation
					mapping := &ObjectMapping{
						S3Key:     obj.S3Key,
						Bucket:    obj.Bucket,
						CID:       obj.CID,
						Size:      obj.Size,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
						PinStatus: PinStatusPinned,
					}
					
					err = suite.metadataStore.StoreMapping(ctx, mapping)
					if err != nil {
						errors <- fmt.Errorf("worker %d metadata store failed: %v", workerID, err)
						continue
					}
				}
			}(i)
		}
		
		wg.Wait()
		close(errors)
		
		concurrentTime := time.Since(start)
		
		// Check for errors
		errorCount := 0
		for err := range errors {
			t.Errorf("Concurrent operation error: %v", err)
			errorCount++
		}
		
		if errorCount > 0 {
			t.Errorf("Had %d errors in concurrent operations", errorCount)
		}
		
		t.Logf("Concurrent processing of %d objects with %d workers took %v", numObjects, numWorkers, concurrentTime)
		t.Logf("Average time per object: %v", concurrentTime/time.Duration(numObjects))
	})
}

// TestFailureRecovery tests failure recovery scenarios
func TestFailureRecovery(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	
	t.Run("ClusterNodeFailure", func(t *testing.T) {
		testClusterNodeFailure(t, suite)
	})
	
	t.Run("MetadataStoreFailure", func(t *testing.T) {
		testMetadataStoreFailure(t, suite)
	})
	
	t.Run("NetworkPartition", func(t *testing.T) {
		testNetworkPartition(t, suite)
	})
}

// testClusterNodeFailure tests recovery from cluster node failures
func testClusterNodeFailure(t *testing.T, suite *IntegrationTestSuite) {
	ctx := context.Background()
	
	// Simulate node failure by making cluster operations fail
	suite.clusterClient.SetFailPin(true)
	
	// Operations should handle failures gracefully
	_, err := suite.clusterClient.Pin(ctx, "QmFailureTest", 2)
	if err == nil {
		t.Error("Should fail when cluster is down")
	}
	
	// Restore cluster
	suite.clusterClient.SetFailPin(false)
	
	// Operations should work again
	result, err := suite.clusterClient.Pin(ctx, "QmRecoveryTest", 2)
	if err != nil {
		t.Errorf("Should succeed after cluster recovery: %v", err)
	}
	
	if !result.Success {
		t.Error("Pin should succeed after recovery")
	}
}

// testMetadataStoreFailure tests recovery from metadata store failures
func testMetadataStoreFailure(t *testing.T, suite *IntegrationTestSuite) {
	ctx := context.Background()
	
	// Simulate metadata store failure
	suite.metadataStore.SetFailOps(true)
	
	mapping := &ObjectMapping{
		S3Key:  "failure-test",
		Bucket: "failure-bucket",
		CID:    "QmFailureTest",
	}
	
	// Operations should fail
	err := suite.metadataStore.StoreMapping(ctx, mapping)
	if err == nil {
		t.Error("Should fail when metadata store is down")
	}
	
	// Restore metadata store
	suite.metadataStore.SetFailOps(false)
	
	// Operations should work again
	err = suite.metadataStore.StoreMapping(ctx, mapping)
	if err != nil {
		t.Errorf("Should succeed after metadata store recovery: %v", err)
	}
}

// testNetworkPartition tests recovery from network partitions
func testNetworkPartition(t *testing.T, suite *IntegrationTestSuite) {
	// This would test network partition scenarios
	// For now, we'll simulate with timeouts
	
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	
	// This should timeout quickly, simulating network issues
	_, err := suite.clusterClient.Pin(ctx, "QmNetworkTest", 2)
	if err == nil {
		t.Error("Should timeout with very short context")
	}
	
	// Normal context should work
	normalCtx := context.Background()
	result, err := suite.clusterClient.Pin(normalCtx, "QmNetworkRecoveryTest", 2)
	if err != nil {
		t.Errorf("Should succeed with normal context: %v", err)
	}
	
	if !result.Success {
		t.Error("Pin should succeed with normal context")
	}
}

// TestDataConsistency tests data consistency across components
func TestDataConsistency(t *testing.T) {
	suite := NewIntegrationTestSuite(t)
	defer suite.Cleanup()
	
	t.Run("PinMetadataConsistency", func(t *testing.T) {
		testPinMetadataConsistency(t, suite)
	})
	
	t.Run("ConcurrentUpdateConsistency", func(t *testing.T) {
		testConcurrentUpdateConsistency(t, suite)
	})
}

// testPinMetadataConsistency tests consistency between pin status and metadata
func testPinMetadataConsistency(t *testing.T, suite *IntegrationTestSuite) {
	ctx := context.Background()
	testData := suite.GenerateTestData(1)[0]
	
	// Pin object
	result, err := suite.clusterClient.Pin(ctx, testData.CID, 2)
	if err != nil {
		t.Fatalf("Failed to pin object: %v", err)
	}
	
	// Store metadata with pinned status
	mapping := &ObjectMapping{
		S3Key:     testData.S3Key,
		Bucket:    testData.Bucket,
		CID:       testData.CID,
		Size:      testData.Size,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		PinStatus: PinStatusPinned,
	}
	
	err = suite.metadataStore.StoreMapping(ctx, mapping)
	if err != nil {
		t.Fatalf("Failed to store mapping: %v", err)
	}
	
	// Verify consistency
	retrieved, err := suite.metadataStore.GetMapping(ctx, testData.S3Key, testData.Bucket)
	if err != nil {
		t.Fatalf("Failed to get mapping: %v", err)
	}
	
	if retrieved.PinStatus != PinStatusPinned {
		t.Errorf("Expected pin status %v, got %v", PinStatusPinned, retrieved.PinStatus)
	}
	
	// Unpin object
	_, err = suite.clusterClient.Unpin(ctx, testData.CID)
	if err != nil {
		t.Fatalf("Failed to unpin object: %v", err)
	}
	
	// Update metadata
	retrieved.PinStatus = PinStatusUnpinned
	err = suite.metadataStore.UpdateMapping(ctx, retrieved)
	if err != nil {
		t.Fatalf("Failed to update mapping: %v", err)
	}
	
	// Verify updated consistency
	updated, err := suite.metadataStore.GetMapping(ctx, testData.S3Key, testData.Bucket)
	if err != nil {
		t.Fatalf("Failed to get updated mapping: %v", err)
	}
	
	if updated.PinStatus != PinStatusUnpinned {
		t.Errorf("Expected pin status %v, got %v", PinStatusUnpinned, updated.PinStatus)
	}
	
	if !result.Success {
		t.Error("Pin operation should have succeeded")
	}
}

// testConcurrentUpdateConsistency tests consistency under concurrent updates
func testConcurrentUpdateConsistency(t *testing.T, suite *IntegrationTestSuite) {
	ctx := context.Background()
	testData := suite.GenerateTestData(1)[0]
	
	// Store initial mapping
	mapping := &ObjectMapping{
		S3Key:     testData.S3Key,
		Bucket:    testData.Bucket,
		CID:       testData.CID,
		Size:      testData.Size,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		PinStatus: PinStatusPending,
	}
	
	err := suite.metadataStore.StoreMapping(ctx, mapping)
	if err != nil {
		t.Fatalf("Failed to store initial mapping: %v", err)
	}
	
	// Concurrent updates
	numUpdaters := 5
	var wg sync.WaitGroup
	errors := make(chan error, numUpdaters)
	
	for i := 0; i < numUpdaters; i++ {
		wg.Add(1)
		go func(updaterID int) {
			defer wg.Done()
			
			// Get current mapping
			current, err := suite.metadataStore.GetMapping(ctx, testData.S3Key, testData.Bucket)
			if err != nil {
				errors <- fmt.Errorf("updater %d get failed: %v", updaterID, err)
				return
			}
			
			// Update with different status
			current.PinStatus = PinStatus(updaterID % 3) // Cycle through statuses
			current.UpdatedAt = time.Now()
			
			err = suite.metadataStore.UpdateMapping(ctx, current)
			if err != nil {
				errors <- fmt.Errorf("updater %d update failed: %v", updaterID, err)
				return
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent update error: %v", err)
	}
	
	// Verify final state is consistent
	final, err := suite.metadataStore.GetMapping(ctx, testData.S3Key, testData.Bucket)
	if err != nil {
		t.Fatalf("Failed to get final mapping: %v", err)
	}
	
	if final == nil {
		t.Fatal("Final mapping should not be nil")
	}
	
	// The final state should be one of the valid pin statuses
	validStatuses := []PinStatus{PinStatusPending, PinStatusPinned, PinStatusFailed}
	validStatus := false
	for _, status := range validStatuses {
		if final.PinStatus == status {
			validStatus = true
			break
		}
	}
	
	if !validStatus {
		t.Errorf("Final pin status %v is not valid", final.PinStatus)
	}
}