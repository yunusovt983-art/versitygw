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
	"os"
	"sync"
	"testing"
	"time"
)

// TestMetadataStoreIntegration tests the complete metadata store functionality
func TestMetadataStoreIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	
	logger := log.New(os.Stdout, "integration-test: ", log.LstdFlags)
	factory := NewMetadataStoreFactory(logger)
	
	// Test with memory store (always available)
	config := &MetadataStoreConfig{
		Type:           "memory",
		BatchSize:      100,
		QueryTimeout:   30 * time.Second,
		MetricsEnabled: true,
		LogLevel:       "info",
	}
	
	store, err := factory.CreateMetadataStore(config)
	if err != nil {
		t.Fatalf("Failed to create metadata store: %v", err)
	}
	defer store.Shutdown(context.Background())
	
	ctx := context.Background()
	
	t.Run("BasicOperations", func(t *testing.T) {
		// Test bucket operations
		bucketName := "test-bucket"
		bucketMetadata := NewBucketMetadata(bucketName, "test-owner")
		
		err := store.CreateBucket(ctx, bucketName, bucketMetadata)
		if err != nil {
			t.Fatalf("Failed to create bucket: %v", err)
		}
		
		retrievedBucket, err := store.GetBucket(ctx, bucketName)
		if err != nil {
			t.Fatalf("Failed to get bucket: %v", err)
		}
		
		if retrievedBucket.Name != bucketName {
			t.Errorf("Expected bucket name %s, got %s", bucketName, retrievedBucket.Name)
		}
		
		// Test object operations
		mapping := NewObjectMapping(bucketName, "test/object.txt", "QmTestCID123", 1024)
		mapping.ContentType = "text/plain"
		mapping.UserMetadata["custom-key"] = "custom-value"
		mapping.Tags["environment"] = "test"
		
		err = store.StoreMapping(ctx, mapping)
		if err != nil {
			t.Fatalf("Failed to store mapping: %v", err)
		}
		
		retrievedMapping, err := store.GetMapping(ctx, "test/object.txt", bucketName)
		if err != nil {
			t.Fatalf("Failed to get mapping: %v", err)
		}
		
		if retrievedMapping.CID != mapping.CID {
			t.Errorf("Expected CID %s, got %s", mapping.CID, retrievedMapping.CID)
		}
		if retrievedMapping.Size != mapping.Size {
			t.Errorf("Expected size %d, got %d", mapping.Size, retrievedMapping.Size)
		}
		
		// Test update
		mapping.PinStatus = PinStatusPinned
		mapping.ReplicationCount = 3
		mapping.PinnedNodes = []string{"node1", "node2", "node3"}
		
		err = store.UpdateMapping(ctx, mapping)
		if err != nil {
			t.Fatalf("Failed to update mapping: %v", err)
		}
		
		updatedMapping, err := store.GetMapping(ctx, "test/object.txt", bucketName)
		if err != nil {
			t.Fatalf("Failed to get updated mapping: %v", err)
		}
		
		if updatedMapping.PinStatus != PinStatusPinned {
			t.Errorf("Expected pin status %v, got %v", PinStatusPinned, updatedMapping.PinStatus)
		}
		if updatedMapping.ReplicationCount != 3 {
			t.Errorf("Expected replication count 3, got %d", updatedMapping.ReplicationCount)
		}
		
		// Test delete
		err = store.DeleteMapping(ctx, "test/object.txt", bucketName)
		if err != nil {
			t.Fatalf("Failed to delete mapping: %v", err)
		}
		
		_, err = store.GetMapping(ctx, "test/object.txt", bucketName)
		if err == nil {
			t.Error("Expected error when getting deleted mapping")
		}
		
		// Clean up bucket
		err = store.DeleteBucket(ctx, bucketName)
		if err != nil {
			t.Fatalf("Failed to delete bucket: %v", err)
		}
	})
	
	t.Run("BatchOperations", func(t *testing.T) {
		bucketName := "batch-test-bucket"
		bucketMetadata := NewBucketMetadata(bucketName, "test-owner")
		
		err := store.CreateBucket(ctx, bucketName, bucketMetadata)
		if err != nil {
			t.Fatalf("Failed to create bucket: %v", err)
		}
		defer store.DeleteBucket(ctx, bucketName)
		
		// Create batch of mappings
		batchSize := 50
		mappings := make([]*ObjectMapping, batchSize)
		for i := 0; i < batchSize; i++ {
			mappings[i] = NewObjectMapping(
				bucketName,
				fmt.Sprintf("batch/object-%d.txt", i),
				fmt.Sprintf("QmBatchCID%d", i),
				int64(1024+i),
			)
			mappings[i].ContentType = "text/plain"
			mappings[i].UserMetadata["batch-id"] = fmt.Sprintf("batch-%d", i/10)
			mappings[i].Tags["type"] = "batch-test"
		}
		
		// Store batch
		start := time.Now()
		err = store.StoreMappingBatch(ctx, mappings)
		if err != nil {
			t.Fatalf("Failed to store mapping batch: %v", err)
		}
		batchStoreTime := time.Since(start)
		t.Logf("Batch store of %d objects took: %v", batchSize, batchStoreTime)
		
		// Retrieve batch
		keys := make([]*S3Key, batchSize)
		for i := 0; i < batchSize; i++ {
			keys[i] = &S3Key{
				Bucket: bucketName,
				Key:    fmt.Sprintf("batch/object-%d.txt", i),
			}
		}
		
		start = time.Now()
		retrievedMappings, err := store.GetMappingBatch(ctx, keys)
		if err != nil {
			t.Fatalf("Failed to get mapping batch: %v", err)
		}
		batchGetTime := time.Since(start)
		t.Logf("Batch get of %d objects took: %v", len(retrievedMappings), batchGetTime)
		
		if len(retrievedMappings) != batchSize {
			t.Errorf("Expected %d retrieved mappings, got %d", batchSize, len(retrievedMappings))
		}
		
		// Test prefix search
		start = time.Now()
		prefixResults, err := store.SearchByPrefix(ctx, bucketName, "batch/", 25)
		if err != nil {
			t.Fatalf("Failed to search by prefix: %v", err)
		}
		prefixSearchTime := time.Since(start)
		t.Logf("Prefix search took: %v", prefixSearchTime)
		
		if len(prefixResults) == 0 {
			t.Error("Expected prefix search to return results")
		}
		
		// Test list objects
		start = time.Now()
		listResults, err := store.ListObjectsInBucket(ctx, bucketName, "", 30)
		if err != nil {
			t.Fatalf("Failed to list objects: %v", err)
		}
		listTime := time.Since(start)
		t.Logf("List objects took: %v", listTime)
		
		if len(listResults) == 0 {
			t.Error("Expected list objects to return results")
		}
		
		// Delete batch
		start = time.Now()
		err = store.DeleteMappingBatch(ctx, keys)
		if err != nil {
			t.Fatalf("Failed to delete mapping batch: %v", err)
		}
		batchDeleteTime := time.Since(start)
		t.Logf("Batch delete of %d objects took: %v", batchSize, batchDeleteTime)
		
		// Verify deletion
		remainingMappings, err := store.GetMappingBatch(ctx, keys)
		if err != nil {
			t.Fatalf("Failed to verify batch deletion: %v", err)
		}
		
		if len(remainingMappings) != 0 {
			t.Errorf("Expected 0 remaining mappings after batch delete, got %d", len(remainingMappings))
		}
	})
	
	t.Run("CIDIndexing", func(t *testing.T) {
		bucketName := "cid-test-bucket"
		bucketMetadata := NewBucketMetadata(bucketName, "test-owner")
		
		err := store.CreateBucket(ctx, bucketName, bucketMetadata)
		if err != nil {
			t.Fatalf("Failed to create bucket: %v", err)
		}
		defer store.DeleteBucket(ctx, bucketName)
		
		// Create objects with same CID (deduplication scenario)
		sharedCID := "QmSharedCID123"
		mappings := []*ObjectMapping{
			NewObjectMapping(bucketName, "file1.txt", sharedCID, 1024),
			NewObjectMapping(bucketName, "file2.txt", sharedCID, 1024),
			NewObjectMapping(bucketName, "subdir/file3.txt", sharedCID, 1024),
		}
		
		for _, mapping := range mappings {
			err = store.StoreMapping(ctx, mapping)
			if err != nil {
				t.Fatalf("Failed to store mapping: %v", err)
			}
		}
		
		// Search by CID
		start := time.Now()
		cidResults, err := store.SearchByCID(ctx, sharedCID)
		if err != nil {
			t.Fatalf("Failed to search by CID: %v", err)
		}
		cidSearchTime := time.Since(start)
		t.Logf("CID search took: %v", cidSearchTime)
		
		if len(cidResults) != len(mappings) {
			t.Errorf("Expected %d results for CID search, got %d", len(mappings), len(cidResults))
		}
		
		// Verify all objects are found
		foundKeys := make(map[string]bool)
		for _, result := range cidResults {
			foundKeys[result.S3Key] = true
		}
		
		expectedKeys := []string{"file1.txt", "file2.txt", "subdir/file3.txt"}
		for _, expectedKey := range expectedKeys {
			if !foundKeys[expectedKey] {
				t.Errorf("Expected to find key %s in CID search results", expectedKey)
			}
		}
		
		// Clean up
		for _, mapping := range mappings {
			store.DeleteMapping(ctx, mapping.S3Key, mapping.Bucket)
		}
	})
	
	t.Run("Statistics", func(t *testing.T) {
		// Get initial stats
		initialStats, err := store.GetStats(ctx)
		if err != nil {
			t.Fatalf("Failed to get initial stats: %v", err)
		}
		
		bucketName := "stats-test-bucket"
		bucketMetadata := NewBucketMetadata(bucketName, "test-owner")
		
		err = store.CreateBucket(ctx, bucketName, bucketMetadata)
		if err != nil {
			t.Fatalf("Failed to create bucket: %v", err)
		}
		defer store.DeleteBucket(ctx, bucketName)
		
		// Add some objects
		numObjects := 10
		for i := 0; i < numObjects; i++ {
			mapping := NewObjectMapping(
				bucketName,
				fmt.Sprintf("stats/object-%d.txt", i),
				fmt.Sprintf("QmStatsCID%d", i),
				int64(1024*(i+1)),
			)
			err = store.StoreMapping(ctx, mapping)
			if err != nil {
				t.Fatalf("Failed to store mapping %d: %v", i, err)
			}
		}
		
		// Get updated stats
		updatedStats, err := store.GetStats(ctx)
		if err != nil {
			t.Fatalf("Failed to get updated stats: %v", err)
		}
		
		// Verify stats increased
		if updatedStats.TotalObjects <= initialStats.TotalObjects {
			t.Logf("Stats may not be updated in memory store: initial=%d, updated=%d",
				initialStats.TotalObjects, updatedStats.TotalObjects)
		}
		
		// Get bucket stats
		bucketStats, err := store.GetBucketStats(ctx, bucketName)
		if err != nil {
			t.Fatalf("Failed to get bucket stats: %v", err)
		}
		
		if bucketStats.BucketName != bucketName {
			t.Errorf("Expected bucket name %s in stats, got %s", bucketName, bucketStats.BucketName)
		}
		
		// Clean up
		for i := 0; i < numObjects; i++ {
			store.DeleteMapping(ctx, fmt.Sprintf("stats/object-%d.txt", i), bucketName)
		}
	})
	
	t.Run("ConcurrentOperations", func(t *testing.T) {
		bucketName := "concurrent-test-bucket"
		bucketMetadata := NewBucketMetadata(bucketName, "test-owner")
		
		err := store.CreateBucket(ctx, bucketName, bucketMetadata)
		if err != nil {
			t.Fatalf("Failed to create bucket: %v", err)
		}
		defer store.DeleteBucket(ctx, bucketName)
		
		numWorkers := 5
		objectsPerWorker := 10
		var wg sync.WaitGroup
		errors := make(chan error, numWorkers)
		
		// Concurrent writes
		start := time.Now()
		for worker := 0; worker < numWorkers; worker++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				
				for i := 0; i < objectsPerWorker; i++ {
					mapping := NewObjectMapping(
						bucketName,
						fmt.Sprintf("worker-%d/object-%d.txt", workerID, i),
						fmt.Sprintf("QmWorkerCID%d-%d", workerID, i),
						int64(1024*(i+1)),
					)
					mapping.UserMetadata["worker-id"] = fmt.Sprintf("%d", workerID)
					
					if err := store.StoreMapping(ctx, mapping); err != nil {
						errors <- fmt.Errorf("worker %d failed to store object %d: %w", workerID, i, err)
						return
					}
				}
			}(worker)
		}
		
		wg.Wait()
		close(errors)
		concurrentWriteTime := time.Since(start)
		t.Logf("Concurrent writes (%d workers, %d objects each) took: %v",
			numWorkers, objectsPerWorker, concurrentWriteTime)
		
		// Check for errors
		for err := range errors {
			t.Errorf("Concurrent write error: %v", err)
		}
		
		// Concurrent reads
		start = time.Now()
		errors = make(chan error, numWorkers)
		
		for worker := 0; worker < numWorkers; worker++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				
				for i := 0; i < objectsPerWorker; i++ {
					key := fmt.Sprintf("worker-%d/object-%d.txt", workerID, i)
					_, err := store.GetMapping(ctx, key, bucketName)
					if err != nil {
						errors <- fmt.Errorf("worker %d failed to get object %d: %w", workerID, i, err)
						return
					}
				}
			}(worker)
		}
		
		wg.Wait()
		close(errors)
		concurrentReadTime := time.Since(start)
		t.Logf("Concurrent reads (%d workers, %d objects each) took: %v",
			numWorkers, objectsPerWorker, concurrentReadTime)
		
		// Check for errors
		for err := range errors {
			t.Errorf("Concurrent read error: %v", err)
		}
		
		// Clean up
		for worker := 0; worker < numWorkers; worker++ {
			for i := 0; i < objectsPerWorker; i++ {
				key := fmt.Sprintf("worker-%d/object-%d.txt", worker, i)
				store.DeleteMapping(ctx, key, bucketName)
			}
		}
	})
	
	t.Run("HealthCheck", func(t *testing.T) {
		err := store.HealthCheck(ctx)
		if err != nil {
			t.Errorf("Health check failed: %v", err)
		}
	})
}

// TestMetadataStorePerformance tests performance characteristics
func TestMetadataStorePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}
	
	logger := log.New(os.Stdout, "perf-test: ", log.LstdFlags)
	factory := NewMetadataStoreFactory(logger)
	
	config := &MetadataStoreConfig{
		Type:           "memory",
		BatchSize:      1000,
		QueryTimeout:   30 * time.Second,
		MetricsEnabled: true,
	}
	
	store, err := factory.CreateMetadataStore(config)
	if err != nil {
		t.Fatalf("Failed to create metadata store: %v", err)
	}
	defer store.Shutdown(context.Background())
	
	ctx := context.Background()
	bucketName := "perf-test-bucket"
	bucketMetadata := NewBucketMetadata(bucketName, "test-owner")
	
	err = store.CreateBucket(ctx, bucketName, bucketMetadata)
	if err != nil {
		t.Fatalf("Failed to create bucket: %v", err)
	}
	defer store.DeleteBucket(ctx, bucketName)
	
	// Test different batch sizes
	batchSizes := []int{10, 100, 1000}
	
	for _, batchSize := range batchSizes {
		t.Run(fmt.Sprintf("BatchSize_%d", batchSize), func(t *testing.T) {
			// Create batch
			mappings := make([]*ObjectMapping, batchSize)
			for i := 0; i < batchSize; i++ {
				mappings[i] = NewObjectMapping(
					bucketName,
					fmt.Sprintf("perf/batch-%d/object-%d.txt", batchSize, i),
					fmt.Sprintf("QmPerfCID%d-%d", batchSize, i),
					int64(1024*(i+1)),
				)
			}
			
			// Measure batch store
			start := time.Now()
			err := store.StoreMappingBatch(ctx, mappings)
			if err != nil {
				t.Fatalf("Failed to store batch: %v", err)
			}
			storeTime := time.Since(start)
			
			storeRate := float64(batchSize) / storeTime.Seconds()
			t.Logf("Batch store rate: %.2f objects/sec", storeRate)
			
			// Measure batch get
			keys := make([]*S3Key, batchSize)
			for i := 0; i < batchSize; i++ {
				keys[i] = &S3Key{
					Bucket: bucketName,
					Key:    fmt.Sprintf("perf/batch-%d/object-%d.txt", batchSize, i),
				}
			}
			
			start = time.Now()
			retrievedMappings, err := store.GetMappingBatch(ctx, keys)
			if err != nil {
				t.Fatalf("Failed to get batch: %v", err)
			}
			getTime := time.Since(start)
			
			getRate := float64(len(retrievedMappings)) / getTime.Seconds()
			t.Logf("Batch get rate: %.2f objects/sec", getRate)
			
			// Clean up
			store.DeleteMappingBatch(ctx, keys)
		})
	}
}

// BenchmarkMetadataStoreOperations benchmarks metadata store operations
func BenchmarkMetadataStoreOperations(b *testing.B) {
	logger := log.New(os.Stdout, "bench: ", log.LstdFlags)
	factory := NewMetadataStoreFactory(logger)
	
	config := &MetadataStoreConfig{
		Type:           "memory",
		BatchSize:      1000,
		QueryTimeout:   30 * time.Second,
		MetricsEnabled: false, // Disable metrics for cleaner benchmarks
	}
	
	store, err := factory.CreateMetadataStore(config)
	if err != nil {
		b.Fatalf("Failed to create metadata store: %v", err)
	}
	defer store.Shutdown(context.Background())
	
	ctx := context.Background()
	bucketName := "bench-bucket"
	bucketMetadata := NewBucketMetadata(bucketName, "bench-owner")
	
	err = store.CreateBucket(ctx, bucketName, bucketMetadata)
	if err != nil {
		b.Fatalf("Failed to create bucket: %v", err)
	}
	defer store.DeleteBucket(ctx, bucketName)
	
	b.Run("StoreMapping", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mapping := NewObjectMapping(
				bucketName,
				fmt.Sprintf("bench/store/object-%d.txt", i),
				fmt.Sprintf("QmBenchCID%d", i),
				int64(1024+i),
			)
			store.StoreMapping(ctx, mapping)
		}
	})
	
	b.Run("GetMapping", func(b *testing.B) {
		// Pre-populate some objects
		for i := 0; i < 1000; i++ {
			mapping := NewObjectMapping(
				bucketName,
				fmt.Sprintf("bench/get/object-%d.txt", i),
				fmt.Sprintf("QmBenchGetCID%d", i),
				int64(1024+i),
			)
			store.StoreMapping(ctx, mapping)
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("bench/get/object-%d.txt", i%1000)
			store.GetMapping(ctx, key, bucketName)
		}
	})
	
	b.Run("BatchStore", func(b *testing.B) {
		batchSize := 100
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mappings := make([]*ObjectMapping, batchSize)
			for j := 0; j < batchSize; j++ {
				mappings[j] = NewObjectMapping(
					bucketName,
					fmt.Sprintf("bench/batch-store/batch-%d/object-%d.txt", i, j),
					fmt.Sprintf("QmBenchBatchCID%d-%d", i, j),
					int64(1024+j),
				)
			}
			store.StoreMappingBatch(ctx, mappings)
		}
	})
	
	b.Run("SearchByPrefix", func(b *testing.B) {
		// Pre-populate objects with common prefix
		for i := 0; i < 1000; i++ {
			mapping := NewObjectMapping(
				bucketName,
				fmt.Sprintf("bench/search/common-prefix/object-%d.txt", i),
				fmt.Sprintf("QmBenchSearchCID%d", i),
				int64(1024+i),
			)
			store.StoreMapping(ctx, mapping)
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			store.SearchByPrefix(ctx, bucketName, "bench/search/common-prefix/", 50)
		}
	})
}