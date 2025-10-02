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

func TestIPFSBackend_CacheIntegration(t *testing.T) {
	config := &IPFSConfig{
		ClusterEndpoints:    []string{"http://localhost:9094"},
		MetadataDBType:      "memory",
		MetadataDBEndpoints: []string{},
		CacheEndpoints:      []string{"localhost:6379"},
		CacheEnabled:        true,
		ConnectTimeout:      5 * time.Second,
		RequestTimeout:      10 * time.Second,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
		MaxConcurrentPins:   10,
		PinTimeout:          30 * time.Second,
		ChunkSize:           1024 * 1024,
		ReplicationMin:      1,
		ReplicationMax:      3,
		CompressionEnabled:  false,
		MetricsEnabled:      true,
		LogLevel:            "info",
	}
	
	logger := log.New(os.Stdout, "[INTEGRATION_TEST] ", log.LstdFlags)
	opts := IPFSOptions{
		Logger:  logger,
		Context: context.Background(),
	}
	
	backend, err := New(config, opts)
	if err != nil {
		t.Fatalf("Failed to create IPFS backend: %v", err)
	}
	defer backend.Shutdown()
	
	ctx := context.Background()
	
	t.Run("CacheLayerInitialization", func(t *testing.T) {
		cacheLayer := backend.GetCacheLayer()
		if cacheLayer == nil {
			t.Fatal("Cache layer should be initialized")
		}
		
		if !backend.IsCacheHealthy() {
			t.Error("Cache layer should be healthy")
		}
		
		stats := backend.GetCacheStats()
		if stats == nil {
			t.Error("Cache stats should not be nil")
		}
		
		if !stats.Healthy {
			t.Error("Cache should be healthy")
		}
	})
	
	t.Run("CachedObjectMapping", func(t *testing.T) {
		s3Key := "test-cache-object.txt"
		bucket := "test-cache-bucket"
		
		mapping := &ObjectMapping{
			S3Key:       s3Key,
			Bucket:      bucket,
			CID:         "QmTestCacheCID123",
			Size:        2048,
			ContentType: "text/plain",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			PinStatus:   PinStatusPinned,
		}
		
		// Store mapping using cached method
		err := backend.StoreCachedObjectMapping(ctx, mapping)
		if err != nil {
			t.Fatalf("Failed to store cached object mapping: %v", err)
		}
		
		// Retrieve mapping using cached method
		retrieved, err := backend.GetCachedObjectMapping(ctx, s3Key, bucket)
		if err != nil {
			t.Fatalf("Failed to get cached object mapping: %v", err)
		}
		
		if retrieved.S3Key != mapping.S3Key {
			t.Errorf("Expected S3Key %s, got %s", mapping.S3Key, retrieved.S3Key)
		}
		if retrieved.CID != mapping.CID {
			t.Errorf("Expected CID %s, got %s", mapping.CID, retrieved.CID)
		}
		
		// Delete mapping using cached method
		err = backend.DeleteCachedObjectMapping(ctx, s3Key, bucket)
		if err != nil {
			t.Fatalf("Failed to delete cached object mapping: %v", err)
		}
	})
	
	t.Run("CacheWarmingAndClearing", func(t *testing.T) {
		// Test cache warming
		keys := []string{"warm-key-1", "warm-key-2", "warm-key-3"}
		err := backend.WarmCache(ctx, keys)
		if err != nil {
			t.Fatalf("Failed to warm cache: %v", err)
		}
		
		// Test cache clearing
		err = backend.ClearCache(ctx)
		if err != nil {
			t.Fatalf("Failed to clear cache: %v", err)
		}
	})
	
	t.Run("CacheStats", func(t *testing.T) {
		// Get overall backend stats (should include cache stats)
		stats := backend.GetStats()
		if stats == nil {
			t.Fatal("Backend stats should not be nil")
		}
		
		// Check that cache-related stats are present
		if _, exists := stats["cache_healthy"]; !exists {
			t.Error("Cache health stat should be present")
		}
		
		if _, exists := stats["cache_l1_hits"]; !exists {
			t.Error("L1 cache hits stat should be present")
		}
		
		if _, exists := stats["cache_l2_hits"]; !exists {
			t.Error("L2 cache hits stat should be present")
		}
	})
	
	t.Run("HealthCheck", func(t *testing.T) {
		// Note: Backend health depends on cluster availability
		// In this test environment, cluster nodes may not be available
		// So we just check that the health check doesn't panic
		healthy := backend.IsHealthy()
		t.Logf("Backend healthy: %v", healthy)
		
		// Cache should still be healthy even if cluster is not
		if !backend.IsCacheHealthy() {
			t.Error("Cache should be healthy")
		}
	})
}