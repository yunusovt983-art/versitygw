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

func TestMultiLevelCache_BasicOperations(t *testing.T) {
	config := &CacheConfig{
		L1MaxSize:        1024 * 1024, // 1MB
		L1MaxEntries:     1000,
		L1DefaultTTL:     5 * time.Minute,
		L1CleanupInterval: 1 * time.Minute,
		L2Endpoints:      []string{"localhost:6379"},
		L2DefaultTTL:     1 * time.Hour,
		MappingTTL:       30 * time.Minute,
		MetadataTTL:      15 * time.Minute,
		BucketTTL:        1 * time.Hour,
		PinStatusTTL:     5 * time.Minute,
		WarmingEnabled:   false,
		MetricsEnabled:   true,
		HealthCheckEnabled: true,
	}
	
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	cache, err := NewCacheLayer(config, logger)
	if err != nil {
		t.Fatalf("Failed to create cache layer: %v", err)
	}
	defer cache.Shutdown(context.Background())
	
	ctx := context.Background()
	
	// Test basic set/get operations
	t.Run("SetAndGet", func(t *testing.T) {
		key := "test-key"
		value := "test-value"
		ttl := 1 * time.Minute
		
		err := cache.Set(ctx, key, value, ttl)
		if err != nil {
			t.Fatalf("Failed to set value: %v", err)
		}
		
		retrieved, err := cache.Get(ctx, key)
		if err != nil {
			t.Fatalf("Failed to get value: %v", err)
		}
		
		if retrieved != value {
			t.Errorf("Expected %v, got %v", value, retrieved)
		}
	})
	
	// Test delete operation
	t.Run("Delete", func(t *testing.T) {
		key := "delete-test-key"
		value := "delete-test-value"
		
		err := cache.Set(ctx, key, value, 1*time.Minute)
		if err != nil {
			t.Fatalf("Failed to set value: %v", err)
		}
		
		err = cache.Delete(ctx, key)
		if err != nil {
			t.Fatalf("Failed to delete value: %v", err)
		}
		
		_, err = cache.Get(ctx, key)
		if err == nil {
			t.Error("Expected error when getting deleted key")
		}
	})
	
	// Test clear operation
	t.Run("Clear", func(t *testing.T) {
		// Set multiple values
		for i := 0; i < 10; i++ {
			key := fmt.Sprintf("clear-test-key-%d", i)
			value := fmt.Sprintf("clear-test-value-%d", i)
			err := cache.Set(ctx, key, value, 1*time.Minute)
			if err != nil {
				t.Fatalf("Failed to set value %d: %v", i, err)
			}
		}
		
		err := cache.Clear(ctx)
		if err != nil {
			t.Fatalf("Failed to clear cache: %v", err)
		}
		
		// Verify all keys are gone
		for i := 0; i < 10; i++ {
			key := fmt.Sprintf("clear-test-key-%d", i)
			_, err := cache.Get(ctx, key)
			if err == nil {
				t.Errorf("Expected error when getting cleared key %s", key)
			}
		}
	})
}

func TestMultiLevelCache_ObjectMappings(t *testing.T) {
	config := &CacheConfig{
		L1MaxSize:        1024 * 1024,
		L1MaxEntries:     1000,
		L1DefaultTTL:     5 * time.Minute,
		L1CleanupInterval: 1 * time.Minute,
		L2Endpoints:      []string{"localhost:6379"},
		L2DefaultTTL:     1 * time.Hour,
		MappingTTL:       30 * time.Minute,
		MetadataTTL:      15 * time.Minute,
		WarmingEnabled:   false,
		MetricsEnabled:   true,
	}
	
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	cache, err := NewCacheLayer(config, logger)
	if err != nil {
		t.Fatalf("Failed to create cache layer: %v", err)
	}
	defer cache.Shutdown(context.Background())
	
	ctx := context.Background()
	
	// Test object mapping operations
	t.Run("ObjectMapping", func(t *testing.T) {
		s3Key := "test-object.txt"
		bucket := "test-bucket"
		mapping := &ObjectMapping{
			S3Key:       s3Key,
			Bucket:      bucket,
			CID:         "QmTestCID123",
			Size:        1024,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			ContentType: "text/plain",
			UserMetadata: map[string]string{
				"author": "test-user",
			},
			PinStatus: PinStatusPinned,
		}
		
		// Set mapping
		err := cache.SetMapping(ctx, s3Key, bucket, mapping, 0)
		if err != nil {
			t.Fatalf("Failed to set mapping: %v", err)
		}
		
		// Get mapping
		retrieved, err := cache.GetMapping(ctx, s3Key, bucket)
		if err != nil {
			t.Fatalf("Failed to get mapping: %v", err)
		}
		
		if retrieved.S3Key != mapping.S3Key {
			t.Errorf("Expected S3Key %s, got %s", mapping.S3Key, retrieved.S3Key)
		}
		if retrieved.CID != mapping.CID {
			t.Errorf("Expected CID %s, got %s", mapping.CID, retrieved.CID)
		}
		
		// Delete mapping
		err = cache.DeleteMapping(ctx, s3Key, bucket)
		if err != nil {
			t.Fatalf("Failed to delete mapping: %v", err)
		}
		
		_, err = cache.GetMapping(ctx, s3Key, bucket)
		if err == nil {
			t.Error("Expected error when getting deleted mapping")
		}
	})
}

func TestMultiLevelCache_TTL(t *testing.T) {
	config := &CacheConfig{
		L1MaxSize:        1024 * 1024,
		L1MaxEntries:     1000,
		L1DefaultTTL:     100 * time.Millisecond, // Short TTL for testing
		L1CleanupInterval: 50 * time.Millisecond,
		L2Endpoints:      []string{"localhost:6379"},
		L2DefaultTTL:     200 * time.Millisecond,
		WarmingEnabled:   false,
		MetricsEnabled:   false,
	}
	
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	cache, err := NewCacheLayer(config, logger)
	if err != nil {
		t.Fatalf("Failed to create cache layer: %v", err)
	}
	defer cache.Shutdown(context.Background())
	
	ctx := context.Background()
	
	t.Run("TTLExpiration", func(t *testing.T) {
		key := "ttl-test-key"
		value := "ttl-test-value"
		ttl := 100 * time.Millisecond
		
		err := cache.Set(ctx, key, value, ttl)
		if err != nil {
			t.Fatalf("Failed to set value: %v", err)
		}
		
		// Should be available immediately
		retrieved, err := cache.Get(ctx, key)
		if err != nil {
			t.Fatalf("Failed to get value: %v", err)
		}
		if retrieved != value {
			t.Errorf("Expected %v, got %v", value, retrieved)
		}
		
		// Wait for expiration
		time.Sleep(150 * time.Millisecond)
		
		// Should be expired now
		_, err = cache.Get(ctx, key)
		if err == nil {
			t.Error("Expected error when getting expired key")
		}
	})
}

func TestMultiLevelCache_ConcurrentAccess(t *testing.T) {
	config := &CacheConfig{
		L1MaxSize:        1024 * 1024,
		L1MaxEntries:     1000,
		L1DefaultTTL:     5 * time.Minute,
		L1CleanupInterval: 1 * time.Minute,
		L2Endpoints:      []string{"localhost:6379"},
		L2DefaultTTL:     1 * time.Hour,
		WarmingEnabled:   false,
		MetricsEnabled:   true,
	}
	
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	cache, err := NewCacheLayer(config, logger)
	if err != nil {
		t.Fatalf("Failed to create cache layer: %v", err)
	}
	defer cache.Shutdown(context.Background())
	
	ctx := context.Background()
	
	t.Run("ConcurrentSetGet", func(t *testing.T) {
		const numGoroutines = 100
		const numOperations = 100
		
		var wg sync.WaitGroup
		
		// Concurrent writers
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("concurrent-key-%d-%d", id, j)
					value := fmt.Sprintf("concurrent-value-%d-%d", id, j)
					err := cache.Set(ctx, key, value, 1*time.Minute)
					if err != nil {
						t.Errorf("Failed to set value: %v", err)
					}
				}
			}(i)
		}
		
		// Concurrent readers
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("concurrent-key-%d-%d", id, j)
					expectedValue := fmt.Sprintf("concurrent-value-%d-%d", id, j)
					
					// Try to get the value (might not exist yet due to concurrency)
					value, err := cache.Get(ctx, key)
					if err == nil {
						if value != expectedValue {
							t.Errorf("Expected %v, got %v", expectedValue, value)
						}
					}
				}
			}(i)
		}
		
		wg.Wait()
	})
}

func TestMultiLevelCache_Stats(t *testing.T) {
	config := &CacheConfig{
		L1MaxSize:        1024 * 1024,
		L1MaxEntries:     1000,
		L1DefaultTTL:     5 * time.Minute,
		L1CleanupInterval: 1 * time.Minute,
		L2Endpoints:      []string{"localhost:6379"},
		L2DefaultTTL:     1 * time.Hour,
		WarmingEnabled:   false,
		MetricsEnabled:   true,
		MetricsInterval:  100 * time.Millisecond,
	}
	
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	cache, err := NewCacheLayer(config, logger)
	if err != nil {
		t.Fatalf("Failed to create cache layer: %v", err)
	}
	defer cache.Shutdown(context.Background())
	
	ctx := context.Background()
	
	t.Run("StatsCollection", func(t *testing.T) {
		// Perform some operations
		for i := 0; i < 10; i++ {
			key := fmt.Sprintf("stats-key-%d", i)
			value := fmt.Sprintf("stats-value-%d", i)
			err := cache.Set(ctx, key, value, 1*time.Minute)
			if err != nil {
				t.Fatalf("Failed to set value: %v", err)
			}
		}
		
		// Get some values (hits)
		for i := 0; i < 5; i++ {
			key := fmt.Sprintf("stats-key-%d", i)
			_, err := cache.Get(ctx, key)
			if err != nil {
				t.Fatalf("Failed to get value: %v", err)
			}
		}
		
		// Try to get non-existent values (misses)
		for i := 10; i < 15; i++ {
			key := fmt.Sprintf("stats-key-%d", i)
			_, err := cache.Get(ctx, key)
			if err == nil {
				t.Error("Expected error when getting non-existent key")
			}
		}
		
		// Wait for metrics to be collected
		time.Sleep(200 * time.Millisecond)
		
		stats := cache.GetStats()
		if stats == nil {
			t.Fatal("Expected stats, got nil")
		}
		
		if stats.TotalHits == 0 {
			t.Error("Expected some hits in stats")
		}
		
		if stats.TotalMisses == 0 {
			t.Error("Expected some misses in stats")
		}
		
		if stats.TotalOps == 0 {
			t.Error("Expected some operations in stats")
		}
		
		if !stats.Healthy {
			t.Error("Expected cache to be healthy")
		}
	})
}

func TestCacheWarmer_BasicOperations(t *testing.T) {
	config := &CacheConfig{
		L1MaxSize:        1024 * 1024,
		L1MaxEntries:     1000,
		L1DefaultTTL:     5 * time.Minute,
		L1CleanupInterval: 1 * time.Minute,
		L2Endpoints:      []string{"localhost:6379"},
		L2DefaultTTL:     1 * time.Hour,
		WarmingEnabled:   true,
		WarmingBatchSize: 10,
		WarmingInterval:  1 * time.Second,
		WarmingThreshold: 0.1,
		MetricsEnabled:   false,
	}
	
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	cache, err := NewCacheLayer(config, logger)
	if err != nil {
		t.Fatalf("Failed to create cache layer: %v", err)
	}
	defer cache.Shutdown(context.Background())
	
	ctx := context.Background()
	
	t.Run("ManualWarming", func(t *testing.T) {
		keys := []string{"warm-key-1", "warm-key-2", "warm-key-3"}
		
		err := cache.Warm(ctx, keys)
		if err != nil {
			t.Fatalf("Failed to warm keys: %v", err)
		}
		
		// Note: In this test implementation, warming doesn't actually load data
		// In a real implementation, you would verify that the keys are now in cache
	})
}

func BenchmarkMultiLevelCache_Set(b *testing.B) {
	config := &CacheConfig{
		L1MaxSize:        10 * 1024 * 1024, // 10MB
		L1MaxEntries:     10000,
		L1DefaultTTL:     5 * time.Minute,
		L1CleanupInterval: 1 * time.Minute,
		L2Endpoints:      []string{"localhost:6379"},
		L2DefaultTTL:     1 * time.Hour,
		WarmingEnabled:   false,
		MetricsEnabled:   false,
		AsyncWrites:      true,
	}
	
	logger := log.New(os.Stdout, "[BENCH] ", log.LstdFlags)
	cache, err := NewCacheLayer(config, logger)
	if err != nil {
		b.Fatalf("Failed to create cache layer: %v", err)
	}
	defer cache.Shutdown(context.Background())
	
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("bench-key-%d", i)
			value := fmt.Sprintf("bench-value-%d", i)
			err := cache.Set(ctx, key, value, 1*time.Minute)
			if err != nil {
				b.Fatalf("Failed to set value: %v", err)
			}
			i++
		}
	})
}

func BenchmarkMultiLevelCache_Get(b *testing.B) {
	config := &CacheConfig{
		L1MaxSize:        10 * 1024 * 1024, // 10MB
		L1MaxEntries:     10000,
		L1DefaultTTL:     5 * time.Minute,
		L1CleanupInterval: 1 * time.Minute,
		L2Endpoints:      []string{"localhost:6379"},
		L2DefaultTTL:     1 * time.Hour,
		WarmingEnabled:   false,
		MetricsEnabled:   false,
	}
	
	logger := log.New(os.Stdout, "[BENCH] ", log.LstdFlags)
	cache, err := NewCacheLayer(config, logger)
	if err != nil {
		b.Fatalf("Failed to create cache layer: %v", err)
	}
	defer cache.Shutdown(context.Background())
	
	ctx := context.Background()
	
	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		key := fmt.Sprintf("bench-key-%d", i)
		value := fmt.Sprintf("bench-value-%d", i)
		err := cache.Set(ctx, key, value, 1*time.Minute)
		if err != nil {
			b.Fatalf("Failed to set value: %v", err)
		}
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("bench-key-%d", i%1000)
			_, err := cache.Get(ctx, key)
			if err != nil {
				b.Fatalf("Failed to get value: %v", err)
			}
			i++
		}
	})
}

func BenchmarkMultiLevelCache_Mixed(b *testing.B) {
	config := &CacheConfig{
		L1MaxSize:        10 * 1024 * 1024, // 10MB
		L1MaxEntries:     10000,
		L1DefaultTTL:     5 * time.Minute,
		L1CleanupInterval: 1 * time.Minute,
		L2Endpoints:      []string{"localhost:6379"},
		L2DefaultTTL:     1 * time.Hour,
		WarmingEnabled:   false,
		MetricsEnabled:   false,
		AsyncWrites:      true,
	}
	
	logger := log.New(os.Stdout, "[BENCH] ", log.LstdFlags)
	cache, err := NewCacheLayer(config, logger)
	if err != nil {
		b.Fatalf("Failed to create cache layer: %v", err)
	}
	defer cache.Shutdown(context.Background())
	
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("bench-key-%d", i)
			
			if i%3 == 0 {
				// Set operation
				value := fmt.Sprintf("bench-value-%d", i)
				err := cache.Set(ctx, key, value, 1*time.Minute)
				if err != nil {
					b.Fatalf("Failed to set value: %v", err)
				}
			} else {
				// Get operation
				_, _ = cache.Get(ctx, key) // Ignore errors for missing keys
			}
			i++
		}
	})
}