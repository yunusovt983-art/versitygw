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
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkComprehensivePinOperations runs comprehensive pin operation benchmarks
func BenchmarkComprehensivePinOperations(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()

	ctx := context.Background()

	b.Run("SequentialPins", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cid := fmt.Sprintf("QmBenchSeq%d", i)
			_, err := suite.clusterClient.Pin(ctx, cid, 2)
			if err != nil {
				b.Fatalf("Sequential pin failed: %v", err)
			}
		}
	})

	b.Run("ParallelPins", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				cid := fmt.Sprintf("QmBenchPar%d", i)
				_, err := suite.clusterClient.Pin(ctx, cid, 2)
				if err != nil {
					b.Fatalf("Parallel pin failed: %v", err)
				}
				i++
			}
		})
	})

	b.Run("HighReplicationPins", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cid := fmt.Sprintf("QmBenchHighRepl%d", i)
			_, err := suite.clusterClient.Pin(ctx, cid, 5) // High replication
			if err != nil {
				b.Fatalf("High replication pin failed: %v", err)
			}
		}
	})

	b.Run("BurstPins", func(b *testing.B) {
		// Test burst pin operations
		burstSize := 100
		numBursts := b.N / burstSize
		if numBursts == 0 {
			numBursts = 1
		}

		b.ResetTimer()
		for burst := 0; burst < numBursts; burst++ {
			var wg sync.WaitGroup
			for i := 0; i < burstSize; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					cid := fmt.Sprintf("QmBenchBurst%d-%d", burst, id)
					_, err := suite.clusterClient.Pin(ctx, cid, 2)
					if err != nil {
						b.Errorf("Burst pin failed: %v", err)
					}
				}(i)
			}
			wg.Wait()
		}
	})
}

// BenchmarkMetadataOperationsExtended runs extended metadata benchmarks
func BenchmarkMetadataOperationsExtended(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()

	ctx := context.Background()

	b.Run("SingleStore", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("bench-key-%d", i),
				Bucket:    "bench-bucket",
				CID:       fmt.Sprintf("QmBench%d", i),
				Size:      1024,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}

			err := suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				b.Fatalf("Store failed: %v", err)
			}
		}
	})

	b.Run("BatchStore", func(b *testing.B) {
		batchSize := 100
		numBatches := b.N / batchSize
		if numBatches == 0 {
			numBatches = 1
		}

		b.ResetTimer()
		for batch := 0; batch < numBatches; batch++ {
			mappings := make([]*ObjectMapping, batchSize)
			for i := 0; i < batchSize; i++ {
				mappings[i] = &ObjectMapping{
					S3Key:     fmt.Sprintf("batch-key-%d-%d", batch, i),
					Bucket:    fmt.Sprintf("batch-bucket-%d", batch%10),
					CID:       fmt.Sprintf("QmBatch%d-%d", batch, i),
					Size:      int64(1024 * (i + 1)),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					PinStatus: PinStatusPinned,
				}
			}

			err := suite.metadataStore.StoreMappingBatch(ctx, mappings)
			if err != nil {
				b.Fatalf("Batch store failed: %v", err)
			}
		}
	})

	b.Run("ConcurrentReads", func(b *testing.B) {
		// Pre-populate some data
		for i := 0; i < 1000; i++ {
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("read-key-%d", i),
				Bucket:    fmt.Sprintf("read-bucket-%d", i%10),
				CID:       fmt.Sprintf("QmRead%d", i),
				Size:      1024,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}
			suite.metadataStore.StoreMapping(ctx, mapping)
		}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				key := fmt.Sprintf("read-key-%d", rand.Intn(1000))
				bucket := fmt.Sprintf("read-bucket-%d", rand.Intn(10))
				_, err := suite.metadataStore.GetMapping(ctx, key, bucket)
				if err != nil {
					// Some keys might not exist, that's okay for this benchmark
				}
			}
		})
	})

	b.Run("SearchOperations", func(b *testing.B) {
		// Pre-populate search data
		for i := 0; i < 1000; i++ {
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("search-key-%d", i),
				Bucket:    "search-bucket",
				CID:       fmt.Sprintf("QmSearch%d", i),
				Size:      1024,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}
			suite.metadataStore.StoreMapping(ctx, mapping)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			prefix := fmt.Sprintf("search-key-%d", rand.Intn(100))
			_, err := suite.metadataStore.SearchByPrefix(ctx, "search-bucket", prefix, 10)
			if err != nil {
				b.Fatalf("Search failed: %v", err)
			}
		}
	})
}

// BenchmarkScalabilityTests runs scalability benchmarks
func BenchmarkScalabilityTests(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()

	ctx := context.Background()

	scales := []int{100, 1000, 10000}

	for _, scale := range scales {
		b.Run(fmt.Sprintf("Scale_%d_Operations", scale), func(b *testing.B) {
			b.ResetTimer()

			var totalOps int64
			var errors int64

			start := time.Now()

			var wg sync.WaitGroup
			numWorkers := 10
			opsPerWorker := scale / numWorkers

			for i := 0; i < numWorkers; i++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()

					for j := 0; j < opsPerWorker; j++ {
						// Mix of operations
						if j%3 == 0 {
							// Pin operation
							cid := fmt.Sprintf("QmScale%d-%d-%d", scale, workerID, j)
							_, err := suite.clusterClient.Pin(ctx, cid, 2)
							if err != nil {
								atomic.AddInt64(&errors, 1)
							} else {
								atomic.AddInt64(&totalOps, 1)
							}
						} else {
							// Metadata operation
							mapping := &ObjectMapping{
								S3Key:     fmt.Sprintf("scale-key-%d-%d-%d", scale, workerID, j),
								Bucket:    fmt.Sprintf("scale-bucket-%d", workerID%10),
								CID:       fmt.Sprintf("QmScaleMeta%d-%d-%d", scale, workerID, j),
								Size:      1024,
								CreatedAt: time.Now(),
								UpdatedAt: time.Now(),
								PinStatus: PinStatusPinned,
							}

							err := suite.metadataStore.StoreMapping(ctx, mapping)
							if err != nil {
								atomic.AddInt64(&errors, 1)
							} else {
								atomic.AddInt64(&totalOps, 1)
							}
						}
					}
				}(i)
			}

			wg.Wait()
			duration := time.Since(start)

			opsPerSec := float64(totalOps) / duration.Seconds()
			errorRate := float64(errors) / float64(totalOps+errors)

			b.ReportMetric(opsPerSec, "ops_per_sec")
			b.ReportMetric(errorRate*100, "error_rate_%")
			b.ReportMetric(float64(totalOps), "total_ops")
		})
	}
}

// BenchmarkConcurrencyLevels tests different concurrency levels
func BenchmarkConcurrencyLevels(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()

	ctx := context.Background()
	concurrencyLevels := []int{1, 5, 10, 25, 50, 100}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Concurrency_%d", concurrency), func(b *testing.B) {
			b.ResetTimer()

			var totalOps int64
			var totalLatency int64

			var wg sync.WaitGroup
			opsPerWorker := b.N / concurrency
			if opsPerWorker == 0 {
				opsPerWorker = 1
			}

			start := time.Now()

			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()

					for j := 0; j < opsPerWorker; j++ {
						opStart := time.Now()

						cid := fmt.Sprintf("QmConcurrency%d-%d-%d", concurrency, workerID, j)
						_, err := suite.clusterClient.Pin(ctx, cid, 2)

						latency := time.Since(opStart)
						atomic.AddInt64(&totalLatency, latency.Nanoseconds())

						if err == nil {
							atomic.AddInt64(&totalOps, 1)
						}
					}
				}(i)
			}

			wg.Wait()
			totalDuration := time.Since(start)

			avgLatency := time.Duration(totalLatency / totalOps)
			opsPerSec := float64(totalOps) / totalDuration.Seconds()

			b.ReportMetric(opsPerSec, "ops_per_sec")
			b.ReportMetric(float64(avgLatency.Nanoseconds())/1e6, "avg_latency_ms")
			b.ReportMetric(float64(totalOps), "total_ops")
		})
	}
}

// BenchmarkMemoryUsage tests memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()

	ctx := context.Background()

	b.Run("LargeObjectMetadata", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// Create mapping with large metadata
			userMetadata := make(map[string]string)
			for j := 0; j < 100; j++ {
				userMetadata[fmt.Sprintf("key-%d", j)] = fmt.Sprintf("value-%d-%s", j,
					"large-value-content-that-takes-up-more-memory-space")
			}

			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("large-meta-key-%d", i),
				Bucket:    "large-meta-bucket",
				CID:       fmt.Sprintf("QmLargeMeta%d", i),
				Size:      1024 * 1024, // 1MB
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
				Metadata: ObjectMetadata{
					UserMetadata: userMetadata,
				},
			}

			err := suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				b.Fatalf("Large metadata store failed: %v", err)
			}
		}
	})

	b.Run("ManySmallObjects", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("small-key-%d", i),
				Bucket:    fmt.Sprintf("small-bucket-%d", i%1000),
				CID:       fmt.Sprintf("QmSmall%d", i),
				Size:      64, // 64 bytes
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}

			err := suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				b.Fatalf("Small object store failed: %v", err)
			}
		}
	})
}

// BenchmarkErrorHandlingPerformance tests performance under error conditions
func BenchmarkErrorHandlingPerformance(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()

	ctx := context.Background()

	b.Run("WithErrors", func(b *testing.B) {
		// Enable some failures
		suite.clusterClient.SetFailRate(0.1) // 10% failure rate
		defer suite.clusterClient.SetFailRate(0)

		b.ResetTimer()

		var successCount int64
		var errorCount int64

		for i := 0; i < b.N; i++ {
			cid := fmt.Sprintf("QmErrorBench%d", i)
			_, err := suite.clusterClient.Pin(ctx, cid, 2)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
			} else {
				atomic.AddInt64(&successCount, 1)
			}
		}

		b.ReportMetric(float64(successCount), "successful_ops")
		b.ReportMetric(float64(errorCount), "failed_ops")
		b.ReportMetric(float64(errorCount)/float64(successCount+errorCount)*100, "error_rate_%")
	})

	b.Run("WithRetries", func(b *testing.B) {
		// Enable failures and retries
		suite.clusterClient.SetFailRate(0.2) // 20% failure rate
		suite.clusterClient.SetRetryEnabled(true)
		defer func() {
			suite.clusterClient.SetFailRate(0)
			suite.clusterClient.SetRetryEnabled(false)
		}()

		b.ResetTimer()

		var successCount int64
		var errorCount int64

		for i := 0; i < b.N; i++ {
			cid := fmt.Sprintf("QmRetryBench%d", i)
			_, err := suite.clusterClient.Pin(ctx, cid, 2)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
			} else {
				atomic.AddInt64(&successCount, 1)
			}
		}

		b.ReportMetric(float64(successCount), "successful_ops")
		b.ReportMetric(float64(errorCount), "failed_ops")
		b.ReportMetric(float64(errorCount)/float64(successCount+errorCount)*100, "error_rate_%")
	})
}

// BenchmarkCachePerformance tests cache performance (when implemented)
func BenchmarkCachePerformance(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()

	ctx := context.Background()

	// Pre-populate some data
	for i := 0; i < 1000; i++ {
		mapping := &ObjectMapping{
			S3Key:     fmt.Sprintf("cache-key-%d", i),
			Bucket:    "cache-bucket",
			CID:       fmt.Sprintf("QmCache%d", i),
			Size:      1024,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			PinStatus: PinStatusPinned,
		}
		suite.metadataStore.StoreMapping(ctx, mapping)
	}

	b.Run("CacheHits", func(b *testing.B) {
		b.ResetTimer()

		// Repeatedly access the same keys to test cache hits
		keys := []string{"cache-key-1", "cache-key-2", "cache-key-3", "cache-key-4", "cache-key-5"}

		for i := 0; i < b.N; i++ {
			key := keys[i%len(keys)]
			_, err := suite.metadataStore.GetMapping(ctx, key, "cache-bucket")
			if err != nil {
				// Some cache misses are expected
			}
		}
	})

	b.Run("CacheMisses", func(b *testing.B) {
		b.ResetTimer()

		// Access random keys to test cache misses
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("cache-miss-key-%d", rand.Intn(10000))
			_, err := suite.metadataStore.GetMapping(ctx, key, "cache-bucket")
			if err != nil {
				// Cache misses are expected
			}
		}
	})
}

// BenchmarkNetworkLatencySimulation simulates different network conditions
func BenchmarkNetworkLatencySimulation(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()

	ctx := context.Background()

	latencies := []time.Duration{
		0, // No latency
		1 * time.Millisecond,
		10 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
	}

	for _, latency := range latencies {
		b.Run(fmt.Sprintf("Latency_%v", latency), func(b *testing.B) {
			suite.clusterClient.SetSimulatedLatency(latency)
			defer suite.clusterClient.SetSimulatedLatency(0)

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				cid := fmt.Sprintf("QmLatency%d", i)
				_, err := suite.clusterClient.Pin(ctx, cid, 2)
				if err != nil {
					b.Fatalf("Pin with latency %v failed: %v", latency, err)
				}
			}
		})
	}
}

// BenchmarkResourceUtilization tests resource utilization patterns
func BenchmarkResourceUtilization(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()

	ctx := context.Background()

	b.Run("CPUIntensive", func(b *testing.B) {
		b.ResetTimer()

		var wg sync.WaitGroup
		numWorkers := 20 // High CPU usage

		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()

				for j := 0; j < b.N/numWorkers; j++ {
					cid := fmt.Sprintf("QmCPU%d-%d", workerID, j)
					_, err := suite.clusterClient.Pin(ctx, cid, 2)
					if err != nil {
						b.Errorf("CPU intensive pin failed: %v", err)
					}
				}
			}(i)
		}

		wg.Wait()
	})

	b.Run("MemoryIntensive", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// Create large metadata objects
			largeMetadata := make(map[string]string)
			for j := 0; j < 1000; j++ {
				largeMetadata[fmt.Sprintf("key-%d", j)] = fmt.Sprintf("large-value-%d", j)
			}

			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("memory-key-%d", i),
				Bucket:    "memory-bucket",
				CID:       fmt.Sprintf("QmMemory%d", i),
				Size:      1024 * 1024, // 1MB
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
				Metadata: ObjectMetadata{
					UserMetadata: largeMetadata,
				},
			}

			err := suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				b.Fatalf("Memory intensive store failed: %v", err)
			}
		}
	})
}
