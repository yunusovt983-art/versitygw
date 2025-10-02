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
	"io"
	"log"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// BenchmarkPinOperations benchmarks pin operations with various scenarios
func BenchmarkPinOperations(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()
	
	ctx := context.Background()
	
	b.Run("SinglePin", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cid := fmt.Sprintf("QmBenchSingle%d", i)
			_, err := suite.clusterClient.Pin(ctx, cid, 2)
			if err != nil {
				b.Fatalf("Pin failed: %v", err)
			}
		}
	})
	
	b.Run("ConcurrentPins", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				cid := fmt.Sprintf("QmBenchConcurrent%d", i)
				_, err := suite.clusterClient.Pin(ctx, cid, 2)
				if err != nil {
					b.Fatalf("Concurrent pin failed: %v", err)
				}
				i++
			}
		})
	})
	
	b.Run("VariableReplication", func(b *testing.B) {
		replicationFactors := []int{1, 2, 3, 4, 5}
		
		for _, rf := range replicationFactors {
			b.Run(fmt.Sprintf("Replication%d", rf), func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					cid := fmt.Sprintf("QmBenchRepl%d-%d", rf, i)
					_, err := suite.clusterClient.Pin(ctx, cid, rf)
					if err != nil {
						b.Fatalf("Pin with replication %d failed: %v", rf, err)
					}
				}
			})
		}
	})
	
	b.Run("PinUnpinCycle", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cid := fmt.Sprintf("QmBenchCycle%d", i)
			
			// Pin
			_, err := suite.clusterClient.Pin(ctx, cid, 2)
			if err != nil {
				b.Fatalf("Pin failed: %v", err)
			}
			
			// Unpin
			_, err = suite.clusterClient.Unpin(ctx, cid)
			if err != nil {
				b.Fatalf("Unpin failed: %v", err)
			}
		}
	})
}

// BenchmarkMetadataOperations benchmarks metadata store operations
func BenchmarkMetadataOperations(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()
	
	ctx := context.Background()
	
	b.Run("StoreMapping", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("bench-key-%d", i),
				Bucket:    "bench-bucket",
				CID:       fmt.Sprintf("QmBenchStore%d", i),
				Size:      int64(1024 * (i%100 + 1)),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}
			
			err := suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				b.Fatalf("Store mapping failed: %v", err)
			}
		}
	})
	
	b.Run("GetMapping", func(b *testing.B) {
		// Pre-populate with test data
		numPrePopulate := 1000
		for i := 0; i < numPrePopulate; i++ {
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("get-bench-key-%d", i),
				Bucket:    "get-bench-bucket",
				CID:       fmt.Sprintf("QmBenchGet%d", i),
				Size:      int64(1024 * (i%100 + 1)),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}
			suite.metadataStore.StoreMapping(ctx, mapping)
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("get-bench-key-%d", i%numPrePopulate)
			_, err := suite.metadataStore.GetMapping(ctx, key, "get-bench-bucket")
			if err != nil {
				b.Fatalf("Get mapping failed: %v", err)
			}
		}
	})
	
	b.Run("BatchOperations", func(b *testing.B) {
		batchSizes := []int{10, 50, 100, 500, 1000}
		
		for _, batchSize := range batchSizes {
			b.Run(fmt.Sprintf("BatchSize%d", batchSize), func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					mappings := make([]*ObjectMapping, batchSize)
					for j := 0; j < batchSize; j++ {
						mappings[j] = &ObjectMapping{
							S3Key:     fmt.Sprintf("batch-key-%d-%d", i, j),
							Bucket:    "batch-bucket",
							CID:       fmt.Sprintf("QmBatch%d-%d", i, j),
							Size:      int64(1024 * (j%100 + 1)),
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
		}
	})
	
	b.Run("ConcurrentMetadata", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				mapping := &ObjectMapping{
					S3Key:     fmt.Sprintf("concurrent-key-%d", i),
					Bucket:    "concurrent-bucket",
					CID:       fmt.Sprintf("QmConcurrent%d", i),
					Size:      int64(1024 * (i%100 + 1)),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					PinStatus: PinStatusPinned,
				}
				
				err := suite.metadataStore.StoreMapping(ctx, mapping)
				if err != nil {
					b.Fatalf("Concurrent store failed: %v", err)
				}
				i++
			}
		})
	})
	
	b.Run("SearchOperations", func(b *testing.B) {
		// Pre-populate with searchable data
		numPrePopulate := 10000
		for i := 0; i < numPrePopulate; i++ {
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("search-key-%d", i),
				Bucket:    fmt.Sprintf("search-bucket-%d", i%10),
				CID:       fmt.Sprintf("QmSearch%d", i),
				Size:      int64(1024 * (i%100 + 1)),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}
			suite.metadataStore.StoreMapping(ctx, mapping)
		}
		
		b.Run("SearchByPrefix", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				bucket := fmt.Sprintf("search-bucket-%d", i%10)
				prefix := fmt.Sprintf("search-key-%d", i%100)
				_, err := suite.metadataStore.SearchByPrefix(ctx, bucket, prefix, 100)
				if err != nil {
					b.Fatalf("Search by prefix failed: %v", err)
				}
			}
		})
		
		b.Run("SearchByCID", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cid := fmt.Sprintf("QmSearch%d", i%numPrePopulate)
				_, err := suite.metadataStore.SearchByCID(ctx, cid)
				if err != nil {
					b.Fatalf("Search by CID failed: %v", err)
				}
			}
		})
	})
}

// BenchmarkScalabilityTests benchmarks operations at different scales
func BenchmarkScalabilityTests(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()
	
	ctx := context.Background()
	
	// Test different scales of operations
	scales := []int{100, 1000, 10000, 100000}
	
	for _, scale := range scales {
		b.Run(fmt.Sprintf("Scale%d", scale), func(b *testing.B) {
			// Pre-populate with data at this scale
			for i := 0; i < scale; i++ {
				mapping := &ObjectMapping{
					S3Key:     fmt.Sprintf("scale-key-%d", i),
					Bucket:    fmt.Sprintf("scale-bucket-%d", i%100),
					CID:       fmt.Sprintf("QmScale%d", i),
					Size:      int64(1024 * (i%1000 + 1)),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					PinStatus: PinStatusPinned,
				}
				suite.metadataStore.StoreMapping(ctx, mapping)
			}
			
			b.ResetTimer()
			
			// Benchmark operations at this scale
			for i := 0; i < b.N; i++ {
				// Random read
				randomKey := fmt.Sprintf("scale-key-%d", rand.Intn(scale))
				randomBucket := fmt.Sprintf("scale-bucket-%d", rand.Intn(100))
				_, err := suite.metadataStore.GetMapping(ctx, randomKey, randomBucket)
				if err != nil {
					// It's okay if some random keys don't exist
				}
				
				// Random write
				newMapping := &ObjectMapping{
					S3Key:     fmt.Sprintf("new-scale-key-%d-%d", scale, i),
					Bucket:    fmt.Sprintf("scale-bucket-%d", rand.Intn(100)),
					CID:       fmt.Sprintf("QmNewScale%d-%d", scale, i),
					Size:      int64(1024 * (i%1000 + 1)),
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					PinStatus: PinStatusPinned,
				}
				
				err = suite.metadataStore.StoreMapping(ctx, newMapping)
				if err != nil {
					b.Fatalf("Scale %d write failed: %v", scale, err)
				}
			}
		})
	}
}

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()
	
	ctx := context.Background()
	
	b.Run("MemoryGrowth", func(b *testing.B) {
		var mappings []*ObjectMapping
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("memory-key-%d", i),
				Bucket:    "memory-bucket",
				CID:       fmt.Sprintf("QmMemory%d", i),
				Size:      int64(1024 * (i%100 + 1)),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
				Metadata: ObjectMetadata{
					ContentType: "application/octet-stream",
					UserMetadata: map[string]string{
						"test-key": fmt.Sprintf("test-value-%d", i),
					},
				},
			}
			
			mappings = append(mappings, mapping)
			
			err := suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				b.Fatalf("Memory test store failed: %v", err)
			}
			
			// Periodically check memory usage
			if i%1000 == 0 {
				b.StopTimer()
				// Here you could add memory usage checks
				b.StartTimer()
			}
		}
	})
}

// BenchmarkThroughput benchmarks throughput under various conditions
func BenchmarkThroughput(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()
	
	ctx := context.Background()
	
	b.Run("MaxThroughput", func(b *testing.B) {
		// Test maximum throughput with optimal conditions
		b.SetParallelism(100) // High parallelism
		
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				// Mix of operations to simulate real workload
				if i%3 == 0 {
					// Pin operation
					cid := fmt.Sprintf("QmThroughputPin%d", i)
					_, err := suite.clusterClient.Pin(ctx, cid, 2)
					if err != nil {
						b.Fatalf("Throughput pin failed: %v", err)
					}
				} else if i%3 == 1 {
					// Metadata store
					mapping := &ObjectMapping{
						S3Key:     fmt.Sprintf("throughput-key-%d", i),
						Bucket:    "throughput-bucket",
						CID:       fmt.Sprintf("QmThroughputMeta%d", i),
						Size:      int64(1024 * (i%100 + 1)),
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
						PinStatus: PinStatusPinned,
					}
					
					err := suite.metadataStore.StoreMapping(ctx, mapping)
					if err != nil {
						b.Fatalf("Throughput metadata failed: %v", err)
					}
				} else {
					// Metadata get
					key := fmt.Sprintf("throughput-key-%d", i-1)
					_, err := suite.metadataStore.GetMapping(ctx, key, "throughput-bucket")
					if err != nil {
						// It's okay if the key doesn't exist yet
					}
				}
				i++
			}
		})
	})
	
	b.Run("SustainedLoad", func(b *testing.B) {
		// Test sustained load over time
		duration := 10 * time.Second
		
		b.ResetTimer()
		
		start := time.Now()
		operations := 0
		
		for time.Since(start) < duration {
			cid := fmt.Sprintf("QmSustained%d", operations)
			_, err := suite.clusterClient.Pin(ctx, cid, 2)
			if err != nil {
				b.Fatalf("Sustained load pin failed: %v", err)
			}
			operations++
		}
		
		b.ReportMetric(float64(operations)/duration.Seconds(), "ops/sec")
	})
}

// BenchmarkLatency benchmarks latency characteristics
func BenchmarkLatency(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()
	
	ctx := context.Background()
	
	b.Run("PinLatency", func(b *testing.B) {
		latencies := make([]time.Duration, b.N)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			start := time.Now()
			
			cid := fmt.Sprintf("QmLatencyPin%d", i)
			_, err := suite.clusterClient.Pin(ctx, cid, 2)
			if err != nil {
				b.Fatalf("Latency pin failed: %v", err)
			}
			
			latencies[i] = time.Since(start)
		}
		
		b.StopTimer()
		
		// Calculate latency statistics
		var total time.Duration
		min := latencies[0]
		max := latencies[0]
		
		for _, lat := range latencies {
			total += lat
			if lat < min {
				min = lat
			}
			if lat > max {
				max = lat
			}
		}
		
		avg := total / time.Duration(len(latencies))
		
		b.ReportMetric(float64(min.Nanoseconds())/1e6, "min_latency_ms")
		b.ReportMetric(float64(avg.Nanoseconds())/1e6, "avg_latency_ms")
		b.ReportMetric(float64(max.Nanoseconds())/1e6, "max_latency_ms")
	})
	
	b.Run("MetadataLatency", func(b *testing.B) {
		latencies := make([]time.Duration, b.N)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			start := time.Now()
			
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("latency-key-%d", i),
				Bucket:    "latency-bucket",
				CID:       fmt.Sprintf("QmLatencyMeta%d", i),
				Size:      int64(1024),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}
			
			err := suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				b.Fatalf("Latency metadata failed: %v", err)
			}
			
			latencies[i] = time.Since(start)
		}
		
		b.StopTimer()
		
		// Calculate latency statistics
		var total time.Duration
		min := latencies[0]
		max := latencies[0]
		
		for _, lat := range latencies {
			total += lat
			if lat < min {
				min = lat
			}
			if lat > max {
				max = lat
			}
		}
		
		avg := total / time.Duration(len(latencies))
		
		b.ReportMetric(float64(min.Nanoseconds())/1e6, "min_latency_ms")
		b.ReportMetric(float64(avg.Nanoseconds())/1e6, "avg_latency_ms")
		b.ReportMetric(float64(max.Nanoseconds())/1e6, "max_latency_ms")
	})
}

// BenchmarkResourceUtilization benchmarks resource utilization
func BenchmarkResourceUtilization(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()
	
	ctx := context.Background()
	
	b.Run("CPUUtilization", func(b *testing.B) {
		// CPU-intensive operations
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				// Simulate CPU-intensive work
				for j := 0; j < 1000; j++ {
					_ = fmt.Sprintf("QmCPUTest%d-%d", i, j)
				}
				
				cid := fmt.Sprintf("QmCPU%d", i)
				_, err := suite.clusterClient.Pin(ctx, cid, 2)
				if err != nil {
					b.Fatalf("CPU test pin failed: %v", err)
				}
				i++
			}
		})
	})
	
	b.Run("MemoryUtilization", func(b *testing.B) {
		// Memory-intensive operations
		var data [][]byte
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Allocate memory
			chunk := make([]byte, 1024*1024) // 1MB
			data = append(data, chunk)
			
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("memory-util-key-%d", i),
				Bucket:    "memory-util-bucket",
				CID:       fmt.Sprintf("QmMemoryUtil%d", i),
				Size:      int64(len(chunk)),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}
			
			err := suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				b.Fatalf("Memory util test failed: %v", err)
			}
			
			// Periodically clean up to avoid OOM
			if i%100 == 0 {
				data = data[:0]
			}
		}
	})
}

// BenchmarkRealWorldScenarios benchmarks realistic usage scenarios
func BenchmarkRealWorldScenarios(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()
	
	ctx := context.Background()
	
	b.Run("TypicalWorkload", func(b *testing.B) {
		// Simulate typical workload: 70% reads, 30% writes
		// Pre-populate some data
		numPrePopulate := 1000
		for i := 0; i < numPrePopulate; i++ {
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("typical-key-%d", i),
				Bucket:    fmt.Sprintf("typical-bucket-%d", i%10),
				CID:       fmt.Sprintf("QmTypical%d", i),
				Size:      int64(1024 * (i%100 + 1)),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
			}
			suite.metadataStore.StoreMapping(ctx, mapping)
		}
		
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if rand.Float64() < 0.7 {
					// Read operation (70%)
					key := fmt.Sprintf("typical-key-%d", rand.Intn(numPrePopulate))
					bucket := fmt.Sprintf("typical-bucket-%d", rand.Intn(10))
					_, err := suite.metadataStore.GetMapping(ctx, key, bucket)
					if err != nil {
						// Some reads might miss, that's okay
					}
				} else {
					// Write operation (30%)
					mapping := &ObjectMapping{
						S3Key:     fmt.Sprintf("new-typical-key-%d", i),
						Bucket:    fmt.Sprintf("typical-bucket-%d", rand.Intn(10)),
						CID:       fmt.Sprintf("QmNewTypical%d", i),
						Size:      int64(1024 * (rand.Intn(100) + 1)),
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
						PinStatus: PinStatusPinned,
					}
					
					err := suite.metadataStore.StoreMapping(ctx, mapping)
					if err != nil {
						b.Fatalf("Typical workload write failed: %v", err)
					}
					
					// Also pin the object
					_, err = suite.clusterClient.Pin(ctx, mapping.CID, 2)
					if err != nil {
						b.Fatalf("Typical workload pin failed: %v", err)
					}
				}
				i++
			}
		})
	})
	
	b.Run("BurstTraffic", func(b *testing.B) {
		// Simulate burst traffic patterns
		b.ResetTimer()
		
		// Normal load phase
		normalOps := b.N / 3
		for i := 0; i < normalOps; i++ {
			cid := fmt.Sprintf("QmBurstNormal%d", i)
			_, err := suite.clusterClient.Pin(ctx, cid, 2)
			if err != nil {
				b.Fatalf("Burst normal pin failed: %v", err)
			}
		}
		
		// Burst phase - high concurrency
		burstOps := b.N / 3
		var wg sync.WaitGroup
		burstChan := make(chan int, burstOps)
		
		// Fill burst channel
		for i := 0; i < burstOps; i++ {
			burstChan <- i
		}
		close(burstChan)
		
		// Process burst with high concurrency
		numWorkers := 50
		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range burstChan {
					cid := fmt.Sprintf("QmBurstHigh%d", i)
					_, err := suite.clusterClient.Pin(ctx, cid, 2)
					if err != nil {
						b.Fatalf("Burst high pin failed: %v", err)
					}
				}
			}()
		}
		wg.Wait()
		
		// Cool down phase
		cooldownOps := b.N - normalOps - burstOps
		for i := 0; i < cooldownOps; i++ {
			cid := fmt.Sprintf("QmBurstCooldown%d", i)
			_, err := suite.clusterClient.Pin(ctx, cid, 2)
			if err != nil {
				b.Fatalf("Burst cooldown pin failed: %v", err)
			}
			
			// Add small delay to simulate cooldown
			time.Sleep(time.Microsecond)
		}
	})
}

// BenchmarkLargeScale benchmarks operations at large scale
func BenchmarkLargeScale(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping large scale benchmarks in short mode")
	}
	
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()
	
	// Disable logging for performance
	suite.logger = log.New(io.Discard, "", 0)
	
	ctx := context.Background()
	
	b.Run("MillionPins", func(b *testing.B) {
		if b.N < 1000000 {
			b.N = 1000000 // Force at least 1 million operations
		}
		
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				cid := fmt.Sprintf("QmMillion%d", i)
				_, err := suite.clusterClient.Pin(ctx, cid, 2)
				if err != nil {
					b.Fatalf("Million pins test failed: %v", err)
				}
				i++
			}
		})
	})
	
	b.Run("LargeMetadataSet", func(b *testing.B) {
		if b.N < 100000 {
			b.N = 100000 // Force at least 100k operations
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mapping := &ObjectMapping{
				S3Key:     fmt.Sprintf("large-meta-key-%d", i),
				Bucket:    fmt.Sprintf("large-bucket-%d", i%1000),
				CID:       fmt.Sprintf("QmLargeMeta%d", i),
				Size:      int64(1024 * (i%1000 + 1)),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
				PinStatus: PinStatusPinned,
				Metadata: ObjectMetadata{
					ContentType: "application/octet-stream",
					UserMetadata: map[string]string{
						"large-key-1": fmt.Sprintf("large-value-1-%d", i),
						"large-key-2": fmt.Sprintf("large-value-2-%d", i),
						"large-key-3": fmt.Sprintf("large-value-3-%d", i),
					},
				},
			}
			
			err := suite.metadataStore.StoreMapping(ctx, mapping)
			if err != nil {
				b.Fatalf("Large metadata set test failed: %v", err)
			}
		}
	})
}

// BenchmarkComparison benchmarks different implementation approaches
func BenchmarkComparison(b *testing.B) {
	suite := NewTestSuite(&testing.T{})
	defer suite.Cleanup()
	
	ctx := context.Background()
	
	b.Run("SingleVsBatch", func(b *testing.B) {
		batchSize := 100
		
		b.Run("SingleOperations", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				mapping := &ObjectMapping{
					S3Key:     fmt.Sprintf("single-key-%d", i),
					Bucket:    "single-bucket",
					CID:       fmt.Sprintf("QmSingle%d", i),
					Size:      1024,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					PinStatus: PinStatusPinned,
				}
				
				err := suite.metadataStore.StoreMapping(ctx, mapping)
				if err != nil {
					b.Fatalf("Single operation failed: %v", err)
				}
			}
		})
		
		b.Run("BatchOperations", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i += batchSize {
				end := i + batchSize
				if end > b.N {
					end = b.N
				}
				
				mappings := make([]*ObjectMapping, end-i)
				for j := i; j < end; j++ {
					mappings[j-i] = &ObjectMapping{
						S3Key:     fmt.Sprintf("batch-key-%d", j),
						Bucket:    "batch-bucket",
						CID:       fmt.Sprintf("QmBatch%d", j),
						Size:      1024,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
						PinStatus: PinStatusPinned,
					}
				}
				
				err := suite.metadataStore.StoreMappingBatch(ctx, mappings)
				if err != nil {
					b.Fatalf("Batch operation failed: %v", err)
				}
			}
		})
	})
	
	b.Run("SyncVsAsync", func(b *testing.B) {
		// This would compare synchronous vs asynchronous operations
		// For now, we'll just test synchronous since async isn't fully implemented
		b.Run("SynchronousOperations", func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cid := fmt.Sprintf("QmSync%d", i)
				_, err := suite.clusterClient.Pin(ctx, cid, 2)
				if err != nil {
					b.Fatalf("Sync operation failed: %v", err)
				}
			}
		})
	})
}