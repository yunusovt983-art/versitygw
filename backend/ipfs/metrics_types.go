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
	"sort"
	"sync/atomic"
	"time"
)

// Implementation of metric types

// newPinMetricsCollector creates a new pin metrics collector
func newPinMetricsCollector() *PinMetricsCollector {
	return &PinMetricsCollector{
		pinLatencyHistogram:        newLatencyHistogram(),
		unpinLatencyHistogram:      newLatencyHistogram(),
		pinThroughput:              newThroughputCounter(),
		unpinThroughput:            newThroughputCounter(),
		pinErrors:                  newErrorCounter(),
		unpinErrors:                newErrorCounter(),
		queueDepth:                 newGaugeMetric(),
		replicationFactorHistogram: newReplicationHistogram(),
	}
}

// newClusterMetricsCollector creates a new cluster metrics collector
func newClusterMetricsCollector() *ClusterMetricsCollector {
	return &ClusterMetricsCollector{
		healthyNodes:       newGaugeMetric(),
		unhealthyNodes:     newGaugeMetric(),
		totalNodes:         newGaugeMetric(),
		splitBrainDetected: newCounterMetric(),
		networkLatency:     newLatencyHistogram(),
		networkErrors:      newErrorCounter(),
		totalStorage:       newGaugeMetric(),
		usedStorage:        newGaugeMetric(),
	}
}

// newUsageMetricsCollector creates a new usage metrics collector
func newUsageMetricsCollector() *UsageMetricsCollector {
	return &UsageMetricsCollector{
		objectAccess:        make(map[string]*ObjectAccessMetrics),
		bucketAccess:        make(map[string]*BucketAccessMetrics),
		geographicAccess:    make(map[string]*GeographicAccessMetrics),
		hotDataObjects:      newGaugeMetric(),
		warmDataObjects:     newGaugeMetric(),
		coldDataObjects:     newGaugeMetric(),
		objectSizeHistogram: newSizeHistogram(),
		hourlyAccess:        newTimeSeriesMetric(),
		dailyAccess:         newTimeSeriesMetric(),
	}
}

// LatencyHistogram implementation

func newLatencyHistogram() *LatencyHistogram {
	// Define latency buckets: 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s, 10s, 30s, 60s
	buckets := []time.Duration{
		1 * time.Millisecond,
		5 * time.Millisecond,
		10 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		5 * time.Second,
		10 * time.Second,
		30 * time.Second,
		60 * time.Second,
	}
	
	return &LatencyHistogram{
		buckets: buckets,
		counts:  make([]int64, len(buckets)),
	}
}

func (h *LatencyHistogram) Record(duration time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	h.total++
	h.sum += duration
	
	// Find the appropriate bucket
	for i, bucket := range h.buckets {
		if duration <= bucket {
			h.counts[i]++
			return
		}
	}
	
	// If duration is larger than all buckets, count it in the last bucket
	if len(h.counts) > 0 {
		h.counts[len(h.counts)-1]++
	}
}

func (h *LatencyHistogram) Percentile(p float64) time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	if h.total == 0 {
		return 0
	}
	
	target := int64(float64(h.total) * p)
	var cumulative int64
	
	for i, count := range h.counts {
		cumulative += count
		if cumulative >= target {
			return h.buckets[i]
		}
	}
	
	// Return the largest bucket if we haven't found the percentile
	if len(h.buckets) > 0 {
		return h.buckets[len(h.buckets)-1]
	}
	
	return 0
}

func (h *LatencyHistogram) Average() time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	if h.total == 0 {
		return 0
	}
	
	return h.sum / time.Duration(h.total)
}

func (h *LatencyHistogram) Total() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.total
}

// ThroughputCounter implementation

func newThroughputCounter() *ThroughputCounter {
	return &ThroughputCounter{
		lastReset: time.Now(),
	}
}

func (t *ThroughputCounter) Increment() {
	atomic.AddInt64(&t.count, 1)
}

func (t *ThroughputCounter) Rate() float64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	
	elapsed := time.Since(t.lastReset)
	if elapsed == 0 {
		return 0
	}
	
	return float64(atomic.LoadInt64(&t.count)) / elapsed.Seconds()
}

func (t *ThroughputCounter) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	atomic.StoreInt64(&t.count, 0)
	t.lastReset = time.Now()
}

func (t *ThroughputCounter) Count() int64 {
	return atomic.LoadInt64(&t.count)
}

// ErrorCounter implementation

func newErrorCounter() *ErrorCounter {
	return &ErrorCounter{
		errorTypes: make(map[string]int64),
	}
}

func (e *ErrorCounter) Increment(errorType string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	atomic.AddInt64(&e.totalErrors, 1)
	e.errorTypes[errorType]++
}

func (e *ErrorCounter) Rate() float64 {
	// This would need a time window to calculate rate
	// For simplicity, return total errors
	return float64(atomic.LoadInt64(&e.totalErrors))
}

func (e *ErrorCounter) Total() int64 {
	return atomic.LoadInt64(&e.totalErrors)
}

func (e *ErrorCounter) ByType() map[string]int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	result := make(map[string]int64)
	for k, v := range e.errorTypes {
		result[k] = v
	}
	return result
}

// GaugeMetric implementation

func newGaugeMetric() *GaugeMetric {
	return &GaugeMetric{}
}

func (g *GaugeMetric) Set(value int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.value = value
}

func (g *GaugeMetric) Get() int64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.value
}

func (g *GaugeMetric) Add(delta int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.value += delta
}

// CounterMetric implementation

func newCounterMetric() *CounterMetric {
	return &CounterMetric{}
}

func (c *CounterMetric) Increment() {
	atomic.AddInt64(&c.value, 1)
}

func (c *CounterMetric) Add(delta int64) {
	atomic.AddInt64(&c.value, delta)
}

func (c *CounterMetric) Get() int64 {
	return atomic.LoadInt64(&c.value)
}

// ReplicationHistogram implementation

func newReplicationHistogram() *ReplicationHistogram {
	return &ReplicationHistogram{
		factors: make(map[int]int64),
	}
}

func (r *ReplicationHistogram) Record(factor int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factors[factor]++
}

func (r *ReplicationHistogram) Distribution() map[int]int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	result := make(map[int]int64)
	for k, v := range r.factors {
		result[k] = v
	}
	return result
}

func (r *ReplicationHistogram) Average() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var total, count int64
	for factor, freq := range r.factors {
		total += int64(factor) * freq
		count += freq
	}
	
	if count == 0 {
		return 0
	}
	
	return float64(total) / float64(count)
}

// SizeHistogram implementation

func newSizeHistogram() *SizeHistogram {
	// Define size buckets: 1KB, 10KB, 100KB, 1MB, 10MB, 100MB, 1GB, 10GB
	buckets := []int64{
		1024,           // 1KB
		10 * 1024,      // 10KB
		100 * 1024,     // 100KB
		1024 * 1024,    // 1MB
		10 * 1024 * 1024,   // 10MB
		100 * 1024 * 1024,  // 100MB
		1024 * 1024 * 1024, // 1GB
		10 * 1024 * 1024 * 1024, // 10GB
	}
	
	return &SizeHistogram{
		buckets: buckets,
		counts:  make([]int64, len(buckets)),
	}
}

func (s *SizeHistogram) Record(size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Find the appropriate bucket
	for i, bucket := range s.buckets {
		if size <= bucket {
			s.counts[i]++
			return
		}
	}
	
	// If size is larger than all buckets, count it in the last bucket
	if len(s.counts) > 0 {
		s.counts[len(s.counts)-1]++
	}
}

func (s *SizeHistogram) Distribution() map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	result := make(map[string]int64)
	labels := []string{"1KB", "10KB", "100KB", "1MB", "10MB", "100MB", "1GB", "10GB+"}
	
	for i, count := range s.counts {
		if i < len(labels) {
			result[labels[i]] = count
		}
	}
	
	return result
}

// TimeSeriesMetric implementation

func newTimeSeriesMetric() *TimeSeriesMetric {
	return &TimeSeriesMetric{
		points: make([]TimePoint, 0),
	}
}

func (t *TimeSeriesMetric) Record(value float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	point := TimePoint{
		Timestamp: time.Now(),
		Value:     value,
	}
	
	t.points = append(t.points, point)
	
	// Keep only recent points (last 24 hours for hourly, last 30 days for daily)
	cutoff := time.Now().Add(-24 * time.Hour)
	var filtered []TimePoint
	for _, p := range t.points {
		if p.Timestamp.After(cutoff) {
			filtered = append(filtered, p)
		}
	}
	t.points = filtered
}

func (t *TimeSeriesMetric) GetRecent(count int) []TimePoint {
	t.mu.RLock()
	defer t.mu.RUnlock()
	
	if len(t.points) <= count {
		result := make([]TimePoint, len(t.points))
		copy(result, t.points)
		return result
	}
	
	// Return the most recent points
	start := len(t.points) - count
	result := make([]TimePoint, count)
	copy(result, t.points[start:])
	return result
}

func (t *TimeSeriesMetric) GetRange(start, end time.Time) []TimePoint {
	t.mu.RLock()
	defer t.mu.RUnlock()
	
	var result []TimePoint
	for _, point := range t.points {
		if point.Timestamp.After(start) && point.Timestamp.Before(end) {
			result = append(result, point)
		}
	}
	
	return result
}

// UsageMetricsCollector methods

func (u *UsageMetricsCollector) recordObjectAccess(cid, s3Key, bucket, region string, latency time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	
	// Update object access metrics
	if metrics, exists := u.objectAccess[cid]; exists {
		metrics.AccessCount++
		metrics.LastAccess = time.Now()
		
		// Update average latency (simple moving average)
		if metrics.AverageLatency == 0 {
			metrics.AverageLatency = latency
		} else {
			metrics.AverageLatency = (metrics.AverageLatency + latency) / 2
		}
		
		// Update geographic access
		if metrics.GeographicAccess == nil {
			metrics.GeographicAccess = make(map[string]int64)
		}
		metrics.GeographicAccess[region]++
	} else {
		u.objectAccess[cid] = &ObjectAccessMetrics{
			CID:              cid,
			S3Key:            s3Key,
			Bucket:           bucket,
			AccessCount:      1,
			LastAccess:       time.Now(),
			AverageLatency:   latency,
			GeographicAccess: map[string]int64{region: 1},
			PeerAccess:       make(map[string]int64),
		}
	}
	
	// Update bucket access metrics
	if metrics, exists := u.bucketAccess[bucket]; exists {
		metrics.AccessCount++
		metrics.LastAccess = time.Now()
	} else {
		u.bucketAccess[bucket] = &BucketAccessMetrics{
			Bucket:      bucket,
			ObjectCount: 1,
			AccessCount: 1,
			LastAccess:  time.Now(),
		}
	}
	
	// Update geographic access metrics
	if metrics, exists := u.geographicAccess[region]; exists {
		metrics.AccessCount++
		// Update average latency
		if metrics.Latency == 0 {
			metrics.Latency = latency
		} else {
			metrics.Latency = (metrics.Latency + latency) / 2
		}
	} else {
		u.geographicAccess[region] = &GeographicAccessMetrics{
			Region:      region,
			AccessCount: 1,
			Latency:     latency,
		}
	}
	
	// Record in time series
	u.hourlyAccess.Record(1.0)
	u.dailyAccess.Record(1.0)
}

func (u *UsageMetricsCollector) cleanup(cutoff time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	
	// Clean up old object access records
	for cid, metrics := range u.objectAccess {
		if metrics.LastAccess.Before(cutoff) {
			delete(u.objectAccess, cid)
		}
	}
	
	// Clean up old bucket access records
	for bucket, metrics := range u.bucketAccess {
		if metrics.LastAccess.Before(cutoff) {
			delete(u.bucketAccess, bucket)
		}
	}
}

// Helper functions for sorting and analysis

func (u *UsageMetricsCollector) GetTopAccessedObjects(limit int) []*ObjectAccessMetrics {
	u.mu.RLock()
	defer u.mu.RUnlock()
	
	var objects []*ObjectAccessMetrics
	for _, metrics := range u.objectAccess {
		objects = append(objects, metrics)
	}
	
	// Sort by access count (descending)
	sort.Slice(objects, func(i, j int) bool {
		return objects[i].AccessCount > objects[j].AccessCount
	})
	
	if len(objects) > limit {
		objects = objects[:limit]
	}
	
	return objects
}

func (u *UsageMetricsCollector) GetBucketStats() []*BucketAccessMetrics {
	u.mu.RLock()
	defer u.mu.RUnlock()
	
	var buckets []*BucketAccessMetrics
	for _, metrics := range u.bucketAccess {
		buckets = append(buckets, metrics)
	}
	
	// Sort by access count (descending)
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].AccessCount > buckets[j].AccessCount
	})
	
	return buckets
}

func (u *UsageMetricsCollector) GetGeographicStats() []*GeographicAccessMetrics {
	u.mu.RLock()
	defer u.mu.RUnlock()
	
	var regions []*GeographicAccessMetrics
	for _, metrics := range u.geographicAccess {
		regions = append(regions, metrics)
	}
	
	// Sort by access count (descending)
	sort.Slice(regions, func(i, j int) bool {
		return regions[i].AccessCount > regions[j].AccessCount
	})
	
	return regions
}