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

	"github.com/versity/versitygw/metrics"
)

func TestIPFSMetricsManager(t *testing.T) {
	// Create test logger
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	
	// Create test configuration
	config := &MetricsConfig{
		PinMetricsInterval:      1 * time.Second,
		ClusterMetricsInterval:  2 * time.Second,
		UsageMetricsInterval:    3 * time.Second,
		MetricsRetentionPeriod:  1 * time.Hour,
		AlertsEnabled:           true,
		AlertCheckInterval:      1 * time.Second,
		DashboardEnabled:        false, // Disable for tests
		PrometheusEnabled:       false, // Disable for tests
	}
	
	// Create metrics manager
	manager, err := NewIPFSMetricsManager(nil, config, logger)
	if err != nil {
		t.Fatalf("Failed to create metrics manager: %v", err)
	}
	
	// Test basic functionality
	t.Run("RecordPinLatency", func(t *testing.T) {
		duration := 100 * time.Millisecond
		manager.RecordPinLatency(duration, true, PinPriorityNormal)
		
		// Verify metrics were recorded
		data := manager.GetDashboardData()
		if pinMetrics, ok := data["pin_metrics"].(map[string]interface{}); ok {
			if throughput, ok := pinMetrics["pin_throughput"].(float64); ok {
				if throughput <= 0 {
					t.Error("Expected pin throughput to be greater than 0")
				}
			} else {
				t.Error("Expected pin_throughput in metrics data")
			}
		} else {
			t.Error("Expected pin_metrics in dashboard data")
		}
	})
	
	t.Run("RecordClusterHealth", func(t *testing.T) {
		manager.RecordClusterHealth(8, 10, false)
		
		// Verify metrics were recorded
		data := manager.GetDashboardData()
		if clusterMetrics, ok := data["cluster_metrics"].(map[string]interface{}); ok {
			if healthyNodes, ok := clusterMetrics["healthy_nodes"].(int64); ok {
				if healthyNodes != 8 {
					t.Errorf("Expected 8 healthy nodes, got %d", healthyNodes)
				}
			} else {
				t.Error("Expected healthy_nodes in cluster metrics")
			}
		} else {
			t.Error("Expected cluster_metrics in dashboard data")
		}
	})
	
	t.Run("RecordObjectAccess", func(t *testing.T) {
		cid := "QmTest123"
		s3Key := "test/object.txt"
		bucket := "test-bucket"
		region := "us-east-1"
		latency := 50 * time.Millisecond
		
		manager.RecordObjectAccess(cid, s3Key, bucket, region, latency)
		
		// Verify usage metrics were updated
		data := manager.GetDashboardData()
		if usageMetrics, ok := data["usage_metrics"].(map[string]interface{}); ok {
			// Check that hourly access was recorded
			if hourlyAccess, ok := usageMetrics["hourly_access"].([]TimePoint); ok {
				if len(hourlyAccess) == 0 {
					t.Error("Expected hourly access data to be recorded")
				}
			}
		}
	})
}

func TestAlertManager(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	config := &MetricsConfig{
		AlertsEnabled:      true,
		AlertCheckInterval: 100 * time.Millisecond,
	}
	
	alertManager := newAlertManager(config, logger)
	
	t.Run("SplitBrainAlert", func(t *testing.T) {
		// Create metrics that should trigger split-brain alert
		metrics := map[string]interface{}{
			"cluster_metrics": map[string]interface{}{
				"split_brain_count": int64(1),
				"last_split_brain":  time.Now(),
			},
		}
		
		// Check alerts
		alertManager.CheckAlerts(metrics)
		
		// Verify alert was created
		activeAlerts := alertManager.GetActiveAlerts()
		if len(activeAlerts) == 0 {
			t.Error("Expected split-brain alert to be created")
		}
		
		found := false
		for _, alert := range activeAlerts {
			if alert.Rule.Name == "cluster_split_brain" {
				found = true
				if alert.Rule.Severity != AlertSeverityCritical {
					t.Error("Expected split-brain alert to be critical severity")
				}
				break
			}
		}
		
		if !found {
			t.Error("Expected to find cluster_split_brain alert")
		}
	})
	
	t.Run("HighPinFailureRateAlert", func(t *testing.T) {
		// Create metrics that should trigger high pin failure rate alert
		metrics := map[string]interface{}{
			"pin_metrics": map[string]interface{}{
				"pin_error_rate": 0.15, // 15% error rate, above 10% threshold
			},
		}
		
		// Check alerts
		alertManager.CheckAlerts(metrics)
		
		// Verify alert was created
		activeAlerts := alertManager.GetActiveAlerts()
		found := false
		for _, alert := range activeAlerts {
			if alert.Rule.Name == "high_pin_failure_rate" {
				found = true
				break
			}
		}
		
		if !found {
			t.Error("Expected to find high_pin_failure_rate alert")
		}
	})
	
	t.Run("AlertResolution", func(t *testing.T) {
		// First trigger an alert
		metrics := map[string]interface{}{
			"pin_metrics": map[string]interface{}{
				"pin_error_rate": 0.15, // High error rate
			},
		}
		
		alertManager.CheckAlerts(metrics)
		
		// Verify alert exists
		activeAlerts := alertManager.GetActiveAlerts()
		if len(activeAlerts) == 0 {
			t.Error("Expected alert to be active")
		}
		
		// Now provide metrics that should resolve the alert
		resolvedMetrics := map[string]interface{}{
			"pin_metrics": map[string]interface{}{
				"pin_error_rate": 0.05, // Low error rate
			},
		}
		
		alertManager.CheckAlerts(resolvedMetrics)
		
		// Verify alert was resolved
		activeAlertsAfter := alertManager.GetActiveAlerts()
		if len(activeAlertsAfter) >= len(activeAlerts) {
			t.Error("Expected alert to be resolved")
		}
	})
}

func TestMetricsTypes(t *testing.T) {
	t.Run("LatencyHistogram", func(t *testing.T) {
		histogram := newLatencyHistogram()
		
		// Record some latencies
		histogram.Record(5 * time.Millisecond)
		histogram.Record(15 * time.Millisecond)
		histogram.Record(25 * time.Millisecond)
		histogram.Record(100 * time.Millisecond)
		
		// Test percentiles
		p50 := histogram.Percentile(0.5)
		p95 := histogram.Percentile(0.95)
		
		if p50 == 0 {
			t.Error("Expected P50 to be greater than 0")
		}
		
		if p95 == 0 {
			t.Error("Expected P95 to be greater than 0")
		}
		
		if p95 < p50 {
			t.Error("Expected P95 to be greater than or equal to P50")
		}
		
		// Test average
		avg := histogram.Average()
		if avg == 0 {
			t.Error("Expected average to be greater than 0")
		}
		
		// Test total
		total := histogram.Total()
		if total != 4 {
			t.Errorf("Expected total count of 4, got %d", total)
		}
	})
	
	t.Run("ThroughputCounter", func(t *testing.T) {
		counter := newThroughputCounter()
		
		// Increment counter
		counter.Increment()
		counter.Increment()
		counter.Increment()
		
		// Test count
		count := counter.Count()
		if count != 3 {
			t.Errorf("Expected count of 3, got %d", count)
		}
		
		// Test rate (should be > 0 since we just incremented)
		rate := counter.Rate()
		if rate <= 0 {
			t.Error("Expected rate to be greater than 0")
		}
		
		// Test reset
		counter.Reset()
		countAfterReset := counter.Count()
		if countAfterReset != 0 {
			t.Errorf("Expected count to be 0 after reset, got %d", countAfterReset)
		}
	})
	
	t.Run("ErrorCounter", func(t *testing.T) {
		counter := newErrorCounter()
		
		// Increment different error types
		counter.Increment("timeout")
		counter.Increment("network")
		counter.Increment("timeout")
		
		// Test total
		total := counter.Total()
		if total != 3 {
			t.Errorf("Expected total of 3, got %d", total)
		}
		
		// Test by type
		byType := counter.ByType()
		if byType["timeout"] != 2 {
			t.Errorf("Expected 2 timeout errors, got %d", byType["timeout"])
		}
		if byType["network"] != 1 {
			t.Errorf("Expected 1 network error, got %d", byType["network"])
		}
	})
	
	t.Run("GaugeMetric", func(t *testing.T) {
		gauge := newGaugeMetric()
		
		// Test set
		gauge.Set(42)
		value := gauge.Get()
		if value != 42 {
			t.Errorf("Expected value of 42, got %d", value)
		}
		
		// Test add
		gauge.Add(8)
		value = gauge.Get()
		if value != 50 {
			t.Errorf("Expected value of 50, got %d", value)
		}
	})
	
	t.Run("ReplicationHistogram", func(t *testing.T) {
		histogram := newReplicationHistogram()
		
		// Record replication factors
		histogram.Record(3)
		histogram.Record(3)
		histogram.Record(5)
		histogram.Record(7)
		
		// Test distribution
		dist := histogram.Distribution()
		if dist[3] != 2 {
			t.Errorf("Expected 2 objects with replication factor 3, got %d", dist[3])
		}
		if dist[5] != 1 {
			t.Errorf("Expected 1 object with replication factor 5, got %d", dist[5])
		}
		
		// Test average
		avg := histogram.Average()
		expected := (3*2 + 5*1 + 7*1) / 4.0 // (6 + 5 + 7) / 4 = 4.5
		if avg != expected {
			t.Errorf("Expected average of %.1f, got %.1f", expected, avg)
		}
	})
}

func TestUsageMetricsCollector(t *testing.T) {
	collector := newUsageMetricsCollector()
	
	t.Run("RecordObjectAccess", func(t *testing.T) {
		cid := "QmTest123"
		s3Key := "test/object.txt"
		bucket := "test-bucket"
		region := "us-east-1"
		latency := 50 * time.Millisecond
		
		// Record access
		collector.recordObjectAccess(cid, s3Key, bucket, region, latency)
		
		// Verify object access was recorded
		collector.mu.RLock()
		objMetrics, exists := collector.objectAccess[cid]
		collector.mu.RUnlock()
		
		if !exists {
			t.Error("Expected object access to be recorded")
		}
		
		if objMetrics.AccessCount != 1 {
			t.Errorf("Expected access count of 1, got %d", objMetrics.AccessCount)
		}
		
		if objMetrics.S3Key != s3Key {
			t.Errorf("Expected S3 key %s, got %s", s3Key, objMetrics.S3Key)
		}
		
		if objMetrics.GeographicAccess[region] != 1 {
			t.Errorf("Expected 1 access from region %s, got %d", region, objMetrics.GeographicAccess[region])
		}
	})
	
	t.Run("GetTopAccessedObjects", func(t *testing.T) {
		// Record multiple accesses
		collector.recordObjectAccess("QmTest1", "test1.txt", "bucket1", "us-east-1", 10*time.Millisecond)
		collector.recordObjectAccess("QmTest1", "test1.txt", "bucket1", "us-east-1", 10*time.Millisecond)
		collector.recordObjectAccess("QmTest1", "test1.txt", "bucket1", "us-east-1", 10*time.Millisecond)
		collector.recordObjectAccess("QmTest2", "test2.txt", "bucket1", "us-east-1", 10*time.Millisecond)
		
		// Get top accessed objects
		topObjects := collector.GetTopAccessedObjects(2)
		
		if len(topObjects) != 2 {
			t.Errorf("Expected 2 top objects, got %d", len(topObjects))
		}
		
		// First object should have highest access count
		if topObjects[0].AccessCount < topObjects[1].AccessCount {
			t.Error("Expected objects to be sorted by access count (descending)")
		}
	})
}

func TestDashboardServer(t *testing.T) {
	// Create test metrics manager
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	config := &MetricsConfig{
		DashboardEnabled: true,
		DashboardPort:    8081, // Use different port for tests
	}
	
	metricsManager, err := NewIPFSMetricsManager(nil, config, logger)
	if err != nil {
		t.Fatalf("Failed to create metrics manager: %v", err)
	}
	
	// Create dashboard server
	dashboard := NewDashboardServer(metricsManager, 8081, logger)
	
	t.Run("CreateDashboard", func(t *testing.T) {
		if dashboard == nil {
			t.Error("Expected dashboard to be created")
		}
		
		if dashboard.server == nil {
			t.Error("Expected HTTP server to be created")
		}
	})
	
	t.Run("GetDashboardData", func(t *testing.T) {
		// Record some test data
		metricsManager.RecordPinLatency(100*time.Millisecond, true, PinPriorityNormal)
		metricsManager.RecordClusterHealth(8, 10, false)
		
		// Get dashboard data
		data := dashboard.getDashboardData()
		
		if data == nil {
			t.Error("Expected dashboard data to be returned")
		}
		
		if data.Timestamp.IsZero() {
			t.Error("Expected timestamp to be set")
		}
		
		if data.SystemInfo == nil {
			t.Error("Expected system info to be included")
		}
	})
}

func TestEnhancedMetricsManager(t *testing.T) {
	// Create mock VersityGW metrics manager
	ctx := context.Background()
	versityConfig := metrics.Config{
		ServiceName: "test-service",
	}
	
	versityManager, err := metrics.NewManager(ctx, versityConfig)
	if err != nil && versityManager != nil {
		// Only test if we can create the manager
		t.Skip("Skipping VersityGW integration test - no metrics endpoints configured")
	}
	
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	config := &MetricsConfig{
		PinMetricsInterval: 1 * time.Second,
		AlertsEnabled:      true,
	}
	
	// Create enhanced metrics manager
	enhanced, err := NewEnhancedIPFSMetricsManager(versityManager, config, logger)
	if err != nil {
		t.Fatalf("Failed to create enhanced metrics manager: %v", err)
	}
	
	t.Run("RecordPinLatencyWithIntegration", func(t *testing.T) {
		duration := 100 * time.Millisecond
		cid := "QmTest123"
		
		// This should record in both internal metrics and VersityGW metrics
		enhanced.RecordPinLatency(duration, true, PinPriorityNormal, cid)
		
		// Verify internal metrics were recorded
		data := enhanced.GetDashboardData()
		if pinMetrics, ok := data["pin_metrics"].(map[string]interface{}); ok {
			if throughput, ok := pinMetrics["pin_throughput"].(float64); ok {
				if throughput <= 0 {
					t.Error("Expected pin throughput to be greater than 0")
				}
			}
		}
		
		// VersityGW metrics recording would be tested with actual metrics endpoints
	})
}

// Benchmark tests for performance validation

func BenchmarkPinLatencyRecording(b *testing.B) {
	logger := log.New(os.Stdout, "[BENCH] ", log.LstdFlags)
	config := &MetricsConfig{
		AlertsEnabled: false, // Disable alerts for benchmarking
	}
	
	manager, err := NewIPFSMetricsManager(nil, config, logger)
	if err != nil {
		b.Fatalf("Failed to create metrics manager: %v", err)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		duration := time.Duration(i%1000) * time.Millisecond
		manager.RecordPinLatency(duration, true, PinPriorityNormal)
	}
}

func BenchmarkObjectAccessRecording(b *testing.B) {
	logger := log.New(os.Stdout, "[BENCH] ", log.LstdFlags)
	config := &MetricsConfig{
		AlertsEnabled: false,
	}
	
	manager, err := NewIPFSMetricsManager(nil, config, logger)
	if err != nil {
		b.Fatalf("Failed to create metrics manager: %v", err)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		cid := "QmTest" + string(rune(i%1000))
		s3Key := "test/object" + string(rune(i%1000)) + ".txt"
		bucket := "test-bucket"
		region := "us-east-1"
		latency := time.Duration(i%100) * time.Millisecond
		
		manager.RecordObjectAccess(cid, s3Key, bucket, region, latency)
	}
}

func BenchmarkAlertChecking(b *testing.B) {
	logger := log.New(os.Stdout, "[BENCH] ", log.LstdFlags)
	config := &MetricsConfig{
		AlertsEnabled: true,
	}
	
	alertManager := newAlertManager(config, logger)
	
	// Create test metrics
	testMetrics := map[string]interface{}{
		"pin_metrics": map[string]interface{}{
			"pin_error_rate":   0.05,
			"pin_latency_p95":  50 * time.Millisecond,
			"queue_depth":      int64(500),
		},
		"cluster_metrics": map[string]interface{}{
			"healthy_nodes":     int64(8),
			"total_nodes":       int64(10),
			"split_brain_count": int64(0),
		},
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		alertManager.CheckAlerts(testMetrics)
	}
}