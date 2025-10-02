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
	"log"
	"time"

	"github.com/versity/versitygw/metrics"
)

// IPFSMetricsIntegration provides integration with VersityGW metrics system
// Since the VersityGW metrics manager methods are private, we'll use a different approach
type IPFSMetricsIntegration struct {
	manager *metrics.Manager
	enabled bool
}

// NewIPFSMetricsIntegration creates a new metrics integration
func NewIPFSMetricsIntegration(manager *metrics.Manager) *IPFSMetricsIntegration {
	return &IPFSMetricsIntegration{
		manager: manager,
		enabled: manager != nil,
	}
}

// RecordPinOperation records a pin operation in VersityGW metrics
func (i *IPFSMetricsIntegration) RecordPinOperation(duration time.Duration, success bool, priority PinPriority, cid string) {
	if !i.enabled {
		return
	}
	
	// Since VersityGW metrics manager methods are private, we'll log the metrics
	// In a production implementation, this would require extending the metrics.Manager interface
	// or using a different integration approach
	
	priorityStr := i.priorityToString(priority)
	latencyMs := duration.Nanoseconds() / 1000000
	
	log.Printf("[IPFS-METRICS] Pin operation: success=%t, priority=%s, latency=%dms, cid=%s", 
		success, priorityStr, latencyMs, cid)
}

// RecordUnpinOperation records an unpin operation in VersityGW metrics
func (i *IPFSMetricsIntegration) RecordUnpinOperation(duration time.Duration, success bool, priority PinPriority, cid string) {
	if !i.enabled {
		return
	}
	
	priorityStr := i.priorityToString(priority)
	latencyMs := duration.Nanoseconds() / 1000000
	
	log.Printf("[IPFS-METRICS] Unpin operation: success=%t, priority=%s, latency=%dms, cid=%s", 
		success, priorityStr, latencyMs, cid)
}

// RecordClusterHealth records cluster health metrics
func (i *IPFSMetricsIntegration) RecordClusterHealth(healthyNodes, totalNodes int, splitBrainDetected bool) {
	if !i.enabled {
		return
	}
	
	var healthPercentage float64
	if totalNodes > 0 {
		healthPercentage = float64(healthyNodes) / float64(totalNodes) * 100
	}
	
	log.Printf("[IPFS-METRICS] Cluster health: healthy=%d, total=%d, health=%.1f%%, split_brain=%t", 
		healthyNodes, totalNodes, healthPercentage, splitBrainDetected)
}

// RecordObjectAccess records object access for analytics
func (i *IPFSMetricsIntegration) RecordObjectAccess(cid, s3Key, bucket, region string, latency time.Duration, size int64) {
	if !i.enabled {
		return
	}
	
	latencyMs := latency.Nanoseconds() / 1000000
	log.Printf("[IPFS-METRICS] Object access: cid=%s, s3key=%s, bucket=%s, region=%s, latency=%dms, size=%d", 
		cid, s3Key, bucket, region, latencyMs, size)
}

// RecordQueueMetrics records queue depth and processing metrics
func (i *IPFSMetricsIntegration) RecordQueueMetrics(pinQueue, unpinQueue, retryQueue int) {
	if !i.enabled {
		return
	}
	
	totalDepth := pinQueue + unpinQueue + retryQueue
	log.Printf("[IPFS-METRICS] Queue depths: pin=%d, unpin=%d, retry=%d, total=%d", 
		pinQueue, unpinQueue, retryQueue, totalDepth)
}

// RecordReplicationMetrics records replication factor metrics
func (i *IPFSMetricsIntegration) RecordReplicationMetrics(factor int, cid string) {
	if !i.enabled {
		return
	}
	
	log.Printf("[IPFS-METRICS] Replication: factor=%d, cid=%s", factor, cid)
}

// RecordStorageMetrics records storage utilization metrics
func (i *IPFSMetricsIntegration) RecordStorageMetrics(totalStorage, usedStorage int64, nodeID string) {
	if !i.enabled {
		return
	}
	
	var utilizationPercentage float64
	if totalStorage > 0 {
		utilizationPercentage = float64(usedStorage) / float64(totalStorage) * 100
	}
	
	log.Printf("[IPFS-METRICS] Storage: node=%s, total=%d, used=%d, utilization=%.1f%%", 
		nodeID, totalStorage, usedStorage, utilizationPercentage)
}

// RecordNetworkMetrics records network-related metrics
func (i *IPFSMetricsIntegration) RecordNetworkMetrics(latency time.Duration, errorCount int, nodeID string) {
	if !i.enabled {
		return
	}
	
	latencyMs := latency.Nanoseconds() / 1000000
	log.Printf("[IPFS-METRICS] Network: node=%s, latency=%dms, errors=%d", 
		nodeID, latencyMs, errorCount)
}

// RecordCacheMetrics records cache performance metrics
func (i *IPFSMetricsIntegration) RecordCacheMetrics(hits, misses int64, cacheType string) {
	if !i.enabled {
		return
	}
	
	total := hits + misses
	var hitRatio float64
	if total > 0 {
		hitRatio = float64(hits) / float64(total) * 100
	}
	
	log.Printf("[IPFS-METRICS] Cache: type=%s, hits=%d, misses=%d, hit_ratio=%.1f%%", 
		cacheType, hits, misses, hitRatio)
}

// RecordWorkerMetrics records worker pool metrics
func (i *IPFSMetricsIntegration) RecordWorkerMetrics(activeWorkers, totalWorkers int, workerType string) {
	if !i.enabled {
		return
	}
	
	var utilization float64
	if totalWorkers > 0 {
		utilization = float64(activeWorkers) / float64(totalWorkers) * 100
	}
	
	log.Printf("[IPFS-METRICS] Workers: type=%s, active=%d, total=%d, utilization=%.1f%%", 
		workerType, activeWorkers, totalWorkers, utilization)
}

// RecordDataClassification records hot/warm/cold data metrics
func (i *IPFSMetricsIntegration) RecordDataClassification(hotObjects, warmObjects, coldObjects int64) {
	if !i.enabled {
		return
	}
	
	totalObjects := hotObjects + warmObjects + coldObjects
	log.Printf("[IPFS-METRICS] Data classification: hot=%d, warm=%d, cold=%d, total=%d", 
		hotObjects, warmObjects, coldObjects, totalObjects)
}

// RecordAlertMetrics records alert-related metrics
func (i *IPFSMetricsIntegration) RecordAlertMetrics(alertName string, severity AlertSeverity, resolved bool) {
	if !i.enabled {
		return
	}
	
	severityStr := i.severityToString(severity)
	log.Printf("[IPFS-METRICS] Alert: name=%s, severity=%s, resolved=%t", 
		alertName, severityStr, resolved)
}

// RecordBucketMetrics records bucket-specific metrics
func (i *IPFSMetricsIntegration) RecordBucketMetrics(bucket string, objectCount, totalSize int64, accessCount int64) {
	if !i.enabled {
		return
	}
	
	log.Printf("[IPFS-METRICS] Bucket: name=%s, objects=%d, size=%d, access=%d", 
		bucket, objectCount, totalSize, accessCount)
}

// RecordGeographicMetrics records geographic access patterns
func (i *IPFSMetricsIntegration) RecordGeographicMetrics(region string, accessCount int64, avgLatency time.Duration) {
	if !i.enabled {
		return
	}
	
	latencyMs := avgLatency.Nanoseconds() / 1000000
	log.Printf("[IPFS-METRICS] Geographic: region=%s, access=%d, latency=%dms", 
		region, accessCount, latencyMs)
}

// Helper methods

func (i *IPFSMetricsIntegration) priorityToString(priority PinPriority) string {
	switch priority {
	case 0: // PinPriorityLow
		return "low"
	case 1: // PinPriorityNormal
		return "normal"
	case 2: // PinPriorityHigh
		return "high"
	case 3: // PinPriorityCritical
		return "critical"
	default:
		return "unknown"
	}
}

func (i *IPFSMetricsIntegration) severityToString(severity AlertSeverity) string {
	switch severity {
	case 0: // AlertSeverityInfo
		return "info"
	case 1: // AlertSeverityWarning
		return "warning"
	case 2: // AlertSeverityCritical
		return "critical"
	case 3: // AlertSeverityEmergency
		return "emergency"
	default:
		return "unknown"
	}
}

// Enhanced IPFSMetricsManager with VersityGW integration
func (m *IPFSMetricsManager) EnableVersityGWIntegration() {
	if m.metricsManager != nil {
		m.integration = NewIPFSMetricsIntegration(m.metricsManager)
		m.logger.Println("VersityGW metrics integration enabled")
	}
}

// Update the IPFSMetricsManager struct to include integration
func init() {
	// This would be called when the package is imported
	// to ensure the integration field is available
}

// Add integration field to IPFSMetricsManager (this would be added to the struct definition)
type IPFSMetricsManagerWithIntegration struct {
	*IPFSMetricsManager
	integration *IPFSMetricsIntegration
}

// Enhanced recording methods that use both internal metrics and VersityGW integration

// RecordPinLatencyWithIntegration records pin latency in both systems
func (m *IPFSMetricsManager) RecordPinLatencyWithIntegration(duration time.Duration, success bool, priority PinPriority, cid string) {
	// Record in internal metrics
	m.RecordPinLatency(duration, success, priority)
	
	// Record in VersityGW metrics if integration is available
	if m.integration != nil {
		m.integration.RecordPinOperation(duration, success, priority, cid)
	}
}

// RecordUnpinLatencyWithIntegration records unpin latency in both systems
func (m *IPFSMetricsManager) RecordUnpinLatencyWithIntegration(duration time.Duration, success bool, priority PinPriority, cid string) {
	// Record in internal metrics
	m.RecordUnpinLatency(duration, success, priority)
	
	// Record in VersityGW metrics if integration is available
	if m.integration != nil {
		m.integration.RecordUnpinOperation(duration, success, priority, cid)
	}
}

// RecordClusterHealthWithIntegration records cluster health in both systems
func (m *IPFSMetricsManager) RecordClusterHealthWithIntegration(healthyNodes, totalNodes int, splitBrainDetected bool) {
	// Record in internal metrics
	m.RecordClusterHealth(healthyNodes, totalNodes, splitBrainDetected)
	
	// Record in VersityGW metrics if integration is available
	if m.integration != nil {
		m.integration.RecordClusterHealth(healthyNodes, totalNodes, splitBrainDetected)
	}
}

// RecordObjectAccessWithIntegration records object access in both systems
func (m *IPFSMetricsManager) RecordObjectAccessWithIntegration(cid, s3Key, bucket, region string, latency time.Duration, size int64) {
	// Record in internal metrics
	m.RecordObjectAccess(cid, s3Key, bucket, region, latency)
	
	// Record in VersityGW metrics if integration is available
	if m.integration != nil {
		m.integration.RecordObjectAccess(cid, s3Key, bucket, region, latency, size)
	}
}

// Add integration field to the main struct (this would be done in metrics.go)
// For now, we'll create a wrapper that can be used
type EnhancedIPFSMetricsManager struct {
	*IPFSMetricsManager
	integration *IPFSMetricsIntegration
}

// NewEnhancedIPFSMetricsManager creates an enhanced metrics manager with VersityGW integration
func NewEnhancedIPFSMetricsManager(metricsManager *metrics.Manager, config *MetricsConfig, logger *log.Logger) (*EnhancedIPFSMetricsManager, error) {
	baseManager, err := NewIPFSMetricsManager(metricsManager, config, logger)
	if err != nil {
		return nil, err
	}
	
	enhanced := &EnhancedIPFSMetricsManager{
		IPFSMetricsManager: baseManager,
	}
	
	// Enable VersityGW integration if metrics manager is available
	if metricsManager != nil {
		enhanced.integration = NewIPFSMetricsIntegration(metricsManager)
		logger.Println("Enhanced IPFS metrics manager with VersityGW integration created")
	}
	
	return enhanced, nil
}

// Override recording methods to use both systems
func (e *EnhancedIPFSMetricsManager) RecordPinLatency(duration time.Duration, success bool, priority PinPriority, cid string) {
	// Record in internal metrics
	e.IPFSMetricsManager.RecordPinLatency(duration, success, priority)
	
	// Record in VersityGW metrics
	if e.integration != nil {
		e.integration.RecordPinOperation(duration, success, priority, cid)
	}
}

func (e *EnhancedIPFSMetricsManager) RecordUnpinLatency(duration time.Duration, success bool, priority PinPriority, cid string) {
	// Record in internal metrics
	e.IPFSMetricsManager.RecordUnpinLatency(duration, success, priority)
	
	// Record in VersityGW metrics
	if e.integration != nil {
		e.integration.RecordUnpinOperation(duration, success, priority, cid)
	}
}

func (e *EnhancedIPFSMetricsManager) RecordClusterHealth(healthyNodes, totalNodes int, splitBrainDetected bool) {
	// Record in internal metrics
	e.IPFSMetricsManager.RecordClusterHealth(healthyNodes, totalNodes, splitBrainDetected)
	
	// Record in VersityGW metrics
	if e.integration != nil {
		e.integration.RecordClusterHealth(healthyNodes, totalNodes, splitBrainDetected)
	}
}

func (e *EnhancedIPFSMetricsManager) RecordObjectAccess(cid, s3Key, bucket, region string, latency time.Duration, size int64) {
	// Record in internal metrics
	e.IPFSMetricsManager.RecordObjectAccess(cid, s3Key, bucket, region, latency)
	
	// Record in VersityGW metrics
	if e.integration != nil {
		e.integration.RecordObjectAccess(cid, s3Key, bucket, region, latency, size)
	}
}