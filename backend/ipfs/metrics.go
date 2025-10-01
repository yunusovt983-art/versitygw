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
	"sync"
	"time"

	"github.com/versity/versitygw/metrics"
)

// IPFSMetricsManager manages IPFS-specific metrics and integrates with VersityGW metrics system
type IPFSMetricsManager struct {
	// Core metrics manager from VersityGW
	metricsManager *metrics.Manager
	
	// IPFS-specific metrics
	pinMetrics     *PinMetricsCollector
	clusterMetrics *ClusterMetricsCollector
	usageMetrics   *UsageMetricsCollector
	alertManager   *AlertManager
	
	// VersityGW integration
	integration    *IPFSMetricsIntegration
	
	// Configuration
	config *MetricsConfig
	
	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// State
	running bool
	mu      sync.RWMutex
	
	// Logging
	logger *log.Logger
}

// MetricsConfig holds configuration for IPFS metrics
type MetricsConfig struct {
	// Collection intervals
	PinMetricsInterval     time.Duration `json:"pin_metrics_interval"`
	ClusterMetricsInterval time.Duration `json:"cluster_metrics_interval"`
	UsageMetricsInterval   time.Duration `json:"usage_metrics_interval"`
	
	// Retention settings
	MetricsRetentionPeriod time.Duration `json:"metrics_retention_period"`
	
	// Alert settings
	AlertsEnabled          bool          `json:"alerts_enabled"`
	AlertCheckInterval     time.Duration `json:"alert_check_interval"`
	
	// Dashboard settings
	DashboardEnabled       bool   `json:"dashboard_enabled"`
	DashboardPort          int    `json:"dashboard_port"`
	DashboardUpdateInterval time.Duration `json:"dashboard_update_interval"`
	
	// Export settings
	PrometheusEnabled      bool   `json:"prometheus_enabled"`
	PrometheusPort         int    `json:"prometheus_port"`
	PrometheusPath         string `json:"prometheus_path"`
}

// PinMetricsCollector collects pin-related metrics
type PinMetricsCollector struct {
	// Latency metrics
	pinLatencyHistogram   *LatencyHistogram
	unpinLatencyHistogram *LatencyHistogram
	
	// Throughput metrics
	pinThroughput   *ThroughputCounter
	unpinThroughput *ThroughputCounter
	
	// Error metrics
	pinErrors   *ErrorCounter
	unpinErrors *ErrorCounter
	
	// Queue metrics
	queueDepth *GaugeMetric
	
	// Replication metrics
	replicationFactorHistogram *ReplicationHistogram
	
	mu sync.RWMutex
}

// ClusterMetricsCollector collects cluster health metrics
type ClusterMetricsCollector struct {
	// Node health metrics
	healthyNodes   *GaugeMetric
	unhealthyNodes *GaugeMetric
	totalNodes     *GaugeMetric
	
	// Cluster split detection
	splitBrainDetected *CounterMetric
	lastSplitBrain     time.Time
	
	// Network metrics
	networkLatency *LatencyHistogram
	networkErrors  *ErrorCounter
	
	// Storage metrics
	totalStorage *GaugeMetric
	usedStorage  *GaugeMetric
	
	mu sync.RWMutex
}

// UsageMetricsCollector collects object usage analytics
type UsageMetricsCollector struct {
	// Access patterns
	objectAccess     map[string]*ObjectAccessMetrics
	bucketAccess     map[string]*BucketAccessMetrics
	geographicAccess map[string]*GeographicAccessMetrics
	
	// Hot/warm/cold data classification
	hotDataObjects  *GaugeMetric
	warmDataObjects *GaugeMetric
	coldDataObjects *GaugeMetric
	
	// Size distribution
	objectSizeHistogram *SizeHistogram
	
	// Temporal patterns
	hourlyAccess *TimeSeriesMetric
	dailyAccess  *TimeSeriesMetric
	
	mu sync.RWMutex
}

// AlertManager manages alerts for critical situations
type AlertManager struct {
	// Alert rules
	rules []AlertRule
	
	// Active alerts
	activeAlerts map[string]*Alert
	
	// Alert history
	alertHistory []*Alert
	
	// Notification channels
	notificationChannels []NotificationChannel
	
	mu sync.RWMutex
}

// Supporting metric types

// LatencyHistogram tracks latency distribution
type LatencyHistogram struct {
	buckets []time.Duration
	counts  []int64
	total   int64
	sum     time.Duration
	mu      sync.RWMutex
}

// ThroughputCounter tracks operations per second
type ThroughputCounter struct {
	count     int64
	lastReset time.Time
	mu        sync.RWMutex
}

// ErrorCounter tracks error rates and types
type ErrorCounter struct {
	totalErrors int64
	errorTypes  map[string]int64
	mu          sync.RWMutex
}

// GaugeMetric tracks current values
type GaugeMetric struct {
	value int64
	mu    sync.RWMutex
}

// CounterMetric tracks cumulative counts
type CounterMetric struct {
	value int64
}

// ReplicationHistogram tracks replication factor distribution
type ReplicationHistogram struct {
	factors map[int]int64
	mu      sync.RWMutex
}

// SizeHistogram tracks object size distribution
type SizeHistogram struct {
	buckets []int64
	counts  []int64
	mu      sync.RWMutex
}

// TimeSeriesMetric tracks values over time
type TimeSeriesMetric struct {
	points []TimePoint
	mu     sync.RWMutex
}

// TimePoint represents a point in time series
type TimePoint struct {
	Timestamp time.Time
	Value     float64
}

// ObjectAccessMetrics tracks access patterns for individual objects
type ObjectAccessMetrics struct {
	CID           string
	S3Key         string
	Bucket        string
	AccessCount   int64
	LastAccess    time.Time
	AverageLatency time.Duration
	GeographicAccess map[string]int64
	PeerAccess    map[string]int64
}

// BucketAccessMetrics tracks access patterns for buckets
type BucketAccessMetrics struct {
	Bucket       string
	ObjectCount  int64
	TotalSize    int64
	AccessCount  int64
	LastAccess   time.Time
	HotObjects   int64
	WarmObjects  int64
	ColdObjects  int64
}

// GeographicAccessMetrics tracks geographic access patterns
type GeographicAccessMetrics struct {
	Region      string
	AccessCount int64
	Latency     time.Duration
	Bandwidth   float64
}

// Alert types

// AlertRule defines conditions for triggering alerts
type AlertRule struct {
	Name        string
	Description string
	Condition   AlertCondition
	Severity    AlertSeverity
	Cooldown    time.Duration
	LastFired   time.Time
}

// AlertCondition defines the condition for an alert
type AlertCondition interface {
	Evaluate(metrics map[string]interface{}) bool
	String() string
}

// AlertSeverity defines alert severity levels
type AlertSeverity int

const (
	AlertSeverityInfo AlertSeverity = iota
	AlertSeverityWarning
	AlertSeverityCritical
	AlertSeverityEmergency
)

// Alert represents an active or historical alert
type Alert struct {
	ID          string
	Rule        *AlertRule
	Timestamp   time.Time
	Resolved    bool
	ResolvedAt  time.Time
	Message     string
	Metadata    map[string]interface{}
}

// NotificationChannel defines how alerts are delivered
type NotificationChannel interface {
	SendAlert(alert *Alert) error
	Name() string
}

// NewIPFSMetricsManager creates a new IPFS metrics manager
func NewIPFSMetricsManager(metricsManager *metrics.Manager, config *MetricsConfig, logger *log.Logger) (*IPFSMetricsManager, error) {
	if config == nil {
		config = getDefaultMetricsConfig()
	}
	
	if logger == nil {
		logger = log.Default()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &IPFSMetricsManager{
		metricsManager: metricsManager,
		config:         config,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
	}
	
	// Initialize collectors
	manager.pinMetrics = newPinMetricsCollector()
	manager.clusterMetrics = newClusterMetricsCollector()
	manager.usageMetrics = newUsageMetricsCollector()
	
	// Initialize alert manager if enabled
	if config.AlertsEnabled {
		manager.alertManager = newAlertManager(config, logger)
	}
	
	// Enable VersityGW integration if metrics manager is available
	if metricsManager != nil {
		manager.integration = NewIPFSMetricsIntegration(metricsManager)
		logger.Println("IPFS metrics manager initialized with VersityGW integration")
	} else {
		logger.Println("IPFS metrics manager initialized without VersityGW integration")
	}
	
	return manager, nil
}

// getDefaultMetricsConfig returns default metrics configuration
func getDefaultMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		PinMetricsInterval:      30 * time.Second,
		ClusterMetricsInterval:  1 * time.Minute,
		UsageMetricsInterval:    5 * time.Minute,
		MetricsRetentionPeriod:  24 * time.Hour,
		AlertsEnabled:           true,
		AlertCheckInterval:      30 * time.Second,
		DashboardEnabled:        true,
		DashboardPort:           8080,
		DashboardUpdateInterval: 10 * time.Second,
		PrometheusEnabled:       false,
		PrometheusPort:          9090,
		PrometheusPath:          "/metrics",
	}
}

// Start starts the metrics collection
func (m *IPFSMetricsManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.running {
		return fmt.Errorf("metrics manager is already running")
	}
	
	m.logger.Println("Starting IPFS metrics collection...")
	
	// Start pin metrics collection
	m.wg.Add(1)
	go m.collectPinMetrics()
	
	// Start cluster metrics collection
	m.wg.Add(1)
	go m.collectClusterMetrics()
	
	// Start usage metrics collection
	m.wg.Add(1)
	go m.collectUsageMetrics()
	
	// Start alert checking if enabled
	if m.config.AlertsEnabled && m.alertManager != nil {
		m.wg.Add(1)
		go m.checkAlerts()
	}
	
	// Start dashboard if enabled
	if m.config.DashboardEnabled {
		m.wg.Add(1)
		go m.runDashboard()
	}
	
	// Start Prometheus exporter if enabled
	if m.config.PrometheusEnabled {
		m.wg.Add(1)
		go m.runPrometheusExporter()
	}
	
	m.running = true
	m.logger.Println("IPFS metrics collection started")
	
	return nil
}

// Stop stops the metrics collection
func (m *IPFSMetricsManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if !m.running {
		return fmt.Errorf("metrics manager is not running")
	}
	
	m.logger.Println("Stopping IPFS metrics collection...")
	
	// Cancel context to stop all goroutines
	m.cancel()
	
	// Wait for all goroutines to finish
	m.wg.Wait()
	
	m.running = false
	m.logger.Println("IPFS metrics collection stopped")
	
	return nil
}

// RecordPinLatency records pin operation latency
func (m *IPFSMetricsManager) RecordPinLatency(duration time.Duration, success bool, priority PinPriority) {
	// Record in internal histogram
	if m.pinMetrics != nil {
		m.pinMetrics.pinLatencyHistogram.Record(duration)
		if success {
			m.pinMetrics.pinThroughput.Increment()
		} else {
			m.pinMetrics.pinErrors.Increment("pin_failed")
		}
	}
	
	// Record in VersityGW metrics if integration is available
	if m.integration != nil {
		m.integration.RecordPinOperation(duration, success, priority, "")
	}
}

// RecordUnpinLatency records unpin operation latency
func (m *IPFSMetricsManager) RecordUnpinLatency(duration time.Duration, success bool, priority PinPriority) {
	// Record in internal histogram
	if m.pinMetrics != nil {
		m.pinMetrics.unpinLatencyHistogram.Record(duration)
		if success {
			m.pinMetrics.unpinThroughput.Increment()
		} else {
			m.pinMetrics.unpinErrors.Increment("unpin_failed")
		}
	}
	
	// Record in VersityGW metrics if integration is available
	if m.integration != nil {
		m.integration.RecordUnpinOperation(duration, success, priority, "")
	}
}

// RecordClusterHealth records cluster health metrics
func (m *IPFSMetricsManager) RecordClusterHealth(healthyNodes, totalNodes int, splitBrainDetected bool) {
	// Record in internal metrics
	if m.clusterMetrics != nil {
		m.clusterMetrics.healthyNodes.Set(int64(healthyNodes))
		m.clusterMetrics.totalNodes.Set(int64(totalNodes))
		m.clusterMetrics.unhealthyNodes.Set(int64(totalNodes - healthyNodes))
		
		if splitBrainDetected {
			m.clusterMetrics.splitBrainDetected.Increment()
			m.clusterMetrics.lastSplitBrain = time.Now()
		}
	}
	
	// Record in VersityGW metrics if integration is available
	if m.integration != nil {
		m.integration.RecordClusterHealth(healthyNodes, totalNodes, splitBrainDetected)
	}
}

// RecordObjectAccess records object access for analytics
func (m *IPFSMetricsManager) RecordObjectAccess(cid, s3Key, bucket, region string, latency time.Duration) {
	// Record in usage metrics
	if m.usageMetrics != nil {
		m.usageMetrics.recordObjectAccess(cid, s3Key, bucket, region, latency)
	}
	
	// Record in VersityGW metrics if integration is available
	if m.integration != nil {
		m.integration.RecordObjectAccess(cid, s3Key, bucket, region, latency, 0) // Size would need to be passed in
	}
}

// RecordQueueDepth records current queue depths
func (m *IPFSMetricsManager) RecordQueueDepth(pinQueue, unpinQueue, retryQueue int) {
	// Record total queue depth
	if m.pinMetrics != nil {
		totalDepth := pinQueue + unpinQueue + retryQueue
		m.pinMetrics.queueDepth.Set(int64(totalDepth))
	}
	
	// Record in VersityGW metrics if integration is available
	if m.integration != nil {
		m.integration.RecordQueueMetrics(pinQueue, unpinQueue, retryQueue)
	}
}

// RecordReplicationFactor records replication factor distribution
func (m *IPFSMetricsManager) RecordReplicationFactor(factor int, cid string) {
	// Record in internal histogram
	if m.pinMetrics != nil {
		m.pinMetrics.replicationFactorHistogram.Record(factor)
	}
	
	// Record in VersityGW metrics if integration is available
	if m.integration != nil {
		m.integration.RecordReplicationMetrics(factor, cid)
	}
}

// GetDashboardData returns data for the monitoring dashboard
func (m *IPFSMetricsManager) GetDashboardData() map[string]interface{} {
	data := make(map[string]interface{})
	
	// Pin metrics
	if m.pinMetrics != nil {
		data["pin_metrics"] = map[string]interface{}{
			"pin_latency_p50":    m.pinMetrics.pinLatencyHistogram.Percentile(0.5),
			"pin_latency_p95":    m.pinMetrics.pinLatencyHistogram.Percentile(0.95),
			"pin_latency_p99":    m.pinMetrics.pinLatencyHistogram.Percentile(0.99),
			"pin_throughput":     m.pinMetrics.pinThroughput.Rate(),
			"unpin_throughput":   m.pinMetrics.unpinThroughput.Rate(),
			"pin_error_rate":     m.pinMetrics.pinErrors.Rate(),
			"unpin_error_rate":   m.pinMetrics.unpinErrors.Rate(),
			"queue_depth":        m.pinMetrics.queueDepth.Get(),
		}
	}
	
	// Cluster metrics
	if m.clusterMetrics != nil {
		data["cluster_metrics"] = map[string]interface{}{
			"healthy_nodes":       m.clusterMetrics.healthyNodes.Get(),
			"unhealthy_nodes":     m.clusterMetrics.unhealthyNodes.Get(),
			"total_nodes":         m.clusterMetrics.totalNodes.Get(),
			"split_brain_count":   m.clusterMetrics.splitBrainDetected.Get(),
			"last_split_brain":    m.clusterMetrics.lastSplitBrain,
			"network_latency_p95": m.clusterMetrics.networkLatency.Percentile(0.95),
			"network_error_rate":  m.clusterMetrics.networkErrors.Rate(),
		}
	}
	
	// Usage metrics
	if m.usageMetrics != nil {
		data["usage_metrics"] = map[string]interface{}{
			"hot_objects":    m.usageMetrics.hotDataObjects.Get(),
			"warm_objects":   m.usageMetrics.warmDataObjects.Get(),
			"cold_objects":   m.usageMetrics.coldDataObjects.Get(),
			"hourly_access":  m.usageMetrics.hourlyAccess.GetRecent(24),
			"daily_access":   m.usageMetrics.dailyAccess.GetRecent(7),
		}
	}
	
	// Active alerts
	if m.alertManager != nil {
		data["alerts"] = m.alertManager.GetActiveAlerts()
	}
	
	return data
}

// collectPinMetrics collects pin-related metrics
func (m *IPFSMetricsManager) collectPinMetrics() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.PinMetricsInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			// Pin metrics are recorded in real-time via RecordPinLatency
			// This goroutine can be used for periodic cleanup or aggregation
			m.cleanupOldMetrics()
		}
	}
}

// collectClusterMetrics collects cluster health metrics
func (m *IPFSMetricsManager) collectClusterMetrics() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.ClusterMetricsInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			// Cluster metrics are recorded via RecordClusterHealth
			// This can be used for additional cluster monitoring
		}
	}
}

// collectUsageMetrics collects usage analytics
func (m *IPFSMetricsManager) collectUsageMetrics() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.UsageMetricsInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			// Analyze usage patterns and classify hot/warm/cold data
			m.analyzeUsagePatterns()
		}
	}
}

// checkAlerts checks for alert conditions
func (m *IPFSMetricsManager) checkAlerts() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.AlertCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if m.alertManager != nil {
				dashboardData := m.GetDashboardData()
				m.alertManager.CheckAlerts(dashboardData)
			}
		}
	}
}

// runDashboard runs the monitoring dashboard
func (m *IPFSMetricsManager) runDashboard() {
	defer m.wg.Done()
	
	// This would implement a web dashboard
	// For now, just log that it would be running
	m.logger.Printf("Dashboard would be running on port %d", m.config.DashboardPort)
	
	ticker := time.NewTicker(m.config.DashboardUpdateInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			// Update dashboard data
			data := m.GetDashboardData()
			m.logger.Printf("Dashboard data updated: %d metrics", len(data))
		}
	}
}

// runPrometheusExporter runs the Prometheus metrics exporter
func (m *IPFSMetricsManager) runPrometheusExporter() {
	defer m.wg.Done()
	
	// This would implement Prometheus metrics export
	m.logger.Printf("Prometheus exporter would be running on port %d%s", m.config.PrometheusPort, m.config.PrometheusPath)
	
	<-m.ctx.Done()
}

// cleanupOldMetrics removes old metrics data
func (m *IPFSMetricsManager) cleanupOldMetrics() {
	cutoff := time.Now().Add(-m.config.MetricsRetentionPeriod)
	
	// Clean up usage metrics
	if m.usageMetrics != nil {
		m.usageMetrics.cleanup(cutoff)
	}
	
	// Clean up alert history
	if m.alertManager != nil {
		m.alertManager.cleanupHistory(cutoff)
	}
}

// analyzeUsagePatterns analyzes object access patterns
func (m *IPFSMetricsManager) analyzeUsagePatterns() {
	if m.usageMetrics == nil {
		return
	}
	
	now := time.Now()
	hotThreshold := now.Add(-1 * time.Hour)
	warmThreshold := now.Add(-24 * time.Hour)
	
	m.usageMetrics.mu.Lock()
	defer m.usageMetrics.mu.Unlock()
	
	var hotCount, warmCount, coldCount int64
	
	for _, objMetrics := range m.usageMetrics.objectAccess {
		if objMetrics.LastAccess.After(hotThreshold) {
			hotCount++
		} else if objMetrics.LastAccess.After(warmThreshold) {
			warmCount++
		} else {
			coldCount++
		}
	}
	
	m.usageMetrics.hotDataObjects.Set(hotCount)
	m.usageMetrics.warmDataObjects.Set(warmCount)
	m.usageMetrics.coldDataObjects.Set(coldCount)
}