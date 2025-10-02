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

package auth

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// PerformanceMonitor monitors authentication performance metrics
type PerformanceMonitor interface {
	// Metrics recording
	RecordAuthenticationLatency(duration time.Duration, success bool)
	RecordCacheHit(hit bool, operation string)
	RecordDatabaseQuery(duration time.Duration, operation string)
	RecordExternalProviderCall(duration time.Duration, provider string, success bool)
	
	// Performance analysis
	GetLatencyStats() *LatencyStats
	GetCacheStats() *CachePerformanceStats
	GetDatabaseStats() *DatabasePerformanceStats
	GetExternalProviderStats() map[string]*ExternalProviderStats
	
	// Alerting
	CheckPerformanceThresholds() []*PerformanceAlert
	SetThresholds(thresholds *PerformanceThresholds) error
	
	// Reporting
	GeneratePerformanceReport() *PerformanceReport
	GetMetricsSnapshot() *MetricsSnapshot
	
	// Lifecycle
	Start() error
	Stop() error
	Reset() error
}

// LatencyStats provides latency statistics
type LatencyStats struct {
	TotalRequests     int64         `json:"total_requests"`
	SuccessfulRequests int64        `json:"successful_requests"`
	FailedRequests    int64         `json:"failed_requests"`
	AverageLatency    time.Duration `json:"average_latency"`
	MedianLatency     time.Duration `json:"median_latency"`
	P95Latency        time.Duration `json:"p95_latency"`
	P99Latency        time.Duration `json:"p99_latency"`
	MinLatency        time.Duration `json:"min_latency"`
	MaxLatency        time.Duration `json:"max_latency"`
	LastUpdate        time.Time     `json:"last_update"`
}

// CachePerformanceStats provides cache performance statistics
type CachePerformanceStats struct {
	TotalOperations int64   `json:"total_operations"`
	CacheHits       int64   `json:"cache_hits"`
	CacheMisses     int64   `json:"cache_misses"`
	HitRate         float64 `json:"hit_rate"`
	OperationStats  map[string]*OperationStats `json:"operation_stats"`
	LastUpdate      time.Time `json:"last_update"`
}

// DatabasePerformanceStats provides database performance statistics
type DatabasePerformanceStats struct {
	TotalQueries      int64         `json:"total_queries"`
	AverageLatency    time.Duration `json:"average_latency"`
	SlowQueries       int64         `json:"slow_queries"`
	FailedQueries     int64         `json:"failed_queries"`
	QueryStats        map[string]*QueryStats `json:"query_stats"`
	LastUpdate        time.Time     `json:"last_update"`
}

// ExternalProviderStats provides external provider performance statistics
type ExternalProviderStats struct {
	Provider          string        `json:"provider"`
	TotalCalls        int64         `json:"total_calls"`
	SuccessfulCalls   int64         `json:"successful_calls"`
	FailedCalls       int64         `json:"failed_calls"`
	AverageLatency    time.Duration `json:"average_latency"`
	TimeoutCalls      int64         `json:"timeout_calls"`
	LastUpdate        time.Time     `json:"last_update"`
}

// OperationStats provides statistics for specific operations
type OperationStats struct {
	Operation   string `json:"operation"`
	Hits        int64  `json:"hits"`
	Misses      int64  `json:"misses"`
	HitRate     float64 `json:"hit_rate"`
	LastUpdate  time.Time `json:"last_update"`
}

// QueryStats provides statistics for specific database queries
type QueryStats struct {
	Query          string        `json:"query"`
	Count          int64         `json:"count"`
	AverageLatency time.Duration `json:"average_latency"`
	SlowCount      int64         `json:"slow_count"`
	ErrorCount     int64         `json:"error_count"`
	LastUpdate     time.Time     `json:"last_update"`
}

// PerformanceAlert represents a performance alert
type PerformanceAlert struct {
	Type        AlertType     `json:"type"`
	Severity    AlertSeverity `json:"severity"`
	Message     string        `json:"message"`
	Metric      string        `json:"metric"`
	Value       interface{}   `json:"value"`
	Threshold   interface{}   `json:"threshold"`
	Timestamp   time.Time     `json:"timestamp"`
}

// PerformanceAlertType defines types of performance alerts
type PerformanceAlertType int

const (
	LatencyAlert PerformanceAlertType = iota
	CacheAlert
	DatabaseAlert
	ExternalProviderAlert
	ThroughputAlert
)

// String returns string representation of PerformanceAlertType
func (a PerformanceAlertType) String() string {
	switch a {
	case LatencyAlert:
		return "latency"
	case CacheAlert:
		return "cache"
	case DatabaseAlert:
		return "database"
	case ExternalProviderAlert:
		return "external_provider"
	case ThroughputAlert:
		return "throughput"
	default:
		return "unknown"
	}
}



// String returns string representation of AlertSeverity
func (s AlertSeverity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// PerformanceThresholds defines performance alert thresholds
type PerformanceThresholds struct {
	MaxAverageLatency    time.Duration `json:"max_average_latency"`
	MaxP95Latency        time.Duration `json:"max_p95_latency"`
	MaxP99Latency        time.Duration `json:"max_p99_latency"`
	MinCacheHitRate      float64       `json:"min_cache_hit_rate"`
	MaxDatabaseLatency   time.Duration `json:"max_database_latency"`
	MaxExternalLatency   time.Duration `json:"max_external_latency"`
	MaxFailureRate       float64       `json:"max_failure_rate"`
	MinThroughput        float64       `json:"min_throughput"`
}

// DefaultPerformanceThresholds returns default performance thresholds
func DefaultPerformanceThresholds() *PerformanceThresholds {
	return &PerformanceThresholds{
		MaxAverageLatency:  100 * time.Millisecond,
		MaxP95Latency:      200 * time.Millisecond,
		MaxP99Latency:      500 * time.Millisecond,
		MinCacheHitRate:    0.8, // 80%
		MaxDatabaseLatency: 50 * time.Millisecond,
		MaxExternalLatency: 1 * time.Second,
		MaxFailureRate:     0.05, // 5%
		MinThroughput:      10.0, // 10 requests per second
	}
}

// PerformanceReport provides a comprehensive performance report
type PerformanceReport struct {
	GeneratedAt           time.Time                          `json:"generated_at"`
	ReportPeriod          time.Duration                      `json:"report_period"`
	LatencyStats          *LatencyStats                      `json:"latency_stats"`
	CacheStats            *CachePerformanceStats             `json:"cache_stats"`
	DatabaseStats         *DatabasePerformanceStats          `json:"database_stats"`
	ExternalProviderStats map[string]*ExternalProviderStats  `json:"external_provider_stats"`
	Alerts                []*PerformanceAlert                `json:"alerts"`
	Recommendations       []string                           `json:"recommendations"`
}

// MetricsSnapshot provides a snapshot of current metrics
type MetricsSnapshot struct {
	Timestamp             time.Time                          `json:"timestamp"`
	CurrentThroughput     float64                            `json:"current_throughput"`
	ActiveConnections     int                                `json:"active_connections"`
	MemoryUsage           float64                            `json:"memory_usage"`
	CPUUsage              float64                            `json:"cpu_usage"`
	LatencyStats          *LatencyStats                      `json:"latency_stats"`
	CacheStats            *CachePerformanceStats             `json:"cache_stats"`
}

// PerformanceMonitorConfig holds configuration for performance monitor
type PerformanceMonitorConfig struct {
	SampleSize          int                    `json:"sample_size"`
	ReportInterval      time.Duration          `json:"report_interval"`
	AlertCheckInterval  time.Duration          `json:"alert_check_interval"`
	RetentionPeriod     time.Duration          `json:"retention_period"`
	Thresholds          *PerformanceThresholds `json:"thresholds"`
	EnableDetailedStats bool                   `json:"enable_detailed_stats"`
}

// DefaultPerformanceMonitorConfig returns default performance monitor configuration
func DefaultPerformanceMonitorConfig() *PerformanceMonitorConfig {
	return &PerformanceMonitorConfig{
		SampleSize:          10000,
		ReportInterval:      5 * time.Minute,
		AlertCheckInterval:  30 * time.Second,
		RetentionPeriod:     24 * time.Hour,
		Thresholds:          DefaultPerformanceThresholds(),
		EnableDetailedStats: true,
	}
}

// performanceMonitorImpl implements PerformanceMonitor
type performanceMonitorImpl struct {
	config    *PerformanceMonitorConfig
	mu        sync.RWMutex
	
	// Latency tracking
	latencySamples    []time.Duration
	successCount      int64
	failureCount      int64
	
	// Cache tracking
	cacheHits         int64
	cacheMisses       int64
	operationStats    map[string]*OperationStats
	
	// Database tracking
	dbQueries         int64
	dbLatencySum      time.Duration
	dbSlowQueries     int64
	dbFailedQueries   int64
	queryStats        map[string]*QueryStats
	
	// External provider tracking
	providerStats     map[string]*ExternalProviderStats
	
	// Background processes
	ctx               context.Context
	cancel            context.CancelFunc
	running           bool
	
	// Alerts
	alerts            []*PerformanceAlert
	lastAlertCheck    time.Time
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(config *PerformanceMonitorConfig) PerformanceMonitor {
	if config == nil {
		config = DefaultPerformanceMonitorConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pm := &performanceMonitorImpl{
		config:         config,
		latencySamples: make([]time.Duration, 0, config.SampleSize),
		operationStats: make(map[string]*OperationStats),
		queryStats:     make(map[string]*QueryStats),
		providerStats:  make(map[string]*ExternalProviderStats),
		alerts:         make([]*PerformanceAlert, 0),
		ctx:            ctx,
		cancel:         cancel,
	}
	
	return pm
}

// RecordAuthenticationLatency records authentication latency
func (pm *performanceMonitorImpl) RecordAuthenticationLatency(duration time.Duration, success bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	// Add to samples (with circular buffer behavior)
	if len(pm.latencySamples) >= pm.config.SampleSize {
		// Remove oldest sample
		pm.latencySamples = pm.latencySamples[1:]
	}
	pm.latencySamples = append(pm.latencySamples, duration)
	
	// Update counters
	if success {
		pm.successCount++
	} else {
		pm.failureCount++
	}
}

// RecordCacheHit records cache hit/miss
func (pm *performanceMonitorImpl) RecordCacheHit(hit bool, operation string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if hit {
		pm.cacheHits++
	} else {
		pm.cacheMisses++
	}
	
	// Update operation-specific stats
	if pm.config.EnableDetailedStats {
		if stats, exists := pm.operationStats[operation]; exists {
			if hit {
				stats.Hits++
			} else {
				stats.Misses++
			}
			stats.HitRate = float64(stats.Hits) / float64(stats.Hits+stats.Misses)
			stats.LastUpdate = time.Now()
		} else {
			stats := &OperationStats{
				Operation:  operation,
				LastUpdate: time.Now(),
			}
			if hit {
				stats.Hits = 1
				stats.HitRate = 1.0
			} else {
				stats.Misses = 1
				stats.HitRate = 0.0
			}
			pm.operationStats[operation] = stats
		}
	}
}

// RecordDatabaseQuery records database query performance
func (pm *performanceMonitorImpl) RecordDatabaseQuery(duration time.Duration, operation string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	pm.dbQueries++
	pm.dbLatencySum += duration
	
	// Check for slow queries
	if duration > pm.config.Thresholds.MaxDatabaseLatency*2 {
		pm.dbSlowQueries++
	}
	
	// Update query-specific stats
	if pm.config.EnableDetailedStats {
		if stats, exists := pm.queryStats[operation]; exists {
			stats.Count++
			// Update average latency
			totalLatency := stats.AverageLatency*time.Duration(stats.Count-1) + duration
			stats.AverageLatency = totalLatency / time.Duration(stats.Count)
			
			if duration > pm.config.Thresholds.MaxDatabaseLatency*2 {
				stats.SlowCount++
			}
			stats.LastUpdate = time.Now()
		} else {
			stats := &QueryStats{
				Query:          operation,
				Count:          1,
				AverageLatency: duration,
				LastUpdate:     time.Now(),
			}
			if duration > pm.config.Thresholds.MaxDatabaseLatency*2 {
				stats.SlowCount = 1
			}
			pm.queryStats[operation] = stats
		}
	}
}

// RecordExternalProviderCall records external provider call performance
func (pm *performanceMonitorImpl) RecordExternalProviderCall(duration time.Duration, provider string, success bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if stats, exists := pm.providerStats[provider]; exists {
		stats.TotalCalls++
		if success {
			stats.SuccessfulCalls++
		} else {
			stats.FailedCalls++
		}
		
		// Update average latency
		totalLatency := stats.AverageLatency*time.Duration(stats.TotalCalls-1) + duration
		stats.AverageLatency = totalLatency / time.Duration(stats.TotalCalls)
		
		// Check for timeouts
		if duration > pm.config.Thresholds.MaxExternalLatency {
			stats.TimeoutCalls++
		}
		
		stats.LastUpdate = time.Now()
	} else {
		stats := &ExternalProviderStats{
			Provider:        provider,
			TotalCalls:      1,
			AverageLatency:  duration,
			LastUpdate:      time.Now(),
		}
		
		if success {
			stats.SuccessfulCalls = 1
		} else {
			stats.FailedCalls = 1
		}
		
		if duration > pm.config.Thresholds.MaxExternalLatency {
			stats.TimeoutCalls = 1
		}
		
		pm.providerStats[provider] = stats
	}
}

// GetLatencyStats returns latency statistics
func (pm *performanceMonitorImpl) GetLatencyStats() *LatencyStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	if len(pm.latencySamples) == 0 {
		return &LatencyStats{
			LastUpdate: time.Now(),
		}
	}
	
	// Sort samples for percentile calculations
	samples := make([]time.Duration, len(pm.latencySamples))
	copy(samples, pm.latencySamples)
	sort.Slice(samples, func(i, j int) bool {
		return samples[i] < samples[j]
	})
	
	// Calculate statistics
	var totalLatency time.Duration
	for _, sample := range samples {
		totalLatency += sample
	}
	
	stats := &LatencyStats{
		TotalRequests:      pm.successCount + pm.failureCount,
		SuccessfulRequests: pm.successCount,
		FailedRequests:     pm.failureCount,
		AverageLatency:     totalLatency / time.Duration(len(samples)),
		MedianLatency:      samples[len(samples)/2],
		MinLatency:         samples[0],
		MaxLatency:         samples[len(samples)-1],
		LastUpdate:         time.Now(),
	}
	
	// Calculate percentiles
	if len(samples) > 0 {
		p95Index := int(float64(len(samples)) * 0.95)
		p99Index := int(float64(len(samples)) * 0.99)
		
		if p95Index >= len(samples) {
			p95Index = len(samples) - 1
		}
		if p99Index >= len(samples) {
			p99Index = len(samples) - 1
		}
		
		stats.P95Latency = samples[p95Index]
		stats.P99Latency = samples[p99Index]
	}
	
	return stats
}

// GetCacheStats returns cache performance statistics
func (pm *performanceMonitorImpl) GetCacheStats() *CachePerformanceStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	total := pm.cacheHits + pm.cacheMisses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(pm.cacheHits) / float64(total)
	}
	
	// Copy operation stats
	operationStats := make(map[string]*OperationStats)
	for k, v := range pm.operationStats {
		operationStats[k] = &(*v) // Copy
	}
	
	return &CachePerformanceStats{
		TotalOperations: total,
		CacheHits:       pm.cacheHits,
		CacheMisses:     pm.cacheMisses,
		HitRate:         hitRate,
		OperationStats:  operationStats,
		LastUpdate:      time.Now(),
	}
}

// GetDatabaseStats returns database performance statistics
func (pm *performanceMonitorImpl) GetDatabaseStats() *DatabasePerformanceStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	avgLatency := time.Duration(0)
	if pm.dbQueries > 0 {
		avgLatency = pm.dbLatencySum / time.Duration(pm.dbQueries)
	}
	
	// Copy query stats
	queryStats := make(map[string]*QueryStats)
	for k, v := range pm.queryStats {
		queryStats[k] = &(*v) // Copy
	}
	
	return &DatabasePerformanceStats{
		TotalQueries:   pm.dbQueries,
		AverageLatency: avgLatency,
		SlowQueries:    pm.dbSlowQueries,
		FailedQueries:  pm.dbFailedQueries,
		QueryStats:     queryStats,
		LastUpdate:     time.Now(),
	}
}

// GetExternalProviderStats returns external provider statistics
func (pm *performanceMonitorImpl) GetExternalProviderStats() map[string]*ExternalProviderStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	// Copy provider stats
	providerStats := make(map[string]*ExternalProviderStats)
	for k, v := range pm.providerStats {
		providerStats[k] = &(*v) // Copy
	}
	
	return providerStats
}

// CheckPerformanceThresholds checks performance against thresholds
func (pm *performanceMonitorImpl) CheckPerformanceThresholds() []*PerformanceAlert {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	var alerts []*PerformanceAlert
	now := time.Now()
	
	// Check latency thresholds
	latencyStats := pm.getLatencyStatsLocked()
	if latencyStats.AverageLatency > pm.config.Thresholds.MaxAverageLatency {
		alerts = append(alerts, &PerformanceAlert{
			Type:      LatencyAlert,
			Severity:  SeverityHigh,
			Message:   "Average latency exceeds threshold",
			Metric:    "average_latency",
			Value:     latencyStats.AverageLatency,
			Threshold: pm.config.Thresholds.MaxAverageLatency,
			Timestamp: now,
		})
	}
	
	if latencyStats.P95Latency > pm.config.Thresholds.MaxP95Latency {
		alerts = append(alerts, &PerformanceAlert{
			Type:      LatencyAlert,
			Severity:  SeverityMedium,
			Message:   "P95 latency exceeds threshold",
			Metric:    "p95_latency",
			Value:     latencyStats.P95Latency,
			Threshold: pm.config.Thresholds.MaxP95Latency,
			Timestamp: now,
		})
	}
	
	// Check cache hit rate
	total := pm.cacheHits + pm.cacheMisses
	if total > 0 {
		hitRate := float64(pm.cacheHits) / float64(total)
		if hitRate < pm.config.Thresholds.MinCacheHitRate {
			alerts = append(alerts, &PerformanceAlert{
				Type:      CacheAlert,
				Severity:  SeverityMedium,
				Message:   "Cache hit rate below threshold",
				Metric:    "cache_hit_rate",
				Value:     hitRate,
				Threshold: pm.config.Thresholds.MinCacheHitRate,
				Timestamp: now,
			})
		}
	}
	
	// Check database latency
	if pm.dbQueries > 0 {
		avgDbLatency := pm.dbLatencySum / time.Duration(pm.dbQueries)
		if avgDbLatency > pm.config.Thresholds.MaxDatabaseLatency {
			alerts = append(alerts, &PerformanceAlert{
				Type:      DatabaseAlert,
				Severity:  SeverityHigh,
				Message:   "Database latency exceeds threshold",
				Metric:    "database_latency",
				Value:     avgDbLatency,
				Threshold: pm.config.Thresholds.MaxDatabaseLatency,
				Timestamp: now,
			})
		}
	}
	
	// Check external provider latency
	for provider, stats := range pm.providerStats {
		if stats.AverageLatency > pm.config.Thresholds.MaxExternalLatency {
			alerts = append(alerts, &PerformanceAlert{
				Type:      ExternalProviderAlert,
				Severity:  SeverityMedium,
				Message:   fmt.Sprintf("External provider %s latency exceeds threshold", provider),
				Metric:    "external_provider_latency",
				Value:     stats.AverageLatency,
				Threshold: pm.config.Thresholds.MaxExternalLatency,
				Timestamp: now,
			})
		}
		
		// Check failure rate
		if stats.TotalCalls > 0 {
			failureRate := float64(stats.FailedCalls) / float64(stats.TotalCalls)
			if failureRate > pm.config.Thresholds.MaxFailureRate {
				alerts = append(alerts, &PerformanceAlert{
					Type:      ExternalProviderAlert,
					Severity:  SeverityHigh,
					Message:   fmt.Sprintf("External provider %s failure rate exceeds threshold", provider),
					Metric:    "external_provider_failure_rate",
					Value:     failureRate,
					Threshold: pm.config.Thresholds.MaxFailureRate,
					Timestamp: now,
				})
			}
		}
	}
	
	// Store alerts
	pm.alerts = append(pm.alerts, alerts...)
	pm.lastAlertCheck = now
	
	return alerts
}

// SetThresholds sets performance thresholds
func (pm *performanceMonitorImpl) SetThresholds(thresholds *PerformanceThresholds) error {
	if thresholds == nil {
		return fmt.Errorf("thresholds cannot be nil")
	}
	
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	pm.config.Thresholds = thresholds
	return nil
}

// GeneratePerformanceReport generates a comprehensive performance report
func (pm *performanceMonitorImpl) GeneratePerformanceReport() *PerformanceReport {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	report := &PerformanceReport{
		GeneratedAt:           time.Now(),
		ReportPeriod:          pm.config.ReportInterval,
		LatencyStats:          pm.getLatencyStatsLocked(),
		CacheStats:            pm.getCacheStatsLocked(),
		DatabaseStats:         pm.getDatabaseStatsLocked(),
		ExternalProviderStats: pm.getExternalProviderStatsLocked(),
		Alerts:                make([]*PerformanceAlert, len(pm.alerts)),
		Recommendations:       pm.generateRecommendations(),
	}
	
	// Copy alerts
	copy(report.Alerts, pm.alerts)
	
	return report
}

// GetMetricsSnapshot returns a snapshot of current metrics
func (pm *performanceMonitorImpl) GetMetricsSnapshot() *MetricsSnapshot {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	// Calculate current throughput (simplified)
	throughput := 0.0
	if len(pm.latencySamples) > 0 {
		// Estimate based on recent samples
		recentSamples := len(pm.latencySamples)
		if recentSamples > 100 {
			recentSamples = 100
		}
		throughput = float64(recentSamples) / pm.config.ReportInterval.Seconds()
	}
	
	return &MetricsSnapshot{
		Timestamp:         time.Now(),
		CurrentThroughput: throughput,
		ActiveConnections: int(pm.successCount + pm.failureCount), // Simplified
		MemoryUsage:       0.0, // Would be populated from system metrics
		CPUUsage:          0.0, // Would be populated from system metrics
		LatencyStats:      pm.getLatencyStatsLocked(),
		CacheStats:        pm.getCacheStatsLocked(),
	}
}

// Start starts the performance monitor
func (pm *performanceMonitorImpl) Start() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if pm.running {
		return nil
	}
	
	// Start background alert checking
	go pm.alertCheckLoop()
	
	pm.running = true
	return nil
}

// Stop stops the performance monitor
func (pm *performanceMonitorImpl) Stop() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if !pm.running {
		return nil
	}
	
	if pm.cancel != nil {
		pm.cancel()
	}
	
	pm.running = false
	return nil
}

// Reset resets all performance metrics
func (pm *performanceMonitorImpl) Reset() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	pm.latencySamples = make([]time.Duration, 0, pm.config.SampleSize)
	pm.successCount = 0
	pm.failureCount = 0
	pm.cacheHits = 0
	pm.cacheMisses = 0
	pm.operationStats = make(map[string]*OperationStats)
	pm.dbQueries = 0
	pm.dbLatencySum = 0
	pm.dbSlowQueries = 0
	pm.dbFailedQueries = 0
	pm.queryStats = make(map[string]*QueryStats)
	pm.providerStats = make(map[string]*ExternalProviderStats)
	pm.alerts = make([]*PerformanceAlert, 0)
	
	return nil
}

// Helper methods (must be called with lock held)

func (pm *performanceMonitorImpl) getLatencyStatsLocked() *LatencyStats {
	if len(pm.latencySamples) == 0 {
		return &LatencyStats{LastUpdate: time.Now()}
	}
	
	samples := make([]time.Duration, len(pm.latencySamples))
	copy(samples, pm.latencySamples)
	sort.Slice(samples, func(i, j int) bool {
		return samples[i] < samples[j]
	})
	
	var totalLatency time.Duration
	for _, sample := range samples {
		totalLatency += sample
	}
	
	stats := &LatencyStats{
		TotalRequests:      pm.successCount + pm.failureCount,
		SuccessfulRequests: pm.successCount,
		FailedRequests:     pm.failureCount,
		AverageLatency:     totalLatency / time.Duration(len(samples)),
		MedianLatency:      samples[len(samples)/2],
		MinLatency:         samples[0],
		MaxLatency:         samples[len(samples)-1],
		LastUpdate:         time.Now(),
	}
	
	if len(samples) > 0 {
		p95Index := int(float64(len(samples)) * 0.95)
		p99Index := int(float64(len(samples)) * 0.99)
		
		if p95Index >= len(samples) {
			p95Index = len(samples) - 1
		}
		if p99Index >= len(samples) {
			p99Index = len(samples) - 1
		}
		
		stats.P95Latency = samples[p95Index]
		stats.P99Latency = samples[p99Index]
	}
	
	return stats
}

func (pm *performanceMonitorImpl) getCacheStatsLocked() *CachePerformanceStats {
	total := pm.cacheHits + pm.cacheMisses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(pm.cacheHits) / float64(total)
	}
	
	operationStats := make(map[string]*OperationStats)
	for k, v := range pm.operationStats {
		operationStats[k] = &(*v)
	}
	
	return &CachePerformanceStats{
		TotalOperations: total,
		CacheHits:       pm.cacheHits,
		CacheMisses:     pm.cacheMisses,
		HitRate:         hitRate,
		OperationStats:  operationStats,
		LastUpdate:      time.Now(),
	}
}

func (pm *performanceMonitorImpl) getDatabaseStatsLocked() *DatabasePerformanceStats {
	avgLatency := time.Duration(0)
	if pm.dbQueries > 0 {
		avgLatency = pm.dbLatencySum / time.Duration(pm.dbQueries)
	}
	
	queryStats := make(map[string]*QueryStats)
	for k, v := range pm.queryStats {
		queryStats[k] = &(*v)
	}
	
	return &DatabasePerformanceStats{
		TotalQueries:   pm.dbQueries,
		AverageLatency: avgLatency,
		SlowQueries:    pm.dbSlowQueries,
		FailedQueries:  pm.dbFailedQueries,
		QueryStats:     queryStats,
		LastUpdate:     time.Now(),
	}
}

func (pm *performanceMonitorImpl) getExternalProviderStatsLocked() map[string]*ExternalProviderStats {
	providerStats := make(map[string]*ExternalProviderStats)
	for k, v := range pm.providerStats {
		providerStats[k] = &(*v)
	}
	return providerStats
}

func (pm *performanceMonitorImpl) generateRecommendations() []string {
	var recommendations []string
	
	// Cache recommendations
	total := pm.cacheHits + pm.cacheMisses
	if total > 0 {
		hitRate := float64(pm.cacheHits) / float64(total)
		if hitRate < 0.7 {
			recommendations = append(recommendations, "Consider increasing cache size or TTL to improve hit rate")
		}
	}
	
	// Database recommendations
	if pm.dbSlowQueries > 0 && pm.dbQueries > 0 {
		slowRate := float64(pm.dbSlowQueries) / float64(pm.dbQueries)
		if slowRate > 0.1 {
			recommendations = append(recommendations, "High number of slow database queries detected - consider query optimization")
		}
	}
	
	// External provider recommendations
	for provider, stats := range pm.providerStats {
		if stats.TotalCalls > 0 {
			failureRate := float64(stats.FailedCalls) / float64(stats.TotalCalls)
			if failureRate > 0.05 {
				recommendations = append(recommendations, 
					fmt.Sprintf("High failure rate for external provider %s - consider implementing circuit breaker", provider))
			}
		}
	}
	
	return recommendations
}

func (pm *performanceMonitorImpl) alertCheckLoop() {
	ticker := time.NewTicker(pm.config.AlertCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.CheckPerformanceThresholds()
		}
	}
}