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
	"log"
	"sync"
	"time"

	"github.com/versity/versitygw/metrics"
)

// MetricsReporter defines the interface for reporting metrics
type MetricsReporter interface {
	ReportMetric(key string, value int64, tags map[string]string)
}

// MetricsManagerAdapter adapts the existing metrics.Manager to our interface
type MetricsManagerAdapter struct {
	manager *metrics.Manager
}

// NewMetricsManagerAdapter creates a new adapter for metrics.Manager
func NewMetricsManagerAdapter(manager *metrics.Manager) *MetricsManagerAdapter {
	return &MetricsManagerAdapter{manager: manager}
}

// ReportMetric reports a metric using the underlying metrics manager
func (a *MetricsManagerAdapter) ReportMetric(key string, value int64, tags map[string]string) {
	// For now, we'll just log the metrics since we can't access private methods
	// In a real implementation, this would integrate with the metrics system
	// through public APIs or by extending the metrics package
	if a.manager != nil {
		// This is a placeholder - in production you would need to extend
		// the metrics package to provide public methods for custom metrics
		log.Printf("SECURITY_METRIC: %s = %d (tags: %+v)", key, value, tags)
	}
}

// SecurityMetricsCollector collects and reports security-related metrics
type SecurityMetricsCollector struct {
	mu                    sync.RWMutex
	metricsReporter       MetricsReporter
	alertSystem           *SecurityAlertSystem
	config                *SecurityMetricsConfig
	
	// Counters
	authAttempts          int64
	authSuccesses         int64
	authFailures          int64
	mfaAttempts           int64
	mfaSuccesses          int64
	mfaFailures           int64
	userLockouts          int64
	alertsTriggered       int64
	suspiciousActivities  int64
	
	// Gauges
	currentLockedUsers    int64
	activeAlerts          int64
	averageRiskScore      float64
	
	// Histograms
	authResponseTimes     []time.Duration
	riskScoreDistribution []int
	
	// Time-based metrics
	lastMetricsUpdate     time.Time
	metricsHistory        []*SecurityMetricsSnapshot
}

// SecurityMetricsConfig contains configuration for security metrics collection
type SecurityMetricsConfig struct {
	CollectionInterval    time.Duration `json:"collection_interval"`
	HistoryRetention      time.Duration `json:"history_retention"`
	MaxHistoryEntries     int           `json:"max_history_entries"`
	EnableDetailedMetrics bool          `json:"enable_detailed_metrics"`
	MetricsPrefix         string        `json:"metrics_prefix"`
}

// SecurityMetricsSnapshot represents a point-in-time snapshot of security metrics
type SecurityMetricsSnapshot struct {
	Timestamp             time.Time `json:"timestamp"`
	AuthAttempts          int64     `json:"auth_attempts"`
	AuthSuccesses         int64     `json:"auth_successes"`
	AuthFailures          int64     `json:"auth_failures"`
	MFAAttempts           int64     `json:"mfa_attempts"`
	MFASuccesses          int64     `json:"mfa_successes"`
	MFAFailures           int64     `json:"mfa_failures"`
	UserLockouts          int64     `json:"user_lockouts"`
	AlertsTriggered       int64     `json:"alerts_triggered"`
	SuspiciousActivities  int64     `json:"suspicious_activities"`
	CurrentLockedUsers    int64     `json:"current_locked_users"`
	ActiveAlerts          int64     `json:"active_alerts"`
	AverageRiskScore      float64   `json:"average_risk_score"`
	AuthSuccessRate       float64   `json:"auth_success_rate"`
	MFASuccessRate        float64   `json:"mfa_success_rate"`
}

// SecurityMetricsReporter defines the interface for reporting security metrics
type SecurityMetricsReporter interface {
	ReportAuthenticationAttempt(success bool, duration time.Duration, riskScore int)
	ReportMFAAttempt(success bool, method string)
	ReportUserLockout(userID string, reason string, duration time.Duration)
	ReportAlert(alertType AlertType, severity AlertSeverity)
	ReportSuspiciousActivity(activityType string, severity SecuritySeverity)
	GetCurrentMetrics() *SecurityMetricsSnapshot
	GetMetricsHistory(duration time.Duration) []*SecurityMetricsSnapshot
}

// DefaultSecurityMetricsConfig returns default configuration for security metrics
func DefaultSecurityMetricsConfig() *SecurityMetricsConfig {
	return &SecurityMetricsConfig{
		CollectionInterval:    1 * time.Minute,
		HistoryRetention:      24 * time.Hour,
		MaxHistoryEntries:     1440, // 24 hours of minute-by-minute data
		EnableDetailedMetrics: true,
		MetricsPrefix:         "security",
	}
}

// NewSecurityMetricsCollector creates a new security metrics collector
func NewSecurityMetricsCollector(metricsReporter MetricsReporter, alertSystem *SecurityAlertSystem, config *SecurityMetricsConfig) *SecurityMetricsCollector {
	if config == nil {
		config = DefaultSecurityMetricsConfig()
	}

	collector := &SecurityMetricsCollector{
		metricsReporter:       metricsReporter,
		alertSystem:           alertSystem,
		config:                config,
		authResponseTimes:     make([]time.Duration, 0),
		riskScoreDistribution: make([]int, 0),
		metricsHistory:        make([]*SecurityMetricsSnapshot, 0),
		lastMetricsUpdate:     time.Now(),
	}

	// Start metrics collection routine
	go collector.metricsCollectionRoutine()

	return collector
}

// NewSecurityMetricsCollectorWithManager creates a collector with a metrics.Manager
func NewSecurityMetricsCollectorWithManager(metricsManager *metrics.Manager, alertSystem *SecurityAlertSystem, config *SecurityMetricsConfig) *SecurityMetricsCollector {
	var reporter MetricsReporter
	if metricsManager != nil {
		reporter = NewMetricsManagerAdapter(metricsManager)
	}
	return NewSecurityMetricsCollector(reporter, alertSystem, config)
}

// ReportAuthenticationAttempt reports an authentication attempt
func (c *SecurityMetricsCollector) ReportAuthenticationAttempt(success bool, duration time.Duration, riskScore int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.authAttempts++
	if success {
		c.authSuccesses++
	} else {
		c.authFailures++
	}

	if c.config.EnableDetailedMetrics {
		c.authResponseTimes = append(c.authResponseTimes, duration)
		c.riskScoreDistribution = append(c.riskScoreDistribution, riskScore)
		
		// Keep only recent data to prevent memory growth
		if len(c.authResponseTimes) > 1000 {
			c.authResponseTimes = c.authResponseTimes[len(c.authResponseTimes)-1000:]
		}
		if len(c.riskScoreDistribution) > 1000 {
			c.riskScoreDistribution = c.riskScoreDistribution[len(c.riskScoreDistribution)-1000:]
		}
	}

	// Update metrics manager if available
	if c.metricsReporter != nil {
		c.updateMetricsReporter()
	}
}

// ReportMFAAttempt reports an MFA attempt
func (c *SecurityMetricsCollector) ReportMFAAttempt(success bool, method string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.mfaAttempts++
	if success {
		c.mfaSuccesses++
	} else {
		c.mfaFailures++
	}

	// Update metrics manager if available
	if c.metricsReporter != nil {
		c.updateMetricsReporter()
	}
}

// ReportUserLockout reports a user lockout event
func (c *SecurityMetricsCollector) ReportUserLockout(userID string, reason string, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.userLockouts++
	c.currentLockedUsers++ // This will be corrected by periodic updates

	// Update metrics manager if available
	if c.metricsReporter != nil {
		c.updateMetricsReporter()
	}
}

// ReportAlert reports a security alert
func (c *SecurityMetricsCollector) ReportAlert(alertType AlertType, severity AlertSeverity) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.alertsTriggered++

	// Update metrics manager if available
	if c.metricsReporter != nil {
		c.updateMetricsReporter()
	}
}

// ReportSuspiciousActivity reports suspicious activity
func (c *SecurityMetricsCollector) ReportSuspiciousActivity(activityType string, severity SecuritySeverity) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.suspiciousActivities++

	// Update metrics manager if available
	if c.metricsReporter != nil {
		c.updateMetricsReporter()
	}
}

// GetCurrentMetrics returns current security metrics
func (c *SecurityMetricsCollector) GetCurrentMetrics() *SecurityMetricsSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.createSnapshot()
}

// GetMetricsHistory returns metrics history for the specified duration
func (c *SecurityMetricsCollector) GetMetricsHistory(duration time.Duration) []*SecurityMetricsSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cutoff := time.Now().Add(-duration)
	var history []*SecurityMetricsSnapshot

	for _, snapshot := range c.metricsHistory {
		if snapshot.Timestamp.After(cutoff) {
			history = append(history, snapshot)
		}
	}

	return history
}

// metricsCollectionRoutine periodically collects and updates metrics
func (c *SecurityMetricsCollector) metricsCollectionRoutine() {
	ticker := time.NewTicker(c.config.CollectionInterval)
	defer ticker.Stop()

	for range ticker.C {
		c.collectPeriodicMetrics()
	}
}

// collectPeriodicMetrics collects metrics that need periodic updates
func (c *SecurityMetricsCollector) collectPeriodicMetrics() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update current locked users count
	if c.alertSystem != nil {
		c.currentLockedUsers = c.countCurrentlyLockedUsers()
		c.activeAlerts = c.countActiveAlerts()
	}

	// Calculate average risk score
	if len(c.riskScoreDistribution) > 0 {
		total := 0
		for _, score := range c.riskScoreDistribution {
			total += score
		}
		c.averageRiskScore = float64(total) / float64(len(c.riskScoreDistribution))
	}

	// Create and store snapshot
	snapshot := c.createSnapshot()
	c.metricsHistory = append(c.metricsHistory, snapshot)

	// Cleanup old history
	c.cleanupMetricsHistory()

	// Update external metrics manager
	if c.metricsReporter != nil {
		c.updateMetricsReporter()
	}

	c.lastMetricsUpdate = time.Now()
}

// createSnapshot creates a metrics snapshot
func (c *SecurityMetricsCollector) createSnapshot() *SecurityMetricsSnapshot {
	snapshot := &SecurityMetricsSnapshot{
		Timestamp:             time.Now(),
		AuthAttempts:          c.authAttempts,
		AuthSuccesses:         c.authSuccesses,
		AuthFailures:          c.authFailures,
		MFAAttempts:           c.mfaAttempts,
		MFASuccesses:          c.mfaSuccesses,
		MFAFailures:           c.mfaFailures,
		UserLockouts:          c.userLockouts,
		AlertsTriggered:       c.alertsTriggered,
		SuspiciousActivities:  c.suspiciousActivities,
		CurrentLockedUsers:    c.currentLockedUsers,
		ActiveAlerts:          c.activeAlerts,
		AverageRiskScore:      c.averageRiskScore,
	}

	// Calculate success rates
	if c.authAttempts > 0 {
		snapshot.AuthSuccessRate = float64(c.authSuccesses) / float64(c.authAttempts) * 100
	}
	if c.mfaAttempts > 0 {
		snapshot.MFASuccessRate = float64(c.mfaSuccesses) / float64(c.mfaAttempts) * 100
	}

	return snapshot
}

// countCurrentlyLockedUsers counts users that are currently locked
func (c *SecurityMetricsCollector) countCurrentlyLockedUsers() int64 {
	// This would need access to the user lock manager
	// For now, return the tracked count
	return c.currentLockedUsers
}

// countActiveAlerts counts currently active (unresolved) alerts
func (c *SecurityMetricsCollector) countActiveAlerts() int64 {
	if c.alertSystem == nil {
		return 0
	}

	filter := &AlertFilter{
		Resolved: &[]bool{false}[0], // Pointer to false
	}
	
	alerts := c.alertSystem.GetAlerts(filter)
	return int64(len(alerts))
}

// cleanupMetricsHistory removes old metrics history entries
func (c *SecurityMetricsCollector) cleanupMetricsHistory() {
	// Remove entries older than retention period
	cutoff := time.Now().Add(-c.config.HistoryRetention)
	var validHistory []*SecurityMetricsSnapshot

	for _, snapshot := range c.metricsHistory {
		if snapshot.Timestamp.After(cutoff) {
			validHistory = append(validHistory, snapshot)
		}
	}

	c.metricsHistory = validHistory

	// Limit to max entries
	if len(c.metricsHistory) > c.config.MaxHistoryEntries {
		excess := len(c.metricsHistory) - c.config.MaxHistoryEntries
		c.metricsHistory = c.metricsHistory[excess:]
	}
}

// updateMetricsReporter updates the external metrics reporter
func (c *SecurityMetricsCollector) updateMetricsReporter() {
	if c.metricsReporter == nil {
		return
	}

	prefix := c.config.MetricsPrefix

	// Create tags for security metrics
	tags := map[string]string{
		"component": "security",
		"service":   "auth",
	}

	// Update counters
	c.metricsReporter.ReportMetric(prefix+"_auth_attempts_total", c.authAttempts, tags)
	c.metricsReporter.ReportMetric(prefix+"_auth_successes_total", c.authSuccesses, tags)
	c.metricsReporter.ReportMetric(prefix+"_auth_failures_total", c.authFailures, tags)
	c.metricsReporter.ReportMetric(prefix+"_mfa_attempts_total", c.mfaAttempts, tags)
	c.metricsReporter.ReportMetric(prefix+"_mfa_successes_total", c.mfaSuccesses, tags)
	c.metricsReporter.ReportMetric(prefix+"_mfa_failures_total", c.mfaFailures, tags)
	c.metricsReporter.ReportMetric(prefix+"_user_lockouts_total", c.userLockouts, tags)
	c.metricsReporter.ReportMetric(prefix+"_alerts_triggered_total", c.alertsTriggered, tags)
	c.metricsReporter.ReportMetric(prefix+"_suspicious_activities_total", c.suspiciousActivities, tags)

	// Update gauges (current values)
	c.metricsReporter.ReportMetric(prefix+"_locked_users_current", c.currentLockedUsers, tags)
	c.metricsReporter.ReportMetric(prefix+"_active_alerts_current", c.activeAlerts, tags)
	c.metricsReporter.ReportMetric(prefix+"_average_risk_score", int64(c.averageRiskScore), tags)

	// Calculate and update success rates
	if c.authAttempts > 0 {
		successRate := int64(float64(c.authSuccesses) / float64(c.authAttempts) * 100)
		c.metricsReporter.ReportMetric(prefix+"_auth_success_rate_percent", successRate, tags)
	}

	if c.mfaAttempts > 0 {
		mfaSuccessRate := int64(float64(c.mfaSuccesses) / float64(c.mfaAttempts) * 100)
		c.metricsReporter.ReportMetric(prefix+"_mfa_success_rate_percent", mfaSuccessRate, tags)
	}
}

// GetMetricsSummary returns a summary of key security metrics
func (c *SecurityMetricsCollector) GetMetricsSummary() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	summary := make(map[string]interface{})
	
	summary["auth_attempts"] = c.authAttempts
	summary["auth_successes"] = c.authSuccesses
	summary["auth_failures"] = c.authFailures
	summary["mfa_attempts"] = c.mfaAttempts
	summary["mfa_successes"] = c.mfaSuccesses
	summary["mfa_failures"] = c.mfaFailures
	summary["user_lockouts"] = c.userLockouts
	summary["alerts_triggered"] = c.alertsTriggered
	summary["suspicious_activities"] = c.suspiciousActivities
	summary["current_locked_users"] = c.currentLockedUsers
	summary["active_alerts"] = c.activeAlerts
	summary["average_risk_score"] = c.averageRiskScore
	summary["last_update"] = c.lastMetricsUpdate

	// Calculate rates
	if c.authAttempts > 0 {
		summary["auth_success_rate"] = float64(c.authSuccesses) / float64(c.authAttempts) * 100
	}
	if c.mfaAttempts > 0 {
		summary["mfa_success_rate"] = float64(c.mfaSuccesses) / float64(c.mfaAttempts) * 100
	}

	return summary
}

// ResetMetrics resets all metrics counters (useful for testing)
func (c *SecurityMetricsCollector) ResetMetrics() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.authAttempts = 0
	c.authSuccesses = 0
	c.authFailures = 0
	c.mfaAttempts = 0
	c.mfaSuccesses = 0
	c.mfaFailures = 0
	c.userLockouts = 0
	c.alertsTriggered = 0
	c.suspiciousActivities = 0
	c.currentLockedUsers = 0
	c.activeAlerts = 0
	c.averageRiskScore = 0
	c.authResponseTimes = make([]time.Duration, 0)
	c.riskScoreDistribution = make([]int, 0)
	c.metricsHistory = make([]*SecurityMetricsSnapshot, 0)
}