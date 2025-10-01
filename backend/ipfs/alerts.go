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
	"fmt"
	"log"
	"time"
)

// PinPriority is defined in pin_manager.go

// newAlertManager creates a new alert manager
func newAlertManager(config *MetricsConfig, logger *log.Logger) *AlertManager {
	am := &AlertManager{
		rules:                make([]AlertRule, 0),
		activeAlerts:         make(map[string]*Alert),
		alertHistory:         make([]*Alert, 0),
		notificationChannels: make([]NotificationChannel, 0),
	}
	
	// Initialize default alert rules
	am.initializeDefaultRules()
	
	// Initialize notification channels
	am.initializeNotificationChannels(logger)
	
	return am
}

// initializeDefaultRules sets up default alert rules for IPFS cluster
func (am *AlertManager) initializeDefaultRules() {
	// Critical: Cluster split-brain detected
	am.rules = append(am.rules, AlertRule{
		Name:        "cluster_split_brain",
		Description: "IPFS cluster split-brain situation detected",
		Condition:   &SplitBrainCondition{},
		Severity:    AlertSeverityCritical,
		Cooldown:    5 * time.Minute,
	})
	
	// Critical: High pin failure rate
	am.rules = append(am.rules, AlertRule{
		Name:        "high_pin_failure_rate",
		Description: "High rate of pin operation failures",
		Condition:   &PinFailureRateCondition{Threshold: 0.1}, // 10% failure rate
		Severity:    AlertSeverityCritical,
		Cooldown:    2 * time.Minute,
	})
	
	// Warning: High pin latency
	am.rules = append(am.rules, AlertRule{
		Name:        "high_pin_latency",
		Description: "Pin operations taking longer than expected",
		Condition:   &PinLatencyCondition{Threshold: 30 * time.Second},
		Severity:    AlertSeverityWarning,
		Cooldown:    5 * time.Minute,
	})
	
	// Warning: Low cluster health
	am.rules = append(am.rules, AlertRule{
		Name:        "low_cluster_health",
		Description: "Significant number of cluster nodes are unhealthy",
		Condition:   &ClusterHealthCondition{MinHealthyRatio: 0.7}, // 70% healthy nodes
		Severity:    AlertSeverityWarning,
		Cooldown:    3 * time.Minute,
	})
	
	// Warning: High queue depth
	am.rules = append(am.rules, AlertRule{
		Name:        "high_queue_depth",
		Description: "Pin operation queues are backing up",
		Condition:   &QueueDepthCondition{Threshold: 10000},
		Severity:    AlertSeverityWarning,
		Cooldown:    2 * time.Minute,
	})
	
	// Info: Low replication factor
	am.rules = append(am.rules, AlertRule{
		Name:        "low_replication_factor",
		Description: "Objects with insufficient replication detected",
		Condition:   &ReplicationFactorCondition{MinFactor: 3},
		Severity:    AlertSeverityInfo,
		Cooldown:    10 * time.Minute,
	})
}

// initializeNotificationChannels sets up notification channels
func (am *AlertManager) initializeNotificationChannels(logger *log.Logger) {
	// Add log notification channel (always available)
	am.notificationChannels = append(am.notificationChannels, &LogNotificationChannel{
		logger: logger,
	})
	
	// Additional channels would be configured based on environment
	// For example: Slack, email, webhook, etc.
}

// CheckAlerts evaluates all alert rules against current metrics
func (am *AlertManager) CheckAlerts(metrics map[string]interface{}) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	now := time.Now()
	
	for _, rule := range am.rules {
		// Check if rule is in cooldown
		if now.Sub(rule.LastFired) < rule.Cooldown {
			continue
		}
		
		// Evaluate condition
		if rule.Condition.Evaluate(metrics) {
			// Check if alert is already active
			alertID := fmt.Sprintf("%s_%d", rule.Name, now.Unix())
			if _, exists := am.activeAlerts[alertID]; !exists {
				// Create new alert
				alert := &Alert{
					ID:        alertID,
					Rule:      &rule,
					Timestamp: now,
					Resolved:  false,
					Message:   am.generateAlertMessage(&rule, metrics),
					Metadata:  am.extractRelevantMetrics(&rule, metrics),
				}
				
				// Add to active alerts
				am.activeAlerts[alertID] = alert
				
				// Add to history
				am.alertHistory = append(am.alertHistory, alert)
				
				// Update rule last fired time
				rule.LastFired = now
				
				// Send notifications
				am.sendAlert(alert)
			}
		}
	}
	
	// Check for resolved alerts
	am.checkResolvedAlerts(metrics)
}

// checkResolvedAlerts checks if any active alerts should be resolved
func (am *AlertManager) checkResolvedAlerts(metrics map[string]interface{}) {
	now := time.Now()
	
	for alertID, alert := range am.activeAlerts {
		if !alert.Resolved && !alert.Rule.Condition.Evaluate(metrics) {
			// Alert condition is no longer true, resolve it
			alert.Resolved = true
			alert.ResolvedAt = now
			
			// Remove from active alerts
			delete(am.activeAlerts, alertID)
			
			// Send resolution notification
			am.sendAlertResolution(alert)
		}
	}
}

// generateAlertMessage creates a human-readable alert message
func (am *AlertManager) generateAlertMessage(rule *AlertRule, metrics map[string]interface{}) string {
	switch rule.Name {
	case "cluster_split_brain":
		return "CRITICAL: IPFS cluster split-brain detected. Immediate attention required."
	case "high_pin_failure_rate":
		if pinMetrics, ok := metrics["pin_metrics"].(map[string]interface{}); ok {
			if errorRate, ok := pinMetrics["pin_error_rate"].(float64); ok {
				return fmt.Sprintf("CRITICAL: Pin failure rate is %.2f%%, exceeding threshold", errorRate*100)
			}
		}
		return "CRITICAL: High pin failure rate detected"
	case "high_pin_latency":
		if pinMetrics, ok := metrics["pin_metrics"].(map[string]interface{}); ok {
			if latency, ok := pinMetrics["pin_latency_p95"].(time.Duration); ok {
				return fmt.Sprintf("WARNING: Pin latency P95 is %v, exceeding threshold", latency)
			}
		}
		return "WARNING: High pin latency detected"
	case "low_cluster_health":
		if clusterMetrics, ok := metrics["cluster_metrics"].(map[string]interface{}); ok {
			if healthy, ok := clusterMetrics["healthy_nodes"].(int64); ok {
				if total, ok := clusterMetrics["total_nodes"].(int64); ok {
					ratio := float64(healthy) / float64(total)
					return fmt.Sprintf("WARNING: Cluster health is %.1f%% (%d/%d nodes healthy)", ratio*100, healthy, total)
				}
			}
		}
		return "WARNING: Low cluster health detected"
	case "high_queue_depth":
		if pinMetrics, ok := metrics["pin_metrics"].(map[string]interface{}); ok {
			if depth, ok := pinMetrics["queue_depth"].(int64); ok {
				return fmt.Sprintf("WARNING: Pin queue depth is %d, exceeding threshold", depth)
			}
		}
		return "WARNING: High queue depth detected"
	case "low_replication_factor":
		return "INFO: Objects with low replication factor detected"
	default:
		return fmt.Sprintf("Alert: %s - %s", rule.Name, rule.Description)
	}
}

// extractRelevantMetrics extracts metrics relevant to the alert
func (am *AlertManager) extractRelevantMetrics(rule *AlertRule, metrics map[string]interface{}) map[string]interface{} {
	relevant := make(map[string]interface{})
	
	switch rule.Name {
	case "cluster_split_brain":
		if clusterMetrics, ok := metrics["cluster_metrics"].(map[string]interface{}); ok {
			relevant["split_brain_count"] = clusterMetrics["split_brain_count"]
			relevant["last_split_brain"] = clusterMetrics["last_split_brain"]
		}
	case "high_pin_failure_rate":
		if pinMetrics, ok := metrics["pin_metrics"].(map[string]interface{}); ok {
			relevant["pin_error_rate"] = pinMetrics["pin_error_rate"]
			relevant["unpin_error_rate"] = pinMetrics["unpin_error_rate"]
		}
	case "high_pin_latency":
		if pinMetrics, ok := metrics["pin_metrics"].(map[string]interface{}); ok {
			relevant["pin_latency_p95"] = pinMetrics["pin_latency_p95"]
			relevant["pin_latency_p99"] = pinMetrics["pin_latency_p99"]
		}
	case "low_cluster_health":
		if clusterMetrics, ok := metrics["cluster_metrics"].(map[string]interface{}); ok {
			relevant["healthy_nodes"] = clusterMetrics["healthy_nodes"]
			relevant["unhealthy_nodes"] = clusterMetrics["unhealthy_nodes"]
			relevant["total_nodes"] = clusterMetrics["total_nodes"]
		}
	case "high_queue_depth":
		if pinMetrics, ok := metrics["pin_metrics"].(map[string]interface{}); ok {
			relevant["queue_depth"] = pinMetrics["queue_depth"]
		}
	}
	
	return relevant
}

// sendAlert sends alert notifications through all configured channels
func (am *AlertManager) sendAlert(alert *Alert) {
	for _, channel := range am.notificationChannels {
		if err := channel.SendAlert(alert); err != nil {
			// Log error but don't fail the alert
			fmt.Printf("Failed to send alert through %s: %v\n", channel.Name(), err)
		}
	}
}

// sendAlertResolution sends alert resolution notifications
func (am *AlertManager) sendAlertResolution(alert *Alert) {
	for _, channel := range am.notificationChannels {
		if resolutionChannel, ok := channel.(ResolutionNotificationChannel); ok {
			if err := resolutionChannel.SendResolution(alert); err != nil {
				fmt.Printf("Failed to send alert resolution through %s: %v\n", channel.Name(), err)
			}
		}
	}
}

// GetActiveAlerts returns all currently active alerts
func (am *AlertManager) GetActiveAlerts() []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	alerts := make([]*Alert, 0, len(am.activeAlerts))
	for _, alert := range am.activeAlerts {
		alerts = append(alerts, alert)
	}
	
	return alerts
}

// GetAlertHistory returns recent alert history
func (am *AlertManager) GetAlertHistory(limit int) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	if len(am.alertHistory) <= limit {
		result := make([]*Alert, len(am.alertHistory))
		copy(result, am.alertHistory)
		return result
	}
	
	// Return the most recent alerts
	start := len(am.alertHistory) - limit
	result := make([]*Alert, limit)
	copy(result, am.alertHistory[start:])
	return result
}

// cleanupHistory removes old alerts from history
func (am *AlertManager) cleanupHistory(cutoff time.Time) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	var filtered []*Alert
	for _, alert := range am.alertHistory {
		if alert.Timestamp.After(cutoff) {
			filtered = append(filtered, alert)
		}
	}
	am.alertHistory = filtered
}

// AddRule adds a custom alert rule
func (am *AlertManager) AddRule(rule AlertRule) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	am.rules = append(am.rules, rule)
}

// RemoveRule removes an alert rule by name
func (am *AlertManager) RemoveRule(name string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	for i, rule := range am.rules {
		if rule.Name == name {
			am.rules = append(am.rules[:i], am.rules[i+1:]...)
			return true
		}
	}
	return false
}

// AddNotificationChannel adds a notification channel
func (am *AlertManager) AddNotificationChannel(channel NotificationChannel) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	am.notificationChannels = append(am.notificationChannels, channel)
}

// Alert condition implementations

// SplitBrainCondition detects cluster split-brain situations
type SplitBrainCondition struct{}

func (c *SplitBrainCondition) Evaluate(metrics map[string]interface{}) bool {
	if clusterMetrics, ok := metrics["cluster_metrics"].(map[string]interface{}); ok {
		if splitCount, ok := clusterMetrics["split_brain_count"].(int64); ok {
			return splitCount > 0
		}
		if lastSplitBrain, ok := clusterMetrics["last_split_brain"].(time.Time); ok {
			// Consider split-brain active if it happened in the last 5 minutes
			return time.Since(lastSplitBrain) < 5*time.Minute
		}
	}
	return false
}

func (c *SplitBrainCondition) String() string {
	return "cluster split-brain detected"
}

// PinFailureRateCondition detects high pin failure rates
type PinFailureRateCondition struct {
	Threshold float64 // Failure rate threshold (0.0 to 1.0)
}

func (c *PinFailureRateCondition) Evaluate(metrics map[string]interface{}) bool {
	if pinMetrics, ok := metrics["pin_metrics"].(map[string]interface{}); ok {
		if errorRate, ok := pinMetrics["pin_error_rate"].(float64); ok {
			return errorRate > c.Threshold
		}
	}
	return false
}

func (c *PinFailureRateCondition) String() string {
	return fmt.Sprintf("pin failure rate > %.2f%%", c.Threshold*100)
}

// PinLatencyCondition detects high pin latencies
type PinLatencyCondition struct {
	Threshold time.Duration
}

func (c *PinLatencyCondition) Evaluate(metrics map[string]interface{}) bool {
	if pinMetrics, ok := metrics["pin_metrics"].(map[string]interface{}); ok {
		if latency, ok := pinMetrics["pin_latency_p95"].(time.Duration); ok {
			return latency > c.Threshold
		}
	}
	return false
}

func (c *PinLatencyCondition) String() string {
	return fmt.Sprintf("pin latency P95 > %v", c.Threshold)
}

// ClusterHealthCondition detects low cluster health
type ClusterHealthCondition struct {
	MinHealthyRatio float64 // Minimum ratio of healthy nodes (0.0 to 1.0)
}

func (c *ClusterHealthCondition) Evaluate(metrics map[string]interface{}) bool {
	if clusterMetrics, ok := metrics["cluster_metrics"].(map[string]interface{}); ok {
		if healthy, ok := clusterMetrics["healthy_nodes"].(int64); ok {
			if total, ok := clusterMetrics["total_nodes"].(int64); ok {
				if total > 0 {
					ratio := float64(healthy) / float64(total)
					return ratio < c.MinHealthyRatio
				}
			}
		}
	}
	return false
}

func (c *ClusterHealthCondition) String() string {
	return fmt.Sprintf("healthy nodes ratio < %.1f%%", c.MinHealthyRatio*100)
}

// QueueDepthCondition detects high queue depths
type QueueDepthCondition struct {
	Threshold int64
}

func (c *QueueDepthCondition) Evaluate(metrics map[string]interface{}) bool {
	if pinMetrics, ok := metrics["pin_metrics"].(map[string]interface{}); ok {
		if depth, ok := pinMetrics["queue_depth"].(int64); ok {
			return depth > c.Threshold
		}
	}
	return false
}

func (c *QueueDepthCondition) String() string {
	return fmt.Sprintf("queue depth > %d", c.Threshold)
}

// ReplicationFactorCondition detects low replication factors
type ReplicationFactorCondition struct {
	MinFactor int
}

func (c *ReplicationFactorCondition) Evaluate(metrics map[string]interface{}) bool {
	// This would need access to replication factor distribution
	// For now, return false as this requires more complex analysis
	return false
}

func (c *ReplicationFactorCondition) String() string {
	return fmt.Sprintf("replication factor < %d", c.MinFactor)
}

// Notification channel implementations

// LogNotificationChannel sends alerts to log
type LogNotificationChannel struct {
	logger *log.Logger
}

func (c *LogNotificationChannel) SendAlert(alert *Alert) error {
	severityStr := []string{"INFO", "WARNING", "CRITICAL", "EMERGENCY"}[alert.Rule.Severity]
	c.logger.Printf("[ALERT-%s] %s: %s", severityStr, alert.Rule.Name, alert.Message)
	return nil
}

func (c *LogNotificationChannel) Name() string {
	return "log"
}

// ResolutionNotificationChannel interface for channels that support resolution notifications
type ResolutionNotificationChannel interface {
	NotificationChannel
	SendResolution(alert *Alert) error
}

// Implement resolution for LogNotificationChannel
func (c *LogNotificationChannel) SendResolution(alert *Alert) error {
	c.logger.Printf("[ALERT-RESOLVED] %s: Alert resolved after %v", 
		alert.Rule.Name, alert.ResolvedAt.Sub(alert.Timestamp))
	return nil
}

// WebhookNotificationChannel sends alerts to webhook endpoints
type WebhookNotificationChannel struct {
	URL     string
	Headers map[string]string
}

func (c *WebhookNotificationChannel) SendAlert(alert *Alert) error {
	// Implementation would send HTTP POST to webhook URL
	// For now, just log that it would send
	fmt.Printf("Would send alert to webhook: %s\n", c.URL)
	return nil
}

func (c *WebhookNotificationChannel) SendResolution(alert *Alert) error {
	// Implementation would send HTTP POST to webhook URL
	fmt.Printf("Would send alert resolution to webhook: %s\n", c.URL)
	return nil
}

func (c *WebhookNotificationChannel) Name() string {
	return "webhook"
}