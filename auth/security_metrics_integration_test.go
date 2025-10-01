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
	"testing"
	"time"
)

// MockMetricsReporter for testing
type MockMetricsReporter struct {
	metrics map[string]int64
}

func NewMockMetricsReporter() *MockMetricsReporter {
	return &MockMetricsReporter{
		metrics: make(map[string]int64),
	}
}

func (m *MockMetricsReporter) ReportMetric(key string, value int64, tags map[string]string) {
	m.metrics[key] = value
}

func (m *MockMetricsReporter) GetMetric(name string) int64 {
	return m.metrics[name]
}

func TestSecurityMetricsCollector_ReportAuthenticationAttempt(t *testing.T) {
	mockMetrics := NewMockMetricsReporter()
	mockLogger := &MockSecurityAuditLogger{}
	alertSystem := NewSecurityAlertSystem(mockLogger, nil, nil)
	
	collector := NewSecurityMetricsCollector(mockMetrics, alertSystem, nil)

	// Report successful authentication
	collector.ReportAuthenticationAttempt(true, 100*time.Millisecond, 25)
	
	// Report failed authentication
	collector.ReportAuthenticationAttempt(false, 200*time.Millisecond, 75)

	metrics := collector.GetCurrentMetrics()
	
	if metrics.AuthAttempts != 2 {
		t.Errorf("Expected 2 auth attempts, got %d", metrics.AuthAttempts)
	}
	
	if metrics.AuthSuccesses != 1 {
		t.Errorf("Expected 1 auth success, got %d", metrics.AuthSuccesses)
	}
	
	if metrics.AuthFailures != 1 {
		t.Errorf("Expected 1 auth failure, got %d", metrics.AuthFailures)
	}
	
	if metrics.AuthSuccessRate != 50.0 {
		t.Errorf("Expected 50%% success rate, got %.2f%%", metrics.AuthSuccessRate)
	}
}

func TestSecurityMetricsCollector_ReportMFAAttempt(t *testing.T) {
	mockMetrics := NewMockMetricsReporter()
	mockLogger := &MockSecurityAuditLogger{}
	alertSystem := NewSecurityAlertSystem(mockLogger, nil, nil)
	
	collector := NewSecurityMetricsCollector(mockMetrics, alertSystem, nil)

	// Report successful MFA
	collector.ReportMFAAttempt(true, "totp")
	
	// Report failed MFA
	collector.ReportMFAAttempt(false, "backup_code")
	collector.ReportMFAAttempt(false, "totp")

	metrics := collector.GetCurrentMetrics()
	
	if metrics.MFAAttempts != 3 {
		t.Errorf("Expected 3 MFA attempts, got %d", metrics.MFAAttempts)
	}
	
	if metrics.MFASuccesses != 1 {
		t.Errorf("Expected 1 MFA success, got %d", metrics.MFASuccesses)
	}
	
	if metrics.MFAFailures != 2 {
		t.Errorf("Expected 2 MFA failures, got %d", metrics.MFAFailures)
	}
	
	expectedRate := float64(1) / float64(3) * 100
	if metrics.MFASuccessRate != expectedRate {
		t.Errorf("Expected %.2f%% MFA success rate, got %.2f%%", expectedRate, metrics.MFASuccessRate)
	}
}

func TestSecurityMetricsCollector_ReportUserLockout(t *testing.T) {
	mockMetrics := NewMockMetricsReporter()
	mockLogger := &MockSecurityAuditLogger{}
	alertSystem := NewSecurityAlertSystem(mockLogger, nil, nil)
	
	collector := NewSecurityMetricsCollector(mockMetrics, alertSystem, nil)

	// Report user lockouts
	collector.ReportUserLockout("user1", "Too many failed attempts", 15*time.Minute)
	collector.ReportUserLockout("user2", "Suspicious activity", 30*time.Minute)

	metrics := collector.GetCurrentMetrics()
	
	if metrics.UserLockouts != 2 {
		t.Errorf("Expected 2 user lockouts, got %d", metrics.UserLockouts)
	}
}

func TestSecurityMetricsCollector_ReportAlert(t *testing.T) {
	mockMetrics := NewMockMetricsReporter()
	mockLogger := &MockSecurityAuditLogger{}
	alertSystem := NewSecurityAlertSystem(mockLogger, nil, nil)
	
	collector := NewSecurityMetricsCollector(mockMetrics, alertSystem, nil)

	// Report alerts
	collector.ReportAlert(AlertTypeBruteForce, AlertSeverityHigh)
	collector.ReportAlert(AlertTypeDistributedAttack, AlertSeverityCritical)
	collector.ReportAlert(AlertTypeUserLocked, AlertSeverityMedium)

	metrics := collector.GetCurrentMetrics()
	
	if metrics.AlertsTriggered != 3 {
		t.Errorf("Expected 3 alerts triggered, got %d", metrics.AlertsTriggered)
	}
}

func TestSecurityMetricsCollector_ReportSuspiciousActivity(t *testing.T) {
	mockMetrics := NewMockMetricsReporter()
	mockLogger := &MockSecurityAuditLogger{}
	alertSystem := NewSecurityAlertSystem(mockLogger, nil, nil)
	
	collector := NewSecurityMetricsCollector(mockMetrics, alertSystem, nil)

	// Report suspicious activities
	collector.ReportSuspiciousActivity("brute_force", SeverityHigh)
	collector.ReportSuspiciousActivity("account_enumeration", SeverityMedium)

	metrics := collector.GetCurrentMetrics()
	
	if metrics.SuspiciousActivities != 2 {
		t.Errorf("Expected 2 suspicious activities, got %d", metrics.SuspiciousActivities)
	}
}

func TestSecurityMetricsCollector_GetMetricsHistory(t *testing.T) {
	mockMetrics := NewMockMetricsReporter()
	mockLogger := &MockSecurityAuditLogger{}
	alertSystem := NewSecurityAlertSystem(mockLogger, nil, nil)
	
	config := DefaultSecurityMetricsConfig()
	config.CollectionInterval = 50 * time.Millisecond // Fast collection for testing
	
	collector := NewSecurityMetricsCollector(mockMetrics, alertSystem, config)

	// Report some metrics
	collector.ReportAuthenticationAttempt(true, 100*time.Millisecond, 25)
	collector.ReportAuthenticationAttempt(false, 200*time.Millisecond, 75)

	// Wait for at least one collection cycle
	time.Sleep(100 * time.Millisecond)

	// Get history
	history := collector.GetMetricsHistory(1 * time.Hour)
	
	if len(history) == 0 {
		t.Error("Expected at least one metrics snapshot in history")
	}

	// Verify the snapshot contains our data
	if len(history) > 0 {
		snapshot := history[len(history)-1] // Get latest snapshot
		if snapshot.AuthAttempts != 2 {
			t.Errorf("Expected 2 auth attempts in snapshot, got %d", snapshot.AuthAttempts)
		}
	}
}

func TestSecurityMetricsCollector_GetMetricsSummary(t *testing.T) {
	mockMetrics := NewMockMetricsReporter()
	mockLogger := &MockSecurityAuditLogger{}
	alertSystem := NewSecurityAlertSystem(mockLogger, nil, nil)
	
	collector := NewSecurityMetricsCollector(mockMetrics, alertSystem, nil)

	// Report various metrics
	collector.ReportAuthenticationAttempt(true, 100*time.Millisecond, 25)
	collector.ReportAuthenticationAttempt(false, 200*time.Millisecond, 75)
	collector.ReportMFAAttempt(true, "totp")
	collector.ReportUserLockout("user1", "Failed attempts", 15*time.Minute)
	collector.ReportAlert(AlertTypeBruteForce, AlertSeverityHigh)
	collector.ReportSuspiciousActivity("enumeration", SeverityMedium)

	summary := collector.GetMetricsSummary()
	
	// Verify all expected keys are present
	expectedKeys := []string{
		"auth_attempts", "auth_successes", "auth_failures",
		"mfa_attempts", "mfa_successes", "mfa_failures",
		"user_lockouts", "alerts_triggered", "suspicious_activities",
		"current_locked_users", "active_alerts", "average_risk_score",
		"last_update", "auth_success_rate", "mfa_success_rate",
	}

	for _, key := range expectedKeys {
		if _, exists := summary[key]; !exists {
			t.Errorf("Expected key '%s' in metrics summary", key)
		}
	}

	// Verify some specific values
	if summary["auth_attempts"] != int64(2) {
		t.Errorf("Expected 2 auth attempts, got %v", summary["auth_attempts"])
	}
	
	if summary["auth_success_rate"] != 50.0 {
		t.Errorf("Expected 50%% auth success rate, got %v", summary["auth_success_rate"])
	}
}

func TestSecurityMetricsCollector_ResetMetrics(t *testing.T) {
	mockMetrics := NewMockMetricsReporter()
	mockLogger := &MockSecurityAuditLogger{}
	alertSystem := NewSecurityAlertSystem(mockLogger, nil, nil)
	
	collector := NewSecurityMetricsCollector(mockMetrics, alertSystem, nil)

	// Report some metrics
	collector.ReportAuthenticationAttempt(true, 100*time.Millisecond, 25)
	collector.ReportMFAAttempt(false, "totp")
	collector.ReportUserLockout("user1", "Failed attempts", 15*time.Minute)

	// Verify metrics are not zero
	metrics := collector.GetCurrentMetrics()
	if metrics.AuthAttempts == 0 {
		t.Error("Expected non-zero auth attempts before reset")
	}

	// Reset metrics
	collector.ResetMetrics()

	// Verify metrics are reset
	metrics = collector.GetCurrentMetrics()
	if metrics.AuthAttempts != 0 {
		t.Errorf("Expected 0 auth attempts after reset, got %d", metrics.AuthAttempts)
	}
	
	if metrics.MFAAttempts != 0 {
		t.Errorf("Expected 0 MFA attempts after reset, got %d", metrics.MFAAttempts)
	}
	
	if metrics.UserLockouts != 0 {
		t.Errorf("Expected 0 user lockouts after reset, got %d", metrics.UserLockouts)
	}
}

func TestSecurityMetricsCollector_DetailedMetrics(t *testing.T) {
	mockMetrics := NewMockMetricsReporter()
	mockLogger := &MockSecurityAuditLogger{}
	alertSystem := NewSecurityAlertSystem(mockLogger, nil, nil)
	
	config := DefaultSecurityMetricsConfig()
	config.EnableDetailedMetrics = true
	
	collector := NewSecurityMetricsCollector(mockMetrics, alertSystem, config)

	// Report authentication attempts with different response times and risk scores
	collector.ReportAuthenticationAttempt(true, 50*time.Millisecond, 10)
	collector.ReportAuthenticationAttempt(true, 100*time.Millisecond, 20)
	collector.ReportAuthenticationAttempt(false, 200*time.Millisecond, 80)
	collector.ReportAuthenticationAttempt(false, 150*time.Millisecond, 90)

	// Wait for metrics collection
	time.Sleep(100 * time.Millisecond)

	metrics := collector.GetCurrentMetrics()
	
	// Average risk score should be calculated
	expectedAvgRisk := float64(10+20+80+90) / 4.0
	if metrics.AverageRiskScore != expectedAvgRisk {
		t.Errorf("Expected average risk score %.2f, got %.2f", expectedAvgRisk, metrics.AverageRiskScore)
	}
}

func TestSecurityMetricsCollector_HistoryCleanup(t *testing.T) {
	mockMetrics := NewMockMetricsReporter()
	mockLogger := &MockSecurityAuditLogger{}
	alertSystem := NewSecurityAlertSystem(mockLogger, nil, nil)
	
	config := DefaultSecurityMetricsConfig()
	config.MaxHistoryEntries = 3 // Small limit for testing
	config.CollectionInterval = 10 * time.Millisecond
	
	collector := NewSecurityMetricsCollector(mockMetrics, alertSystem, config)

	// Wait for several collection cycles to generate history
	time.Sleep(100 * time.Millisecond)

	history := collector.GetMetricsHistory(1 * time.Hour)
	
	// Should not exceed max entries
	if len(history) > config.MaxHistoryEntries {
		t.Errorf("Expected at most %d history entries, got %d", config.MaxHistoryEntries, len(history))
	}
}

func TestSecurityMetricsSnapshot_CalculateRates(t *testing.T) {
	mockMetrics := NewMockMetricsReporter()
	mockLogger := &MockSecurityAuditLogger{}
	alertSystem := NewSecurityAlertSystem(mockLogger, nil, nil)
	
	collector := NewSecurityMetricsCollector(mockMetrics, alertSystem, nil)

	// Report mixed success/failure attempts
	collector.ReportAuthenticationAttempt(true, 100*time.Millisecond, 25)
	collector.ReportAuthenticationAttempt(true, 100*time.Millisecond, 25)
	collector.ReportAuthenticationAttempt(false, 100*time.Millisecond, 75)
	collector.ReportAuthenticationAttempt(false, 100*time.Millisecond, 75)

	collector.ReportMFAAttempt(true, "totp")
	collector.ReportMFAAttempt(false, "totp")
	collector.ReportMFAAttempt(false, "totp")

	snapshot := collector.GetCurrentMetrics()
	
	// Auth success rate should be 50% (2 successes out of 4 attempts)
	if snapshot.AuthSuccessRate != 50.0 {
		t.Errorf("Expected 50%% auth success rate, got %.2f%%", snapshot.AuthSuccessRate)
	}
	
	// MFA success rate should be 33.33% (1 success out of 3 attempts)
	expectedMFARate := float64(1) / float64(3) * 100
	if snapshot.MFASuccessRate != expectedMFARate {
		t.Errorf("Expected %.2f%% MFA success rate, got %.2f%%", expectedMFARate, snapshot.MFASuccessRate)
	}
}