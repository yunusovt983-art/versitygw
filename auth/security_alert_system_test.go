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

func TestSecurityAlertSystem_TriggerAlert(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	system := NewSecurityAlertSystem(mockLogger, nil, nil)

	details := map[string]interface{}{
		"user_id":    "test-user",
		"ip_address": "192.168.1.100",
		"attempts":   5,
	}

	err := system.TriggerAlert(
		AlertTypeBruteForce,
		AlertSeverityHigh,
		"Brute force attack detected",
		"Multiple failed login attempts detected",
		details,
	)

	if err != nil {
		t.Fatalf("Failed to trigger alert: %v", err)
	}

	// Verify alert was stored
	alerts := system.GetAlerts(nil)
	if len(alerts) != 1 {
		t.Fatalf("Expected 1 alert, got %d", len(alerts))
	}

	alert := alerts[0]
	if alert.Type != AlertTypeBruteForce {
		t.Errorf("Expected alert type %s, got %s", AlertTypeBruteForce, alert.Type)
	}

	if alert.Severity != AlertSeverityHigh {
		t.Errorf("Expected severity %s, got %s", AlertSeverityHigh, alert.Severity)
	}

	if alert.UserID != "test-user" {
		t.Errorf("Expected user ID 'test-user', got '%s'", alert.UserID)
	}
}

func TestSecurityAlertSystem_RecordFailedAuthentication(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	thresholds := DefaultSecurityThresholds()
	thresholds.MaxFailedAttemptsPerUser = 3 // Lower threshold for testing
	
	system := NewSecurityAlertSystem(mockLogger, nil, thresholds)

	userID := "test-user"
	ipAddress := "192.168.1.100"
	reason := "Invalid password"

	// Record failed attempts below threshold
	for i := 0; i < 2; i++ {
		err := system.RecordFailedAuthentication(userID, ipAddress, reason)
		if err != nil {
			t.Fatalf("Failed to record authentication failure: %v", err)
		}

		// User should not be locked yet
		if system.IsUserLocked(userID) {
			t.Error("User should not be locked yet")
		}
	}

	// Record the attempt that should trigger lockout
	err := system.RecordFailedAuthentication(userID, ipAddress, reason)
	if err != nil {
		t.Fatalf("Failed to record authentication failure: %v", err)
	}

	// User should now be locked
	if !system.IsUserLocked(userID) {
		t.Error("User should be locked after exceeding threshold")
	}

	// Verify alert was triggered
	alerts := system.GetAlerts(&AlertFilter{Type: AlertTypeUserLocked})
	if len(alerts) != 1 {
		t.Fatalf("Expected 1 user locked alert, got %d", len(alerts))
	}
}

func TestUserLockManager_ProgressiveLockout(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	thresholds := DefaultSecurityThresholds()
	thresholds.MaxFailedAttemptsPerUser = 2
	thresholds.UserLockoutDuration = 1 * time.Minute
	thresholds.ProgressiveLockoutEnabled = true
	
	manager := NewUserLockManager(thresholds, mockLogger)
	userID := "test-user"

	// First lockout
	for i := 0; i < 2; i++ {
		manager.RecordFailedAttempt(userID, "192.168.1.100", "Invalid password")
	}
	shouldLock, duration := manager.RecordFailedAttempt(userID, "192.168.1.100", "Invalid password")
	
	if !shouldLock {
		t.Error("User should be locked after exceeding threshold")
	}
	
	if duration != 1*time.Minute {
		t.Errorf("Expected lockout duration 1m, got %v", duration)
	}

	// Simulate lock expiration
	status := manager.GetUserLockStatus(userID)
	status.Locked = false
	status.FailedAttempts = 0

	// Second lockout should have doubled duration
	for i := 0; i < 2; i++ {
		manager.RecordFailedAttempt(userID, "192.168.1.100", "Invalid password")
	}
	shouldLock, duration = manager.RecordFailedAttempt(userID, "192.168.1.100", "Invalid password")
	
	if !shouldLock {
		t.Error("User should be locked again")
	}
	
	if duration != 2*time.Minute {
		t.Errorf("Expected progressive lockout duration 2m, got %v", duration)
	}
}

func TestSecurityAlertSystem_AlertFiltering(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	system := NewSecurityAlertSystem(mockLogger, nil, nil)

	// Create multiple alerts
	alerts := []struct {
		alertType AlertType
		severity  AlertSeverity
		userID    string
		ipAddress string
	}{
		{AlertTypeBruteForce, AlertSeverityHigh, "user1", "192.168.1.100"},
		{AlertTypeDistributedAttack, AlertSeverityCritical, "user2", "192.168.1.101"},
		{AlertTypeBruteForce, AlertSeverityMedium, "user1", "192.168.1.102"},
		{AlertTypeUserLocked, AlertSeverityHigh, "user3", "192.168.1.100"},
	}

	for _, alert := range alerts {
		details := map[string]interface{}{
			"user_id":    alert.userID,
			"ip_address": alert.ipAddress,
		}
		system.TriggerAlert(alert.alertType, alert.severity, "Test alert", "Test description", details)
	}

	// Test filtering by type
	bruteForceAlerts := system.GetAlerts(&AlertFilter{Type: AlertTypeBruteForce})
	if len(bruteForceAlerts) != 2 {
		t.Errorf("Expected 2 brute force alerts, got %d", len(bruteForceAlerts))
	}

	// Test filtering by severity
	criticalAlerts := system.GetAlerts(&AlertFilter{Severity: AlertSeverityCritical})
	if len(criticalAlerts) != 1 {
		t.Errorf("Expected 1 critical alert, got %d", len(criticalAlerts))
	}

	// Test filtering by user
	user1Alerts := system.GetAlerts(&AlertFilter{UserID: "user1"})
	if len(user1Alerts) != 2 {
		t.Errorf("Expected 2 alerts for user1, got %d", len(user1Alerts))
	}

	// Test filtering by IP
	ipAlerts := system.GetAlerts(&AlertFilter{IPAddress: "192.168.1.100"})
	if len(ipAlerts) != 2 {
		t.Errorf("Expected 2 alerts for IP 192.168.1.100, got %d", len(ipAlerts))
	}
}

func TestSecurityAlertSystem_AlertCooldown(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	config := DefaultAlertSystemConfig()
	config.AlertCooldownPeriod = 1 * time.Second
	
	system := NewSecurityAlertSystem(mockLogger, config, nil)

	details := map[string]interface{}{
		"user_id":    "test-user",
		"ip_address": "192.168.1.100",
	}

	// Trigger first alert
	err := system.TriggerAlert(AlertTypeBruteForce, AlertSeverityHigh, "Test alert", "Test", details)
	if err != nil {
		t.Fatalf("Failed to trigger first alert: %v", err)
	}

	// Trigger duplicate alert immediately (should be ignored due to cooldown)
	err = system.TriggerAlert(AlertTypeBruteForce, AlertSeverityHigh, "Test alert", "Test", details)
	if err != nil {
		t.Fatalf("Failed to trigger duplicate alert: %v", err)
	}

	// Should only have one alert due to cooldown
	alerts := system.GetAlerts(nil)
	if len(alerts) != 1 {
		t.Errorf("Expected 1 alert due to cooldown, got %d", len(alerts))
	}

	// Wait for cooldown to expire
	time.Sleep(1100 * time.Millisecond)

	// Trigger alert again (should work now)
	err = system.TriggerAlert(AlertTypeBruteForce, AlertSeverityHigh, "Test alert", "Test", details)
	if err != nil {
		t.Fatalf("Failed to trigger alert after cooldown: %v", err)
	}

	// Should now have two alerts
	alerts = system.GetAlerts(nil)
	if len(alerts) != 2 {
		t.Errorf("Expected 2 alerts after cooldown, got %d", len(alerts))
	}
}

func TestSecurityAlertSystem_UnlockUser(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	thresholds := DefaultSecurityThresholds()
	thresholds.MaxFailedAttemptsPerUser = 2
	
	system := NewSecurityAlertSystem(mockLogger, nil, thresholds)
	userID := "test-user"

	// Lock the user
	for i := 0; i < 3; i++ {
		system.RecordFailedAuthentication(userID, "192.168.1.100", "Invalid password")
	}

	if !system.IsUserLocked(userID) {
		t.Error("User should be locked")
	}

	// Unlock the user
	err := system.UnlockUser(userID, "admin")
	if err != nil {
		t.Fatalf("Failed to unlock user: %v", err)
	}

	if system.IsUserLocked(userID) {
		t.Error("User should be unlocked")
	}

	// Try to unlock already unlocked user
	err = system.UnlockUser(userID, "admin")
	if err == nil {
		t.Error("Expected error when unlocking already unlocked user")
	}
}

func TestSecurityAlertSystem_UpdateThresholds(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	system := NewSecurityAlertSystem(mockLogger, nil, nil)

	// Get original thresholds
	originalThresholds := system.GetThresholds()
	originalMaxAttempts := originalThresholds.MaxFailedAttemptsPerUser

	// Update thresholds
	newThresholds := DefaultSecurityThresholds()
	newThresholds.MaxFailedAttemptsPerUser = originalMaxAttempts + 10
	
	system.UpdateThresholds(newThresholds)

	// Verify thresholds were updated
	updatedThresholds := system.GetThresholds()
	if updatedThresholds.MaxFailedAttemptsPerUser != originalMaxAttempts+10 {
		t.Errorf("Expected max attempts %d, got %d", 
			originalMaxAttempts+10, updatedThresholds.MaxFailedAttemptsPerUser)
	}

	// Verify original object wasn't modified (should be a copy)
	if originalThresholds.MaxFailedAttemptsPerUser != originalMaxAttempts {
		t.Error("Original thresholds object was modified")
	}
}

func TestUserLockManager_LockExpiration(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	thresholds := DefaultSecurityThresholds()
	thresholds.MaxFailedAttemptsPerUser = 2
	thresholds.UserLockoutDuration = 100 * time.Millisecond // Very short for testing
	
	manager := NewUserLockManager(thresholds, mockLogger)
	userID := "test-user"

	// Lock the user
	for i := 0; i < 3; i++ {
		manager.RecordFailedAttempt(userID, "192.168.1.100", "Invalid password")
	}

	if !manager.IsUserLocked(userID) {
		t.Error("User should be locked")
	}

	// Wait for lock to expire
	time.Sleep(150 * time.Millisecond)

	// User should be automatically unlocked
	if manager.IsUserLocked(userID) {
		t.Error("User should be automatically unlocked after expiration")
	}
}

func TestLogAlertHandler_HandleAlert(t *testing.T) {
	handler := &LogAlertHandler{LogLevel: "warn"}
	
	alert := &SecurityAlert{
		ID:          "test-alert-1",
		Type:        AlertTypeBruteForce,
		Severity:    AlertSeverityHigh,
		Title:       "Test Alert",
		Description: "Test alert description",
		UserID:      "test-user",
		IPAddress:   "192.168.1.100",
		Timestamp:   time.Now(),
	}

	err := handler.HandleAlert(alert)
	if err != nil {
		t.Errorf("LogAlertHandler should not return error, got: %v", err)
	}
}

func TestWebhookAlertHandler_HandleAlert(t *testing.T) {
	handler := &WebhookAlertHandler{
		WebhookURL: "https://example.com/webhook",
		Timeout:    5 * time.Second,
	}
	
	alert := &SecurityAlert{
		ID:          "test-alert-1",
		Type:        AlertTypeBruteForce,
		Severity:    AlertSeverityHigh,
		Title:       "Test Alert",
		Description: "Test alert description",
		UserID:      "test-user",
		IPAddress:   "192.168.1.100",
		Timestamp:   time.Now(),
	}

	err := handler.HandleAlert(alert)
	if err != nil {
		t.Errorf("WebhookAlertHandler should not return error, got: %v", err)
	}
}

func TestEmailAlertHandler_HandleAlert(t *testing.T) {
	handler := &EmailAlertHandler{
		SMTPServer: "smtp.example.com",
		SMTPPort:   587,
		Recipients: []string{"admin@example.com"},
	}
	
	alert := &SecurityAlert{
		ID:          "test-alert-1",
		Type:        AlertTypeBruteForce,
		Severity:    AlertSeverityHigh,
		Title:       "Test Alert",
		Description: "Test alert description",
		UserID:      "test-user",
		IPAddress:   "192.168.1.100",
		Timestamp:   time.Now(),
	}

	err := handler.HandleAlert(alert)
	if err != nil {
		t.Errorf("EmailAlertHandler should not return error, got: %v", err)
	}
}

func TestSecurityAlertSystem_TimeRangeFiltering(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	system := NewSecurityAlertSystem(mockLogger, nil, nil)

	// Create alerts at different times
	details1 := map[string]interface{}{"user_id": "user1"}
	details2 := map[string]interface{}{"user_id": "user2"}
	details3 := map[string]interface{}{"user_id": "user3"}

	system.TriggerAlert(AlertTypeBruteForce, AlertSeverityHigh, "Alert 1", "Description 1", details1)
	
	// Simulate time passing
	time.Sleep(10 * time.Millisecond)
	midTime := time.Now()
	time.Sleep(10 * time.Millisecond)
	
	system.TriggerAlert(AlertTypeBruteForce, AlertSeverityHigh, "Alert 2", "Description 2", details2)
	system.TriggerAlert(AlertTypeBruteForce, AlertSeverityHigh, "Alert 3", "Description 3", details3)

	// Test filtering by start time
	startTimeFilter := &AlertFilter{StartTime: &midTime}
	recentAlerts := system.GetAlerts(startTimeFilter)
	if len(recentAlerts) != 2 {
		t.Errorf("Expected 2 alerts after midTime, got %d", len(recentAlerts))
	}

	// Test filtering by end time
	endTimeFilter := &AlertFilter{EndTime: &midTime}
	oldAlerts := system.GetAlerts(endTimeFilter)
	if len(oldAlerts) != 1 {
		t.Errorf("Expected 1 alert before midTime, got %d", len(oldAlerts))
	}
}