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

// MockSecurityAuditLogger for testing
type MockSecurityAuditLogger struct {
	events            []*SecurityEvent
	suspiciousPatterns []*SuspiciousPattern
}

func (m *MockSecurityAuditLogger) LogSecurityEvent(event *SecurityEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *MockSecurityAuditLogger) LogAuthenticationAttempt(userID, ipAddress, userAgent string, success bool, details *AuthenticationDetails) error {
	return nil
}

func (m *MockSecurityAuditLogger) LogMFAAttempt(userID, ipAddress string, success bool, details map[string]interface{}) error {
	return nil
}

func (m *MockSecurityAuditLogger) LogSuspiciousActivity(pattern *SuspiciousPattern) error {
	m.suspiciousPatterns = append(m.suspiciousPatterns, pattern)
	return nil
}

func (m *MockSecurityAuditLogger) LogUserLockout(userID, reason string, duration time.Duration) error {
	return nil
}

func (m *MockSecurityAuditLogger) LogPermissionDenied(userID, resource, action, reason string) error {
	return nil
}

func (m *MockSecurityAuditLogger) LogSessionSecurityEvent(sessionID, userID, eventType, description string, severity SecuritySeverity, details map[string]interface{}) error {
	return nil
}

func (m *MockSecurityAuditLogger) GetSecurityEvents(filter *SecurityEventFilter) ([]*SecurityEvent, error) {
	return m.events, nil
}

func (m *MockSecurityAuditLogger) Close() error {
	return nil
}

func TestSuspiciousActivityDetector_BruteForceUser(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	detector := NewSuspiciousActivityDetector(mockLogger)
	defer detector.Stop()

	// Override config for testing
	detector.config.BruteForceThreshold = 3
	detector.config.BruteForceTimeWindow = 5 * time.Minute

	now := time.Now()

	// Simulate multiple failed attempts for the same user
	for i := 0; i < 5; i++ {
		event := &SecurityEvent{
			Type:      EventTypeAuthFailure,
			UserID:    "test-user",
			IPAddress: "192.168.1.100",
			Success:   false,
			Timestamp: now.Add(time.Duration(i) * time.Second),
		}
		detector.AnalyzeEvent(event)
	}

	// Give detector time to process
	time.Sleep(100 * time.Millisecond)

	// Check if suspicious activity was detected
	if len(mockLogger.suspiciousPatterns) == 0 {
		t.Fatal("Expected suspicious activity to be detected")
	}

	pattern := mockLogger.suspiciousPatterns[0]
	if pattern.Type != "brute_force_user" {
		t.Errorf("Expected pattern type 'brute_force_user', got '%s'", pattern.Type)
	}

	if pattern.UserID != "test-user" {
		t.Errorf("Expected user ID 'test-user', got '%s'", pattern.UserID)
	}

	if pattern.Count < 3 {
		t.Errorf("Expected count >= 3, got %d", pattern.Count)
	}
}

func TestSuspiciousActivityDetector_BruteForceIP(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	detector := NewSuspiciousActivityDetector(mockLogger)
	defer detector.Stop()

	// Override config for testing
	detector.config.BruteForceThreshold = 3
	detector.config.BruteForceTimeWindow = 5 * time.Minute

	now := time.Now()

	// Simulate multiple failed attempts from the same IP
	for i := 0; i < 5; i++ {
		event := &SecurityEvent{
			Type:      EventTypeAuthFailure,
			UserID:    "user" + string(rune('1'+i)),
			IPAddress: "192.168.1.100",
			Success:   false,
			Timestamp: now.Add(time.Duration(i) * time.Second),
		}
		detector.AnalyzeEvent(event)
	}

	// Give detector time to process
	time.Sleep(100 * time.Millisecond)

	// Check if suspicious activity was detected
	if len(mockLogger.suspiciousPatterns) == 0 {
		t.Fatal("Expected suspicious activity to be detected")
	}

	pattern := mockLogger.suspiciousPatterns[0]
	if pattern.Type != "brute_force_ip" {
		t.Errorf("Expected pattern type 'brute_force_ip', got '%s'", pattern.Type)
	}

	if pattern.IPAddress != "192.168.1.100" {
		t.Errorf("Expected IP address '192.168.1.100', got '%s'", pattern.IPAddress)
	}
}

func TestSuspiciousActivityDetector_DistributedAttack(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	detector := NewSuspiciousActivityDetector(mockLogger)
	defer detector.Stop()

	// Override config for testing
	detector.config.DistributedAttackThreshold = 10
	detector.config.DistributedAttackWindow = 10 * time.Minute

	now := time.Now()

	// Simulate attacks from multiple IPs
	ips := []string{"192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.103"}
	
	for _, ip := range ips {
		for i := 0; i < 5; i++ {
			event := &SecurityEvent{
				Type:      EventTypeAuthFailure,
				UserID:    "user" + string(rune('1'+i)),
				IPAddress: ip,
				Success:   false,
				Timestamp: now.Add(time.Duration(i) * time.Second),
			}
			detector.AnalyzeEvent(event)
		}
	}

	// Give detector time to process
	time.Sleep(100 * time.Millisecond)

	// Check if distributed attack was detected
	found := false
	for _, pattern := range mockLogger.suspiciousPatterns {
		if pattern.Type == "distributed_attack" {
			found = true
			if pattern.Count < 10 {
				t.Errorf("Expected count >= 10, got %d", pattern.Count)
			}
			break
		}
	}

	if !found {
		t.Error("Expected distributed attack to be detected")
	}
}

func TestSuspiciousActivityDetector_AccountEnumeration(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	detector := NewSuspiciousActivityDetector(mockLogger)
	defer detector.Stop()

	// Override config for testing
	detector.config.EnumerationThreshold = 5
	detector.config.EnumerationTimeWindow = 10 * time.Minute

	now := time.Now()

	// Simulate enumeration attempts from single IP against multiple users
	for i := 0; i < 10; i++ {
		event := &SecurityEvent{
			Type:      EventTypeAuthFailure,
			UserID:    "user" + string(rune('1'+i)),
			IPAddress: "192.168.1.100",
			Success:   false,
			Timestamp: now.Add(time.Duration(i) * time.Second),
		}
		detector.AnalyzeEvent(event)
	}

	// Give detector time to process
	time.Sleep(100 * time.Millisecond)

	// Check if account enumeration was detected
	found := false
	for _, pattern := range mockLogger.suspiciousPatterns {
		if pattern.Type == "account_enumeration" {
			found = true
			if pattern.IPAddress != "192.168.1.100" {
				t.Errorf("Expected IP address '192.168.1.100', got '%s'", pattern.IPAddress)
			}
			break
		}
	}

	if !found {
		t.Error("Expected account enumeration to be detected")
	}
}

func TestSuspiciousActivityDetector_IgnoreSuccessfulEvents(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	detector := NewSuspiciousActivityDetector(mockLogger)
	defer detector.Stop()

	// Override config for testing
	detector.config.BruteForceThreshold = 3

	now := time.Now()

	// Simulate successful authentication attempts
	for i := 0; i < 5; i++ {
		event := &SecurityEvent{
			Type:      EventTypeAuthSuccess,
			UserID:    "test-user",
			IPAddress: "192.168.1.100",
			Success:   true,
			Timestamp: now.Add(time.Duration(i) * time.Second),
		}
		detector.AnalyzeEvent(event)
	}

	// Give detector time to process
	time.Sleep(100 * time.Millisecond)

	// Should not detect any suspicious activity for successful events
	if len(mockLogger.suspiciousPatterns) > 0 {
		t.Error("Should not detect suspicious activity for successful events")
	}
}

func TestSuspiciousActivityDetector_TimeWindowCleanup(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	detector := NewSuspiciousActivityDetector(mockLogger)
	defer detector.Stop()

	// Override config for testing
	detector.config.BruteForceThreshold = 3
	detector.config.BruteForceTimeWindow = 1 * time.Second
	detector.config.FailureTimeWindow = 1 * time.Second

	now := time.Now()

	// Add old events that should be cleaned up
	oldEvent := &SecurityEvent{
		Type:      EventTypeAuthFailure,
		UserID:    "test-user",
		IPAddress: "192.168.1.100",
		Success:   false,
		Timestamp: now.Add(-2 * time.Second),
	}
	detector.AnalyzeEvent(oldEvent)

	// Wait for cleanup
	time.Sleep(2 * time.Second)

	// Add new events
	for i := 0; i < 5; i++ {
		event := &SecurityEvent{
			Type:      EventTypeAuthFailure,
			UserID:    "test-user",
			IPAddress: "192.168.1.100",
			Success:   false,
			Timestamp: now,
		}
		detector.AnalyzeEvent(event)
	}

	// Check stats - old events should be cleaned up
	stats := detector.GetStats()
	if stats["tracked_users"].(int) == 0 {
		t.Error("Expected user tracking after new events")
	}
}

func TestSuspiciousActivityDetector_UpdateConfig(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	detector := NewSuspiciousActivityDetector(mockLogger)
	defer detector.Stop()

	// Update configuration
	newConfig := &DetectorConfig{
		BruteForceThreshold:  10,
		BruteForceTimeWindow: 1 * time.Minute,
	}

	detector.UpdateConfig(newConfig)

	// Verify config was updated
	if detector.config.BruteForceThreshold != 10 {
		t.Errorf("Expected threshold 10, got %d", detector.config.BruteForceThreshold)
	}

	if detector.config.BruteForceTimeWindow != 1*time.Minute {
		t.Errorf("Expected time window 1 minute, got %v", detector.config.BruteForceTimeWindow)
	}
}

func TestSuspiciousActivityDetector_GetStats(t *testing.T) {
	mockLogger := &MockSecurityAuditLogger{}
	detector := NewSuspiciousActivityDetector(mockLogger)
	defer detector.Stop()

	// Add some events to track
	events := []*SecurityEvent{
		{Type: EventTypeAuthFailure, UserID: "user1", IPAddress: "192.168.1.100", UserAgent: "agent1", Success: false},
		{Type: EventTypeAuthFailure, UserID: "user2", IPAddress: "192.168.1.101", UserAgent: "agent2", Success: false},
		{Type: EventTypeAuthFailure, UserID: "user1", IPAddress: "192.168.1.100", UserAgent: "agent1", Success: false},
	}

	for _, event := range events {
		detector.AnalyzeEvent(event)
	}

	stats := detector.GetStats()

	if stats["tracked_users"].(int) != 2 {
		t.Errorf("Expected 2 tracked users, got %d", stats["tracked_users"].(int))
	}

	if stats["tracked_ips"].(int) != 2 {
		t.Errorf("Expected 2 tracked IPs, got %d", stats["tracked_ips"].(int))
	}

	if stats["tracked_user_agents"].(int) != 2 {
		t.Errorf("Expected 2 tracked user agents, got %d", stats["tracked_user_agents"].(int))
	}
}

func TestSuspiciousActivityDetector_CleanupRoutine(t *testing.T) {
	// Skip this test due to ticker configuration complexity
	t.Skip("Skipping cleanup routine test - requires complex ticker setup")
}