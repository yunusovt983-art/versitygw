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

func TestSecurityAuditLogger_LogSecurityEvent(t *testing.T) {
	logger := NewSecurityAuditLogger(nil)
	defer logger.Close()

	event := &SecurityEvent{
		Type:      EventTypeAuthFailure,
		Severity:  SeverityHigh,
		UserID:    "test-user",
		IPAddress: "192.168.1.100",
		Success:   false,
		Message:   "Authentication failed",
	}

	err := logger.LogSecurityEvent(event)
	if err != nil {
		t.Fatalf("Failed to log security event: %v", err)
	}

	// Verify event was stored
	events, err := logger.GetSecurityEvents(nil)
	if err != nil {
		t.Fatalf("Failed to get security events: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	if events[0].Type != EventTypeAuthFailure {
		t.Errorf("Expected event type %s, got %s", EventTypeAuthFailure, events[0].Type)
	}
}

func TestSecurityAuditLogger_LogAuthenticationAttempt(t *testing.T) {
	logger := NewSecurityAuditLogger(nil)
	defer logger.Close()

	details := &AuthenticationDetails{
		UserID:         "test-user",
		AuthMethod:     "signature_v4",
		MFAEnabled:     true,
		MFAUsed:        false,
		FailedAttempts: 3,
		AccountLocked:  false,
	}

	err := logger.LogAuthenticationAttempt("test-user", "192.168.1.100", "test-agent", false, details)
	if err != nil {
		t.Fatalf("Failed to log authentication attempt: %v", err)
	}

	// Verify event was stored
	events, err := logger.GetSecurityEvents(&SecurityEventFilter{
		EventType: EventTypeAuthFailure,
	})
	if err != nil {
		t.Fatalf("Failed to get security events: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.UserID != "test-user" {
		t.Errorf("Expected user ID 'test-user', got '%s'", event.UserID)
	}

	if event.Success {
		t.Error("Expected failed authentication")
	}

	if event.Details["mfa_enabled"] != true {
		t.Error("Expected MFA enabled to be true")
	}
}

func TestSecurityAuditLogger_LogMFAAttempt(t *testing.T) {
	logger := NewSecurityAuditLogger(nil)
	defer logger.Close()

	details := map[string]interface{}{
		"mfa_method": "totp",
		"token_used": "123456",
	}

	err := logger.LogMFAAttempt("test-user", "192.168.1.100", true, details)
	if err != nil {
		t.Fatalf("Failed to log MFA attempt: %v", err)
	}

	// Verify event was stored
	events, err := logger.GetSecurityEvents(&SecurityEventFilter{
		EventType: EventTypeMFASuccess,
	})
	if err != nil {
		t.Fatalf("Failed to get security events: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]
	if !event.MFAUsed {
		t.Error("Expected MFA used to be true")
	}

	if event.Details["mfa_method"] != "totp" {
		t.Error("Expected MFA method to be 'totp'")
	}
}

func TestSecurityAuditLogger_LogSuspiciousActivity(t *testing.T) {
	logger := NewSecurityAuditLogger(nil)
	defer logger.Close()

	pattern := &SuspiciousPattern{
		Type:        "brute_force",
		Description: "Multiple failed login attempts",
		Severity:    SeverityHigh,
		UserID:      "test-user",
		IPAddress:   "192.168.1.100",
		Count:       10,
		TimeWindow:  5 * time.Minute,
		FirstSeen:   time.Now().Add(-5 * time.Minute),
		LastSeen:    time.Now(),
	}

	err := logger.LogSuspiciousActivity(pattern)
	if err != nil {
		t.Fatalf("Failed to log suspicious activity: %v", err)
	}

	// Verify event was stored
	events, err := logger.GetSecurityEvents(&SecurityEventFilter{
		EventType: EventTypeSuspiciousActivity,
	})
	if err != nil {
		t.Fatalf("Failed to get security events: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	event := events[0]
	if event.Details["pattern_type"] != "brute_force" {
		t.Error("Expected pattern type to be 'brute_force'")
	}
}

func TestSecurityAuditLogger_FilterEvents(t *testing.T) {
	logger := NewSecurityAuditLogger(nil)
	defer logger.Close()

	// Log multiple events
	events := []*SecurityEvent{
		{
			Type:      EventTypeAuthSuccess,
			UserID:    "user1",
			IPAddress: "192.168.1.100",
			Success:   true,
		},
		{
			Type:      EventTypeAuthFailure,
			UserID:    "user2",
			IPAddress: "192.168.1.101",
			Success:   false,
		},
		{
			Type:      EventTypeAuthFailure,
			UserID:    "user1",
			IPAddress: "192.168.1.100",
			Success:   false,
		},
	}

	for _, event := range events {
		logger.LogSecurityEvent(event)
	}

	// Test filtering by user
	filtered, err := logger.GetSecurityEvents(&SecurityEventFilter{
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("Failed to filter events: %v", err)
	}

	if len(filtered) != 2 {
		t.Fatalf("Expected 2 events for user1, got %d", len(filtered))
	}

	// Test filtering by success
	successFilter := true
	filtered, err = logger.GetSecurityEvents(&SecurityEventFilter{
		Success: &successFilter,
	})
	if err != nil {
		t.Fatalf("Failed to filter events: %v", err)
	}

	if len(filtered) != 1 {
		t.Fatalf("Expected 1 successful event, got %d", len(filtered))
	}

	// Test filtering by IP
	filtered, err = logger.GetSecurityEvents(&SecurityEventFilter{
		IPAddress: "192.168.1.101",
	})
	if err != nil {
		t.Fatalf("Failed to filter events: %v", err)
	}

	if len(filtered) != 1 {
		t.Fatalf("Expected 1 event from IP 192.168.1.101, got %d", len(filtered))
	}
}

func TestSecurityAuditLogger_EventCleanup(t *testing.T) {
	config := &SecurityAuditConfig{
		MaxEvents:           3,
		RetentionPeriod:     time.Hour,
		EnablePatternDetection: false,
	}

	logger := NewSecurityAuditLogger(config)
	defer logger.Close()

	// Log more events than the limit
	for i := 0; i < 5; i++ {
		event := &SecurityEvent{
			Type:    EventTypeAuthFailure,
			UserID:  "test-user",
			Success: false,
			Message: "Test event",
		}
		logger.LogSecurityEvent(event)
	}

	// Verify only max events are kept
	events, err := logger.GetSecurityEvents(nil)
	if err != nil {
		t.Fatalf("Failed to get events: %v", err)
	}

	if len(events) != 3 {
		t.Fatalf("Expected 3 events after cleanup, got %d", len(events))
	}
}

func TestSecurityAuditLogger_LogUserLockout(t *testing.T) {
	logger := NewSecurityAuditLogger(nil)
	defer logger.Close()

	err := logger.LogUserLockout("test-user", "Too many failed attempts", 15*time.Minute)
	if err != nil {
		t.Fatalf("Failed to log user lockout: %v", err)
	}

	events, err := logger.GetSecurityEvents(&SecurityEventFilter{
		EventType: EventTypeUserLocked,
	})
	if err != nil {
		t.Fatalf("Failed to get events: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 lockout event, got %d", len(events))
	}

	event := events[0]
	if event.Details["reason"] != "Too many failed attempts" {
		t.Error("Expected lockout reason to match")
	}
}

func TestSecurityAuditLogger_LogPermissionDenied(t *testing.T) {
	logger := NewSecurityAuditLogger(nil)
	defer logger.Close()

	err := logger.LogPermissionDenied("test-user", "bucket/object", "read", "Insufficient permissions")
	if err != nil {
		t.Fatalf("Failed to log permission denied: %v", err)
	}

	events, err := logger.GetSecurityEvents(&SecurityEventFilter{
		EventType: EventTypePermissionDenied,
	})
	if err != nil {
		t.Fatalf("Failed to get events: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 permission denied event, got %d", len(events))
	}

	event := events[0]
	if event.Resource != "bucket/object" {
		t.Errorf("Expected resource 'bucket/object', got '%s'", event.Resource)
	}

	if event.Action != "read" {
		t.Errorf("Expected action 'read', got '%s'", event.Action)
	}
}

func TestSecurityAuditLogger_TimeRangeFilter(t *testing.T) {
	logger := NewSecurityAuditLogger(nil)
	defer logger.Close()

	now := time.Now()
	
	// Log events at different times
	events := []*SecurityEvent{
		{
			Type:      EventTypeAuthSuccess,
			UserID:    "user1",
			Success:   true,
			Timestamp: now.Add(-2 * time.Hour),
		},
		{
			Type:      EventTypeAuthFailure,
			UserID:    "user2",
			Success:   false,
			Timestamp: now.Add(-1 * time.Hour),
		},
		{
			Type:      EventTypeAuthSuccess,
			UserID:    "user3",
			Success:   true,
			Timestamp: now,
		},
	}

	for _, event := range events {
		logger.LogSecurityEvent(event)
	}

	// Filter events from the last hour
	startTime := now.Add(-90 * time.Minute)
	filtered, err := logger.GetSecurityEvents(&SecurityEventFilter{
		StartTime: &startTime,
	})
	if err != nil {
		t.Fatalf("Failed to filter events by time: %v", err)
	}

	if len(filtered) != 2 {
		t.Fatalf("Expected 2 events in the last 90 minutes, got %d", len(filtered))
	}

	// Filter events before 30 minutes ago
	endTime := now.Add(-30 * time.Minute)
	filtered, err = logger.GetSecurityEvents(&SecurityEventFilter{
		EndTime: &endTime,
	})
	if err != nil {
		t.Fatalf("Failed to filter events by end time: %v", err)
	}

	if len(filtered) != 2 {
		t.Fatalf("Expected 2 events before 30 minutes ago, got %d", len(filtered))
	}
}

func TestSecurityAuditLogger_EventLimit(t *testing.T) {
	logger := NewSecurityAuditLogger(nil)
	defer logger.Close()

	// Log multiple events
	for i := 0; i < 10; i++ {
		event := &SecurityEvent{
			Type:    EventTypeAuthFailure,
			UserID:  "test-user",
			Success: false,
		}
		logger.LogSecurityEvent(event)
	}

	// Test limit
	filtered, err := logger.GetSecurityEvents(&SecurityEventFilter{
		Limit: 5,
	})
	if err != nil {
		t.Fatalf("Failed to filter events with limit: %v", err)
	}

	if len(filtered) != 5 {
		t.Fatalf("Expected 5 events with limit, got %d", len(filtered))
	}
}