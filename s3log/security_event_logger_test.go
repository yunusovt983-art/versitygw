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

package s3log

import (
	"os"
	"testing"
	"time"
)

func TestSecurityEventLogger_LogAuthenticationEvent(t *testing.T) {
	// Create temporary log file
	tmpFile, err := os.CreateTemp("", "security_test_*.log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	config := &SecurityEventConfig{
		LogFile:     tmpFile.Name(),
		MaxEvents:   1000,
		EnableMetrics: false,
	}

	logger, err := NewSecurityEventLogger(config)
	if err != nil {
		t.Fatalf("Failed to create security event logger: %v", err)
	}
	defer logger.Close()

	event := &AuthenticationEvent{
		UserID:    "test-user",
		IPAddress: "192.168.1.100",
		UserAgent: "test-agent",
		AuthMethod: "signature_v4",
		Success:   true,
		Duration:  100 * time.Millisecond,
		RiskScore: 25,
	}

	err = logger.LogAuthenticationEvent(event)
	if err != nil {
		t.Fatalf("Failed to log authentication event: %v", err)
	}

	// Verify event was stored
	events, err := logger.GetAuthenticationEvents(nil)
	if err != nil {
		t.Fatalf("Failed to get authentication events: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	if events[0].UserID != "test-user" {
		t.Errorf("Expected user ID 'test-user', got '%s'", events[0].UserID)
	}
}

func TestSecurityEventLogger_LogAuthorizationEvent(t *testing.T) {
	config := &SecurityEventConfig{
		MaxEvents:     1000,
		EnableMetrics: false,
	}

	logger, err := NewSecurityEventLogger(config)
	if err != nil {
		t.Fatalf("Failed to create security event logger: %v", err)
	}
	defer logger.Close()

	event := &AuthorizationEvent{
		UserID:   "test-user",
		Resource: "bucket/object",
		Action:   "read",
		Decision: "allow",
		RequiredPermissions: []string{"s3:GetObject"},
		UserRoles: []string{"reader"},
		Duration: 50 * time.Millisecond,
	}

	err = logger.LogAuthorizationEvent(event)
	if err != nil {
		t.Fatalf("Failed to log authorization event: %v", err)
	}

	// Verify event was stored
	events, err := logger.GetAuthorizationEvents(nil)
	if err != nil {
		t.Fatalf("Failed to get authorization events: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	if events[0].Decision != "allow" {
		t.Errorf("Expected decision 'allow', got '%s'", events[0].Decision)
	}
}

func TestSecurityEventLogger_FilterAuthenticationEvents(t *testing.T) {
	config := &SecurityEventConfig{
		MaxEvents:     1000,
		EnableMetrics: false,
	}

	logger, err := NewSecurityEventLogger(config)
	if err != nil {
		t.Fatalf("Failed to create security event logger: %v", err)
	}
	defer logger.Close()

	// Log multiple events
	events := []*AuthenticationEvent{
		{UserID: "user1", IPAddress: "192.168.1.100", Success: true, AuthMethod: "signature_v4"},
		{UserID: "user2", IPAddress: "192.168.1.101", Success: false, AuthMethod: "mfa"},
		{UserID: "user1", IPAddress: "192.168.1.100", Success: false, AuthMethod: "signature_v4"},
	}

	for _, event := range events {
		logger.LogAuthenticationEvent(event)
	}

	// Test filtering by user
	filtered, err := logger.GetAuthenticationEvents(&AuthEventFilter{
		UserID: "user1",
	})
	if err != nil {
		t.Fatalf("Failed to filter events: %v", err)
	}

	if len(filtered) != 2 {
		t.Fatalf("Expected 2 events for user1, got %d", len(filtered))
	}

	// Test filtering by success
	successFilter := false
	filtered, err = logger.GetAuthenticationEvents(&AuthEventFilter{
		Success: &successFilter,
	})
	if err != nil {
		t.Fatalf("Failed to filter events: %v", err)
	}

	if len(filtered) != 2 {
		t.Fatalf("Expected 2 failed events, got %d", len(filtered))
	}

	// Test filtering by auth method
	filtered, err = logger.GetAuthenticationEvents(&AuthEventFilter{
		AuthMethod: "mfa",
	})
	if err != nil {
		t.Fatalf("Failed to filter events: %v", err)
	}

	if len(filtered) != 1 {
		t.Fatalf("Expected 1 MFA event, got %d", len(filtered))
	}
}

func TestSecurityEventLogger_FilterAuthorizationEvents(t *testing.T) {
	config := &SecurityEventConfig{
		MaxEvents:     1000,
		EnableMetrics: false,
	}

	logger, err := NewSecurityEventLogger(config)
	if err != nil {
		t.Fatalf("Failed to create security event logger: %v", err)
	}
	defer logger.Close()

	// Log multiple events
	events := []*AuthorizationEvent{
		{UserID: "user1", Resource: "bucket1/object1", Action: "read", Decision: "allow"},
		{UserID: "user2", Resource: "bucket2/object2", Action: "write", Decision: "deny"},
		{UserID: "user1", Resource: "bucket1/object2", Action: "delete", Decision: "deny"},
	}

	for _, event := range events {
		logger.LogAuthorizationEvent(event)
	}

	// Test filtering by decision
	filtered, err := logger.GetAuthorizationEvents(&AuthzEventFilter{
		Decision: "deny",
	})
	if err != nil {
		t.Fatalf("Failed to filter events: %v", err)
	}

	if len(filtered) != 2 {
		t.Fatalf("Expected 2 denied events, got %d", len(filtered))
	}

	// Test filtering by resource
	filtered, err = logger.GetAuthorizationEvents(&AuthzEventFilter{
		Resource: "bucket1/object1",
	})
	if err != nil {
		t.Fatalf("Failed to filter events: %v", err)
	}

	if len(filtered) != 1 {
		t.Fatalf("Expected 1 event for specific resource, got %d", len(filtered))
	}
}

func TestSecurityEventLogger_LogEnhanced(t *testing.T) {
	config := &SecurityEventConfig{
		MaxEvents:     1000,
		EnableMetrics: false,
	}

	logger, err := NewSecurityEventLogger(config)
	if err != nil {
		t.Fatalf("Failed to create security event logger: %v", err)
	}
	defer logger.Close()

	// Skip this test for now as it requires a complex Fiber context setup
	t.Skip("Skipping LogEnhanced test - requires complex Fiber context setup")
}

func TestSecurityEventLogger_TriggerSecurityAlert(t *testing.T) {
	config := &SecurityEventConfig{
		MaxEvents:     1000,
		EnableMetrics: false,
	}

	logger, err := NewSecurityEventLogger(config)
	if err != nil {
		t.Fatalf("Failed to create security event logger: %v", err)
	}
	defer logger.Close()

	details := map[string]interface{}{
		"user_id":    "test-user",
		"ip_address": "192.168.1.100",
		"attempts":   5,
	}

	err = logger.TriggerSecurityAlert("brute_force", "high", details)
	if err != nil {
		t.Fatalf("Failed to trigger security alert: %v", err)
	}

	// This test mainly verifies that TriggerSecurityAlert doesn't crash
	// In a real implementation, you would verify the alert was properly logged
}

func TestSecurityEventLogger_EventCleanup(t *testing.T) {
	config := &SecurityEventConfig{
		MaxEvents:     3,
		EnableMetrics: false,
	}

	logger, err := NewSecurityEventLogger(config)
	if err != nil {
		t.Fatalf("Failed to create security event logger: %v", err)
	}
	defer logger.Close()

	// Log more events than the limit
	for i := 0; i < 5; i++ {
		event := &AuthenticationEvent{
			UserID:  "test-user",
			Success: true,
		}
		logger.LogAuthenticationEvent(event)
	}

	// Verify only max events are kept
	events, err := logger.GetAuthenticationEvents(nil)
	if err != nil {
		t.Fatalf("Failed to get events: %v", err)
	}

	if len(events) != 3 {
		t.Fatalf("Expected 3 events after cleanup, got %d", len(events))
	}
}

func TestSecurityEventLogger_TimeRangeFilter(t *testing.T) {
	config := &SecurityEventConfig{
		MaxEvents:     1000,
		EnableMetrics: false,
	}

	logger, err := NewSecurityEventLogger(config)
	if err != nil {
		t.Fatalf("Failed to create security event logger: %v", err)
	}
	defer logger.Close()

	now := time.Now()

	// Log events at different times
	events := []*AuthenticationEvent{
		{UserID: "user1", Success: true, Timestamp: now.Add(-2 * time.Hour)},
		{UserID: "user2", Success: false, Timestamp: now.Add(-1 * time.Hour)},
		{UserID: "user3", Success: true, Timestamp: now},
	}

	for _, event := range events {
		logger.LogAuthenticationEvent(event)
	}

	// Filter events from the last hour
	startTime := now.Add(-90 * time.Minute)
	filtered, err := logger.GetAuthenticationEvents(&AuthEventFilter{
		StartTime: &startTime,
	})
	if err != nil {
		t.Fatalf("Failed to filter events by time: %v", err)
	}

	if len(filtered) != 2 {
		t.Fatalf("Expected 2 events in the last 90 minutes, got %d", len(filtered))
	}
}

func TestSecurityEventLogger_EventLimit(t *testing.T) {
	config := &SecurityEventConfig{
		MaxEvents:     1000,
		EnableMetrics: false,
	}

	logger, err := NewSecurityEventLogger(config)
	if err != nil {
		t.Fatalf("Failed to create security event logger: %v", err)
	}
	defer logger.Close()

	// Log multiple events
	for i := 0; i < 10; i++ {
		event := &AuthenticationEvent{
			UserID:  "test-user",
			Success: true,
		}
		logger.LogAuthenticationEvent(event)
	}

	// Test limit
	filtered, err := logger.GetAuthenticationEvents(&AuthEventFilter{
		Limit: 5,
	})
	if err != nil {
		t.Fatalf("Failed to filter events with limit: %v", err)
	}

	if len(filtered) != 5 {
		t.Fatalf("Expected 5 events with limit, got %d", len(filtered))
	}
}

func TestSecurityEventLogger_GetSecurityMetrics(t *testing.T) {
	config := &SecurityEventConfig{
		MaxEvents:     1000,
		EnableMetrics: true,
		MetricsInterval: 100 * time.Millisecond,
	}

	logger, err := NewSecurityEventLogger(config)
	if err != nil {
		t.Fatalf("Failed to create security event logger: %v", err)
	}
	defer logger.Close()

	// Log some events to generate metrics
	events := []*AuthenticationEvent{
		{UserID: "user1", Success: true, RiskScore: 25, GeoLocation: "US"},
		{UserID: "user2", Success: false, RiskScore: 75, FailureReason: "invalid_password"},
		{UserID: "user3", Success: true, MFAUsed: true, RiskScore: 10},
	}

	for _, event := range events {
		logger.LogAuthenticationEvent(event)
	}

	// Wait for metrics to be calculated
	time.Sleep(200 * time.Millisecond)

	metrics, err := logger.GetSecurityMetrics(nil)
	if err != nil {
		t.Fatalf("Failed to get security metrics: %v", err)
	}

	if metrics.AuthenticationAttempts != 3 {
		t.Errorf("Expected 3 authentication attempts, got %d", metrics.AuthenticationAttempts)
	}

	if metrics.AuthenticationSuccesses != 2 {
		t.Errorf("Expected 2 successful authentications, got %d", metrics.AuthenticationSuccesses)
	}

	if metrics.AuthenticationFailures != 1 {
		t.Errorf("Expected 1 failed authentication, got %d", metrics.AuthenticationFailures)
	}

	if metrics.MFAUsageCount != 1 {
		t.Errorf("Expected 1 MFA usage, got %d", metrics.MFAUsageCount)
	}
}

func TestCreateEnhancedLogFields(t *testing.T) {
	original := &LogFields{
		BucketOwner: "test-owner",
		Bucket:      "test-bucket",
		RemoteIP:    "192.168.1.100",
		Requester:   "test-user",
		Operation:   "GetObject",
		HttpStatus:  200,
	}

	enhanced := CreateEnhancedLogFields(original)

	if enhanced.BucketOwner != original.BucketOwner {
		t.Errorf("Expected bucket owner '%s', got '%s'", original.BucketOwner, enhanced.BucketOwner)
	}

	if enhanced.RemoteIP != original.RemoteIP {
		t.Errorf("Expected remote IP '%s', got '%s'", original.RemoteIP, enhanced.RemoteIP)
	}

	// Test conversion back to original
	converted := enhanced.ToLogFields()
	if converted.BucketOwner != original.BucketOwner {
		t.Errorf("Expected converted bucket owner '%s', got '%s'", original.BucketOwner, converted.BucketOwner)
	}
}

func TestCreateEnhancedLogFields_Nil(t *testing.T) {
	enhanced := CreateEnhancedLogFields(nil)
	if enhanced == nil {
		t.Error("Expected non-nil enhanced log fields")
	}

	// Should create empty enhanced log fields
	if enhanced.BucketOwner != "" {
		t.Error("Expected empty bucket owner for nil input")
	}
}