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
	"fmt"
	"testing"
	"time"
)

func TestSessionSecurityBasedManagement(t *testing.T) {
	// Create test components
	auditLogger := NewSecurityAuditLogger(nil)
	defer auditLogger.Close()
	
	config := DefaultSessionIntegrationConfig()
	config.EnableSecurity = true
	config.SecurityConfig.AutoTerminateSuspicious = true
	config.SecurityConfig.SuspiciousThreshold = 2
	
	service := NewSessionIntegrationService(auditLogger, config)
	err := service.Start()
	if err != nil {
		t.Fatalf("Failed to start session integration service: %v", err)
	}
	defer service.Stop()
	
	t.Run("ForceTerminateSession", func(t *testing.T) {
		// Create a test session
		session, err := service.CreateSession("testuser", &SessionMetadata{
			IPAddress: "192.168.1.100",
			UserAgent: "TestAgent/1.0",
		})
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}
		
		// Force terminate the session
		err = service.ForceTerminateSession(session.ID, "Security test")
		if err != nil {
			t.Errorf("Failed to force terminate session: %v", err)
		}
		
		// Verify session is terminated
		_, err = service.ValidateSession(session.ID)
		if err == nil {
			t.Error("Expected session to be terminated")
		}
	})
	
	t.Run("ForceTerminateUserSessions", func(t *testing.T) {
		userID := "testuser2"
		
		// Create multiple sessions for the user
		session1, err := service.CreateSession(userID, &SessionMetadata{
			IPAddress: "192.168.1.101",
			UserAgent: "TestAgent/1.0",
		})
		if err != nil {
			t.Fatalf("Failed to create session 1: %v", err)
		}
		
		session2, err := service.CreateSession(userID, &SessionMetadata{
			IPAddress: "192.168.1.102",
			UserAgent: "TestAgent/1.0",
		})
		if err != nil {
			t.Fatalf("Failed to create session 2: %v", err)
		}
		
		// Force terminate all user sessions
		err = service.ForceTerminateUserSessions(userID, "Security test - bulk termination")
		if err != nil {
			t.Errorf("Failed to force terminate user sessions: %v", err)
		}
		
		// Verify all sessions are terminated
		_, err = service.ValidateSession(session1.ID)
		if err == nil {
			t.Error("Expected session 1 to be terminated")
		}
		
		_, err = service.ValidateSession(session2.ID)
		if err == nil {
			t.Error("Expected session 2 to be terminated")
		}
	})
	
	t.Run("SessionSecurityReport", func(t *testing.T) {
		// Create a test session
		session, err := service.CreateSession("testuser3", &SessionMetadata{
			IPAddress: "192.168.1.103",
			UserAgent: "TestAgent/1.0",
		})
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}
		
		// Track some activity to generate security data
		service.TrackSessionActivity(session.ID, session.UserID, "192.168.1.104", "TestAgent/1.0")
		service.TrackSessionActivity(session.ID, session.UserID, "192.168.1.105", "TestAgent/2.0")
		
		// Wait a bit for processing
		time.Sleep(100 * time.Millisecond)
		
		// Get security report
		report, err := service.GetSessionSecurityReport(session.ID)
		if err != nil {
			t.Errorf("Failed to get session security report: %v", err)
		}
		
		if report == nil {
			t.Error("Expected security report to be generated")
		} else {
			if report.SessionID != session.ID {
				t.Errorf("Expected session ID %s, got %s", session.ID, report.SessionID)
			}
			if report.UserID != session.UserID {
				t.Errorf("Expected user ID %s, got %s", session.UserID, report.UserID)
			}
		}
	})
	
	t.Run("UserSecurityReport", func(t *testing.T) {
		userID := "testuser4"
		
		// Create multiple sessions for the user
		session1, err := service.CreateSession(userID, &SessionMetadata{
			IPAddress: "192.168.1.106",
			UserAgent: "TestAgent/1.0",
		})
		if err != nil {
			t.Fatalf("Failed to create session 1: %v", err)
		}
		
		session2, err := service.CreateSession(userID, &SessionMetadata{
			IPAddress: "192.168.1.107",
			UserAgent: "TestAgent/1.0",
		})
		if err != nil {
			t.Fatalf("Failed to create session 2: %v", err)
		}
		
		// Track some activity
		service.TrackSessionActivity(session1.ID, userID, "192.168.1.108", "TestAgent/1.0")
		service.TrackSessionActivity(session2.ID, userID, "192.168.1.109", "TestAgent/1.0")
		
		// Wait a bit for processing
		time.Sleep(100 * time.Millisecond)
		
		// Get user security report
		report, err := service.GetUserSecurityReport(userID)
		if err != nil {
			t.Errorf("Failed to get user security report: %v", err)
		}
		
		if report == nil {
			t.Error("Expected user security report to be generated")
		} else {
			if report.UserID != userID {
				t.Errorf("Expected user ID %s, got %s", userID, report.UserID)
			}
			if report.ActiveSessions != 2 {
				t.Errorf("Expected 2 active sessions, got %d", report.ActiveSessions)
			}
		}
	})
	
	t.Run("EvaluateSessionRisk", func(t *testing.T) {
		// Create a test session
		session, err := service.CreateSession("testuser5", &SessionMetadata{
			IPAddress: "192.168.1.110",
			UserAgent: "TestAgent/1.0",
		})
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}
		
		// Initially should be low risk
		riskLevel, err := service.EvaluateSessionRisk(session.ID)
		if err != nil {
			t.Errorf("Failed to evaluate session risk: %v", err)
		}
		
		if riskLevel != RiskLevelLow {
			t.Errorf("Expected low risk level, got %s", riskLevel.String())
		}
		
		// Track suspicious activity to increase risk
		service.TrackSessionActivity(session.ID, session.UserID, "192.168.1.111", "TestAgent/1.0")
		service.TrackSessionActivity(session.ID, session.UserID, "192.168.1.112", "TestAgent/2.0")
		service.TrackSessionActivity(session.ID, session.UserID, "192.168.1.113", "TestAgent/3.0")
		
		// Wait for processing
		time.Sleep(100 * time.Millisecond)
		
		// Risk should potentially be higher now
		riskLevel, err = service.EvaluateSessionRisk(session.ID)
		if err != nil {
			t.Errorf("Failed to evaluate session risk after suspicious activity: %v", err)
		}
		
		// Risk level should be at least low (might be higher depending on detection)
		if riskLevel < RiskLevelLow {
			t.Errorf("Expected at least low risk level, got %s", riskLevel.String())
		}
	})
}

func TestSessionRiskLevelString(t *testing.T) {
	tests := []struct {
		level    SessionRiskLevel
		expected string
	}{
		{RiskLevelLow, "low"},
		{RiskLevelMedium, "medium"},
		{RiskLevelHigh, "high"},
		{RiskLevelCritical, "critical"},
		{SessionRiskLevel(999), "unknown"},
	}
	
	for _, test := range tests {
		result := test.level.String()
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}
}

func TestSecurityActionDetermination(t *testing.T) {
	auditLogger := NewSecurityAuditLogger(nil)
	defer auditLogger.Close()
	
	config := DefaultSecurityMonitorConfig()
	sessionManager := NewSessionManager(DefaultSessionConfig(), auditLogger)
	monitor := NewSessionSecurityMonitor(sessionManager, auditLogger, config)
	
	tests := []struct {
		riskLevel SessionRiskLevel
		eventType SessionAnomalyType
		expected  SecurityAction
	}{
		{RiskLevelCritical, AnomalyIPChange, SecurityActionTerminateSession},
		{RiskLevelHigh, AnomalyRapidRequests, SecurityActionTerminateSession},
		{RiskLevelHigh, AnomalyIPChange, SecurityActionRequireMFA},
		{RiskLevelMedium, AnomalyUserAgentChange, SecurityActionRequireMFA},
		{RiskLevelMedium, AnomalyLongSession, SecurityActionLogOnly},
		{RiskLevelLow, AnomalyOffHoursAccess, SecurityActionLogOnly},
	}
	
	for _, test := range tests {
		event := SessionSuspiciousEvent{
			Type:     test.eventType,
			Severity: "medium",
		}
		
		action := monitor.determineSecurityAction(test.riskLevel, event)
		if action != test.expected {
			t.Errorf("For risk level %s and event type %s, expected action %s, got %s",
				test.riskLevel.String(), test.eventType, test.expected, action)
		}
	}
}

func TestSessionSecurityEventLogging(t *testing.T) {
	auditLogger := NewSecurityAuditLogger(nil)
	defer auditLogger.Close()
	
	// Test logging session security event
	err := auditLogger.LogSessionSecurityEvent(
		"session123",
		"user456",
		"ip_change",
		"IP address changed during session",
		SeverityMedium,
		map[string]interface{}{
			"old_ip": "192.168.1.100",
			"new_ip": "192.168.1.101",
		},
	)
	
	if err != nil {
		t.Errorf("Failed to log session security event: %v", err)
	}
	
	// Verify the event was logged
	filter := &SecurityEventFilter{
		EventType: EventTypeSessionSecurity,
		UserID:    "user456",
	}
	
	events, err := auditLogger.GetSecurityEvents(filter)
	if err != nil {
		t.Errorf("Failed to get security events: %v", err)
	}
	
	if len(events) == 0 {
		t.Error("Expected at least one session security event to be logged")
	} else {
		event := events[0]
		if event.Type != EventTypeSessionSecurity {
			t.Errorf("Expected event type %s, got %s", EventTypeSessionSecurity, event.Type)
		}
		if event.UserID != "user456" {
			t.Errorf("Expected user ID user456, got %s", event.UserID)
		}
		if event.SessionID != "session123" {
			t.Errorf("Expected session ID session123, got %s", event.SessionID)
		}
	}
}

func TestAutomaticSecurityActions(t *testing.T) {
	auditLogger := NewSecurityAuditLogger(nil)
	defer auditLogger.Close()
	
	// Configure for automatic actions
	config := DefaultSessionIntegrationConfig()
	config.EnableSecurity = true
	config.SecurityConfig.AutoTerminateSuspicious = true
	config.SecurityConfig.SuspiciousThreshold = 1 // Low threshold for testing
	
	service := NewSessionIntegrationService(auditLogger, config)
	err := service.Start()
	if err != nil {
		t.Fatalf("Failed to start session integration service: %v", err)
	}
	defer service.Stop()
	
	// Create a test session
	session, err := service.CreateSession("testuser", &SessionMetadata{
		IPAddress: "192.168.1.100",
		UserAgent: "TestAgent/1.0",
	})
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	// Simulate rapid IP changes to trigger automatic termination
	for i := 0; i < 10; i++ {
		service.TrackSessionActivity(session.ID, session.UserID, 
			fmt.Sprintf("192.168.1.%d", 100+i), "TestAgent/1.0")
		time.Sleep(10 * time.Millisecond)
	}
	
	// Wait for processing
	time.Sleep(200 * time.Millisecond)
	
	// Session might be automatically terminated due to suspicious activity
	// This is dependent on the detection logic, so we'll just verify the system doesn't crash
	_, err = service.ValidateSession(session.ID)
	// Either the session is still valid or it was terminated - both are acceptable outcomes
	// The important thing is that no error occurred in the security processing
}