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
	"log"
	"time"
)

// ExampleSessionSecurityBasedManagement demonstrates how to use the security-based session management features
func ExampleSessionSecurityBasedManagement() {
	// Create audit logger
	auditLogger := NewSecurityAuditLogger(nil)
	defer auditLogger.Close()
	
	// Configure session integration with security monitoring enabled
	config := &SessionIntegrationConfig{
		SessionConfig: &SessionConfig{
			DefaultTTL:        24 * time.Hour,
			MaxSessionsPerUser: 5,
		},
		SecurityConfig: &SecurityMonitorConfig{
			Enabled:                 true,
			AutoTerminateSuspicious: true,
			SuspiciousThreshold:     3,
			DetectIPChanges:         true,
			DetectUserAgentChanges:  true,
			DetectRapidRequests:     true,
			MaxRequestsPerMinute:    100,
		},
		EnableSecurity: true,
		EnableCleanup:  true,
		EnableAPI:      true,
	}
	
	// Create and start the session integration service
	service := NewSessionIntegrationService(auditLogger, config)
	err := service.Start()
	if err != nil {
		log.Fatalf("Failed to start session service: %v", err)
	}
	defer service.Stop()
	
	// Create a session
	session, err := service.CreateSession("user123", &SessionMetadata{
		IPAddress: "192.168.1.100",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	})
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}
	
	fmt.Printf("Created session: %s for user: %s\n", session.ID, session.UserID)
	
	// Track normal activity
	service.TrackSessionActivity(session.ID, session.UserID, "192.168.1.100", 
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
	// Simulate suspicious activity - IP change
	service.TrackSessionActivity(session.ID, session.UserID, "10.0.0.1", 
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
	// Simulate suspicious activity - User agent change
	service.TrackSessionActivity(session.ID, session.UserID, "10.0.0.1", 
		"curl/7.68.0")
	
	// Wait for security monitoring to process
	time.Sleep(100 * time.Millisecond)
	
	// Get session security report
	report, err := service.GetSessionSecurityReport(session.ID)
	if err != nil {
		log.Printf("Failed to get security report: %v", err)
	} else {
		fmt.Printf("Session Risk Level: %s\n", report.RiskLevel.String())
		fmt.Printf("Risk Score: %d\n", report.RiskScore)
		fmt.Printf("Suspicious Events: %d\n", len(report.SuspiciousEvents))
		fmt.Printf("IP Changes: %d\n", len(report.IPChanges))
		fmt.Printf("User Agent Changes: %d\n", len(report.UserAgentChanges))
	}
	
	// Get user security report
	userReport, err := service.GetUserSecurityReport(session.UserID)
	if err != nil {
		log.Printf("Failed to get user security report: %v", err)
	} else {
		fmt.Printf("User Risk Level: %s\n", userReport.RiskLevel.String())
		fmt.Printf("Active Sessions: %d\n", userReport.ActiveSessions)
		fmt.Printf("Total Suspicious Events: %d\n", len(userReport.SuspiciousEvents))
	}
	
	// Evaluate current session risk
	riskLevel, err := service.EvaluateSessionRisk(session.ID)
	if err != nil {
		log.Printf("Failed to evaluate session risk: %v", err)
	} else {
		fmt.Printf("Current Session Risk: %s\n", riskLevel.String())
	}
	
	// Force terminate session if risk is too high
	if riskLevel >= RiskLevelHigh {
		err = service.ForceTerminateSession(session.ID, "High risk session detected")
		if err != nil {
			log.Printf("Failed to force terminate session: %v", err)
		} else {
			fmt.Println("Session forcefully terminated due to high risk")
		}
	}
	
	// Get integrated statistics
	stats := service.GetIntegratedStats()
	if stats.SecurityStats != nil {
		fmt.Printf("Total Suspicious Events Detected: %d\n", stats.SecurityStats.SuspiciousEventsDetected)
		fmt.Printf("Sessions Terminated: %d\n", stats.SecurityStats.SessionsTerminated)
	}
	
	fmt.Println("Session security management example completed")
}

// ExampleForceTerminateUserSessions demonstrates how to forcefully terminate all sessions for a user
func ExampleForceTerminateUserSessions() {
	auditLogger := NewSecurityAuditLogger(nil)
	defer auditLogger.Close()
	
	service := NewSessionIntegrationService(auditLogger, nil)
	err := service.Start()
	if err != nil {
		log.Fatalf("Failed to start session service: %v", err)
	}
	defer service.Stop()
	
	userID := "compromised_user"
	
	// Create multiple sessions for the user
	for i := 0; i < 3; i++ {
		_, err := service.CreateSession(userID, &SessionMetadata{
			IPAddress: fmt.Sprintf("192.168.1.%d", 100+i),
			UserAgent: "TestAgent/1.0",
		})
		if err != nil {
			log.Printf("Failed to create session %d: %v", i, err)
		}
	}
	
	// Get active sessions before termination
	sessions, err := service.GetActiveSessions(userID)
	if err != nil {
		log.Printf("Failed to get active sessions: %v", err)
	} else {
		fmt.Printf("Active sessions before termination: %d\n", len(sessions))
	}
	
	// Force terminate all user sessions
	err = service.ForceTerminateUserSessions(userID, "User account compromised")
	if err != nil {
		log.Printf("Failed to force terminate user sessions: %v", err)
	} else {
		fmt.Printf("All sessions for user %s have been forcefully terminated\n", userID)
	}
	
	// Verify sessions are terminated
	sessions, err = service.GetActiveSessions(userID)
	if err != nil {
		log.Printf("Failed to get active sessions: %v", err)
	} else {
		fmt.Printf("Active sessions after termination: %d\n", len(sessions))
	}
}

// ExampleSessionSecurityEventLogging demonstrates session security event logging
func ExampleSessionSecurityEventLogging() {
	auditLogger := NewSecurityAuditLogger(nil)
	defer auditLogger.Close()
	
	// Log various session security events
	err := auditLogger.LogSessionSecurityEvent(
		"session123",
		"user456",
		"ip_change",
		"IP address changed from 192.168.1.100 to 10.0.0.1",
		SeverityMedium,
		map[string]interface{}{
			"old_ip": "192.168.1.100",
			"new_ip": "10.0.0.1",
			"distance_km": 500.0,
		},
	)
	if err != nil {
		log.Printf("Failed to log session security event: %v", err)
	}
	
	err = auditLogger.LogSessionSecurityEvent(
		"session456",
		"user789",
		"user_agent_change",
		"User agent changed during session",
		SeverityLow,
		map[string]interface{}{
			"old_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			"new_user_agent": "curl/7.68.0",
		},
	)
	if err != nil {
		log.Printf("Failed to log session security event: %v", err)
	}
	
	// Query security events
	filter := &SecurityEventFilter{
		EventType: EventTypeSessionSecurity,
		Limit:     10,
	}
	
	events, err := auditLogger.GetSecurityEvents(filter)
	if err != nil {
		log.Printf("Failed to get security events: %v", err)
	} else {
		fmt.Printf("Found %d session security events\n", len(events))
		for _, event := range events {
			fmt.Printf("Event: %s - %s (Severity: %s)\n", 
				event.Type, event.Message, event.Severity)
		}
	}
}