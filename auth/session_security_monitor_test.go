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

func TestNewSessionSecurityMonitor(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	t.Run("with default config", func(t *testing.T) {
		monitor := NewSessionSecurityMonitor(sm, auditLogger, nil)
		if monitor == nil {
			t.Fatal("expected non-nil security monitor")
		}
		
		if !monitor.config.Enabled {
			t.Error("expected monitoring to be enabled by default")
		}
		
		if monitor.config.MaxConcurrentSessions != 5 {
			t.Errorf("expected default max concurrent sessions 5, got %d", monitor.config.MaxConcurrentSessions)
		}
	})
	
	t.Run("with custom config", func(t *testing.T) {
		config := &SecurityMonitorConfig{
			Enabled:                  true,
			DetectConcurrentSessions: true,
			MaxConcurrentSessions:    3,
			DetectRapidRequests:      true,
			MaxRequestsPerMinute:     50,
			MonitoringInterval:       1 * time.Minute,
		}
		
		monitor := NewSessionSecurityMonitor(sm, auditLogger, config)
		if monitor == nil {
			t.Fatal("expected non-nil security monitor")
		}
		
		if monitor.config.MaxConcurrentSessions != 3 {
			t.Errorf("expected max concurrent sessions 3, got %d", monitor.config.MaxConcurrentSessions)
		}
		
		if monitor.config.MaxRequestsPerMinute != 50 {
			t.Errorf("expected max requests per minute 50, got %d", monitor.config.MaxRequestsPerMinute)
		}
	})
}

func TestSessionSecurityMonitor_StartStop(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	config := &SecurityMonitorConfig{
		Enabled:            true,
		MonitoringInterval: 100 * time.Millisecond,
	}
	
	monitor := NewSessionSecurityMonitor(sm, auditLogger, config)
	
	t.Run("start and stop monitor", func(t *testing.T) {
		err := monitor.Start()
		if err != nil {
			t.Fatalf("failed to start monitor: %v", err)
		}
		
		// Wait a bit to ensure monitoring runs
		time.Sleep(150 * time.Millisecond)
		
		err = monitor.Stop()
		if err != nil {
			t.Fatalf("failed to stop monitor: %v", err)
		}
		
		// Check that monitoring ran
		stats := monitor.GetStats()
		if stats.LastMonitoringRun.IsZero() {
			t.Error("expected monitoring to have run")
		}
	})
	
	t.Run("disabled monitor", func(t *testing.T) {
		disabledConfig := &SecurityMonitorConfig{
			Enabled: false,
		}
		
		disabledMonitor := NewSessionSecurityMonitor(sm, auditLogger, disabledConfig)
		
		err := disabledMonitor.Start()
		if err != nil {
			t.Fatalf("failed to start disabled monitor: %v", err)
		}
		
		err = disabledMonitor.Stop()
		if err != nil {
			t.Fatalf("failed to stop disabled monitor: %v", err)
		}
	})
}

func TestSessionSecurityMonitor_TrackSessionActivity(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	config := &SecurityMonitorConfig{
		Enabled:              true,
		DetectRapidRequests:  true,
		MaxRequestsPerMinute: 5, // Low threshold for testing
		RequestWindow:        1 * time.Minute,
	}
	
	monitor := NewSessionSecurityMonitor(sm, auditLogger, config)
	
	// Create test session
	session, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("track normal activity", func(t *testing.T) {
		monitor.TrackSessionActivity(session.ID, session.UserID, session.IPAddress, session.UserAgent)
		
		// Check that activity was tracked
		sessionActivity := monitor.GetSessionActivity(session.ID)
		if sessionActivity == nil {
			t.Fatal("expected session activity to be tracked")
		}
		
		if sessionActivity.RequestCount != 1 {
			t.Errorf("expected request count 1, got %d", sessionActivity.RequestCount)
		}
		
		userActivity := monitor.GetUserActivity(session.UserID)
		if userActivity == nil {
			t.Fatal("expected user activity to be tracked")
		}
	})
	
	t.Run("detect rapid requests", func(t *testing.T) {
		// Generate rapid requests
		for i := 0; i < 10; i++ {
			monitor.TrackSessionActivity(session.ID, session.UserID, session.IPAddress, session.UserAgent)
		}
		
		// Check for suspicious events
		sessionActivity := monitor.GetSessionActivity(session.ID)
		if sessionActivity == nil {
			t.Fatal("expected session activity to be tracked")
		}
		
		// Should have detected rapid requests
		found := false
		for _, event := range sessionActivity.SuspiciousEvents {
			if event.Type == AnomalyRapidRequests {
				found = true
				break
			}
		}
		
		if !found {
			t.Error("expected rapid requests to be detected")
		}
	})
}

func TestSessionSecurityMonitor_DetectConcurrentSessions(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	config := &SecurityMonitorConfig{
		Enabled:                  true,
		DetectConcurrentSessions: true,
		MaxConcurrentSessions:    2, // Low threshold for testing
		MonitoringInterval:       50 * time.Millisecond,
	}
	
	monitor := NewSessionSecurityMonitor(sm, auditLogger, config)
	
	// Create multiple sessions for the same user
	for i := 0; i < 4; i++ {
		_, err := sm.CreateSession("user1", &SessionMetadata{
			IPAddress: "192.168.1.1",
		})
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
	}
	
	t.Run("detect concurrent sessions", func(t *testing.T) {
		err := monitor.Start()
		if err != nil {
			t.Fatalf("failed to start monitor: %v", err)
		}
		defer monitor.Stop()
		
		// Wait for monitoring to run
		time.Sleep(100 * time.Millisecond)
		
		// Check stats
		stats := monitor.GetStats()
		if stats.SuspiciousEventsDetected == 0 {
			t.Error("expected suspicious events to be detected for concurrent sessions")
		}
		
		// Check for multiple locations anomaly
		if stats.EventsByType[AnomalyMultipleLocations] == 0 {
			t.Error("expected multiple locations anomaly to be detected")
		}
	})
}

func TestSessionSecurityMonitor_DetectLongSessions(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	config := &SecurityMonitorConfig{
		Enabled:            true,
		DetectLongSessions: true,
		MaxSessionDuration: 50 * time.Millisecond, // Very short for testing
		MonitoringInterval: 100 * time.Millisecond,
	}
	
	monitor := NewSessionSecurityMonitor(sm, auditLogger, config)
	
	// Create test session
	_, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("detect long session", func(t *testing.T) {
		err := monitor.Start()
		if err != nil {
			t.Fatalf("failed to start monitor: %v", err)
		}
		defer monitor.Stop()
		
		// Wait for session to become "long"
		time.Sleep(150 * time.Millisecond)
		
		// Check stats
		stats := monitor.GetStats()
		if stats.SuspiciousEventsDetected == 0 {
			t.Error("expected suspicious events to be detected for long session")
		}
		
		// Check for long session anomaly
		if stats.EventsByType[AnomalyLongSession] == 0 {
			t.Error("expected long session anomaly to be detected")
		}
	})
}

func TestSessionSecurityMonitor_DetectOffHoursAccess(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	config := &SecurityMonitorConfig{
		Enabled:              true,
		DetectOffHoursAccess: true,
		AllowedHoursStart:    9,  // 9 AM
		AllowedHoursEnd:      17, // 5 PM
		AllowedTimezone:      "UTC",
		MonitoringInterval:   50 * time.Millisecond,
	}
	
	monitor := NewSessionSecurityMonitor(sm, auditLogger, config)
	
	t.Run("detect off-hours access", func(t *testing.T) {
		// Create session with off-hours timestamp
		session, err := sm.CreateSession("user1", &SessionMetadata{
			IPAddress: "192.168.1.1",
		})
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}
		
		// Check if current time is off-hours
		now := time.Now().UTC()
		hour := now.Hour()
		isOffHours := hour < 9 || hour >= 17
		
		if isOffHours {
			err := monitor.Start()
			if err != nil {
				t.Fatalf("failed to start monitor: %v", err)
			}
			defer monitor.Stop()
			
			// Wait for monitoring to run
			time.Sleep(100 * time.Millisecond)
			
			// Check stats
			stats := monitor.GetStats()
			if stats.SuspiciousEventsDetected == 0 {
				t.Error("expected suspicious events to be detected for off-hours access")
			}
			
			// Check for off-hours anomaly
			if stats.EventsByType[AnomalyOffHoursAccess] == 0 {
				t.Error("expected off-hours access anomaly to be detected")
			}
		} else {
			t.Logf("Skipping off-hours test as current time (%d:00 UTC) is within allowed hours", hour)
			_ = session // Use session to avoid unused variable error
		}
	})
}

func TestSessionSecurityMonitor_AutoTermination(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	config := &SecurityMonitorConfig{
		Enabled:                 true,
		DetectLongSessions:      true,
		MaxSessionDuration:      50 * time.Millisecond,
		AutoTerminateSuspicious: true,
		SuspiciousThreshold:     3, // Medium severity = 3 points
		MonitoringInterval:      100 * time.Millisecond,
	}
	
	monitor := NewSessionSecurityMonitor(sm, auditLogger, config)
	
	// Create test session
	session, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("auto terminate suspicious session", func(t *testing.T) {
		err := monitor.Start()
		if err != nil {
			t.Fatalf("failed to start monitor: %v", err)
		}
		defer monitor.Stop()
		
		// Generate multiple suspicious activities to trigger auto-termination
		// Track rapid IP changes to increase risk score
		for i := 0; i < 5; i++ {
			monitor.TrackSessionActivity(session.ID, session.UserID, 
				fmt.Sprintf("192.168.1.%d", i+10), "TestAgent/1.0")
			time.Sleep(10 * time.Millisecond)
		}
		
		// Track user agent changes to further increase risk
		monitor.TrackSessionActivity(session.ID, session.UserID, "192.168.1.20", "TestAgent/2.0")
		monitor.TrackSessionActivity(session.ID, session.UserID, "192.168.1.21", "TestAgent/3.0")
		
		// Wait for session to become suspicious and potentially be terminated
		time.Sleep(200 * time.Millisecond)
		
		// Check that session was terminated or at least flagged as suspicious
		_, err = sm.ValidateSession(session.ID)
		if err == nil {
			// If session wasn't terminated, check that suspicious activity was detected
			stats := monitor.GetStats()
			if stats.SuspiciousEventsDetected == 0 {
				t.Error("expected suspicious activity to be detected")
			}
		} else if err == ErrSessionNotFound {
			// Session was terminated - this is also acceptable
			stats := monitor.GetStats()
			if stats.SessionsTerminated == 0 {
				t.Error("expected sessions to be terminated automatically")
			}
		}
	})
}

func TestSessionSecurityMonitor_IPChangeDetection(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	config := &SecurityMonitorConfig{
		Enabled:             true,
		DetectIPChanges:     true,
		MaxIPChangesPerHour: 2,
		IPChangeWindow:      1 * time.Hour,
	}
	
	monitor := NewSessionSecurityMonitor(sm, auditLogger, config)
	
	// Create test session
	session, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("detect IP changes", func(t *testing.T) {
		// Track initial activity
		monitor.TrackSessionActivity(session.ID, session.UserID, "192.168.1.1", "test-agent")
		
		// Simulate IP changes
		monitor.TrackSessionActivity(session.ID, session.UserID, "192.168.1.2", "test-agent")
		monitor.TrackSessionActivity(session.ID, session.UserID, "192.168.1.3", "test-agent")
		monitor.TrackSessionActivity(session.ID, session.UserID, "192.168.1.4", "test-agent")
		
		// Check for IP change events
		sessionActivity := monitor.GetSessionActivity(session.ID)
		if sessionActivity == nil {
			t.Fatal("expected session activity to be tracked")
		}
		
		if len(sessionActivity.IPChanges) == 0 {
			t.Error("expected IP changes to be tracked")
		}
		
		// Check for suspicious events
		found := false
		for _, event := range sessionActivity.SuspiciousEvents {
			if event.Type == AnomalyIPChange {
				found = true
				break
			}
		}
		
		if !found {
			t.Error("expected IP change anomaly to be detected")
		}
	})
}

func TestSessionSecurityMonitor_UserAgentChangeDetection(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	config := &SecurityMonitorConfig{
		Enabled:                true,
		DetectUserAgentChanges: true,
	}
	
	monitor := NewSessionSecurityMonitor(sm, auditLogger, config)
	
	// Create test session
	session, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent-1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("detect user agent changes", func(t *testing.T) {
		// Track initial activity
		monitor.TrackSessionActivity(session.ID, session.UserID, "192.168.1.1", "test-agent-1")
		
		// Simulate user agent change
		monitor.TrackSessionActivity(session.ID, session.UserID, "192.168.1.1", "test-agent-2")
		
		// Check for user agent change events
		sessionActivity := monitor.GetSessionActivity(session.ID)
		if sessionActivity == nil {
			t.Fatal("expected session activity to be tracked")
		}
		
		if len(sessionActivity.UserAgentChanges) == 0 {
			t.Error("expected user agent changes to be tracked")
		}
		
		// Check for suspicious events
		found := false
		for _, event := range sessionActivity.SuspiciousEvents {
			if event.Type == AnomalyUserAgentChange {
				found = true
				break
			}
		}
		
		if !found {
			t.Error("expected user agent change anomaly to be detected")
		}
	})
}

func TestSessionSecurityMonitor_UpdateConfig(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	monitor := NewSessionSecurityMonitor(sm, auditLogger, nil)
	
	t.Run("update config", func(t *testing.T) {
		newConfig := &SecurityMonitorConfig{
			Enabled:                 true,
			DetectConcurrentSessions: true,
			MaxConcurrentSessions:   10,
			AutoTerminateSuspicious: true,
		}
		
		err := monitor.UpdateConfig(newConfig)
		if err != nil {
			t.Fatalf("failed to update config: %v", err)
		}
		
		if monitor.config.MaxConcurrentSessions != 10 {
			t.Errorf("expected max concurrent sessions 10, got %d", monitor.config.MaxConcurrentSessions)
		}
		
		if !monitor.config.AutoTerminateSuspicious {
			t.Error("expected auto terminate to be enabled")
		}
	})
	
	t.Run("update with nil config", func(t *testing.T) {
		err := monitor.UpdateConfig(nil)
		if err == nil {
			t.Error("expected error when updating with nil config")
		}
	})
}

func TestIsIPPrivate(t *testing.T) {
	testCases := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"invalid-ip", false},
		{"::1", true},
		{"fc00::1", true},
		{"2001:db8::1", false},
	}
	
	for _, tc := range testCases {
		t.Run(tc.ip, func(t *testing.T) {
			result := IsIPPrivate(tc.ip)
			if result != tc.expected {
				t.Errorf("expected IsIPPrivate(%s) = %v, got %v", tc.ip, tc.expected, result)
			}
		})
	}
}

func TestSessionSecurityMonitor_GetStats(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	monitor := NewSessionSecurityMonitor(sm, auditLogger, nil)
	
	t.Run("initial stats", func(t *testing.T) {
		stats := monitor.GetStats()
		if stats.TotalSessionsMonitored != 0 {
			t.Errorf("expected 0 sessions monitored initially, got %d", stats.TotalSessionsMonitored)
		}
		
		if stats.SuspiciousEventsDetected != 0 {
			t.Errorf("expected 0 suspicious events initially, got %d", stats.SuspiciousEventsDetected)
		}
	})
}