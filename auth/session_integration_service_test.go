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
	"net/http"
	"testing"
	"time"
)

func TestNewSessionIntegrationService(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	
	t.Run("with default config", func(t *testing.T) {
		service := NewSessionIntegrationService(auditLogger, nil)
		if service == nil {
			t.Fatal("expected non-nil integration service")
		}
		
		if service.GetSessionManager() == nil {
			t.Error("expected session manager to be created")
		}
		
		if service.GetSecurityMonitor() == nil {
			t.Error("expected security monitor to be created")
		}
		
		if service.GetCleanupService() == nil {
			t.Error("expected cleanup service to be created")
		}
		
		if service.GetSessionAPI() == nil {
			t.Error("expected session API to be created")
		}
	})
	
	t.Run("with custom config", func(t *testing.T) {
		config := &SessionIntegrationConfig{
			SessionConfig:  DefaultSessionConfig(),
			SecurityConfig: DefaultSecurityMonitorConfig(),
			CleanupConfig:  DefaultCleanupConfig(),
			EnableAPI:      false,
			EnableSecurity: false,
			EnableCleanup:  false,
		}
		
		service := NewSessionIntegrationService(auditLogger, config)
		if service == nil {
			t.Fatal("expected non-nil integration service")
		}
		
		if service.GetSessionManager() == nil {
			t.Error("expected session manager to be created")
		}
		
		if service.GetSecurityMonitor() != nil {
			t.Error("expected security monitor to be disabled")
		}
		
		if service.GetCleanupService() != nil {
			t.Error("expected cleanup service to be disabled")
		}
		
		if service.GetSessionAPI() != nil {
			t.Error("expected session API to be disabled")
		}
	})
}

func TestSessionIntegrationService_StartStop(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	config := &SessionIntegrationConfig{
		SessionConfig: &SessionConfig{
			DefaultTTL:      1 * time.Hour,
			CleanupInterval: 1 * time.Minute,
		},
		SecurityConfig: &SecurityMonitorConfig{
			Enabled:            true,
			MonitoringInterval: 1 * time.Minute,
		},
		CleanupConfig: &CleanupConfig{
			CleanupInterval: 1 * time.Minute,
		},
		EnableAPI:      true,
		EnableSecurity: true,
		EnableCleanup:  true,
	}
	
	service := NewSessionIntegrationService(auditLogger, config)
	
	t.Run("start and stop service", func(t *testing.T) {
		// Initially not running
		if service.IsRunning() {
			t.Error("expected service to not be running initially")
		}
		
		// Start service
		err := service.Start()
		if err != nil {
			t.Fatalf("failed to start service: %v", err)
		}
		
		if !service.IsRunning() {
			t.Error("expected service to be running after start")
		}
		
		// Starting again should not error
		err = service.Start()
		if err != nil {
			t.Errorf("starting already running service should not error: %v", err)
		}
		
		// Stop service
		err = service.Stop()
		if err != nil {
			t.Fatalf("failed to stop service: %v", err)
		}
		
		if service.IsRunning() {
			t.Error("expected service to not be running after stop")
		}
		
		// Stopping again should not error
		err = service.Stop()
		if err != nil {
			t.Errorf("stopping already stopped service should not error: %v", err)
		}
	})
}

func TestSessionIntegrationService_CreateSession(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	service := NewSessionIntegrationService(auditLogger, nil)
	defer service.Stop()
	
	err := service.Start()
	if err != nil {
		t.Fatalf("failed to start service: %v", err)
	}
	
	t.Run("create session with tracking", func(t *testing.T) {
		metadata := &SessionMetadata{
			IPAddress: "192.168.1.1",
			UserAgent: "test-agent",
			MFAVerified: true,
		}
		
		session, err := service.CreateSession("user1", metadata)
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}
		
		if session.ID == "" {
			t.Error("expected non-empty session ID")
		}
		
		if session.UserID != "user1" {
			t.Errorf("expected user ID 'user1', got '%s'", session.UserID)
		}
		
		// Check that security monitoring is tracking the session
		if service.GetSecurityMonitor() != nil {
			activity := service.GetSessionActivity(session.ID)
			if activity == nil {
				t.Error("expected session activity to be tracked")
			}
		}
	})
}

func TestSessionIntegrationService_ValidateSession(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	service := NewSessionIntegrationService(auditLogger, nil)
	defer service.Stop()
	
	err := service.Start()
	if err != nil {
		t.Fatalf("failed to start service: %v", err)
	}
	
	// Create test session
	session, err := service.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("validate session with tracking", func(t *testing.T) {
		validatedSession, err := service.ValidateSession(session.ID)
		if err != nil {
			t.Fatalf("failed to validate session: %v", err)
		}
		
		if validatedSession.ID != session.ID {
			t.Errorf("expected session ID '%s', got '%s'", session.ID, validatedSession.ID)
		}
		
		// Check that security monitoring tracked the validation
		if service.GetSecurityMonitor() != nil {
			activity := service.GetSessionActivity(session.ID)
			if activity == nil {
				t.Error("expected session activity to be tracked")
			}
			
			if activity.RequestCount < 2 { // Create + Validate
				t.Errorf("expected at least 2 requests tracked, got %d", activity.RequestCount)
			}
		}
	})
}

func TestSessionIntegrationService_GetIntegratedStats(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	service := NewSessionIntegrationService(auditLogger, nil)
	defer service.Stop()
	
	err := service.Start()
	if err != nil {
		t.Fatalf("failed to start service: %v", err)
	}
	
	// Create test sessions
	for i := 0; i < 3; i++ {
		_, err := service.CreateSession("user1", &SessionMetadata{
			IPAddress: "192.168.1.1",
		})
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
	}
	
	t.Run("get integrated statistics", func(t *testing.T) {
		stats := service.GetIntegratedStats()
		if stats == nil {
			t.Fatal("expected non-nil integrated stats")
		}
		
		if stats.SessionStats == nil {
			t.Error("expected session stats to be included")
		} else {
			if stats.SessionStats.TotalActiveSessions != 3 {
				t.Errorf("expected 3 active sessions, got %d", stats.SessionStats.TotalActiveSessions)
			}
		}
		
		if stats.SecurityStats == nil {
			t.Error("expected security stats to be included")
		}
		
		if stats.CleanupStats == nil {
			t.Error("expected cleanup stats to be included")
		}
		
		if stats.Timestamp.IsZero() {
			t.Error("expected timestamp to be set")
		}
	})
}

func TestSessionIntegrationService_RegisterAPIRoutes(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	service := NewSessionIntegrationService(auditLogger, nil)
	defer service.Stop()
	
	t.Run("register API routes", func(t *testing.T) {
		mux := http.NewServeMux()
		service.RegisterAPIRoutes(mux)
		
		// Test that routes are registered by checking if they exist
		// This is a basic test - in a real scenario you'd make HTTP requests
		if service.GetSessionAPI() == nil {
			t.Error("expected session API to be available for route registration")
		}
	})
	
	t.Run("register routes with disabled API", func(t *testing.T) {
		config := &SessionIntegrationConfig{
			EnableAPI: false,
		}
		
		serviceNoAPI := NewSessionIntegrationService(auditLogger, config)
		defer serviceNoAPI.Stop()
		
		mux := http.NewServeMux()
		serviceNoAPI.RegisterAPIRoutes(mux) // Should not panic
		
		if serviceNoAPI.GetSessionAPI() != nil {
			t.Error("expected session API to be disabled")
		}
	})
}

func TestSessionIntegrationService_TrackSessionActivity(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	service := NewSessionIntegrationService(auditLogger, nil)
	defer service.Stop()
	
	err := service.Start()
	if err != nil {
		t.Fatalf("failed to start service: %v", err)
	}
	
	// Create test session
	session, err := service.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("track session activity", func(t *testing.T) {
		// Track additional activity
		service.TrackSessionActivity(session.ID, session.UserID, "192.168.1.1", "test-agent")
		service.TrackSessionActivity(session.ID, session.UserID, "192.168.1.1", "test-agent")
		
		// Check that activity was tracked
		if service.GetSecurityMonitor() != nil {
			activity := service.GetSessionActivity(session.ID)
			if activity == nil {
				t.Fatal("expected session activity to be tracked")
			}
			
			if activity.RequestCount < 3 { // Create + 2 manual tracks
				t.Errorf("expected at least 3 requests tracked, got %d", activity.RequestCount)
			}
		}
	})
}

func TestSessionIntegrationService_HealthCheck(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	service := NewSessionIntegrationService(auditLogger, nil)
	defer service.Stop()
	
	err := service.Start()
	if err != nil {
		t.Fatalf("failed to start service: %v", err)
	}
	
	t.Run("health check", func(t *testing.T) {
		health := service.HealthCheck()
		if health == nil {
			t.Fatal("expected non-nil health status")
		}
		
		if health.Overall != "healthy" {
			t.Errorf("expected overall status 'healthy', got '%s'", health.Overall)
		}
		
		if health.Services["session_manager"].Status != "healthy" {
			t.Error("expected session manager to be healthy")
		}
		
		if health.Services["security_monitor"].Status != "healthy" {
			t.Error("expected security monitor to be healthy")
		}
		
		if health.Services["cleanup_service"].Status != "healthy" {
			t.Error("expected cleanup service to be healthy")
		}
		
		if health.Services["session_api"].Status != "healthy" {
			t.Error("expected session API to be healthy")
		}
		
		if health.Timestamp.IsZero() {
			t.Error("expected timestamp to be set")
		}
	})
}

func TestSessionIntegrationService_UpdateConfigs(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	service := NewSessionIntegrationService(auditLogger, nil)
	defer service.Stop()
	
	t.Run("update security config", func(t *testing.T) {
		newConfig := &SecurityMonitorConfig{
			Enabled:                  true,
			DetectConcurrentSessions: true,
			MaxConcurrentSessions:    10,
		}
		
		err := service.UpdateSecurityConfig(newConfig)
		if err != nil {
			t.Fatalf("failed to update security config: %v", err)
		}
	})
	
	t.Run("update cleanup config", func(t *testing.T) {
		newConfig := &CleanupConfig{
			CleanupInterval: 30 * time.Minute,
			MaxCleanupBatch: 500,
		}
		
		err := service.UpdateCleanupConfig(newConfig)
		if err != nil {
			t.Fatalf("failed to update cleanup config: %v", err)
		}
	})
	
	t.Run("update config with disabled services", func(t *testing.T) {
		config := &SessionIntegrationConfig{
			EnableSecurity: false,
			EnableCleanup:  false,
		}
		
		serviceDisabled := NewSessionIntegrationService(auditLogger, config)
		defer serviceDisabled.Stop()
		
		err := serviceDisabled.UpdateSecurityConfig(&SecurityMonitorConfig{})
		if err == nil {
			t.Error("expected error when updating security config with disabled security monitor")
		}
		
		err = serviceDisabled.UpdateCleanupConfig(&CleanupConfig{})
		if err == nil {
			t.Error("expected error when updating cleanup config with disabled cleanup service")
		}
	})
}

func TestSessionIntegrationService_SessionOperations(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	service := NewSessionIntegrationService(auditLogger, nil)
	defer service.Stop()
	
	err := service.Start()
	if err != nil {
		t.Fatalf("failed to start service: %v", err)
	}
	
	// Create test sessions
	session1, err := service.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("failed to create session1: %v", err)
	}
	
	_, err = service.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.2",
	})
	if err != nil {
		t.Fatalf("failed to create session2: %v", err)
	}
	
	t.Run("get active sessions", func(t *testing.T) {
		sessions, err := service.GetActiveSessions("user1")
		if err != nil {
			t.Fatalf("failed to get active sessions: %v", err)
		}
		
		if len(sessions) != 2 {
			t.Errorf("expected 2 active sessions, got %d", len(sessions))
		}
	})
	
	t.Run("refresh session", func(t *testing.T) {
		err := service.RefreshSession(session1.ID)
		if err != nil {
			t.Fatalf("failed to refresh session: %v", err)
		}
	})
	
	t.Run("get session info", func(t *testing.T) {
		info, err := service.GetSessionInfo(session1.ID)
		if err != nil {
			t.Fatalf("failed to get session info: %v", err)
		}
		
		if info.ID != session1.ID {
			t.Errorf("expected session ID '%s', got '%s'", session1.ID, info.ID)
		}
	})
	
	t.Run("list all active sessions", func(t *testing.T) {
		sessions, err := service.ListAllActiveSessions()
		if err != nil {
			t.Fatalf("failed to list all active sessions: %v", err)
		}
		
		if len(sessions) != 2 {
			t.Errorf("expected 2 active sessions, got %d", len(sessions))
		}
	})
	
	t.Run("terminate session", func(t *testing.T) {
		err := service.TerminateSession(session1.ID)
		if err != nil {
			t.Fatalf("failed to terminate session: %v", err)
		}
		
		// Verify session is terminated
		_, err = service.ValidateSession(session1.ID)
		if err != ErrSessionNotFound {
			t.Errorf("expected session to be terminated, got error: %v", err)
		}
	})
	
	t.Run("terminate all user sessions", func(t *testing.T) {
		err := service.TerminateAllUserSessions("user1")
		if err != nil {
			t.Fatalf("failed to terminate all user sessions: %v", err)
		}
		
		// Verify all sessions are terminated
		sessions, err := service.GetActiveSessions("user1")
		if err != nil {
			t.Fatalf("failed to get active sessions: %v", err)
		}
		
		if len(sessions) != 0 {
			t.Errorf("expected 0 active sessions, got %d", len(sessions))
		}
	})
	
	t.Run("cleanup expired sessions", func(t *testing.T) {
		err := service.CleanupExpiredSessions()
		if err != nil {
			t.Fatalf("failed to cleanup expired sessions: %v", err)
		}
	})
}

func TestSessionIntegrationService_ActivityTracking(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	service := NewSessionIntegrationService(auditLogger, nil)
	defer service.Stop()
	
	err := service.Start()
	if err != nil {
		t.Fatalf("failed to start service: %v", err)
	}
	
	// Create test session
	session, err := service.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("get user activity", func(t *testing.T) {
		activity := service.GetUserActivity("user1")
		if activity == nil {
			t.Error("expected user activity to be tracked")
		} else {
			if activity.UserID != "user1" {
				t.Errorf("expected user ID 'user1', got '%s'", activity.UserID)
			}
		}
	})
	
	t.Run("get session activity", func(t *testing.T) {
		activity := service.GetSessionActivity(session.ID)
		if activity == nil {
			t.Error("expected session activity to be tracked")
		} else {
			if activity.SessionID != session.ID {
				t.Errorf("expected session ID '%s', got '%s'", session.ID, activity.SessionID)
			}
		}
	})
}