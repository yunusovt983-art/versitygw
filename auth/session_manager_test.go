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

// MockSecurityAuditLoggerForSessions for testing
type MockSecurityAuditLoggerForSessions struct {
	events []interface{}
}

func (m *MockSecurityAuditLoggerForSessions) LogSecurityEvent(event *SecurityEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *MockSecurityAuditLoggerForSessions) LogAuthenticationAttempt(userID, ipAddress, userAgent string, success bool, details *AuthenticationDetails) error {
	return nil
}

func (m *MockSecurityAuditLoggerForSessions) LogMFAAttempt(userID, ipAddress string, success bool, details map[string]interface{}) error {
	return nil
}

func (m *MockSecurityAuditLoggerForSessions) LogSuspiciousActivity(pattern *SuspiciousPattern) error {
	return nil
}

func (m *MockSecurityAuditLoggerForSessions) LogUserLockout(userID, reason string, duration time.Duration) error {
	return nil
}

func (m *MockSecurityAuditLoggerForSessions) LogPermissionDenied(userID, resource, action, reason string) error {
	return nil
}

func (m *MockSecurityAuditLoggerForSessions) LogSessionSecurityEvent(sessionID, userID, eventType, description string, severity SecuritySeverity, details map[string]interface{}) error {
	return nil
}

func (m *MockSecurityAuditLoggerForSessions) GetSecurityEvents(filter *SecurityEventFilter) ([]*SecurityEvent, error) {
	return nil, nil
}

func (m *MockSecurityAuditLoggerForSessions) Close() error {
	return nil
}

func TestNewSessionManager(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	
	t.Run("with default config", func(t *testing.T) {
		sm := NewSessionManager(nil, auditLogger)
		if sm == nil {
			t.Fatal("expected non-nil session manager")
		}
		
		stats := sm.GetSessionStats()
		if stats.TotalActiveSessions != 0 {
			t.Errorf("expected 0 active sessions, got %d", stats.TotalActiveSessions)
		}
		
		sm.Shutdown()
	})
	
	t.Run("with custom config", func(t *testing.T) {
		config := &SessionConfig{
			DefaultTTL:         1 * time.Hour,
			MaxSessionsPerUser: 5,
			CleanupInterval:    1 * time.Minute,
		}
		
		sm := NewSessionManager(config, auditLogger)
		if sm == nil {
			t.Fatal("expected non-nil session manager")
		}
		
		sm.Shutdown()
	})
}

func TestSessionManager_CreateSession(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	config := &SessionConfig{
		DefaultTTL:         1 * time.Hour,
		MaxSessionsPerUser: 3,
		CleanupInterval:    0, // Disable cleanup for testing
	}
	sm := NewSessionManager(config, auditLogger)
	defer sm.Shutdown()
	
	t.Run("successful session creation", func(t *testing.T) {
		metadata := &SessionMetadata{
			IPAddress: "192.168.1.1",
			UserAgent: "test-agent",
			MFAVerified: true,
			Provider: "test-provider",
		}
		
		session, err := sm.CreateSession("user1", metadata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		if session.ID == "" {
			t.Error("expected non-empty session ID")
		}
		
		if session.UserID != "user1" {
			t.Errorf("expected user ID 'user1', got '%s'", session.UserID)
		}
		
		if session.IPAddress != "192.168.1.1" {
			t.Errorf("expected IP address '192.168.1.1', got '%s'", session.IPAddress)
		}
		
		if !session.MFAVerified {
			t.Error("expected MFA verified to be true")
		}
		
		if session.Provider != "test-provider" {
			t.Errorf("expected provider 'test-provider', got '%s'", session.Provider)
		}
		
		// Check if session is tracked
		stats := sm.GetSessionStats()
		if stats.TotalActiveSessions != 1 {
			t.Errorf("expected 1 active session, got %d", stats.TotalActiveSessions)
		}
	})
	
	t.Run("session creation with empty user ID", func(t *testing.T) {
		_, err := sm.CreateSession("", nil)
		if err != ErrUserNotFound {
			t.Errorf("expected ErrUserNotFound, got %v", err)
		}
	})
	
	t.Run("session limit enforcement", func(t *testing.T) {
		// Create sessions up to the limit
		for i := 0; i < 3; i++ {
			_, err := sm.CreateSession("user2", &SessionMetadata{
				IPAddress: "192.168.1.2",
			})
			if err != nil {
				t.Fatalf("unexpected error creating session %d: %v", i, err)
			}
		}
		
		// Create one more session (should remove oldest)
		_, err := sm.CreateSession("user2", &SessionMetadata{
			IPAddress: "192.168.1.2",
		})
		if err != nil {
			t.Fatalf("unexpected error creating session beyond limit: %v", err)
		}
		
		// Check that user still has only 3 sessions
		sessions, err := sm.GetActiveSessions("user2")
		if err != nil {
			t.Fatalf("unexpected error getting active sessions: %v", err)
		}
		
		if len(sessions) != 3 {
			t.Errorf("expected 3 active sessions, got %d", len(sessions))
		}
	})
}

func TestSessionManager_ValidateSession(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	config := &SessionConfig{
		DefaultTTL:        1 * time.Hour,
		InactivityTimeout: 30 * time.Minute,
		CleanupInterval:   0,
	}
	sm := NewSessionManager(config, auditLogger)
	defer sm.Shutdown()
	
	// Create a test session
	session, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("validate valid session", func(t *testing.T) {
		// Wait a bit to ensure time difference
		time.Sleep(10 * time.Millisecond)
		
		validatedSession, err := sm.ValidateSession(session.ID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		if validatedSession.ID != session.ID {
			t.Errorf("expected session ID '%s', got '%s'", session.ID, validatedSession.ID)
		}
		
		// Last used time should be updated or at least equal (due to time resolution)
		if validatedSession.LastUsed.Before(session.LastUsed) {
			t.Error("expected last used time to be updated or at least equal")
		}
	})
	
	t.Run("validate non-existent session", func(t *testing.T) {
		_, err := sm.ValidateSession("non-existent")
		if err != ErrSessionNotFound {
			t.Errorf("expected ErrSessionNotFound, got %v", err)
		}
	})
	
	t.Run("validate empty session ID", func(t *testing.T) {
		_, err := sm.ValidateSession("")
		if err != ErrInvalidSessionID {
			t.Errorf("expected ErrInvalidSessionID, got %v", err)
		}
	})
}

func TestSessionManager_RefreshSession(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	config := &SessionConfig{
		DefaultTTL:  1 * time.Hour,
		MaxTTL:      24 * time.Hour,
		CleanupInterval: 0,
	}
	sm := NewSessionManager(config, auditLogger)
	defer sm.Shutdown()
	
	// Create a test session
	session, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	originalExpiry := session.ExpiresAt
	
	t.Run("refresh valid session", func(t *testing.T) {
		// Wait a bit to ensure time difference
		time.Sleep(10 * time.Millisecond)
		
		err := sm.RefreshSession(session.ID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		// Get updated session info
		updatedSession, err := sm.GetSessionInfo(session.ID)
		if err != nil {
			t.Fatalf("failed to get session info: %v", err)
		}
		
		// Expiry should be extended
		if !updatedSession.ExpiresAt.After(originalExpiry) {
			t.Error("expected expiry time to be extended")
		}
		
		// Last used should be updated or at least equal (due to time resolution)
		if updatedSession.LastUsed.Before(session.LastUsed) {
			t.Error("expected last used time to be updated or at least equal")
		}
	})
	
	t.Run("refresh non-existent session", func(t *testing.T) {
		err := sm.RefreshSession("non-existent")
		if err != ErrSessionNotFound {
			t.Errorf("expected ErrSessionNotFound, got %v", err)
		}
	})
}

func TestSessionManager_TerminateSession(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	// Create a test session
	session, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("terminate existing session", func(t *testing.T) {
		err := sm.TerminateSession(session.ID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		// Session should no longer exist
		_, err = sm.ValidateSession(session.ID)
		if err != ErrSessionNotFound {
			t.Errorf("expected ErrSessionNotFound, got %v", err)
		}
		
		// Stats should be updated
		stats := sm.GetSessionStats()
		if stats.TotalActiveSessions != 0 {
			t.Errorf("expected 0 active sessions, got %d", stats.TotalActiveSessions)
		}
	})
	
	t.Run("terminate non-existent session", func(t *testing.T) {
		err := sm.TerminateSession("non-existent")
		if err != ErrSessionNotFound {
			t.Errorf("expected ErrSessionNotFound, got %v", err)
		}
	})
}

func TestSessionManager_TerminateAllUserSessions(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	// Create multiple sessions for user1
	var sessions []*UserSession
	for i := 0; i < 3; i++ {
		session, err := sm.CreateSession("user1", &SessionMetadata{
			IPAddress: "192.168.1.1",
		})
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
		sessions = append(sessions, session)
	}
	
	// Create a session for user2
	user2Session, err := sm.CreateSession("user2", &SessionMetadata{
		IPAddress: "192.168.1.2",
	})
	if err != nil {
		t.Fatalf("failed to create session for user2: %v", err)
	}
	
	t.Run("terminate all user sessions", func(t *testing.T) {
		err := sm.TerminateAllUserSessions("user1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		// All user1 sessions should be gone
		activeSessions, err := sm.GetActiveSessions("user1")
		if err != nil {
			t.Fatalf("unexpected error getting active sessions: %v", err)
		}
		
		if len(activeSessions) != 0 {
			t.Errorf("expected 0 active sessions for user1, got %d", len(activeSessions))
		}
		
		// user2 session should still exist
		_, err = sm.ValidateSession(user2Session.ID)
		if err != nil {
			t.Errorf("user2 session should still be valid: %v", err)
		}
	})
	
	t.Run("terminate sessions for non-existent user", func(t *testing.T) {
		err := sm.TerminateAllUserSessions("non-existent-user")
		if err != nil {
			t.Errorf("expected no error for non-existent user, got %v", err)
		}
	})
}

func TestSessionManager_GetActiveSessions(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	// Create sessions for user1
	for i := 0; i < 2; i++ {
		_, err := sm.CreateSession("user1", &SessionMetadata{
			IPAddress: "192.168.1.1",
		})
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
	}
	
	// Create session for user2
	_, err := sm.CreateSession("user2", &SessionMetadata{
		IPAddress: "192.168.1.2",
	})
	if err != nil {
		t.Fatalf("failed to create session for user2: %v", err)
	}
	
	t.Run("get active sessions for user1", func(t *testing.T) {
		sessions, err := sm.GetActiveSessions("user1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		if len(sessions) != 2 {
			t.Errorf("expected 2 active sessions, got %d", len(sessions))
		}
		
		for _, session := range sessions {
			if session.UserID != "user1" {
				t.Errorf("expected user ID 'user1', got '%s'", session.UserID)
			}
		}
	})
	
	t.Run("get active sessions for user2", func(t *testing.T) {
		sessions, err := sm.GetActiveSessions("user2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		if len(sessions) != 1 {
			t.Errorf("expected 1 active session, got %d", len(sessions))
		}
	})
	
	t.Run("get active sessions for non-existent user", func(t *testing.T) {
		sessions, err := sm.GetActiveSessions("non-existent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		if len(sessions) != 0 {
			t.Errorf("expected 0 active sessions, got %d", len(sessions))
		}
	})
}

func TestSessionManager_CleanupExpiredSessions(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	config := &SessionConfig{
		DefaultTTL:        100 * time.Millisecond, // Very short TTL for testing
		InactivityTimeout: 50 * time.Millisecond,
		CleanupInterval:   0, // Disable automatic cleanup
	}
	sm := NewSessionManager(config, auditLogger)
	defer sm.Shutdown()
	
	// Create a session
	session, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	// Wait for session to expire
	time.Sleep(150 * time.Millisecond)
	
	t.Run("cleanup expired sessions", func(t *testing.T) {
		err := sm.CleanupExpiredSessions()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		// Session should be removed
		_, err = sm.ValidateSession(session.ID)
		if err != ErrSessionNotFound {
			t.Errorf("expected ErrSessionNotFound, got %v", err)
		}
		
		// Stats should reflect cleanup
		stats := sm.GetSessionStats()
		if stats.ExpiredSessions == 0 {
			t.Error("expected expired sessions count to be > 0")
		}
	})
}

func TestSessionManager_GetSessionStats(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	// Create sessions for different users and providers
	_, err := sm.CreateSession("user1", &SessionMetadata{
		Provider: "provider1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	_, err = sm.CreateSession("user1", &SessionMetadata{
		Provider: "provider1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	_, err = sm.CreateSession("user2", &SessionMetadata{
		Provider: "provider2",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("get session statistics", func(t *testing.T) {
		stats := sm.GetSessionStats()
		
		if stats.TotalActiveSessions != 3 {
			t.Errorf("expected 3 total active sessions, got %d", stats.TotalActiveSessions)
		}
		
		if stats.SessionsByUser["user1"] != 2 {
			t.Errorf("expected 2 sessions for user1, got %d", stats.SessionsByUser["user1"])
		}
		
		if stats.SessionsByUser["user2"] != 1 {
			t.Errorf("expected 1 session for user2, got %d", stats.SessionsByUser["user2"])
		}
		
		if stats.SessionsByProvider["provider1"] != 2 {
			t.Errorf("expected 2 sessions for provider1, got %d", stats.SessionsByProvider["provider1"])
		}
		
		if stats.SessionsByProvider["provider2"] != 1 {
			t.Errorf("expected 1 session for provider2, got %d", stats.SessionsByProvider["provider2"])
		}
		
		if stats.CreatedSessions != 3 {
			t.Errorf("expected 3 created sessions, got %d", stats.CreatedSessions)
		}
	})
}

func TestSessionManager_LegacyInterface(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	// Create sessions for testing
	session1, err := sm.CreateSession("user1", &SessionMetadata{})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	session2, err := sm.CreateSession("user1", &SessionMetadata{})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("InvalidateUserSessions", func(t *testing.T) {
		err := sm.InvalidateUserSessions("user1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		// Sessions should be terminated
		_, err = sm.ValidateSession(session1.ID)
		if err != ErrSessionNotFound {
			t.Errorf("expected ErrSessionNotFound, got %v", err)
		}
		
		_, err = sm.ValidateSession(session2.ID)
		if err != ErrSessionNotFound {
			t.Errorf("expected ErrSessionNotFound, got %v", err)
		}
	})
	
	t.Run("GetActiveUserSessions", func(t *testing.T) {
		// Create new sessions
		_, err := sm.CreateSession("user2", &SessionMetadata{})
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}
		
		_, err = sm.CreateSession("user2", &SessionMetadata{})
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}
		
		sessionIDs, err := sm.GetActiveUserSessions("user2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		if len(sessionIDs) != 2 {
			t.Errorf("expected 2 session IDs, got %d", len(sessionIDs))
		}
	})
	
	t.Run("RefreshUserPermissions", func(t *testing.T) {
		err := sm.RefreshUserPermissions("user1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		// Should log an event
		if len(auditLogger.events) == 0 {
			t.Error("expected audit event to be logged")
		}
	})
	
	t.Run("NotifySessionUpdate", func(t *testing.T) {
		err := sm.NotifySessionUpdate("session123", "permission_change")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		
		// Should log an event
		found := false
		for _, event := range auditLogger.events {
			if securityEvent, ok := event.(*SecurityEvent); ok {
				if securityEvent.Type == EventTypeSessionCreated {
					found = true
					break
				}
			}
		}
		
		if !found {
			t.Error("expected session update event to be logged")
		}
	})
}

func TestSessionManager_ConcurrentAccess(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	// Test concurrent session creation and validation
	t.Run("concurrent operations", func(t *testing.T) {
		const numGoroutines = 10
		const sessionsPerGoroutine = 5
		
		done := make(chan bool, numGoroutines)
		
		// Create sessions concurrently
		for i := 0; i < numGoroutines; i++ {
			go func(userID string) {
				defer func() { done <- true }()
				
				for j := 0; j < sessionsPerGoroutine; j++ {
					session, err := sm.CreateSession(userID, &SessionMetadata{
						IPAddress: "192.168.1.1",
					})
					if err != nil {
						t.Errorf("failed to create session: %v", err)
						return
					}
					
					// Validate the session
					_, err = sm.ValidateSession(session.ID)
					if err != nil {
						t.Errorf("failed to validate session: %v", err)
						return
					}
				}
			}(fmt.Sprintf("user%d", i))
		}
		
		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines; i++ {
			<-done
		}
		
		// Check final stats
		stats := sm.GetSessionStats()
		expectedSessions := numGoroutines * sessionsPerGoroutine
		if stats.TotalActiveSessions != expectedSessions {
			t.Errorf("expected %d active sessions, got %d", expectedSessions, stats.TotalActiveSessions)
		}
	})
}

func TestSessionManager_SessionExpiration(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	config := &SessionConfig{
		DefaultTTL:        50 * time.Millisecond,
		InactivityTimeout: 0, // Disable inactivity timeout for this test
		CleanupInterval:   0, // Disable automatic cleanup
	}
	sm := NewSessionManager(config, auditLogger)
	defer sm.Shutdown()
	
	// Create a session
	session, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	// Session should be valid initially
	_, err = sm.ValidateSession(session.ID)
	if err != nil {
		t.Fatalf("session should be valid initially: %v", err)
	}
	
	// Wait for session to expire
	time.Sleep(100 * time.Millisecond)
	
	// Session should now be expired
	_, err = sm.ValidateSession(session.ID)
	if err != ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func TestSessionManager_InactivityTimeout(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	config := &SessionConfig{
		DefaultTTL:        1 * time.Hour, // Long TTL
		InactivityTimeout: 50 * time.Millisecond,
		CleanupInterval:   0,
	}
	sm := NewSessionManager(config, auditLogger)
	defer sm.Shutdown()
	
	// Create a session
	session, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	// Wait for inactivity timeout
	time.Sleep(100 * time.Millisecond)
	
	// Session should be expired due to inactivity
	_, err = sm.ValidateSession(session.ID)
	if err != ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired due to inactivity, got %v", err)
	}
}