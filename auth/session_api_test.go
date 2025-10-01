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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionAPI_ListAllSessions(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	api := NewSessionAPI(sm, auditLogger)
	
	// Create test sessions
	for i := 0; i < 5; i++ {
		_, err := sm.CreateSession(fmt.Sprintf("user%d", i), &SessionMetadata{
			IPAddress: "192.168.1.1",
		})
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
	}
	
	t.Run("list all sessions", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
		w := httptest.NewRecorder()
		
		api.listAllSessions(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		var response SessionListResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		
		if response.TotalCount != 5 {
			t.Errorf("expected 5 sessions, got %d", response.TotalCount)
		}
		
		if len(response.Sessions) != 5 {
			t.Errorf("expected 5 sessions in response, got %d", len(response.Sessions))
		}
	})
	
	t.Run("list sessions with pagination", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions?page=1&page_size=2", nil)
		w := httptest.NewRecorder()
		
		api.listAllSessions(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		var response SessionListResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		
		if response.TotalCount != 5 {
			t.Errorf("expected total count 5, got %d", response.TotalCount)
		}
		
		if len(response.Sessions) != 2 {
			t.Errorf("expected 2 sessions in page, got %d", len(response.Sessions))
		}
		
		if response.CurrentPage != 1 {
			t.Errorf("expected page 1, got %d", response.CurrentPage)
		}
		
		if response.PageSize != 2 {
			t.Errorf("expected page size 2, got %d", response.PageSize)
		}
	})
}

func TestSessionAPI_GetSessionInfo(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	api := NewSessionAPI(sm, auditLogger)
	
	// Create test session
	session, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
		UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("get existing session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/sessions/%s", session.ID), nil)
		w := httptest.NewRecorder()
		
		api.getSessionInfo(w, req, session.ID)
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		var response UserSession
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		
		if response.ID != session.ID {
			t.Errorf("expected session ID %s, got %s", session.ID, response.ID)
		}
		
		if response.UserID != "user1" {
			t.Errorf("expected user ID 'user1', got %s", response.UserID)
		}
	})
	
	t.Run("get non-existent session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/non-existent", nil)
		w := httptest.NewRecorder()
		
		api.getSessionInfo(w, req, "non-existent")
		
		if w.Code != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", w.Code)
		}
	})
}

func TestSessionAPI_GetUserSessions(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	api := NewSessionAPI(sm, auditLogger)
	
	// Create test sessions for user1
	for i := 0; i < 3; i++ {
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
	
	t.Run("get user sessions", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/user1/sessions", nil)
		w := httptest.NewRecorder()
		
		api.getUserSessions(w, req, "user1")
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		var response SessionListResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		
		if response.TotalCount != 3 {
			t.Errorf("expected 3 sessions for user1, got %d", response.TotalCount)
		}
		
		for _, session := range response.Sessions {
			if session.UserID != "user1" {
				t.Errorf("expected user ID 'user1', got %s", session.UserID)
			}
		}
	})
}

func TestSessionAPI_TerminateSession(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	api := NewSessionAPI(sm, auditLogger)
	
	// Create test session
	session, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	t.Run("terminate existing session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/sessions/%s", session.ID), nil)
		w := httptest.NewRecorder()
		
		api.terminateSession(w, req, session.ID)
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		var response SessionActionResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		
		if !response.Success {
			t.Error("expected success to be true")
		}
		
		if response.AffectedCount != 1 {
			t.Errorf("expected affected count 1, got %d", response.AffectedCount)
		}
		
		// Verify session is terminated
		_, err := sm.ValidateSession(session.ID)
		if err != ErrSessionNotFound {
			t.Errorf("expected session to be terminated, got error: %v", err)
		}
	})
	
	t.Run("terminate non-existent session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/non-existent", nil)
		w := httptest.NewRecorder()
		
		api.terminateSession(w, req, "non-existent")
		
		if w.Code != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", w.Code)
		}
	})
}

func TestSessionAPI_TerminateUserSessions(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	api := NewSessionAPI(sm, auditLogger)
	
	// Create test sessions for user1
	for i := 0; i < 3; i++ {
		_, err := sm.CreateSession("user1", &SessionMetadata{
			IPAddress: "192.168.1.1",
		})
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
	}
	
	t.Run("terminate all user sessions", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/user1/sessions", nil)
		w := httptest.NewRecorder()
		
		api.terminateUserSessions(w, req, "user1")
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		var response SessionActionResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		
		if !response.Success {
			t.Error("expected success to be true")
		}
		
		if response.AffectedCount != 3 {
			t.Errorf("expected affected count 3, got %d", response.AffectedCount)
		}
		
		// Verify all sessions are terminated
		sessions, err := sm.GetActiveSessions("user1")
		if err != nil {
			t.Fatalf("failed to get active sessions: %v", err)
		}
		
		if len(sessions) != 0 {
			t.Errorf("expected 0 active sessions, got %d", len(sessions))
		}
	})
}

func TestSessionAPI_GetSessionStats(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	api := NewSessionAPI(sm, auditLogger)
	
	// Create test sessions
	for i := 0; i < 3; i++ {
		_, err := sm.CreateSession(fmt.Sprintf("user%d", i), &SessionMetadata{
			IPAddress: "192.168.1.1",
			Provider:  "test-provider",
		})
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
	}
	
	t.Run("get session statistics", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/stats", nil)
		w := httptest.NewRecorder()
		
		api.getSessionStats(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		var response SessionStatsResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		
		if response.Stats.TotalActiveSessions != 3 {
			t.Errorf("expected 3 active sessions, got %d", response.Stats.TotalActiveSessions)
		}
		
		if response.Stats.SessionsByProvider["test-provider"] != 3 {
			t.Errorf("expected 3 sessions for test-provider, got %d", response.Stats.SessionsByProvider["test-provider"])
		}
	})
}

func TestSessionAPI_PerformSessionActions(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	api := NewSessionAPI(sm, auditLogger)
	
	// Create test sessions
	var sessionIDs []string
	for i := 0; i < 3; i++ {
		session, err := sm.CreateSession("user1", &SessionMetadata{
			IPAddress: "192.168.1.1",
		})
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
		sessionIDs = append(sessionIDs, session.ID)
	}
	
	t.Run("bulk terminate sessions", func(t *testing.T) {
		request := SessionActionRequest{
			Action:     "terminate",
			SessionIDs: sessionIDs[:2], // Terminate first 2 sessions
			Reason:     "test termination",
		}
		
		body, _ := json.Marshal(request)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/actions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		api.performSessionActions(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		var response SessionActionResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		
		if !response.Success {
			t.Error("expected success to be true")
		}
		
		if response.AffectedCount != 2 {
			t.Errorf("expected affected count 2, got %d", response.AffectedCount)
		}
		
		// Verify sessions are terminated
		for _, sessionID := range sessionIDs[:2] {
			_, err := sm.ValidateSession(sessionID)
			if err != ErrSessionNotFound {
				t.Errorf("expected session %s to be terminated", sessionID)
			}
		}
		
		// Verify third session still exists
		_, err := sm.ValidateSession(sessionIDs[2])
		if err != nil {
			t.Errorf("expected session %s to still exist: %v", sessionIDs[2], err)
		}
	})
	
	t.Run("bulk refresh sessions", func(t *testing.T) {
		request := SessionActionRequest{
			Action:     "refresh",
			SessionIDs: []string{sessionIDs[2]}, // Refresh remaining session
		}
		
		body, _ := json.Marshal(request)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/actions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		api.performSessionActions(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		var response SessionActionResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		
		if !response.Success {
			t.Error("expected success to be true")
		}
		
		if response.AffectedCount != 1 {
			t.Errorf("expected affected count 1, got %d", response.AffectedCount)
		}
	})
	
	t.Run("invalid action", func(t *testing.T) {
		request := SessionActionRequest{
			Action: "invalid",
		}
		
		body, _ := json.Marshal(request)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/actions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		api.performSessionActions(w, req)
		
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})
}

func TestSessionAPI_CleanupSessions(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	config := &SessionConfig{
		DefaultTTL:      100 * time.Millisecond, // Very short TTL for testing
		CleanupInterval: 0,                      // Disable automatic cleanup
	}
	sm := NewSessionManager(config, auditLogger)
	defer sm.Shutdown()
	
	api := NewSessionAPI(sm, auditLogger)
	
	// Create test session
	_, err := sm.CreateSession("user1", &SessionMetadata{
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	// Wait for session to expire
	time.Sleep(150 * time.Millisecond)
	
	t.Run("manual cleanup", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/cleanup", nil)
		w := httptest.NewRecorder()
		
		api.cleanupSessions(w, req)
		
		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
		
		var response SessionActionResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		
		if !response.Success {
			t.Error("expected success to be true")
		}
	})
}

func TestSessionAPI_RegisterRoutes(t *testing.T) {
	auditLogger := &MockSecurityAuditLoggerForSessions{}
	sm := NewSessionManager(nil, auditLogger)
	defer sm.Shutdown()
	
	api := NewSessionAPI(sm, auditLogger)
	mux := http.NewServeMux()
	
	// Register routes
	api.RegisterRoutes(mux)
	
	// Test that routes are registered by making requests
	testCases := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/api/v1/sessions", http.StatusOK},
		{http.MethodGet, "/api/v1/sessions/stats", http.StatusOK},
		{http.MethodPost, "/api/v1/sessions/cleanup", http.StatusOK},
	}
	
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s %s", tc.method, tc.path), func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			
			mux.ServeHTTP(w, req)
			
			if w.Code != tc.status {
				t.Errorf("expected status %d, got %d", tc.status, w.Code)
			}
		})
	}
}