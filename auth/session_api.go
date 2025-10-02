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
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SessionAPI provides HTTP API endpoints for session management
type SessionAPI struct {
	sessionManager EnhancedSessionManager
	auditLogger    SecurityAuditLogger
}

// NewSessionAPI creates a new session API instance
func NewSessionAPI(sessionManager EnhancedSessionManager, auditLogger SecurityAuditLogger) *SessionAPI {
	return &SessionAPI{
		sessionManager: sessionManager,
		auditLogger:    auditLogger,
	}
}

// SessionListResponse represents the response for listing sessions
type SessionListResponse struct {
	Sessions    []*UserSession `json:"sessions"`
	TotalCount  int            `json:"total_count"`
	CurrentPage int            `json:"current_page"`
	PageSize    int            `json:"page_size"`
}

// SessionStatsResponse represents the response for session statistics
type SessionStatsResponse struct {
	Stats     *SessionStats `json:"stats"`
	Timestamp time.Time     `json:"timestamp"`
}

// SessionActionRequest represents a request to perform an action on sessions
type SessionActionRequest struct {
	Action    string   `json:"action"`    // "terminate", "refresh", "extend"
	SessionIDs []string `json:"session_ids,omitempty"`
	UserID    string   `json:"user_id,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

// SessionActionResponse represents the response for session actions
type SessionActionResponse struct {
	Success        bool     `json:"success"`
	Message        string   `json:"message"`
	AffectedCount  int      `json:"affected_count"`
	FailedSessions []string `json:"failed_sessions,omitempty"`
}

// RegisterRoutes registers session API routes with the provided mux
func (api *SessionAPI) RegisterRoutes(mux *http.ServeMux) {
	// Session listing and info endpoints
	mux.HandleFunc("/api/v1/sessions", api.handleSessions)
	mux.HandleFunc("/api/v1/sessions/", api.handleSessionByID)
	mux.HandleFunc("/api/v1/users/", api.handleUserSessions)
	
	// Session statistics endpoint
	mux.HandleFunc("/api/v1/sessions/stats", api.handleSessionStats)
	
	// Session actions endpoint
	mux.HandleFunc("/api/v1/sessions/actions", api.handleSessionActions)
	
	// Session cleanup endpoint
	mux.HandleFunc("/api/v1/sessions/cleanup", api.handleSessionCleanup)
}

// handleSessions handles requests to list all sessions
func (api *SessionAPI) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		api.listAllSessions(w, r)
	default:
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleSessionByID handles requests for specific sessions
func (api *SessionAPI) handleSessionByID(w http.ResponseWriter, r *http.Request) {
	// Extract session ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/sessions/")
	sessionID := strings.Split(path, "/")[0]
	
	if sessionID == "" {
		api.writeError(w, http.StatusBadRequest, "Session ID required")
		return
	}
	
	switch r.Method {
	case http.MethodGet:
		api.getSessionInfo(w, r, sessionID)
	case http.MethodDelete:
		api.terminateSession(w, r, sessionID)
	default:
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleUserSessions handles requests for user-specific sessions
func (api *SessionAPI) handleUserSessions(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "sessions" {
		api.writeError(w, http.StatusBadRequest, "Invalid path")
		return
	}
	
	userID := parts[0]
	if userID == "" {
		api.writeError(w, http.StatusBadRequest, "User ID required")
		return
	}
	
	switch r.Method {
	case http.MethodGet:
		api.getUserSessions(w, r, userID)
	case http.MethodDelete:
		api.terminateUserSessions(w, r, userID)
	default:
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleSessionStats handles requests for session statistics
func (api *SessionAPI) handleSessionStats(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		api.getSessionStats(w, r)
	default:
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleSessionActions handles bulk session actions
func (api *SessionAPI) handleSessionActions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		api.performSessionActions(w, r)
	default:
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleSessionCleanup handles session cleanup requests
func (api *SessionAPI) handleSessionCleanup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		api.cleanupSessions(w, r)
	default:
		api.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// listAllSessions lists all active sessions with pagination
func (api *SessionAPI) listAllSessions(w http.ResponseWriter, r *http.Request) {
	// Parse pagination parameters
	page, pageSize := api.parsePagination(r)
	
	// Get all active sessions
	sessions, err := api.sessionManager.ListAllActiveSessions()
	if err != nil {
		api.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to list sessions: %v", err))
		return
	}
	
	// Apply pagination
	start := (page - 1) * pageSize
	end := start + pageSize
	
	if start > len(sessions) {
		start = len(sessions)
	}
	if end > len(sessions) {
		end = len(sessions)
	}
	
	paginatedSessions := sessions[start:end]
	
	response := &SessionListResponse{
		Sessions:    paginatedSessions,
		TotalCount:  len(sessions),
		CurrentPage: page,
		PageSize:    pageSize,
	}
	
	api.writeJSON(w, http.StatusOK, response)
	
	// Log the access
	if api.auditLogger != nil {
		api.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypePermissionDenied, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			Success:   true,
			Message:   "Session list accessed",
			Details: map[string]interface{}{
				"action":      "list_sessions",
				"total_count": len(sessions),
				"page":        page,
				"page_size":   pageSize,
			},
		})
	}
}

// getSessionInfo returns information about a specific session
func (api *SessionAPI) getSessionInfo(w http.ResponseWriter, r *http.Request, sessionID string) {
	session, err := api.sessionManager.GetSessionInfo(sessionID)
	if err != nil {
		if err == ErrSessionNotFound {
			api.writeError(w, http.StatusNotFound, "Session not found")
		} else {
			api.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get session info: %v", err))
		}
		return
	}
	
	api.writeJSON(w, http.StatusOK, session)
	
	// Log the access
	if api.auditLogger != nil {
		api.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypePermissionDenied, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			SessionID: sessionID,
			Success:   true,
			Message:   "Session info accessed",
			Details: map[string]interface{}{
				"action":     "get_session_info",
				"session_id": sessionID,
			},
		})
	}
}

// getUserSessions returns all sessions for a specific user
func (api *SessionAPI) getUserSessions(w http.ResponseWriter, r *http.Request, userID string) {
	sessions, err := api.sessionManager.GetActiveSessions(userID)
	if err != nil {
		api.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get user sessions: %v", err))
		return
	}
	
	response := &SessionListResponse{
		Sessions:    sessions,
		TotalCount:  len(sessions),
		CurrentPage: 1,
		PageSize:    len(sessions),
	}
	
	api.writeJSON(w, http.StatusOK, response)
	
	// Log the access
	if api.auditLogger != nil {
		api.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypePermissionDenied, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			UserID:    userID,
			Success:   true,
			Message:   fmt.Sprintf("User sessions accessed for %s", userID),
			Details: map[string]interface{}{
				"action":        "get_user_sessions",
				"user_id":       userID,
				"session_count": len(sessions),
			},
		})
	}
}

// terminateSession terminates a specific session
func (api *SessionAPI) terminateSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	err := api.sessionManager.TerminateSession(sessionID)
	if err != nil {
		if err == ErrSessionNotFound {
			api.writeError(w, http.StatusNotFound, "Session not found")
		} else {
			api.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to terminate session: %v", err))
		}
		return
	}
	
	response := &SessionActionResponse{
		Success:       true,
		Message:       "Session terminated successfully",
		AffectedCount: 1,
	}
	
	api.writeJSON(w, http.StatusOK, response)
	
	// Log the termination
	if api.auditLogger != nil {
		api.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionExpired,
			Severity:  SeverityMedium,
			Timestamp: time.Now(),
			SessionID: sessionID,
			Success:   true,
			Message:   "Session terminated via API",
			Details: map[string]interface{}{
				"action":     "terminate_session",
				"session_id": sessionID,
				"method":     "api",
			},
		})
	}
}

// terminateUserSessions terminates all sessions for a user
func (api *SessionAPI) terminateUserSessions(w http.ResponseWriter, r *http.Request, userID string) {
	// Get session count before termination
	sessions, err := api.sessionManager.GetActiveSessions(userID)
	if err != nil {
		api.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get user sessions: %v", err))
		return
	}
	
	sessionCount := len(sessions)
	
	err = api.sessionManager.TerminateAllUserSessions(userID)
	if err != nil {
		api.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to terminate user sessions: %v", err))
		return
	}
	
	response := &SessionActionResponse{
		Success:       true,
		Message:       fmt.Sprintf("Terminated %d sessions for user %s", sessionCount, userID),
		AffectedCount: sessionCount,
	}
	
	api.writeJSON(w, http.StatusOK, response)
	
	// Log the termination
	if api.auditLogger != nil {
		api.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionExpired,
			Severity:  SeverityHigh,
			Timestamp: time.Now(),
			UserID:    userID,
			Success:   true,
			Message:   fmt.Sprintf("All sessions terminated for user %s via API", userID),
			Details: map[string]interface{}{
				"action":         "terminate_user_sessions",
				"user_id":        userID,
				"session_count":  sessionCount,
				"method":         "api",
			},
		})
	}
}

// getSessionStats returns session statistics
func (api *SessionAPI) getSessionStats(w http.ResponseWriter, r *http.Request) {
	stats := api.sessionManager.GetSessionStats()
	
	response := &SessionStatsResponse{
		Stats:     stats,
		Timestamp: time.Now(),
	}
	
	api.writeJSON(w, http.StatusOK, response)
	
	// Log the access
	if api.auditLogger != nil {
		api.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypePermissionDenied, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			Success:   true,
			Message:   "Session statistics accessed",
			Details: map[string]interface{}{
				"action":          "get_session_stats",
				"active_sessions": stats.TotalActiveSessions,
			},
		})
	}
}

// performSessionActions performs bulk actions on sessions
func (api *SessionAPI) performSessionActions(w http.ResponseWriter, r *http.Request) {
	var request SessionActionRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	
	var affectedCount int
	var failedSessions []string
	var message string
	
	switch request.Action {
	case "terminate":
		affectedCount, failedSessions = api.bulkTerminateSessions(request.SessionIDs, request.UserID)
		message = fmt.Sprintf("Terminated %d sessions", affectedCount)
		
	case "refresh":
		affectedCount, failedSessions = api.bulkRefreshSessions(request.SessionIDs)
		message = fmt.Sprintf("Refreshed %d sessions", affectedCount)
		
	default:
		api.writeError(w, http.StatusBadRequest, fmt.Sprintf("Unknown action: %s", request.Action))
		return
	}
	
	response := &SessionActionResponse{
		Success:        len(failedSessions) == 0,
		Message:        message,
		AffectedCount:  affectedCount,
		FailedSessions: failedSessions,
	}
	
	api.writeJSON(w, http.StatusOK, response)
	
	// Log the bulk action
	if api.auditLogger != nil {
		api.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionExpired,
			Severity:  SeverityMedium,
			Timestamp: time.Now(),
			UserID:    request.UserID,
			Success:   len(failedSessions) == 0,
			Message:   fmt.Sprintf("Bulk session action: %s", request.Action),
			Details: map[string]interface{}{
				"action":          request.Action,
				"affected_count":  affectedCount,
				"failed_count":    len(failedSessions),
				"reason":          request.Reason,
				"method":          "api",
			},
		})
	}
}

// cleanupSessions performs manual session cleanup
func (api *SessionAPI) cleanupSessions(w http.ResponseWriter, r *http.Request) {
	err := api.sessionManager.CleanupExpiredSessions()
	if err != nil {
		api.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to cleanup sessions: %v", err))
		return
	}
	
	// Get updated stats to show cleanup results
	stats := api.sessionManager.GetSessionStats()
	
	response := &SessionActionResponse{
		Success: true,
		Message: "Session cleanup completed successfully",
	}
	
	api.writeJSON(w, http.StatusOK, response)
	
	// Log the cleanup
	if api.auditLogger != nil {
		api.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionExpired,
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			Success:   true,
			Message:   "Manual session cleanup performed",
			Details: map[string]interface{}{
				"action":           "manual_cleanup",
				"expired_sessions": stats.ExpiredSessions,
				"method":           "api",
			},
		})
	}
}

// Helper methods

// bulkTerminateSessions terminates multiple sessions
func (api *SessionAPI) bulkTerminateSessions(sessionIDs []string, userID string) (int, []string) {
	var affectedCount int
	var failedSessions []string
	
	if userID != "" {
		// Terminate all sessions for user
		err := api.sessionManager.TerminateAllUserSessions(userID)
		if err != nil {
			failedSessions = append(failedSessions, userID)
		} else {
			// Count sessions that were terminated
			sessions, _ := api.sessionManager.GetActiveSessions(userID)
			affectedCount = len(sessions)
		}
	} else {
		// Terminate specific sessions
		for _, sessionID := range sessionIDs {
			err := api.sessionManager.TerminateSession(sessionID)
			if err != nil {
				failedSessions = append(failedSessions, sessionID)
			} else {
				affectedCount++
			}
		}
	}
	
	return affectedCount, failedSessions
}

// bulkRefreshSessions refreshes multiple sessions
func (api *SessionAPI) bulkRefreshSessions(sessionIDs []string) (int, []string) {
	var affectedCount int
	var failedSessions []string
	
	for _, sessionID := range sessionIDs {
		err := api.sessionManager.RefreshSession(sessionID)
		if err != nil {
			failedSessions = append(failedSessions, sessionID)
		} else {
			affectedCount++
		}
	}
	
	return affectedCount, failedSessions
}

// parsePagination parses pagination parameters from request
func (api *SessionAPI) parsePagination(r *http.Request) (page, pageSize int) {
	page = 1
	pageSize = 50 // Default page size
	
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	
	if sizeStr := r.URL.Query().Get("page_size"); sizeStr != "" {
		if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 && s <= 1000 {
			pageSize = s
		}
	}
	
	return page, pageSize
}

// writeJSON writes a JSON response
func (api *SessionAPI) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response
func (api *SessionAPI) writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   message,
		"status":  http.StatusText(status),
		"code":    strconv.Itoa(status),
	})
}