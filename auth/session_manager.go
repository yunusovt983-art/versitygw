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
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionExpired     = errors.New("session expired")
	ErrInvalidSessionID   = errors.New("invalid session ID")
	ErrUserNotFound       = errors.New("user not found")
	ErrSessionLimitReached = errors.New("session limit reached for user")
)

// EnhancedSessionManager defines the interface for enhanced session management
type EnhancedSessionManager interface {
	// Core session operations
	CreateSession(userID string, metadata *SessionMetadata) (*UserSession, error)
	ValidateSession(sessionID string) (*UserSession, error)
	RefreshSession(sessionID string) error
	TerminateSession(sessionID string) error
	TerminateAllUserSessions(userID string) error
	
	// Session monitoring and control
	GetActiveSessions(userID string) ([]*UserSession, error)
	GetSessionInfo(sessionID string) (*UserSession, error)
	ListAllActiveSessions() ([]*UserSession, error)
	
	// Maintenance operations
	CleanupExpiredSessions() error
	GetSessionStats() *SessionStats
	
	// Legacy interface compatibility (implements existing SessionManager)
	InvalidateUserSessions(userID string) error
	RefreshUserPermissions(userID string) error
	GetActiveUserSessions(userID string) ([]string, error)
	NotifySessionUpdate(sessionID string, updateType string) error
	
	// Lifecycle
	Shutdown() error
}

// UserSession represents a user session with security metadata
type UserSession struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	LastUsed    time.Time              `json:"last_used"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	MFAVerified bool                   `json:"mfa_verified"`
	Provider    string                 `json:"provider,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	
	// Security tracking
	LoginAttempts    int       `json:"login_attempts"`
	SuspiciousFlags  []string  `json:"suspicious_flags,omitempty"`
	LastIPChange     time.Time `json:"last_ip_change,omitempty"`
	DeviceFingerprint string   `json:"device_fingerprint,omitempty"`
}

// SessionMetadata contains metadata for session creation
type SessionMetadata struct {
	IPAddress         string                 `json:"ip_address"`
	UserAgent         string                 `json:"user_agent"`
	MFAVerified       bool                   `json:"mfa_verified"`
	Provider          string                 `json:"provider,omitempty"`
	DeviceFingerprint string                 `json:"device_fingerprint,omitempty"`
	CustomData        map[string]interface{} `json:"custom_data,omitempty"`
}

// SessionStats provides statistics about session management
type SessionStats struct {
	TotalActiveSessions int                        `json:"total_active_sessions"`
	SessionsByUser      map[string]int             `json:"sessions_by_user"`
	SessionsByProvider  map[string]int             `json:"sessions_by_provider"`
	ExpiredSessions     int64                      `json:"expired_sessions"`
	CreatedSessions     int64                      `json:"created_sessions"`
	TerminatedSessions  int64                      `json:"terminated_sessions"`
	AverageSessionDuration time.Duration           `json:"average_session_duration"`
	LastCleanup         time.Time                  `json:"last_cleanup"`
}

// SessionConfig holds configuration for session management
type SessionConfig struct {
	// Session lifetime settings
	DefaultTTL          time.Duration `json:"default_ttl"`
	MaxTTL              time.Duration `json:"max_ttl"`
	InactivityTimeout   time.Duration `json:"inactivity_timeout"`
	
	// Security settings
	MaxSessionsPerUser  int           `json:"max_sessions_per_user"`
	RequireMFA          bool          `json:"require_mfa"`
	TrackDeviceFingerprint bool       `json:"track_device_fingerprint"`
	
	// Maintenance settings
	CleanupInterval     time.Duration `json:"cleanup_interval"`
	
	// Storage settings
	StorageType         string        `json:"storage_type"` // "memory", "redis", "database"
	StorageConfig       map[string]interface{} `json:"storage_config,omitempty"`
}

// DefaultSessionConfig returns a default session configuration
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		DefaultTTL:             24 * time.Hour,
		MaxTTL:                 7 * 24 * time.Hour,
		InactivityTimeout:      2 * time.Hour,
		MaxSessionsPerUser:     10,
		RequireMFA:             false,
		TrackDeviceFingerprint: true,
		CleanupInterval:        15 * time.Minute,
		StorageType:            "memory",
	}
}

// sessionManagerImpl implements the EnhancedSessionManager interface
type sessionManagerImpl struct {
	mu       sync.RWMutex
	config   *SessionConfig
	sessions map[string]*UserSession
	userSessions map[string][]string // userID -> []sessionID
	stats    *SessionStats
	
	// Background cleanup
	ctx    context.Context
	cancel context.CancelFunc
	
	// Security audit logger
	auditLogger SecurityAuditLogger
}

// NewSessionManager creates a new session manager instance
func NewSessionManager(config *SessionConfig, auditLogger SecurityAuditLogger) EnhancedSessionManager {
	if config == nil {
		config = DefaultSessionConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	sm := &sessionManagerImpl{
		config:       config,
		sessions:     make(map[string]*UserSession),
		userSessions: make(map[string][]string),
		stats: &SessionStats{
			SessionsByUser:     make(map[string]int),
			SessionsByProvider: make(map[string]int),
		},
		ctx:         ctx,
		cancel:      cancel,
		auditLogger: auditLogger,
	}
	
	// Start background cleanup
	if config.CleanupInterval > 0 {
		go sm.cleanupLoop()
	}
	
	return sm
}

// CreateSession creates a new session for a user
func (sm *sessionManagerImpl) CreateSession(userID string, metadata *SessionMetadata) (*UserSession, error) {
	if userID == "" {
		return nil, ErrUserNotFound
	}
	
	if metadata == nil {
		metadata = &SessionMetadata{}
	}
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	// Check session limit per user
	if sm.config.MaxSessionsPerUser > 0 {
		if userSessions, exists := sm.userSessions[userID]; exists {
			if len(userSessions) >= sm.config.MaxSessionsPerUser {
				// Remove oldest session
				sm.removeOldestUserSession(userID)
			}
		}
	}
	
	// Generate secure session ID
	sessionID, err := sm.generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}
	
	now := time.Now()
	session := &UserSession{
		ID:                sessionID,
		UserID:            userID,
		CreatedAt:         now,
		ExpiresAt:         now.Add(sm.config.DefaultTTL),
		LastUsed:          now,
		IPAddress:         metadata.IPAddress,
		UserAgent:         metadata.UserAgent,
		MFAVerified:       metadata.MFAVerified,
		Provider:          metadata.Provider,
		DeviceFingerprint: metadata.DeviceFingerprint,
		Metadata:          metadata.CustomData,
		LoginAttempts:     1,
	}
	
	// Store session
	sm.sessions[sessionID] = session
	
	// Update user sessions mapping
	if sm.userSessions[userID] == nil {
		sm.userSessions[userID] = make([]string, 0)
	}
	sm.userSessions[userID] = append(sm.userSessions[userID], sessionID)
	
	// Update statistics
	sm.stats.CreatedSessions++
	sm.stats.TotalActiveSessions = len(sm.sessions)
	sm.stats.SessionsByUser[userID]++
	if session.Provider != "" {
		sm.stats.SessionsByProvider[session.Provider]++
	}
	
	// Log session creation
	if sm.auditLogger != nil {
		sm.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionCreated,
			Severity:  SeverityLow,
			Timestamp: now,
			UserID:    userID,
			IPAddress: metadata.IPAddress,
			UserAgent: metadata.UserAgent,
			SessionID: sessionID,
			Success:   true,
			Message:   fmt.Sprintf("Session created for user %s", userID),
			Details: map[string]interface{}{
				"provider":     metadata.Provider,
				"mfa_verified": metadata.MFAVerified,
			},
		})
	}
	
	return session, nil
}

// ValidateSession validates a session and updates last used time
func (sm *sessionManagerImpl) ValidateSession(sessionID string) (*UserSession, error) {
	if sessionID == "" {
		return nil, ErrInvalidSessionID
	}
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}
	
	now := time.Now()
	
	// Check if session is expired
	if now.After(session.ExpiresAt) {
		// Remove expired session
		sm.removeSessionLocked(sessionID)
		return nil, ErrSessionExpired
	}
	
	// Check inactivity timeout
	if sm.config.InactivityTimeout > 0 {
		if now.Sub(session.LastUsed) > sm.config.InactivityTimeout {
			sm.removeSessionLocked(sessionID)
			return nil, ErrSessionExpired
		}
	}
	
	// Update last used time
	session.LastUsed = now
	
	return session, nil
}

// RefreshSession extends the session expiration time
func (sm *sessionManagerImpl) RefreshSession(sessionID string) error {
	if sessionID == "" {
		return ErrInvalidSessionID
	}
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	session, exists := sm.sessions[sessionID]
	if !exists {
		return ErrSessionNotFound
	}
	
	now := time.Now()
	
	// Check if session is expired
	if now.After(session.ExpiresAt) {
		sm.removeSessionLocked(sessionID)
		return ErrSessionExpired
	}
	
	// Extend expiration time
	newExpiry := now.Add(sm.config.DefaultTTL)
	if sm.config.MaxTTL > 0 {
		maxExpiry := session.CreatedAt.Add(sm.config.MaxTTL)
		if newExpiry.After(maxExpiry) {
			newExpiry = maxExpiry
		}
	}
	
	session.ExpiresAt = newExpiry
	session.LastUsed = now
	
	// Log session refresh
	if sm.auditLogger != nil {
		sm.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionCreated, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: now,
			UserID:    session.UserID,
			SessionID: sessionID,
			Success:   true,
			Message:   fmt.Sprintf("Session refreshed for user %s", session.UserID),
			Details: map[string]interface{}{
				"new_expiry": newExpiry,
				"action":     "refresh",
			},
		})
	}
	
	return nil
}

// TerminateSession terminates a specific session
func (sm *sessionManagerImpl) TerminateSession(sessionID string) error {
	if sessionID == "" {
		return ErrInvalidSessionID
	}
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	session, exists := sm.sessions[sessionID]
	if !exists {
		return ErrSessionNotFound
	}
	
	userID := session.UserID
	sm.removeSessionLocked(sessionID)
	
	// Log session termination
	if sm.auditLogger != nil {
		sm.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionExpired, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			UserID:    userID,
			SessionID: sessionID,
			Success:   true,
			Message:   fmt.Sprintf("Session terminated for user %s", userID),
			Details: map[string]interface{}{
				"reason": "manual_termination",
			},
		})
	}
	
	return nil
}

// TerminateAllUserSessions terminates all sessions for a user
func (sm *sessionManagerImpl) TerminateAllUserSessions(userID string) error {
	if userID == "" {
		return ErrUserNotFound
	}
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sessionIDs, exists := sm.userSessions[userID]
	if !exists {
		return nil // No sessions to terminate
	}
	
	// Make a copy of session IDs to avoid modifying slice while iterating
	sessionIDsCopy := make([]string, len(sessionIDs))
	copy(sessionIDsCopy, sessionIDs)
	
	// Remove all user sessions
	for _, sessionID := range sessionIDsCopy {
		sm.removeSessionLocked(sessionID)
	}
	
	// Log bulk session termination
	if sm.auditLogger != nil {
		sm.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionExpired,
			Severity:  SeverityMedium,
			Timestamp: time.Now(),
			UserID:    userID,
			Success:   true,
			Message:   fmt.Sprintf("All sessions terminated for user %s", userID),
			Details: map[string]interface{}{
				"terminated_count": len(sessionIDsCopy),
				"reason":          "user_sessions_terminated",
			},
		})
	}
	
	return nil
}

// GetActiveSessions returns all active sessions for a user
func (sm *sessionManagerImpl) GetActiveSessions(userID string) ([]*UserSession, error) {
	if userID == "" {
		return nil, ErrUserNotFound
	}
	
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	sessionIDs, exists := sm.userSessions[userID]
	if !exists {
		return []*UserSession{}, nil
	}
	
	var activeSessions []*UserSession
	now := time.Now()
	
	for _, sessionID := range sessionIDs {
		if session, exists := sm.sessions[sessionID]; exists {
			// Check if session is still valid
			if now.Before(session.ExpiresAt) {
				// Create a copy to avoid race conditions
				sessionCopy := *session
				activeSessions = append(activeSessions, &sessionCopy)
			}
		}
	}
	
	return activeSessions, nil
}

// GetSessionInfo returns information about a specific session
func (sm *sessionManagerImpl) GetSessionInfo(sessionID string) (*UserSession, error) {
	if sessionID == "" {
		return nil, ErrInvalidSessionID
	}
	
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}
	
	// Create a copy to avoid race conditions
	sessionCopy := *session
	return &sessionCopy, nil
}

// ListAllActiveSessions returns all active sessions (admin function)
func (sm *sessionManagerImpl) ListAllActiveSessions() ([]*UserSession, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	var activeSessions []*UserSession
	now := time.Now()
	
	for _, session := range sm.sessions {
		// Check if session is still valid
		if now.Before(session.ExpiresAt) {
			// Create a copy to avoid race conditions
			sessionCopy := *session
			activeSessions = append(activeSessions, &sessionCopy)
		}
	}
	
	return activeSessions, nil
}

// CleanupExpiredSessions removes expired sessions
func (sm *sessionManagerImpl) CleanupExpiredSessions() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	now := time.Now()
	var expiredSessions []string
	
	// Find expired sessions
	for sessionID, session := range sm.sessions {
		if now.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
		} else if sm.config.InactivityTimeout > 0 {
			// Check inactivity timeout
			if now.Sub(session.LastUsed) > sm.config.InactivityTimeout {
				expiredSessions = append(expiredSessions, sessionID)
			}
		}
	}
	
	// Remove expired sessions
	for _, sessionID := range expiredSessions {
		sm.removeSessionLocked(sessionID)
	}
	
	sm.stats.ExpiredSessions += int64(len(expiredSessions))
	sm.stats.LastCleanup = now
	
	// Log cleanup if sessions were removed
	if len(expiredSessions) > 0 && sm.auditLogger != nil {
		sm.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionExpired,
			Severity:  SeverityLow,
			Timestamp: now,
			Success:   true,
			Message:   fmt.Sprintf("Cleaned up %d expired sessions", len(expiredSessions)),
			Details: map[string]interface{}{
				"expired_count": len(expiredSessions),
				"action":        "cleanup",
			},
		})
	}
	
	return nil
}

// GetSessionStats returns current session statistics
func (sm *sessionManagerImpl) GetSessionStats() *SessionStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	// Create a copy of stats
	stats := &SessionStats{
		TotalActiveSessions:    len(sm.sessions),
		SessionsByUser:         make(map[string]int),
		SessionsByProvider:     make(map[string]int),
		ExpiredSessions:        sm.stats.ExpiredSessions,
		CreatedSessions:        sm.stats.CreatedSessions,
		TerminatedSessions:     sm.stats.TerminatedSessions,
		AverageSessionDuration: sm.calculateAverageSessionDuration(),
		LastCleanup:            sm.stats.LastCleanup,
	}
	
	// Copy maps to avoid race conditions
	for k, v := range sm.stats.SessionsByUser {
		stats.SessionsByUser[k] = v
	}
	for k, v := range sm.stats.SessionsByProvider {
		stats.SessionsByProvider[k] = v
	}
	
	return stats
}

// Legacy interface compatibility methods

// InvalidateUserSessions implements legacy interface
func (sm *sessionManagerImpl) InvalidateUserSessions(userID string) error {
	return sm.TerminateAllUserSessions(userID)
}

// RefreshUserPermissions implements legacy interface
func (sm *sessionManagerImpl) RefreshUserPermissions(userID string) error {
	// This could trigger permission refresh in sessions
	// For now, we'll just log the event
	if sm.auditLogger != nil {
		sm.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypePermissionDenied, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			UserID:    userID,
			Success:   true,
			Message:   fmt.Sprintf("User permissions refreshed for %s", userID),
			Details: map[string]interface{}{
				"action": "permission_refresh",
			},
		})
	}
	return nil
}

// GetActiveUserSessions implements legacy interface
func (sm *sessionManagerImpl) GetActiveUserSessions(userID string) ([]string, error) {
	sessions, err := sm.GetActiveSessions(userID)
	if err != nil {
		return nil, err
	}
	
	sessionIDs := make([]string, len(sessions))
	for i, session := range sessions {
		sessionIDs[i] = session.ID
	}
	
	return sessionIDs, nil
}

// NotifySessionUpdate implements legacy interface
func (sm *sessionManagerImpl) NotifySessionUpdate(sessionID string, updateType string) error {
	if sm.auditLogger != nil {
		sm.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionCreated, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			SessionID: sessionID,
			Success:   true,
			Message:   fmt.Sprintf("Session updated: %s", updateType),
			Details: map[string]interface{}{
				"update_type": updateType,
				"action":      "session_update",
			},
		})
	}
	return nil
}

// Shutdown gracefully shuts down the session manager
func (sm *sessionManagerImpl) Shutdown() error {
	if sm.cancel != nil {
		sm.cancel()
	}
	
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	// Clear all sessions
	sm.sessions = make(map[string]*UserSession)
	sm.userSessions = make(map[string][]string)
	
	return nil
}

// Helper methods

// generateSessionID generates a cryptographically secure session ID
func (sm *sessionManagerImpl) generateSessionID() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// removeSessionLocked removes a session (must be called with lock held)
func (sm *sessionManagerImpl) removeSessionLocked(sessionID string) {
	session, exists := sm.sessions[sessionID]
	if !exists {
		return
	}
	
	userID := session.UserID
	
	// Remove from sessions map
	delete(sm.sessions, sessionID)
	
	// Remove from user sessions mapping
	if userSessions, exists := sm.userSessions[userID]; exists {
		for i, id := range userSessions {
			if id == sessionID {
				sm.userSessions[userID] = append(userSessions[:i], userSessions[i+1:]...)
				break
			}
		}
		
		// Clean up empty user session list
		if len(sm.userSessions[userID]) == 0 {
			delete(sm.userSessions, userID)
		}
	}
	
	// Update statistics
	sm.stats.TerminatedSessions++
	sm.stats.TotalActiveSessions = len(sm.sessions)
	if sm.stats.SessionsByUser[userID] > 0 {
		sm.stats.SessionsByUser[userID]--
		if sm.stats.SessionsByUser[userID] == 0 {
			delete(sm.stats.SessionsByUser, userID)
		}
	}
	if session.Provider != "" && sm.stats.SessionsByProvider[session.Provider] > 0 {
		sm.stats.SessionsByProvider[session.Provider]--
		if sm.stats.SessionsByProvider[session.Provider] == 0 {
			delete(sm.stats.SessionsByProvider, session.Provider)
		}
	}
}

// removeOldestUserSession removes the oldest session for a user
func (sm *sessionManagerImpl) removeOldestUserSession(userID string) {
	userSessions, exists := sm.userSessions[userID]
	if !exists || len(userSessions) == 0 {
		return
	}
	
	var oldestSessionID string
	var oldestTime time.Time
	first := true
	
	for _, sessionID := range userSessions {
		if session, exists := sm.sessions[sessionID]; exists {
			if first || session.CreatedAt.Before(oldestTime) {
				oldestSessionID = sessionID
				oldestTime = session.CreatedAt
				first = false
			}
		}
	}
	
	if oldestSessionID != "" {
		sm.removeSessionLocked(oldestSessionID)
	}
}

// calculateAverageSessionDuration calculates the average session duration
func (sm *sessionManagerImpl) calculateAverageSessionDuration() time.Duration {
	if len(sm.sessions) == 0 {
		return 0
	}
	
	now := time.Now()
	var totalDuration time.Duration
	count := 0
	
	for _, session := range sm.sessions {
		duration := now.Sub(session.CreatedAt)
		totalDuration += duration
		count++
	}
	
	if count == 0 {
		return 0
	}
	
	return totalDuration / time.Duration(count)
}

// cleanupLoop runs periodic cleanup of expired sessions
func (sm *sessionManagerImpl) cleanupLoop() {
	ticker := time.NewTicker(sm.config.CleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			sm.CleanupExpiredSessions()
		}
	}
}