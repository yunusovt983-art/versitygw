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
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// SessionSecurityMonitor monitors sessions for suspicious activity
type SessionSecurityMonitor struct {
	sessionManager EnhancedSessionManager
	auditLogger    SecurityAuditLogger
	config         *SecurityMonitorConfig
	
	// Activity tracking
	mu              sync.RWMutex
	userActivity    map[string]*UserActivityTracker
	ipActivity      map[string]*IPActivityTracker
	sessionActivity map[string]*SessionActivityTracker
	
	// Background monitoring
	ctx    context.Context
	cancel context.CancelFunc
	
	// Statistics
	stats *SecurityMonitorStats
}

// SecurityMonitorConfig holds configuration for security monitoring
type SecurityMonitorConfig struct {
	// Enable monitoring
	Enabled bool `json:"enabled"`
	
	// IP change detection
	DetectIPChanges        bool          `json:"detect_ip_changes"`
	MaxIPChangesPerHour    int           `json:"max_ip_changes_per_hour"`
	IPChangeWindow         time.Duration `json:"ip_change_window"`
	
	// Geographic location detection
	DetectUnusualLocations bool `json:"detect_unusual_locations"`
	MaxDistanceKm          int  `json:"max_distance_km"`
	
	// Concurrent session detection
	DetectConcurrentSessions bool `json:"detect_concurrent_sessions"`
	MaxConcurrentSessions    int  `json:"max_concurrent_sessions"`
	
	// Activity pattern detection
	DetectRapidRequests    bool          `json:"detect_rapid_requests"`
	MaxRequestsPerMinute   int           `json:"max_requests_per_minute"`
	RequestWindow          time.Duration `json:"request_window"`
	
	// Time-based detection
	DetectOffHoursAccess bool `json:"detect_off_hours_access"`
	AllowedHoursStart    int  `json:"allowed_hours_start"` // 0-23
	AllowedHoursEnd      int  `json:"allowed_hours_end"`   // 0-23
	AllowedTimezone      string `json:"allowed_timezone"`
	
	// Session duration detection
	DetectLongSessions bool          `json:"detect_long_sessions"`
	MaxSessionDuration time.Duration `json:"max_session_duration"`
	
	// User agent detection
	DetectUserAgentChanges bool `json:"detect_user_agent_changes"`
	
	// Automatic actions
	AutoTerminateSuspicious bool `json:"auto_terminate_suspicious"`
	AutoLockUser            bool `json:"auto_lock_user"`
	SuspiciousThreshold     int  `json:"suspicious_threshold"` // Number of suspicious events before action
	
	// Monitoring interval
	MonitoringInterval time.Duration `json:"monitoring_interval"`
}

// UserActivityTracker tracks activity for a specific user
type UserActivityTracker struct {
	UserID           string                    `json:"user_id"`
	IPChanges        []IPChangeEvent           `json:"ip_changes"`
	LocationChanges  []LocationChangeEvent     `json:"location_changes"`
	RequestCounts    map[string]int            `json:"request_counts"` // time window -> count
	SuspiciousEvents []SessionSuspiciousEvent  `json:"suspicious_events"`
	LastActivity     time.Time                 `json:"last_activity"`
	ActiveSessions   map[string]*UserSession   `json:"active_sessions"`
}

// IPActivityTracker tracks activity for a specific IP address
type IPActivityTracker struct {
	IPAddress        string                   `json:"ip_address"`
	Users            map[string]time.Time     `json:"users"` // userID -> last seen
	RequestCounts    map[string]int           `json:"request_counts"`
	SuspiciousEvents []SessionSuspiciousEvent `json:"suspicious_events"`
	FirstSeen        time.Time                `json:"first_seen"`
	LastSeen         time.Time                `json:"last_seen"`
	Location         *GeoLocation             `json:"location,omitempty"`
}

// SessionActivityTracker tracks activity for a specific session
type SessionActivityTracker struct {
	SessionID        string                   `json:"session_id"`
	UserID           string                   `json:"user_id"`
	RequestCount     int                      `json:"request_count"`
	IPChanges        []IPChangeEvent          `json:"ip_changes"`
	UserAgentChanges []UserAgentChangeEvent   `json:"user_agent_changes"`
	SuspiciousEvents []SessionSuspiciousEvent `json:"suspicious_events"`
	RiskScore        int                      `json:"risk_score"`
	LastActivity     time.Time                `json:"last_activity"`
}

// IPChangeEvent represents an IP address change
type IPChangeEvent struct {
	Timestamp   time.Time    `json:"timestamp"`
	OldIP       string       `json:"old_ip"`
	NewIP       string       `json:"new_ip"`
	OldLocation *GeoLocation `json:"old_location,omitempty"`
	NewLocation *GeoLocation `json:"new_location,omitempty"`
	Distance    float64      `json:"distance_km,omitempty"`
}

// LocationChangeEvent represents a geographic location change
type LocationChangeEvent struct {
	Timestamp   time.Time    `json:"timestamp"`
	OldLocation *GeoLocation `json:"old_location"`
	NewLocation *GeoLocation `json:"new_location"`
	Distance    float64      `json:"distance_km"`
}

// UserAgentChangeEvent represents a user agent change
type UserAgentChangeEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	OldUserAgent string    `json:"old_user_agent"`
	NewUserAgent string    `json:"new_user_agent"`
}

// SessionSuspiciousEvent represents a suspicious activity event
type SessionSuspiciousEvent struct {
	Type        SessionAnomalyType     `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details"`
	ActionTaken string                 `json:"action_taken,omitempty"`
}

// GeoLocation represents a geographic location
type GeoLocation struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// SessionRiskLevel represents the risk level of a session
type SessionRiskLevel int

const (
	RiskLevelLow SessionRiskLevel = iota
	RiskLevelMedium
	RiskLevelHigh
	RiskLevelCritical
)

// String returns the string representation of the risk level
func (r SessionRiskLevel) String() string {
	switch r {
	case RiskLevelLow:
		return "low"
	case RiskLevelMedium:
		return "medium"
	case RiskLevelHigh:
		return "high"
	case RiskLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// SecurityAction represents the type of security action to take
type SecurityAction string

const (
	SecurityActionLogOnly         SecurityAction = "log_only"
	SecurityActionRequireMFA      SecurityAction = "require_mfa"
	SecurityActionTerminateSession SecurityAction = "terminate_session"
	SecurityActionLockUser        SecurityAction = "lock_user"
)

// SessionSecurityReport provides a comprehensive security report for a session
type SessionSecurityReport struct {
	SessionID         string                    `json:"session_id"`
	UserID            string                    `json:"user_id"`
	RiskLevel         SessionRiskLevel          `json:"risk_level"`
	RiskScore         int                       `json:"risk_score"`
	SuspiciousEvents  []SessionSuspiciousEvent  `json:"suspicious_events"`
	IPChanges         []IPChangeEvent           `json:"ip_changes"`
	UserAgentChanges  []UserAgentChangeEvent    `json:"user_agent_changes"`
	RequestCount      int                       `json:"request_count"`
	LastActivity      time.Time                 `json:"last_activity"`
	GeneratedAt       time.Time                 `json:"generated_at"`
}

// UserSecurityReport provides a comprehensive security report for a user
type UserSecurityReport struct {
	UserID           string                    `json:"user_id"`
	RiskLevel        SessionRiskLevel          `json:"risk_level"`
	RiskScore        int                       `json:"risk_score"`
	ActiveSessions   int                       `json:"active_sessions"`
	SuspiciousEvents []SessionSuspiciousEvent  `json:"suspicious_events"`
	IPChanges        []IPChangeEvent           `json:"ip_changes"`
	LocationChanges  []LocationChangeEvent     `json:"location_changes"`
	LastActivity     time.Time                 `json:"last_activity"`
	GeneratedAt      time.Time                 `json:"generated_at"`
}

// SecurityMonitorStats provides statistics about security monitoring
type SecurityMonitorStats struct {
	TotalSessionsMonitored int64                            `json:"total_sessions_monitored"`
	SuspiciousEventsDetected int64                          `json:"suspicious_events_detected"`
	SessionsTerminated     int64                            `json:"sessions_terminated"`
	UsersLocked            int64                            `json:"users_locked"`
	EventsByType           map[SessionAnomalyType]int64     `json:"events_by_type"`
	LastMonitoringRun      time.Time                        `json:"last_monitoring_run"`
	MonitoringErrors       int64                            `json:"monitoring_errors"`
}

// DefaultSecurityMonitorConfig returns a default security monitoring configuration
func DefaultSecurityMonitorConfig() *SecurityMonitorConfig {
	return &SecurityMonitorConfig{
		Enabled:                    true,
		DetectIPChanges:            true,
		MaxIPChangesPerHour:        5,
		IPChangeWindow:             1 * time.Hour,
		DetectUnusualLocations:     true,
		MaxDistanceKm:              1000, // 1000km
		DetectConcurrentSessions:   true,
		MaxConcurrentSessions:      5,
		DetectRapidRequests:        true,
		MaxRequestsPerMinute:       100,
		RequestWindow:              1 * time.Minute,
		DetectOffHoursAccess:       false,
		AllowedHoursStart:          9,  // 9 AM
		AllowedHoursEnd:            17, // 5 PM
		AllowedTimezone:            "UTC",
		DetectLongSessions:         true,
		MaxSessionDuration:         8 * time.Hour,
		DetectUserAgentChanges:     true,
		AutoTerminateSuspicious:    false,
		AutoLockUser:               false,
		SuspiciousThreshold:        3,
		MonitoringInterval:         5 * time.Minute,
	}
}

// NewSessionSecurityMonitor creates a new session security monitor
func NewSessionSecurityMonitor(sessionManager EnhancedSessionManager, auditLogger SecurityAuditLogger, config *SecurityMonitorConfig) *SessionSecurityMonitor {
	if config == nil {
		config = DefaultSecurityMonitorConfig()
	}
	
	return &SessionSecurityMonitor{
		sessionManager:  sessionManager,
		auditLogger:     auditLogger,
		config:          config,
		userActivity:    make(map[string]*UserActivityTracker),
		ipActivity:      make(map[string]*IPActivityTracker),
		sessionActivity: make(map[string]*SessionActivityTracker),
		stats: &SecurityMonitorStats{
			EventsByType: make(map[SessionAnomalyType]int64),
		},
	}
}

// Start starts the security monitoring service
func (m *SessionSecurityMonitor) Start() error {
	if !m.config.Enabled {
		return nil
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.ctx, m.cancel = context.WithCancel(context.Background())
	
	// Start monitoring loop
	go m.monitoringLoop()
	
	// Log service start
	if m.auditLogger != nil {
		m.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionCreated, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			Success:   true,
			Message:   "Session security monitoring started",
			Details: map[string]interface{}{
				"monitoring_interval": m.config.MonitoringInterval.String(),
				"auto_terminate":      m.config.AutoTerminateSuspicious,
			},
		})
	}
	
	return nil
}

// Stop stops the security monitoring service
func (m *SessionSecurityMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.cancel != nil {
		m.cancel()
	}
	
	// Log service stop
	if m.auditLogger != nil {
		m.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionExpired,
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			Success:   true,
			Message:   "Session security monitoring stopped",
			Details: map[string]interface{}{
				"sessions_monitored": m.stats.TotalSessionsMonitored,
				"suspicious_events":  m.stats.SuspiciousEventsDetected,
			},
		})
	}
	
	return nil
}

// TrackSessionActivity tracks activity for a session
func (m *SessionSecurityMonitor) TrackSessionActivity(sessionID, userID, ipAddress, userAgent string) {
	if !m.config.Enabled {
		return
	}
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	now := time.Now()
	
	// Update session activity
	if tracker, exists := m.sessionActivity[sessionID]; exists {
		tracker.RequestCount++
		tracker.LastActivity = now
		
		// Check for IP changes
		if m.config.DetectIPChanges {
			m.checkIPChange(tracker, ipAddress)
		}
		
		// Check for user agent changes
		if m.config.DetectUserAgentChanges {
			m.checkUserAgentChange(tracker, userAgent)
		}
	} else {
		// Create new session tracker
		m.sessionActivity[sessionID] = &SessionActivityTracker{
			SessionID:    sessionID,
			UserID:       userID,
			RequestCount: 1,
			LastActivity: now,
		}
	}
	
	// Update user activity
	if _, exists := m.userActivity[userID]; !exists {
		m.userActivity[userID] = &UserActivityTracker{
			UserID:         userID,
			RequestCounts:  make(map[string]int),
			ActiveSessions: make(map[string]*UserSession),
			LastActivity:   now,
		}
	}
	m.userActivity[userID].LastActivity = now
	
	// Update IP activity
	if _, exists := m.ipActivity[ipAddress]; !exists {
		m.ipActivity[ipAddress] = &IPActivityTracker{
			IPAddress:     ipAddress,
			Users:         make(map[string]time.Time),
			RequestCounts: make(map[string]int),
			FirstSeen:     now,
		}
	}
	m.ipActivity[ipAddress].Users[userID] = now
	m.ipActivity[ipAddress].LastSeen = now
	
	// Check for rapid requests
	if m.config.DetectRapidRequests {
		m.checkRapidRequests(userID, sessionID)
	}
}

// monitoringLoop runs periodic security monitoring
func (m *SessionSecurityMonitor) monitoringLoop() {
	ticker := time.NewTicker(m.config.MonitoringInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.performSecurityCheck()
		}
	}
}

// performSecurityCheck performs a comprehensive security check
func (m *SessionSecurityMonitor) performSecurityCheck() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.stats.LastMonitoringRun = time.Now()
	
	// Get all active sessions
	sessions, err := m.sessionManager.ListAllActiveSessions()
	if err != nil {
		m.stats.MonitoringErrors++
		return
	}
	
	m.stats.TotalSessionsMonitored += int64(len(sessions))
	
	for _, session := range sessions {
		m.checkSessionSecurity(session)
	}
	
	// Clean up old activity data
	m.cleanupOldActivity()
}

// checkSessionSecurity performs security checks on a session
func (m *SessionSecurityMonitor) checkSessionSecurity(session *UserSession) {
	suspiciousEvents := []SessionSuspiciousEvent{}
	
	// Check session duration
	if m.config.DetectLongSessions {
		if time.Since(session.CreatedAt) > m.config.MaxSessionDuration {
			event := SessionSuspiciousEvent{
				Type:        AnomalyLongSession,
				Timestamp:   time.Now(),
				Severity:    "medium",
				Description: fmt.Sprintf("Session duration exceeds maximum allowed (%v)", m.config.MaxSessionDuration),
				Details: map[string]interface{}{
					"session_duration": time.Since(session.CreatedAt).String(),
					"max_duration":     m.config.MaxSessionDuration.String(),
				},
			}
			suspiciousEvents = append(suspiciousEvents, event)
		}
	}
	
	// Check off-hours access
	if m.config.DetectOffHoursAccess {
		if m.isOffHoursAccess(session.LastUsed) {
			event := SessionSuspiciousEvent{
				Type:        AnomalyOffHoursAccess,
				Timestamp:   time.Now(),
				Severity:    "medium",
				Description: "Session active during off-hours",
				Details: map[string]interface{}{
					"access_time":     session.LastUsed.Format(time.RFC3339),
					"allowed_hours":   fmt.Sprintf("%d:00-%d:00", m.config.AllowedHoursStart, m.config.AllowedHoursEnd),
					"timezone":        m.config.AllowedTimezone,
				},
			}
			suspiciousEvents = append(suspiciousEvents, event)
		}
	}
	
	// Check concurrent sessions
	if m.config.DetectConcurrentSessions {
		userSessions, err := m.sessionManager.GetActiveSessions(session.UserID)
		if err == nil && len(userSessions) > m.config.MaxConcurrentSessions {
			event := SessionSuspiciousEvent{
				Type:        AnomalyMultipleLocations,
				Timestamp:   time.Now(),
				Severity:    "high",
				Description: fmt.Sprintf("User has %d concurrent sessions (max: %d)", len(userSessions), m.config.MaxConcurrentSessions),
				Details: map[string]interface{}{
					"concurrent_sessions": len(userSessions),
					"max_allowed":         m.config.MaxConcurrentSessions,
				},
			}
			suspiciousEvents = append(suspiciousEvents, event)
		}
	}
	
	// Process suspicious events
	for _, event := range suspiciousEvents {
		m.handleSuspiciousEvent(session, event)
	}
}

// checkIPChange checks for suspicious IP address changes
func (m *SessionSecurityMonitor) checkIPChange(tracker *SessionActivityTracker, newIP string) {
	// Get current session info
	session, err := m.sessionManager.GetSessionInfo(tracker.SessionID)
	if err != nil {
		return
	}
	
	if session.IPAddress != newIP {
		// IP address changed
		event := IPChangeEvent{
			Timestamp: time.Now(),
			OldIP:     session.IPAddress,
			NewIP:     newIP,
		}
		
		tracker.IPChanges = append(tracker.IPChanges, event)
		
		// Check if this is suspicious
		recentChanges := 0
		cutoff := time.Now().Add(-m.config.IPChangeWindow)
		for _, change := range tracker.IPChanges {
			if change.Timestamp.After(cutoff) {
				recentChanges++
			}
		}
		
		if recentChanges > m.config.MaxIPChangesPerHour {
			suspiciousEvent := SessionSuspiciousEvent{
				Type:        AnomalyIPChange,
				Timestamp:   time.Now(),
				Severity:    "high",
				Description: fmt.Sprintf("Rapid IP changes detected (%d in %v)", recentChanges, m.config.IPChangeWindow),
				Details: map[string]interface{}{
					"old_ip":         session.IPAddress,
					"new_ip":         newIP,
					"recent_changes": recentChanges,
					"time_window":    m.config.IPChangeWindow.String(),
				},
			}
			
			m.handleSuspiciousEvent(session, suspiciousEvent)
		}
	}
}

// checkUserAgentChange checks for user agent changes
func (m *SessionSecurityMonitor) checkUserAgentChange(tracker *SessionActivityTracker, newUserAgent string) {
	// Get current session info
	session, err := m.sessionManager.GetSessionInfo(tracker.SessionID)
	if err != nil {
		return
	}
	
	if session.UserAgent != newUserAgent && session.UserAgent != "" {
		// User agent changed
		event := UserAgentChangeEvent{
			Timestamp:    time.Now(),
			OldUserAgent: session.UserAgent,
			NewUserAgent: newUserAgent,
		}
		
		tracker.UserAgentChanges = append(tracker.UserAgentChanges, event)
		
		suspiciousEvent := SessionSuspiciousEvent{
			Type:        AnomalyUserAgentChange,
			Timestamp:   time.Now(),
			Severity:    "medium",
			Description: "User agent changed during session",
			Details: map[string]interface{}{
				"old_user_agent": session.UserAgent,
				"new_user_agent": newUserAgent,
			},
		}
		
		m.handleSuspiciousEvent(session, suspiciousEvent)
	}
}

// checkRapidRequests checks for rapid request patterns
func (m *SessionSecurityMonitor) checkRapidRequests(userID, sessionID string) {
	userTracker := m.userActivity[userID]
	sessionTracker := m.sessionActivity[sessionID]
	
	// Count requests in the current window
	windowKey := time.Now().Truncate(m.config.RequestWindow).Format(time.RFC3339)
	userTracker.RequestCounts[windowKey]++
	
	if userTracker.RequestCounts[windowKey] > m.config.MaxRequestsPerMinute {
		session, err := m.sessionManager.GetSessionInfo(sessionID)
		if err != nil {
			return
		}
		
		suspiciousEvent := SessionSuspiciousEvent{
			Type:        AnomalyRapidRequests,
			Timestamp:   time.Now(),
			Severity:    "high",
			Description: fmt.Sprintf("Rapid requests detected (%d in %v)", userTracker.RequestCounts[windowKey], m.config.RequestWindow),
			Details: map[string]interface{}{
				"request_count": userTracker.RequestCounts[windowKey],
				"time_window":   m.config.RequestWindow.String(),
				"max_allowed":   m.config.MaxRequestsPerMinute,
			},
		}
		
		sessionTracker.SuspiciousEvents = append(sessionTracker.SuspiciousEvents, suspiciousEvent)
		m.handleSuspiciousEvent(session, suspiciousEvent)
	}
}

// isOffHoursAccess checks if the access time is during off-hours
func (m *SessionSecurityMonitor) isOffHoursAccess(accessTime time.Time) bool {
	// Load timezone
	loc, err := time.LoadLocation(m.config.AllowedTimezone)
	if err != nil {
		loc = time.UTC
	}
	
	// Convert to configured timezone
	localTime := accessTime.In(loc)
	hour := localTime.Hour()
	
	// Check if within allowed hours
	if m.config.AllowedHoursStart <= m.config.AllowedHoursEnd {
		// Normal case: 9-17
		return hour < m.config.AllowedHoursStart || hour >= m.config.AllowedHoursEnd
	} else {
		// Overnight case: 22-6
		return hour < m.config.AllowedHoursStart && hour >= m.config.AllowedHoursEnd
	}
}

// handleSuspiciousEvent handles a suspicious event
func (m *SessionSecurityMonitor) handleSuspiciousEvent(session *UserSession, event SessionSuspiciousEvent) {
	m.stats.SuspiciousEventsDetected++
	m.stats.EventsByType[event.Type]++
	
	// Add to session tracker
	if tracker, exists := m.sessionActivity[session.ID]; exists {
		tracker.SuspiciousEvents = append(tracker.SuspiciousEvents, event)
		tracker.RiskScore += m.getSeverityScore(event.Severity)
	}
	
	// Log session security event with enhanced details
	m.logSessionSecurityEvent(session, event)
	
	// Log the suspicious event to audit logger
	if m.auditLogger != nil {
		m.auditLogger.LogSuspiciousActivity(&SuspiciousPattern{
			Type:        string(event.Type),
			Description: event.Description,
			Severity:    SecuritySeverity(event.Severity),
			UserID:      session.UserID,
			IPAddress:   session.IPAddress,
			Count:       1,
			TimeWindow:  m.config.MonitoringInterval,
			FirstSeen:   event.Timestamp,
			LastSeen:    event.Timestamp,
			Details:     event.Details,
		})
	}
	
	// Evaluate risk and take automatic action if configured
	riskLevel := m.evaluateSessionRisk(session.ID)
	if m.shouldTakeAutomaticAction(riskLevel, event) {
		m.takeSecurityAction(session, event, riskLevel)
	}
}

// terminateSuspiciousSession terminates a session due to suspicious activity
func (m *SessionSecurityMonitor) terminateSuspiciousSession(session *UserSession, reason string) {
	err := m.sessionManager.TerminateSession(session.ID)
	if err == nil {
		m.stats.SessionsTerminated++
		
		// Log termination
		if m.auditLogger != nil {
			m.auditLogger.LogSecurityEvent(&SecurityEvent{
				Type:      EventTypeSessionExpired,
				Severity:  SeverityHigh,
				Timestamp: time.Now(),
				UserID:    session.UserID,
				SessionID: session.ID,
				IPAddress: session.IPAddress,
				Success:   true,
				Message:   "Session terminated due to suspicious activity",
				Details: map[string]interface{}{
					"reason":           reason,
					"termination_type": "automatic",
				},
			})
		}
		
		// Update session tracker
		if tracker, exists := m.sessionActivity[session.ID]; exists {
			for i := range tracker.SuspiciousEvents {
				tracker.SuspiciousEvents[i].ActionTaken = "session_terminated"
			}
		}
	}
}

// lockSuspiciousUser locks a user due to suspicious activity
func (m *SessionSecurityMonitor) lockSuspiciousUser(userID, reason string) {
	// Terminate all user sessions
	err := m.sessionManager.TerminateAllUserSessions(userID)
	if err == nil {
		m.stats.UsersLocked++
		
		// Log user lock
		if m.auditLogger != nil {
			m.auditLogger.LogUserLockout(userID, reason, 24*time.Hour) // Default 24 hour lock
		}
	}
}

// getSeverityScore returns a numeric score for severity levels
func (m *SessionSecurityMonitor) getSeverityScore(severity string) int {
	switch strings.ToLower(severity) {
	case "low":
		return 1
	case "medium":
		return 3
	case "high":
		return 5
	case "critical":
		return 10
	default:
		return 1
	}
}

// cleanupOldActivity removes old activity data to prevent memory leaks
func (m *SessionSecurityMonitor) cleanupOldActivity() {
	cutoff := time.Now().Add(-24 * time.Hour) // Keep 24 hours of data
	
	// Clean up session activity for terminated sessions
	for sessionID, tracker := range m.sessionActivity {
		if tracker.LastActivity.Before(cutoff) {
			// Check if session still exists
			_, err := m.sessionManager.GetSessionInfo(sessionID)
			if err == ErrSessionNotFound {
				delete(m.sessionActivity, sessionID)
			}
		}
	}
	
	// Clean up old request counts
	for _, userTracker := range m.userActivity {
		for windowKey := range userTracker.RequestCounts {
			if windowTime, err := time.Parse(time.RFC3339, windowKey); err == nil {
				if windowTime.Before(cutoff) {
					delete(userTracker.RequestCounts, windowKey)
				}
			}
		}
	}
	
	for _, ipTracker := range m.ipActivity {
		for windowKey := range ipTracker.RequestCounts {
			if windowTime, err := time.Parse(time.RFC3339, windowKey); err == nil {
				if windowTime.Before(cutoff) {
					delete(ipTracker.RequestCounts, windowKey)
				}
			}
		}
	}
}

// GetStats returns security monitoring statistics
func (m *SessionSecurityMonitor) GetStats() *SecurityMonitorStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Return a copy to avoid race conditions
	statsCopy := *m.stats
	statsCopy.EventsByType = make(map[SessionAnomalyType]int64)
	for k, v := range m.stats.EventsByType {
		statsCopy.EventsByType[k] = v
	}
	
	return &statsCopy
}

// GetUserActivity returns activity information for a user
func (m *SessionSecurityMonitor) GetUserActivity(userID string) *UserActivityTracker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if tracker, exists := m.userActivity[userID]; exists {
		// Return a copy to avoid race conditions
		trackerCopy := *tracker
		return &trackerCopy
	}
	
	return nil
}

// GetSessionActivity returns activity information for a session
func (m *SessionSecurityMonitor) GetSessionActivity(sessionID string) *SessionActivityTracker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if tracker, exists := m.sessionActivity[sessionID]; exists {
		// Return a copy to avoid race conditions
		trackerCopy := *tracker
		return &trackerCopy
	}
	
	return nil
}

// UpdateConfig updates the security monitoring configuration
func (m *SessionSecurityMonitor) UpdateConfig(config *SecurityMonitorConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if config == nil {
		return ErrInvalidSessionID // Reusing existing error
	}
	
	m.config = config
	
	// Log config update
	if m.auditLogger != nil {
		m.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionCreated, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			Success:   true,
			Message:   "Security monitoring configuration updated",
			Details: map[string]interface{}{
				"enabled":           config.Enabled,
				"auto_terminate":    config.AutoTerminateSuspicious,
				"monitoring_interval": config.MonitoringInterval.String(),
			},
		})
	}
	
	return nil
}

// logSessionSecurityEvent logs a detailed session security event
func (m *SessionSecurityMonitor) logSessionSecurityEvent(session *UserSession, event SessionSuspiciousEvent) {
	if m.auditLogger == nil {
		return
	}
	
	// Create detailed session security event
	securityEvent := &SecurityEvent{
		Type:      EventTypeSessionSecurity,
		Severity:  SecuritySeverity(event.Severity),
		Timestamp: event.Timestamp,
		UserID:    session.UserID,
		SessionID: session.ID,
		IPAddress: session.IPAddress,
		UserAgent: session.UserAgent,
		Success:   false, // Security events are typically failures/concerns
		Message:   fmt.Sprintf("Session security event: %s", event.Description),
		Details: map[string]interface{}{
			"anomaly_type":        string(event.Type),
			"session_created_at":  session.CreatedAt,
			"session_last_used":   session.LastUsed,
			"session_duration":    time.Since(session.CreatedAt).String(),
			"mfa_verified":        session.MFAVerified,
			"provider":            session.Provider,
			"device_fingerprint":  session.DeviceFingerprint,
			"login_attempts":      session.LoginAttempts,
			"suspicious_flags":    session.SuspiciousFlags,
			"event_details":       event.Details,
		},
	}
	
	// Add session activity context if available
	if tracker, exists := m.sessionActivity[session.ID]; exists {
		securityEvent.Details["request_count"] = tracker.RequestCount
		securityEvent.Details["risk_score"] = tracker.RiskScore
		securityEvent.Details["ip_changes"] = len(tracker.IPChanges)
		securityEvent.Details["user_agent_changes"] = len(tracker.UserAgentChanges)
		securityEvent.Details["total_suspicious_events"] = len(tracker.SuspiciousEvents)
	}
	
	m.auditLogger.LogSecurityEvent(securityEvent)
}

// evaluateSessionRisk evaluates the overall risk level of a session
func (m *SessionSecurityMonitor) evaluateSessionRisk(sessionID string) SessionRiskLevel {
	tracker, exists := m.sessionActivity[sessionID]
	if !exists {
		return RiskLevelLow
	}
	
	// Calculate risk based on multiple factors
	riskScore := tracker.RiskScore
	
	// Additional risk factors
	if len(tracker.IPChanges) > 2 {
		riskScore += 2
	}
	if len(tracker.UserAgentChanges) > 1 {
		riskScore += 3
	}
	if len(tracker.SuspiciousEvents) > 3 {
		riskScore += 5
	}
	
	// Determine risk level
	if riskScore >= 15 {
		return RiskLevelCritical
	} else if riskScore >= 10 {
		return RiskLevelHigh
	} else if riskScore >= 5 {
		return RiskLevelMedium
	}
	
	return RiskLevelLow
}

// shouldTakeAutomaticAction determines if automatic action should be taken
func (m *SessionSecurityMonitor) shouldTakeAutomaticAction(riskLevel SessionRiskLevel, event SessionSuspiciousEvent) bool {
	// Critical events always trigger action if auto-termination is enabled
	if event.Severity == "critical" && m.config.AutoTerminateSuspicious {
		return true
	}
	
	// High risk sessions trigger action
	if riskLevel >= RiskLevelHigh && m.config.AutoTerminateSuspicious {
		return true
	}
	
	// Multiple high-severity events trigger action
	if event.Severity == "high" && m.config.AutoTerminateSuspicious {
		return true
	}
	
	return false
}

// takeSecurityAction takes appropriate security action based on risk level
func (m *SessionSecurityMonitor) takeSecurityAction(session *UserSession, event SessionSuspiciousEvent, riskLevel SessionRiskLevel) {
	action := m.determineSecurityAction(riskLevel, event)
	
	switch action {
	case SecurityActionTerminateSession:
		reason := fmt.Sprintf("Automatic termination due to %s (Risk: %s)", event.Description, riskLevel)
		m.terminateSuspiciousSession(session, reason)
		
	case SecurityActionLockUser:
		reason := fmt.Sprintf("Automatic lock due to %s (Risk: %s)", event.Description, riskLevel)
		m.lockSuspiciousUser(session.UserID, reason)
		
	case SecurityActionRequireMFA:
		m.requireMFAReauthentication(session, event)
		
	case SecurityActionLogOnly:
		// Already logged, no additional action needed
		
	default:
		// No action taken
	}
	
	// Update event with action taken
	if tracker, exists := m.sessionActivity[session.ID]; exists {
		for i := range tracker.SuspiciousEvents {
			if tracker.SuspiciousEvents[i].Timestamp.Equal(event.Timestamp) {
				tracker.SuspiciousEvents[i].ActionTaken = string(action)
				break
			}
		}
	}
}

// determineSecurityAction determines the appropriate security action
func (m *SessionSecurityMonitor) determineSecurityAction(riskLevel SessionRiskLevel, event SessionSuspiciousEvent) SecurityAction {
	// Critical risk always terminates session
	if riskLevel == RiskLevelCritical {
		return SecurityActionTerminateSession
	}
	
	// High risk events
	if riskLevel == RiskLevelHigh {
		switch event.Type {
		case AnomalyIPChange, AnomalyMultipleLocations:
			return SecurityActionRequireMFA
		case AnomalyRapidRequests, AnomalyPrivilegeEscalation:
			return SecurityActionTerminateSession
		default:
			return SecurityActionTerminateSession
		}
	}
	
	// Medium risk events
	if riskLevel == RiskLevelMedium {
		switch event.Type {
		case AnomalyUserAgentChange, AnomalyOffHoursAccess:
			return SecurityActionRequireMFA
		case AnomalyLongSession:
			return SecurityActionLogOnly
		default:
			return SecurityActionLogOnly
		}
	}
	
	// Low risk - just log
	return SecurityActionLogOnly
}

// requireMFAReauthentication requires MFA re-authentication for a session
func (m *SessionSecurityMonitor) requireMFAReauthentication(session *UserSession, event SessionSuspiciousEvent) {
	// Mark session as requiring MFA re-authentication
	session.MFAVerified = false
	session.SuspiciousFlags = append(session.SuspiciousFlags, fmt.Sprintf("mfa_required_%s", event.Type))
	
	// Log MFA requirement
	if m.auditLogger != nil {
		m.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeMFAAttempt,
			Severity:  SeverityMedium,
			Timestamp: time.Now(),
			UserID:    session.UserID,
			SessionID: session.ID,
			IPAddress: session.IPAddress,
			Success:   false,
			Message:   fmt.Sprintf("MFA re-authentication required due to %s", event.Description),
			Details: map[string]interface{}{
				"reason":       event.Description,
				"anomaly_type": string(event.Type),
				"action":       "mfa_required",
			},
		})
	}
}

// ForceTerminateSession forcefully terminates a session due to security concerns
func (m *SessionSecurityMonitor) ForceTerminateSession(sessionID, reason string) error {
	session, err := m.sessionManager.GetSessionInfo(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session info: %w", err)
	}
	
	// Terminate the session
	err = m.sessionManager.TerminateSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to terminate session: %w", err)
	}
	
	m.mu.Lock()
	m.stats.SessionsTerminated++
	m.mu.Unlock()
	
	// Log forced termination
	if m.auditLogger != nil {
		m.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionExpired,
			Severity:  SeverityHigh,
			Timestamp: time.Now(),
			UserID:    session.UserID,
			SessionID: sessionID,
			IPAddress: session.IPAddress,
			Success:   true,
			Message:   fmt.Sprintf("Session forcefully terminated: %s", reason),
			Details: map[string]interface{}{
				"reason":           reason,
				"termination_type": "forced",
				"action":           "force_terminate",
			},
		})
	}
	
	return nil
}

// ForceTerminateUserSessions forcefully terminates all sessions for a user
func (m *SessionSecurityMonitor) ForceTerminateUserSessions(userID, reason string) error {
	sessions, err := m.sessionManager.GetActiveSessions(userID)
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}
	
	terminatedCount := 0
	for _, session := range sessions {
		if err := m.ForceTerminateSession(session.ID, reason); err == nil {
			terminatedCount++
		}
	}
	
	// Log bulk termination
	if m.auditLogger != nil {
		m.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionExpired,
			Severity:  SeverityHigh,
			Timestamp: time.Now(),
			UserID:    userID,
			Success:   true,
			Message:   fmt.Sprintf("All user sessions forcefully terminated: %s", reason),
			Details: map[string]interface{}{
				"reason":             reason,
				"terminated_count":   terminatedCount,
				"termination_type":   "forced_bulk",
				"action":             "force_terminate_user",
			},
		})
	}
	
	return nil
}

// GetSessionSecurityReport generates a security report for a session
func (m *SessionSecurityMonitor) GetSessionSecurityReport(sessionID string) (*SessionSecurityReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	session, err := m.sessionManager.GetSessionInfo(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session info: %w", err)
	}
	
	tracker, exists := m.sessionActivity[sessionID]
	if !exists {
		return &SessionSecurityReport{
			SessionID: sessionID,
			UserID:    session.UserID,
			RiskLevel: RiskLevelLow,
			GeneratedAt: time.Now(),
		}, nil
	}
	
	report := &SessionSecurityReport{
		SessionID:         sessionID,
		UserID:            session.UserID,
		RiskLevel:         m.evaluateSessionRisk(sessionID),
		RiskScore:         tracker.RiskScore,
		SuspiciousEvents:  make([]SessionSuspiciousEvent, len(tracker.SuspiciousEvents)),
		IPChanges:         make([]IPChangeEvent, len(tracker.IPChanges)),
		UserAgentChanges:  make([]UserAgentChangeEvent, len(tracker.UserAgentChanges)),
		RequestCount:      tracker.RequestCount,
		LastActivity:      tracker.LastActivity,
		GeneratedAt:       time.Now(),
	}
	
	// Copy events to avoid race conditions
	copy(report.SuspiciousEvents, tracker.SuspiciousEvents)
	copy(report.IPChanges, tracker.IPChanges)
	copy(report.UserAgentChanges, tracker.UserAgentChanges)
	
	return report, nil
}

// GetUserSecurityReport generates a security report for all user sessions
func (m *SessionSecurityMonitor) GetUserSecurityReport(userID string) (*UserSecurityReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	userTracker, exists := m.userActivity[userID]
	if !exists {
		return &UserSecurityReport{
			UserID:      userID,
			RiskLevel:   RiskLevelLow,
			GeneratedAt: time.Now(),
		}, nil
	}
	
	// Get all user sessions
	sessions, err := m.sessionManager.GetActiveSessions(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}
	
	report := &UserSecurityReport{
		UserID:           userID,
		ActiveSessions:   len(sessions),
		SuspiciousEvents: make([]SessionSuspiciousEvent, len(userTracker.SuspiciousEvents)),
		IPChanges:        make([]IPChangeEvent, len(userTracker.IPChanges)),
		LocationChanges:  make([]LocationChangeEvent, len(userTracker.LocationChanges)),
		LastActivity:     userTracker.LastActivity,
		GeneratedAt:      time.Now(),
	}
	
	// Calculate overall risk level
	totalRiskScore := 0
	for _, session := range sessions {
		if tracker, exists := m.sessionActivity[session.ID]; exists {
			totalRiskScore += tracker.RiskScore
		}
	}
	
	if totalRiskScore >= 20 {
		report.RiskLevel = RiskLevelCritical
	} else if totalRiskScore >= 15 {
		report.RiskLevel = RiskLevelHigh
	} else if totalRiskScore >= 8 {
		report.RiskLevel = RiskLevelMedium
	} else {
		report.RiskLevel = RiskLevelLow
	}
	
	report.RiskScore = totalRiskScore
	
	// Copy events to avoid race conditions
	copy(report.SuspiciousEvents, userTracker.SuspiciousEvents)
	copy(report.IPChanges, userTracker.IPChanges)
	copy(report.LocationChanges, userTracker.LocationChanges)
	
	return report, nil
}

// IsIPPrivate checks if an IP address is private
func IsIPPrivate(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	// Check for private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	
	for _, rangeStr := range privateRanges {
		_, network, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	
	return false
}