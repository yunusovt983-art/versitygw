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
	"log"
	"sync"
	"time"
)

// SecurityEventType represents the type of security event
type SecurityEventType string

const (
	EventTypeAuthAttempt     SecurityEventType = "auth_attempt"
	EventTypeAuthSuccess     SecurityEventType = "auth_success"
	EventTypeAuthFailure     SecurityEventType = "auth_failure"
	EventTypeMFAAttempt      SecurityEventType = "mfa_attempt"
	EventTypeMFASuccess      SecurityEventType = "mfa_success"
	EventTypeMFAFailure      SecurityEventType = "mfa_failure"
	EventTypeUserLocked      SecurityEventType = "user_locked"
	EventTypeUserUnlocked    SecurityEventType = "user_unlocked"
	EventTypeSuspiciousActivity SecurityEventType = "suspicious_activity"
	EventTypeSessionCreated  SecurityEventType = "session_created"
	EventTypeSessionExpired  SecurityEventType = "session_expired"
	EventTypeSessionSecurity SecurityEventType = "session_security"
	EventTypeSessionTerminated SecurityEventType = "session_terminated"
	EventTypePermissionDenied SecurityEventType = "permission_denied"
)

// SecuritySeverity represents the severity level of a security event
type SecuritySeverity string

const (
	SecuritySeverityLow      SecuritySeverity = "low"
	SecuritySeverityMedium   SecuritySeverity = "medium"
	SecuritySeverityHigh     SecuritySeverity = "high"
	SecuritySeverityCritical SecuritySeverity = "critical"
)

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID          string            `json:"id"`
	Type        SecurityEventType `json:"type"`
	Severity    SecuritySeverity  `json:"severity"`
	Timestamp   time.Time         `json:"timestamp"`
	UserID      string            `json:"user_id,omitempty"`
	IPAddress   string            `json:"ip_address,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Success     bool              `json:"success"`
	Message     string            `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	RequestID   string            `json:"request_id,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
	MFAUsed     bool              `json:"mfa_used,omitempty"`
	Provider    string            `json:"provider,omitempty"`
	Resource    string            `json:"resource,omitempty"`
	Action      string            `json:"action,omitempty"`
}

// AuthenticationDetails contains extended authentication information
type AuthenticationDetails struct {
	UserID           string            `json:"user_id"`
	Username         string            `json:"username,omitempty"`
	AuthMethod       string            `json:"auth_method"`
	MFAEnabled       bool              `json:"mfa_enabled"`
	MFAUsed          bool              `json:"mfa_used"`
	Provider         string            `json:"provider,omitempty"`
	FailedAttempts   int               `json:"failed_attempts,omitempty"`
	LastFailedAt     *time.Time        `json:"last_failed_at,omitempty"`
	AccountLocked    bool              `json:"account_locked"`
	LockedUntil      *time.Time        `json:"locked_until,omitempty"`
	SessionDuration  time.Duration     `json:"session_duration,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// SuspiciousPattern represents a detected suspicious activity pattern
type SuspiciousPattern struct {
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Severity    SecuritySeverity  `json:"severity"`
	UserID      string            `json:"user_id,omitempty"`
	IPAddress   string            `json:"ip_address,omitempty"`
	Count       int               `json:"count"`
	TimeWindow  time.Duration     `json:"time_window"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// SecurityAuditLogger interface for security event logging
type SecurityAuditLogger interface {
	LogSecurityEvent(event *SecurityEvent) error
	LogAuthenticationAttempt(userID, ipAddress, userAgent string, success bool, details *AuthenticationDetails) error
	LogMFAAttempt(userID, ipAddress string, success bool, details map[string]interface{}) error
	LogSuspiciousActivity(pattern *SuspiciousPattern) error
	LogUserLockout(userID, reason string, duration time.Duration) error
	LogPermissionDenied(userID, resource, action, reason string) error
	LogSessionSecurityEvent(sessionID, userID, eventType, description string, severity SecuritySeverity, details map[string]interface{}) error
	GetSecurityEvents(filter *SecurityEventFilter) ([]*SecurityEvent, error)
	Close() error
}

// SecurityEventFilter for querying security events
type SecurityEventFilter struct {
	UserID     string            `json:"user_id,omitempty"`
	IPAddress  string            `json:"ip_address,omitempty"`
	EventType  SecurityEventType `json:"event_type,omitempty"`
	Severity   SecuritySeverity  `json:"severity,omitempty"`
	StartTime  *time.Time        `json:"start_time,omitempty"`
	EndTime    *time.Time        `json:"end_time,omitempty"`
	Success    *bool             `json:"success,omitempty"`
	Limit      int               `json:"limit,omitempty"`
}

// SecurityAuditLoggerImpl implements SecurityAuditLogger
type SecurityAuditLoggerImpl struct {
	mu       sync.RWMutex
	events   []*SecurityEvent // In-memory storage for demo, should use persistent storage
	detector *SuspiciousActivityDetector
	config   *SecurityAuditConfig
}

// SecurityAuditConfig contains configuration for security audit logging
type SecurityAuditConfig struct {
	MaxEvents           int           `json:"max_events"`
	RetentionPeriod     time.Duration `json:"retention_period"`
	EnablePatternDetection bool       `json:"enable_pattern_detection"`
	LogLevel            string        `json:"log_level"`
	OutputFormat        string        `json:"output_format"`
}

// NewSecurityAuditLogger creates a new security audit logger
func NewSecurityAuditLogger(config *SecurityAuditConfig) *SecurityAuditLoggerImpl {
	if config == nil {
		config = &SecurityAuditConfig{
			MaxEvents:           10000,
			RetentionPeriod:     30 * 24 * time.Hour, // 30 days
			EnablePatternDetection: true,
			LogLevel:            "info",
			OutputFormat:        "json",
		}
	}

	logger := &SecurityAuditLoggerImpl{
		events:   make([]*SecurityEvent, 0),
		config:   config,
	}

	if config.EnablePatternDetection {
		logger.detector = NewSuspiciousActivityDetector(logger)
	}

	return logger
}

// LogSecurityEvent logs a security event
func (s *SecurityAuditLoggerImpl) LogSecurityEvent(event *SecurityEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Generate ID if not provided
	if event.ID == "" {
		event.ID = generateEventID()
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Add event to storage
	s.events = append(s.events, event)

	// Cleanup old events if needed
	s.cleanupOldEvents()

	// Log to standard logger
	s.logToStandardLogger(event)

	// Trigger pattern detection if enabled
	if s.detector != nil {
		go s.detector.AnalyzeEvent(event)
	}

	return nil
}

// LogAuthenticationAttempt logs an authentication attempt
func (s *SecurityAuditLoggerImpl) LogAuthenticationAttempt(userID, ipAddress, userAgent string, success bool, details *AuthenticationDetails) error {
	eventType := EventTypeAuthFailure
	severity := SeverityMedium
	message := fmt.Sprintf("Authentication failed for user %s", userID)

	if success {
		eventType = EventTypeAuthSuccess
		severity = SecuritySeverityLow
		message = fmt.Sprintf("Authentication successful for user %s", userID)
	}

	event := &SecurityEvent{
		Type:      eventType,
		Severity:  severity,
		UserID:    userID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   success,
		Message:   message,
		Details:   make(map[string]interface{}),
	}

	if details != nil {
		event.Details["auth_method"] = details.AuthMethod
		event.Details["mfa_enabled"] = details.MFAEnabled
		event.Details["mfa_used"] = details.MFAUsed
		event.Details["provider"] = details.Provider
		event.Details["failed_attempts"] = details.FailedAttempts
		event.Details["account_locked"] = details.AccountLocked
		if details.Metadata != nil {
			for k, v := range details.Metadata {
				event.Details[k] = v
			}
		}
	}

	return s.LogSecurityEvent(event)
}

// LogMFAAttempt logs an MFA attempt
func (s *SecurityAuditLoggerImpl) LogMFAAttempt(userID, ipAddress string, success bool, details map[string]interface{}) error {
	eventType := EventTypeMFAFailure
	severity := SeverityHigh
	message := fmt.Sprintf("MFA validation failed for user %s", userID)

	if success {
		eventType = EventTypeMFASuccess
		severity = SecuritySeverityLow
		message = fmt.Sprintf("MFA validation successful for user %s", userID)
	}

	event := &SecurityEvent{
		Type:      eventType,
		Severity:  severity,
		UserID:    userID,
		IPAddress: ipAddress,
		Success:   success,
		Message:   message,
		MFAUsed:   true,
		Details:   details,
	}

	return s.LogSecurityEvent(event)
}

// LogSuspiciousActivity logs suspicious activity
func (s *SecurityAuditLoggerImpl) LogSuspiciousActivity(pattern *SuspiciousPattern) error {
	event := &SecurityEvent{
		Type:      EventTypeSuspiciousActivity,
		Severity:  pattern.Severity,
		UserID:    pattern.UserID,
		IPAddress: pattern.IPAddress,
		Success:   false,
		Message:   fmt.Sprintf("Suspicious activity detected: %s", pattern.Description),
		Details: map[string]interface{}{
			"pattern_type":  pattern.Type,
			"count":         pattern.Count,
			"time_window":   pattern.TimeWindow.String(),
			"first_seen":    pattern.FirstSeen,
			"last_seen":     pattern.LastSeen,
			"pattern_details": pattern.Details,
		},
	}

	return s.LogSecurityEvent(event)
}

// LogUserLockout logs user lockout events
func (s *SecurityAuditLoggerImpl) LogUserLockout(userID, reason string, duration time.Duration) error {
	event := &SecurityEvent{
		Type:     EventTypeUserLocked,
		Severity: SeverityHigh,
		UserID:   userID,
		Success:  false,
		Message:  fmt.Sprintf("User %s locked: %s", userID, reason),
		Details: map[string]interface{}{
			"reason":   reason,
			"duration": duration.String(),
		},
	}

	return s.LogSecurityEvent(event)
}

// LogPermissionDenied logs permission denied events
func (s *SecurityAuditLoggerImpl) LogPermissionDenied(userID, resource, action, reason string) error {
	event := &SecurityEvent{
		Type:     EventTypePermissionDenied,
		Severity: SeverityMedium,
		UserID:   userID,
		Resource: resource,
		Action:   action,
		Success:  false,
		Message:  fmt.Sprintf("Permission denied for user %s on %s:%s - %s", userID, resource, action, reason),
		Details: map[string]interface{}{
			"reason": reason,
		},
	}

	return s.LogSecurityEvent(event)
}

// LogSessionSecurityEvent logs session security events
func (s *SecurityAuditLoggerImpl) LogSessionSecurityEvent(sessionID, userID, eventType, description string, severity SecuritySeverity, details map[string]interface{}) error {
	event := &SecurityEvent{
		Type:      EventTypeSessionSecurity,
		Severity:  severity,
		UserID:    userID,
		SessionID: sessionID,
		Success:   false, // Security events are typically concerns/failures
		Message:   fmt.Sprintf("Session security event: %s", description),
		Details:   details,
	}

	if event.Details == nil {
		event.Details = make(map[string]interface{})
	}
	event.Details["event_type"] = eventType

	return s.LogSecurityEvent(event)
}

// GetSecurityEvents retrieves security events based on filter
func (s *SecurityAuditLoggerImpl) GetSecurityEvents(filter *SecurityEventFilter) ([]*SecurityEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*SecurityEvent

	for _, event := range s.events {
		if s.matchesFilter(event, filter) {
			filtered = append(filtered, event)
		}
	}

	// Apply limit if specified
	if filter != nil && filter.Limit > 0 && len(filtered) > filter.Limit {
		filtered = filtered[:filter.Limit]
	}

	return filtered, nil
}

// Close closes the security audit logger
func (s *SecurityAuditLoggerImpl) Close() error {
	if s.detector != nil {
		s.detector.Stop()
	}
	return nil
}

// Helper methods

func (s *SecurityAuditLoggerImpl) cleanupOldEvents() {
	if len(s.events) <= s.config.MaxEvents {
		return
	}

	// Remove oldest events
	excess := len(s.events) - s.config.MaxEvents
	s.events = s.events[excess:]
}

func (s *SecurityAuditLoggerImpl) logToStandardLogger(event *SecurityEvent) {
	if s.config.OutputFormat == "json" {
		if jsonData, err := json.Marshal(event); err == nil {
			log.Printf("SECURITY_EVENT: %s", string(jsonData))
		}
	} else {
		log.Printf("SECURITY_EVENT: [%s] %s - %s (User: %s, IP: %s, Success: %t)",
			event.Severity, event.Type, event.Message, event.UserID, event.IPAddress, event.Success)
	}
}

func (s *SecurityAuditLoggerImpl) matchesFilter(event *SecurityEvent, filter *SecurityEventFilter) bool {
	if filter == nil {
		return true
	}

	if filter.UserID != "" && event.UserID != filter.UserID {
		return false
	}

	if filter.IPAddress != "" && event.IPAddress != filter.IPAddress {
		return false
	}

	if filter.EventType != "" && event.Type != filter.EventType {
		return false
	}

	if filter.Severity != "" && event.Severity != filter.Severity {
		return false
	}

	if filter.Success != nil && event.Success != *filter.Success {
		return false
	}

	if filter.StartTime != nil && event.Timestamp.Before(*filter.StartTime) {
		return false
	}

	if filter.EndTime != nil && event.Timestamp.After(*filter.EndTime) {
		return false
	}

	return true
}

func generateEventID() string {
	return fmt.Sprintf("evt_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%1000)
}