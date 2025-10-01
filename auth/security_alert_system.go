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
	"sync"
	"time"
)

// AlertSeverity represents the severity level of a security alert
type AlertSeverity string

const (
	AlertSeverityLow      AlertSeverity = "low"
	AlertSeverityMedium   AlertSeverity = "medium"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertType represents the type of security alert
type AlertType string

const (
	AlertTypeBruteForce        AlertType = "brute_force"
	AlertTypeDistributedAttack AlertType = "distributed_attack"
	AlertTypeAccountEnumeration AlertType = "account_enumeration"
	AlertTypeUserLocked        AlertType = "user_locked"
	AlertTypeHighRiskActivity  AlertType = "high_risk_activity"
	AlertTypeAnomalousAccess   AlertType = "anomalous_access"
	AlertTypeComplianceViolation AlertType = "compliance_violation"
)

// SecurityAlert represents a security alert
type SecurityAlert struct {
	ID          string                 `json:"id"`
	Type        AlertType              `json:"type"`
	Severity    AlertSeverity          `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	UserID      string                 `json:"user_id,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Actions     []string               `json:"actions,omitempty"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy  string                 `json:"resolved_by,omitempty"`
}

// AlertHandler defines the interface for handling security alerts
type AlertHandler interface {
	HandleAlert(alert *SecurityAlert) error
}

// EmailAlertHandler sends alerts via email
type EmailAlertHandler struct {
	SMTPServer   string
	SMTPPort     int
	Username     string
	Password     string
	Recipients   []string
	TemplateFile string
}

// WebhookAlertHandler sends alerts to a webhook endpoint
type WebhookAlertHandler struct {
	WebhookURL string
	Headers    map[string]string
	Timeout    time.Duration
}

// LogAlertHandler logs alerts to the standard logger
type LogAlertHandler struct {
	LogLevel string
}

// SecurityAlertSystem manages security alerts and notifications
type SecurityAlertSystem struct {
	mu                sync.RWMutex
	alerts            []*SecurityAlert
	handlers          []AlertHandler
	config            *AlertSystemConfig
	thresholds        *SecurityThresholds
	userLockManager   *UserLockManager
	auditLogger       SecurityAuditLogger
}

// AlertSystemConfig contains configuration for the alert system
type AlertSystemConfig struct {
	MaxAlerts           int           `json:"max_alerts"`
	RetentionPeriod     time.Duration `json:"retention_period"`
	EnableAutoResolve   bool          `json:"enable_auto_resolve"`
	AutoResolveTimeout  time.Duration `json:"auto_resolve_timeout"`
	AlertCooldownPeriod time.Duration `json:"alert_cooldown_period"`
}

// SecurityThresholds defines configurable thresholds for security events
type SecurityThresholds struct {
	// Authentication failure thresholds
	MaxFailedAttemptsPerUser   int           `json:"max_failed_attempts_per_user"`
	MaxFailedAttemptsPerIP     int           `json:"max_failed_attempts_per_ip"`
	FailureTimeWindow          time.Duration `json:"failure_time_window"`
	
	// User lockout settings
	UserLockoutDuration        time.Duration `json:"user_lockout_duration"`
	ProgressiveLockoutEnabled  bool          `json:"progressive_lockout_enabled"`
	MaxLockoutDuration         time.Duration `json:"max_lockout_duration"`
	
	// Brute force detection
	BruteForceThreshold        int           `json:"brute_force_threshold"`
	BruteForceTimeWindow       time.Duration `json:"brute_force_time_window"`
	
	// Distributed attack detection
	DistributedAttackThreshold int           `json:"distributed_attack_threshold"`
	DistributedAttackWindow    time.Duration `json:"distributed_attack_window"`
	
	// Risk scoring thresholds
	HighRiskScoreThreshold     int           `json:"high_risk_score_threshold"`
	CriticalRiskScoreThreshold int           `json:"critical_risk_score_threshold"`
	
	// Rate limiting
	MaxRequestsPerMinute       int           `json:"max_requests_per_minute"`
	MaxRequestsPerHour         int           `json:"max_requests_per_hour"`
}

// UserLockStatus represents the lock status of a user
type UserLockStatus struct {
	UserID         string        `json:"user_id"`
	Locked         bool          `json:"locked"`
	LockedAt       time.Time     `json:"locked_at"`
	LockedUntil    time.Time     `json:"locked_until"`
	LockReason     string        `json:"lock_reason"`
	FailedAttempts int           `json:"failed_attempts"`
	LockCount      int           `json:"lock_count"`
	LastAttemptAt  time.Time     `json:"last_attempt_at"`
}

// UserLockManager manages user account lockouts
type UserLockManager struct {
	mu          sync.RWMutex
	lockedUsers map[string]*UserLockStatus
	thresholds  *SecurityThresholds
	auditLogger SecurityAuditLogger
}

// DefaultSecurityThresholds returns default security thresholds
func DefaultSecurityThresholds() *SecurityThresholds {
	return &SecurityThresholds{
		MaxFailedAttemptsPerUser:   5,
		MaxFailedAttemptsPerIP:     20,
		FailureTimeWindow:          15 * time.Minute,
		UserLockoutDuration:        15 * time.Minute,
		ProgressiveLockoutEnabled:  true,
		MaxLockoutDuration:         24 * time.Hour,
		BruteForceThreshold:        10,
		BruteForceTimeWindow:       5 * time.Minute,
		DistributedAttackThreshold: 50,
		DistributedAttackWindow:    10 * time.Minute,
		HighRiskScoreThreshold:     70,
		CriticalRiskScoreThreshold: 90,
		MaxRequestsPerMinute:       60,
		MaxRequestsPerHour:         1000,
	}
}

// DefaultAlertSystemConfig returns default alert system configuration
func DefaultAlertSystemConfig() *AlertSystemConfig {
	return &AlertSystemConfig{
		MaxAlerts:           10000,
		RetentionPeriod:     30 * 24 * time.Hour, // 30 days
		EnableAutoResolve:   true,
		AutoResolveTimeout:  24 * time.Hour,
		AlertCooldownPeriod: 5 * time.Minute,
	}
}

// NewSecurityAlertSystem creates a new security alert system
func NewSecurityAlertSystem(auditLogger SecurityAuditLogger, config *AlertSystemConfig, thresholds *SecurityThresholds) *SecurityAlertSystem {
	if config == nil {
		config = DefaultAlertSystemConfig()
	}
	if thresholds == nil {
		thresholds = DefaultSecurityThresholds()
	}

	system := &SecurityAlertSystem{
		alerts:          make([]*SecurityAlert, 0),
		handlers:        make([]AlertHandler, 0),
		config:          config,
		thresholds:      thresholds,
		auditLogger:     auditLogger,
		userLockManager: NewUserLockManager(thresholds, auditLogger),
	}

	// Add default log handler
	system.AddHandler(&LogAlertHandler{LogLevel: "warn"})

	return system
}

// NewUserLockManager creates a new user lock manager
func NewUserLockManager(thresholds *SecurityThresholds, auditLogger SecurityAuditLogger) *UserLockManager {
	return &UserLockManager{
		lockedUsers: make(map[string]*UserLockStatus),
		thresholds:  thresholds,
		auditLogger: auditLogger,
	}
}

// AddHandler adds an alert handler to the system
func (s *SecurityAlertSystem) AddHandler(handler AlertHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers = append(s.handlers, handler)
}

// TriggerAlert creates and processes a security alert
func (s *SecurityAlertSystem) TriggerAlert(alertType AlertType, severity AlertSeverity, title, description string, details map[string]interface{}) error {
	alert := &SecurityAlert{
		ID:          generateAlertID(),
		Type:        alertType,
		Severity:    severity,
		Title:       title,
		Description: description,
		Timestamp:   time.Now(),
		Details:     details,
		Actions:     s.generateRecommendedActions(alertType, severity),
		Resolved:    false,
	}

	// Extract user ID and IP address from details if available
	if userID, ok := details["user_id"].(string); ok {
		alert.UserID = userID
	}
	if ipAddress, ok := details["ip_address"].(string); ok {
		alert.IPAddress = ipAddress
	}

	return s.processAlert(alert)
}

// processAlert processes and stores an alert
func (s *SecurityAlertSystem) processAlert(alert *SecurityAlert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for alert cooldown to prevent spam
	if s.isInCooldownPeriod(alert) {
		return nil // Skip duplicate alerts within cooldown period
	}

	// Store alert
	s.alerts = append(s.alerts, alert)
	s.cleanupOldAlerts()

	// Log to audit logger
	if s.auditLogger != nil {
		s.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSuspiciousActivity,
			Severity:  SecuritySeverity(alert.Severity),
			UserID:    alert.UserID,
			IPAddress: alert.IPAddress,
			Success:   false,
			Message:   fmt.Sprintf("Security alert triggered: %s", alert.Title),
			Details: map[string]interface{}{
				"alert_id":    alert.ID,
				"alert_type":  alert.Type,
				"description": alert.Description,
				"actions":     alert.Actions,
			},
		})
	}

	// Process handlers
	for _, handler := range s.handlers {
		go func(h AlertHandler) {
			if err := h.HandleAlert(alert); err != nil {
				log.Printf("Alert handler error: %v", err)
			}
		}(handler)
	}

	return nil
}

// RecordFailedAuthentication records a failed authentication attempt and checks for lockout
func (s *SecurityAlertSystem) RecordFailedAuthentication(userID, ipAddress, reason string) error {
	// Check if user should be locked
	shouldLock, lockDuration := s.userLockManager.RecordFailedAttempt(userID, ipAddress, reason)
	
	if shouldLock {
		// Trigger user lockout alert
		details := map[string]interface{}{
			"user_id":       userID,
			"ip_address":    ipAddress,
			"reason":        reason,
			"lock_duration": lockDuration.String(),
		}
		
		return s.TriggerAlert(
			AlertTypeUserLocked,
			AlertSeverityHigh,
			fmt.Sprintf("User %s locked due to failed authentication attempts", userID),
			fmt.Sprintf("User account locked for %s due to: %s", lockDuration, reason),
			details,
		)
	}

	return nil
}

// IsUserLocked checks if a user is currently locked
func (s *SecurityAlertSystem) IsUserLocked(userID string) bool {
	return s.userLockManager.IsUserLocked(userID)
}

// GetUserLockStatus returns the lock status for a user
func (s *SecurityAlertSystem) GetUserLockStatus(userID string) *UserLockStatus {
	return s.userLockManager.GetUserLockStatus(userID)
}

// UnlockUser manually unlocks a user account
func (s *SecurityAlertSystem) UnlockUser(userID, unlockedBy string) error {
	if s.userLockManager.UnlockUser(userID) {
		// Log unlock event
		if s.auditLogger != nil {
			s.auditLogger.LogSecurityEvent(&SecurityEvent{
				Type:     EventTypeUserUnlocked,
				Severity: SeverityMedium,
				UserID:   userID,
				Success:  true,
				Message:  fmt.Sprintf("User %s manually unlocked by %s", userID, unlockedBy),
				Details: map[string]interface{}{
					"unlocked_by": unlockedBy,
					"unlock_time": time.Now(),
				},
			})
		}
		return nil
	}
	return fmt.Errorf("user %s was not locked", userID)
}

// GetAlerts returns alerts based on filter criteria
func (s *SecurityAlertSystem) GetAlerts(filter *AlertFilter) []*SecurityAlert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*SecurityAlert
	for _, alert := range s.alerts {
		if s.matchesAlertFilter(alert, filter) {
			filtered = append(filtered, alert)
		}
	}

	return filtered
}

// AlertFilter defines criteria for filtering alerts
type AlertFilter struct {
	Type      AlertType     `json:"type,omitempty"`
	Severity  AlertSeverity `json:"severity,omitempty"`
	UserID    string        `json:"user_id,omitempty"`
	IPAddress string        `json:"ip_address,omitempty"`
	Resolved  *bool         `json:"resolved,omitempty"`
	StartTime *time.Time    `json:"start_time,omitempty"`
	EndTime   *time.Time    `json:"end_time,omitempty"`
	Limit     int           `json:"limit,omitempty"`
}

// UpdateThresholds updates the security thresholds
func (s *SecurityAlertSystem) UpdateThresholds(thresholds *SecurityThresholds) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.thresholds = thresholds
	s.userLockManager.UpdateThresholds(thresholds)
}

// GetThresholds returns the current security thresholds
func (s *SecurityAlertSystem) GetThresholds() *SecurityThresholds {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a copy to prevent external modifications
	thresholdsCopy := *s.thresholds
	return &thresholdsCopy
}

// Helper methods for UserLockManager

// RecordFailedAttempt records a failed authentication attempt
func (u *UserLockManager) RecordFailedAttempt(userID, ipAddress, reason string) (bool, time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()

	now := time.Now()
	status, exists := u.lockedUsers[userID]
	
	if !exists {
		status = &UserLockStatus{
			UserID:         userID,
			Locked:         false,
			FailedAttempts: 0,
			LockCount:      0,
		}
		u.lockedUsers[userID] = status
	}

	// Check if user is currently locked
	if status.Locked && now.Before(status.LockedUntil) {
		return false, 0 // User is already locked
	}

	// If lock has expired, unlock the user
	if status.Locked && now.After(status.LockedUntil) {
		status.Locked = false
		status.FailedAttempts = 0
	}

	// Increment failed attempts
	status.FailedAttempts++
	status.LastAttemptAt = now

	// Check if user should be locked
	if status.FailedAttempts >= u.thresholds.MaxFailedAttemptsPerUser {
		lockDuration := u.calculateLockoutDuration(status.LockCount)
		status.Locked = true
		status.LockedAt = now
		status.LockedUntil = now.Add(lockDuration)
		status.LockReason = reason
		status.LockCount++
		status.FailedAttempts = 0 // Reset counter after lock

		// Log lockout event
		if u.auditLogger != nil {
			u.auditLogger.LogUserLockout(userID, reason, lockDuration)
		}

		return true, lockDuration
	}

	return false, 0
}

// IsUserLocked checks if a user is currently locked
func (u *UserLockManager) IsUserLocked(userID string) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	status, exists := u.lockedUsers[userID]
	if !exists {
		return false
	}

	// Check if lock has expired
	if status.Locked && time.Now().After(status.LockedUntil) {
		// Unlock expired lock
		go func() {
			u.mu.Lock()
			defer u.mu.Unlock()
			status.Locked = false
			status.FailedAttempts = 0
		}()
		return false
	}

	return status.Locked
}

// GetUserLockStatus returns the lock status for a user
func (u *UserLockManager) GetUserLockStatus(userID string) *UserLockStatus {
	u.mu.RLock()
	defer u.mu.RUnlock()

	status, exists := u.lockedUsers[userID]
	if !exists {
		return nil
	}

	// Return a copy to prevent external modifications
	statusCopy := *status
	return &statusCopy
}

// UnlockUser manually unlocks a user
func (u *UserLockManager) UnlockUser(userID string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()

	status, exists := u.lockedUsers[userID]
	if !exists || !status.Locked {
		return false
	}

	status.Locked = false
	status.FailedAttempts = 0
	return true
}

// UpdateThresholds updates the security thresholds
func (u *UserLockManager) UpdateThresholds(thresholds *SecurityThresholds) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.thresholds = thresholds
}

// calculateLockoutDuration calculates the lockout duration based on previous lockouts
func (u *UserLockManager) calculateLockoutDuration(lockCount int) time.Duration {
	if !u.thresholds.ProgressiveLockoutEnabled {
		return u.thresholds.UserLockoutDuration
	}

	// Progressive lockout: double the duration for each subsequent lockout
	duration := u.thresholds.UserLockoutDuration
	for i := 0; i < lockCount && duration < u.thresholds.MaxLockoutDuration; i++ {
		duration *= 2
	}

	if duration > u.thresholds.MaxLockoutDuration {
		duration = u.thresholds.MaxLockoutDuration
	}

	return duration
}

// Helper methods for SecurityAlertSystem

func (s *SecurityAlertSystem) isInCooldownPeriod(alert *SecurityAlert) bool {
	cutoff := time.Now().Add(-s.config.AlertCooldownPeriod)
	
	for _, existingAlert := range s.alerts {
		if existingAlert.Type == alert.Type &&
			existingAlert.UserID == alert.UserID &&
			existingAlert.IPAddress == alert.IPAddress &&
			existingAlert.Timestamp.After(cutoff) {
			return true
		}
	}
	
	return false
}

func (s *SecurityAlertSystem) cleanupOldAlerts() {
	if len(s.alerts) <= s.config.MaxAlerts {
		return
	}

	// Remove oldest alerts
	excess := len(s.alerts) - s.config.MaxAlerts
	s.alerts = s.alerts[excess:]
}

func (s *SecurityAlertSystem) generateRecommendedActions(alertType AlertType, severity AlertSeverity) []string {
	actions := make([]string, 0)

	switch alertType {
	case AlertTypeBruteForce:
		actions = append(actions, "Block IP address", "Increase monitoring", "Review authentication logs")
	case AlertTypeDistributedAttack:
		actions = append(actions, "Enable rate limiting", "Contact security team", "Review firewall rules")
	case AlertTypeUserLocked:
		actions = append(actions, "Verify user identity", "Check for compromised credentials", "Consider password reset")
	case AlertTypeHighRiskActivity:
		actions = append(actions, "Investigate user activity", "Verify location", "Check device fingerprint")
	case AlertTypeAnomalousAccess:
		actions = append(actions, "Verify user identity", "Check access patterns", "Review permissions")
	}

	if severity == AlertSeverityCritical {
		actions = append(actions, "Escalate to security team", "Consider emergency response")
	}

	return actions
}

func (s *SecurityAlertSystem) matchesAlertFilter(alert *SecurityAlert, filter *AlertFilter) bool {
	if filter == nil {
		return true
	}

	if filter.Type != "" && alert.Type != filter.Type {
		return false
	}

	if filter.Severity != "" && alert.Severity != filter.Severity {
		return false
	}

	if filter.UserID != "" && alert.UserID != filter.UserID {
		return false
	}

	if filter.IPAddress != "" && alert.IPAddress != filter.IPAddress {
		return false
	}

	if filter.Resolved != nil && alert.Resolved != *filter.Resolved {
		return false
	}

	if filter.StartTime != nil && alert.Timestamp.Before(*filter.StartTime) {
		return false
	}

	if filter.EndTime != nil && alert.Timestamp.After(*filter.EndTime) {
		return false
	}

	return true
}

// Alert handler implementations

// HandleAlert implements AlertHandler for LogAlertHandler
func (h *LogAlertHandler) HandleAlert(alert *SecurityAlert) error {
	logMessage := fmt.Sprintf("SECURITY_ALERT [%s] %s: %s (User: %s, IP: %s)",
		alert.Severity, alert.Type, alert.Title, alert.UserID, alert.IPAddress)
	
	switch h.LogLevel {
	case "error":
		log.Printf("ERROR: %s", logMessage)
	case "warn":
		log.Printf("WARN: %s", logMessage)
	default:
		log.Printf("INFO: %s", logMessage)
	}
	
	return nil
}

// HandleAlert implements AlertHandler for WebhookAlertHandler
func (h *WebhookAlertHandler) HandleAlert(alert *SecurityAlert) error {
	// This would implement HTTP webhook posting
	// For now, just log that webhook would be called
	log.Printf("WEBHOOK_ALERT: Would send alert %s to %s", alert.ID, h.WebhookURL)
	return nil
}

// HandleAlert implements AlertHandler for EmailAlertHandler
func (h *EmailAlertHandler) HandleAlert(alert *SecurityAlert) error {
	// This would implement email sending
	// For now, just log that email would be sent
	log.Printf("EMAIL_ALERT: Would send alert %s to %v", alert.ID, h.Recipients)
	return nil
}

// Utility functions

func generateAlertID() string {
	return fmt.Sprintf("alert_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%1000)
}