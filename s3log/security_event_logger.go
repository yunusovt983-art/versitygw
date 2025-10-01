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

package s3log

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// SecurityEventLogger implements structured security event logging
type SecurityEventLogger struct {
	mu                sync.RWMutex
	file              *os.File
	config            *SecurityEventConfig
	authEvents        []*AuthenticationEvent
	authzEvents       []*AuthorizationEvent
	metrics           *SecurityMetrics
	metricsUpdateTime time.Time
}

// SecurityEventConfig contains configuration for security event logging
type SecurityEventConfig struct {
	LogFile           string        `json:"log_file"`
	MaxEvents         int           `json:"max_events"`
	RetentionPeriod   time.Duration `json:"retention_period"`
	EnableMetrics     bool          `json:"enable_metrics"`
	MetricsInterval   time.Duration `json:"metrics_interval"`
	AlertThresholds   *AlertThresholds `json:"alert_thresholds"`
}

// AlertThresholds defines thresholds for triggering security alerts
type AlertThresholds struct {
	FailedAuthPerMinute    int     `json:"failed_auth_per_minute"`
	HighRiskScoreThreshold int     `json:"high_risk_score_threshold"`
	SuspiciousIPThreshold  int     `json:"suspicious_ip_threshold"`
	ComplianceViolationMax int     `json:"compliance_violation_max"`
	AverageRiskScoreMax    float64 `json:"average_risk_score_max"`
}

// DefaultSecurityEventConfig returns default configuration
func DefaultSecurityEventConfig() *SecurityEventConfig {
	return &SecurityEventConfig{
		LogFile:         "/var/log/versitygw/security_events.log",
		MaxEvents:       50000,
		RetentionPeriod: 90 * 24 * time.Hour, // 90 days
		EnableMetrics:   true,
		MetricsInterval: 5 * time.Minute,
		AlertThresholds: &AlertThresholds{
			FailedAuthPerMinute:    10,
			HighRiskScoreThreshold: 80,
			SuspiciousIPThreshold:  20,
			ComplianceViolationMax: 5,
			AverageRiskScoreMax:    60.0,
		},
	}
}

// NewSecurityEventLogger creates a new security event logger
func NewSecurityEventLogger(config *SecurityEventConfig) (*SecurityEventLogger, error) {
	if config == nil {
		config = DefaultSecurityEventConfig()
	}

	var file *os.File
	var err error

	if config.LogFile != "" {
		file, err = os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open security log file: %w", err)
		}
	}

	logger := &SecurityEventLogger{
		file:              file,
		config:            config,
		authEvents:        make([]*AuthenticationEvent, 0),
		authzEvents:       make([]*AuthorizationEvent, 0),
		metrics:           &SecurityMetrics{
			TopFailureReasons:      make(map[string]int64),
			TopRiskFactors:         make(map[string]int64),
			GeographicDistribution: make(map[string]int64),
		},
		metricsUpdateTime: time.Now(),
	}

	// Start metrics collection if enabled
	if config.EnableMetrics {
		go logger.metricsCollectionRoutine()
	}

	return logger, nil
}

// LogEnhanced logs an enhanced audit event
func (s *SecurityEventLogger) LogEnhanced(ctx interface{}, err error, body []byte, meta *SecurityLogMeta) error {
	fiberCtx, ok := ctx.(*fiber.Ctx)
	if !ok {
		return fmt.Errorf("invalid context type")
	}

	// Create enhanced log fields
	enhanced := &EnhancedLogFields{
		Time:      time.Now(),
		RemoteIP:  fiberCtx.IP(),
		UserAgent: fiberCtx.Get("User-Agent"),
		RequestID: fiberCtx.Get("X-Request-ID"),
		Operation: fiberCtx.Method() + " " + fiberCtx.Path(),
		RequestURI: fiberCtx.OriginalURL(),
	}

	if meta != nil {
		enhanced.HttpStatus = meta.HttpStatus
		enhanced.ObjectSize = meta.ObjectSize
		enhanced.BucketOwner = meta.BucketOwner
		enhanced.AuthMethod = meta.AuthenticationResult
		enhanced.SecurityEventID = generateEventID()
		
		// Set security-specific fields
		if meta.ThreatLevel != "" {
			switch meta.ThreatLevel {
			case "low":
				enhanced.RiskScore = 25
			case "medium":
				enhanced.RiskScore = 50
			case "high":
				enhanced.RiskScore = 75
			case "critical":
				enhanced.RiskScore = 100
			}
		}
		
		enhanced.PermissionsUsed = meta.GrantedPermissions
		enhanced.ComplianceFlags = meta.PolicyViolations
	}

	if err != nil {
		enhanced.ErrorCode = "SecurityError"
		enhanced.AuthFailureReason = err.Error()
	}

	// Log to file if configured
	if s.file != nil {
		if jsonData, jsonErr := json.Marshal(enhanced); jsonErr == nil {
			s.file.WriteString(string(jsonData) + "\n")
			s.file.Sync()
		}
	}

	// Log to standard logger
	log.Printf("SECURITY_ENHANCED: %+v", enhanced)

	return nil
}

// LogAuthenticationEvent logs an authentication event
func (s *SecurityEventLogger) LogAuthenticationEvent(event *AuthenticationEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Generate ID if not provided
	if event.EventID == "" {
		event.EventID = generateEventID()
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Add to in-memory storage
	s.authEvents = append(s.authEvents, event)
	s.cleanupAuthEvents()

	// Update metrics
	s.updateAuthMetrics(event)

	// Log to file
	if s.file != nil {
		if jsonData, err := json.Marshal(event); err == nil {
			s.file.WriteString(fmt.Sprintf("AUTH_EVENT: %s\n", string(jsonData)))
			s.file.Sync()
		}
	}

	// Log to standard logger
	log.Printf("AUTH_EVENT: [%s] User: %s, IP: %s, Success: %t, Method: %s",
		event.EventID, event.UserID, event.IPAddress, event.Success, event.AuthMethod)

	// Check for alert conditions
	s.checkAuthAlerts(event)

	return nil
}

// LogAuthorizationEvent logs an authorization event
func (s *SecurityEventLogger) LogAuthorizationEvent(event *AuthorizationEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Generate ID if not provided
	if event.EventID == "" {
		event.EventID = generateEventID()
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Add to in-memory storage
	s.authzEvents = append(s.authzEvents, event)
	s.cleanupAuthzEvents()

	// Update metrics
	s.updateAuthzMetrics(event)

	// Log to file
	if s.file != nil {
		if jsonData, err := json.Marshal(event); err == nil {
			s.file.WriteString(fmt.Sprintf("AUTHZ_EVENT: %s\n", string(jsonData)))
			s.file.Sync()
		}
	}

	// Log to standard logger
	log.Printf("AUTHZ_EVENT: [%s] User: %s, Resource: %s, Action: %s, Decision: %s",
		event.EventID, event.UserID, event.Resource, event.Action, event.Decision)

	return nil
}

// LogSecurityMetrics logs security metrics
func (s *SecurityEventLogger) LogSecurityMetrics(metrics *SecurityMetrics) error {
	if metrics == nil {
		return fmt.Errorf("metrics cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Update stored metrics
	s.metrics = metrics
	s.metricsUpdateTime = time.Now()

	// Log to file
	if s.file != nil {
		if jsonData, err := json.Marshal(metrics); err == nil {
			s.file.WriteString(fmt.Sprintf("SECURITY_METRICS: %s\n", string(jsonData)))
			s.file.Sync()
		}
	}

	// Log summary to standard logger
	log.Printf("SECURITY_METRICS: Auth Success: %d, Auth Failures: %d, MFA Usage: %d, Risk Score: %.2f",
		metrics.AuthenticationSuccesses, metrics.AuthenticationFailures,
		metrics.MFAUsageCount, metrics.AverageRiskScore)

	return nil
}

// GetAuthenticationEvents retrieves authentication events based on filter
func (s *SecurityEventLogger) GetAuthenticationEvents(filter *AuthEventFilter) ([]*AuthenticationEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*AuthenticationEvent

	for _, event := range s.authEvents {
		if s.matchesAuthFilter(event, filter) {
			filtered = append(filtered, event)
		}
	}

	// Apply limit if specified
	if filter != nil && filter.Limit > 0 && len(filtered) > filter.Limit {
		filtered = filtered[:filter.Limit]
	}

	return filtered, nil
}

// GetAuthorizationEvents retrieves authorization events based on filter
func (s *SecurityEventLogger) GetAuthorizationEvents(filter *AuthzEventFilter) ([]*AuthorizationEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*AuthorizationEvent

	for _, event := range s.authzEvents {
		if s.matchesAuthzFilter(event, filter) {
			filtered = append(filtered, event)
		}
	}

	// Apply limit if specified
	if filter != nil && filter.Limit > 0 && len(filtered) > filter.Limit {
		filtered = filtered[:filter.Limit]
	}

	return filtered, nil
}

// GetSecurityMetrics returns current security metrics
func (s *SecurityEventLogger) GetSecurityMetrics(timeRange *TimeRange) (*SecurityMetrics, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// For now, return current metrics
	// In a full implementation, this would calculate metrics for the specified time range
	metricsCopy := *s.metrics
	return &metricsCopy, nil
}

// TriggerSecurityAlert triggers a security alert
func (s *SecurityEventLogger) TriggerSecurityAlert(alertType string, severity string, details map[string]interface{}) error {
	alert := map[string]interface{}{
		"alert_type": alertType,
		"severity":   severity,
		"timestamp":  time.Now(),
		"details":    details,
	}

	// Log alert to file
	if s.file != nil {
		if jsonData, err := json.Marshal(alert); err == nil {
			s.file.WriteString(fmt.Sprintf("SECURITY_ALERT: %s\n", string(jsonData)))
			s.file.Sync()
		}
	}

	// Log alert to standard logger
	log.Printf("SECURITY_ALERT: [%s] %s - %+v", severity, alertType, details)

	return nil
}

// Helper methods

func (s *SecurityEventLogger) cleanupAuthEvents() {
	if len(s.authEvents) <= s.config.MaxEvents {
		return
	}

	// Remove oldest events
	excess := len(s.authEvents) - s.config.MaxEvents
	s.authEvents = s.authEvents[excess:]
}

func (s *SecurityEventLogger) cleanupAuthzEvents() {
	if len(s.authzEvents) <= s.config.MaxEvents {
		return
	}

	// Remove oldest events
	excess := len(s.authzEvents) - s.config.MaxEvents
	s.authzEvents = s.authzEvents[excess:]
}

func (s *SecurityEventLogger) updateAuthMetrics(event *AuthenticationEvent) {
	s.metrics.AuthenticationAttempts++
	
	if event.Success {
		s.metrics.AuthenticationSuccesses++
	} else {
		s.metrics.AuthenticationFailures++
		
		// Update failure reasons
		if s.metrics.TopFailureReasons == nil {
			s.metrics.TopFailureReasons = make(map[string]int64)
		}
		s.metrics.TopFailureReasons[event.FailureReason]++
	}

	if event.MFAUsed {
		s.metrics.MFAUsageCount++
	}

	if s.config.AlertThresholds != nil && event.RiskScore >= s.config.AlertThresholds.HighRiskScoreThreshold {
		s.metrics.HighRiskRequests++
	}

	// Update geographic distribution
	if event.GeoLocation != "" {
		if s.metrics.GeographicDistribution == nil {
			s.metrics.GeographicDistribution = make(map[string]int64)
		}
		s.metrics.GeographicDistribution[event.GeoLocation]++
	}
}

func (s *SecurityEventLogger) updateAuthzMetrics(event *AuthorizationEvent) {
	if event.Decision == "deny" {
		s.metrics.PermissionDenials++
	}
}

func (s *SecurityEventLogger) checkAuthAlerts(event *AuthenticationEvent) {
	if s.config.AlertThresholds == nil {
		return
	}

	if !event.Success {
		// Check for high failure rate
		recentFailures := s.countRecentFailures(time.Minute)
		if recentFailures >= s.config.AlertThresholds.FailedAuthPerMinute {
			s.TriggerSecurityAlert("high_failure_rate", "high", map[string]interface{}{
				"failures_per_minute": recentFailures,
				"threshold":          s.config.AlertThresholds.FailedAuthPerMinute,
			})
		}
	}

	// Check for high risk score
	if event.RiskScore >= s.config.AlertThresholds.HighRiskScoreThreshold {
		s.TriggerSecurityAlert("high_risk_request", "medium", map[string]interface{}{
			"user_id":    event.UserID,
			"ip_address": event.IPAddress,
			"risk_score": event.RiskScore,
			"threshold":  s.config.AlertThresholds.HighRiskScoreThreshold,
		})
	}
}

func (s *SecurityEventLogger) countRecentFailures(duration time.Duration) int {
	cutoff := time.Now().Add(-duration)
	count := 0

	for _, event := range s.authEvents {
		if event.Timestamp.After(cutoff) && !event.Success {
			count++
		}
	}

	return count
}

func (s *SecurityEventLogger) matchesAuthFilter(event *AuthenticationEvent, filter *AuthEventFilter) bool {
	if filter == nil {
		return true
	}

	if filter.UserID != "" && event.UserID != filter.UserID {
		return false
	}

	if filter.IPAddress != "" && event.IPAddress != filter.IPAddress {
		return false
	}

	if filter.Success != nil && event.Success != *filter.Success {
		return false
	}

	if filter.AuthMethod != "" && event.AuthMethod != filter.AuthMethod {
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

func (s *SecurityEventLogger) matchesAuthzFilter(event *AuthorizationEvent, filter *AuthzEventFilter) bool {
	if filter == nil {
		return true
	}

	if filter.UserID != "" && event.UserID != filter.UserID {
		return false
	}

	if filter.Resource != "" && event.Resource != filter.Resource {
		return false
	}

	if filter.Action != "" && event.Action != filter.Action {
		return false
	}

	if filter.Decision != "" && event.Decision != filter.Decision {
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

func (s *SecurityEventLogger) metricsCollectionRoutine() {
	ticker := time.NewTicker(s.config.MetricsInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.collectMetrics()
	}
}

func (s *SecurityEventLogger) collectMetrics() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Calculate current metrics
	now := time.Now()
	s.metrics.Timestamp = now

	// Calculate average risk score
	if len(s.authEvents) > 0 {
		totalRisk := 0
		count := 0
		for _, event := range s.authEvents {
			if event.RiskScore > 0 {
				totalRisk += event.RiskScore
				count++
			}
		}
		if count > 0 {
			s.metrics.AverageRiskScore = float64(totalRisk) / float64(count)
		}
	}

	// Count unique users and IPs
	uniqueUsers := make(map[string]bool)
	uniqueIPs := make(map[string]bool)
	
	for _, event := range s.authEvents {
		uniqueUsers[event.UserID] = true
		uniqueIPs[event.IPAddress] = true
	}
	
	s.metrics.UniqueUsers = int64(len(uniqueUsers))
	s.metrics.UniqueIPs = int64(len(uniqueIPs))
}

// Close closes the security event logger
func (s *SecurityEventLogger) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// Implement the original AuditLogger interface methods
func (s *SecurityEventLogger) Log(ctx *fiber.Ctx, err error, body []byte, meta LogMeta) {
	// Convert to SecurityLogMeta and call LogEnhanced
	securityMeta := &SecurityLogMeta{
		BucketOwner: meta.BucketOwner,
		ObjectSize:  meta.ObjectSize,
		Action:      meta.Action,
		HttpStatus:  meta.HttpStatus,
	}
	
	s.LogEnhanced(ctx, err, body, securityMeta)
}

func (s *SecurityEventLogger) HangUp() error {
	return nil // No-op for this implementation
}

func (s *SecurityEventLogger) Shutdown() error {
	return s.Close()
}

func generateEventID() string {
	return fmt.Sprintf("evt_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%1000)
}