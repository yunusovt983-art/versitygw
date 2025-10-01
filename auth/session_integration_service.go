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
	"net/http"
	"sync"
	"time"
)

// SessionIntegrationService integrates all session management components
type SessionIntegrationService struct {
	sessionManager    EnhancedSessionManager
	securityMonitor   *SessionSecurityMonitor
	cleanupService    *SessionCleanupService
	sessionAPI        *SessionAPI
	auditLogger       SecurityAuditLogger
	
	mu      sync.RWMutex
	running bool
}

// SessionIntegrationConfig holds configuration for the integration service
type SessionIntegrationConfig struct {
	SessionConfig   *SessionConfig         `json:"session_config"`
	SecurityConfig  *SecurityMonitorConfig `json:"security_config"`
	CleanupConfig   *CleanupConfig         `json:"cleanup_config"`
	EnableAPI       bool                   `json:"enable_api"`
	EnableSecurity  bool                   `json:"enable_security"`
	EnableCleanup   bool                   `json:"enable_cleanup"`
}

// DefaultSessionIntegrationConfig returns a default integration configuration
func DefaultSessionIntegrationConfig() *SessionIntegrationConfig {
	return &SessionIntegrationConfig{
		SessionConfig:  DefaultSessionConfig(),
		SecurityConfig: DefaultSecurityMonitorConfig(),
		CleanupConfig:  DefaultCleanupConfig(),
		EnableAPI:      true,
		EnableSecurity: true,
		EnableCleanup:  true,
	}
}

// NewSessionIntegrationService creates a new session integration service
func NewSessionIntegrationService(auditLogger SecurityAuditLogger, config *SessionIntegrationConfig) *SessionIntegrationService {
	if config == nil {
		config = DefaultSessionIntegrationConfig()
	}
	
	// Create session manager
	sessionManager := NewSessionManager(config.SessionConfig, auditLogger)
	
	service := &SessionIntegrationService{
		sessionManager: sessionManager,
		auditLogger:    auditLogger,
	}
	
	// Create security monitor if enabled
	if config.EnableSecurity {
		service.securityMonitor = NewSessionSecurityMonitor(sessionManager, auditLogger, config.SecurityConfig)
	}
	
	// Create cleanup service if enabled
	if config.EnableCleanup {
		service.cleanupService = NewSessionCleanupService(sessionManager, auditLogger, config.CleanupConfig)
	}
	
	// Create API if enabled
	if config.EnableAPI {
		service.sessionAPI = NewSessionAPI(sessionManager, auditLogger)
	}
	
	return service
}

// Start starts all enabled services
func (s *SessionIntegrationService) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.running {
		return nil
	}
	
	// Start security monitor
	if s.securityMonitor != nil {
		if err := s.securityMonitor.Start(); err != nil {
			return fmt.Errorf("failed to start security monitor: %w", err)
		}
	}
	
	// Start cleanup service
	if s.cleanupService != nil {
		if err := s.cleanupService.Start(); err != nil {
			return fmt.Errorf("failed to start cleanup service: %w", err)
		}
	}
	
	s.running = true
	
	// Log service start
	if s.auditLogger != nil {
		s.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionCreated, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			Success:   true,
			Message:   "Session integration service started",
			Details: map[string]interface{}{
				"security_enabled": s.securityMonitor != nil,
				"cleanup_enabled":  s.cleanupService != nil,
				"api_enabled":      s.sessionAPI != nil,
			},
		})
	}
	
	return nil
}

// Stop stops all services
func (s *SessionIntegrationService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if !s.running {
		return nil
	}
	
	var errors []error
	
	// Stop security monitor
	if s.securityMonitor != nil {
		if err := s.securityMonitor.Stop(); err != nil {
			errors = append(errors, fmt.Errorf("failed to stop security monitor: %w", err))
		}
	}
	
	// Stop cleanup service
	if s.cleanupService != nil {
		if err := s.cleanupService.Stop(); err != nil {
			errors = append(errors, fmt.Errorf("failed to stop cleanup service: %w", err))
		}
	}
	
	// Stop session manager
	if err := s.sessionManager.Shutdown(); err != nil {
		errors = append(errors, fmt.Errorf("failed to stop session manager: %w", err))
	}
	
	s.running = false
	
	// Log service stop
	if s.auditLogger != nil {
		s.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionExpired,
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			Success:   len(errors) == 0,
			Message:   "Session integration service stopped",
			Details: map[string]interface{}{
				"errors": len(errors),
			},
		})
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("errors stopping services: %v", errors)
	}
	
	return nil
}

// IsRunning returns whether the service is running
func (s *SessionIntegrationService) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GetSessionManager returns the session manager
func (s *SessionIntegrationService) GetSessionManager() EnhancedSessionManager {
	return s.sessionManager
}

// GetSecurityMonitor returns the security monitor
func (s *SessionIntegrationService) GetSecurityMonitor() *SessionSecurityMonitor {
	return s.securityMonitor
}

// GetCleanupService returns the cleanup service
func (s *SessionIntegrationService) GetCleanupService() *SessionCleanupService {
	return s.cleanupService
}

// GetSessionAPI returns the session API
func (s *SessionIntegrationService) GetSessionAPI() *SessionAPI {
	return s.sessionAPI
}

// RegisterAPIRoutes registers API routes with the provided mux
func (s *SessionIntegrationService) RegisterAPIRoutes(mux *http.ServeMux) {
	if s.sessionAPI != nil {
		s.sessionAPI.RegisterRoutes(mux)
	}
}

// TrackSessionActivity tracks session activity for security monitoring
func (s *SessionIntegrationService) TrackSessionActivity(sessionID, userID, ipAddress, userAgent string) {
	if s.securityMonitor != nil {
		s.securityMonitor.TrackSessionActivity(sessionID, userID, ipAddress, userAgent)
	}
}

// GetIntegratedStats returns combined statistics from all services
func (s *SessionIntegrationService) GetIntegratedStats() *IntegratedSessionStats {
	stats := &IntegratedSessionStats{
		Timestamp: time.Now(),
	}
	
	// Get session manager stats
	if s.sessionManager != nil {
		stats.SessionStats = s.sessionManager.GetSessionStats()
	}
	
	// Get security monitor stats
	if s.securityMonitor != nil {
		stats.SecurityStats = s.securityMonitor.GetStats()
	}
	
	// Get cleanup service stats
	if s.cleanupService != nil {
		stats.CleanupStats = s.cleanupService.GetStats()
	}
	
	return stats
}

// IntegratedSessionStats combines statistics from all session services
type IntegratedSessionStats struct {
	Timestamp     time.Time              `json:"timestamp"`
	SessionStats  *SessionStats          `json:"session_stats,omitempty"`
	SecurityStats *SecurityMonitorStats  `json:"security_stats,omitempty"`
	CleanupStats  *CleanupStats          `json:"cleanup_stats,omitempty"`
}

// CreateSession creates a new session and tracks it for security monitoring
func (s *SessionIntegrationService) CreateSession(userID string, metadata *SessionMetadata) (*UserSession, error) {
	// Create session
	session, err := s.sessionManager.CreateSession(userID, metadata)
	if err != nil {
		return nil, err
	}
	
	// Track initial activity for security monitoring
	if s.securityMonitor != nil && metadata != nil {
		s.securityMonitor.TrackSessionActivity(session.ID, userID, metadata.IPAddress, metadata.UserAgent)
	}
	
	return session, nil
}

// ValidateSession validates a session and tracks the activity
func (s *SessionIntegrationService) ValidateSession(sessionID string) (*UserSession, error) {
	session, err := s.sessionManager.ValidateSession(sessionID)
	if err != nil {
		return nil, err
	}
	
	// Track validation activity for security monitoring
	if s.securityMonitor != nil {
		s.securityMonitor.TrackSessionActivity(sessionID, session.UserID, session.IPAddress, session.UserAgent)
	}
	
	return session, nil
}

// TerminateSession terminates a session
func (s *SessionIntegrationService) TerminateSession(sessionID string) error {
	return s.sessionManager.TerminateSession(sessionID)
}

// TerminateAllUserSessions terminates all sessions for a user
func (s *SessionIntegrationService) TerminateAllUserSessions(userID string) error {
	return s.sessionManager.TerminateAllUserSessions(userID)
}

// GetActiveSessions returns active sessions for a user
func (s *SessionIntegrationService) GetActiveSessions(userID string) ([]*UserSession, error) {
	return s.sessionManager.GetActiveSessions(userID)
}

// RefreshSession refreshes a session
func (s *SessionIntegrationService) RefreshSession(sessionID string) error {
	return s.sessionManager.RefreshSession(sessionID)
}

// GetSessionInfo returns information about a session
func (s *SessionIntegrationService) GetSessionInfo(sessionID string) (*UserSession, error) {
	return s.sessionManager.GetSessionInfo(sessionID)
}

// ListAllActiveSessions returns all active sessions
func (s *SessionIntegrationService) ListAllActiveSessions() ([]*UserSession, error) {
	return s.sessionManager.ListAllActiveSessions()
}

// CleanupExpiredSessions manually triggers session cleanup
func (s *SessionIntegrationService) CleanupExpiredSessions() error {
	return s.sessionManager.CleanupExpiredSessions()
}

// GetUserActivity returns security activity information for a user
func (s *SessionIntegrationService) GetUserActivity(userID string) *UserActivityTracker {
	if s.securityMonitor != nil {
		return s.securityMonitor.GetUserActivity(userID)
	}
	return nil
}

// GetSessionActivity returns security activity information for a session
func (s *SessionIntegrationService) GetSessionActivity(sessionID string) *SessionActivityTracker {
	if s.securityMonitor != nil {
		return s.securityMonitor.GetSessionActivity(sessionID)
	}
	return nil
}

// UpdateSecurityConfig updates the security monitoring configuration
func (s *SessionIntegrationService) UpdateSecurityConfig(config *SecurityMonitorConfig) error {
	if s.securityMonitor != nil {
		return s.securityMonitor.UpdateConfig(config)
	}
	return fmt.Errorf("security monitor not enabled")
}

// ForceTerminateSession forcefully terminates a session due to security concerns
func (s *SessionIntegrationService) ForceTerminateSession(sessionID, reason string) error {
	if s.securityMonitor != nil {
		return s.securityMonitor.ForceTerminateSession(sessionID, reason)
	}
	// Fallback to regular termination if security monitor is not available
	return s.sessionManager.TerminateSession(sessionID)
}

// ForceTerminateUserSessions forcefully terminates all sessions for a user
func (s *SessionIntegrationService) ForceTerminateUserSessions(userID, reason string) error {
	if s.securityMonitor != nil {
		return s.securityMonitor.ForceTerminateUserSessions(userID, reason)
	}
	// Fallback to regular termination if security monitor is not available
	return s.sessionManager.TerminateAllUserSessions(userID)
}

// GetSessionSecurityReport generates a security report for a session
func (s *SessionIntegrationService) GetSessionSecurityReport(sessionID string) (*SessionSecurityReport, error) {
	if s.securityMonitor != nil {
		return s.securityMonitor.GetSessionSecurityReport(sessionID)
	}
	return nil, fmt.Errorf("security monitor not enabled")
}

// GetUserSecurityReport generates a security report for all user sessions
func (s *SessionIntegrationService) GetUserSecurityReport(userID string) (*UserSecurityReport, error) {
	if s.securityMonitor != nil {
		return s.securityMonitor.GetUserSecurityReport(userID)
	}
	return nil, fmt.Errorf("security monitor not enabled")
}

// EvaluateSessionRisk evaluates the risk level of a session
func (s *SessionIntegrationService) EvaluateSessionRisk(sessionID string) (SessionRiskLevel, error) {
	if s.securityMonitor != nil {
		return s.securityMonitor.evaluateSessionRisk(sessionID), nil
	}
	return RiskLevelLow, fmt.Errorf("security monitor not enabled")
}

// UpdateCleanupConfig updates the cleanup service configuration
func (s *SessionIntegrationService) UpdateCleanupConfig(config *CleanupConfig) error {
	if s.cleanupService != nil {
		return s.cleanupService.UpdateConfig(config)
	}
	return fmt.Errorf("cleanup service not enabled")
}

// HealthCheck performs a health check on all services
func (s *SessionIntegrationService) HealthCheck() *ServiceHealthStatus {
	status := &ServiceHealthStatus{
		Timestamp: time.Now(),
		Overall:   "healthy",
		Services:  make(map[string]ServiceStatus),
	}
	
	// Check session manager
	sessionStats := s.sessionManager.GetSessionStats()
	status.Services["session_manager"] = ServiceStatus{
		Status:  "healthy",
		Details: map[string]interface{}{
			"active_sessions": sessionStats.TotalActiveSessions,
		},
	}
	
	// Check security monitor
	if s.securityMonitor != nil {
		securityStats := s.securityMonitor.GetStats()
		securityStatus := ServiceStatus{
			Status: "healthy",
			Details: map[string]interface{}{
				"suspicious_events": securityStats.SuspiciousEventsDetected,
				"monitoring_errors": securityStats.MonitoringErrors,
			},
		}
		
		if securityStats.MonitoringErrors > 0 {
			securityStatus.Status = "degraded"
			status.Overall = "degraded"
		}
		
		status.Services["security_monitor"] = securityStatus
	}
	
	// Check cleanup service
	if s.cleanupService != nil {
		cleanupStats := s.cleanupService.GetStats()
		cleanupStatus := ServiceStatus{
			Status: "healthy",
			Details: map[string]interface{}{
				"total_runs": cleanupStats.TotalRuns,
				"errors":     cleanupStats.Errors,
			},
		}
		
		if cleanupStats.Errors > 0 {
			cleanupStatus.Status = "degraded"
			if status.Overall == "healthy" {
				status.Overall = "degraded"
			}
		}
		
		status.Services["cleanup_service"] = cleanupStatus
	}
	
	// Check API
	if s.sessionAPI != nil {
		status.Services["session_api"] = ServiceStatus{
			Status: "healthy",
			Details: map[string]interface{}{
				"enabled": true,
			},
		}
	}
	
	return status
}

// ServiceHealthStatus represents the health status of all services
type ServiceHealthStatus struct {
	Timestamp time.Time                  `json:"timestamp"`
	Overall   string                     `json:"overall"` // "healthy", "degraded", "unhealthy"
	Services  map[string]ServiceStatus   `json:"services"`
}

// ServiceStatus represents the status of an individual service
type ServiceStatus struct {
	Status  string                 `json:"status"`
	Details map[string]interface{} `json:"details,omitempty"`
}