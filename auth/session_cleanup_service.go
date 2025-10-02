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
	"sync"
	"time"
)

// SessionCleanupService provides automatic cleanup of expired sessions
type SessionCleanupService struct {
	sessionManager EnhancedSessionManager
	auditLogger    SecurityAuditLogger
	config         *CleanupConfig
	
	mu       sync.RWMutex
	running  bool
	ctx      context.Context
	cancel   context.CancelFunc
	ticker   *time.Ticker
	
	// Statistics
	stats *CleanupStats
}

// CleanupConfig holds configuration for the cleanup service
type CleanupConfig struct {
	// Interval between cleanup runs
	CleanupInterval time.Duration `json:"cleanup_interval"`
	
	// Maximum number of sessions to clean up in one run
	MaxCleanupBatch int `json:"max_cleanup_batch"`
	
	// Enable detailed logging of cleanup operations
	VerboseLogging bool `json:"verbose_logging"`
	
	// Cleanup inactive sessions even if not expired
	CleanupInactive bool `json:"cleanup_inactive"`
	
	// Inactivity threshold for cleanup
	InactivityThreshold time.Duration `json:"inactivity_threshold"`
	
	// Enable cleanup of sessions with suspicious activity
	CleanupSuspicious bool `json:"cleanup_suspicious"`
}

// CleanupStats provides statistics about cleanup operations
type CleanupStats struct {
	TotalRuns           int64     `json:"total_runs"`
	TotalCleaned        int64     `json:"total_cleaned"`
	LastRun             time.Time `json:"last_run"`
	LastCleanedCount    int       `json:"last_cleaned_count"`
	AverageCleanupTime  time.Duration `json:"average_cleanup_time"`
	LargestCleanupBatch int       `json:"largest_cleanup_batch"`
	Errors              int64     `json:"errors"`
	LastError           string    `json:"last_error,omitempty"`
	LastErrorTime       time.Time `json:"last_error_time,omitempty"`
}

// DefaultCleanupConfig returns a default cleanup configuration
func DefaultCleanupConfig() *CleanupConfig {
	return &CleanupConfig{
		CleanupInterval:     15 * time.Minute,
		MaxCleanupBatch:     1000,
		VerboseLogging:      false,
		CleanupInactive:     true,
		InactivityThreshold: 2 * time.Hour,
		CleanupSuspicious:   false,
	}
}

// NewSessionCleanupService creates a new session cleanup service
func NewSessionCleanupService(sessionManager EnhancedSessionManager, auditLogger SecurityAuditLogger, config *CleanupConfig) *SessionCleanupService {
	if config == nil {
		config = DefaultCleanupConfig()
	}
	
	return &SessionCleanupService{
		sessionManager: sessionManager,
		auditLogger:    auditLogger,
		config:         config,
		stats: &CleanupStats{},
	}
}

// Start starts the cleanup service
func (s *SessionCleanupService) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.running {
		return nil // Already running
	}
	
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.ticker = time.NewTicker(s.config.CleanupInterval)
	s.running = true
	
	// Start the cleanup loop
	go s.cleanupLoop()
	
	// Log service start
	if s.auditLogger != nil {
		s.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionCreated, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			Success:   true,
			Message:   "Session cleanup service started",
			Details: map[string]interface{}{
				"cleanup_interval": s.config.CleanupInterval.String(),
				"max_batch_size":   s.config.MaxCleanupBatch,
			},
		})
	}
	
	return nil
}

// Stop stops the cleanup service
func (s *SessionCleanupService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if !s.running {
		return nil // Already stopped
	}
	
	s.running = false
	
	if s.cancel != nil {
		s.cancel()
	}
	
	if s.ticker != nil {
		s.ticker.Stop()
	}
	
	// Log service stop
	if s.auditLogger != nil {
		s.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionExpired,
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			Success:   true,
			Message:   "Session cleanup service stopped",
			Details: map[string]interface{}{
				"total_runs":    s.stats.TotalRuns,
				"total_cleaned": s.stats.TotalCleaned,
			},
		})
	}
	
	return nil
}

// IsRunning returns whether the cleanup service is running
func (s *SessionCleanupService) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GetStats returns cleanup statistics
func (s *SessionCleanupService) GetStats() *CleanupStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	// Return a copy to avoid race conditions
	statsCopy := *s.stats
	return &statsCopy
}

// RunCleanup manually triggers a cleanup run
func (s *SessionCleanupService) RunCleanup() error {
	return s.performCleanup()
}

// UpdateConfig updates the cleanup configuration
func (s *SessionCleanupService) UpdateConfig(config *CleanupConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if config == nil {
		return ErrInvalidSessionID // Reusing existing error
	}
	
	oldInterval := s.config.CleanupInterval
	s.config = config
	
	// If running and interval changed, restart ticker
	if s.running && oldInterval != config.CleanupInterval {
		if s.ticker != nil {
			s.ticker.Stop()
		}
		s.ticker = time.NewTicker(config.CleanupInterval)
	}
	
	// Log config update
	if s.auditLogger != nil {
		s.auditLogger.LogSecurityEvent(&SecurityEvent{
			Type:      EventTypeSessionCreated, // Using existing event type
			Severity:  SeverityLow,
			Timestamp: time.Now(),
			Success:   true,
			Message:   "Session cleanup service configuration updated",
			Details: map[string]interface{}{
				"old_interval": oldInterval.String(),
				"new_interval": config.CleanupInterval.String(),
			},
		})
	}
	
	return nil
}

// cleanupLoop runs the periodic cleanup
func (s *SessionCleanupService) cleanupLoop() {
	// Run initial cleanup
	s.performCleanup()
	
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.ticker.C:
			s.performCleanup()
		}
	}
}

// performCleanup performs the actual cleanup operation
func (s *SessionCleanupService) performCleanup() error {
	start := time.Now()
	
	s.mu.Lock()
	s.stats.TotalRuns++
	s.stats.LastRun = start
	s.mu.Unlock()
	
	// Perform basic session cleanup
	err := s.sessionManager.CleanupExpiredSessions()
	if err != nil {
		s.recordError(err)
		return err
	}
	
	// Get current session stats for additional cleanup logic
	sessionStats := s.sessionManager.GetSessionStats()
	cleanedCount := 0
	
	// Additional cleanup based on configuration
	if s.config.CleanupInactive {
		cleanedCount += s.cleanupInactiveSessions()
	}
	
	if s.config.CleanupSuspicious {
		cleanedCount += s.cleanupSuspiciousSessions()
	}
	
	duration := time.Since(start)
	
	// Update statistics
	s.mu.Lock()
	s.stats.TotalCleaned += int64(cleanedCount)
	s.stats.LastCleanedCount = cleanedCount
	
	// Update average cleanup time
	if s.stats.TotalRuns == 1 {
		s.stats.AverageCleanupTime = duration
	} else {
		s.stats.AverageCleanupTime = (s.stats.AverageCleanupTime + duration) / 2
	}
	
	if cleanedCount > s.stats.LargestCleanupBatch {
		s.stats.LargestCleanupBatch = cleanedCount
	}
	s.mu.Unlock()
	
	// Log cleanup results
	if s.config.VerboseLogging || cleanedCount > 0 {
		if s.auditLogger != nil {
			s.auditLogger.LogSecurityEvent(&SecurityEvent{
				Type:      EventTypeSessionExpired,
				Severity:  SeverityLow,
				Timestamp: time.Now(),
				Success:   true,
				Message:   "Session cleanup completed",
				Details: map[string]interface{}{
					"cleaned_count":     cleanedCount,
					"duration_ms":       duration.Milliseconds(),
					"active_sessions":   sessionStats.TotalActiveSessions,
					"total_runs":        s.stats.TotalRuns,
					"total_cleaned":     s.stats.TotalCleaned,
				},
			})
		}
	}
	
	return nil
}

// cleanupInactiveSessions removes sessions that have been inactive for too long
func (s *SessionCleanupService) cleanupInactiveSessions() int {
	if s.config.InactivityThreshold <= 0 {
		return 0
	}
	
	// Get all active sessions
	allSessions, err := s.sessionManager.ListAllActiveSessions()
	if err != nil {
		s.recordError(err)
		return 0
	}
	
	now := time.Now()
	cleanedCount := 0
	
	for _, session := range allSessions {
		if now.Sub(session.LastUsed) > s.config.InactivityThreshold {
			err := s.sessionManager.TerminateSession(session.ID)
			if err == nil {
				cleanedCount++
				
				// Log individual session cleanup if verbose
				if s.config.VerboseLogging && s.auditLogger != nil {
					s.auditLogger.LogSecurityEvent(&SecurityEvent{
						Type:      EventTypeSessionExpired,
						Severity:  SeverityLow,
						Timestamp: now,
						UserID:    session.UserID,
						SessionID: session.ID,
						Success:   true,
						Message:   "Session terminated due to inactivity",
						Details: map[string]interface{}{
							"inactive_duration": now.Sub(session.LastUsed).String(),
							"threshold":         s.config.InactivityThreshold.String(),
							"reason":            "inactivity_cleanup",
						},
					})
				}
			}
			
			// Respect batch size limit
			if cleanedCount >= s.config.MaxCleanupBatch {
				break
			}
		}
	}
	
	return cleanedCount
}

// cleanupSuspiciousSessions removes sessions flagged as suspicious
func (s *SessionCleanupService) cleanupSuspiciousSessions() int {
	// Get all active sessions
	allSessions, err := s.sessionManager.ListAllActiveSessions()
	if err != nil {
		s.recordError(err)
		return 0
	}
	
	cleanedCount := 0
	
	for _, session := range allSessions {
		// Check for suspicious flags
		if len(session.SuspiciousFlags) > 0 {
			err := s.sessionManager.TerminateSession(session.ID)
			if err == nil {
				cleanedCount++
				
				// Log suspicious session cleanup
				if s.auditLogger != nil {
					s.auditLogger.LogSecurityEvent(&SecurityEvent{
						Type:      EventTypeSessionExpired,
						Severity:  SeverityHigh,
						Timestamp: time.Now(),
						UserID:    session.UserID,
						SessionID: session.ID,
						Success:   true,
						Message:   "Suspicious session terminated",
						Details: map[string]interface{}{
							"suspicious_flags": session.SuspiciousFlags,
							"reason":           "suspicious_activity_cleanup",
						},
					})
				}
			}
			
			// Respect batch size limit
			if cleanedCount >= s.config.MaxCleanupBatch {
				break
			}
		}
	}
	
	return cleanedCount
}

// recordError records an error in the statistics
func (s *SessionCleanupService) recordError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.stats.Errors++
	s.stats.LastError = err.Error()
	s.stats.LastErrorTime = time.Now()
}

// GetConfig returns the current cleanup configuration
func (s *SessionCleanupService) GetConfig() *CleanupConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	// Return a copy to avoid race conditions
	configCopy := *s.config
	return &configCopy
}