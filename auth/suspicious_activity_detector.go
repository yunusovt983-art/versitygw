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
	"sync"
	"time"
)

// SuspiciousActivityDetector detects patterns of suspicious activity
type SuspiciousActivityDetector struct {
	mu                sync.RWMutex
	logger            SecurityAuditLogger
	userFailures      map[string]*FailureTracker
	ipFailures        map[string]*FailureTracker
	userAgentFailures map[string]*FailureTracker
	config            *DetectorConfig
	stopCh            chan struct{}
}

// FailureTracker tracks failures for pattern detection
type FailureTracker struct {
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
	Events    []*SecurityEvent
}

// DetectorConfig contains configuration for the suspicious activity detector
type DetectorConfig struct {
	// Thresholds for different types of suspicious activity
	MaxFailuresPerUser      int           `json:"max_failures_per_user"`
	MaxFailuresPerIP        int           `json:"max_failures_per_ip"`
	MaxFailuresPerUserAgent int           `json:"max_failures_per_user_agent"`
	
	// Time windows for pattern detection
	FailureTimeWindow       time.Duration `json:"failure_time_window"`
	CleanupInterval         time.Duration `json:"cleanup_interval"`
	
	// Brute force detection
	BruteForceThreshold     int           `json:"brute_force_threshold"`
	BruteForceTimeWindow    time.Duration `json:"brute_force_time_window"`
	
	// Distributed attack detection
	DistributedAttackThreshold int        `json:"distributed_attack_threshold"`
	DistributedAttackWindow    time.Duration `json:"distributed_attack_window"`
	
	// Account enumeration detection
	EnumerationThreshold    int           `json:"enumeration_threshold"`
	EnumerationTimeWindow   time.Duration `json:"enumeration_time_window"`
}

// DefaultDetectorConfig returns default configuration for the detector
func DefaultDetectorConfig() *DetectorConfig {
	return &DetectorConfig{
		MaxFailuresPerUser:         5,
		MaxFailuresPerIP:           20,
		MaxFailuresPerUserAgent:    10,
		FailureTimeWindow:          15 * time.Minute,
		CleanupInterval:            5 * time.Minute,
		BruteForceThreshold:        10,
		BruteForceTimeWindow:       5 * time.Minute,
		DistributedAttackThreshold: 50,
		DistributedAttackWindow:    10 * time.Minute,
		EnumerationThreshold:       20,
		EnumerationTimeWindow:      10 * time.Minute,
	}
}

// ValidateConfig ensures the configuration has valid values
func (c *DetectorConfig) Validate() error {
	if c.CleanupInterval <= 0 {
		c.CleanupInterval = 5 * time.Minute
	}
	if c.FailureTimeWindow <= 0 {
		c.FailureTimeWindow = 15 * time.Minute
	}
	if c.BruteForceTimeWindow <= 0 {
		c.BruteForceTimeWindow = 5 * time.Minute
	}
	if c.DistributedAttackWindow <= 0 {
		c.DistributedAttackWindow = 10 * time.Minute
	}
	if c.EnumerationTimeWindow <= 0 {
		c.EnumerationTimeWindow = 10 * time.Minute
	}
	return nil
}

// NewSuspiciousActivityDetector creates a new suspicious activity detector
func NewSuspiciousActivityDetector(logger SecurityAuditLogger) *SuspiciousActivityDetector {
	config := DefaultDetectorConfig()
	config.Validate() // Ensure valid configuration
	
	detector := &SuspiciousActivityDetector{
		logger:            logger,
		userFailures:      make(map[string]*FailureTracker),
		ipFailures:        make(map[string]*FailureTracker),
		userAgentFailures: make(map[string]*FailureTracker),
		config:            config,
		stopCh:            make(chan struct{}),
	}

	// Start cleanup goroutine
	go detector.cleanupRoutine()

	return detector
}

// AnalyzeEvent analyzes a security event for suspicious patterns
func (d *SuspiciousActivityDetector) AnalyzeEvent(event *SecurityEvent) {
	if event == nil || event.Success {
		return // Only analyze failed events
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// Track failures by user
	if event.UserID != "" {
		d.trackFailure(d.userFailures, event.UserID, event, now)
		d.checkUserBruteForce(event.UserID, now)
	}

	// Track failures by IP
	if event.IPAddress != "" {
		d.trackFailure(d.ipFailures, event.IPAddress, event, now)
		d.checkIPBruteForce(event.IPAddress, now)
	}

	// Track failures by User Agent
	if event.UserAgent != "" {
		d.trackFailure(d.userAgentFailures, event.UserAgent, event, now)
	}

	// Check for distributed attacks
	d.checkDistributedAttack(now)

	// Check for account enumeration
	d.checkAccountEnumeration(now)
}

// trackFailure tracks a failure for a specific key (user, IP, etc.)
func (d *SuspiciousActivityDetector) trackFailure(trackers map[string]*FailureTracker, key string, event *SecurityEvent, now time.Time) {
	tracker, exists := trackers[key]
	if !exists {
		tracker = &FailureTracker{
			FirstSeen: now,
			Events:    make([]*SecurityEvent, 0),
		}
		trackers[key] = tracker
	}

	tracker.Count++
	tracker.LastSeen = now
	tracker.Events = append(tracker.Events, event)

	// Clean up old events outside the time window
	d.cleanupTrackerEvents(tracker, now)
}

// cleanupTrackerEvents removes events outside the time window
func (d *SuspiciousActivityDetector) cleanupTrackerEvents(tracker *FailureTracker, now time.Time) {
	cutoff := now.Add(-d.config.FailureTimeWindow)
	validEvents := make([]*SecurityEvent, 0)

	for _, event := range tracker.Events {
		if event.Timestamp.After(cutoff) {
			validEvents = append(validEvents, event)
		}
	}

	tracker.Events = validEvents
	tracker.Count = len(validEvents)

	if len(validEvents) > 0 {
		tracker.FirstSeen = validEvents[0].Timestamp
	}
}

// checkUserBruteForce checks for brute force attacks against a specific user
func (d *SuspiciousActivityDetector) checkUserBruteForce(userID string, now time.Time) {
	tracker := d.userFailures[userID]
	if tracker == nil || tracker.Count < d.config.BruteForceThreshold {
		return
	}

	// Check if failures occurred within the brute force time window
	if now.Sub(tracker.FirstSeen) <= d.config.BruteForceTimeWindow {
		pattern := &SuspiciousPattern{
			Type:        "brute_force_user",
			Description: "Brute force attack detected against user account",
			Severity:    SeverityHigh,
			UserID:      userID,
			Count:       tracker.Count,
			TimeWindow:  now.Sub(tracker.FirstSeen),
			FirstSeen:   tracker.FirstSeen,
			LastSeen:    tracker.LastSeen,
			Details: map[string]interface{}{
				"threshold_exceeded": d.config.BruteForceThreshold,
				"actual_failures":    tracker.Count,
			},
		}

		d.logger.LogSuspiciousActivity(pattern)
	}
}

// checkIPBruteForce checks for brute force attacks from a specific IP
func (d *SuspiciousActivityDetector) checkIPBruteForce(ipAddress string, now time.Time) {
	tracker := d.ipFailures[ipAddress]
	if tracker == nil || tracker.Count < d.config.BruteForceThreshold {
		return
	}

	// Check if failures occurred within the brute force time window
	if now.Sub(tracker.FirstSeen) <= d.config.BruteForceTimeWindow {
		pattern := &SuspiciousPattern{
			Type:        "brute_force_ip",
			Description: "Brute force attack detected from IP address",
			Severity:    SeverityHigh,
			IPAddress:   ipAddress,
			Count:       tracker.Count,
			TimeWindow:  now.Sub(tracker.FirstSeen),
			FirstSeen:   tracker.FirstSeen,
			LastSeen:    tracker.LastSeen,
			Details: map[string]interface{}{
				"threshold_exceeded": d.config.BruteForceThreshold,
				"actual_failures":    tracker.Count,
			},
		}

		d.logger.LogSuspiciousActivity(pattern)
	}
}

// checkDistributedAttack checks for distributed attacks across multiple IPs
func (d *SuspiciousActivityDetector) checkDistributedAttack(now time.Time) {
	cutoff := now.Add(-d.config.DistributedAttackWindow)
	totalFailures := 0
	activeIPs := 0

	for _, tracker := range d.ipFailures {
		if tracker.LastSeen.After(cutoff) && tracker.Count > 0 {
			totalFailures += tracker.Count
			activeIPs++
		}
	}

	if totalFailures >= d.config.DistributedAttackThreshold && activeIPs >= 3 {
		pattern := &SuspiciousPattern{
			Type:        "distributed_attack",
			Description: "Distributed attack detected across multiple IP addresses",
			Severity:    SeverityCritical,
			Count:       totalFailures,
			TimeWindow:  d.config.DistributedAttackWindow,
			FirstSeen:   now.Add(-d.config.DistributedAttackWindow),
			LastSeen:    now,
			Details: map[string]interface{}{
				"total_failures":     totalFailures,
				"active_ips":         activeIPs,
				"threshold_exceeded": d.config.DistributedAttackThreshold,
			},
		}

		d.logger.LogSuspiciousActivity(pattern)
	}
}

// checkAccountEnumeration checks for account enumeration attempts
func (d *SuspiciousActivityDetector) checkAccountEnumeration(now time.Time) {
	cutoff := now.Add(-d.config.EnumerationTimeWindow)
	
	// Group failures by IP to detect enumeration from single source
	ipEnumerationCounts := make(map[string]int)
	ipUniqueUsers := make(map[string]map[string]bool)

	for userID, tracker := range d.userFailures {
		if tracker.LastSeen.After(cutoff) {
			for _, event := range tracker.Events {
				if event.Timestamp.After(cutoff) && event.IPAddress != "" {
					ipEnumerationCounts[event.IPAddress]++
					
					if ipUniqueUsers[event.IPAddress] == nil {
						ipUniqueUsers[event.IPAddress] = make(map[string]bool)
					}
					ipUniqueUsers[event.IPAddress][userID] = true
				}
			}
		}
	}

	// Check for enumeration patterns
	for ipAddress, count := range ipEnumerationCounts {
		uniqueUsers := len(ipUniqueUsers[ipAddress])
		
		if count >= d.config.EnumerationThreshold && uniqueUsers >= 5 {
			pattern := &SuspiciousPattern{
				Type:        "account_enumeration",
				Description: "Account enumeration attempt detected",
				Severity:    SeverityMedium,
				IPAddress:   ipAddress,
				Count:       count,
				TimeWindow:  d.config.EnumerationTimeWindow,
				FirstSeen:   now.Add(-d.config.EnumerationTimeWindow),
				LastSeen:    now,
				Details: map[string]interface{}{
					"total_attempts":     count,
					"unique_users":       uniqueUsers,
					"threshold_exceeded": d.config.EnumerationThreshold,
				},
			}

			d.logger.LogSuspiciousActivity(pattern)
		}
	}
}

// cleanupRoutine periodically cleans up old tracking data
func (d *SuspiciousActivityDetector) cleanupRoutine() {
	ticker := time.NewTicker(d.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.cleanup()
		case <-d.stopCh:
			return
		}
	}
}

// cleanup removes old tracking data
func (d *SuspiciousActivityDetector) cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-d.config.FailureTimeWindow)

	// Clean up user failures
	for key, tracker := range d.userFailures {
		d.cleanupTrackerEvents(tracker, now)
		if tracker.Count == 0 || tracker.LastSeen.Before(cutoff) {
			delete(d.userFailures, key)
		}
	}

	// Clean up IP failures
	for key, tracker := range d.ipFailures {
		d.cleanupTrackerEvents(tracker, now)
		if tracker.Count == 0 || tracker.LastSeen.Before(cutoff) {
			delete(d.ipFailures, key)
		}
	}

	// Clean up User Agent failures
	for key, tracker := range d.userAgentFailures {
		d.cleanupTrackerEvents(tracker, now)
		if tracker.Count == 0 || tracker.LastSeen.Before(cutoff) {
			delete(d.userAgentFailures, key)
		}
	}
}

// Stop stops the suspicious activity detector
func (d *SuspiciousActivityDetector) Stop() {
	close(d.stopCh)
}

// GetStats returns statistics about tracked failures
func (d *SuspiciousActivityDetector) GetStats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return map[string]interface{}{
		"tracked_users":       len(d.userFailures),
		"tracked_ips":         len(d.ipFailures),
		"tracked_user_agents": len(d.userAgentFailures),
		"config":              d.config,
	}
}

// UpdateConfig updates the detector configuration
func (d *SuspiciousActivityDetector) UpdateConfig(config *DetectorConfig) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	d.config = config
}