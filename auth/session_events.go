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
	"time"
)

// SessionEventType defines the type of session event
type SessionEventType string

const (
	SessionEventCreated           SessionEventType = "session_created"
	SessionEventTerminated        SessionEventType = "session_terminated"
	SessionEventExpired           SessionEventType = "session_expired"
	SessionEventRefreshed         SessionEventType = "session_refreshed"
	SessionEventUpdated           SessionEventType = "session_updated"
	SessionEventBulkTerminated    SessionEventType = "session_bulk_terminated"
	SessionEventCleanup           SessionEventType = "session_cleanup"
	SessionEventPermissionRefresh SessionEventType = "session_permission_refresh"
	SessionEventSuspicious        SessionEventType = "session_suspicious_activity"
	SessionEventSecurityViolation SessionEventType = "session_security_violation"
)

// SessionEvent represents a session-related event for audit logging
type SessionEvent struct {
	Type      SessionEventType       `json:"type"`
	SessionID string                 `json:"session_id,omitempty"`
	UserID    string                 `json:"user_id"`
	IPAddress string                 `json:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// SessionSecurityEvent represents a security-related session event
type SessionSecurityEvent struct {
	SessionID         string                 `json:"session_id"`
	UserID            string                 `json:"user_id"`
	EventType         string                 `json:"event_type"`
	Severity          string                 `json:"severity"`
	Description       string                 `json:"description"`
	IPAddress         string                 `json:"ip_address,omitempty"`
	UserAgent         string                 `json:"user_agent,omitempty"`
	PreviousIPAddress string                 `json:"previous_ip_address,omitempty"`
	Timestamp         time.Time              `json:"timestamp"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// SessionAnomalyType defines types of session anomalies
type SessionAnomalyType string

const (
	AnomalyIPChange           SessionAnomalyType = "ip_change"
	AnomalyUserAgentChange    SessionAnomalyType = "user_agent_change"
	AnomalyUnusualLocation    SessionAnomalyType = "unusual_location"
	AnomalyRapidRequests      SessionAnomalyType = "rapid_requests"
	AnomalyOffHoursAccess     SessionAnomalyType = "off_hours_access"
	AnomalyMultipleLocations  SessionAnomalyType = "multiple_locations"
	AnomalyLongSession        SessionAnomalyType = "long_session"
	AnomalyPrivilegeEscalation SessionAnomalyType = "privilege_escalation"
)

// SessionAnomaly represents a detected session anomaly
type SessionAnomaly struct {
	Type        SessionAnomalyType     `json:"type"`
	SessionID   string                 `json:"session_id"`
	UserID      string                 `json:"user_id"`
	Severity    string                 `json:"severity"` // "low", "medium", "high", "critical"
	Description string                 `json:"description"`
	DetectedAt  time.Time              `json:"detected_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SessionMetrics represents session-related metrics
type SessionMetrics struct {
	ActiveSessions        int                        `json:"active_sessions"`
	SessionsCreatedToday  int                        `json:"sessions_created_today"`
	SessionsExpiredToday  int                        `json:"sessions_expired_today"`
	AverageSessionLength  time.Duration              `json:"average_session_length"`
	SessionsByProvider    map[string]int             `json:"sessions_by_provider"`
	SessionsByUserType    map[string]int             `json:"sessions_by_user_type"`
	SuspiciousActivities  int                        `json:"suspicious_activities"`
	SecurityViolations    int                        `json:"security_violations"`
	Timestamp             time.Time                  `json:"timestamp"`
}