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
	"time"
)

// EnhancedLogFields extends the existing LogFields with security-focused authentication details
type EnhancedLogFields struct {
	// Original LogFields
	BucketOwner        string `json:"bucket_owner"`
	Bucket             string `json:"bucket"`
	Time               time.Time `json:"time"`
	RemoteIP           string `json:"remote_ip"`
	Requester          string `json:"requester"`
	RequestID          string `json:"request_id"`
	Operation          string `json:"operation"`
	Key                string `json:"key"`
	RequestURI         string `json:"request_uri"`
	HttpStatus         int    `json:"http_status"`
	ErrorCode          string `json:"error_code"`
	BytesSent          int    `json:"bytes_sent"`
	ObjectSize         int64  `json:"object_size"`
	TotalTime          int64  `json:"total_time"`
	TurnAroundTime     int64  `json:"turn_around_time"`
	Referer            string `json:"referer"`
	UserAgent          string `json:"user_agent"`
	VersionID          string `json:"version_id"`
	HostID             string `json:"host_id"`
	SignatureVersion   string `json:"signature_version"`
	CipherSuite        string `json:"cipher_suite"`
	AuthenticationType string `json:"authentication_type"`
	HostHeader         string `json:"host_header"`
	TLSVersion         string `json:"tls_version"`
	AccessPointARN     string `json:"access_point_arn"`
	AclRequired        string `json:"acl_required"`

	// Enhanced Authentication Fields
	AuthMethod         string    `json:"auth_method,omitempty"`         // e.g., "signature_v4", "mfa", "external_saml"
	AuthProvider       string    `json:"auth_provider,omitempty"`       // e.g., "internal", "ldap", "saml", "oauth2"
	MFAEnabled         bool      `json:"mfa_enabled"`                   // Whether MFA is enabled for the user
	MFAUsed            bool      `json:"mfa_used"`                      // Whether MFA was used for this request
	MFAMethod          string    `json:"mfa_method,omitempty"`          // e.g., "totp", "backup_code"
	SessionID          string    `json:"session_id,omitempty"`          // Session identifier
	SessionDuration    int64     `json:"session_duration,omitempty"`    // Session duration in seconds
	UserRoles          []string  `json:"user_roles,omitempty"`          // User roles at time of request
	PermissionsUsed    []string  `json:"permissions_used,omitempty"`    // Specific permissions checked
	AuthFailureReason  string    `json:"auth_failure_reason,omitempty"` // Reason for authentication failure
	FailedAttempts     int       `json:"failed_attempts,omitempty"`     // Number of recent failed attempts
	AccountLocked      bool      `json:"account_locked"`                // Whether account is locked
	LockedUntil        *time.Time `json:"locked_until,omitempty"`       // When account lock expires
	SecurityEventID    string    `json:"security_event_id,omitempty"`   // Reference to security event
	RiskScore          int       `json:"risk_score,omitempty"`          // Risk score for the request (0-100)
	GeoLocation        string    `json:"geo_location,omitempty"`        // Geographic location of request
	DeviceFingerprint  string    `json:"device_fingerprint,omitempty"`  // Device fingerprint hash
	
	// Compliance and Audit Fields
	ComplianceFlags    []string  `json:"compliance_flags,omitempty"`    // Compliance-related flags
	DataClassification string    `json:"data_classification,omitempty"` // Data classification level
	RetentionPolicy    string    `json:"retention_policy,omitempty"`    // Applicable retention policy
	AuditTrailID       string    `json:"audit_trail_id,omitempty"`      // Audit trail identifier
}

// SecurityLogMeta contains metadata for security-focused logging
type SecurityLogMeta struct {
	// Original LogMeta
	BucketOwner string
	ObjectSize  int64
	Action      string
	HttpStatus  int

	// Enhanced Security Metadata
	AuthenticationResult string            // "success", "failure", "partial"
	SecurityEventType    string            // Type of security event
	ThreatLevel          string            // "low", "medium", "high", "critical"
	RequiredPermissions  []string          // Permissions required for the operation
	GrantedPermissions   []string          // Permissions actually granted
	PolicyViolations     []string          // Any policy violations detected
	ComplianceContext    map[string]string // Compliance-related context
	RiskFactors          []string          // Risk factors identified
}

// AuthenticationEvent represents a detailed authentication event
type AuthenticationEvent struct {
	EventID           string            `json:"event_id"`
	Timestamp         time.Time         `json:"timestamp"`
	UserID            string            `json:"user_id"`
	Username          string            `json:"username,omitempty"`
	IPAddress         string            `json:"ip_address"`
	UserAgent         string            `json:"user_agent"`
	AuthMethod        string            `json:"auth_method"`
	AuthProvider      string            `json:"auth_provider"`
	Success           bool              `json:"success"`
	FailureReason     string            `json:"failure_reason,omitempty"`
	MFAUsed           bool              `json:"mfa_used"`
	MFAMethod         string            `json:"mfa_method,omitempty"`
	SessionID         string            `json:"session_id,omitempty"`
	RequestID         string            `json:"request_id,omitempty"`
	Duration          time.Duration     `json:"duration"`
	RiskScore         int               `json:"risk_score"`
	GeoLocation       string            `json:"geo_location,omitempty"`
	DeviceFingerprint string            `json:"device_fingerprint,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// AuthorizationEvent represents a detailed authorization event
type AuthorizationEvent struct {
	EventID             string            `json:"event_id"`
	Timestamp           time.Time         `json:"timestamp"`
	UserID              string            `json:"user_id"`
	Resource            string            `json:"resource"`
	Action              string            `json:"action"`
	Decision            string            `json:"decision"` // "allow", "deny"
	Reason              string            `json:"reason,omitempty"`
	RequiredPermissions []string          `json:"required_permissions"`
	UserRoles           []string          `json:"user_roles"`
	UserPermissions     []string          `json:"user_permissions"`
	PolicyEvaluations   []PolicyEvaluation `json:"policy_evaluations,omitempty"`
	RequestID           string            `json:"request_id,omitempty"`
	SessionID           string            `json:"session_id,omitempty"`
	IPAddress           string            `json:"ip_address"`
	Duration            time.Duration     `json:"duration"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyEvaluation represents the evaluation of a specific policy
type PolicyEvaluation struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Effect     string `json:"effect"` // "allow", "deny"
	Matched    bool   `json:"matched"`
	Reason     string `json:"reason,omitempty"`
}

// SecurityMetrics contains security-related metrics for monitoring
type SecurityMetrics struct {
	AuthenticationAttempts    int64             `json:"authentication_attempts"`
	AuthenticationSuccesses   int64             `json:"authentication_successes"`
	AuthenticationFailures    int64             `json:"authentication_failures"`
	MFAUsageCount            int64             `json:"mfa_usage_count"`
	SuspiciousActivityCount   int64             `json:"suspicious_activity_count"`
	AccountLockouts          int64             `json:"account_lockouts"`
	PermissionDenials        int64             `json:"permission_denials"`
	HighRiskRequests         int64             `json:"high_risk_requests"`
	ComplianceViolations     int64             `json:"compliance_violations"`
	UniqueUsers              int64             `json:"unique_users"`
	UniqueIPs                int64             `json:"unique_ips"`
	AverageRiskScore         float64           `json:"average_risk_score"`
	TopFailureReasons        map[string]int64  `json:"top_failure_reasons"`
	TopRiskFactors           map[string]int64  `json:"top_risk_factors"`
	GeographicDistribution   map[string]int64  `json:"geographic_distribution"`
	Timestamp                time.Time         `json:"timestamp"`
}

// EnhancedAuditLogger interface extends the basic AuditLogger with security-focused methods
type EnhancedAuditLogger interface {
	AuditLogger // Embed the original interface
	
	// Enhanced logging methods
	LogEnhanced(ctx interface{}, err error, body []byte, meta *SecurityLogMeta) error
	LogAuthenticationEvent(event *AuthenticationEvent) error
	LogAuthorizationEvent(event *AuthorizationEvent) error
	LogSecurityMetrics(metrics *SecurityMetrics) error
	
	// Query methods for security analysis
	GetAuthenticationEvents(filter *AuthEventFilter) ([]*AuthenticationEvent, error)
	GetAuthorizationEvents(filter *AuthzEventFilter) ([]*AuthorizationEvent, error)
	GetSecurityMetrics(timeRange *TimeRange) (*SecurityMetrics, error)
	
	// Alert methods
	TriggerSecurityAlert(alertType string, severity string, details map[string]interface{}) error
}

// AuthEventFilter for filtering authentication events
type AuthEventFilter struct {
	UserID     string     `json:"user_id,omitempty"`
	IPAddress  string     `json:"ip_address,omitempty"`
	Success    *bool      `json:"success,omitempty"`
	AuthMethod string     `json:"auth_method,omitempty"`
	StartTime  *time.Time `json:"start_time,omitempty"`
	EndTime    *time.Time `json:"end_time,omitempty"`
	Limit      int        `json:"limit,omitempty"`
}

// AuthzEventFilter for filtering authorization events
type AuthzEventFilter struct {
	UserID    string     `json:"user_id,omitempty"`
	Resource  string     `json:"resource,omitempty"`
	Action    string     `json:"action,omitempty"`
	Decision  string     `json:"decision,omitempty"`
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Limit     int        `json:"limit,omitempty"`
}

// TimeRange represents a time range for queries
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// CreateEnhancedLogFields creates EnhancedLogFields from original LogFields
func CreateEnhancedLogFields(original *LogFields) *EnhancedLogFields {
	if original == nil {
		return &EnhancedLogFields{}
	}

	return &EnhancedLogFields{
		BucketOwner:        original.BucketOwner,
		Bucket:             original.Bucket,
		Time:               original.Time,
		RemoteIP:           original.RemoteIP,
		Requester:          original.Requester,
		RequestID:          original.RequestID,
		Operation:          original.Operation,
		Key:                original.Key,
		RequestURI:         original.RequestURI,
		HttpStatus:         original.HttpStatus,
		ErrorCode:          original.ErrorCode,
		BytesSent:          original.BytesSent,
		ObjectSize:         original.ObjectSize,
		TotalTime:          original.TotalTime,
		TurnAroundTime:     original.TurnAroundTime,
		Referer:            original.Referer,
		UserAgent:          original.UserAgent,
		VersionID:          original.VersionID,
		HostID:             original.HostID,
		SignatureVersion:   original.SignatureVersion,
		CipherSuite:        original.CipherSuite,
		AuthenticationType: original.AuthenticationType,
		HostHeader:         original.HostHeader,
		TLSVersion:         original.TLSVersion,
		AccessPointARN:     original.AccessPointARN,
		AclRequired:        original.AclRequired,
		// Enhanced fields will be set separately
	}
}

// ToLogFields converts EnhancedLogFields back to original LogFields
func (e *EnhancedLogFields) ToLogFields() *LogFields {
	return &LogFields{
		BucketOwner:        e.BucketOwner,
		Bucket:             e.Bucket,
		Time:               e.Time,
		RemoteIP:           e.RemoteIP,
		Requester:          e.Requester,
		RequestID:          e.RequestID,
		Operation:          e.Operation,
		Key:                e.Key,
		RequestURI:         e.RequestURI,
		HttpStatus:         e.HttpStatus,
		ErrorCode:          e.ErrorCode,
		BytesSent:          e.BytesSent,
		ObjectSize:         e.ObjectSize,
		TotalTime:          e.TotalTime,
		TurnAroundTime:     e.TurnAroundTime,
		Referer:            e.Referer,
		UserAgent:          e.UserAgent,
		VersionID:          e.VersionID,
		HostID:             e.HostID,
		SignatureVersion:   e.SignatureVersion,
		CipherSuite:        e.CipherSuite,
		AuthenticationType: e.AuthenticationType,
		HostHeader:         e.HostHeader,
		TLSVersion:         e.TLSVersion,
		AccessPointARN:     e.AccessPointARN,
		AclRequired:        e.AclRequired,
	}
}