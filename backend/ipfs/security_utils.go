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

package ipfs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// SecurityUtils provides utility functions for IPFS security operations
type SecurityUtils struct{}

// NewSecurityUtils creates a new SecurityUtils instance
func NewSecurityUtils() *SecurityUtils {
	return &SecurityUtils{}
}

// GenerateSecureToken generates a cryptographically secure random token
func (su *SecurityUtils) GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

// HashPassword creates a secure hash of a password
func (su *SecurityUtils) HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	// Generate salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Create hash
	hash := sha256.New()
	hash.Write([]byte(password))
	hash.Write(salt)
	
	hashedPassword := hash.Sum(nil)
	
	// Combine salt and hash
	result := append(salt, hashedPassword...)
	return hex.EncodeToString(result), nil
}

// VerifyPassword verifies a password against its hash
func (su *SecurityUtils) VerifyPassword(password, hashedPassword string) (bool, error) {
	if password == "" || hashedPassword == "" {
		return false, fmt.Errorf("password and hash cannot be empty")
	}

	// Decode the stored hash
	decoded, err := hex.DecodeString(hashedPassword)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	if len(decoded) < 32 {
		return false, fmt.Errorf("invalid hash format")
	}

	// Extract salt and hash
	salt := decoded[:32]
	storedHash := decoded[32:]

	// Compute hash of provided password
	hash := sha256.New()
	hash.Write([]byte(password))
	hash.Write(salt)
	computedHash := hash.Sum(nil)

	// Compare hashes
	if len(computedHash) != len(storedHash) {
		return false, nil
	}

	for i := range computedHash {
		if computedHash[i] != storedHash[i] {
			return false, nil
		}
	}

	return true, nil
}

// ValidateIPAddress validates if an IP address is valid
func (su *SecurityUtils) ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsPrivateIP checks if an IP address is in a private range
func (su *SecurityUtils) IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check for private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// SanitizeInput sanitizes user input to prevent injection attacks
func (su *SecurityUtils) SanitizeInput(input string) string {
	// Remove potentially dangerous characters
	dangerous := []string{
		"<script", "</script>", "javascript:", "vbscript:",
		"onload=", "onerror=", "onclick=", "onmouseover=",
		"<iframe", "</iframe>", "<object", "</object>",
		"<embed", "</embed>", "<link", "<meta",
	}

	sanitized := input
	for _, danger := range dangerous {
		sanitized = strings.ReplaceAll(strings.ToLower(sanitized), danger, "")
	}

	// Remove control characters
	sanitized = regexp.MustCompile(`[\x00-\x1f\x7f]`).ReplaceAllString(sanitized, "")

	return strings.TrimSpace(sanitized)
}

// ValidateS3Key validates an S3 key format
func (su *SecurityUtils) ValidateS3Key(key string) error {
	if key == "" {
		return fmt.Errorf("S3 key cannot be empty")
	}

	if len(key) > 1024 {
		return fmt.Errorf("S3 key too long (max 1024 characters)")
	}

	// Check for invalid characters
	invalidChars := []string{"\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07"}
	for _, char := range invalidChars {
		if strings.Contains(key, char) {
			return fmt.Errorf("S3 key contains invalid character")
		}
	}

	return nil
}

// ValidateBucketName validates a bucket name format
func (su *SecurityUtils) ValidateBucketName(bucket string) error {
	if bucket == "" {
		return fmt.Errorf("bucket name cannot be empty")
	}

	if len(bucket) < 3 || len(bucket) > 63 {
		return fmt.Errorf("bucket name must be between 3 and 63 characters")
	}

	// Check bucket name format (simplified S3 rules)
	validName := regexp.MustCompile(`^[a-z0-9][a-z0-9\-]*[a-z0-9]$`)
	if !validName.MatchString(bucket) {
		return fmt.Errorf("invalid bucket name format")
	}

	// Check for consecutive hyphens
	if strings.Contains(bucket, "--") {
		return fmt.Errorf("bucket name cannot contain consecutive hyphens")
	}

	return nil
}

// ValidateCID validates an IPFS CID format
func (su *SecurityUtils) ValidateCID(cid string) error {
	if cid == "" {
		return fmt.Errorf("CID cannot be empty")
	}

	// Basic CID validation (simplified)
	if len(cid) < 10 {
		return fmt.Errorf("CID too short")
	}

	// Check for valid CID prefixes
	validPrefixes := []string{"Qm", "baf", "bag", "bah", "bai"}
	hasValidPrefix := false
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(cid, prefix) {
			hasValidPrefix = true
			break
		}
	}

	if !hasValidPrefix {
		return fmt.Errorf("invalid CID format")
	}

	// Check for valid characters (base58 for v0, base32 for v1)
	if strings.HasPrefix(cid, "Qm") {
		// CIDv0 - base58
		validChars := regexp.MustCompile(`^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$`)
		if !validChars.MatchString(cid) {
			return fmt.Errorf("invalid characters in CIDv0")
		}
	} else {
		// CIDv1 - base32
		validChars := regexp.MustCompile(`^[a-z2-7]+$`)
		if !validChars.MatchString(cid[3:]) { // Skip prefix
			return fmt.Errorf("invalid characters in CIDv1")
		}
	}

	return nil
}

// CalculateRiskScore calculates a risk score for an operation
func (su *SecurityUtils) CalculateRiskScore(factors *RiskFactors) int {
	if factors == nil {
		return 0
	}

	score := 0

	// IP-based risk
	if !su.IsPrivateIP(factors.IPAddress) {
		score += 20 // External IP
	}

	// Time-based risk
	hour := time.Now().Hour()
	if hour < 6 || hour > 22 {
		score += 15 // Off-hours activity
	}

	// Operation-based risk
	switch factors.Operation {
	case "pin", "unpin":
		score += 10 // Pin operations are medium risk
	case "metadata:delete":
		score += 25 // Delete operations are high risk
	case "cluster:admin":
		score += 50 // Admin operations are very high risk
	}

	// User-based risk
	if factors.IsNewUser {
		score += 20
	}

	if factors.HasRecentFailures {
		score += 30
	}

	// Resource-based risk
	if factors.IsSystemResource {
		score += 40
	}

	// Frequency-based risk
	if factors.RequestFrequency > 100 {
		score += 25 // High frequency requests
	}

	// Geographic risk
	if factors.IsUnusualLocation {
		score += 35
	}

	// Ensure score is within bounds
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	return score
}

// RiskFactors contains factors used for risk calculation
type RiskFactors struct {
	IPAddress          string
	Operation          string
	IsNewUser          bool
	HasRecentFailures  bool
	IsSystemResource   bool
	RequestFrequency   int
	IsUnusualLocation  bool
	UserAgent          string
	TimeOfDay          int
}

// DetectAnomalousActivity detects potentially anomalous activity patterns
func (su *SecurityUtils) DetectAnomalousActivity(activity *ActivityPattern) []string {
	var anomalies []string

	if activity == nil {
		return anomalies
	}

	// Check for unusual request frequency
	if activity.RequestsPerMinute > 1000 {
		anomalies = append(anomalies, "extremely_high_request_frequency")
	} else if activity.RequestsPerMinute > 500 {
		anomalies = append(anomalies, "high_request_frequency")
	}

	// Check for unusual failure rate
	if activity.FailureRate > 0.5 {
		anomalies = append(anomalies, "high_failure_rate")
	}

	// Check for unusual operation patterns
	if activity.UnusualOperationRatio > 0.8 {
		anomalies = append(anomalies, "unusual_operation_pattern")
	}

	// Check for geographic anomalies
	if activity.NewLocationAccess {
		anomalies = append(anomalies, "new_location_access")
	}

	// Check for time-based anomalies
	if activity.OffHoursActivity > 0.7 {
		anomalies = append(anomalies, "excessive_off_hours_activity")
	}

	// Check for resource access patterns
	if activity.SystemResourceAccess > 0.3 {
		anomalies = append(anomalies, "unusual_system_resource_access")
	}

	return anomalies
}

// ActivityPattern represents user activity patterns for anomaly detection
type ActivityPattern struct {
	UserID                 string
	RequestsPerMinute      int
	FailureRate           float64
	UnusualOperationRatio float64
	NewLocationAccess     bool
	OffHoursActivity      float64
	SystemResourceAccess  float64
	TimeWindow            time.Duration
}

// GenerateSecurityReport generates a security report for a user
func (su *SecurityUtils) GenerateSecurityReport(userID string, metrics *SecurityMetrics) *SecurityReport {
	report := &SecurityReport{
		UserID:      userID,
		GeneratedAt: time.Now(),
		Summary:     make(map[string]interface{}),
		Recommendations: make([]string, 0),
	}

	if metrics == nil {
		report.Summary["status"] = "no_data"
		return report
	}

	// Calculate overall security score
	securityScore := 100
	
	if metrics.FailedOperations > 0 {
		failureRate := float64(metrics.FailedOperations) / float64(metrics.TotalOperations)
		if failureRate > 0.1 {
			securityScore -= 20
			report.Recommendations = append(report.Recommendations, "investigate_high_failure_rate")
		}
	}

	if metrics.RateLimitViolations > 10 {
		securityScore -= 15
		report.Recommendations = append(report.Recommendations, "review_rate_limiting_policies")
	}

	if metrics.PermissionDenials > 5 {
		securityScore -= 10
		report.Recommendations = append(report.Recommendations, "review_user_permissions")
	}

	report.Summary["security_score"] = securityScore
	report.Summary["total_operations"] = metrics.TotalOperations
	report.Summary["failure_rate"] = float64(metrics.FailedOperations) / float64(metrics.TotalOperations)
	report.Summary["encrypted_objects"] = metrics.EncryptedObjects

	// Determine security level
	if securityScore >= 90 {
		report.Summary["security_level"] = "excellent"
	} else if securityScore >= 75 {
		report.Summary["security_level"] = "good"
	} else if securityScore >= 60 {
		report.Summary["security_level"] = "fair"
	} else {
		report.Summary["security_level"] = "poor"
		report.Recommendations = append(report.Recommendations, "immediate_security_review_required")
	}

	return report
}

// SecurityReport contains a security assessment report
type SecurityReport struct {
	UserID          string                 `json:"user_id"`
	GeneratedAt     time.Time              `json:"generated_at"`
	Summary         map[string]interface{} `json:"summary"`
	Recommendations []string               `json:"recommendations"`
}

// ValidateSecurityConfiguration validates a security configuration
func (su *SecurityUtils) ValidateSecurityConfiguration(config *ComprehensiveSecurityConfig) []string {
	var issues []string

	if config == nil {
		return []string{"configuration_is_null"}
	}

	// Validate authentication settings
	if config.Authentication != nil {
		if config.Authentication.SessionTimeout <= 0 {
			issues = append(issues, "invalid_session_timeout")
		}
		if config.Authentication.MaxLoginAttempts <= 0 {
			issues = append(issues, "invalid_max_login_attempts")
		}
	}

	// Validate encryption settings
	if config.Encryption != nil && config.Encryption.Enabled {
		if config.Encryption.KeySize < 128 {
			issues = append(issues, "weak_encryption_key_size")
		}
		if config.Encryption.Algorithm == "" {
			issues = append(issues, "missing_encryption_algorithm")
		}
	}

	// Validate rate limiting settings
	if config.RateLimiting != nil && config.RateLimiting.Enabled {
		if config.RateLimiting.GlobalRateLimit <= 0 {
			issues = append(issues, "invalid_global_rate_limit")
		}
		if config.RateLimiting.WindowSize <= 0 {
			issues = append(issues, "invalid_rate_limit_window")
		}
	}

	// Validate audit logging settings
	if config.AuditLogging != nil && config.AuditLogging.Enabled {
		if config.AuditLogging.LogFile == "" {
			issues = append(issues, "missing_audit_log_file")
		}
		if config.AuditLogging.MaxLogSize <= 0 {
			issues = append(issues, "invalid_max_log_size")
		}
	}

	// Validate network security settings
	if config.Network != nil {
		if config.Network.EnableTLS && config.Network.TLSMinVersion == "" {
			issues = append(issues, "missing_tls_min_version")
		}
		if config.Network.MaxRequestSize <= 0 {
			issues = append(issues, "invalid_max_request_size")
		}
	}

	return issues
}

// SecureCompare performs a constant-time comparison of two strings
func (su *SecurityUtils) SecureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}

	return result == 0
}

// GenerateCSRFToken generates a CSRF token
func (su *SecurityUtils) GenerateCSRFToken() (string, error) {
	return su.GenerateSecureToken(32)
}

// ValidateCSRFToken validates a CSRF token
func (su *SecurityUtils) ValidateCSRFToken(provided, expected string) bool {
	return su.SecureCompare(provided, expected)
}

// GetSecurityHeaders returns recommended security headers
func (su *SecurityUtils) GetSecurityHeaders() map[string]string {
	return map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Content-Security-Policy":   "default-src 'self'",
		"X-Permitted-Cross-Domain-Policies": "none",
		"Cache-Control":             "no-cache, no-store, must-revalidate",
		"Pragma":                    "no-cache",
		"Expires":                   "0",
	}
}

// LogSecurityEvent logs a security event with proper formatting
func (su *SecurityUtils) LogSecurityEvent(eventType, userID, details string) {
	timestamp := time.Now().Format(time.RFC3339)
	fmt.Printf("[SECURITY] %s - %s - User: %s - %s\n", timestamp, eventType, userID, details)
}