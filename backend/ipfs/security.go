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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3log"
)

// IPFSSecurityManager manages security aspects of IPFS operations
type IPFSSecurityManager struct {
	iamService      auth.IAMService
	roleManager     auth.RoleManager
	auditLogger     *s3log.SecurityEventLogger
	rateLimiter     *RateLimiter
	encryptionKey   []byte
	config          *SecurityConfig
	mu              sync.RWMutex
}

// SecurityConfig contains security configuration for IPFS backend
type SecurityConfig struct {
	// Encryption settings
	EnableClientSideEncryption bool   `json:"enable_client_side_encryption"`
	EncryptionAlgorithm       string `json:"encryption_algorithm"`
	KeyDerivationRounds       int    `json:"key_derivation_rounds"`
	
	// Rate limiting settings
	EnableRateLimiting        bool          `json:"enable_rate_limiting"`
	PinRateLimit             int           `json:"pin_rate_limit"`           // pins per minute per user
	UnpinRateLimit           int           `json:"unpin_rate_limit"`         // unpins per minute per user
	MetadataRateLimit        int           `json:"metadata_rate_limit"`      // metadata ops per minute per user
	RateLimitWindow          time.Duration `json:"rate_limit_window"`
	
	// Audit logging settings
	EnableAuditLogging       bool   `json:"enable_audit_logging"`
	AuditLogFile            string `json:"audit_log_file"`
	LogAllOperations        bool   `json:"log_all_operations"`
	LogFailedOperationsOnly bool   `json:"log_failed_operations_only"`
	
	// Permission settings
	EnableFineGrainedPermissions bool     `json:"enable_fine_grained_permissions"`
	DefaultPermissions          []string `json:"default_permissions"`
	AdminBypassPermissions      bool     `json:"admin_bypass_permissions"`
	
	// Security monitoring
	EnableThreatDetection    bool          `json:"enable_threat_detection"`
	SuspiciousActivityWindow time.Duration `json:"suspicious_activity_window"`
	MaxFailedAttemptsPerIP   int           `json:"max_failed_attempts_per_ip"`
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		EnableClientSideEncryption:   true,
		EncryptionAlgorithm:         "AES-256-GCM",
		KeyDerivationRounds:         100000,
		EnableRateLimiting:          true,
		PinRateLimit:               1000,
		UnpinRateLimit:             500,
		MetadataRateLimit:          2000,
		RateLimitWindow:            time.Minute,
		EnableAuditLogging:         true,
		AuditLogFile:              "/var/log/versitygw/ipfs_security.log",
		LogAllOperations:          true,
		LogFailedOperationsOnly:   false,
		EnableFineGrainedPermissions: true,
		DefaultPermissions:         []string{"ipfs:pin:read", "ipfs:metadata:read"},
		AdminBypassPermissions:     true,
		EnableThreatDetection:      true,
		SuspiciousActivityWindow:   time.Hour,
		MaxFailedAttemptsPerIP:     50,
	}
}

// NewIPFSSecurityManager creates a new IPFS security manager
func NewIPFSSecurityManager(iamService auth.IAMService, roleManager auth.RoleManager, config *SecurityConfig) (*IPFSSecurityManager, error) {
	if config == nil {
		config = DefaultSecurityConfig()
	}

	// Initialize audit logger
	auditConfig := &s3log.SecurityEventConfig{
		LogFile:         config.AuditLogFile,
		MaxEvents:       100000,
		RetentionPeriod: 90 * 24 * time.Hour,
		EnableMetrics:   true,
		MetricsInterval: 5 * time.Minute,
	}
	
	auditLogger, err := s3log.NewSecurityEventLogger(auditConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
	}

	// Initialize rate limiter
	rateLimiter := NewRateLimiter(config.RateLimitWindow)

	// Generate encryption key if encryption is enabled
	var encryptionKey []byte
	if config.EnableClientSideEncryption {
		encryptionKey = make([]byte, 32) // 256-bit key
		if _, err := rand.Read(encryptionKey); err != nil {
			return nil, fmt.Errorf("failed to generate encryption key: %w", err)
		}
	}

	return &IPFSSecurityManager{
		iamService:    iamService,
		roleManager:   roleManager,
		auditLogger:   auditLogger,
		rateLimiter:   rateLimiter,
		encryptionKey: encryptionKey,
		config:        config,
	}, nil
}

// IPFSPermission represents IPFS-specific permissions
type IPFSPermission string

const (
	// Pin operations
	IPFSPermissionPinCreate IPFSPermission = "ipfs:pin:create"
	IPFSPermissionPinRead   IPFSPermission = "ipfs:pin:read"
	IPFSPermissionPinDelete IPFSPermission = "ipfs:pin:delete"
	IPFSPermissionPinList   IPFSPermission = "ipfs:pin:list"
	
	// Metadata operations
	IPFSPermissionMetadataRead   IPFSPermission = "ipfs:metadata:read"
	IPFSPermissionMetadataWrite  IPFSPermission = "ipfs:metadata:write"
	IPFSPermissionMetadataDelete IPFSPermission = "ipfs:metadata:delete"
	
	// Cluster operations
	IPFSPermissionClusterStatus IPFSPermission = "ipfs:cluster:status"
	IPFSPermissionClusterAdmin  IPFSPermission = "ipfs:cluster:admin"
	
	// Replication operations
	IPFSPermissionReplicationManage IPFSPermission = "ipfs:replication:manage"
	IPFSPermissionReplicationView   IPFSPermission = "ipfs:replication:view"
)

// SecurityContext contains security information for an operation
type SecurityContext struct {
	UserID      string
	Account     auth.Account
	IPAddress   string
	UserAgent   string
	RequestID   string
	Operation   string
	Resource    string
	Timestamp   time.Time
	IsRoot      bool
	Permissions []IPFSPermission
}

// ValidateAccess validates access for an IPFS operation
func (sm *IPFSSecurityManager) ValidateAccess(ctx context.Context, secCtx *SecurityContext, permission IPFSPermission) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Check rate limiting first
	if sm.config.EnableRateLimiting {
		if err := sm.checkRateLimit(secCtx, permission); err != nil {
			sm.logSecurityEvent(secCtx, "rate_limit_exceeded", false, err)
			return err
		}
	}

	// Root user bypass
	if secCtx.IsRoot {
		sm.logSecurityEvent(secCtx, "access_granted_root", true, nil)
		return nil
	}

	// Admin bypass if configured
	if sm.config.AdminBypassPermissions && secCtx.Account.Role == auth.RoleAdmin {
		sm.logSecurityEvent(secCtx, "access_granted_admin", true, nil)
		return nil
	}

	// Check fine-grained permissions if enabled
	if sm.config.EnableFineGrainedPermissions && sm.roleManager != nil {
		allowed, err := sm.checkEnhancedPermissions(secCtx, permission)
		if err != nil {
			sm.logSecurityEvent(secCtx, "permission_check_error", false, err)
			return fmt.Errorf("permission check failed: %w", err)
		}
		
		if !allowed {
			sm.logSecurityEvent(secCtx, "access_denied_insufficient_permissions", false, 
				fmt.Errorf("insufficient permissions for %s", permission))
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}
	}

	// Check basic IAM permissions
	if err := sm.checkBasicPermissions(secCtx, permission); err != nil {
		sm.logSecurityEvent(secCtx, "access_denied_basic_permissions", false, err)
		return err
	}

	sm.logSecurityEvent(secCtx, "access_granted", true, nil)
	return nil
}

// EncryptData encrypts data using client-side encryption
func (sm *IPFSSecurityManager) EncryptData(data []byte, metadata map[string]string) ([]byte, map[string]string, error) {
	if !sm.config.EnableClientSideEncryption {
		return data, metadata, nil
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Add encryption metadata
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["x-ipfs-encryption"] = "AES-256-GCM"
	metadata["x-ipfs-encryption-version"] = "1.0"
	metadata["x-ipfs-key-hash"] = sm.getKeyHash()

	return ciphertext, metadata, nil
}

// DecryptData decrypts data using client-side encryption
func (sm *IPFSSecurityManager) DecryptData(data []byte, metadata map[string]string) ([]byte, error) {
	if !sm.config.EnableClientSideEncryption {
		return data, nil
	}

	// Check if data is encrypted
	if metadata["x-ipfs-encryption"] != "AES-256-GCM" {
		return data, nil // Not encrypted
	}

	// Verify key hash
	if metadata["x-ipfs-key-hash"] != sm.getKeyHash() {
		return nil, fmt.Errorf("encryption key mismatch")
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// LogPinOperation logs a pin operation for audit purposes
func (sm *IPFSSecurityManager) LogPinOperation(secCtx *SecurityContext, operation string, cid string, success bool, err error) {
	if !sm.config.EnableAuditLogging {
		return
	}

	// Skip logging successful operations if configured
	if sm.config.LogFailedOperationsOnly && success {
		return
	}

	event := &s3log.AuthorizationEvent{
		EventID:   generateEventID(),
		Timestamp: time.Now(),
		UserID:    secCtx.UserID,
		IPAddress: secCtx.IPAddress,
		UserAgent: secCtx.UserAgent,
		RequestID: secCtx.RequestID,
		Resource:  fmt.Sprintf("ipfs:cid:%s", cid),
		Action:    operation,
		Decision:  "allow",
		Context: map[string]interface{}{
			"operation": operation,
			"cid":       cid,
			"success":   success,
			"resource":  secCtx.Resource,
		},
	}

	if err != nil {
		event.Decision = "deny"
		event.Context["error"] = err.Error()
	}

	sm.auditLogger.LogAuthorizationEvent(event)
}

// LogMetadataOperation logs a metadata operation for audit purposes
func (sm *IPFSSecurityManager) LogMetadataOperation(secCtx *SecurityContext, operation string, s3Key string, success bool, err error) {
	if !sm.config.EnableAuditLogging {
		return
	}

	// Skip logging successful operations if configured
	if sm.config.LogFailedOperationsOnly && success {
		return
	}

	event := &s3log.AuthorizationEvent{
		EventID:   generateEventID(),
		Timestamp: time.Now(),
		UserID:    secCtx.UserID,
		IPAddress: secCtx.IPAddress,
		UserAgent: secCtx.UserAgent,
		RequestID: secCtx.RequestID,
		Resource:  fmt.Sprintf("ipfs:metadata:%s", s3Key),
		Action:    operation,
		Decision:  "allow",
		Context: map[string]interface{}{
			"operation": operation,
			"s3_key":    s3Key,
			"success":   success,
		},
	}

	if err != nil {
		event.Decision = "deny"
		event.Context["error"] = err.Error()
	}

	sm.auditLogger.LogMetadataOperation(event)
}

// Helper methods

func (sm *IPFSSecurityManager) checkRateLimit(secCtx *SecurityContext, permission IPFSPermission) error {
	var limit int
	
	switch {
	case strings.Contains(string(permission), "pin:create"):
		limit = sm.config.PinRateLimit
	case strings.Contains(string(permission), "pin:delete"):
		limit = sm.config.UnpinRateLimit
	case strings.Contains(string(permission), "metadata"):
		limit = sm.config.MetadataRateLimit
	default:
		limit = sm.config.MetadataRateLimit // Default limit
	}

	key := fmt.Sprintf("%s:%s", secCtx.UserID, permission)
	if !sm.rateLimiter.Allow(key, limit) {
		return fmt.Errorf("rate limit exceeded for user %s, operation %s", secCtx.UserID, permission)
	}

	return nil
}

func (sm *IPFSSecurityManager) checkEnhancedPermissions(secCtx *SecurityContext, permission IPFSPermission) (bool, error) {
	// Build resource ARN for IPFS operations
	resource := fmt.Sprintf("arn:aws:ipfs:::%s", secCtx.Resource)
	
	// Check permission using role manager
	allowed, err := sm.roleManager.CheckPermission(secCtx.UserID, resource, string(permission))
	if err != nil {
		return false, fmt.Errorf("failed to check enhanced permission: %w", err)
	}
	
	return allowed, nil
}

func (sm *IPFSSecurityManager) checkBasicPermissions(secCtx *SecurityContext, permission IPFSPermission) error {
	// Basic permission checks based on user role
	switch secCtx.Account.Role {
	case auth.RoleAdmin:
		return nil // Admin has all permissions
	case auth.RoleUserPlus:
		// UserPlus can perform most operations except admin functions
		if permission == IPFSPermissionClusterAdmin {
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}
		return nil
	case auth.RoleUser:
		// Regular users have limited permissions
		allowedPermissions := []IPFSPermission{
			IPFSPermissionPinRead,
			IPFSPermissionPinList,
			IPFSPermissionMetadataRead,
			IPFSPermissionReplicationView,
		}
		
		for _, allowed := range allowedPermissions {
			if permission == allowed {
				return nil
			}
		}
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	default:
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}
}

func (sm *IPFSSecurityManager) logSecurityEvent(secCtx *SecurityContext, eventType string, success bool, err error) {
	if !sm.config.EnableAuditLogging {
		return
	}

	event := &s3log.AuthenticationEvent{
		EventID:   generateEventID(),
		Timestamp: time.Now(),
		UserID:    secCtx.UserID,
		IPAddress: secCtx.IPAddress,
		UserAgent: secCtx.UserAgent,
		Success:   success,
		AuthMethod: "iam",
		Context: map[string]interface{}{
			"event_type": eventType,
			"operation":  secCtx.Operation,
			"resource":   secCtx.Resource,
		},
	}

	if err != nil {
		event.FailureReason = err.Error()
	}

	sm.auditLogger.LogAuthenticationEvent(event)
}

func (sm *IPFSSecurityManager) getKeyHash() string {
	hash := sha256.Sum256(sm.encryptionKey)
	return base64.StdEncoding.EncodeToString(hash[:8]) // First 8 bytes for verification
}

// GetSecurityMetrics returns security metrics
func (sm *IPFSSecurityManager) GetSecurityMetrics() (*SecurityMetrics, error) {
	if sm.auditLogger == nil {
		return &SecurityMetrics{
			Timestamp: time.Now(),
		}, nil
	}
	return sm.auditLogger.GetSecurityMetrics(nil)
}

// Shutdown gracefully shuts down the security manager
func (sm *IPFSSecurityManager) Shutdown() error {
	if sm.auditLogger != nil {
		return sm.auditLogger.Shutdown()
	}
	return nil
}

// SecurityMetrics contains security-related metrics
type SecurityMetrics struct {
	TotalOperations       int64                 `json:"total_operations"`
	SuccessfulOperations  int64                 `json:"successful_operations"`
	FailedOperations      int64                 `json:"failed_operations"`
	RateLimitViolations   int64                 `json:"rate_limit_violations"`
	PermissionDenials     int64                 `json:"permission_denials"`
	EncryptedObjects      int64                 `json:"encrypted_objects"`
	TopUsers              map[string]int64      `json:"top_users"`
	TopOperations         map[string]int64      `json:"top_operations"`
	HourlyActivity        map[string]int64      `json:"hourly_activity"`
	Timestamp             time.Time             `json:"timestamp"`
}

func generateEventID() string {
	return fmt.Sprintf("ipfs_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%1000)
}