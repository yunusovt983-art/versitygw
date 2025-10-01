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
	"fmt"
	"sync"
	"time"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3err"
)

// SecurityIntegration provides comprehensive security integration for IPFS operations
type SecurityIntegration struct {
	// Core security components
	securityManager *IPFSSecurityManager
	iamIntegration  *IPFSIAMIntegration
	auditLogger     *IPFSAuditLogger
	rateLimiter     *AdaptiveRateLimiter
	configManager   *SecurityConfigManager
	
	// Configuration
	config *SecurityIntegrationConfig
	
	// State management
	mu       sync.RWMutex
	started  bool
	stopChan chan bool
	wg       sync.WaitGroup
}

// SecurityIntegrationConfig contains configuration for the security integration
type SecurityIntegrationConfig struct {
	EnableSecurityManager bool `json:"enable_security_manager"`
	EnableIAMIntegration  bool `json:"enable_iam_integration"`
	EnableAuditLogging    bool `json:"enable_audit_logging"`
	EnableRateLimiting    bool `json:"enable_rate_limiting"`
	EnableConfigManager   bool `json:"enable_config_manager"`
	
	// Component configurations
	SecurityManagerConfig *SecurityConfig              `json:"security_manager_config"`
	IAMIntegrationConfig  *IAMIntegrationConfig        `json:"iam_integration_config"`
	AuditConfig          *AuditConfig                 `json:"audit_config"`
	RateLimitConfig      *RateLimitConfig             `json:"rate_limit_config"`
	ConfigPath           string                       `json:"config_path"`
}

// DefaultSecurityIntegrationConfig returns default security integration configuration
func DefaultSecurityIntegrationConfig() *SecurityIntegrationConfig {
	return &SecurityIntegrationConfig{
		EnableSecurityManager: true,
		EnableIAMIntegration:  true,
		EnableAuditLogging:    true,
		EnableRateLimiting:    true,
		EnableConfigManager:   true,
		SecurityManagerConfig: DefaultSecurityConfig(),
		IAMIntegrationConfig:  DefaultIAMIntegrationConfig(),
		AuditConfig:          DefaultAuditConfig(),
		RateLimitConfig:      DefaultRateLimitConfig(),
		ConfigPath:           "/etc/versitygw/ipfs_security.json",
	}
}

// NewSecurityIntegration creates a new security integration
func NewSecurityIntegration(
	iamService auth.IAMService,
	roleManager auth.RoleManager,
	config *SecurityIntegrationConfig,
) (*SecurityIntegration, error) {
	if config == nil {
		config = DefaultSecurityIntegrationConfig()
	}

	integration := &SecurityIntegration{
		config:   config,
		stopChan: make(chan bool, 1),
	}

	// Initialize configuration manager if enabled
	if config.EnableConfigManager {
		configManager, err := NewSecurityConfigManager(config.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create config manager: %w", err)
		}
		integration.configManager = configManager
	}

	// Initialize security manager if enabled
	if config.EnableSecurityManager {
		securityManager, err := NewIPFSSecurityManager(iamService, roleManager, config.SecurityManagerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create security manager: %w", err)
		}
		integration.securityManager = securityManager
	}

	// Initialize IAM integration if enabled
	if config.EnableIAMIntegration {
		iamIntegration, err := NewIPFSIAMIntegration(iamService, roleManager, config.IAMIntegrationConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create IAM integration: %w", err)
		}
		integration.iamIntegration = iamIntegration
	}

	// Initialize audit logger if enabled
	if config.EnableAuditLogging {
		auditLogger, err := NewIPFSAuditLogger(config.AuditConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create audit logger: %w", err)
		}
		integration.auditLogger = auditLogger
	}

	// Initialize rate limiter if enabled
	if config.EnableRateLimiting {
		rateLimiter := NewAdaptiveRateLimiter(time.Minute, config.RateLimitConfig)
		integration.rateLimiter = rateLimiter
	}

	return integration, nil
}

// Start starts the security integration
func (si *SecurityIntegration) Start() error {
	si.mu.Lock()
	defer si.mu.Unlock()

	if si.started {
		return fmt.Errorf("security integration already started")
	}

	// Start monitoring routines
	if si.rateLimiter != nil {
		si.wg.Add(1)
		go si.systemLoadMonitoringRoutine()
	}

	si.started = true
	return nil
}

// Stop stops the security integration
func (si *SecurityIntegration) Stop() error {
	si.mu.Lock()
	defer si.mu.Unlock()

	if !si.started {
		return nil
	}

	// Signal stop
	close(si.stopChan)

	// Wait for routines to finish
	si.wg.Wait()

	// Shutdown components
	if si.auditLogger != nil {
		si.auditLogger.Shutdown()
	}

	if si.securityManager != nil {
		si.securityManager.Shutdown()
	}

	if si.iamIntegration != nil {
		si.iamIntegration.Shutdown()
	}

	si.started = false
	return nil
}

// ValidatePinOperation validates a pin operation request
func (si *SecurityIntegration) ValidatePinOperation(ctx context.Context, req *PinOperationRequest) error {
	// Check rate limits first
	if si.rateLimiter != nil {
		if !si.rateLimiter.Allow(req.UserID, "pin") {
			return fmt.Errorf("rate limit exceeded for pin operations")
		}
	}

	// Validate permissions using security manager
	if si.securityManager != nil {
		secCtx := &SecurityContext{
			UserID:    req.UserID,
			Account:   req.Account,
			IPAddress: req.IPAddress,
			UserAgent: req.UserAgent,
			RequestID: req.RequestID,
			Operation: req.Operation,
			Resource:  fmt.Sprintf("ipfs:cid:%s", req.CID),
			Timestamp: time.Now(),
			IsRoot:    req.IsRoot,
		}

		var permission IPFSPermission
		switch req.Operation {
		case "pin":
			permission = IPFSPermissionPinCreate
		case "unpin":
			permission = IPFSPermissionPinDelete
		case "status":
			permission = IPFSPermissionPinRead
		case "list":
			permission = IPFSPermissionPinList
		default:
			return fmt.Errorf("unknown pin operation: %s", req.Operation)
		}

		if err := si.securityManager.ValidateAccess(ctx, secCtx, permission); err != nil {
			return err
		}
	}

	// Additional IAM checks if available
	if si.iamIntegration != nil {
		resource := fmt.Sprintf("arn:aws:ipfs:::%s/%s", req.Bucket, req.S3Key)
		allowed, err := si.iamIntegration.CheckIPFSPermission(ctx, req.UserID, resource, req.Operation)
		if err != nil {
			return fmt.Errorf("IAM permission check failed: %w", err)
		}
		if !allowed {
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}
	}

	return nil
}

// ValidateMetadataOperation validates a metadata operation request
func (si *SecurityIntegration) ValidateMetadataOperation(ctx context.Context, req *MetadataOperationRequest) error {
	// Check rate limits first
	if si.rateLimiter != nil {
		if !si.rateLimiter.Allow(req.UserID, "metadata") {
			return fmt.Errorf("rate limit exceeded for metadata operations")
		}
	}

	// Validate permissions using security manager
	if si.securityManager != nil {
		secCtx := &SecurityContext{
			UserID:    req.UserID,
			Account:   req.Account,
			IPAddress: req.IPAddress,
			UserAgent: req.UserAgent,
			RequestID: req.RequestID,
			Operation: req.Operation,
			Resource:  fmt.Sprintf("ipfs:metadata:%s/%s", req.Bucket, req.S3Key),
			Timestamp: time.Now(),
			IsRoot:    req.IsRoot,
		}

		var permission IPFSPermission
		switch req.Operation {
		case "create", "update":
			permission = IPFSPermissionMetadataWrite
		case "read":
			permission = IPFSPermissionMetadataRead
		case "delete":
			permission = IPFSPermissionMetadataDelete
		default:
			return fmt.Errorf("unknown metadata operation: %s", req.Operation)
		}

		if err := si.securityManager.ValidateAccess(ctx, secCtx, permission); err != nil {
			return err
		}
	}

	// Additional IAM checks if available
	if si.iamIntegration != nil {
		resource := fmt.Sprintf("arn:aws:ipfs:::%s/%s", req.Bucket, req.S3Key)
		allowed, err := si.iamIntegration.CheckIPFSPermission(ctx, req.UserID, resource, req.Operation)
		if err != nil {
			return fmt.Errorf("IAM permission check failed: %w", err)
		}
		if !allowed {
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}
	}

	return nil
}

// CheckRateLimit checks rate limits for a user and operation type
func (si *SecurityIntegration) CheckRateLimit(userID, operationType string) error {
	if si.rateLimiter == nil {
		return nil
	}

	if !si.rateLimiter.Allow(userID, operationType) {
		return fmt.Errorf("rate limit exceeded for user %s, operation %s", userID, operationType)
	}

	return nil
}

// EncryptData encrypts data using the security manager
func (si *SecurityIntegration) EncryptData(data []byte, metadata map[string]string) ([]byte, map[string]string, error) {
	if si.securityManager == nil {
		return data, metadata, nil
	}

	return si.securityManager.EncryptData(data, metadata)
}

// DecryptData decrypts data using the security manager
func (si *SecurityIntegration) DecryptData(data []byte, metadata map[string]string) ([]byte, error) {
	if si.securityManager == nil {
		return data, nil
	}

	return si.securityManager.DecryptData(data, metadata)
}

// LogPinOperation logs a pin operation
func (si *SecurityIntegration) LogPinOperation(req *PinOperationRequest, success bool, duration time.Duration, err error) {
	if si.auditLogger == nil {
		return
	}

	ctx := context.Background()
	var operation IPFSOperation
	switch req.Operation {
	case "pin":
		operation = IPFSOpPinAdd
	case "unpin":
		operation = IPFSOpPinRemove
	case "status":
		operation = IPFSOpPinStatus
	case "list":
		operation = IPFSOpPinList
	default:
		operation = IPFSOperation(req.Operation)
	}

	si.auditLogger.LogPinOperation(ctx, req.UserID, req.CID, req.S3Key, req.Bucket, operation, success, duration, err)

	// Also log to security manager if available
	if si.securityManager != nil {
		secCtx := &SecurityContext{
			UserID:    req.UserID,
			Account:   req.Account,
			IPAddress: req.IPAddress,
			UserAgent: req.UserAgent,
			RequestID: req.RequestID,
			Operation: req.Operation,
			Resource:  fmt.Sprintf("ipfs:cid:%s", req.CID),
			Timestamp: time.Now(),
			IsRoot:    req.IsRoot,
		}
		si.securityManager.LogPinOperation(secCtx, req.Operation, req.CID, success, err)
	}
}

// LogMetadataOperation logs a metadata operation
func (si *SecurityIntegration) LogMetadataOperation(req *MetadataOperationRequest, success bool, duration time.Duration, err error) {
	if si.auditLogger == nil {
		return
	}

	ctx := context.Background()
	var operation IPFSOperation
	switch req.Operation {
	case "create":
		operation = IPFSOpMetadataWrite
	case "read":
		operation = IPFSOpMetadataRead
	case "update":
		operation = IPFSOpMetadataWrite
	case "delete":
		operation = IPFSOpMetadataDelete
	default:
		operation = IPFSOperation(req.Operation)
	}

	si.auditLogger.LogMetadataOperation(ctx, req.UserID, req.S3Key, req.Bucket, operation, success, 0, err)

	// Also log to security manager if available
	if si.securityManager != nil {
		secCtx := &SecurityContext{
			UserID:    req.UserID,
			Account:   req.Account,
			IPAddress: req.IPAddress,
			UserAgent: req.UserAgent,
			RequestID: req.RequestID,
			Operation: req.Operation,
			Resource:  fmt.Sprintf("ipfs:metadata:%s/%s", req.Bucket, req.S3Key),
			Timestamp: time.Now(),
			IsRoot:    req.IsRoot,
		}
		si.securityManager.LogMetadataOperation(secCtx, req.Operation, req.S3Key, success, err)
	}
}

// LogSecurityEvent logs a security event
func (si *SecurityIntegration) LogSecurityEvent(ctx context.Context, userID, eventType string, riskScore int, details map[string]interface{}) {
	if si.auditLogger != nil {
		si.auditLogger.LogSecurityEvent(ctx, userID, eventType, riskScore, details)
	}
}

// GetSecurityMetrics returns comprehensive security metrics
func (si *SecurityIntegration) GetSecurityMetrics() (*ComprehensiveSecurityMetrics, error) {
	metrics := &ComprehensiveSecurityMetrics{
		Timestamp: time.Now(),
	}

	// Get audit metrics
	if si.auditLogger != nil {
		auditMetrics := si.auditLogger.GetMetrics()
		metrics.AuditMetrics = auditMetrics
	}

	// Get security manager metrics
	if si.securityManager != nil {
		securityMetrics, err := si.securityManager.GetSecurityMetrics()
		if err == nil {
			metrics.SecurityMetrics = securityMetrics
		}
	}

	// Get rate limiting metrics
	if si.rateLimiter != nil {
		metrics.RateLimitingMetrics = &RateLimitingMetrics{
			SystemLoad:      si.rateLimiter.GetSystemLoad(),
			AdaptiveFactor:  si.rateLimiter.GetAdaptiveFactor(),
			Timestamp:       time.Now(),
		}
	}

	return metrics, nil
}

// GetConfiguration returns the current security configuration
func (si *SecurityIntegration) GetConfiguration() (*ComprehensiveSecurityConfig, error) {
	if si.configManager == nil {
		return nil, fmt.Errorf("configuration manager not available")
	}

	return si.configManager.GetConfig(), nil
}

// UpdateConfiguration updates the security configuration
func (si *SecurityIntegration) UpdateConfiguration(updater func(*ComprehensiveSecurityConfig) error) error {
	if si.configManager == nil {
		return fmt.Errorf("configuration manager not available")
	}

	return si.configManager.UpdateConfig(updater)
}

// systemLoadMonitoringRoutine monitors system load and adjusts rate limits
func (si *SecurityIntegration) systemLoadMonitoringRoutine() {
	defer si.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			si.updateSystemLoad()
		case <-si.stopChan:
			return
		}
	}
}

// updateSystemLoad updates the system load for adaptive rate limiting
func (si *SecurityIntegration) updateSystemLoad() {
	// This is a simplified implementation
	// In a real system, you would collect actual system metrics
	
	// For now, we'll simulate system load based on audit metrics
	if si.auditLogger != nil && si.rateLimiter != nil {
		metrics := si.auditLogger.GetMetrics()
		
		// Calculate load based on recent activity
		// This is a simplified calculation
		totalOps := metrics.TotalEvents
		failedOps := metrics.FailedOperations
		
		var load float64
		if totalOps > 0 {
			failureRate := float64(failedOps) / float64(totalOps)
			load = failureRate * 2.0 // Scale failure rate to load
			
			// Add some randomness to simulate varying load
			if totalOps > 1000 {
				load += 0.1
			}
			if totalOps > 10000 {
				load += 0.2
			}
		}
		
		// Ensure load is within bounds
		if load > 1.0 {
			load = 1.0
		}
		if load < 0.0 {
			load = 0.0
		}
		
		si.rateLimiter.UpdateSystemLoad(load)
	}
}

// Request types for security validation

// PinOperationRequest represents a pin operation request
type PinOperationRequest struct {
	UserID    string
	Account   auth.Account
	IPAddress string
	UserAgent string
	RequestID string
	Operation string // "pin", "unpin", "status", "list"
	CID       string
	S3Key     string
	Bucket    string
	IsRoot    bool
}

// MetadataOperationRequest represents a metadata operation request
type MetadataOperationRequest struct {
	UserID    string
	Account   auth.Account
	IPAddress string
	UserAgent string
	RequestID string
	Operation string // "create", "read", "update", "delete"
	S3Key     string
	Bucket    string
	CID       string
	IsRoot    bool
}

// Metrics types

// ComprehensiveSecurityMetrics contains all security-related metrics
type ComprehensiveSecurityMetrics struct {
	AuditMetrics        *IPFSAuditMetrics     `json:"audit_metrics"`
	SecurityMetrics     *SecurityMetrics      `json:"security_metrics"`
	RateLimitingMetrics *RateLimitingMetrics  `json:"rate_limiting_metrics"`
	Timestamp           time.Time             `json:"timestamp"`
}

// RateLimitingMetrics contains rate limiting metrics
type RateLimitingMetrics struct {
	SystemLoad     float64   `json:"system_load"`
	AdaptiveFactor float64   `json:"adaptive_factor"`
	Timestamp      time.Time `json:"timestamp"`
}

// Helper functions for extracting context information

func extractIPFromContext(ctx context.Context) string {
	if ip := ctx.Value("ip_address"); ip != nil {
		if ipStr, ok := ip.(string); ok {
			return ipStr
		}
	}
	return "unknown"
}

func extractUserAgentFromContext(ctx context.Context) string {
	if ua := ctx.Value("user_agent"); ua != nil {
		if uaStr, ok := ua.(string); ok {
			return uaStr
		}
	}
	return "unknown"
}

func extractRequestIDFromContext(ctx context.Context) string {
	if rid := ctx.Value("request_id"); rid != nil {
		if ridStr, ok := rid.(string); ok {
			return ridStr
		}
	}
	return "unknown"
}