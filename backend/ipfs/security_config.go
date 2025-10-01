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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SecurityConfigManager manages security configuration for IPFS backend
type SecurityConfigManager struct {
	config     *ComprehensiveSecurityConfig
	configPath string
	mu         sync.RWMutex
	watchers   []ConfigWatcher
}

// ComprehensiveSecurityConfig contains all security-related configuration
type ComprehensiveSecurityConfig struct {
	// General security settings
	Enabled                bool   `json:"enabled"`
	StrictMode            bool   `json:"strict_mode"`
	ConfigVersion         string `json:"config_version"`
	LastUpdated           string `json:"last_updated"`
	
	// Authentication and authorization
	Authentication *AuthenticationConfig `json:"authentication"`
	Authorization  *AuthorizationConfig  `json:"authorization"`
	
	// Encryption settings
	Encryption *EncryptionConfig `json:"encryption"`
	
	// Rate limiting
	RateLimiting *RateLimitingConfig `json:"rate_limiting"`
	
	// Audit logging
	AuditLogging *AuditLoggingConfig `json:"audit_logging"`
	
	// Security monitoring
	Monitoring *SecurityMonitoringConfig `json:"monitoring"`
	
	// Network security
	Network *NetworkSecurityConfig `json:"network"`
	
	// Compliance settings
	Compliance *ComplianceConfig `json:"compliance"`
}

// AuthenticationConfig contains authentication settings
type AuthenticationConfig struct {
	Enabled                bool          `json:"enabled"`
	RequireAuthentication  bool          `json:"require_authentication"`
	AllowAnonymousRead     bool          `json:"allow_anonymous_read"`
	SessionTimeout         time.Duration `json:"session_timeout"`
	MaxLoginAttempts       int           `json:"max_login_attempts"`
	LockoutDuration        time.Duration `json:"lockout_duration"`
	RequireStrongPasswords bool          `json:"require_strong_passwords"`
	EnableMFA              bool          `json:"enable_mfa"`
	MFARequired            bool          `json:"mfa_required"`
	TokenExpiration        time.Duration `json:"token_expiration"`
}

// AuthorizationConfig contains authorization settings
type AuthorizationConfig struct {
	Enabled                    bool     `json:"enabled"`
	EnableFineGrainedPermissions bool     `json:"enable_fine_grained_permissions"`
	DefaultPermissions         []string `json:"default_permissions"`
	AdminBypassPermissions     bool     `json:"admin_bypass_permissions"`
	EnableRoleInheritance      bool     `json:"enable_role_inheritance"`
	PermissionCacheTimeout     time.Duration `json:"permission_cache_timeout"`
	EnableResourceBasedAccess  bool     `json:"enable_resource_based_access"`
}

// EncryptionConfig contains encryption settings
type EncryptionConfig struct {
	Enabled                   bool   `json:"enabled"`
	Algorithm                 string `json:"algorithm"`
	KeySize                   int    `json:"key_size"`
	KeyRotationInterval       time.Duration `json:"key_rotation_interval"`
	EnableClientSideEncryption bool   `json:"enable_client_side_encryption"`
	EnableTransitEncryption   bool   `json:"enable_transit_encryption"`
	EnableAtRestEncryption    bool   `json:"enable_at_rest_encryption"`
	KeyDerivationRounds       int    `json:"key_derivation_rounds"`
	CompressionBeforeEncryption bool   `json:"compression_before_encryption"`
}

// RateLimitingConfig contains rate limiting settings
type RateLimitingConfig struct {
	Enabled                bool          `json:"enabled"`
	EnableAdaptiveLimiting bool          `json:"enable_adaptive_limiting"`
	GlobalRateLimit        int           `json:"global_rate_limit"`
	PerUserRateLimit       int           `json:"per_user_rate_limit"`
	PerIPRateLimit         int           `json:"per_ip_rate_limit"`
	WindowSize             time.Duration `json:"window_size"`
	BurstSize              int           `json:"burst_size"`
	
	// Operation-specific limits
	PinOperationLimit      int `json:"pin_operation_limit"`
	UnpinOperationLimit    int `json:"unpin_operation_limit"`
	MetadataOperationLimit int `json:"metadata_operation_limit"`
	ListOperationLimit     int `json:"list_operation_limit"`
	
	// Adaptive settings
	LoadThresholdHigh      float64 `json:"load_threshold_high"`
	LoadThresholdLow       float64 `json:"load_threshold_low"`
	AdaptiveFactorHigh     float64 `json:"adaptive_factor_high"`
	AdaptiveFactorLow      float64 `json:"adaptive_factor_low"`
}

// AuditLoggingConfig contains audit logging settings
type AuditLoggingConfig struct {
	Enabled                 bool          `json:"enabled"`
	LogFile                 string        `json:"log_file"`
	LogLevel                string        `json:"log_level"`
	MaxLogSize              int64         `json:"max_log_size"`
	MaxLogFiles             int           `json:"max_log_files"`
	LogRotationInterval     time.Duration `json:"log_rotation_interval"`
	CompressOldLogs         bool          `json:"compress_old_logs"`
	
	// What to log
	LogAllOperations        bool `json:"log_all_operations"`
	LogFailedOperationsOnly bool `json:"log_failed_operations_only"`
	LogPinOperations        bool `json:"log_pin_operations"`
	LogMetadataOperations   bool `json:"log_metadata_operations"`
	LogAuthenticationEvents bool `json:"log_authentication_events"`
	LogAuthorizationEvents  bool `json:"log_authorization_events"`
	
	// Retention settings
	RetentionPeriod         time.Duration `json:"retention_period"`
	ArchiveOldLogs          bool          `json:"archive_old_logs"`
	ArchiveLocation         string        `json:"archive_location"`
}

// SecurityMonitoringConfig contains security monitoring settings
type SecurityMonitoringConfig struct {
	Enabled                    bool          `json:"enabled"`
	EnableThreatDetection      bool          `json:"enable_threat_detection"`
	EnableAnomalyDetection     bool          `json:"enable_anomaly_detection"`
	EnableRealTimeAlerts       bool          `json:"enable_real_time_alerts"`
	
	// Thresholds
	SuspiciousActivityWindow   time.Duration `json:"suspicious_activity_window"`
	MaxFailedAttemptsPerIP     int           `json:"max_failed_attempts_per_ip"`
	MaxFailedAttemptsPerUser   int           `json:"max_failed_attempts_per_user"`
	UnusualActivityThreshold   float64       `json:"unusual_activity_threshold"`
	
	// Alerting
	AlertWebhookURL            string        `json:"alert_webhook_url"`
	AlertEmailRecipients       []string      `json:"alert_email_recipients"`
	AlertCooldownPeriod        time.Duration `json:"alert_cooldown_period"`
	
	// Metrics collection
	MetricsCollectionInterval  time.Duration `json:"metrics_collection_interval"`
	MetricsRetentionPeriod     time.Duration `json:"metrics_retention_period"`
}

// NetworkSecurityConfig contains network security settings
type NetworkSecurityConfig struct {
	EnableTLS                  bool     `json:"enable_tls"`
	TLSMinVersion              string   `json:"tls_min_version"`
	TLSCipherSuites            []string `json:"tls_cipher_suites"`
	EnableHSTS                 bool     `json:"enable_hsts"`
	HSTSMaxAge                 int      `json:"hsts_max_age"`
	
	// IP filtering
	EnableIPFiltering          bool     `json:"enable_ip_filtering"`
	AllowedIPs                 []string `json:"allowed_ips"`
	BlockedIPs                 []string `json:"blocked_ips"`
	EnableGeoBlocking          bool     `json:"enable_geo_blocking"`
	BlockedCountries           []string `json:"blocked_countries"`
	
	// Request filtering
	MaxRequestSize             int64    `json:"max_request_size"`
	MaxHeaderSize              int      `json:"max_header_size"`
	EnableRequestValidation    bool     `json:"enable_request_validation"`
	
	// CORS settings
	EnableCORS                 bool     `json:"enable_cors"`
	AllowedOrigins             []string `json:"allowed_origins"`
	AllowedMethods             []string `json:"allowed_methods"`
	AllowedHeaders             []string `json:"allowed_headers"`
	MaxAge                     int      `json:"max_age"`
}

// ComplianceConfig contains compliance-related settings
type ComplianceConfig struct {
	EnableGDPRCompliance       bool          `json:"enable_gdpr_compliance"`
	EnableHIPAACompliance      bool          `json:"enable_hipaa_compliance"`
	EnableSOX404Compliance     bool          `json:"enable_sox404_compliance"`
	DataRetentionPeriod        time.Duration `json:"data_retention_period"`
	EnableDataAnonymization    bool          `json:"enable_data_anonymization"`
	EnableRightToBeForgotten   bool          `json:"enable_right_to_be_forgotten"`
	RequireDataProcessingConsent bool        `json:"require_data_processing_consent"`
	EnableAuditTrail           bool          `json:"enable_audit_trail"`
	AuditTrailRetentionPeriod  time.Duration `json:"audit_trail_retention_period"`
}

// ConfigWatcher interface for configuration change notifications
type ConfigWatcher interface {
	OnConfigChanged(config *ComprehensiveSecurityConfig) error
}

// DefaultComprehensiveSecurityConfig returns a default comprehensive security configuration
func DefaultComprehensiveSecurityConfig() *ComprehensiveSecurityConfig {
	return &ComprehensiveSecurityConfig{
		Enabled:       true,
		StrictMode:    false,
		ConfigVersion: "1.0",
		LastUpdated:   time.Now().Format(time.RFC3339),
		
		Authentication: &AuthenticationConfig{
			Enabled:                true,
			RequireAuthentication:  true,
			AllowAnonymousRead:     false,
			SessionTimeout:         24 * time.Hour,
			MaxLoginAttempts:       5,
			LockoutDuration:        15 * time.Minute,
			RequireStrongPasswords: true,
			EnableMFA:              false,
			MFARequired:            false,
			TokenExpiration:        1 * time.Hour,
		},
		
		Authorization: &AuthorizationConfig{
			Enabled:                    true,
			EnableFineGrainedPermissions: true,
			DefaultPermissions:         []string{"ipfs:pin:read", "ipfs:metadata:read"},
			AdminBypassPermissions:     true,
			EnableRoleInheritance:      true,
			PermissionCacheTimeout:     5 * time.Minute,
			EnableResourceBasedAccess:  true,
		},
		
		Encryption: &EncryptionConfig{
			Enabled:                   true,
			Algorithm:                 "AES-256-GCM",
			KeySize:                   256,
			KeyRotationInterval:       30 * 24 * time.Hour, // 30 days
			EnableClientSideEncryption: true,
			EnableTransitEncryption:   true,
			EnableAtRestEncryption:    true,
			KeyDerivationRounds:       100000,
			CompressionBeforeEncryption: true,
		},
		
		RateLimiting: &RateLimitingConfig{
			Enabled:                true,
			EnableAdaptiveLimiting: true,
			GlobalRateLimit:        10000,
			PerUserRateLimit:       1000,
			PerIPRateLimit:         500,
			WindowSize:             time.Minute,
			BurstSize:              100,
			PinOperationLimit:      1000,
			UnpinOperationLimit:    500,
			MetadataOperationLimit: 2000,
			ListOperationLimit:     5000,
			LoadThresholdHigh:      0.8,
			LoadThresholdLow:       0.3,
			AdaptiveFactorHigh:     0.5,
			AdaptiveFactorLow:      1.5,
		},
		
		AuditLogging: &AuditLoggingConfig{
			Enabled:                 true,
			LogFile:                 "/var/log/versitygw/ipfs_security.log",
			LogLevel:                "INFO",
			MaxLogSize:              100 * 1024 * 1024, // 100MB
			MaxLogFiles:             10,
			LogRotationInterval:     24 * time.Hour,
			CompressOldLogs:         true,
			LogAllOperations:        true,
			LogFailedOperationsOnly: false,
			LogPinOperations:        true,
			LogMetadataOperations:   true,
			LogAuthenticationEvents: true,
			LogAuthorizationEvents:  true,
			RetentionPeriod:         90 * 24 * time.Hour, // 90 days
			ArchiveOldLogs:          true,
			ArchiveLocation:         "/var/log/versitygw/archive/",
		},
		
		Monitoring: &SecurityMonitoringConfig{
			Enabled:                    true,
			EnableThreatDetection:      true,
			EnableAnomalyDetection:     true,
			EnableRealTimeAlerts:       true,
			SuspiciousActivityWindow:   time.Hour,
			MaxFailedAttemptsPerIP:     50,
			MaxFailedAttemptsPerUser:   10,
			UnusualActivityThreshold:   2.0,
			AlertWebhookURL:            "",
			AlertEmailRecipients:       []string{},
			AlertCooldownPeriod:        5 * time.Minute,
			MetricsCollectionInterval:  5 * time.Minute,
			MetricsRetentionPeriod:     30 * 24 * time.Hour, // 30 days
		},
		
		Network: &NetworkSecurityConfig{
			EnableTLS:               true,
			TLSMinVersion:           "1.2",
			TLSCipherSuites:         []string{},
			EnableHSTS:              true,
			HSTSMaxAge:              31536000, // 1 year
			EnableIPFiltering:       false,
			AllowedIPs:              []string{},
			BlockedIPs:              []string{},
			EnableGeoBlocking:       false,
			BlockedCountries:        []string{},
			MaxRequestSize:          100 * 1024 * 1024, // 100MB
			MaxHeaderSize:           8192,
			EnableRequestValidation: true,
			EnableCORS:              true,
			AllowedOrigins:          []string{"*"},
			AllowedMethods:          []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:          []string{"Content-Type", "Authorization", "X-Request-ID"},
			MaxAge:                  86400,
		},
		
		Compliance: &ComplianceConfig{
			EnableGDPRCompliance:       false,
			EnableHIPAACompliance:      false,
			EnableSOX404Compliance:     false,
			DataRetentionPeriod:        7 * 365 * 24 * time.Hour, // 7 years
			EnableDataAnonymization:    false,
			EnableRightToBeForgotten:   false,
			RequireDataProcessingConsent: false,
			EnableAuditTrail:           true,
			AuditTrailRetentionPeriod:  7 * 365 * 24 * time.Hour, // 7 years
		},
	}
}

// NewSecurityConfigManager creates a new security configuration manager
func NewSecurityConfigManager(configPath string) (*SecurityConfigManager, error) {
	manager := &SecurityConfigManager{
		configPath: configPath,
		watchers:   make([]ConfigWatcher, 0),
	}

	// Load existing configuration or create default
	if err := manager.LoadConfig(); err != nil {
		// If config doesn't exist, create default
		manager.config = DefaultComprehensiveSecurityConfig()
		if err := manager.SaveConfig(); err != nil {
			return nil, fmt.Errorf("failed to save default config: %w", err)
		}
	}

	return manager, nil
}

// LoadConfig loads configuration from file
func (scm *SecurityConfigManager) LoadConfig() error {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	data, err := os.ReadFile(scm.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config ComprehensiveSecurityConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	scm.config = &config
	return nil
}

// SaveConfig saves configuration to file
func (scm *SecurityConfigManager) SaveConfig() error {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	// Update last modified timestamp
	scm.config.LastUpdated = time.Now().Format(time.RFC3339)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(scm.configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(scm.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(scm.configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// Notify watchers
	scm.notifyWatchers()

	return nil
}

// GetConfig returns a copy of the current configuration
func (scm *SecurityConfigManager) GetConfig() *ComprehensiveSecurityConfig {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	// Return a deep copy to prevent external modifications
	configJSON, _ := json.Marshal(scm.config)
	var configCopy ComprehensiveSecurityConfig
	json.Unmarshal(configJSON, &configCopy)
	
	return &configCopy
}

// UpdateConfig updates the configuration
func (scm *SecurityConfigManager) UpdateConfig(updater func(*ComprehensiveSecurityConfig) error) error {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	// Apply updates
	if err := updater(scm.config); err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	// Validate configuration
	if err := scm.validateConfig(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Save updated configuration
	scm.mu.Unlock() // Unlock before calling SaveConfig which will lock again
	err := scm.SaveConfig()
	scm.mu.Lock() // Re-lock for defer

	return err
}

// AddWatcher adds a configuration change watcher
func (scm *SecurityConfigManager) AddWatcher(watcher ConfigWatcher) {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	scm.watchers = append(scm.watchers, watcher)
}

// RemoveWatcher removes a configuration change watcher
func (scm *SecurityConfigManager) RemoveWatcher(watcher ConfigWatcher) {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	for i, w := range scm.watchers {
		if w == watcher {
			scm.watchers = append(scm.watchers[:i], scm.watchers[i+1:]...)
			break
		}
	}
}

// ValidateConfig validates the current configuration
func (scm *SecurityConfigManager) ValidateConfig() error {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	return scm.validateConfig()
}

// Helper methods

func (scm *SecurityConfigManager) validateConfig() error {
	config := scm.config

	// Validate authentication settings
	if config.Authentication != nil {
		if config.Authentication.SessionTimeout <= 0 {
			return fmt.Errorf("session timeout must be positive")
		}
		if config.Authentication.MaxLoginAttempts <= 0 {
			return fmt.Errorf("max login attempts must be positive")
		}
	}

	// Validate encryption settings
	if config.Encryption != nil && config.Encryption.Enabled {
		if config.Encryption.KeySize <= 0 {
			return fmt.Errorf("encryption key size must be positive")
		}
		if config.Encryption.Algorithm == "" {
			return fmt.Errorf("encryption algorithm must be specified")
		}
	}

	// Validate rate limiting settings
	if config.RateLimiting != nil && config.RateLimiting.Enabled {
		if config.RateLimiting.GlobalRateLimit <= 0 {
			return fmt.Errorf("global rate limit must be positive")
		}
		if config.RateLimiting.WindowSize <= 0 {
			return fmt.Errorf("rate limit window size must be positive")
		}
	}

	// Validate audit logging settings
	if config.AuditLogging != nil && config.AuditLogging.Enabled {
		if config.AuditLogging.LogFile == "" {
			return fmt.Errorf("audit log file must be specified")
		}
		if config.AuditLogging.MaxLogSize <= 0 {
			return fmt.Errorf("max log size must be positive")
		}
	}

	return nil
}

func (scm *SecurityConfigManager) notifyWatchers() {
	for _, watcher := range scm.watchers {
		go func(w ConfigWatcher) {
			if err := w.OnConfigChanged(scm.config); err != nil {
				// Log error but don't fail the config update
				fmt.Printf("Config watcher error: %v\n", err)
			}
		}(watcher)
	}
}

// ExportConfig exports configuration to a different format
func (scm *SecurityConfigManager) ExportConfig(format string) ([]byte, error) {
	config := scm.GetConfig()

	switch format {
	case "json":
		return json.MarshalIndent(config, "", "  ")
	case "yaml":
		// Would implement YAML marshaling if needed
		return nil, fmt.Errorf("YAML export not implemented")
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// ImportConfig imports configuration from data
func (scm *SecurityConfigManager) ImportConfig(data []byte, format string) error {
	var config ComprehensiveSecurityConfig

	switch format {
	case "json":
		if err := json.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to parse JSON config: %w", err)
		}
	case "yaml":
		// Would implement YAML unmarshaling if needed
		return fmt.Errorf("YAML import not implemented")
	default:
		return fmt.Errorf("unsupported import format: %s", format)
	}

	return scm.UpdateConfig(func(c *ComprehensiveSecurityConfig) error {
		*c = config
		return nil
	})
}

// GetConfigSummary returns a summary of the current configuration
func (scm *SecurityConfigManager) GetConfigSummary() map[string]interface{} {
	config := scm.GetConfig()

	return map[string]interface{}{
		"enabled":                    config.Enabled,
		"strict_mode":               config.StrictMode,
		"config_version":            config.ConfigVersion,
		"last_updated":              config.LastUpdated,
		"authentication_enabled":    config.Authentication != nil && config.Authentication.Enabled,
		"authorization_enabled":     config.Authorization != nil && config.Authorization.Enabled,
		"encryption_enabled":        config.Encryption != nil && config.Encryption.Enabled,
		"rate_limiting_enabled":     config.RateLimiting != nil && config.RateLimiting.Enabled,
		"audit_logging_enabled":     config.AuditLogging != nil && config.AuditLogging.Enabled,
		"monitoring_enabled":        config.Monitoring != nil && config.Monitoring.Enabled,
		"network_security_enabled":  config.Network != nil && config.Network.EnableTLS,
		"compliance_features":       scm.getEnabledComplianceFeatures(config.Compliance),
	}
}

func (scm *SecurityConfigManager) getEnabledComplianceFeatures(compliance *ComplianceConfig) []string {
	if compliance == nil {
		return []string{}
	}

	var features []string
	if compliance.EnableGDPRCompliance {
		features = append(features, "GDPR")
	}
	if compliance.EnableHIPAACompliance {
		features = append(features, "HIPAA")
	}
	if compliance.EnableSOX404Compliance {
		features = append(features, "SOX-404")
	}
	if compliance.EnableAuditTrail {
		features = append(features, "Audit Trail")
	}

	return features
}