package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ConfigManager manages dynamic configuration with hot-reload capabilities
type ConfigManager interface {
	// LoadConfig loads configuration from file
	LoadConfig(configPath string) error
	
	// ReloadConfig reloads configuration from the current file
	ReloadConfig() error
	
	// GetConfig returns the current configuration
	GetConfig() *AuthSystemConfig
	
	// UpdateConfig updates configuration and persists to file
	UpdateConfig(config *AuthSystemConfig) error
	
	// ValidateConfig validates configuration
	ValidateConfig(config *AuthSystemConfig) error
	
	// StartWatching starts watching for configuration file changes
	StartWatching(ctx context.Context) error
	
	// StopWatching stops watching for configuration file changes
	StopWatching() error
	
	// RegisterChangeCallback registers a callback for configuration changes
	RegisterChangeCallback(callback ConfigChangeCallback)
	
	// GetConfigHistory returns configuration change history
	GetConfigHistory() []*ConfigChange
}

// ConfigChangeCallback is called when configuration changes
type ConfigChangeCallback func(oldConfig, newConfig *AuthSystemConfig) error

// ConfigChange represents a configuration change event
type ConfigChange struct {
	Timestamp   time.Time                `json:"timestamp"`
	User        string                   `json:"user,omitempty"`
	Source      string                   `json:"source"`
	OldConfig   *AuthSystemConfig        `json:"old_config,omitempty"`
	NewConfig   *AuthSystemConfig        `json:"new_config"`
	Changes     map[string]interface{}   `json:"changes"`
	ValidationErrors []string            `json:"validation_errors,omitempty"`
}

// AuthSystemConfig represents the complete authentication system configuration
type AuthSystemConfig struct {
	// Cache configuration
	Cache *EnhancedIAMCacheConfig `json:"cache,omitempty"`
	
	// MFA configuration
	MFA *MFAConfig `json:"mfa,omitempty"`
	
	// Session configuration
	Session *SessionConfig `json:"session,omitempty"`
	
	// Security configuration
	Security *SecurityConfig `json:"security,omitempty"`
	
	// External providers configuration
	ExternalProviders *ExternalProvidersConfig `json:"external_providers,omitempty"`
	
	// Performance configuration
	Performance *PerformanceConfig `json:"performance,omitempty"`
	
	// Cluster configuration
	Cluster *ClusterConfig `json:"cluster,omitempty"`
	
	// Health check configuration
	HealthCheck *HealthCheckerConfig `json:"health_check,omitempty"`
	
	// Rate limiting configuration
	RateLimit *AuthRateLimitConfig `json:"rate_limit,omitempty"`
	
	// Circuit breaker configuration
	CircuitBreaker *AuthCircuitBreakerConfig `json:"circuit_breaker,omitempty"`
	
	// Graceful degradation configuration
	Degradation *DegradationConfig `json:"degradation,omitempty"`
	
	// Audit configuration
	Audit *SecurityAuditConfig `json:"audit,omitempty"`
	
	// Alert system configuration
	Alerts *AlertSystemConfig `json:"alerts,omitempty"`
	
	// Reporting configuration
	Reporting *ReportingConfig `json:"reporting,omitempty"`
	
	// Metrics configuration
	Metrics *SecurityMetricsConfig `json:"metrics,omitempty"`
	
	// Load balancer configuration
	LoadBalancer *LoadBalancerConfig `json:"load_balancer,omitempty"`
	
	// Version for configuration compatibility
	Version string `json:"version"`
	
	// Last updated timestamp
	LastUpdated time.Time `json:"last_updated"`
}

// SecurityConfig holds general security configuration
type SecurityConfig struct {
	// Enable security features
	Enabled bool `json:"enabled"`
	
	// Suspicious activity detection
	SuspiciousActivity *DetectorConfig `json:"suspicious_activity,omitempty"`
	
	// Session security monitoring
	SessionSecurity *SecurityMonitorConfig `json:"session_security,omitempty"`
	
	// Fallback configuration
	Fallback *FallbackConfig `json:"fallback,omitempty"`
}

// ExternalProvidersConfig holds configuration for external identity providers
type ExternalProvidersConfig struct {
	// SAML providers
	SAML []*SAMLConfig `json:"saml,omitempty"`
	
	// OAuth2/OIDC providers
	OAuth2 []*OAuth2Config `json:"oauth2,omitempty"`
	
	// Provider fallback configuration
	Fallback *FallbackConfig `json:"fallback,omitempty"`
}

// PerformanceConfig holds performance-related configuration
type PerformanceConfig struct {
	// Optimized middleware configuration
	Middleware *OptimizedMiddlewareConfig `json:"middleware,omitempty"`
	
	// Performance monitoring configuration
	Monitor *PerformanceMonitorConfig `json:"monitor,omitempty"`
}

// configManagerImpl implements ConfigManager
type configManagerImpl struct {
	mu              sync.RWMutex
	config          *AuthSystemConfig
	configPath      string
	watcher         *fsnotify.Watcher
	callbacks       []ConfigChangeCallback
	history         []*ConfigChange
	maxHistorySize  int
	auditLogger     SecurityAuditLogger
	watcherCtx      context.Context
	watcherCancel   context.CancelFunc
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(auditLogger SecurityAuditLogger) ConfigManager {
	return &configManagerImpl{
		config:         DefaultAuthSystemConfig(),
		callbacks:      make([]ConfigChangeCallback, 0),
		history:        make([]*ConfigChange, 0),
		maxHistorySize: 100,
		auditLogger:    auditLogger,
	}
}

// DefaultAuthSystemConfig returns a default authentication system configuration
func DefaultAuthSystemConfig() *AuthSystemConfig {
	return &AuthSystemConfig{
		Cache:             DefaultEnhancedIAMCacheConfig(),
		MFA:               DefaultMFAConfig(),
		Session:           DefaultSessionConfig(),
		Security:          DefaultSecurityConfig(),
		ExternalProviders: DefaultExternalProvidersConfig(),
		Performance:       DefaultPerformanceConfig(),
		Cluster:           DefaultClusterConfig(),
		HealthCheck:       DefaultHealthCheckerConfig(),
		RateLimit:         DefaultAuthRateLimitConfig(),
		CircuitBreaker:    DefaultAuthCircuitBreakerConfig(),
		Degradation:       DefaultDegradationConfig(),
		Audit:             DefaultSecurityAuditConfig(),
		Alerts:            DefaultAlertSystemConfig(),
		Reporting:         DefaultReportingConfig(),
		Metrics:           DefaultSecurityMetricsConfig(),
		LoadBalancer:      DefaultLoadBalancerConfig(),
		Version:           "1.0.0",
		LastUpdated:       time.Now(),
	}
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		Enabled:            true,
		SuspiciousActivity: DefaultDetectorConfig(),
		SessionSecurity:    DefaultSecurityMonitorConfig(),
		Fallback:           DefaultFallbackConfig(),
	}
}

// DefaultExternalProvidersConfig returns default external providers configuration
func DefaultExternalProvidersConfig() *ExternalProvidersConfig {
	return &ExternalProvidersConfig{
		SAML:     make([]*SAMLConfig, 0),
		OAuth2:   make([]*OAuth2Config, 0),
		Fallback: DefaultFallbackConfig(),
	}
}

// DefaultPerformanceConfig returns default performance configuration
func DefaultPerformanceConfig() *PerformanceConfig {
	return &PerformanceConfig{
		Middleware: DefaultOptimizedMiddlewareConfig(),
		Monitor:    DefaultPerformanceMonitorConfig(),
	}
}

// LoadConfig loads configuration from file
func (cm *configManagerImpl) LoadConfig(configPath string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	cm.configPath = configPath
	
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default configuration file
		if err := cm.createDefaultConfigFile(configPath); err != nil {
			return fmt.Errorf("failed to create default config file: %w", err)
		}
	}
	
	// Read configuration file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Parse configuration
	var newConfig AuthSystemConfig
	if err := json.Unmarshal(data, &newConfig); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}
	
	// Validate configuration
	if err := cm.validateConfigInternal(&newConfig); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	// Store old config for change tracking
	oldConfig := cm.config
	
	// Update configuration
	cm.config = &newConfig
	cm.config.LastUpdated = time.Now()
	
	// Record configuration change
	change := &ConfigChange{
		Timestamp: time.Now(),
		Source:    "file_load",
		OldConfig: oldConfig,
		NewConfig: cm.config,
		Changes:   cm.calculateChanges(oldConfig, cm.config),
	}
	cm.addToHistory(change)
	
	// Log configuration load
	if cm.auditLogger != nil {
		cm.auditLogger.LogAuthenticationAttempt(&AuthEvent{
			Action:    "config_loaded",
			Success:   true,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"config_path": configPath,
				"version":     newConfig.Version,
			},
		})
	}
	
	return nil
}

// ReloadConfig reloads configuration from the current file
func (cm *configManagerImpl) ReloadConfig() error {
	cm.mu.RLock()
	configPath := cm.configPath
	cm.mu.RUnlock()
	
	if configPath == "" {
		return fmt.Errorf("no configuration file loaded")
	}
	
	return cm.LoadConfig(configPath)
}

// GetConfig returns the current configuration
func (cm *configManagerImpl) GetConfig() *AuthSystemConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	// Return a deep copy to prevent external modifications
	configCopy := *cm.config
	return &configCopy
}

// UpdateConfig updates configuration and persists to file
func (cm *configManagerImpl) UpdateConfig(config *AuthSystemConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	// Validate configuration
	if err := cm.ValidateConfig(config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Store old config for change tracking
	oldConfig := cm.config
	
	// Update timestamp and version
	config.LastUpdated = time.Now()
	if config.Version == "" {
		config.Version = "1.0.0"
	}
	
	// Update configuration
	cm.config = config
	
	// Persist to file if we have a config path
	if cm.configPath != "" {
		if err := cm.persistConfig(); err != nil {
			// Rollback on persistence failure
			cm.config = oldConfig
			return fmt.Errorf("failed to persist configuration: %w", err)
		}
	}
	
	// Record configuration change
	change := &ConfigChange{
		Timestamp: time.Now(),
		Source:    "api_update",
		OldConfig: oldConfig,
		NewConfig: cm.config,
		Changes:   cm.calculateChanges(oldConfig, cm.config),
	}
	cm.addToHistory(change)
	
	// Notify callbacks
	for _, callback := range cm.callbacks {
		if err := callback(oldConfig, cm.config); err != nil {
			// Log callback error but don't fail the update
			if cm.auditLogger != nil {
				cm.auditLogger.LogAuthenticationAttempt(&AuthEvent{
					Action:    "config_callback_error",
					Success:   false,
					Timestamp: time.Now(),
					Details: map[string]interface{}{
						"error": err.Error(),
					},
				})
			}
		}
	}
	
	// Log configuration update
	if cm.auditLogger != nil {
		cm.auditLogger.LogAuthenticationAttempt(&AuthEvent{
			Action:    "config_updated",
			Success:   true,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"version": config.Version,
				"changes": len(change.Changes),
			},
		})
	}
	
	return nil
}

// ValidateConfig validates configuration
func (cm *configManagerImpl) ValidateConfig(config *AuthSystemConfig) error {
	return cm.validateConfigInternal(config)
}

// validateConfigInternal performs internal configuration validation
func (cm *configManagerImpl) validateConfigInternal(config *AuthSystemConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	var errors []string
	
	// Validate cache configuration
	if config.Cache != nil {
		if err := cm.validateCacheConfig(config.Cache); err != nil {
			errors = append(errors, fmt.Sprintf("cache config: %v", err))
		}
	}
	
	// Validate MFA configuration
	if config.MFA != nil {
		if err := config.MFA.Validate(); err != nil {
			errors = append(errors, fmt.Sprintf("mfa config: %v", err))
		}
	}
	
	// Validate session configuration
	if config.Session != nil {
		if err := cm.validateSessionConfig(config.Session); err != nil {
			errors = append(errors, fmt.Sprintf("session config: %v", err))
		}
	}
	
	// Validate external providers configuration
	if config.ExternalProviders != nil {
		if err := cm.validateExternalProvidersConfig(config.ExternalProviders); err != nil {
			errors = append(errors, fmt.Sprintf("external providers config: %v", err))
		}
	}
	
	// Validate cluster configuration
	if config.Cluster != nil {
		if err := cm.validateClusterConfig(config.Cluster); err != nil {
			errors = append(errors, fmt.Sprintf("cluster config: %v", err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %v", errors)
	}
	
	return nil
}

// validateCacheConfig validates cache configuration
func (cm *configManagerImpl) validateCacheConfig(config *EnhancedIAMCacheConfig) error {
	if config.CacheConfig != nil {
		if config.CacheConfig.MaxSize <= 0 {
			return fmt.Errorf("cache max size must be positive")
		}
		if config.CacheConfig.CleanupInterval <= 0 {
			return fmt.Errorf("cache cleanup interval must be positive")
		}
	}
	return nil
}

// validateSessionConfig validates session configuration
func (cm *configManagerImpl) validateSessionConfig(config *SessionConfig) error {
	if config.DefaultTTL <= 0 {
		return fmt.Errorf("session default TTL must be positive")
	}
	if config.MaxConcurrentSessions < 0 {
		return fmt.Errorf("max concurrent sessions cannot be negative")
	}
	return nil
}

// validateExternalProvidersConfig validates external providers configuration
func (cm *configManagerImpl) validateExternalProvidersConfig(config *ExternalProvidersConfig) error {
	// Validate SAML providers
	for i, samlConfig := range config.SAML {
		if samlConfig.Name == "" {
			return fmt.Errorf("SAML provider %d: name is required", i)
		}
		if samlConfig.EntityID == "" {
			return fmt.Errorf("SAML provider %d: entity ID is required", i)
		}
	}
	
	// Validate OAuth2 providers
	for i, oauth2Config := range config.OAuth2 {
		if err := validateOAuth2Config(oauth2Config); err != nil {
			return fmt.Errorf("OAuth2 provider %d: %v", i, err)
		}
	}
	
	return nil
}

// validateClusterConfig validates cluster configuration
func (cm *configManagerImpl) validateClusterConfig(config *ClusterConfig) error {
	if config.NodeID == "" {
		return fmt.Errorf("node ID is required")
	}
	if config.ListenAddress == "" {
		return fmt.Errorf("listen address is required")
	}
	return nil
}

// StartWatching starts watching for configuration file changes
func (cm *configManagerImpl) StartWatching(ctx context.Context) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if cm.configPath == "" {
		return fmt.Errorf("no configuration file to watch")
	}
	
	if cm.watcher != nil {
		return fmt.Errorf("already watching configuration file")
	}
	
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	
	// Watch the configuration file directory
	configDir := filepath.Dir(cm.configPath)
	if err := watcher.Add(configDir); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to watch config directory: %w", err)
	}
	
	cm.watcher = watcher
	cm.watcherCtx, cm.watcherCancel = context.WithCancel(ctx)
	
	// Start watching in a goroutine
	go cm.watchConfigFile()
	
	return nil
}

// StopWatching stops watching for configuration file changes
func (cm *configManagerImpl) StopWatching() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if cm.watcher == nil {
		return nil
	}
	
	// Cancel the watcher context
	if cm.watcherCancel != nil {
		cm.watcherCancel()
	}
	
	// Close the watcher
	err := cm.watcher.Close()
	cm.watcher = nil
	cm.watcherCancel = nil
	
	return err
}

// watchConfigFile watches for configuration file changes
func (cm *configManagerImpl) watchConfigFile() {
	configFileName := filepath.Base(cm.configPath)
	
	for {
		select {
		case <-cm.watcherCtx.Done():
			return
		case event, ok := <-cm.watcher.Events:
			if !ok {
				return
			}
			
			// Check if the event is for our config file
			if filepath.Base(event.Name) != configFileName {
				continue
			}
			
			// Handle write events (file modifications)
			if event.Op&fsnotify.Write == fsnotify.Write {
				// Add a small delay to ensure the file write is complete
				time.Sleep(100 * time.Millisecond)
				
				if err := cm.ReloadConfig(); err != nil {
					// Log reload error
					if cm.auditLogger != nil {
						cm.auditLogger.LogAuthenticationAttempt(&AuthEvent{
							Action:    "config_reload_error",
							Success:   false,
							Timestamp: time.Now(),
							Details: map[string]interface{}{
								"error": err.Error(),
								"file":  event.Name,
							},
						})
					}
				}
			}
		case err, ok := <-cm.watcher.Errors:
			if !ok {
				return
			}
			
			// Log watcher error
			if cm.auditLogger != nil {
				cm.auditLogger.LogAuthenticationAttempt(&AuthEvent{
					Action:    "config_watcher_error",
					Success:   false,
					Timestamp: time.Now(),
					Details: map[string]interface{}{
						"error": err.Error(),
					},
				})
			}
		}
	}
}

// RegisterChangeCallback registers a callback for configuration changes
func (cm *configManagerImpl) RegisterChangeCallback(callback ConfigChangeCallback) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	cm.callbacks = append(cm.callbacks, callback)
}

// GetConfigHistory returns configuration change history
func (cm *configManagerImpl) GetConfigHistory() []*ConfigChange {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	// Return a copy of the history
	history := make([]*ConfigChange, len(cm.history))
	copy(history, cm.history)
	return history
}

// createDefaultConfigFile creates a default configuration file
func (cm *configManagerImpl) createDefaultConfigFile(configPath string) error {
	// Ensure directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// Create default configuration
	defaultConfig := DefaultAuthSystemConfig()
	
	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal default config: %w", err)
	}
	
	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write default config file: %w", err)
	}
	
	return nil
}

// persistConfig persists the current configuration to file
func (cm *configManagerImpl) persistConfig() error {
	// Marshal configuration to JSON with indentation
	data, err := json.MarshalIndent(cm.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	// Write to temporary file first
	tempPath := cm.configPath + ".tmp"
	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp config file: %w", err)
	}
	
	// Atomic rename
	if err := os.Rename(tempPath, cm.configPath); err != nil {
		os.Remove(tempPath) // Clean up temp file
		return fmt.Errorf("failed to rename temp config file: %w", err)
	}
	
	return nil
}

// addToHistory adds a configuration change to history
func (cm *configManagerImpl) addToHistory(change *ConfigChange) {
	cm.history = append(cm.history, change)
	
	// Trim history if it exceeds max size
	if len(cm.history) > cm.maxHistorySize {
		cm.history = cm.history[len(cm.history)-cm.maxHistorySize:]
	}
}

// calculateChanges calculates the differences between two configurations
func (cm *configManagerImpl) calculateChanges(oldConfig, newConfig *AuthSystemConfig) map[string]interface{} {
	changes := make(map[string]interface{})
	
	if oldConfig == nil {
		changes["initial_config"] = true
		return changes
	}
	
	// Compare major configuration sections
	if !cm.compareConfigs(oldConfig.Cache, newConfig.Cache) {
		changes["cache"] = "modified"
	}
	
	if !cm.compareConfigs(oldConfig.MFA, newConfig.MFA) {
		changes["mfa"] = "modified"
	}
	
	if !cm.compareConfigs(oldConfig.Session, newConfig.Session) {
		changes["session"] = "modified"
	}
	
	if !cm.compareConfigs(oldConfig.Security, newConfig.Security) {
		changes["security"] = "modified"
	}
	
	if !cm.compareConfigs(oldConfig.ExternalProviders, newConfig.ExternalProviders) {
		changes["external_providers"] = "modified"
	}
	
	if !cm.compareConfigs(oldConfig.Performance, newConfig.Performance) {
		changes["performance"] = "modified"
	}
	
	if !cm.compareConfigs(oldConfig.Cluster, newConfig.Cluster) {
		changes["cluster"] = "modified"
	}
	
	if oldConfig.Version != newConfig.Version {
		changes["version"] = map[string]string{
			"old": oldConfig.Version,
			"new": newConfig.Version,
		}
	}
	
	return changes
}

// compareConfigs compares two configuration objects using JSON marshaling
func (cm *configManagerImpl) compareConfigs(old, new interface{}) bool {
	oldJSON, err1 := json.Marshal(old)
	newJSON, err2 := json.Marshal(new)
	
	if err1 != nil || err2 != nil {
		return false
	}
	
	return string(oldJSON) == string(newJSON)
}

// ConfigValidationError represents a configuration validation error
type ConfigValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error implements the error interface
func (e *ConfigValidationError) Error() string {
	return fmt.Sprintf("validation error in field '%s': %s", e.Field, e.Message)
}

// ValidateConfigFile validates a configuration file without loading it
func ValidateConfigFile(configPath string) ([]*ConfigValidationError, error) {
	// Read configuration file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Parse configuration
	var config AuthSystemConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return []*ConfigValidationError{
			{
				Field:   "json",
				Message: fmt.Sprintf("invalid JSON: %v", err),
			},
		}, nil
	}
	
	// Create temporary config manager for validation
	cm := NewConfigManager(nil)
	
	// Validate configuration
	if err := cm.ValidateConfig(&config); err != nil {
		return []*ConfigValidationError{
			{
				Field:   "config",
				Message: err.Error(),
			},
		}, nil
	}
	
	return nil, nil
}

// GetConfigSchema returns a JSON schema for the configuration
func GetConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type":    "object",
		"title":   "Authentication System Configuration",
		"properties": map[string]interface{}{
			"version": map[string]interface{}{
				"type":        "string",
				"description": "Configuration version",
				"default":     "1.0.0",
			},
			"cache": map[string]interface{}{
				"type":        "object",
				"description": "Cache configuration",
			},
			"mfa": map[string]interface{}{
				"type":        "object",
				"description": "Multi-factor authentication configuration",
			},
			"session": map[string]interface{}{
				"type":        "object",
				"description": "Session management configuration",
			},
			"security": map[string]interface{}{
				"type":        "object",
				"description": "Security configuration",
			},
			"external_providers": map[string]interface{}{
				"type":        "object",
				"description": "External identity providers configuration",
			},
			"performance": map[string]interface{}{
				"type":        "object",
				"description": "Performance configuration",
			},
			"cluster": map[string]interface{}{
				"type":        "object",
				"description": "Cluster configuration",
			},
		},
		"additionalProperties": false,
	}
}