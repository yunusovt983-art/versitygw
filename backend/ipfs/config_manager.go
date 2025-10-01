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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// ConfigManager manages IPFS backend configuration with hot-reload capabilities
type ConfigManager struct {
	// Configuration
	config       *IPFSConfig
	configPath   string
	configFormat ConfigFormat
	
	// Hot-reload functionality
	watcher      *fsnotify.Watcher
	reloadChan   chan struct{}
	stopChan     chan struct{}
	
	// Callbacks for configuration changes
	callbacks    []ConfigChangeCallback
	
	// Validation
	validator    *ConfigValidator
	
	// API server for dynamic configuration management
	apiServer    *ConfigAPIServer
	
	// Synchronization
	mu           sync.RWMutex
	
	// Logging
	logger       *log.Logger
	
	// Context for lifecycle management
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

// ConfigFormat represents the configuration file format
type ConfigFormat int

const (
	ConfigFormatJSON ConfigFormat = iota
	ConfigFormatYAML
	ConfigFormatTOML
)

// ConfigChangeCallback is called when configuration changes
type ConfigChangeCallback func(oldConfig, newConfig *IPFSConfig) error

// ConfigManagerOptions holds options for creating a ConfigManager
type ConfigManagerOptions struct {
	ConfigPath     string
	ConfigFormat   ConfigFormat
	EnableHotReload bool
	EnableAPI      bool
	APIPort        int
	Logger         *log.Logger
	Context        context.Context
}

// ConfigValidator validates IPFS configuration
type ConfigValidator struct {
	logger *log.Logger
}

// ConfigAPIServer provides HTTP API for configuration management
type ConfigAPIServer struct {
	configManager *ConfigManager
	server        *http.Server
	port          int
	logger        *log.Logger
}

// ConfigValidationError represents a configuration validation error
type ConfigValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e *ConfigValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s' (value: %v): %s", e.Field, e.Value, e.Message)
}

// ConfigValidationResult holds the result of configuration validation
type ConfigValidationResult struct {
	Valid  bool
	Errors []ConfigValidationError
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(opts ConfigManagerOptions) (*ConfigManager, error) {
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	
	cm := &ConfigManager{
		configPath:   opts.ConfigPath,
		configFormat: opts.ConfigFormat,
		reloadChan:   make(chan struct{}, 1),
		stopChan:     make(chan struct{}),
		callbacks:    make([]ConfigChangeCallback, 0),
		validator:    NewConfigValidator(opts.Logger),
		logger:       opts.Logger,
		ctx:          ctx,
		cancel:       cancel,
	}
	
	// Load initial configuration
	if err := cm.loadConfig(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to load initial configuration: %w", err)
	}
	
	// Set up file watcher for hot-reload
	if opts.EnableHotReload && opts.ConfigPath != "" {
		if err := cm.setupFileWatcher(); err != nil {
			cancel()
			return nil, fmt.Errorf("failed to setup file watcher: %w", err)
		}
	}
	
	// Set up API server
	if opts.EnableAPI {
		port := opts.APIPort
		if port == 0 {
			port = 8081 // Default API port
		}
		cm.apiServer = NewConfigAPIServer(cm, port, opts.Logger)
	}
	
	return cm, nil
}

// Start starts the configuration manager
func (cm *ConfigManager) Start() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Start file watcher goroutine
	if cm.watcher != nil {
		cm.wg.Add(1)
		go cm.watchConfigFile()
	}
	
	// Start API server
	if cm.apiServer != nil {
		if err := cm.apiServer.Start(); err != nil {
			return fmt.Errorf("failed to start config API server: %w", err)
		}
	}
	
	cm.logger.Println("Configuration manager started successfully")
	return nil
}

// Stop stops the configuration manager
func (cm *ConfigManager) Stop() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Signal stop
	close(cm.stopChan)
	
	// Cancel context
	if cm.cancel != nil {
		cm.cancel()
	}
	
	// Stop file watcher
	if cm.watcher != nil {
		cm.watcher.Close()
	}
	
	// Stop API server
	if cm.apiServer != nil {
		if err := cm.apiServer.Stop(); err != nil {
			cm.logger.Printf("Error stopping config API server: %v", err)
		}
	}
	
	// Wait for goroutines to finish
	cm.wg.Wait()
	
	cm.logger.Println("Configuration manager stopped")
	return nil
}

// GetConfig returns the current configuration (thread-safe)
func (cm *ConfigManager) GetConfig() *IPFSConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	// Return a deep copy to prevent external modifications
	return cm.deepCopyConfig(cm.config)
}

// UpdateConfig updates the configuration and triggers callbacks
func (cm *ConfigManager) UpdateConfig(newConfig *IPFSConfig) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Validate new configuration
	if result := cm.validator.Validate(newConfig); !result.Valid {
		return fmt.Errorf("configuration validation failed: %v", result.Errors)
	}
	
	oldConfig := cm.deepCopyConfig(cm.config)
	
	// Update configuration
	cm.config = cm.deepCopyConfig(newConfig)
	
	// Trigger callbacks
	for _, callback := range cm.callbacks {
		if err := callback(oldConfig, cm.config); err != nil {
			cm.logger.Printf("Configuration change callback error: %v", err)
		}
	}
	
	cm.logger.Println("Configuration updated successfully")
	return nil
}

// RegisterCallback registers a callback for configuration changes
func (cm *ConfigManager) RegisterCallback(callback ConfigChangeCallback) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	cm.callbacks = append(cm.callbacks, callback)
}

// ValidateConfig validates a configuration
func (cm *ConfigManager) ValidateConfig(config *IPFSConfig) *ConfigValidationResult {
	return cm.validator.Validate(config)
}

// ReloadConfig manually reloads configuration from file
func (cm *ConfigManager) ReloadConfig() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	return cm.loadConfig()
}

// SaveConfig saves the current configuration to file
func (cm *ConfigManager) SaveConfig() error {
	cm.mu.RLock()
	config := cm.deepCopyConfig(cm.config)
	configPath := cm.configPath
	configFormat := cm.configFormat
	cm.mu.RUnlock()
	
	if configPath == "" {
		return fmt.Errorf("no config path specified")
	}
	
	var data []byte
	var err error
	
	switch configFormat {
	case ConfigFormatJSON:
		data, err = json.MarshalIndent(config, "", "  ")
	case ConfigFormatYAML:
		data, err = yaml.Marshal(config)
	default:
		return fmt.Errorf("unsupported config format: %v", configFormat)
	}
	
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// Write to temporary file first, then rename (atomic operation)
	tempPath := configPath + ".tmp"
	if err := ioutil.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp config file: %w", err)
	}
	
	if err := os.Rename(tempPath, configPath); err != nil {
		os.Remove(tempPath) // Clean up temp file
		return fmt.Errorf("failed to rename temp config file: %w", err)
	}
	
	cm.logger.Printf("Configuration saved to %s", configPath)
	return nil
}

// loadConfig loads configuration from file and environment variables
func (cm *ConfigManager) loadConfig() error {
	var config *IPFSConfig
	
	// Load from file if path is specified
	if cm.configPath != "" {
		fileConfig, err := cm.loadConfigFromFile()
		if err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("failed to load config from file: %w", err)
			}
			cm.logger.Printf("Config file not found, using defaults: %s", cm.configPath)
			config = getDefaultIPFSConfig()
		} else {
			config = fileConfig
		}
	} else {
		config = getDefaultIPFSConfig()
	}
	
	// Override with environment variables
	if err := cm.loadConfigFromEnv(config); err != nil {
		return fmt.Errorf("failed to load config from environment: %w", err)
	}
	
	// Validate configuration
	if result := cm.validator.Validate(config); !result.Valid {
		return fmt.Errorf("configuration validation failed: %v", result.Errors)
	}
	
	oldConfig := cm.config
	cm.config = config
	
	// Trigger callbacks if this is a reload
	if oldConfig != nil {
		for _, callback := range cm.callbacks {
			if err := callback(oldConfig, cm.config); err != nil {
				cm.logger.Printf("Configuration change callback error: %v", err)
			}
		}
	}
	
	cm.logger.Println("Configuration loaded successfully")
	return nil
}

// loadConfigFromFile loads configuration from file
func (cm *ConfigManager) loadConfigFromFile() (*IPFSConfig, error) {
	data, err := ioutil.ReadFile(cm.configPath)
	if err != nil {
		return nil, err
	}
	
	var config IPFSConfig
	
	switch cm.configFormat {
	case ConfigFormatJSON:
		err = json.Unmarshal(data, &config)
	case ConfigFormatYAML:
		err = yaml.Unmarshal(data, &config)
	default:
		return nil, fmt.Errorf("unsupported config format: %v", cm.configFormat)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	return &config, nil
}

// loadConfigFromEnv loads configuration from environment variables
func (cm *ConfigManager) loadConfigFromEnv(config *IPFSConfig) error {
	// Cluster endpoints
	if endpoints := os.Getenv("IPFS_CLUSTER_ENDPOINTS"); endpoints != "" {
		config.ClusterEndpoints = strings.Split(endpoints, ",")
		for i, endpoint := range config.ClusterEndpoints {
			config.ClusterEndpoints[i] = strings.TrimSpace(endpoint)
		}
	}
	
	// Authentication
	if username := os.Getenv("IPFS_CLUSTER_USERNAME"); username != "" {
		config.Username = username
	}
	if password := os.Getenv("IPFS_CLUSTER_PASSWORD"); password != "" {
		config.Password = password
	}
	
	// Timeouts
	if timeout := os.Getenv("IPFS_CONNECT_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			config.ConnectTimeout = d
		}
	}
	if timeout := os.Getenv("IPFS_REQUEST_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			config.RequestTimeout = d
		}
	}
	if timeout := os.Getenv("IPFS_PIN_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			config.PinTimeout = d
		}
	}
	
	// Numeric settings
	if retries := os.Getenv("IPFS_MAX_RETRIES"); retries != "" {
		if i, err := strconv.Atoi(retries); err == nil {
			config.MaxRetries = i
		}
	}
	if pins := os.Getenv("IPFS_MAX_CONCURRENT_PINS"); pins != "" {
		if i, err := strconv.Atoi(pins); err == nil {
			config.MaxConcurrentPins = i
		}
	}
	if size := os.Getenv("IPFS_CHUNK_SIZE"); size != "" {
		if i, err := strconv.ParseInt(size, 10, 64); err == nil {
			config.ChunkSize = i
		}
	}
	
	// Replication settings
	if min := os.Getenv("IPFS_REPLICATION_MIN"); min != "" {
		if i, err := strconv.Atoi(min); err == nil {
			config.ReplicationMin = i
		}
	}
	if max := os.Getenv("IPFS_REPLICATION_MAX"); max != "" {
		if i, err := strconv.Atoi(max); err == nil {
			config.ReplicationMax = i
		}
	}
	
	// Boolean settings
	if compression := os.Getenv("IPFS_COMPRESSION_ENABLED"); compression != "" {
		if b, err := strconv.ParseBool(compression); err == nil {
			config.CompressionEnabled = b
		}
	}
	if cache := os.Getenv("IPFS_CACHE_ENABLED"); cache != "" {
		if b, err := strconv.ParseBool(cache); err == nil {
			config.CacheEnabled = b
		}
	}
	if metrics := os.Getenv("IPFS_METRICS_ENABLED"); metrics != "" {
		if b, err := strconv.ParseBool(metrics); err == nil {
			config.MetricsEnabled = b
		}
	}
	
	// Database settings
	if dbType := os.Getenv("IPFS_METADATA_DB_TYPE"); dbType != "" {
		config.MetadataDBType = dbType
	}
	if endpoints := os.Getenv("IPFS_METADATA_DB_ENDPOINTS"); endpoints != "" {
		config.MetadataDBEndpoints = strings.Split(endpoints, ",")
		for i, endpoint := range config.MetadataDBEndpoints {
			config.MetadataDBEndpoints[i] = strings.TrimSpace(endpoint)
		}
	}
	
	// Cache endpoints
	if endpoints := os.Getenv("IPFS_CACHE_ENDPOINTS"); endpoints != "" {
		config.CacheEndpoints = strings.Split(endpoints, ",")
		for i, endpoint := range config.CacheEndpoints {
			config.CacheEndpoints[i] = strings.TrimSpace(endpoint)
		}
	}
	
	// Log level
	if logLevel := os.Getenv("IPFS_LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}
	
	// Replica manager settings
	if enabled := os.Getenv("IPFS_REPLICA_MANAGER_ENABLED"); enabled != "" {
		if b, err := strconv.ParseBool(enabled); err == nil {
			config.ReplicaManagerEnabled = b
		}
	}
	
	return nil
}

// setupFileWatcher sets up file system watcher for hot-reload
func (cm *ConfigManager) setupFileWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	
	cm.watcher = watcher
	
	// Watch the config file directory
	configDir := filepath.Dir(cm.configPath)
	if err := watcher.Add(configDir); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to watch config directory: %w", err)
	}
	
	cm.logger.Printf("File watcher set up for config directory: %s", configDir)
	return nil
}

// watchConfigFile watches for configuration file changes
func (cm *ConfigManager) watchConfigFile() {
	defer cm.wg.Done()
	
	configFileName := filepath.Base(cm.configPath)
	
	for {
		select {
		case event, ok := <-cm.watcher.Events:
			if !ok {
				return
			}
			
			// Check if the event is for our config file
			if filepath.Base(event.Name) == configFileName {
				if event.Op&fsnotify.Write == fsnotify.Write {
					cm.logger.Printf("Config file modified: %s", event.Name)
					
					// Debounce rapid file changes
					select {
					case cm.reloadChan <- struct{}{}:
					default:
					}
					
					// Wait a bit and then reload
					go func() {
						time.Sleep(100 * time.Millisecond)
						select {
						case <-cm.reloadChan:
							if err := cm.ReloadConfig(); err != nil {
								cm.logger.Printf("Failed to reload config: %v", err)
							} else {
								cm.logger.Println("Configuration reloaded successfully")
							}
						default:
						}
					}()
				}
			}
			
		case err, ok := <-cm.watcher.Errors:
			if !ok {
				return
			}
			cm.logger.Printf("File watcher error: %v", err)
			
		case <-cm.stopChan:
			return
		}
	}
}

// deepCopyConfig creates a deep copy of the configuration
func (cm *ConfigManager) deepCopyConfig(config *IPFSConfig) *IPFSConfig {
	if config == nil {
		return nil
	}
	
	// Use JSON marshaling/unmarshaling for deep copy
	data, err := json.Marshal(config)
	if err != nil {
		cm.logger.Printf("Failed to marshal config for deep copy: %v", err)
		return config // Return original if copy fails
	}
	
	var copy IPFSConfig
	if err := json.Unmarshal(data, &copy); err != nil {
		cm.logger.Printf("Failed to unmarshal config for deep copy: %v", err)
		return config // Return original if copy fails
	}
	
	return &copy
}

// getDefaultIPFSConfig returns default IPFS configuration
func getDefaultIPFSConfig() *IPFSConfig {
	return &IPFSConfig{
		ClusterEndpoints:    []string{"http://localhost:9094"},
		ConnectTimeout:      30 * time.Second,
		RequestTimeout:      60 * time.Second,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
		MaxConcurrentPins:   100,
		PinTimeout:          300 * time.Second,
		ChunkSize:           1024 * 1024, // 1MB
		ReplicationMin:      1,
		ReplicationMax:      3,
		CompressionEnabled:  false,
		MetadataDBType:      "memory",
		MetadataDBEndpoints: []string{},
		CacheEndpoints:      []string{},
		CacheEnabled:        false,
		MetricsEnabled:      false,
		LogLevel:            "info",
		ReplicaManagerEnabled: false,
		AnalysisInterval:    15 * time.Minute,
		RebalancingInterval: 1 * time.Hour,
		GeographicOptimization: false,
		LoadBalancingEnabled: false,
		HotDataThreshold:    100,
		WarmDataThreshold:   50,
		ColdDataThreshold:   10,
	}
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator(logger *log.Logger) *ConfigValidator {
	return &ConfigValidator{
		logger: logger,
	}
}

// Validate validates an IPFS configuration
func (v *ConfigValidator) Validate(config *IPFSConfig) *ConfigValidationResult {
	result := &ConfigValidationResult{
		Valid:  true,
		Errors: make([]ConfigValidationError, 0),
	}
	
	// Validate cluster endpoints
	if len(config.ClusterEndpoints) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ConfigValidationError{
			Field:   "ClusterEndpoints",
			Value:   config.ClusterEndpoints,
			Message: "at least one cluster endpoint must be specified",
		})
	}
	
	// Validate timeouts
	if config.ConnectTimeout <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ConfigValidationError{
			Field:   "ConnectTimeout",
			Value:   config.ConnectTimeout,
			Message: "connect timeout must be positive",
		})
	}
	
	if config.RequestTimeout <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ConfigValidationError{
			Field:   "RequestTimeout",
			Value:   config.RequestTimeout,
			Message: "request timeout must be positive",
		})
	}
	
	if config.PinTimeout <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ConfigValidationError{
			Field:   "PinTimeout",
			Value:   config.PinTimeout,
			Message: "pin timeout must be positive",
		})
	}
	
	// Validate numeric values
	if config.MaxRetries <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ConfigValidationError{
			Field:   "MaxRetries",
			Value:   config.MaxRetries,
			Message: "max retries must be positive",
		})
	}
	
	if config.MaxConcurrentPins <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ConfigValidationError{
			Field:   "MaxConcurrentPins",
			Value:   config.MaxConcurrentPins,
			Message: "max concurrent pins must be positive",
		})
	}
	
	if config.ChunkSize <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ConfigValidationError{
			Field:   "ChunkSize",
			Value:   config.ChunkSize,
			Message: "chunk size must be positive",
		})
	}
	
	// Validate replication settings
	if config.ReplicationMin <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ConfigValidationError{
			Field:   "ReplicationMin",
			Value:   config.ReplicationMin,
			Message: "minimum replication must be positive",
		})
	}
	
	if config.ReplicationMax <= 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ConfigValidationError{
			Field:   "ReplicationMax",
			Value:   config.ReplicationMax,
			Message: "maximum replication must be positive",
		})
	}
	
	if config.ReplicationMin > config.ReplicationMax {
		result.Valid = false
		result.Errors = append(result.Errors, ConfigValidationError{
			Field:   "ReplicationMin/ReplicationMax",
			Value:   fmt.Sprintf("min=%d, max=%d", config.ReplicationMin, config.ReplicationMax),
			Message: "minimum replication cannot be greater than maximum replication",
		})
	}
	
	// Validate metadata DB type
	validDBTypes := []string{"memory", "ydb", "scylla", "postgres", "mysql"}
	validDBType := false
	for _, dbType := range validDBTypes {
		if config.MetadataDBType == dbType {
			validDBType = true
			break
		}
	}
	if !validDBType {
		result.Valid = false
		result.Errors = append(result.Errors, ConfigValidationError{
			Field:   "MetadataDBType",
			Value:   config.MetadataDBType,
			Message: fmt.Sprintf("invalid metadata DB type, must be one of: %v", validDBTypes),
		})
	}
	
	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "error", "fatal"}
	validLogLevel := false
	for _, level := range validLogLevels {
		if config.LogLevel == level {
			validLogLevel = true
			break
		}
	}
	if !validLogLevel {
		result.Valid = false
		result.Errors = append(result.Errors, ConfigValidationError{
			Field:   "LogLevel",
			Value:   config.LogLevel,
			Message: fmt.Sprintf("invalid log level, must be one of: %v", validLogLevels),
		})
	}
	
	// Validate replica manager settings
	if config.ReplicaManagerEnabled {
		if config.AnalysisInterval <= 0 {
			result.Valid = false
			result.Errors = append(result.Errors, ConfigValidationError{
				Field:   "AnalysisInterval",
				Value:   config.AnalysisInterval,
				Message: "analysis interval must be positive when replica manager is enabled",
			})
		}
		
		if config.RebalancingInterval <= 0 {
			result.Valid = false
			result.Errors = append(result.Errors, ConfigValidationError{
				Field:   "RebalancingInterval",
				Value:   config.RebalancingInterval,
				Message: "rebalancing interval must be positive when replica manager is enabled",
			})
		}
		
		if config.HotDataThreshold <= 0 {
			result.Valid = false
			result.Errors = append(result.Errors, ConfigValidationError{
				Field:   "HotDataThreshold",
				Value:   config.HotDataThreshold,
				Message: "hot data threshold must be positive when replica manager is enabled",
			})
		}
	}
	
	return result
}