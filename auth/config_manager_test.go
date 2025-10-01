package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigManager_LoadConfig(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "auth_config.json")
	
	// Create mock audit logger
	auditLogger := &MockSecurityAuditLogger{}
	
	// Create config manager
	cm := NewConfigManager(auditLogger)
	
	// Test loading non-existent config (should create default)
	err = cm.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	
	// Verify config file was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatal("Config file was not created")
	}
	
	// Verify default configuration was loaded
	config := cm.GetConfig()
	if config == nil {
		t.Fatal("Config is nil")
	}
	
	if config.Version == "" {
		t.Error("Config version is empty")
	}
	
	if config.Cache == nil {
		t.Error("Cache config is nil")
	}
	
	if config.MFA == nil {
		t.Error("MFA config is nil")
	}
}

func TestConfigManager_UpdateConfig(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "auth_config.json")
	
	// Create mock audit logger
	auditLogger := &MockSecurityAuditLogger{}
	
	// Create config manager
	cm := NewConfigManager(auditLogger)
	
	// Load initial config
	err = cm.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	
	// Get initial config
	initialConfig := cm.GetConfig()
	
	// Create updated config
	updatedConfig := *initialConfig
	updatedConfig.Version = "2.0.0"
	updatedConfig.MFA.Required = !updatedConfig.MFA.Required
	
	// Update config
	err = cm.UpdateConfig(&updatedConfig)
	if err != nil {
		t.Fatalf("Failed to update config: %v", err)
	}
	
	// Verify config was updated
	currentConfig := cm.GetConfig()
	if currentConfig.Version != "2.0.0" {
		t.Errorf("Expected version 2.0.0, got %s", currentConfig.Version)
	}
	
	if currentConfig.MFA.Required == initialConfig.MFA.Required {
		t.Error("MFA required setting was not updated")
	}
	
	// Verify config was persisted to file
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}
	
	var fileConfig AuthSystemConfig
	err = json.Unmarshal(data, &fileConfig)
	if err != nil {
		t.Fatalf("Failed to parse config file: %v", err)
	}
	
	if fileConfig.Version != "2.0.0" {
		t.Errorf("Expected persisted version 2.0.0, got %s", fileConfig.Version)
	}
}

func TestConfigManager_ValidateConfig(t *testing.T) {
	// Create mock audit logger
	auditLogger := &MockSecurityAuditLogger{}
	
	// Create config manager
	cm := NewConfigManager(auditLogger)
	
	tests := []struct {
		name        string
		config      *AuthSystemConfig
		expectError bool
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name:        "valid default config",
			config:      DefaultAuthSystemConfig(),
			expectError: false,
		},
		{
			name: "invalid cache config",
			config: &AuthSystemConfig{
				Cache: &EnhancedIAMCacheConfig{
					CacheConfig: &EnhancedCacheConfig{
						MaxSize: -1, // Invalid
					},
				},
				Version: "1.0.0",
			},
			expectError: true,
		},
		{
			name: "invalid session config",
			config: &AuthSystemConfig{
				Session: &SessionConfig{
					DefaultTTL: -1 * time.Hour, // Invalid
				},
				Version: "1.0.0",
			},
			expectError: true,
		},
		{
			name: "invalid external provider config",
			config: &AuthSystemConfig{
				ExternalProviders: &ExternalProvidersConfig{
					SAML: []*SAMLConfig{
						{
							Name: "", // Invalid - empty name
						},
					},
				},
				Version: "1.0.0",
			},
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cm.ValidateConfig(tt.config)
			if tt.expectError && err == nil {
				t.Error("Expected validation error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no validation error, got: %v", err)
			}
		})
	}
}

func TestConfigManager_ConfigHistory(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "auth_config.json")
	
	// Create mock audit logger
	auditLogger := &MockSecurityAuditLogger{}
	
	// Create config manager
	cm := NewConfigManager(auditLogger)
	
	// Load initial config
	err = cm.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	
	// Check initial history
	history := cm.GetConfigHistory()
	if len(history) != 1 {
		t.Errorf("Expected 1 history entry, got %d", len(history))
	}
	
	if history[0].Source != "file_load" {
		t.Errorf("Expected source 'file_load', got %s", history[0].Source)
	}
	
	// Update config multiple times
	for i := 0; i < 3; i++ {
		config := cm.GetConfig()
		config.Version = fmt.Sprintf("1.%d.0", i+1)
		
		err = cm.UpdateConfig(config)
		if err != nil {
			t.Fatalf("Failed to update config: %v", err)
		}
	}
	
	// Check history after updates
	history = cm.GetConfigHistory()
	if len(history) != 4 { // 1 initial load + 3 updates
		t.Errorf("Expected 4 history entries, got %d", len(history))
	}
	
	// Verify last entry is an update
	lastEntry := history[len(history)-1]
	if lastEntry.Source != "api_update" {
		t.Errorf("Expected last source 'api_update', got %s", lastEntry.Source)
	}
	
	if lastEntry.NewConfig.Version != "1.3.0" {
		t.Errorf("Expected last version '1.3.0', got %s", lastEntry.NewConfig.Version)
	}
}

func TestConfigManager_ChangeCallbacks(t *testing.T) {
	// Create mock audit logger
	auditLogger := &MockSecurityAuditLogger{}
	
	// Create config manager
	cm := NewConfigManager(auditLogger)
	
	// Track callback invocations
	callbackInvoked := false
	var callbackOldConfig, callbackNewConfig *AuthSystemConfig
	
	// Register callback
	cm.RegisterChangeCallback(func(oldConfig, newConfig *AuthSystemConfig) error {
		callbackInvoked = true
		callbackOldConfig = oldConfig
		callbackNewConfig = newConfig
		return nil
	})
	
	// Update config
	config := DefaultAuthSystemConfig()
	config.Version = "2.0.0"
	
	err := cm.UpdateConfig(config)
	if err != nil {
		t.Fatalf("Failed to update config: %v", err)
	}
	
	// Verify callback was invoked
	if !callbackInvoked {
		t.Error("Callback was not invoked")
	}
	
	if callbackOldConfig == nil {
		t.Error("Callback old config is nil")
	}
	
	if callbackNewConfig == nil {
		t.Error("Callback new config is nil")
	}
	
	if callbackNewConfig.Version != "2.0.0" {
		t.Errorf("Expected callback new config version '2.0.0', got %s", callbackNewConfig.Version)
	}
}

func TestConfigManager_FileWatching(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "auth_config.json")
	
	// Create mock audit logger
	auditLogger := &MockSecurityAuditLogger{}
	
	// Create config manager
	cm := NewConfigManager(auditLogger)
	
	// Load initial config
	err = cm.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	
	// Start watching
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err = cm.StartWatching(ctx)
	if err != nil {
		t.Fatalf("Failed to start watching: %v", err)
	}
	defer cm.StopWatching()
	
	// Get initial version
	initialVersion := cm.GetConfig().Version
	
	// Modify config file externally
	config := DefaultAuthSystemConfig()
	config.Version = "external_update"
	
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}
	
	err = os.WriteFile(configPath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
	
	// Wait for file watcher to detect change and reload
	time.Sleep(200 * time.Millisecond)
	
	// Verify config was reloaded
	currentVersion := cm.GetConfig().Version
	if currentVersion == initialVersion {
		t.Error("Config was not reloaded after file change")
	}
	
	if currentVersion != "external_update" {
		t.Errorf("Expected version 'external_update', got %s", currentVersion)
	}
}

func TestValidateConfigFile(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name        string
		configData  string
		expectError bool
	}{
		{
			name: "valid config",
			configData: `{
				"version": "1.0.0",
				"mfa": {
					"required": false,
					"totp_window": 1,
					"backup_codes": 10
				}
			}`,
			expectError: false,
		},
		{
			name:        "invalid JSON",
			configData:  `{"version": "1.0.0",}`, // Trailing comma
			expectError: true,
		},
		{
			name: "invalid config values",
			configData: `{
				"version": "1.0.0",
				"session": {
					"default_ttl": -3600
				}
			}`,
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(tempDir, fmt.Sprintf("test_%s.json", tt.name))
			
			err := os.WriteFile(configPath, []byte(tt.configData), 0644)
			if err != nil {
				t.Fatalf("Failed to write test config file: %v", err)
			}
			
			errors, err := ValidateConfigFile(configPath)
			if err != nil {
				t.Fatalf("ValidateConfigFile returned error: %v", err)
			}
			
			hasErrors := len(errors) > 0
			if tt.expectError && !hasErrors {
				t.Error("Expected validation errors, got none")
			}
			if !tt.expectError && hasErrors {
				t.Errorf("Expected no validation errors, got: %v", errors)
			}
		})
	}
}

func TestGetConfigSchema(t *testing.T) {
	schema := GetConfigSchema()
	
	if schema == nil {
		t.Fatal("Schema is nil")
	}
	
	// Verify basic schema structure
	if schema["$schema"] != "http://json-schema.org/draft-07/schema#" {
		t.Error("Invalid schema version")
	}
	
	if schema["type"] != "object" {
		t.Error("Schema type should be object")
	}
	
	properties, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("Properties should be a map")
	}
	
	// Verify some key properties exist
	expectedProperties := []string{"version", "cache", "mfa", "session", "security"}
	for _, prop := range expectedProperties {
		if _, exists := properties[prop]; !exists {
			t.Errorf("Property '%s' missing from schema", prop)
		}
	}
}

// MockSecurityAuditLogger for testing
type MockSecurityAuditLogger struct {
	events []AuthEvent
}

func (m *MockSecurityAuditLogger) LogAuthenticationAttempt(event *AuthEvent) error {
	m.events = append(m.events, *event)
	return nil
}

func (m *MockSecurityAuditLogger) LogAuthorizationCheck(event *AuthzEvent) error {
	return nil
}

func (m *MockSecurityAuditLogger) LogSecurityAlert(alert *SecurityAlert) error {
	return nil
}

func (m *MockSecurityAuditLogger) LogSessionEvent(event *SessionEvent) error {
	return nil
}

func (m *MockSecurityAuditLogger) QueryAuditLogs(query *AuditQuery) ([]*AuditRecord, error) {
	return nil, nil
}

func (m *MockSecurityAuditLogger) GenerateSecurityReport(params *ReportParams) (*SecurityReport, error) {
	return nil, nil
}