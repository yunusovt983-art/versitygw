package auth

import (
	"testing"
)

func TestAdminCLI_ExecuteCommand(t *testing.T) {
	// Create mock components
	configManager := NewConfigManager(nil)
	statusMonitor := NewSystemStatusMonitor(nil, configManager)
	healthChecker := NewHealthChecker(nil)
	
	// Create CLI
	cli := NewAdminCLI(nil, configManager, statusMonitor, healthChecker)
	
	// Test help command
	err := cli.ExecuteCommand([]string{"help"})
	if err != nil {
		t.Errorf("Help command failed: %v", err)
	}
	
	// Test unknown command
	err = cli.ExecuteCommand([]string{"unknown-command"})
	if err == nil {
		t.Error("Expected error for unknown command")
	}
	
	// Test empty command
	err = cli.ExecuteCommand([]string{})
	if err != nil {
		t.Errorf("Empty command should not fail: %v", err)
	}
}

func TestAdminCLI_ConfigCommands(t *testing.T) {
	cli := NewAdminCLI(nil, nil, nil, nil)
	
	configCommands := cli.ConfigCommands()
	
	// Should have config commands
	if len(configCommands) == 0 {
		t.Error("Expected config commands to be available")
	}
	
	// Check for specific commands
	commandNames := make(map[string]bool)
	for _, cmd := range configCommands {
		commandNames[cmd.Name] = true
	}
	
	expectedCommands := []string{"config-show", "config-validate", "config-reload", "config-history"}
	for _, expected := range expectedCommands {
		if !commandNames[expected] {
			t.Errorf("Expected command %s not found", expected)
		}
	}
}

func TestAdminCLI_SystemCommands(t *testing.T) {
	cli := NewAdminCLI(nil, nil, nil, nil)
	
	systemCommands := cli.SystemCommands()
	
	// Should have system commands
	if len(systemCommands) == 0 {
		t.Error("Expected system commands to be available")
	}
	
	// Check for specific commands
	commandNames := make(map[string]bool)
	for _, cmd := range systemCommands {
		commandNames[cmd.Name] = true
	}
	
	expectedCommands := []string{"system-status", "system-report", "system-alerts"}
	for _, expected := range expectedCommands {
		if !commandNames[expected] {
			t.Errorf("Expected command %s not found", expected)
		}
	}
}

func TestAdminCLI_DiagnosticCommands(t *testing.T) {
	cli := NewAdminCLI(nil, nil, nil, nil)
	
	diagnosticCommands := cli.DiagnosticCommands()
	
	// Should have diagnostic commands
	if len(diagnosticCommands) == 0 {
		t.Error("Expected diagnostic commands to be available")
	}
	
	// Check for specific commands
	commandNames := make(map[string]bool)
	for _, cmd := range diagnosticCommands {
		commandNames[cmd.Name] = true
	}
	
	expectedCommands := []string{"health", "diag-performance", "diag-security", "diag-dependencies"}
	for _, expected := range expectedCommands {
		if !commandNames[expected] {
			t.Errorf("Expected command %s not found", expected)
		}
	}
}

func TestAdminCLI_PrintUsage(t *testing.T) {
	cli := NewAdminCLI(nil, nil, nil, nil)
	
	// This should not panic
	cli.PrintUsage()
}

func TestAdminCLI_PrintCommandHelp(t *testing.T) {
	cli := NewAdminCLI(nil, nil, nil, nil)
	
	// Test help for existing command
	cli.PrintCommandHelp("config-show")
	
	// Test help for non-existing command
	cli.PrintCommandHelp("non-existing-command")
}

func TestCLICommand_Structure(t *testing.T) {
	cli := NewAdminCLI(nil, nil, nil, nil)
	
	configCommands := cli.ConfigCommands()
	
	for _, cmd := range configCommands {
		if cmd.Name == "" {
			t.Error("Command name should not be empty")
		}
		
		if cmd.Description == "" {
			t.Error("Command description should not be empty")
		}
		
		if cmd.Usage == "" {
			t.Error("Command usage should not be empty")
		}
		
		// Handler can be nil for some commands
	}
}

func TestDefaultAdminAPIConfig(t *testing.T) {
	config := DefaultAdminAPIConfig()
	
	if config == nil {
		t.Fatal("Default config should not be nil")
	}
	
	if config.RequestTimeout <= 0 {
		t.Error("Request timeout should be positive")
	}
	
	if config.MaxRequestSize <= 0 {
		t.Error("Max request size should be positive")
	}
	
	if config.RateLimitRequests <= 0 {
		t.Error("Rate limit requests should be positive")
	}
	
	if config.RateLimitWindow <= 0 {
		t.Error("Rate limit window should be positive")
	}
}

func TestNewAdminAPI(t *testing.T) {
	// Create mock components
	configManager := NewConfigManager(nil)
	statusMonitor := NewSystemStatusMonitor(nil, configManager)
	healthChecker := NewHealthChecker(nil)
	
	// Test with nil config (should use defaults)
	api := NewAdminAPI(nil, configManager, statusMonitor, healthChecker)
	if api == nil {
		t.Fatal("Admin API should not be nil")
	}
	
	// Test with custom config
	config := &AdminAPIConfig{
		EnableAuthentication: false,
		EnableAuthorization:  false,
		EnableCORS:          false,
		EnableLogging:       false,
	}
	
	api = NewAdminAPI(config, configManager, statusMonitor, healthChecker)
	if api == nil {
		t.Fatal("Admin API should not be nil")
	}
}

// Test helper functions
func TestValidateToken(t *testing.T) {
	api := &adminAPIImpl{}
	
	// Test valid token
	if !api.validateToken("valid-token-123") {
		t.Error("Valid token should pass validation")
	}
	
	// Test invalid tokens
	if api.validateToken("") {
		t.Error("Empty token should fail validation")
	}
	
	if api.validateToken("short") {
		t.Error("Short token should fail validation")
	}
}

func TestGetUserFromToken(t *testing.T) {
	api := &adminAPIImpl{}
	
	user := api.getUserFromToken("test-token")
	if user == nil {
		t.Error("User should not be nil")
	}
	
	userMap, ok := user.(map[string]interface{})
	if !ok {
		t.Error("User should be a map")
	}
	
	if userMap["id"] == nil {
		t.Error("User should have an ID")
	}
	
	if userMap["roles"] == nil {
		t.Error("User should have roles")
	}
}

func TestUserHasRole(t *testing.T) {
	api := &adminAPIImpl{}
	
	user := map[string]interface{}{
		"id":    "test-user",
		"roles": []string{"admin", "user"},
	}
	
	// Test existing role
	if !api.userHasRole(user, "admin") {
		t.Error("User should have admin role")
	}
	
	if !api.userHasRole(user, "user") {
		t.Error("User should have user role")
	}
	
	// Test non-existing role
	if api.userHasRole(user, "superuser") {
		t.Error("User should not have superuser role")
	}
	
	// Test with invalid user
	if api.userHasRole(nil, "admin") {
		t.Error("Nil user should not have any role")
	}
	
	if api.userHasRole("invalid", "admin") {
		t.Error("Invalid user should not have any role")
	}
}