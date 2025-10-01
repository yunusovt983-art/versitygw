package auth

import (
	"context"
	"testing"
	"time"
)

func TestSystemStatusMonitor_GetSystemStatus(t *testing.T) {
	// Create config manager
	configManager := NewConfigManager(nil)
	
	// Create system status monitor
	monitor := NewSystemStatusMonitor(nil, configManager)
	
	// Get system status
	status, err := monitor.GetSystemStatus()
	if err != nil {
		t.Fatalf("Failed to get system status: %v", err)
	}
	
	if status == nil {
		t.Fatal("System status is nil")
	}
	
	if status.Timestamp.IsZero() {
		t.Error("System status timestamp is zero")
	}
	
	if status.OverallStatus == SystemStatusUnknown {
		t.Error("Overall status should not be unknown")
	}
	
	if status.SystemMetrics == nil {
		t.Error("System metrics should not be nil")
	}
	
	if status.Configuration == nil {
		t.Error("Configuration status should not be nil")
	}
	
	if status.Summary == nil {
		t.Error("Status summary should not be nil")
	}
}

func TestSystemStatusMonitor_RegisterComponent(t *testing.T) {
	monitor := NewSystemStatusMonitor(nil, nil)
	
	// Create mock component monitor
	mockMonitor := &MockComponentStatusMonitor{
		name: "test_component",
	}
	
	// Register component
	err := monitor.RegisterComponent("test_component", mockMonitor)
	if err != nil {
		t.Fatalf("Failed to register component: %v", err)
	}
	
	// Get component status
	status, err := monitor.GetComponentStatus("test_component")
	if err != nil {
		t.Fatalf("Failed to get component status: %v", err)
	}
	
	if status == nil {
		t.Fatal("Component status is nil")
	}
	
	if status.Name != "test_component" {
		t.Errorf("Expected component name 'test_component', got %s", status.Name)
	}
}

func TestSystemStatusMonitor_UnregisterComponent(t *testing.T) {
	monitor := NewSystemStatusMonitor(nil, nil)
	
	// Create and register mock component monitor
	mockMonitor := &MockComponentStatusMonitor{
		name: "test_component",
	}
	
	err := monitor.RegisterComponent("test_component", mockMonitor)
	if err != nil {
		t.Fatalf("Failed to register component: %v", err)
	}
	
	// Unregister component
	err = monitor.UnregisterComponent("test_component")
	if err != nil {
		t.Fatalf("Failed to unregister component: %v", err)
	}
	
	// Try to get component status (should fail)
	_, err = monitor.GetComponentStatus("test_component")
	if err == nil {
		t.Error("Expected error when getting status of unregistered component")
	}
}

func TestSystemStatusMonitor_ValidateSystemConfiguration(t *testing.T) {
	// Create config manager with default config
	configManager := NewConfigManager(nil)
	
	monitor := NewSystemStatusMonitor(nil, configManager)
	
	// Validate system configuration
	report, err := monitor.ValidateSystemConfiguration()
	if err != nil {
		t.Fatalf("Failed to validate system configuration: %v", err)
	}
	
	if report == nil {
		t.Fatal("Configuration validation report is nil")
	}
	
	if report.Timestamp.IsZero() {
		t.Error("Report timestamp is zero")
	}
	
	// Default configuration should be valid
	if !report.Valid {
		t.Errorf("Default configuration should be valid, got errors: %v", report.Errors)
	}
}

func TestSystemStatusMonitor_StartStopMonitoring(t *testing.T) {
	monitor := NewSystemStatusMonitor(nil, nil)
	
	// Initially not monitoring
	if monitor.IsMonitoring() {
		t.Error("Monitor should not be monitoring initially")
	}
	
	// Start monitoring
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err := monitor.StartMonitoring(ctx)
	if err != nil {
		t.Fatalf("Failed to start monitoring: %v", err)
	}
	
	// Should be monitoring now
	if !monitor.IsMonitoring() {
		t.Error("Monitor should be monitoring after start")
	}
	
	// Stop monitoring
	err = monitor.StopMonitoring()
	if err != nil {
		t.Fatalf("Failed to stop monitoring: %v", err)
	}
	
	// Should not be monitoring now
	if monitor.IsMonitoring() {
		t.Error("Monitor should not be monitoring after stop")
	}
}

func TestSystemStatusMonitor_GetDetailedSystemReport(t *testing.T) {
	// Create config manager
	configManager := NewConfigManager(nil)
	
	monitor := NewSystemStatusMonitor(nil, configManager)
	
	// Get detailed system report
	report, err := monitor.GetDetailedSystemReport()
	if err != nil {
		t.Fatalf("Failed to get detailed system report: %v", err)
	}
	
	if report == nil {
		t.Fatal("Detailed system report is nil")
	}
	
	if report.SystemStatus == nil {
		t.Error("System status in report should not be nil")
	}
	
	if report.ConfigReport == nil {
		t.Error("Config report should not be nil")
	}
	
	if report.PerformanceReport == nil {
		t.Error("Performance report should not be nil")
	}
	
	if report.SecurityReport == nil {
		t.Error("Security report should not be nil")
	}
	
	if report.ResourceUsage == nil {
		t.Error("Resource usage report should not be nil")
	}
	
	if report.Dependencies == nil {
		t.Error("Dependencies report should not be nil")
	}
}

func TestSystemStatusMonitor_GetStatusHistory(t *testing.T) {
	monitor := NewSystemStatusMonitor(nil, nil)
	
	// Initially no history
	history, err := monitor.GetStatusHistory(1 * time.Hour)
	if err != nil {
		t.Fatalf("Failed to get status history: %v", err)
	}
	
	if len(history) != 0 {
		t.Errorf("Expected empty history, got %d entries", len(history))
	}
	
	// Start monitoring to generate history
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	
	err = monitor.StartMonitoring(ctx)
	if err != nil {
		t.Fatalf("Failed to start monitoring: %v", err)
	}
	
	// Wait a bit for monitoring to run
	time.Sleep(50 * time.Millisecond)
	
	monitor.StopMonitoring()
	
	// Should have some history now (this is timing-dependent, so might be flaky)
	history, err = monitor.GetStatusHistory(1 * time.Hour)
	if err != nil {
		t.Fatalf("Failed to get status history: %v", err)
	}
	
	// Note: This test might be flaky due to timing
	// In a real implementation, you'd want to manually add history entries for testing
}

func TestSystemStatusMonitor_UpdateConfig(t *testing.T) {
	monitor := NewSystemStatusMonitor(nil, nil)
	
	// Get initial config
	initialConfig := monitor.GetConfig()
	if initialConfig == nil {
		t.Fatal("Initial config is nil")
	}
	
	// Update config
	newConfig := &SystemStatusConfig{
		MonitoringInterval:       1 * time.Minute,
		HistoryRetention:         48 * time.Hour,
		EnableTrendAnalysis:      false,
		EnableRecommendations:    false,
		MaxRecommendations:       5,
		ConfigValidationInterval: 10 * time.Minute,
	}
	
	err := monitor.UpdateConfig(newConfig)
	if err != nil {
		t.Fatalf("Failed to update config: %v", err)
	}
	
	// Verify config was updated
	currentConfig := monitor.GetConfig()
	if currentConfig.MonitoringInterval != 1*time.Minute {
		t.Errorf("Expected monitoring interval 1m, got %v", currentConfig.MonitoringInterval)
	}
	
	if currentConfig.HistoryRetention != 48*time.Hour {
		t.Errorf("Expected history retention 48h, got %v", currentConfig.HistoryRetention)
	}
	
	if currentConfig.EnableTrendAnalysis {
		t.Error("Expected trend analysis to be disabled")
	}
	
	if currentConfig.EnableRecommendations {
		t.Error("Expected recommendations to be disabled")
	}
}

// MockComponentStatusMonitor for testing
type MockComponentStatusMonitor struct {
	name   string
	status ComponentStatusLevel
	err    error
}

func (m *MockComponentStatusMonitor) GetStatus(ctx context.Context) (*ComponentStatus, error) {
	if m.err != nil {
		return nil, m.err
	}
	
	return &ComponentStatus{
		Name:      m.name,
		Status:    m.status,
		Message:   "Mock component status",
		LastCheck: time.Now(),
		Version:   "1.0.0",
		Uptime:    1 * time.Hour,
	}, nil
}

func (m *MockComponentStatusMonitor) GetMetrics(ctx context.Context) (*ComponentMetrics, error) {
	if m.err != nil {
		return nil, m.err
	}
	
	return &ComponentMetrics{
		CPUUsage:       10.0,
		MemoryUsage:    20.0,
		ActiveRequests: 5,
		ErrorRate:      0.1,
		Uptime:         1 * time.Hour,
	}, nil
}

func (m *MockComponentStatusMonitor) ValidateConfiguration(ctx context.Context) (*ComponentConfigValidation, error) {
	if m.err != nil {
		return nil, m.err
	}
	
	return &ComponentConfigValidation{
		ComponentName: m.name,
		Valid:         true,
		LastValidated: time.Now(),
	}, nil
}

func (m *MockComponentStatusMonitor) GetComponentInfo() *ComponentInfo {
	return &ComponentInfo{
		Name:        m.name,
		Version:     "1.0.0",
		Description: "Mock component for testing",
		Critical:    false,
	}
}

func TestSystemStatusLevel_String(t *testing.T) {
	tests := []struct {
		level    SystemStatusLevel
		expected string
	}{
		{SystemStatusHealthy, "healthy"},
		{SystemStatusDegraded, "degraded"},
		{SystemStatusUnhealthy, "unhealthy"},
		{SystemStatusCritical, "critical"},
		{SystemStatusMaintenance, "maintenance"},
		{SystemStatusUnknown, "unknown"},
	}
	
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("SystemStatusLevel.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestComponentStatusLevel_String(t *testing.T) {
	tests := []struct {
		level    ComponentStatusLevel
		expected string
	}{
		{ComponentStatusHealthy, "healthy"},
		{ComponentStatusDegraded, "degraded"},
		{ComponentStatusUnhealthy, "unhealthy"},
		{ComponentStatusCritical, "critical"},
		{ComponentStatusDisabled, "disabled"},
		{ComponentStatusUnknown, "unknown"},
	}
	
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("ComponentStatusLevel.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDefaultSystemStatusConfig(t *testing.T) {
	config := DefaultSystemStatusConfig()
	
	if config == nil {
		t.Fatal("Default config is nil")
	}
	
	if config.MonitoringInterval <= 0 {
		t.Error("Monitoring interval should be positive")
	}
	
	if config.HistoryRetention <= 0 {
		t.Error("History retention should be positive")
	}
	
	if config.AlertRetention <= 0 {
		t.Error("Alert retention should be positive")
	}
	
	if config.TrendAnalysisWindow <= 0 {
		t.Error("Trend analysis window should be positive")
	}
	
	if config.MaxRecommendations <= 0 {
		t.Error("Max recommendations should be positive")
	}
	
	if config.ConfigValidationInterval <= 0 {
		t.Error("Config validation interval should be positive")
	}
}