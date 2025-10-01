package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// SystemStatusMonitor provides comprehensive system status monitoring and reporting
type SystemStatusMonitor interface {
	// System status
	GetSystemStatus() (*SystemStatus, error)
	GetDetailedSystemReport() (*DetailedSystemReport, error)
	
	// Component management
	RegisterComponent(name string, monitor ComponentStatusMonitor) error
	UnregisterComponent(name string) error
	GetComponentStatus(name string) (*ComponentStatus, error)
	
	// Health integration
	SetHealthChecker(healthChecker HealthChecker) error
	
	// Configuration validation
	ValidateSystemConfiguration() (*ConfigurationValidationReport, error)
	ValidateComponentConfiguration(componentName string) (*ComponentConfigValidation, error)
	
	// Monitoring control
	StartMonitoring(ctx context.Context) error
	StopMonitoring() error
	IsMonitoring() bool
	
	// Status history and trends
	GetStatusHistory(duration time.Duration) ([]*SystemStatus, error)
	GetComponentTrends(componentName string, duration time.Duration) (*ComponentTrends, error)
	
	// Alerting and notifications
	SetStatusChangeCallback(callback StatusChangeCallback) error
	GetActiveAlerts() ([]*SystemAlert, error)
	
	// Configuration
	UpdateConfig(config *SystemStatusConfig) error
	GetConfig() *SystemStatusConfig
}

// ComponentStatusMonitor defines interface for component-specific status monitoring
type ComponentStatusMonitor interface {
	GetStatus(ctx context.Context) (*ComponentStatus, error)
	GetMetrics(ctx context.Context) (*ComponentMetrics, error)
	ValidateConfiguration(ctx context.Context) (*ComponentConfigValidation, error)
	GetComponentInfo() *ComponentInfo
}

// SystemStatus represents the overall system status
type SystemStatus struct {
	Timestamp        time.Time                    `json:"timestamp"`
	OverallStatus    SystemStatusLevel            `json:"overall_status"`
	Message          string                       `json:"message"`
	Version          string                       `json:"version"`
	Uptime           time.Duration                `json:"uptime"`
	Components       map[string]*ComponentStatus  `json:"components"`
	SystemMetrics    *SystemMetrics               `json:"system_metrics"`
	Configuration    *ConfigurationStatus         `json:"configuration"`
	Alerts           []*SystemAlert               `json:"alerts,omitempty"`
	Summary          *SystemStatusSummary         `json:"summary"`
}

// DetailedSystemReport provides comprehensive system information
type DetailedSystemReport struct {
	SystemStatus     *SystemStatus                `json:"system_status"`
	HealthReport     *SystemHealth                `json:"health_report"`
	ConfigReport     *ConfigurationValidationReport `json:"config_report"`
	PerformanceReport *PerformanceReport          `json:"performance_report"`
	SecurityReport   *SecurityStatusReport        `json:"security_report"`
	ResourceUsage    *ResourceUsageReport         `json:"resource_usage"`
	Dependencies     *DependencyReport            `json:"dependencies"`
	Recommendations  []*SystemRecommendation      `json:"recommendations,omitempty"`
}

// ComponentStatus represents the status of a system component
type ComponentStatus struct {
	Name             string                       `json:"name"`
	Status           ComponentStatusLevel         `json:"status"`
	Message          string                       `json:"message"`
	LastCheck        time.Time                    `json:"last_check"`
	Version          string                       `json:"version"`
	Uptime           time.Duration                `json:"uptime"`
	Metrics          *ComponentMetrics            `json:"metrics,omitempty"`
	Configuration    *ComponentConfigStatus       `json:"configuration,omitempty"`
	Dependencies     []string                     `json:"dependencies,omitempty"`
	Alerts           []*ComponentAlert            `json:"alerts,omitempty"`
	Details          map[string]interface{}       `json:"details,omitempty"`
}

// SystemMetrics provides system-level metrics
type SystemMetrics struct {
	CPUUsage         float64                      `json:"cpu_usage"`
	MemoryUsage      float64                      `json:"memory_usage"`
	MemoryTotal      uint64                       `json:"memory_total"`
	MemoryUsed       uint64                       `json:"memory_used"`
	GoroutineCount   int                          `json:"goroutine_count"`
	GCStats          *GCStats                     `json:"gc_stats"`
	RequestsPerSecond float64                     `json:"requests_per_second"`
	ActiveConnections int                         `json:"active_connections"`
	ErrorRate        float64                      `json:"error_rate"`
}

// GCStats provides garbage collection statistics
type GCStats struct {
	NumGC        uint32        `json:"num_gc"`
	PauseTotal   time.Duration `json:"pause_total"`
	PauseNs      []uint64      `json:"pause_ns"`
	LastGC       time.Time     `json:"last_gc"`
}

// ConfigurationStatus represents the status of system configuration
type ConfigurationStatus struct {
	Valid            bool                         `json:"valid"`
	LastValidated    time.Time                    `json:"last_validated"`
	LastModified     time.Time                    `json:"last_modified"`
	Version          string                       `json:"version"`
	Errors           []*ConfigurationError        `json:"errors,omitempty"`
	Warnings         []*ConfigurationWarning      `json:"warnings,omitempty"`
	ComponentConfigs map[string]*ComponentConfigStatus `json:"component_configs,omitempty"`
}

// ComponentConfigStatus represents component configuration status
type ComponentConfigStatus struct {
	Valid        bool                      `json:"valid"`
	LastValidated time.Time                `json:"last_validated"`
	Errors       []*ConfigurationError     `json:"errors,omitempty"`
	Warnings     []*ConfigurationWarning   `json:"warnings,omitempty"`
}

// ConfigurationError represents a configuration error
type ConfigurationError struct {
	Component    string                    `json:"component"`
	Field        string                    `json:"field"`
	Message      string                    `json:"message"`
	Severity     ErrorSeverity             `json:"severity"`
	Timestamp    time.Time                 `json:"timestamp"`
}

// ConfigurationWarning represents a configuration warning
type ConfigurationWarning struct {
	Component    string                    `json:"component"`
	Field        string                    `json:"field"`
	Message      string                    `json:"message"`
	Recommendation string                  `json:"recommendation,omitempty"`
	Timestamp    time.Time                 `json:"timestamp"`
}

// SystemAlert represents a system-level alert
type SystemAlert struct {
	ID           string                    `json:"id"`
	Type         AlertType                 `json:"type"`
	Severity     AlertSeverity             `json:"severity"`
	Component    string                    `json:"component,omitempty"`
	Title        string                    `json:"title"`
	Message      string                    `json:"message"`
	Timestamp    time.Time                 `json:"timestamp"`
	Resolved     bool                      `json:"resolved"`
	ResolvedAt   *time.Time                `json:"resolved_at,omitempty"`
	Details      map[string]interface{}    `json:"details,omitempty"`
}

// ComponentAlert represents a component-level alert
type ComponentAlert struct {
	ID           string                    `json:"id"`
	Type         AlertType                 `json:"type"`
	Severity     AlertSeverity             `json:"severity"`
	Title        string                    `json:"title"`
	Message      string                    `json:"message"`
	Timestamp    time.Time                 `json:"timestamp"`
	Resolved     bool                      `json:"resolved"`
	ResolvedAt   *time.Time                `json:"resolved_at,omitempty"`
	Details      map[string]interface{}    `json:"details,omitempty"`
}

// SystemStatusSummary provides a summary of system status
type SystemStatusSummary struct {
	TotalComponents      int                  `json:"total_components"`
	HealthyComponents    int                  `json:"healthy_components"`
	DegradedComponents   int                  `json:"degraded_components"`
	UnhealthyComponents  int                  `json:"unhealthy_components"`
	CriticalComponents   int                  `json:"critical_components"`
	ActiveAlerts         int                  `json:"active_alerts"`
	CriticalAlerts       int                  `json:"critical_alerts"`
	ConfigurationErrors  int                  `json:"configuration_errors"`
	ConfigurationWarnings int                 `json:"configuration_warnings"`
}

// ComponentTrends provides trend analysis for a component
type ComponentTrends struct {
	ComponentName    string                   `json:"component_name"`
	Period           time.Duration            `json:"period"`
	StatusTrend      StatusTrend              `json:"status_trend"`
	PerformanceTrend PerformanceTrend         `json:"performance_trend"`
	ErrorTrend       ErrorTrend               `json:"error_trend"`
	Recommendations  []*TrendRecommendation   `json:"recommendations,omitempty"`
}

// StatusTrend represents status trend over time
type StatusTrend struct {
	Direction        TrendDirection           `json:"direction"`
	Stability        float64                  `json:"stability"` // 0-100
	HealthyPercentage float64                 `json:"healthy_percentage"`
	DegradedPercentage float64                `json:"degraded_percentage"`
	UnhealthyPercentage float64               `json:"unhealthy_percentage"`
}

// PerformanceTrend represents performance trend over time
type PerformanceTrend struct {
	ResponseTimeTrend TrendDirection          `json:"response_time_trend"`
	ThroughputTrend   TrendDirection          `json:"throughput_trend"`
	ResourceUsageTrend TrendDirection         `json:"resource_usage_trend"`
	AverageResponseTime time.Duration         `json:"average_response_time"`
	PeakResponseTime  time.Duration           `json:"peak_response_time"`
}

// ErrorTrend represents error trend over time
type ErrorTrend struct {
	Direction        TrendDirection           `json:"direction"`
	ErrorRate        float64                  `json:"error_rate"`
	ErrorCount       int                      `json:"error_count"`
	CriticalErrors   int                      `json:"critical_errors"`
}

// TrendRecommendation provides recommendations based on trends
type TrendRecommendation struct {
	Type         RecommendationType       `json:"type"`
	Priority     RecommendationPriority   `json:"priority"`
	Title        string                   `json:"title"`
	Description  string                   `json:"description"`
	Action       string                   `json:"action"`
	Impact       string                   `json:"impact"`
}

// SystemRecommendation provides system-level recommendations
type SystemRecommendation struct {
	ID           string                   `json:"id"`
	Type         RecommendationType       `json:"type"`
	Priority     RecommendationPriority   `json:"priority"`
	Component    string                   `json:"component,omitempty"`
	Title        string                   `json:"title"`
	Description  string                   `json:"description"`
	Action       string                   `json:"action"`
	Impact       string                   `json:"impact"`
	Timestamp    time.Time                `json:"timestamp"`
}

// Enums and constants

// SystemStatusLevel represents the overall system status level
type SystemStatusLevel int

const (
	SystemStatusUnknown SystemStatusLevel = iota
	SystemStatusHealthy
	SystemStatusDegraded
	SystemStatusUnhealthy
	SystemStatusCritical
	SystemStatusMaintenance
)

func (s SystemStatusLevel) String() string {
	switch s {
	case SystemStatusHealthy:
		return "healthy"
	case SystemStatusDegraded:
		return "degraded"
	case SystemStatusUnhealthy:
		return "unhealthy"
	case SystemStatusCritical:
		return "critical"
	case SystemStatusMaintenance:
		return "maintenance"
	default:
		return "unknown"
	}
}

// ComponentStatusLevel represents component status level
type ComponentStatusLevel int

const (
	ComponentStatusUnknown ComponentStatusLevel = iota
	ComponentStatusHealthy
	ComponentStatusDegraded
	ComponentStatusUnhealthy
	ComponentStatusCritical
	ComponentStatusDisabled
)

func (s ComponentStatusLevel) String() string {
	switch s {
	case ComponentStatusHealthy:
		return "healthy"
	case ComponentStatusDegraded:
		return "degraded"
	case ComponentStatusUnhealthy:
		return "unhealthy"
	case ComponentStatusCritical:
		return "critical"
	case ComponentStatusDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

// TrendDirection represents the direction of a trend
type TrendDirection int

const (
	TrendUnknown TrendDirection = iota
	TrendImproving
	TrendStable
	TrendDegrading
)

func (t TrendDirection) String() string {
	switch t {
	case TrendImproving:
		return "improving"
	case TrendStable:
		return "stable"
	case TrendDegrading:
		return "degrading"
	default:
		return "unknown"
	}
}

// RecommendationType represents the type of recommendation
type RecommendationType int

const (
	RecommendationUnknown RecommendationType = iota
	RecommendationPerformance
	RecommendationSecurity
	RecommendationConfiguration
	RecommendationCapacity
	RecommendationMaintenance
)

func (r RecommendationType) String() string {
	switch r {
	case RecommendationPerformance:
		return "performance"
	case RecommendationSecurity:
		return "security"
	case RecommendationConfiguration:
		return "configuration"
	case RecommendationCapacity:
		return "capacity"
	case RecommendationMaintenance:
		return "maintenance"
	default:
		return "unknown"
	}
}

// RecommendationPriority represents the priority of a recommendation
type RecommendationPriority int

const (
	RecommendationPriorityLow RecommendationPriority = iota
	RecommendationPriorityMedium
	RecommendationPriorityHigh
	RecommendationPriorityCritical
)

func (r RecommendationPriority) String() string {
	switch r {
	case RecommendationPriorityLow:
		return "low"
	case RecommendationPriorityMedium:
		return "medium"
	case RecommendationPriorityHigh:
		return "high"
	case RecommendationPriorityCritical:
		return "critical"
	default:
		return "low"
	}
}

// ErrorSeverity represents the severity of an error
type ErrorSeverity int

const (
	ErrorSeverityLow ErrorSeverity = iota
	ErrorSeverityMedium
	ErrorSeverityHigh
	ErrorSeverityCritical
)

func (e ErrorSeverity) String() string {
	switch e {
	case ErrorSeverityLow:
		return "low"
	case ErrorSeverityMedium:
		return "medium"
	case ErrorSeverityHigh:
		return "high"
	case ErrorSeverityCritical:
		return "critical"
	default:
		return "low"
	}
}

// StatusChangeCallback is called when system status changes
type StatusChangeCallback func(oldStatus, newStatus *SystemStatus)

// SystemStatusConfig holds configuration for system status monitoring
type SystemStatusConfig struct {
	MonitoringInterval    time.Duration `json:"monitoring_interval"`
	HistoryRetention      time.Duration `json:"history_retention"`
	AlertRetention        time.Duration `json:"alert_retention"`
	EnableTrendAnalysis   bool          `json:"enable_trend_analysis"`
	TrendAnalysisWindow   time.Duration `json:"trend_analysis_window"`
	EnableRecommendations bool          `json:"enable_recommendations"`
	MaxRecommendations    int           `json:"max_recommendations"`
	ConfigValidationInterval time.Duration `json:"config_validation_interval"`
}

// DefaultSystemStatusConfig returns default system status configuration
func DefaultSystemStatusConfig() *SystemStatusConfig {
	return &SystemStatusConfig{
		MonitoringInterval:       30 * time.Second,
		HistoryRetention:         24 * time.Hour,
		AlertRetention:           7 * 24 * time.Hour,
		EnableTrendAnalysis:      true,
		TrendAnalysisWindow:      1 * time.Hour,
		EnableRecommendations:    true,
		MaxRecommendations:       10,
		ConfigValidationInterval: 5 * time.Minute,
	}
}

// systemStatusMonitorImpl implements SystemStatusMonitor
type systemStatusMonitorImpl struct {
	config           *SystemStatusConfig
	healthChecker    HealthChecker
	configManager    ConfigManager
	components       map[string]ComponentStatusMonitor
	statusHistory    []*SystemStatus
	alerts           []*SystemAlert
	changeCallback   StatusChangeCallback
	mu               sync.RWMutex
	
	// Monitoring control
	ctx              context.Context
	cancel           context.CancelFunc
	monitoring       bool
	startTime        time.Time
}

// NewSystemStatusMonitor creates a new system status monitor
func NewSystemStatusMonitor(config *SystemStatusConfig, configManager ConfigManager) SystemStatusMonitor {
	if config == nil {
		config = DefaultSystemStatusConfig()
	}
	
	return &systemStatusMonitorImpl{
		config:        config,
		configManager: configManager,
		components:    make(map[string]ComponentStatusMonitor),
		statusHistory: make([]*SystemStatus, 0),
		alerts:        make([]*SystemAlert, 0),
		startTime:     time.Now(),
	}
}

// GetSystemStatus returns the current system status
func (ssm *systemStatusMonitorImpl) GetSystemStatus() (*SystemStatus, error) {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()
	
	// Collect component statuses
	componentStatuses := make(map[string]*ComponentStatus)
	var componentErrors []error
	
	for name, monitor := range ssm.components {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		status, err := monitor.GetStatus(ctx)
		cancel()
		
		if err != nil {
			componentErrors = append(componentErrors, fmt.Errorf("component %s: %w", name, err))
			// Create error status
			status = &ComponentStatus{
				Name:      name,
				Status:    ComponentStatusUnhealthy,
				Message:   fmt.Sprintf("Failed to get status: %v", err),
				LastCheck: time.Now(),
			}
		}
		
		componentStatuses[name] = status
	}
	
	// Get system metrics
	systemMetrics := ssm.getSystemMetrics()
	
	// Get configuration status
	configStatus := ssm.getConfigurationStatus()
	
	// Get active alerts
	activeAlerts := ssm.getActiveAlerts()
	
	// Calculate overall status
	overallStatus, message := ssm.calculateOverallStatus(componentStatuses, configStatus, activeAlerts)
	
	// Create system status
	systemStatus := &SystemStatus{
		Timestamp:     time.Now(),
		OverallStatus: overallStatus,
		Message:       message,
		Version:       ssm.getSystemVersion(),
		Uptime:        time.Since(ssm.startTime),
		Components:    componentStatuses,
		SystemMetrics: systemMetrics,
		Configuration: configStatus,
		Alerts:        activeAlerts,
		Summary:       ssm.calculateStatusSummary(componentStatuses, activeAlerts, configStatus),
	}
	
	return systemStatus, nil
}

// GetDetailedSystemReport returns a comprehensive system report
func (ssm *systemStatusMonitorImpl) GetDetailedSystemReport() (*DetailedSystemReport, error) {
	// Get system status
	systemStatus, err := ssm.GetSystemStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get system status: %w", err)
	}
	
	// Get health report
	var healthReport *SystemHealth
	if ssm.healthChecker != nil {
		healthReport, _ = ssm.healthChecker.GetSystemHealth()
	}
	
	// Get configuration validation report
	configReport, _ := ssm.ValidateSystemConfiguration()
	
	// Get performance report
	performanceReport := ssm.generatePerformanceReport()
	
	// Get security report
	securityReport := ssm.generateSecurityReport()
	
	// Get resource usage report
	resourceUsage := ssm.generateResourceUsageReport()
	
	// Get dependency report
	dependencies := ssm.generateDependencyReport()
	
	// Generate recommendations
	var recommendations []*SystemRecommendation
	if ssm.config.EnableRecommendations {
		recommendations = ssm.generateRecommendations(systemStatus, healthReport, configReport)
	}
	
	return &DetailedSystemReport{
		SystemStatus:      systemStatus,
		HealthReport:      healthReport,
		ConfigReport:      configReport,
		PerformanceReport: performanceReport,
		SecurityReport:    securityReport,
		ResourceUsage:     resourceUsage,
		Dependencies:      dependencies,
		Recommendations:   recommendations,
	}, nil
}

// RegisterComponent registers a component for status monitoring
func (ssm *systemStatusMonitorImpl) RegisterComponent(name string, monitor ComponentStatusMonitor) error {
	if name == "" {
		return fmt.Errorf("component name cannot be empty")
	}
	if monitor == nil {
		return fmt.Errorf("component monitor cannot be nil")
	}
	
	ssm.mu.Lock()
	defer ssm.mu.Unlock()
	
	ssm.components[name] = monitor
	return nil
}

// UnregisterComponent unregisters a component
func (ssm *systemStatusMonitorImpl) UnregisterComponent(name string) error {
	if name == "" {
		return fmt.Errorf("component name cannot be empty")
	}
	
	ssm.mu.Lock()
	defer ssm.mu.Unlock()
	
	delete(ssm.components, name)
	return nil
}

// GetComponentStatus returns the status of a specific component
func (ssm *systemStatusMonitorImpl) GetComponentStatus(name string) (*ComponentStatus, error) {
	if name == "" {
		return nil, fmt.Errorf("component name cannot be empty")
	}
	
	ssm.mu.RLock()
	monitor, exists := ssm.components[name]
	ssm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("component not found: %s", name)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	return monitor.GetStatus(ctx)
}

// SetHealthChecker sets the health checker for integration
func (ssm *systemStatusMonitorImpl) SetHealthChecker(healthChecker HealthChecker) error {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()
	
	ssm.healthChecker = healthChecker
	return nil
}

// ValidateSystemConfiguration validates the entire system configuration
func (ssm *systemStatusMonitorImpl) ValidateSystemConfiguration() (*ConfigurationValidationReport, error) {
	var errors []*ConfigurationError
	var warnings []*ConfigurationWarning
	
	// Validate main configuration
	if ssm.configManager != nil {
		config := ssm.configManager.GetConfig()
		if err := ssm.configManager.ValidateConfig(config); err != nil {
			errors = append(errors, &ConfigurationError{
				Component: "system",
				Field:     "main_config",
				Message:   err.Error(),
				Severity:  ErrorSeverityHigh,
				Timestamp: time.Now(),
			})
		}
	}
	
	// Validate component configurations
	componentValidations := make(map[string]*ComponentConfigValidation)
	
	ssm.mu.RLock()
	components := make(map[string]ComponentStatusMonitor)
	for name, monitor := range ssm.components {
		components[name] = monitor
	}
	ssm.mu.RUnlock()
	
	for name, monitor := range components {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		validation, err := monitor.ValidateConfiguration(ctx)
		cancel()
		
		if err != nil {
			errors = append(errors, &ConfigurationError{
				Component: name,
				Field:     "component_config",
				Message:   fmt.Sprintf("Validation failed: %v", err),
				Severity:  ErrorSeverityMedium,
				Timestamp: time.Now(),
			})
		} else if validation != nil {
			componentValidations[name] = validation
			
			// Collect component errors and warnings
			for _, compError := range validation.Errors {
				compError.Component = name
				errors = append(errors, compError)
			}
			
			for _, compWarning := range validation.Warnings {
				compWarning.Component = name
				warnings = append(warnings, compWarning)
			}
		}
	}
	
	// Determine overall validation status
	valid := len(errors) == 0
	severity := ErrorSeverityLow
	if len(errors) > 0 {
		// Find highest severity
		for _, err := range errors {
			if err.Severity > severity {
				severity = err.Severity
			}
		}
	}
	
	return &ConfigurationValidationReport{
		Valid:                valid,
		Timestamp:           time.Now(),
		OverallSeverity:     severity,
		TotalErrors:         len(errors),
		TotalWarnings:       len(warnings),
		Errors:              errors,
		Warnings:            warnings,
		ComponentValidations: componentValidations,
	}, nil
}

// ValidateComponentConfiguration validates a specific component's configuration
func (ssm *systemStatusMonitorImpl) ValidateComponentConfiguration(componentName string) (*ComponentConfigValidation, error) {
	if componentName == "" {
		return nil, fmt.Errorf("component name cannot be empty")
	}
	
	ssm.mu.RLock()
	monitor, exists := ssm.components[componentName]
	ssm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("component not found: %s", componentName)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	return monitor.ValidateConfiguration(ctx)
}

// StartMonitoring starts continuous system monitoring
func (ssm *systemStatusMonitorImpl) StartMonitoring(ctx context.Context) error {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()
	
	if ssm.monitoring {
		return nil
	}
	
	ssm.ctx, ssm.cancel = context.WithCancel(ctx)
	ssm.monitoring = true
	
	// Start monitoring goroutines
	go ssm.monitoringLoop()
	go ssm.configValidationLoop()
	go ssm.alertCleanupLoop()
	
	return nil
}

// StopMonitoring stops continuous system monitoring
func (ssm *systemStatusMonitorImpl) StopMonitoring() error {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()
	
	if !ssm.monitoring {
		return nil
	}
	
	if ssm.cancel != nil {
		ssm.cancel()
	}
	
	ssm.monitoring = false
	return nil
}

// IsMonitoring returns whether continuous monitoring is active
func (ssm *systemStatusMonitorImpl) IsMonitoring() bool {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()
	return ssm.monitoring
}

// GetStatusHistory returns system status history
func (ssm *systemStatusMonitorImpl) GetStatusHistory(duration time.Duration) ([]*SystemStatus, error) {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()
	
	cutoff := time.Now().Add(-duration)
	var filteredHistory []*SystemStatus
	
	for _, status := range ssm.statusHistory {
		if status.Timestamp.After(cutoff) {
			// Create copy to avoid race conditions
			statusCopy := *status
			filteredHistory = append(filteredHistory, &statusCopy)
		}
	}
	
	return filteredHistory, nil
}

// GetComponentTrends returns trend analysis for a component
func (ssm *systemStatusMonitorImpl) GetComponentTrends(componentName string, duration time.Duration) (*ComponentTrends, error) {
	if !ssm.config.EnableTrendAnalysis {
		return nil, fmt.Errorf("trend analysis is disabled")
	}
	
	// Get status history
	history, err := ssm.GetStatusHistory(duration)
	if err != nil {
		return nil, fmt.Errorf("failed to get status history: %w", err)
	}
	
	// Extract component data from history
	var componentData []*ComponentStatus
	for _, status := range history {
		if compStatus, exists := status.Components[componentName]; exists {
			componentData = append(componentData, compStatus)
		}
	}
	
	if len(componentData) == 0 {
		return nil, fmt.Errorf("no data found for component: %s", componentName)
	}
	
	// Analyze trends
	statusTrend := ssm.analyzeStatusTrend(componentData)
	performanceTrend := ssm.analyzePerformanceTrend(componentData)
	errorTrend := ssm.analyzeErrorTrend(componentData)
	
	// Generate recommendations based on trends
	var recommendations []*TrendRecommendation
	if ssm.config.EnableRecommendations {
		recommendations = ssm.generateTrendRecommendations(componentName, statusTrend, performanceTrend, errorTrend)
	}
	
	return &ComponentTrends{
		ComponentName:    componentName,
		Period:           duration,
		StatusTrend:      statusTrend,
		PerformanceTrend: performanceTrend,
		ErrorTrend:       errorTrend,
		Recommendations:  recommendations,
	}, nil
}

// SetStatusChangeCallback sets the callback for status changes
func (ssm *systemStatusMonitorImpl) SetStatusChangeCallback(callback StatusChangeCallback) error {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()
	
	ssm.changeCallback = callback
	return nil
}

// GetActiveAlerts returns active system alerts
func (ssm *systemStatusMonitorImpl) GetActiveAlerts() ([]*SystemAlert, error) {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()
	
	return ssm.getActiveAlerts(), nil
}

// UpdateConfig updates the system status monitor configuration
func (ssm *systemStatusMonitorImpl) UpdateConfig(config *SystemStatusConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	ssm.mu.Lock()
	defer ssm.mu.Unlock()
	
	ssm.config = config
	return nil
}

// GetConfig returns the current configuration
func (ssm *systemStatusMonitorImpl) GetConfig() *SystemStatusConfig {
	ssm.mu.RLock()
	defer ssm.mu.RUnlock()
	
	// Return copy to prevent external modifications
	configCopy := *ssm.config
	return &configCopy
}

// Helper methods

// getSystemMetrics collects system-level metrics
func (ssm *systemStatusMonitorImpl) getSystemMetrics() *SystemMetrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	// Calculate GC stats
	gcStats := &GCStats{
		NumGC:      memStats.NumGC,
		PauseTotal: time.Duration(memStats.PauseTotalNs),
		LastGC:     time.Unix(0, int64(memStats.LastGC)),
	}
	
	// Get recent pause times (last 10)
	pauseCount := int(memStats.NumGC)
	if pauseCount > 10 {
		pauseCount = 10
	}
	
	gcStats.PauseNs = make([]uint64, pauseCount)
	for i := 0; i < pauseCount; i++ {
		gcStats.PauseNs[i] = memStats.PauseNs[i]
	}
	
	return &SystemMetrics{
		MemoryTotal:      memStats.Sys,
		MemoryUsed:       memStats.Alloc,
		MemoryUsage:      float64(memStats.Alloc) / float64(memStats.Sys) * 100,
		GoroutineCount:   runtime.NumGoroutine(),
		GCStats:          gcStats,
		// Note: CPU usage, requests per second, etc. would need additional monitoring
		CPUUsage:         0, // Would need external monitoring
		RequestsPerSecond: 0, // Would need request tracking
		ActiveConnections: 0, // Would need connection tracking
		ErrorRate:        0, // Would need error tracking
	}
}

// getConfigurationStatus gets the current configuration status
func (ssm *systemStatusMonitorImpl) getConfigurationStatus() *ConfigurationStatus {
	if ssm.configManager == nil {
		return &ConfigurationStatus{
			Valid:         false,
			LastValidated: time.Now(),
			Errors: []*ConfigurationError{
				{
					Component: "system",
					Field:     "config_manager",
					Message:   "Configuration manager not available",
					Severity:  ErrorSeverityHigh,
					Timestamp: time.Now(),
				},
			},
		}
	}
	
	config := ssm.configManager.GetConfig()
	err := ssm.configManager.ValidateConfig(config)
	
	status := &ConfigurationStatus{
		Valid:         err == nil,
		LastValidated: time.Now(),
		LastModified:  config.LastUpdated,
		Version:       config.Version,
	}
	
	if err != nil {
		status.Errors = []*ConfigurationError{
			{
				Component: "system",
				Field:     "main_config",
				Message:   err.Error(),
				Severity:  ErrorSeverityHigh,
				Timestamp: time.Now(),
			},
		}
	}
	
	return status
}

// getActiveAlerts returns currently active alerts
func (ssm *systemStatusMonitorImpl) getActiveAlerts() []*SystemAlert {
	var activeAlerts []*SystemAlert
	
	for _, alert := range ssm.alerts {
		if !alert.Resolved {
			activeAlerts = append(activeAlerts, alert)
		}
	}
	
	return activeAlerts
}

// calculateOverallStatus determines the overall system status
func (ssm *systemStatusMonitorImpl) calculateOverallStatus(components map[string]*ComponentStatus, configStatus *ConfigurationStatus, alerts []*SystemAlert) (SystemStatusLevel, string) {
	// Check for critical alerts
	criticalAlerts := 0
	for _, alert := range alerts {
		if alert.Severity == AlertSeverityCritical {
			criticalAlerts++
		}
	}
	
	if criticalAlerts > 0 {
		return SystemStatusCritical, fmt.Sprintf("%d critical alert(s) active", criticalAlerts)
	}
	
	// Check configuration status
	if !configStatus.Valid {
		return SystemStatusDegraded, "Configuration validation failed"
	}
	
	// Check component statuses
	criticalComponents := 0
	unhealthyComponents := 0
	degradedComponents := 0
	
	for _, status := range components {
		switch status.Status {
		case ComponentStatusCritical:
			criticalComponents++
		case ComponentStatusUnhealthy:
			unhealthyComponents++
		case ComponentStatusDegraded:
			degradedComponents++
		}
	}
	
	if criticalComponents > 0 {
		return SystemStatusCritical, fmt.Sprintf("%d critical component(s)", criticalComponents)
	}
	
	if unhealthyComponents > 0 {
		return SystemStatusUnhealthy, fmt.Sprintf("%d unhealthy component(s)", unhealthyComponents)
	}
	
	if degradedComponents > 0 {
		return SystemStatusDegraded, fmt.Sprintf("%d degraded component(s)", degradedComponents)
	}
	
	return SystemStatusHealthy, "All systems operational"
}

// calculateStatusSummary calculates system status summary
func (ssm *systemStatusMonitorImpl) calculateStatusSummary(components map[string]*ComponentStatus, alerts []*SystemAlert, configStatus *ConfigurationStatus) *SystemStatusSummary {
	summary := &SystemStatusSummary{
		TotalComponents: len(components),
	}
	
	// Count component statuses
	for _, status := range components {
		switch status.Status {
		case ComponentStatusHealthy:
			summary.HealthyComponents++
		case ComponentStatusDegraded:
			summary.DegradedComponents++
		case ComponentStatusUnhealthy:
			summary.UnhealthyComponents++
		case ComponentStatusCritical:
			summary.CriticalComponents++
		}
	}
	
	// Count alerts
	summary.ActiveAlerts = len(alerts)
	for _, alert := range alerts {
		if alert.Severity == AlertSeverityCritical {
			summary.CriticalAlerts++
		}
	}
	
	// Count configuration issues
	if configStatus != nil {
		summary.ConfigurationErrors = len(configStatus.Errors)
		summary.ConfigurationWarnings = len(configStatus.Warnings)
	}
	
	return summary
}

// getSystemVersion returns the system version
func (ssm *systemStatusMonitorImpl) getSystemVersion() string {
	if ssm.configManager != nil {
		config := ssm.configManager.GetConfig()
		return config.Version
	}
	return "unknown"
}

// monitoringLoop runs continuous system monitoring
func (ssm *systemStatusMonitorImpl) monitoringLoop() {
	ticker := time.NewTicker(ssm.config.MonitoringInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ssm.ctx.Done():
			return
		case <-ticker.C:
			status, err := ssm.GetSystemStatus()
			if err != nil {
				continue
			}
			
			// Store in history
			ssm.mu.Lock()
			ssm.addToHistory(status)
			ssm.mu.Unlock()
			
			// Check for status changes and notify
			if ssm.changeCallback != nil {
				// Get previous status for comparison
				ssm.mu.RLock()
				var prevStatus *SystemStatus
				if len(ssm.statusHistory) >= 2 {
					prevStatus = ssm.statusHistory[len(ssm.statusHistory)-2]
				}
				ssm.mu.RUnlock()
				
				if prevStatus != nil && prevStatus.OverallStatus != status.OverallStatus {
					go ssm.changeCallback(prevStatus, status)
				}
			}
		}
	}
}

// configValidationLoop runs periodic configuration validation
func (ssm *systemStatusMonitorImpl) configValidationLoop() {
	ticker := time.NewTicker(ssm.config.ConfigValidationInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ssm.ctx.Done():
			return
		case <-ticker.C:
			// Validate configuration and generate alerts if needed
			report, err := ssm.ValidateSystemConfiguration()
			if err != nil {
				continue
			}
			
			// Generate alerts for configuration errors
			for _, configError := range report.Errors {
				if configError.Severity >= ErrorSeverityHigh {
					alert := &SystemAlert{
						ID:        fmt.Sprintf("config_error_%d", time.Now().UnixNano()),
						Type:      AlertTypeConfiguration,
						Severity:  AlertSeverity(configError.Severity),
						Component: configError.Component,
						Title:     "Configuration Error",
						Message:   configError.Message,
						Timestamp: time.Now(),
						Details: map[string]interface{}{
							"field": configError.Field,
						},
					}
					
					ssm.mu.Lock()
					ssm.alerts = append(ssm.alerts, alert)
					ssm.mu.Unlock()
				}
			}
		}
	}
}

// alertCleanupLoop cleans up old resolved alerts
func (ssm *systemStatusMonitorImpl) alertCleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-ssm.ctx.Done():
			return
		case <-ticker.C:
			ssm.mu.Lock()
			cutoff := time.Now().Add(-ssm.config.AlertRetention)
			var activeAlerts []*SystemAlert
			
			for _, alert := range ssm.alerts {
				if !alert.Resolved || (alert.ResolvedAt != nil && alert.ResolvedAt.After(cutoff)) {
					activeAlerts = append(activeAlerts, alert)
				}
			}
			
			ssm.alerts = activeAlerts
			ssm.mu.Unlock()
		}
	}
}

// addToHistory adds a status to history and manages retention
func (ssm *systemStatusMonitorImpl) addToHistory(status *SystemStatus) {
	ssm.statusHistory = append(ssm.statusHistory, status)
	
	// Clean old history
	cutoff := time.Now().Add(-ssm.config.HistoryRetention)
	var filteredHistory []*SystemStatus
	
	for _, s := range ssm.statusHistory {
		if s.Timestamp.After(cutoff) {
			filteredHistory = append(filteredHistory, s)
		}
	}
	
	ssm.statusHistory = filteredHistory
}

// generatePerformanceReport generates a performance analysis report
func (ssm *systemStatusMonitorImpl) generatePerformanceReport() *PerformanceReport {
	systemMetrics := ssm.getSystemMetrics()
	
	// Collect component metrics
	componentMetrics := make(map[string]*ComponentMetrics)
	
	ssm.mu.RLock()
	components := make(map[string]ComponentStatusMonitor)
	for name, monitor := range ssm.components {
		components[name] = monitor
	}
	ssm.mu.RUnlock()
	
	for name, monitor := range components {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		metrics, err := monitor.GetMetrics(ctx)
		cancel()
		
		if err == nil && metrics != nil {
			componentMetrics[name] = metrics
		}
	}
	
	// Calculate overall performance score
	overallScore := ssm.calculatePerformanceScore(systemMetrics, componentMetrics)
	
	// Identify bottlenecks
	bottlenecks := ssm.identifyBottlenecks(systemMetrics, componentMetrics)
	
	// Generate performance recommendations
	recommendations := ssm.generatePerformanceRecommendations(systemMetrics, componentMetrics, bottlenecks)
	
	return &PerformanceReport{
		Timestamp:        time.Now(),
		OverallScore:     overallScore,
		SystemMetrics:    systemMetrics,
		ComponentMetrics: componentMetrics,
		Bottlenecks:      bottlenecks,
		Recommendations:  recommendations,
	}
}

// generateSecurityReport generates a security status report
func (ssm *systemStatusMonitorImpl) generateSecurityReport() *SecurityStatusReport {
	// This would integrate with security monitoring systems
	// For now, return a basic report
	return &SecurityStatusReport{
		Timestamp:     time.Now(),
		SecurityScore: 85.0, // Would be calculated based on actual security metrics
		ThreatLevel:   ThreatLevelLow,
		ComplianceStatus: &ComplianceStatus{
			Overall:      ComplianceLevelSubstantial,
			LastAssessed: time.Now(),
		},
		SecurityMetrics: &SecurityMetrics{
			CollectionInterval: 1 * time.Minute,
			HistoryRetention:   24 * time.Hour,
			BufferSize:         1000,
			FlushInterval:      30 * time.Second,
		},
	}
}

// generateResourceUsageReport generates a resource usage report
func (ssm *systemStatusMonitorImpl) generateResourceUsageReport() *ResourceUsageReport {
	systemMetrics := ssm.getSystemMetrics()
	
	// Convert system metrics to resource usage format
	systemResources := &SystemResourceUsage{
		CPU: &ResourceMetric{
			Current:     systemMetrics.CPUUsage,
			Utilization: systemMetrics.CPUUsage,
			Trend:       TrendStable, // Would need historical data
		},
		Memory: &ResourceMetric{
			Current:     float64(systemMetrics.MemoryUsed),
			Maximum:     float64(systemMetrics.MemoryTotal),
			Utilization: systemMetrics.MemoryUsage,
			Trend:       TrendStable, // Would need historical data
		},
	}
	
	// Collect component resource usage
	componentUsage := make(map[string]*ComponentResourceUsage)
	
	ssm.mu.RLock()
	components := make(map[string]ComponentStatusMonitor)
	for name, monitor := range ssm.components {
		components[name] = monitor
	}
	ssm.mu.RUnlock()
	
	for name, monitor := range components {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		metrics, err := monitor.GetMetrics(ctx)
		cancel()
		
		if err == nil && metrics != nil {
			componentUsage[name] = &ComponentResourceUsage{
				ComponentName: name,
				CPU: &ResourceMetric{
					Current:     metrics.CPUUsage,
					Utilization: metrics.CPUUsage,
					Trend:       TrendStable,
				},
				Memory: &ResourceMetric{
					Current:     metrics.MemoryUsage,
					Utilization: metrics.MemoryUsage,
					Trend:       TrendStable,
				},
			}
		}
	}
	
	return &ResourceUsageReport{
		Timestamp:       time.Now(),
		SystemResources: systemResources,
		ComponentUsage:  componentUsage,
	}
}

// generateDependencyReport generates a dependency analysis report
func (ssm *systemStatusMonitorImpl) generateDependencyReport() *DependencyReport {
	// This would analyze actual system dependencies
	// For now, return a basic structure
	dependencies := []*SystemDependency{
		{
			Name:        "enhanced_cache",
			Type:        DependencyTypeCache,
			Status:      DependencyStatusAvailable,
			Required:    true,
			Health:      HealthStatusHealthy,
			LastChecked: time.Now(),
		},
		{
			Name:        "session_manager",
			Type:        DependencyTypeService,
			Status:      DependencyStatusAvailable,
			Required:    true,
			Health:      HealthStatusHealthy,
			LastChecked: time.Now(),
		},
	}
	
	// Create dependency graph
	nodes := []*DependencyNode{
		{
			ID:       "auth_system",
			Name:     "Authentication System",
			Type:     DependencyTypeService,
			Critical: true,
			Status:   DependencyStatusAvailable,
		},
		{
			ID:       "enhanced_cache",
			Name:     "Enhanced Cache",
			Type:     DependencyTypeCache,
			Critical: true,
			Status:   DependencyStatusAvailable,
		},
		{
			ID:       "session_manager",
			Name:     "Session Manager",
			Type:     DependencyTypeService,
			Critical: true,
			Status:   DependencyStatusAvailable,
		},
	}
	
	edges := []*DependencyEdge{
		{
			From:     "auth_system",
			To:       "enhanced_cache",
			Type:     DependencyRelationRequires,
			Required: true,
		},
		{
			From:     "auth_system",
			To:       "session_manager",
			Type:     DependencyRelationRequires,
			Required: true,
		},
	}
	
	graph := &DependencyGraph{
		Nodes: nodes,
		Edges: edges,
	}
	
	return &DependencyReport{
		Timestamp:    time.Now(),
		Dependencies: dependencies,
		Graph:        graph,
		CriticalPath: nodes, // Simplified - would need actual path analysis
	}
}

// generateRecommendations generates system-level recommendations
func (ssm *systemStatusMonitorImpl) generateRecommendations(systemStatus *SystemStatus, healthReport *SystemHealth, configReport *ConfigurationValidationReport) []*SystemRecommendation {
	var recommendations []*SystemRecommendation
	
	// Configuration-based recommendations
	if configReport != nil && len(configReport.Errors) > 0 {
		recommendations = append(recommendations, &SystemRecommendation{
			ID:          fmt.Sprintf("config_fix_%d", time.Now().UnixNano()),
			Type:        RecommendationConfiguration,
			Priority:    RecommendationPriorityHigh,
			Title:       "Fix Configuration Errors",
			Description: fmt.Sprintf("There are %d configuration errors that need attention", len(configReport.Errors)),
			Action:      "Review and fix configuration errors in the system configuration",
			Impact:      "Improved system stability and security",
			Timestamp:   time.Now(),
		})
	}
	
	// Performance-based recommendations
	if systemStatus.SystemMetrics.MemoryUsage > 80 {
		recommendations = append(recommendations, &SystemRecommendation{
			ID:          fmt.Sprintf("memory_opt_%d", time.Now().UnixNano()),
			Type:        RecommendationPerformance,
			Priority:    RecommendationPriorityMedium,
			Title:       "High Memory Usage",
			Description: fmt.Sprintf("System memory usage is at %.1f%%", systemStatus.SystemMetrics.MemoryUsage),
			Action:      "Consider increasing memory allocation or optimizing memory usage",
			Impact:      "Improved system performance and stability",
			Timestamp:   time.Now(),
		})
	}
	
	// Health-based recommendations
	if healthReport != nil && healthReport.Summary.UnhealthyComponents > 0 {
		recommendations = append(recommendations, &SystemRecommendation{
			ID:          fmt.Sprintf("health_fix_%d", time.Now().UnixNano()),
			Type:        RecommendationMaintenance,
			Priority:    RecommendationPriorityHigh,
			Title:       "Unhealthy Components",
			Description: fmt.Sprintf("There are %d unhealthy components", healthReport.Summary.UnhealthyComponents),
			Action:      "Investigate and fix unhealthy components",
			Impact:      "Improved system reliability",
			Timestamp:   time.Now(),
		})
	}
	
	// Limit recommendations
	if len(recommendations) > ssm.config.MaxRecommendations {
		recommendations = recommendations[:ssm.config.MaxRecommendations]
	}
	
	return recommendations
}

// calculatePerformanceScore calculates overall performance score
func (ssm *systemStatusMonitorImpl) calculatePerformanceScore(systemMetrics *SystemMetrics, componentMetrics map[string]*ComponentMetrics) float64 {
	score := 100.0
	
	// Deduct points for high resource usage
	if systemMetrics.MemoryUsage > 90 {
		score -= 20
	} else if systemMetrics.MemoryUsage > 80 {
		score -= 10
	} else if systemMetrics.MemoryUsage > 70 {
		score -= 5
	}
	
	// Deduct points for high error rate
	if systemMetrics.ErrorRate > 5 {
		score -= 30
	} else if systemMetrics.ErrorRate > 1 {
		score -= 15
	} else if systemMetrics.ErrorRate > 0.1 {
		score -= 5
	}
	
	// Deduct points for component issues
	for _, metrics := range componentMetrics {
		if metrics.ErrorRate > 1 {
			score -= 5
		}
	}
	
	if score < 0 {
		score = 0
	}
	
	return score
}

// identifyBottlenecks identifies performance bottlenecks
func (ssm *systemStatusMonitorImpl) identifyBottlenecks(systemMetrics *SystemMetrics, componentMetrics map[string]*ComponentMetrics) []*PerformanceBottleneck {
	var bottlenecks []*PerformanceBottleneck
	
	// System-level bottlenecks
	if systemMetrics.MemoryUsage > 90 {
		bottlenecks = append(bottlenecks, &PerformanceBottleneck{
			Component:   "system",
			Type:        BottleneckMemory,
			Severity:    BottleneckSeverityCritical,
			Description: "System memory usage is critically high",
			Impact:      "May cause system instability and performance degradation",
			Suggestion:  "Increase memory allocation or optimize memory usage",
			Metrics: map[string]interface{}{
				"memory_usage": systemMetrics.MemoryUsage,
				"memory_used":  systemMetrics.MemoryUsed,
				"memory_total": systemMetrics.MemoryTotal,
			},
		})
	}
	
	if systemMetrics.ErrorRate > 5 {
		bottlenecks = append(bottlenecks, &PerformanceBottleneck{
			Component:   "system",
			Type:        BottleneckCPU, // Assuming high error rate indicates processing issues
			Severity:    BottleneckSeverityHigh,
			Description: "High system error rate detected",
			Impact:      "Degraded user experience and system reliability",
			Suggestion:  "Investigate error sources and optimize error handling",
			Metrics: map[string]interface{}{
				"error_rate": systemMetrics.ErrorRate,
			},
		})
	}
	
	// Component-level bottlenecks
	for name, metrics := range componentMetrics {
		if metrics.ErrorRate > 2 {
			bottlenecks = append(bottlenecks, &PerformanceBottleneck{
				Component:   name,
				Type:        BottleneckCPU,
				Severity:    BottleneckSeverityMedium,
				Description: fmt.Sprintf("Component %s has high error rate", name),
				Impact:      "Component performance degradation",
				Suggestion:  "Review component implementation and error handling",
				Metrics: map[string]interface{}{
					"error_rate": metrics.ErrorRate,
				},
			})
		}
	}
	
	return bottlenecks
}

// generatePerformanceRecommendations generates performance improvement recommendations
func (ssm *systemStatusMonitorImpl) generatePerformanceRecommendations(systemMetrics *SystemMetrics, componentMetrics map[string]*ComponentMetrics, bottlenecks []*PerformanceBottleneck) []*PerformanceRecommendation {
	var recommendations []*PerformanceRecommendation
	
	// Generate recommendations based on bottlenecks
	for _, bottleneck := range bottlenecks {
		switch bottleneck.Type {
		case BottleneckMemory:
			recommendations = append(recommendations, &PerformanceRecommendation{
				Component:    bottleneck.Component,
				Type:         RecommendationPerformance,
				Priority:     RecommendationPriorityHigh,
				Title:        "Memory Optimization",
				Description:  "High memory usage detected",
				Action:       "Optimize memory usage or increase memory allocation",
				ExpectedGain: "20-30% performance improvement",
				Effort:       "Medium",
			})
		case BottleneckCPU:
			recommendations = append(recommendations, &PerformanceRecommendation{
				Component:    bottleneck.Component,
				Type:         RecommendationPerformance,
				Priority:     RecommendationPriorityMedium,
				Title:        "CPU Optimization",
				Description:  "High CPU usage or error rate detected",
				Action:       "Optimize algorithms or increase CPU resources",
				ExpectedGain: "15-25% performance improvement",
				Effort:       "High",
			})
		}
	}
	
	return recommendations
}

// analyzeStatusTrend analyzes status trend from historical data
func (ssm *systemStatusMonitorImpl) analyzeStatusTrend(componentData []*ComponentStatus) StatusTrend {
	if len(componentData) < 2 {
		return StatusTrend{
			Direction: TrendUnknown,
			Stability: 0,
		}
	}
	
	// Count status occurrences
	healthyCount := 0
	degradedCount := 0
	unhealthyCount := 0
	
	for _, status := range componentData {
		switch status.Status {
		case ComponentStatusHealthy:
			healthyCount++
		case ComponentStatusDegraded:
			degradedCount++
		case ComponentStatusUnhealthy, ComponentStatusCritical:
			unhealthyCount++
		}
	}
	
	total := len(componentData)
	healthyPercentage := float64(healthyCount) / float64(total) * 100
	degradedPercentage := float64(degradedCount) / float64(total) * 100
	unhealthyPercentage := float64(unhealthyCount) / float64(total) * 100
	
	// Determine trend direction (simplified)
	direction := TrendStable
	if len(componentData) >= 5 {
		recentHealthy := 0
		for i := len(componentData) - 3; i < len(componentData); i++ {
			if componentData[i].Status == ComponentStatusHealthy {
				recentHealthy++
			}
		}
		
		if recentHealthy == 3 && healthyPercentage < 80 {
			direction = TrendImproving
		} else if recentHealthy == 0 && healthyPercentage > 50 {
			direction = TrendDegrading
		}
	}
	
	// Calculate stability (how consistent the status has been)
	stability := healthyPercentage
	if degradedPercentage > unhealthyPercentage {
		stability = 100 - degradedPercentage
	} else {
		stability = 100 - unhealthyPercentage
	}
	
	return StatusTrend{
		Direction:           direction,
		Stability:           stability,
		HealthyPercentage:   healthyPercentage,
		DegradedPercentage:  degradedPercentage,
		UnhealthyPercentage: unhealthyPercentage,
	}
}

// analyzePerformanceTrend analyzes performance trend from historical data
func (ssm *systemStatusMonitorImpl) analyzePerformanceTrend(componentData []*ComponentStatus) PerformanceTrend {
	if len(componentData) < 2 {
		return PerformanceTrend{
			ResponseTimeTrend: TrendUnknown,
			ThroughputTrend:   TrendUnknown,
			ResourceUsageTrend: TrendUnknown,
		}
	}
	
	// This would analyze actual performance metrics from historical data
	// For now, return a simplified trend
	return PerformanceTrend{
		ResponseTimeTrend:   TrendStable,
		ThroughputTrend:     TrendStable,
		ResourceUsageTrend:  TrendStable,
		AverageResponseTime: 50 * time.Millisecond,
		PeakResponseTime:    200 * time.Millisecond,
	}
}

// analyzeErrorTrend analyzes error trend from historical data
func (ssm *systemStatusMonitorImpl) analyzeErrorTrend(componentData []*ComponentStatus) ErrorTrend {
	if len(componentData) < 2 {
		return ErrorTrend{
			Direction: TrendUnknown,
			ErrorRate: 0,
		}
	}
	
	// Count errors in the data
	errorCount := 0
	for _, status := range componentData {
		if status.Status == ComponentStatusUnhealthy || status.Status == ComponentStatusCritical {
			errorCount++
		}
	}
	
	errorRate := float64(errorCount) / float64(len(componentData)) * 100
	
	// Determine trend direction (simplified)
	direction := TrendStable
	if len(componentData) >= 5 {
		recentErrors := 0
		for i := len(componentData) - 3; i < len(componentData); i++ {
			if componentData[i].Status == ComponentStatusUnhealthy || componentData[i].Status == ComponentStatusCritical {
				recentErrors++
			}
		}
		
		if recentErrors > errorCount/2 {
			direction = TrendDegrading
		} else if recentErrors == 0 && errorCount > 0 {
			direction = TrendImproving
		}
	}
	
	return ErrorTrend{
		Direction:      direction,
		ErrorRate:      errorRate,
		ErrorCount:     errorCount,
		CriticalErrors: errorCount, // Simplified
	}
}

// generateTrendRecommendations generates recommendations based on trends
func (ssm *systemStatusMonitorImpl) generateTrendRecommendations(componentName string, statusTrend StatusTrend, performanceTrend PerformanceTrend, errorTrend ErrorTrend) []*TrendRecommendation {
	var recommendations []*TrendRecommendation
	
	// Status trend recommendations
	if statusTrend.Direction == TrendDegrading {
		recommendations = append(recommendations, &TrendRecommendation{
			Type:        RecommendationMaintenance,
			Priority:    RecommendationPriorityHigh,
			Title:       "Degrading Status Trend",
			Description: fmt.Sprintf("Component %s status is trending downward", componentName),
			Action:      "Investigate recent changes and perform maintenance",
			Impact:      "Prevent further degradation and improve stability",
		})
	}
	
	// Error trend recommendations
	if errorTrend.Direction == TrendDegrading {
		recommendations = append(recommendations, &TrendRecommendation{
			Type:        RecommendationSecurity,
			Priority:    RecommendationPriorityMedium,
			Title:       "Increasing Error Rate",
			Description: fmt.Sprintf("Component %s error rate is increasing", componentName),
			Action:      "Review error logs and implement error reduction measures",
			Impact:      "Improved reliability and user experience",
		})
	}
	
	// Performance trend recommendations
	if performanceTrend.ResponseTimeTrend == TrendDegrading {
		recommendations = append(recommendations, &TrendRecommendation{
			Type:        RecommendationPerformance,
			Priority:    RecommendationPriorityMedium,
			Title:       "Degrading Response Time",
			Description: fmt.Sprintf("Component %s response time is increasing", componentName),
			Action:      "Optimize performance and consider scaling",
			Impact:      "Better user experience and system responsiveness",
		})
	}
	
	return recommendations
}