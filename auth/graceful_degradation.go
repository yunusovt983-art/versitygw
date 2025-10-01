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

package auth

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// GracefulDegradationManager manages graceful degradation of authentication services
type GracefulDegradationManager interface {
	// Degradation modes
	SetDegradationMode(mode DegradationMode) error
	GetDegradationMode() DegradationMode
	
	// Component management
	RegisterComponent(name string, component DegradableComponent) error
	UnregisterComponent(name string) error
	
	// Degradation control
	DegradeComponent(componentName string, level DegradationLevel) error
	RestoreComponent(componentName string) error
	DegradeSystem(level DegradationLevel) error
	RestoreSystem() error
	
	// Status monitoring
	GetSystemStatus() *SystemDegradationStatus
	GetComponentStatus(componentName string) (*ComponentDegradationStatus, error)
	
	// Health integration
	SetHealthChecker(healthChecker HealthChecker) error
	EnableAutoDegrade(enable bool) error
	
	// Configuration
	UpdateConfig(config *DegradationConfig) error
	
	// Lifecycle
	Start() error
	Stop() error
}

// DegradableComponent defines the interface for components that support graceful degradation
type DegradableComponent interface {
	// Degradation control
	Degrade(level DegradationLevel) error
	Restore() error
	
	// Status
	GetDegradationStatus() *ComponentDegradationStatus
	GetComponentInfo() *DegradableComponentInfo
	
	// Health check
	IsHealthy() bool
}

// DegradationMode defines different degradation modes
type DegradationMode int

const (
	DegradationModeNormal DegradationMode = iota
	DegradationModeConservative
	DegradationModeAggressive
	DegradationModeEmergency
)

// String returns string representation of DegradationMode
func (m DegradationMode) String() string {
	switch m {
	case DegradationModeNormal:
		return "normal"
	case DegradationModeConservative:
		return "conservative"
	case DegradationModeAggressive:
		return "aggressive"
	case DegradationModeEmergency:
		return "emergency"
	default:
		return "unknown"
	}
}

// DegradationLevel defines different levels of degradation
type DegradationLevel int

const (
	DegradationLevelNone DegradationLevel = iota
	DegradationLevelMinor
	DegradationLevelModerate
	DegradationLevelSevere
	DegradationLevelCritical
)

// String returns string representation of DegradationLevel
func (l DegradationLevel) String() string {
	switch l {
	case DegradationLevelNone:
		return "none"
	case DegradationLevelMinor:
		return "minor"
	case DegradationLevelModerate:
		return "moderate"
	case DegradationLevelSevere:
		return "severe"
	case DegradationLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// SystemDegradationStatus represents the overall system degradation status
type SystemDegradationStatus struct {
	Mode                DegradationMode                            `json:"mode"`
	OverallLevel        DegradationLevel                           `json:"overall_level"`
	Components          map[string]*ComponentDegradationStatus     `json:"components"`
	DegradedComponents  []string                                   `json:"degraded_components"`
	HealthyComponents   []string                                   `json:"healthy_components"`
	LastUpdate          time.Time                                  `json:"last_update"`
	AutoDegradeEnabled  bool                                       `json:"auto_degrade_enabled"`
}

// ComponentDegradationStatus represents the degradation status of a component
type ComponentDegradationStatus struct {
	ComponentName       string           `json:"component_name"`
	Level               DegradationLevel `json:"level"`
	Healthy             bool             `json:"healthy"`
	LastDegradation     time.Time        `json:"last_degradation"`
	LastRestoration     time.Time        `json:"last_restoration"`
	DegradationReason   string           `json:"degradation_reason"`
	AvailableFeatures   []string         `json:"available_features"`
	DisabledFeatures    []string         `json:"disabled_features"`
}

// DegradableComponentInfo provides information about a degradable component
type DegradableComponentInfo struct {
	Name                string                              `json:"name"`
	Description         string                              `json:"description"`
	Critical            bool                                `json:"critical"`
	SupportedLevels     []DegradationLevel                  `json:"supported_levels"`
	FeatureMap          map[DegradationLevel][]string       `json:"feature_map"`
	Dependencies        []string                            `json:"dependencies"`
}

// DegradationConfig holds configuration for graceful degradation
type DegradationConfig struct {
	// Auto-degradation settings
	EnableAutoDegrade       bool          `json:"enable_auto_degrade"`
	HealthCheckInterval     time.Duration `json:"health_check_interval"`
	DegradationThreshold    int           `json:"degradation_threshold"`
	RestorationThreshold    int           `json:"restoration_threshold"`
	
	// Degradation rules
	ComponentRules          map[string]*ComponentDegradationRule `json:"component_rules"`
	SystemRules             []*SystemDegradationRule             `json:"system_rules"`
	
	// Timeouts
	DegradationTimeout      time.Duration `json:"degradation_timeout"`
	RestorationTimeout      time.Duration `json:"restoration_timeout"`
	
	// Notifications
	EnableNotifications     bool          `json:"enable_notifications"`
	NotificationCallback    func(event *DegradationEvent) `json:"-"`
}

// ComponentDegradationRule defines degradation rules for a component
type ComponentDegradationRule struct {
	ComponentName           string                              `json:"component_name"`
	HealthThresholds        map[HealthStatus]DegradationLevel   `json:"health_thresholds"`
	AutoRestore             bool                                `json:"auto_restore"`
	RestoreDelay            time.Duration                       `json:"restore_delay"`
	MaxDegradationLevel     DegradationLevel                    `json:"max_degradation_level"`
}

// SystemDegradationRule defines system-wide degradation rules
type SystemDegradationRule struct {
	Condition               string           `json:"condition"`
	Action                  DegradationLevel `json:"action"`
	Components              []string         `json:"components"`
	Priority                int              `json:"priority"`
}

// DegradationEvent represents a degradation event
type DegradationEvent struct {
	Type                    DegradationEventType `json:"type"`
	ComponentName           string               `json:"component_name"`
	OldLevel                DegradationLevel     `json:"old_level"`
	NewLevel                DegradationLevel     `json:"new_level"`
	Reason                  string               `json:"reason"`
	Timestamp               time.Time            `json:"timestamp"`
	SystemStatus            *SystemDegradationStatus `json:"system_status"`
}

// DegradationEventType defines types of degradation events
type DegradationEventType int

const (
	DegradationEventComponentDegraded DegradationEventType = iota
	DegradationEventComponentRestored
	DegradationEventSystemDegraded
	DegradationEventSystemRestored
)

// String returns string representation of DegradationEventType
func (t DegradationEventType) String() string {
	switch t {
	case DegradationEventComponentDegraded:
		return "component_degraded"
	case DegradationEventComponentRestored:
		return "component_restored"
	case DegradationEventSystemDegraded:
		return "system_degraded"
	case DegradationEventSystemRestored:
		return "system_restored"
	default:
		return "unknown"
	}
}

// DefaultDegradationConfig returns default degradation configuration
func DefaultDegradationConfig() *DegradationConfig {
	return &DegradationConfig{
		EnableAutoDegrade:       true,
		HealthCheckInterval:     30 * time.Second,
		DegradationThreshold:    3,
		RestorationThreshold:    5,
		DegradationTimeout:      10 * time.Second,
		RestorationTimeout:      30 * time.Second,
		EnableNotifications:     true,
		ComponentRules:          make(map[string]*ComponentDegradationRule),
		SystemRules:             make([]*SystemDegradationRule, 0),
	}
}

// gracefulDegradationManagerImpl implements GracefulDegradationManager
type gracefulDegradationManagerImpl struct {
	config              *DegradationConfig
	mode                DegradationMode
	components          map[string]DegradableComponent
	componentStatus     map[string]*ComponentDegradationStatus
	healthChecker       HealthChecker
	autoDegrade         bool
	mu                  sync.RWMutex
	
	// Health monitoring
	healthFailures      map[string]int
	healthSuccesses     map[string]int
	
	// Background monitoring
	ctx                 context.Context
	cancel              context.CancelFunc
	running             bool
}

// NewGracefulDegradationManager creates a new graceful degradation manager
func NewGracefulDegradationManager(config *DegradationConfig) GracefulDegradationManager {
	if config == nil {
		config = DefaultDegradationConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &gracefulDegradationManagerImpl{
		config:          config,
		mode:            DegradationModeNormal,
		components:      make(map[string]DegradableComponent),
		componentStatus: make(map[string]*ComponentDegradationStatus),
		healthFailures:  make(map[string]int),
		healthSuccesses: make(map[string]int),
		autoDegrade:     config.EnableAutoDegrade,
		ctx:             ctx,
		cancel:          cancel,
	}
}

// SetDegradationMode sets the degradation mode
func (gdm *gracefulDegradationManagerImpl) SetDegradationMode(mode DegradationMode) error {
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	oldMode := gdm.mode
	gdm.mode = mode
	
	// Apply mode-specific degradation rules
	switch mode {
	case DegradationModeConservative:
		// Degrade non-critical components to minor level
		for name, component := range gdm.components {
			info := component.GetComponentInfo()
			if !info.Critical {
				component.Degrade(DegradationLevelMinor)
				gdm.updateComponentStatus(name, DegradationLevelMinor, "Conservative mode enabled")
			}
		}
	case DegradationModeAggressive:
		// Degrade all non-critical components to moderate level
		for name, component := range gdm.components {
			info := component.GetComponentInfo()
			if !info.Critical {
				component.Degrade(DegradationLevelModerate)
				gdm.updateComponentStatus(name, DegradationLevelModerate, "Aggressive mode enabled")
			}
		}
	case DegradationModeEmergency:
		// Degrade all components to maximum safe level
		for name, component := range gdm.components {
			info := component.GetComponentInfo()
			maxLevel := DegradationLevelSevere
			if !info.Critical {
				maxLevel = DegradationLevelCritical
			}
			component.Degrade(maxLevel)
			gdm.updateComponentStatus(name, maxLevel, "Emergency mode enabled")
		}
	case DegradationModeNormal:
		// Restore all components if coming from degraded mode
		if oldMode != DegradationModeNormal {
			for name, component := range gdm.components {
				component.Restore()
				gdm.updateComponentStatus(name, DegradationLevelNone, "Normal mode restored")
			}
		}
	}
	
	return nil
}

// GetDegradationMode returns the current degradation mode
func (gdm *gracefulDegradationManagerImpl) GetDegradationMode() DegradationMode {
	gdm.mu.RLock()
	defer gdm.mu.RUnlock()
	return gdm.mode
}

// RegisterComponent registers a degradable component
func (gdm *gracefulDegradationManagerImpl) RegisterComponent(name string, component DegradableComponent) error {
	if name == "" {
		return fmt.Errorf("component name cannot be empty")
	}
	if component == nil {
		return fmt.Errorf("component cannot be nil")
	}
	
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	gdm.components[name] = component
	gdm.componentStatus[name] = &ComponentDegradationStatus{
		ComponentName:     name,
		Level:             DegradationLevelNone,
		Healthy:           true,
		LastRestoration:   time.Now(),
		AvailableFeatures: component.GetComponentInfo().FeatureMap[DegradationLevelNone],
		DisabledFeatures:  []string{},
	}
	
	return nil
}

// UnregisterComponent unregisters a component
func (gdm *gracefulDegradationManagerImpl) UnregisterComponent(name string) error {
	if name == "" {
		return fmt.Errorf("component name cannot be empty")
	}
	
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	delete(gdm.components, name)
	delete(gdm.componentStatus, name)
	delete(gdm.healthFailures, name)
	delete(gdm.healthSuccesses, name)
	
	return nil
}

// DegradeComponent degrades a specific component
func (gdm *gracefulDegradationManagerImpl) DegradeComponent(componentName string, level DegradationLevel) error {
	if componentName == "" {
		return fmt.Errorf("component name cannot be empty")
	}
	
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	component, exists := gdm.components[componentName]
	if !exists {
		return fmt.Errorf("component not found: %s", componentName)
	}
	
	// Check if component supports this degradation level
	info := component.GetComponentInfo()
	supported := false
	for _, supportedLevel := range info.SupportedLevels {
		if supportedLevel == level {
			supported = true
			break
		}
	}
	
	if !supported {
		return fmt.Errorf("component %s does not support degradation level %s", componentName, level.String())
	}
	
	// Apply degradation
	err := component.Degrade(level)
	if err != nil {
		return fmt.Errorf("failed to degrade component %s: %w", componentName, err)
	}
	
	// Update status
	gdm.updateComponentStatus(componentName, level, "Manual degradation")
	
	// Send notification
	gdm.sendNotification(&DegradationEvent{
		Type:          DegradationEventComponentDegraded,
		ComponentName: componentName,
		OldLevel:      gdm.componentStatus[componentName].Level,
		NewLevel:      level,
		Reason:        "Manual degradation",
		Timestamp:     time.Now(),
		SystemStatus:  gdm.getSystemStatusLocked(),
	})
	
	return nil
}

// RestoreComponent restores a specific component
func (gdm *gracefulDegradationManagerImpl) RestoreComponent(componentName string) error {
	if componentName == "" {
		return fmt.Errorf("component name cannot be empty")
	}
	
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	component, exists := gdm.components[componentName]
	if !exists {
		return fmt.Errorf("component not found: %s", componentName)
	}
	
	oldLevel := gdm.componentStatus[componentName].Level
	
	// Restore component
	err := component.Restore()
	if err != nil {
		return fmt.Errorf("failed to restore component %s: %w", componentName, err)
	}
	
	// Update status
	gdm.updateComponentStatus(componentName, DegradationLevelNone, "Manual restoration")
	
	// Send notification
	gdm.sendNotification(&DegradationEvent{
		Type:          DegradationEventComponentRestored,
		ComponentName: componentName,
		OldLevel:      oldLevel,
		NewLevel:      DegradationLevelNone,
		Reason:        "Manual restoration",
		Timestamp:     time.Now(),
		SystemStatus:  gdm.getSystemStatusLocked(),
	})
	
	return nil
}

// DegradeSystem degrades the entire system
func (gdm *gracefulDegradationManagerImpl) DegradeSystem(level DegradationLevel) error {
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	var errors []error
	
	for name, component := range gdm.components {
		info := component.GetComponentInfo()
		
		// Determine appropriate level for this component
		componentLevel := level
		if info.Critical && level > DegradationLevelModerate {
			componentLevel = DegradationLevelModerate // Don't degrade critical components too much
		}
		
		// Check if component supports this level
		supported := false
		for _, supportedLevel := range info.SupportedLevels {
			if supportedLevel == componentLevel {
				supported = true
				break
			}
		}
		
		if !supported {
			continue // Skip components that don't support this level
		}
		
		err := component.Degrade(componentLevel)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to degrade component %s: %w", name, err))
			continue
		}
		
		gdm.updateComponentStatus(name, componentLevel, "System degradation")
	}
	
	// Send system degradation notification
	gdm.sendNotification(&DegradationEvent{
		Type:         DegradationEventSystemDegraded,
		NewLevel:     level,
		Reason:       "System degradation",
		Timestamp:    time.Now(),
		SystemStatus: gdm.getSystemStatusLocked(),
	})
	
	if len(errors) > 0 {
		return fmt.Errorf("system degradation completed with errors: %v", errors)
	}
	
	return nil
}

// RestoreSystem restores the entire system
func (gdm *gracefulDegradationManagerImpl) RestoreSystem() error {
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	var errors []error
	
	for name, component := range gdm.components {
		err := component.Restore()
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to restore component %s: %w", name, err))
			continue
		}
		
		gdm.updateComponentStatus(name, DegradationLevelNone, "System restoration")
	}
	
	// Send system restoration notification
	gdm.sendNotification(&DegradationEvent{
		Type:         DegradationEventSystemRestored,
		NewLevel:     DegradationLevelNone,
		Reason:       "System restoration",
		Timestamp:    time.Now(),
		SystemStatus: gdm.getSystemStatusLocked(),
	})
	
	if len(errors) > 0 {
		return fmt.Errorf("system restoration completed with errors: %v", errors)
	}
	
	return nil
}

// GetSystemStatus returns the current system degradation status
func (gdm *gracefulDegradationManagerImpl) GetSystemStatus() *SystemDegradationStatus {
	gdm.mu.RLock()
	defer gdm.mu.RUnlock()
	return gdm.getSystemStatusLocked()
}

// GetComponentStatus returns the degradation status of a specific component
func (gdm *gracefulDegradationManagerImpl) GetComponentStatus(componentName string) (*ComponentDegradationStatus, error) {
	if componentName == "" {
		return nil, fmt.Errorf("component name cannot be empty")
	}
	
	gdm.mu.RLock()
	defer gdm.mu.RUnlock()
	
	status, exists := gdm.componentStatus[componentName]
	if !exists {
		return nil, fmt.Errorf("component not found: %s", componentName)
	}
	
	// Return copy to avoid race conditions
	statusCopy := *status
	return &statusCopy, nil
}

// SetHealthChecker sets the health checker for auto-degradation
func (gdm *gracefulDegradationManagerImpl) SetHealthChecker(healthChecker HealthChecker) error {
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	gdm.healthChecker = healthChecker
	
	// Set up health change callback
	if healthChecker != nil {
		healthChecker.SetHealthChangeCallback(gdm.handleHealthChange)
	}
	
	return nil
}

// EnableAutoDegrade enables or disables auto-degradation
func (gdm *gracefulDegradationManagerImpl) EnableAutoDegrade(enable bool) error {
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	gdm.autoDegrade = enable
	return nil
}

// UpdateConfig updates the degradation configuration
func (gdm *gracefulDegradationManagerImpl) UpdateConfig(config *DegradationConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	gdm.config = config
	gdm.autoDegrade = config.EnableAutoDegrade
	
	return nil
}

// Start starts the degradation manager
func (gdm *gracefulDegradationManagerImpl) Start() error {
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	if gdm.running {
		return nil
	}
	
	// Start background monitoring if auto-degrade is enabled
	if gdm.autoDegrade && gdm.healthChecker != nil {
		go gdm.monitoringLoop()
	}
	
	gdm.running = true
	return nil
}

// Stop stops the degradation manager
func (gdm *gracefulDegradationManagerImpl) Stop() error {
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	if !gdm.running {
		return nil
	}
	
	if gdm.cancel != nil {
		gdm.cancel()
	}
	
	gdm.running = false
	return nil
}

// Helper methods

// getSystemStatusLocked returns system status (must be called with lock held)
func (gdm *gracefulDegradationManagerImpl) getSystemStatusLocked() *SystemDegradationStatus {
	components := make(map[string]*ComponentDegradationStatus)
	var degradedComponents []string
	var healthyComponents []string
	overallLevel := DegradationLevelNone
	
	for name, status := range gdm.componentStatus {
		// Create copy
		statusCopy := *status
		components[name] = &statusCopy
		
		if status.Level > DegradationLevelNone {
			degradedComponents = append(degradedComponents, name)
			if status.Level > overallLevel {
				overallLevel = status.Level
			}
		} else if status.Healthy {
			healthyComponents = append(healthyComponents, name)
		}
	}
	
	return &SystemDegradationStatus{
		Mode:               gdm.mode,
		OverallLevel:       overallLevel,
		Components:         components,
		DegradedComponents: degradedComponents,
		HealthyComponents:  healthyComponents,
		LastUpdate:         time.Now(),
		AutoDegradeEnabled: gdm.autoDegrade,
	}
}

// updateComponentStatus updates component status
func (gdm *gracefulDegradationManagerImpl) updateComponentStatus(componentName string, level DegradationLevel, reason string) {
	status := gdm.componentStatus[componentName]
	if status == nil {
		status = &ComponentDegradationStatus{
			ComponentName: componentName,
		}
		gdm.componentStatus[componentName] = status
	}
	
	status.Level = level
	status.DegradationReason = reason
	
	if level > DegradationLevelNone {
		status.LastDegradation = time.Now()
	} else {
		status.LastRestoration = time.Now()
	}
	
	// Update feature availability
	if component, exists := gdm.components[componentName]; exists {
		info := component.GetComponentInfo()
		if features, exists := info.FeatureMap[level]; exists {
			status.AvailableFeatures = features
		}
		
		// Calculate disabled features
		allFeatures := info.FeatureMap[DegradationLevelNone]
		status.DisabledFeatures = []string{}
		for _, feature := range allFeatures {
			available := false
			for _, availableFeature := range status.AvailableFeatures {
				if feature == availableFeature {
					available = true
					break
				}
			}
			if !available {
				status.DisabledFeatures = append(status.DisabledFeatures, feature)
			}
		}
	}
}

// handleHealthChange handles health changes from health checker
func (gdm *gracefulDegradationManagerImpl) handleHealthChange(componentName string, oldHealth, newHealth *ComponentHealth) {
	if !gdm.autoDegrade {
		return
	}
	
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	component, exists := gdm.components[componentName]
	if !exists {
		return
	}
	
	// Update health tracking
	if newHealth.Status == HealthStatusHealthy {
		gdm.healthSuccesses[componentName]++
		gdm.healthFailures[componentName] = 0
	} else {
		gdm.healthFailures[componentName]++
		gdm.healthSuccesses[componentName] = 0
	}
	
	// Check degradation rules
	rule, exists := gdm.config.ComponentRules[componentName]
	if !exists {
		// Use default rule
		rule = &ComponentDegradationRule{
			ComponentName:       componentName,
			HealthThresholds:    map[HealthStatus]DegradationLevel{
				HealthStatusUnhealthy: DegradationLevelModerate,
				HealthStatusCritical:  DegradationLevelSevere,
			},
			AutoRestore:         true,
			RestoreDelay:        30 * time.Second,
			MaxDegradationLevel: DegradationLevelSevere,
		}
	}
	
	// Apply degradation based on health status
	if degradationLevel, exists := rule.HealthThresholds[newHealth.Status]; exists {
		if gdm.healthFailures[componentName] >= gdm.config.DegradationThreshold {
			if degradationLevel <= rule.MaxDegradationLevel {
				component.Degrade(degradationLevel)
				gdm.updateComponentStatus(componentName, degradationLevel, fmt.Sprintf("Auto-degradation due to health status: %s", newHealth.Status.String()))
			}
		}
	}
	
	// Auto-restore if health improves
	if rule.AutoRestore && newHealth.Status == HealthStatusHealthy {
		if gdm.healthSuccesses[componentName] >= gdm.config.RestorationThreshold {
			component.Restore()
			gdm.updateComponentStatus(componentName, DegradationLevelNone, "Auto-restoration due to improved health")
		}
	}
}

// sendNotification sends a degradation event notification
func (gdm *gracefulDegradationManagerImpl) sendNotification(event *DegradationEvent) {
	if gdm.config.EnableNotifications && gdm.config.NotificationCallback != nil {
		go gdm.config.NotificationCallback(event)
	}
}

// monitoringLoop runs background monitoring
func (gdm *gracefulDegradationManagerImpl) monitoringLoop() {
	ticker := time.NewTicker(gdm.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-gdm.ctx.Done():
			return
		case <-ticker.C:
			gdm.performHealthBasedDegradation()
		}
	}
}

// performHealthBasedDegradation performs health-based degradation checks
func (gdm *gracefulDegradationManagerImpl) performHealthBasedDegradation() {
	if gdm.healthChecker == nil {
		return
	}
	
	systemHealth, err := gdm.healthChecker.GetSystemHealth()
	if err != nil {
		return
	}
	
	gdm.mu.Lock()
	defer gdm.mu.Unlock()
	
	// Apply system-wide degradation rules
	for _, rule := range gdm.config.SystemRules {
		// Simplified rule evaluation - in practice would be more sophisticated
		if gdm.evaluateSystemRule(rule, systemHealth) {
			for _, componentName := range rule.Components {
				if component, exists := gdm.components[componentName]; exists {
					component.Degrade(rule.Action)
					gdm.updateComponentStatus(componentName, rule.Action, fmt.Sprintf("System rule: %s", rule.Condition))
				}
			}
		}
	}
}

// evaluateSystemRule evaluates a system degradation rule
func (gdm *gracefulDegradationManagerImpl) evaluateSystemRule(rule *SystemDegradationRule, systemHealth *SystemHealth) bool {
	// Simplified rule evaluation - in practice would parse and evaluate complex conditions
	switch rule.Condition {
	case "critical_failures > 0":
		return len(systemHealth.CriticalFailures) > 0
	case "unhealthy_components > 2":
		return systemHealth.Summary.UnhealthyComponents > 2
	case "degraded_components > 5":
		return systemHealth.Summary.DegradedComponents > 5
	default:
		return false
	}
}