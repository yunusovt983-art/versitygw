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

// HealthChecker provides health checking functionality for authentication components
type HealthChecker interface {
	// Component registration
	RegisterComponent(name string, checker ComponentHealthChecker) error
	UnregisterComponent(name string) error
	
	// Health checks
	CheckHealth(componentName string) (*ComponentHealth, error)
	CheckAllHealth() (*SystemHealth, error)
	
	// Continuous monitoring
	StartMonitoring() error
	StopMonitoring() error
	IsMonitoring() bool
	
	// Health status
	GetSystemHealth() (*SystemHealth, error)
	GetComponentHealth(componentName string) (*ComponentHealth, error)
	GetHealthHistory(componentName string, duration time.Duration) ([]*ComponentHealth, error)
	
	// Alerting
	SetHealthChangeCallback(callback HealthChangeCallback) error
	
	// Configuration
	UpdateConfig(config *HealthCheckerConfig) error
}

// ComponentHealthChecker defines the interface for component-specific health checks
type ComponentHealthChecker interface {
	CheckHealth(ctx context.Context) (*ComponentHealth, error)
	GetComponentInfo() *ComponentInfo
}

// ComponentHealth represents the health status of a component
type ComponentHealth struct {
	ComponentName   string                 `json:"component_name"`
	Status          HealthStatus           `json:"status"`
	Message         string                 `json:"message"`
	LastCheck       time.Time              `json:"last_check"`
	ResponseTime    time.Duration          `json:"response_time"`
	Details         map[string]interface{} `json:"details,omitempty"`
	Metrics         *ComponentMetrics      `json:"metrics,omitempty"`
	Dependencies    []string               `json:"dependencies,omitempty"`
}

// ComponentInfo provides information about a component
type ComponentInfo struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Description  string   `json:"description"`
	Dependencies []string `json:"dependencies"`
	Critical     bool     `json:"critical"`
}

// ComponentMetrics provides metrics for a component
type ComponentMetrics struct {
	CPUUsage       float64 `json:"cpu_usage"`
	MemoryUsage    float64 `json:"memory_usage"`
	ActiveRequests int     `json:"active_requests"`
	ErrorRate      float64 `json:"error_rate"`
	Uptime         time.Duration `json:"uptime"`
}

// SystemHealth represents the overall system health
type SystemHealth struct {
	Status           HealthStatus                    `json:"status"`
	Message          string                          `json:"message"`
	LastCheck        time.Time                       `json:"last_check"`
	Components       map[string]*ComponentHealth     `json:"components"`
	CriticalFailures []string                        `json:"critical_failures,omitempty"`
	Warnings         []string                        `json:"warnings,omitempty"`
	Summary          *HealthSummary                  `json:"summary"`
}

// HealthSummary provides a summary of system health
type HealthSummary struct {
	TotalComponents    int `json:"total_components"`
	HealthyComponents  int `json:"healthy_components"`
	DegradedComponents int `json:"degraded_components"`
	UnhealthyComponents int `json:"unhealthy_components"`
	CriticalComponents int `json:"critical_components"`
}

// HealthStatus represents the health status of a component or system
type HealthStatus int

const (
	HealthStatusUnknown HealthStatus = iota
	HealthStatusHealthy
	HealthStatusDegraded
	HealthStatusUnhealthy
	HealthStatusCritical
)

// String returns string representation of HealthStatus
func (s HealthStatus) String() string {
	switch s {
	case HealthStatusHealthy:
		return "healthy"
	case HealthStatusDegraded:
		return "degraded"
	case HealthStatusUnhealthy:
		return "unhealthy"
	case HealthStatusCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// HealthChangeCallback is called when component health changes
type HealthChangeCallback func(componentName string, oldHealth, newHealth *ComponentHealth)

// HealthCheckerConfig holds configuration for health checker
type HealthCheckerConfig struct {
	CheckInterval       time.Duration `json:"check_interval"`
	Timeout             time.Duration `json:"timeout"`
	RetryAttempts       int           `json:"retry_attempts"`
	RetryDelay          time.Duration `json:"retry_delay"`
	HistoryRetention    time.Duration `json:"history_retention"`
	EnableDetailedMetrics bool        `json:"enable_detailed_metrics"`
	CriticalThreshold   time.Duration `json:"critical_threshold"`
	DegradedThreshold   time.Duration `json:"degraded_threshold"`
}

// DefaultHealthCheckerConfig returns default health checker configuration
func DefaultHealthCheckerConfig() *HealthCheckerConfig {
	return &HealthCheckerConfig{
		CheckInterval:         30 * time.Second,
		Timeout:               10 * time.Second,
		RetryAttempts:         3,
		RetryDelay:            1 * time.Second,
		HistoryRetention:      24 * time.Hour,
		EnableDetailedMetrics: true,
		CriticalThreshold:     5 * time.Second,
		DegradedThreshold:     2 * time.Second,
	}
}

// healthCheckerImpl implements HealthChecker
type healthCheckerImpl struct {
	config             *HealthCheckerConfig
	components         map[string]ComponentHealthChecker
	componentHealth    map[string]*ComponentHealth
	healthHistory      map[string][]*ComponentHealth
	changeCallback     HealthChangeCallback
	mu                 sync.RWMutex
	
	// Background monitoring
	ctx                context.Context
	cancel             context.CancelFunc
	monitoring         bool
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(config *HealthCheckerConfig) HealthChecker {
	if config == nil {
		config = DefaultHealthCheckerConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &healthCheckerImpl{
		config:          config,
		components:      make(map[string]ComponentHealthChecker),
		componentHealth: make(map[string]*ComponentHealth),
		healthHistory:   make(map[string][]*ComponentHealth),
		ctx:             ctx,
		cancel:          cancel,
	}
}

// RegisterComponent registers a component for health checking
func (hc *healthCheckerImpl) RegisterComponent(name string, checker ComponentHealthChecker) error {
	if name == "" {
		return fmt.Errorf("component name cannot be empty")
	}
	if checker == nil {
		return fmt.Errorf("component checker cannot be nil")
	}
	
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	hc.components[name] = checker
	
	// Perform initial health check
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), hc.config.Timeout)
		defer cancel()
		
		health, err := checker.CheckHealth(ctx)
		if err != nil {
			health = &ComponentHealth{
				ComponentName: name,
				Status:        HealthStatusUnhealthy,
				Message:       fmt.Sprintf("Initial health check failed: %v", err),
				LastCheck:     time.Now(),
			}
		}
		
		hc.mu.Lock()
		hc.componentHealth[name] = health
		hc.addToHistory(name, health)
		hc.mu.Unlock()
	}()
	
	return nil
}

// UnregisterComponent unregisters a component
func (hc *healthCheckerImpl) UnregisterComponent(name string) error {
	if name == "" {
		return fmt.Errorf("component name cannot be empty")
	}
	
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	delete(hc.components, name)
	delete(hc.componentHealth, name)
	delete(hc.healthHistory, name)
	
	return nil
}

// CheckHealth checks the health of a specific component
func (hc *healthCheckerImpl) CheckHealth(componentName string) (*ComponentHealth, error) {
	if componentName == "" {
		return nil, fmt.Errorf("component name cannot be empty")
	}
	
	hc.mu.RLock()
	checker, exists := hc.components[componentName]
	hc.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("component not found: %s", componentName)
	}
	
	// Perform health check with retries
	var health *ComponentHealth
	var err error
	
	for attempt := 0; attempt <= hc.config.RetryAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), hc.config.Timeout)
		
		start := time.Now()
		health, err = checker.CheckHealth(ctx)
		responseTime := time.Since(start)
		
		cancel()
		
		if err == nil && health != nil {
			health.ResponseTime = responseTime
			health.LastCheck = time.Now()
			
			// Determine status based on response time if not set
			if health.Status == HealthStatusUnknown {
				health.Status = hc.determineStatusFromResponseTime(responseTime)
			}
			
			break
		}
		
		// Wait before retry
		if attempt < hc.config.RetryAttempts {
			time.Sleep(hc.config.RetryDelay)
		}
	}
	
	// If all attempts failed, create unhealthy status
	if err != nil || health == nil {
		health = &ComponentHealth{
			ComponentName: componentName,
			Status:        HealthStatusUnhealthy,
			Message:       fmt.Sprintf("Health check failed after %d attempts: %v", hc.config.RetryAttempts+1, err),
			LastCheck:     time.Now(),
		}
	}
	
	// Store health status and history
	hc.mu.Lock()
	oldHealth := hc.componentHealth[componentName]
	hc.componentHealth[componentName] = health
	hc.addToHistory(componentName, health)
	hc.mu.Unlock()
	
	// Notify of health changes
	if hc.changeCallback != nil && oldHealth != nil && oldHealth.Status != health.Status {
		go hc.changeCallback(componentName, oldHealth, health)
	}
	
	return health, nil
}

// CheckAllHealth checks the health of all registered components
func (hc *healthCheckerImpl) CheckAllHealth() (*SystemHealth, error) {
	hc.mu.RLock()
	componentNames := make([]string, 0, len(hc.components))
	for name := range hc.components {
		componentNames = append(componentNames, name)
	}
	hc.mu.RUnlock()
	
	// Check all components concurrently
	type healthResult struct {
		name   string
		health *ComponentHealth
		err    error
	}
	
	results := make(chan healthResult, len(componentNames))
	
	for _, name := range componentNames {
		go func(componentName string) {
			health, err := hc.CheckHealth(componentName)
			results <- healthResult{
				name:   componentName,
				health: health,
				err:    err,
			}
		}(name)
	}
	
	// Collect results
	componentHealths := make(map[string]*ComponentHealth)
	var criticalFailures []string
	var warnings []string
	
	for i := 0; i < len(componentNames); i++ {
		result := <-results
		
		if result.err != nil {
			warnings = append(warnings, fmt.Sprintf("Failed to check %s: %v", result.name, result.err))
			continue
		}
		
		componentHealths[result.name] = result.health
		
		// Check for critical failures
		if result.health.Status == HealthStatusCritical || result.health.Status == HealthStatusUnhealthy {
			// Check if component is critical
			hc.mu.RLock()
			checker := hc.components[result.name]
			hc.mu.RUnlock()
			
			if checker != nil {
				info := checker.GetComponentInfo()
				if info.Critical {
					criticalFailures = append(criticalFailures, result.name)
				}
			}
		}
	}
	
	// Determine overall system health
	systemHealth := &SystemHealth{
		LastCheck:        time.Now(),
		Components:       componentHealths,
		CriticalFailures: criticalFailures,
		Warnings:         warnings,
		Summary:          hc.calculateHealthSummary(componentHealths),
	}
	
	// Determine overall status
	if len(criticalFailures) > 0 {
		systemHealth.Status = HealthStatusCritical
		systemHealth.Message = fmt.Sprintf("%d critical component(s) failing", len(criticalFailures))
	} else if systemHealth.Summary.UnhealthyComponents > 0 {
		systemHealth.Status = HealthStatusUnhealthy
		systemHealth.Message = fmt.Sprintf("%d component(s) unhealthy", systemHealth.Summary.UnhealthyComponents)
	} else if systemHealth.Summary.DegradedComponents > 0 {
		systemHealth.Status = HealthStatusDegraded
		systemHealth.Message = fmt.Sprintf("%d component(s) degraded", systemHealth.Summary.DegradedComponents)
	} else {
		systemHealth.Status = HealthStatusHealthy
		systemHealth.Message = "All components healthy"
	}
	
	return systemHealth, nil
}

// StartMonitoring starts continuous health monitoring
func (hc *healthCheckerImpl) StartMonitoring() error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	if hc.monitoring {
		return nil
	}
	
	go hc.monitoringLoop()
	hc.monitoring = true
	
	return nil
}

// StopMonitoring stops continuous health monitoring
func (hc *healthCheckerImpl) StopMonitoring() error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	if !hc.monitoring {
		return nil
	}
	
	if hc.cancel != nil {
		hc.cancel()
	}
	
	hc.monitoring = false
	return nil
}

// IsMonitoring returns whether continuous monitoring is active
func (hc *healthCheckerImpl) IsMonitoring() bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.monitoring
}

// GetSystemHealth returns the current system health
func (hc *healthCheckerImpl) GetSystemHealth() (*SystemHealth, error) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	// Create system health from current component health
	componentHealths := make(map[string]*ComponentHealth)
	for name, health := range hc.componentHealth {
		// Create copy to avoid race conditions
		healthCopy := *health
		componentHealths[name] = &healthCopy
	}
	
	var criticalFailures []string
	for name, health := range componentHealths {
		if health.Status == HealthStatusCritical || health.Status == HealthStatusUnhealthy {
			if checker, exists := hc.components[name]; exists {
				info := checker.GetComponentInfo()
				if info.Critical {
					criticalFailures = append(criticalFailures, name)
				}
			}
		}
	}
	
	systemHealth := &SystemHealth{
		LastCheck:        time.Now(),
		Components:       componentHealths,
		CriticalFailures: criticalFailures,
		Summary:          hc.calculateHealthSummary(componentHealths),
	}
	
	// Determine overall status
	if len(criticalFailures) > 0 {
		systemHealth.Status = HealthStatusCritical
		systemHealth.Message = fmt.Sprintf("%d critical component(s) failing", len(criticalFailures))
	} else if systemHealth.Summary.UnhealthyComponents > 0 {
		systemHealth.Status = HealthStatusUnhealthy
		systemHealth.Message = fmt.Sprintf("%d component(s) unhealthy", systemHealth.Summary.UnhealthyComponents)
	} else if systemHealth.Summary.DegradedComponents > 0 {
		systemHealth.Status = HealthStatusDegraded
		systemHealth.Message = fmt.Sprintf("%d component(s) degraded", systemHealth.Summary.DegradedComponents)
	} else {
		systemHealth.Status = HealthStatusHealthy
		systemHealth.Message = "All components healthy"
	}
	
	return systemHealth, nil
}

// GetComponentHealth returns the current health of a specific component
func (hc *healthCheckerImpl) GetComponentHealth(componentName string) (*ComponentHealth, error) {
	if componentName == "" {
		return nil, fmt.Errorf("component name cannot be empty")
	}
	
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	health, exists := hc.componentHealth[componentName]
	if !exists {
		return nil, fmt.Errorf("component not found: %s", componentName)
	}
	
	// Return copy to avoid race conditions
	healthCopy := *health
	return &healthCopy, nil
}

// GetHealthHistory returns the health history for a component
func (hc *healthCheckerImpl) GetHealthHistory(componentName string, duration time.Duration) ([]*ComponentHealth, error) {
	if componentName == "" {
		return nil, fmt.Errorf("component name cannot be empty")
	}
	
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	
	history, exists := hc.healthHistory[componentName]
	if !exists {
		return []*ComponentHealth{}, nil
	}
	
	// Filter history by duration
	cutoff := time.Now().Add(-duration)
	var filteredHistory []*ComponentHealth
	
	for _, health := range history {
		if health.LastCheck.After(cutoff) {
			// Create copy to avoid race conditions
			healthCopy := *health
			filteredHistory = append(filteredHistory, &healthCopy)
		}
	}
	
	return filteredHistory, nil
}

// SetHealthChangeCallback sets the callback for health changes
func (hc *healthCheckerImpl) SetHealthChangeCallback(callback HealthChangeCallback) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	hc.changeCallback = callback
	return nil
}

// UpdateConfig updates the health checker configuration
func (hc *healthCheckerImpl) UpdateConfig(config *HealthCheckerConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	hc.config = config
	return nil
}

// Helper methods

// determineStatusFromResponseTime determines health status based on response time
func (hc *healthCheckerImpl) determineStatusFromResponseTime(responseTime time.Duration) HealthStatus {
	if responseTime > hc.config.CriticalThreshold {
		return HealthStatusCritical
	} else if responseTime > hc.config.DegradedThreshold {
		return HealthStatusDegraded
	}
	return HealthStatusHealthy
}

// calculateHealthSummary calculates health summary from component healths
func (hc *healthCheckerImpl) calculateHealthSummary(componentHealths map[string]*ComponentHealth) *HealthSummary {
	summary := &HealthSummary{
		TotalComponents: len(componentHealths),
	}
	
	for _, health := range componentHealths {
		switch health.Status {
		case HealthStatusHealthy:
			summary.HealthyComponents++
		case HealthStatusDegraded:
			summary.DegradedComponents++
		case HealthStatusUnhealthy:
			summary.UnhealthyComponents++
		case HealthStatusCritical:
			summary.CriticalComponents++
		}
	}
	
	return summary
}

// addToHistory adds a health check result to history
func (hc *healthCheckerImpl) addToHistory(componentName string, health *ComponentHealth) {
	if hc.healthHistory[componentName] == nil {
		hc.healthHistory[componentName] = make([]*ComponentHealth, 0)
	}
	
	// Add to history
	healthCopy := *health
	hc.healthHistory[componentName] = append(hc.healthHistory[componentName], &healthCopy)
	
	// Clean old history
	cutoff := time.Now().Add(-hc.config.HistoryRetention)
	var filteredHistory []*ComponentHealth
	
	for _, h := range hc.healthHistory[componentName] {
		if h.LastCheck.After(cutoff) {
			filteredHistory = append(filteredHistory, h)
		}
	}
	
	hc.healthHistory[componentName] = filteredHistory
}

// monitoringLoop runs continuous health monitoring
func (hc *healthCheckerImpl) monitoringLoop() {
	ticker := time.NewTicker(hc.config.CheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-hc.ctx.Done():
			return
		case <-ticker.C:
			hc.CheckAllHealth()
		}
	}
}

// Predefined component health checkers

// CacheHealthChecker checks the health of cache components
type CacheHealthChecker struct {
	cache EnhancedCache
	info  *ComponentInfo
}

// NewCacheHealthChecker creates a new cache health checker
func NewCacheHealthChecker(cache EnhancedCache) *CacheHealthChecker {
	return &CacheHealthChecker{
		cache: cache,
		info: &ComponentInfo{
			Name:        "enhanced_cache",
			Version:     "1.0.0",
			Description: "Enhanced authentication cache",
			Critical:    true,
		},
	}
}

// CheckHealth checks cache health
func (chc *CacheHealthChecker) CheckHealth(ctx context.Context) (*ComponentHealth, error) {
	start := time.Now()
	
	// Test cache operations
	testKey := fmt.Sprintf("health_check_%d", time.Now().UnixNano())
	testValue := "health_check_value"
	
	// Test set operation
	chc.cache.Set(testKey, testValue, 1*time.Minute, UserCredentials)
	
	// Test get operation
	value, found := chc.cache.Get(testKey, UserCredentials)
	if !found || value != testValue {
		return &ComponentHealth{
			ComponentName: chc.info.Name,
			Status:        HealthStatusUnhealthy,
			Message:       "Cache get/set operations failed",
			LastCheck:     time.Now(),
			ResponseTime:  time.Since(start),
		}, nil
	}
	
	// Get cache stats
	stats := chc.cache.GetStats()
	
	health := &ComponentHealth{
		ComponentName: chc.info.Name,
		Status:        HealthStatusHealthy,
		Message:       "Cache operations successful",
		LastCheck:     time.Now(),
		ResponseTime:  time.Since(start),
		Details: map[string]interface{}{
			"cache_size":    stats.Size,
			"hit_rate":      stats.HitRate(),
			"fallback_mode": stats.FallbackActive,
		},
	}
	
	// Determine status based on hit rate
	hitRate := stats.HitRate()
	if hitRate < 50 {
		health.Status = HealthStatusDegraded
		health.Message = fmt.Sprintf("Low cache hit rate: %.2f%%", hitRate)
	}
	
	return health, nil
}

// GetComponentInfo returns component information
func (chc *CacheHealthChecker) GetComponentInfo() *ComponentInfo {
	return chc.info
}

// SessionManagerHealthChecker checks the health of session manager
type SessionManagerHealthChecker struct {
	sessionManager EnhancedSessionManager
	info           *ComponentInfo
}

// NewSessionManagerHealthChecker creates a new session manager health checker
func NewSessionManagerHealthChecker(sessionManager EnhancedSessionManager) *SessionManagerHealthChecker {
	return &SessionManagerHealthChecker{
		sessionManager: sessionManager,
		info: &ComponentInfo{
			Name:        "session_manager",
			Version:     "1.0.0",
			Description: "Enhanced session manager",
			Critical:    true,
		},
	}
}

// CheckHealth checks session manager health
func (smhc *SessionManagerHealthChecker) CheckHealth(ctx context.Context) (*ComponentHealth, error) {
	start := time.Now()
	
	// Test session operations
	testUserID := fmt.Sprintf("health_check_user_%d", time.Now().UnixNano())
	metadata := &SessionMetadata{
		IPAddress: "127.0.0.1",
		UserAgent: "health_check",
	}
	
	// Test session creation
	session, err := smhc.sessionManager.CreateSession(testUserID, metadata)
	if err != nil {
		return &ComponentHealth{
			ComponentName: smhc.info.Name,
			Status:        HealthStatusUnhealthy,
			Message:       fmt.Sprintf("Session creation failed: %v", err),
			LastCheck:     time.Now(),
			ResponseTime:  time.Since(start),
		}, nil
	}
	
	// Test session validation
	_, err = smhc.sessionManager.ValidateSession(session.ID)
	if err != nil {
		return &ComponentHealth{
			ComponentName: smhc.info.Name,
			Status:        HealthStatusUnhealthy,
			Message:       fmt.Sprintf("Session validation failed: %v", err),
			LastCheck:     time.Now(),
			ResponseTime:  time.Since(start),
		}, nil
	}
	
	// Clean up test session
	smhc.sessionManager.TerminateSession(session.ID)
	
	// Get session stats
	stats := smhc.sessionManager.GetSessionStats()
	
	return &ComponentHealth{
		ComponentName: smhc.info.Name,
		Status:        HealthStatusHealthy,
		Message:       "Session manager operations successful",
		LastCheck:     time.Now(),
		ResponseTime:  time.Since(start),
		Details: map[string]interface{}{
			"active_sessions": stats.TotalActiveSessions,
			"created_sessions": stats.CreatedSessions,
			"expired_sessions": stats.ExpiredSessions,
		},
	}, nil
}

// GetComponentInfo returns component information
func (smhc *SessionManagerHealthChecker) GetComponentInfo() *ComponentInfo {
	return smhc.info
}