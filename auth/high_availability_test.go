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
	"testing"
	"time"
)

// TestCircuitBreakerBasicFunctionality tests basic circuit breaker functionality
func TestCircuitBreakerBasicFunctionality(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	config.FailureThreshold = 3
	config.OpenTimeout = 100 * time.Millisecond
	
	cb := NewCircuitBreaker(config)
	cb.Start()
	defer cb.Stop()
	
	// Test initial state
	if cb.GetState() != StateClosed {
		t.Errorf("Expected initial state to be closed, got %s", cb.GetState().String())
	}
	
	// Test successful operations
	for i := 0; i < 5; i++ {
		err := cb.Execute(func() error {
			return nil // Success
		})
		if err != nil {
			t.Errorf("Expected successful operation, got error: %v", err)
		}
	}
	
	// Test failures to trigger opening
	for i := 0; i < 3; i++ {
		err := cb.Execute(func() error {
			return fmt.Errorf("simulated failure")
		})
		if err == nil {
			t.Error("Expected operation to fail")
		}
	}
	
	// Circuit should now be open
	if cb.GetState() != StateOpen {
		t.Errorf("Expected circuit to be open after failures, got %s", cb.GetState().String())
	}
	
	// Test that operations are rejected when open
	err := cb.Execute(func() error {
		return nil
	})
	if err == nil {
		t.Error("Expected operation to be rejected when circuit is open")
	}
	
	// Wait for circuit to go to half-open
	time.Sleep(150 * time.Millisecond)
	
	// Test half-open state
	err = cb.Execute(func() error {
		return nil // Success
	})
	if err != nil {
		t.Errorf("Expected operation to succeed in half-open state, got: %v", err)
	}
	
	// After successful operations, circuit should close
	for i := 0; i < 3; i++ {
		cb.Execute(func() error {
			return nil
		})
	}
	
	if cb.GetState() != StateClosed {
		t.Errorf("Expected circuit to be closed after successful operations, got %s", cb.GetState().String())
	}
}

// TestCircuitBreakerStats tests circuit breaker statistics
func TestCircuitBreakerStats(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	config.FailureThreshold = 2
	
	cb := NewCircuitBreaker(config)
	cb.Start()
	defer cb.Stop()
	
	// Perform some operations
	cb.Execute(func() error { return nil })                        // Success
	cb.Execute(func() error { return fmt.Errorf("failure") })      // Failure
	cb.Execute(func() error { return nil })                        // Success
	cb.Execute(func() error { return fmt.Errorf("failure") })      // Failure
	cb.Execute(func() error { return fmt.Errorf("failure") })      // Failure (should open circuit)
	
	stats := cb.GetStats()
	
	if stats.TotalRequests != 5 {
		t.Errorf("Expected 5 total requests, got %d", stats.TotalRequests)
	}
	
	if stats.SuccessfulRequests != 2 {
		t.Errorf("Expected 2 successful requests, got %d", stats.SuccessfulRequests)
	}
	
	if stats.FailedRequests != 3 {
		t.Errorf("Expected 3 failed requests, got %d", stats.FailedRequests)
	}
	
	if stats.State != StateOpen {
		t.Errorf("Expected circuit to be open, got %s", stats.State.String())
	}
	
	if stats.StateChanges == 0 {
		t.Error("Expected at least one state change")
	}
}

// TestHealthCheckerBasicFunctionality tests basic health checker functionality
func TestHealthCheckerBasicFunctionality(t *testing.T) {
	config := DefaultHealthCheckerConfig()
	config.CheckInterval = 50 * time.Millisecond
	
	hc := NewHealthChecker(config)
	
	// Create a mock component
	mockComponent := &MockHealthCheckComponent{
		name:    "test_component",
		healthy: true,
	}
	
	// Register component
	err := hc.RegisterComponent("test_component", mockComponent)
	if err != nil {
		t.Fatalf("Failed to register component: %v", err)
	}
	
	// Check component health
	health, err := hc.CheckHealth("test_component")
	if err != nil {
		t.Fatalf("Failed to check health: %v", err)
	}
	
	if health.Status != HealthStatusHealthy {
		t.Errorf("Expected healthy status, got %s", health.Status.String())
	}
	
	if health.ComponentName != "test_component" {
		t.Errorf("Expected component name 'test_component', got %s", health.ComponentName)
	}
	
	// Make component unhealthy
	mockComponent.healthy = false
	
	health, err = hc.CheckHealth("test_component")
	if err != nil {
		t.Fatalf("Failed to check health: %v", err)
	}
	
	if health.Status != HealthStatusUnhealthy {
		t.Errorf("Expected unhealthy status, got %s", health.Status.String())
	}
	
	// Test system health
	systemHealth, err := hc.CheckAllHealth()
	if err != nil {
		t.Fatalf("Failed to check system health: %v", err)
	}
	
	if systemHealth.Status != HealthStatusUnhealthy {
		t.Errorf("Expected system to be unhealthy, got %s", systemHealth.Status.String())
	}
	
	if systemHealth.Summary.UnhealthyComponents != 1 {
		t.Errorf("Expected 1 unhealthy component, got %d", systemHealth.Summary.UnhealthyComponents)
	}
}

// TestHealthCheckerMonitoring tests continuous health monitoring
func TestHealthCheckerMonitoring(t *testing.T) {
	config := DefaultHealthCheckerConfig()
	config.CheckInterval = 50 * time.Millisecond
	
	hc := NewHealthChecker(config)
	
	// Create mock component
	mockComponent := &MockHealthCheckComponent{
		name:    "monitored_component",
		healthy: true,
	}
	
	hc.RegisterComponent("monitored_component", mockComponent)
	
	// Set up health change callback
	var healthChanges []string
	var mu sync.Mutex
	
	hc.SetHealthChangeCallback(func(componentName string, oldHealth, newHealth *ComponentHealth) {
		mu.Lock()
		defer mu.Unlock()
		healthChanges = append(healthChanges, fmt.Sprintf("%s: %s -> %s", 
			componentName, oldHealth.Status.String(), newHealth.Status.String()))
	})
	
	// Start monitoring
	err := hc.StartMonitoring()
	if err != nil {
		t.Fatalf("Failed to start monitoring: %v", err)
	}
	defer hc.StopMonitoring()
	
	// Wait for initial health check
	time.Sleep(100 * time.Millisecond)
	
	// Change component health
	mockComponent.healthy = false
	
	// Wait for health change to be detected
	time.Sleep(150 * time.Millisecond)
	
	// Check that health change was detected
	mu.Lock()
	if len(healthChanges) == 0 {
		t.Error("Expected health change to be detected")
	}
	mu.Unlock()
	
	// Verify monitoring is active
	if !hc.IsMonitoring() {
		t.Error("Expected monitoring to be active")
	}
}

// TestGracefulDegradationBasicFunctionality tests basic graceful degradation functionality
func TestGracefulDegradationBasicFunctionality(t *testing.T) {
	config := DefaultDegradationConfig()
	gdm := NewGracefulDegradationManager(config)
	
	// Create mock degradable component
	mockComponent := &MockDegradableComponent{
		name:     "test_component",
		healthy:  true,
		level:    DegradationLevelNone,
		features: map[DegradationLevel][]string{
			DegradationLevelNone:     {"feature1", "feature2", "feature3"},
			DegradationLevelMinor:    {"feature1", "feature2"},
			DegradationLevelModerate: {"feature1"},
			DegradationLevelSevere:   {},
		},
	}
	
	// Register component
	err := gdm.RegisterComponent("test_component", mockComponent)
	if err != nil {
		t.Fatalf("Failed to register component: %v", err)
	}
	
	// Test initial status
	status := gdm.GetSystemStatus()
	if status.OverallLevel != DegradationLevelNone {
		t.Errorf("Expected no degradation initially, got %s", status.OverallLevel.String())
	}
	
	// Test component degradation
	err = gdm.DegradeComponent("test_component", DegradationLevelMinor)
	if err != nil {
		t.Fatalf("Failed to degrade component: %v", err)
	}
	
	if mockComponent.level != DegradationLevelMinor {
		t.Errorf("Expected component to be degraded to minor level, got %s", mockComponent.level.String())
	}
	
	// Check component status
	componentStatus, err := gdm.GetComponentStatus("test_component")
	if err != nil {
		t.Fatalf("Failed to get component status: %v", err)
	}
	
	if componentStatus.Level != DegradationLevelMinor {
		t.Errorf("Expected component status to show minor degradation, got %s", componentStatus.Level.String())
	}
	
	if len(componentStatus.AvailableFeatures) != 2 {
		t.Errorf("Expected 2 available features, got %d", len(componentStatus.AvailableFeatures))
	}
	
	// Test component restoration
	err = gdm.RestoreComponent("test_component")
	if err != nil {
		t.Fatalf("Failed to restore component: %v", err)
	}
	
	if mockComponent.level != DegradationLevelNone {
		t.Errorf("Expected component to be restored, got %s", mockComponent.level.String())
	}
}

// TestGracefulDegradationModes tests different degradation modes
func TestGracefulDegradationModes(t *testing.T) {
	config := DefaultDegradationConfig()
	gdm := NewGracefulDegradationManager(config)
	
	// Create mock components
	criticalComponent := &MockDegradableComponent{
		name:     "critical_component",
		healthy:  true,
		level:    DegradationLevelNone,
		critical: true,
		supportedLevels: []DegradationLevel{
			DegradationLevelNone, DegradationLevelMinor, DegradationLevelModerate,
		},
	}
	
	nonCriticalComponent := &MockDegradableComponent{
		name:     "non_critical_component",
		healthy:  true,
		level:    DegradationLevelNone,
		critical: false,
		supportedLevels: []DegradationLevel{
			DegradationLevelNone, DegradationLevelMinor, DegradationLevelModerate, DegradationLevelSevere,
		},
	}
	
	gdm.RegisterComponent("critical_component", criticalComponent)
	gdm.RegisterComponent("non_critical_component", nonCriticalComponent)
	
	// Test conservative mode
	err := gdm.SetDegradationMode(DegradationModeConservative)
	if err != nil {
		t.Fatalf("Failed to set conservative mode: %v", err)
	}
	
	// Critical component should not be degraded in conservative mode
	if criticalComponent.level != DegradationLevelNone {
		t.Errorf("Expected critical component to remain at none level, got %s", criticalComponent.level.String())
	}
	
	// Non-critical component should be degraded to minor level
	if nonCriticalComponent.level != DegradationLevelMinor {
		t.Errorf("Expected non-critical component to be degraded to minor level, got %s", nonCriticalComponent.level.String())
	}
	
	// Test aggressive mode
	err = gdm.SetDegradationMode(DegradationModeAggressive)
	if err != nil {
		t.Fatalf("Failed to set aggressive mode: %v", err)
	}
	
	// Non-critical component should be degraded to moderate level
	if nonCriticalComponent.level != DegradationLevelModerate {
		t.Errorf("Expected non-critical component to be degraded to moderate level, got %s", nonCriticalComponent.level.String())
	}
	
	// Test normal mode restoration
	err = gdm.SetDegradationMode(DegradationModeNormal)
	if err != nil {
		t.Fatalf("Failed to set normal mode: %v", err)
	}
	
	// All components should be restored
	if criticalComponent.level != DegradationLevelNone {
		t.Errorf("Expected critical component to be restored, got %s", criticalComponent.level.String())
	}
	
	if nonCriticalComponent.level != DegradationLevelNone {
		t.Errorf("Expected non-critical component to be restored, got %s", nonCriticalComponent.level.String())
	}
}

// TestIntegratedHighAvailability tests integrated high availability functionality
func TestIntegratedHighAvailability(t *testing.T) {
	// Create integrated system
	healthChecker := NewHealthChecker(DefaultHealthCheckerConfig())
	degradationManager := NewGracefulDegradationManager(DefaultDegradationConfig())
	circuitBreaker := NewCircuitBreaker(DefaultCircuitBreakerConfig())
	
	// Create mock components
	mockCache := &MockCacheComponent{healthy: true}
	mockSessionManager := &MockSessionManagerComponent{healthy: true}
	
	// Register health checkers
	healthChecker.RegisterComponent("cache", &MockHealthCheckComponent{
		name:    "cache",
		healthy: true,
	})
	healthChecker.RegisterComponent("session_manager", &MockHealthCheckComponent{
		name:    "session_manager",
		healthy: true,
	})
	
	// Register degradable components
	degradationManager.RegisterComponent("cache", &MockDegradableComponent{
		name:    "cache",
		healthy: true,
		level:   DegradationLevelNone,
		supportedLevels: []DegradationLevel{
			DegradationLevelNone, DegradationLevelMinor, DegradationLevelModerate,
		},
	})
	
	// Set up integration
	degradationManager.SetHealthChecker(healthChecker)
	degradationManager.EnableAutoDegrade(true)
	
	// Start all components
	healthChecker.StartMonitoring()
	degradationManager.Start()
	circuitBreaker.Start()
	
	defer func() {
		healthChecker.StopMonitoring()
		degradationManager.Stop()
		circuitBreaker.Stop()
	}()
	
	// Test normal operation
	systemHealth, err := healthChecker.GetSystemHealth()
	if err != nil {
		t.Fatalf("Failed to get system health: %v", err)
	}
	
	if systemHealth.Status != HealthStatusHealthy {
		t.Errorf("Expected system to be healthy, got %s", systemHealth.Status.String())
	}
	
	// Test circuit breaker with successful operations
	for i := 0; i < 10; i++ {
		err := circuitBreaker.Execute(func() error {
			if mockCache.healthy {
				return nil
			}
			return fmt.Errorf("cache unavailable")
		})
		if err != nil {
			t.Errorf("Expected successful operation, got error: %v", err)
		}
	}
	
	// Simulate component failure
	mockCache.healthy = false
	
	// Circuit breaker should start failing
	failureCount := 0
	for i := 0; i < 10; i++ {
		err := circuitBreaker.Execute(func() error {
			if mockCache.healthy {
				return nil
			}
			return fmt.Errorf("cache unavailable")
		})
		if err != nil {
			failureCount++
		}
	}
	
	if failureCount == 0 {
		t.Error("Expected some failures when component is unhealthy")
	}
	
	// Circuit should eventually open
	if circuitBreaker.GetState() != StateOpen {
		t.Errorf("Expected circuit to be open after failures, got %s", circuitBreaker.GetState().String())
	}
	
	// Test system recovery
	mockCache.healthy = true
	
	// Wait for circuit to go half-open and then close
	time.Sleep(100 * time.Millisecond)
	
	// Test successful operations after recovery
	successCount := 0
	for i := 0; i < 5; i++ {
		err := circuitBreaker.Execute(func() error {
			if mockCache.healthy {
				return nil
			}
			return fmt.Errorf("cache unavailable")
		})
		if err == nil {
			successCount++
		}
	}
	
	if successCount == 0 {
		t.Error("Expected some successful operations after recovery")
	}
}

// TestHighAvailabilityUnderLoad tests high availability components under load
func TestHighAvailabilityUnderLoad(t *testing.T) {
	// Create components
	circuitBreaker := NewCircuitBreaker(DefaultCircuitBreakerConfig())
	healthChecker := NewHealthChecker(DefaultHealthCheckerConfig())
	
	// Register multiple components
	for i := 0; i < 10; i++ {
		componentName := fmt.Sprintf("component_%d", i)
		healthChecker.RegisterComponent(componentName, &MockHealthCheckComponent{
			name:    componentName,
			healthy: true,
		})
	}
	
	circuitBreaker.Start()
	healthChecker.StartMonitoring()
	
	defer func() {
		circuitBreaker.Stop()
		healthChecker.StopMonitoring()
	}()
	
	// Test concurrent operations
	numGoroutines := 100
	operationsPerGoroutine := 100
	
	var wg sync.WaitGroup
	successCount := int64(0)
	failureCount := int64(0)
	var mu sync.Mutex
	
	start := time.Now()
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerGoroutine; j++ {
				// Circuit breaker operations
				err := circuitBreaker.Execute(func() error {
					// Simulate occasional failures
					if (goroutineID*operationsPerGoroutine+j)%50 == 0 {
						return fmt.Errorf("simulated failure")
					}
					return nil
				})
				
				mu.Lock()
				if err == nil {
					successCount++
				} else {
					failureCount++
				}
				mu.Unlock()
				
				// Health check operations
				if j%10 == 0 {
					componentName := fmt.Sprintf("component_%d", goroutineID%10)
					healthChecker.CheckHealth(componentName)
				}
			}
		}(i)
	}
	
	wg.Wait()
	totalTime := time.Since(start)
	
	totalOperations := int64(numGoroutines * operationsPerGoroutine)
	
	t.Logf("High availability load test results:")
	t.Logf("  Total operations: %d", totalOperations)
	t.Logf("  Successful operations: %d", successCount)
	t.Logf("  Failed operations: %d", failureCount)
	t.Logf("  Total time: %v", totalTime)
	t.Logf("  Operations per second: %.2f", float64(totalOperations)/totalTime.Seconds())
	
	// Verify circuit breaker stats
	stats := circuitBreaker.GetStats()
	t.Logf("Circuit breaker stats:")
	t.Logf("  Total requests: %d", stats.TotalRequests)
	t.Logf("  Successful requests: %d", stats.SuccessfulRequests)
	t.Logf("  Failed requests: %d", stats.FailedRequests)
	t.Logf("  State changes: %d", stats.StateChanges)
	
	// Verify system health
	systemHealth, err := healthChecker.GetSystemHealth()
	if err != nil {
		t.Fatalf("Failed to get system health: %v", err)
	}
	
	t.Logf("System health:")
	t.Logf("  Status: %s", systemHealth.Status.String())
	t.Logf("  Total components: %d", systemHealth.Summary.TotalComponents)
	t.Logf("  Healthy components: %d", systemHealth.Summary.HealthyComponents)
	
	// Performance assertions
	if totalTime > 30*time.Second {
		t.Errorf("Load test took too long: %v", totalTime)
	}
	
	if successCount == 0 {
		t.Error("No successful operations recorded")
	}
	
	if stats.TotalRequests == 0 {
		t.Error("No requests recorded by circuit breaker")
	}
}

// Mock components for testing

type MockHealthCheckComponent struct {
	name    string
	healthy bool
	mu      sync.RWMutex
}

func (m *MockHealthCheckComponent) CheckHealth(ctx context.Context) (*ComponentHealth, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	status := HealthStatusHealthy
	message := "Component is healthy"
	
	if !m.healthy {
		status = HealthStatusUnhealthy
		message = "Component is unhealthy"
	}
	
	return &ComponentHealth{
		ComponentName: m.name,
		Status:        status,
		Message:       message,
		LastCheck:     time.Now(),
		ResponseTime:  10 * time.Millisecond,
	}, nil
}

func (m *MockHealthCheckComponent) GetComponentInfo() *ComponentInfo {
	return &ComponentInfo{
		Name:        m.name,
		Version:     "1.0.0",
		Description: "Mock component for testing",
		Critical:    false,
	}
}

type MockDegradableComponent struct {
	name            string
	healthy         bool
	level           DegradationLevel
	critical        bool
	supportedLevels []DegradationLevel
	features        map[DegradationLevel][]string
	mu              sync.RWMutex
}

func (m *MockDegradableComponent) Degrade(level DegradationLevel) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Check if level is supported
	supported := false
	for _, supportedLevel := range m.supportedLevels {
		if supportedLevel == level {
			supported = true
			break
		}
	}
	
	if !supported {
		return fmt.Errorf("degradation level %s not supported", level.String())
	}
	
	m.level = level
	return nil
}

func (m *MockDegradableComponent) Restore() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.level = DegradationLevelNone
	return nil
}

func (m *MockDegradableComponent) GetDegradationStatus() *ComponentDegradationStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	availableFeatures := []string{}
	if features, exists := m.features[m.level]; exists {
		availableFeatures = features
	}
	
	return &ComponentDegradationStatus{
		ComponentName:     m.name,
		Level:             m.level,
		Healthy:           m.healthy,
		LastDegradation:   time.Now(),
		AvailableFeatures: availableFeatures,
	}
}

func (m *MockDegradableComponent) GetComponentInfo() *DegradableComponentInfo {
	return &DegradableComponentInfo{
		Name:            m.name,
		Description:     "Mock degradable component",
		Critical:        m.critical,
		SupportedLevels: m.supportedLevels,
		FeatureMap:      m.features,
	}
}

func (m *MockDegradableComponent) IsHealthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthy
}

type MockCacheComponent struct {
	healthy bool
	mu      sync.RWMutex
}

func (m *MockCacheComponent) IsHealthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthy
}

type MockSessionManagerComponent struct {
	healthy bool
	mu      sync.RWMutex
}

func (m *MockSessionManagerComponent) IsHealthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthy
}