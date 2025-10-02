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

// CircuitBreaker provides circuit breaker functionality for authentication services
type CircuitBreaker interface {
	// Execute operations with circuit breaker protection
	Execute(operation func() error) error
	ExecuteWithContext(ctx context.Context, operation func(context.Context) error) error
	
	// State management
	GetState() CircuitBreakerState
	ForceOpen() error
	ForceClosed() error
	Reset() error
	
	// Statistics
	GetStats() *CircuitBreakerStats
	
	// Configuration
	UpdateConfig(config *CircuitBreakerConfig) error
	
	// Lifecycle
	Start() error
	Stop() error
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateHalfOpen
	StateOpen
)

// String returns string representation of CircuitBreakerState
func (s CircuitBreakerState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateHalfOpen:
		return "half-open"
	case StateOpen:
		return "open"
	default:
		return "unknown"
	}
}

// CircuitBreakerStats provides statistics about circuit breaker operations
type CircuitBreakerStats struct {
	State                CircuitBreakerState `json:"state"`
	TotalRequests        int64               `json:"total_requests"`
	SuccessfulRequests   int64               `json:"successful_requests"`
	FailedRequests       int64               `json:"failed_requests"`
	ConsecutiveFailures  int64               `json:"consecutive_failures"`
	LastFailureTime      time.Time           `json:"last_failure_time"`
	LastSuccessTime      time.Time           `json:"last_success_time"`
	StateChanges         int64               `json:"state_changes"`
	LastStateChange      time.Time           `json:"last_state_change"`
	OpenDuration         time.Duration       `json:"open_duration"`
	FailureRate          float64             `json:"failure_rate"`
}

// CircuitBreakerConfig holds configuration for circuit breaker
type CircuitBreakerConfig struct {
	// Failure thresholds
	FailureThreshold     int           `json:"failure_threshold"`
	SuccessThreshold     int           `json:"success_threshold"`
	FailureRate          float64       `json:"failure_rate"`
	MinimumRequests      int           `json:"minimum_requests"`
	
	// Timeouts
	Timeout              time.Duration `json:"timeout"`
	OpenTimeout          time.Duration `json:"open_timeout"`
	HalfOpenTimeout      time.Duration `json:"half_open_timeout"`
	
	// Monitoring
	MonitoringWindow     time.Duration `json:"monitoring_window"`
	
	// Fallback
	EnableFallback       bool          `json:"enable_fallback"`
	FallbackTimeout      time.Duration `json:"fallback_timeout"`
}

// DefaultCircuitBreakerConfig returns default circuit breaker configuration
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		FailureThreshold:  5,
		SuccessThreshold:  3,
		FailureRate:       0.5, // 50%
		MinimumRequests:   10,
		Timeout:           30 * time.Second,
		OpenTimeout:       60 * time.Second,
		HalfOpenTimeout:   30 * time.Second,
		MonitoringWindow:  1 * time.Minute,
		EnableFallback:    true,
		FallbackTimeout:   5 * time.Second,
	}
}

// circuitBreakerImpl implements CircuitBreaker
type circuitBreakerImpl struct {
	config              *CircuitBreakerConfig
	state               CircuitBreakerState
	consecutiveFailures int64
	consecutiveSuccesses int64
	stats               *CircuitBreakerStats
	lastStateChange     time.Time
	mu                  sync.RWMutex
	
	// Request tracking for failure rate calculation
	requests            []requestRecord
	requestsMu          sync.Mutex
	
	// Background monitoring
	ctx                 context.Context
	cancel              context.CancelFunc
	running             bool
}

// requestRecord tracks individual request results
type requestRecord struct {
	timestamp time.Time
	success   bool
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config *CircuitBreakerConfig) CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	cb := &circuitBreakerImpl{
		config:          config,
		state:           StateClosed,
		lastStateChange: time.Now(),
		stats: &CircuitBreakerStats{
			State:           StateClosed,
			LastStateChange: time.Now(),
		},
		requests: make([]requestRecord, 0),
		ctx:      ctx,
		cancel:   cancel,
	}
	
	return cb
}

// Execute executes an operation with circuit breaker protection
func (cb *circuitBreakerImpl) Execute(operation func() error) error {
	return cb.ExecuteWithContext(context.Background(), func(ctx context.Context) error {
		return operation()
	})
}

// ExecuteWithContext executes an operation with context and circuit breaker protection
func (cb *circuitBreakerImpl) ExecuteWithContext(ctx context.Context, operation func(context.Context) error) error {
	// Check if circuit breaker allows the request
	if !cb.allowRequest() {
		return fmt.Errorf("circuit breaker is open")
	}
	
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, cb.config.Timeout)
	defer cancel()
	
	// Execute operation
	start := time.Now()
	err := operation(timeoutCtx)
	duration := time.Since(start)
	
	// Record result
	cb.recordResult(err == nil, duration)
	
	return err
}

// GetState returns the current state of the circuit breaker
func (cb *circuitBreakerImpl) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// ForceOpen forces the circuit breaker to open state
func (cb *circuitBreakerImpl) ForceOpen() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	cb.setState(StateOpen)
	return nil
}

// ForceClosed forces the circuit breaker to closed state
func (cb *circuitBreakerImpl) ForceClosed() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	cb.setState(StateClosed)
	cb.consecutiveFailures = 0
	cb.consecutiveSuccesses = 0
	return nil
}

// Reset resets the circuit breaker to initial state
func (cb *circuitBreakerImpl) Reset() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	cb.setState(StateClosed)
	cb.consecutiveFailures = 0
	cb.consecutiveSuccesses = 0
	cb.stats.TotalRequests = 0
	cb.stats.SuccessfulRequests = 0
	cb.stats.FailedRequests = 0
	cb.stats.StateChanges = 0
	
	// Clear request history
	cb.requestsMu.Lock()
	cb.requests = make([]requestRecord, 0)
	cb.requestsMu.Unlock()
	
	return nil
}

// GetStats returns circuit breaker statistics
func (cb *circuitBreakerImpl) GetStats() *CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	// Create a copy of stats
	stats := *cb.stats
	stats.ConsecutiveFailures = cb.consecutiveFailures
	stats.FailureRate = cb.calculateFailureRate()
	
	if cb.state == StateOpen {
		stats.OpenDuration = time.Since(cb.lastStateChange)
	}
	
	return &stats
}

// UpdateConfig updates the circuit breaker configuration
func (cb *circuitBreakerImpl) UpdateConfig(config *CircuitBreakerConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	cb.config = config
	return nil
}

// Start starts the circuit breaker
func (cb *circuitBreakerImpl) Start() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	if cb.running {
		return nil
	}
	
	// Start background monitoring
	go cb.monitoringLoop()
	
	cb.running = true
	return nil
}

// Stop stops the circuit breaker
func (cb *circuitBreakerImpl) Stop() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	if !cb.running {
		return nil
	}
	
	if cb.cancel != nil {
		cb.cancel()
	}
	
	cb.running = false
	return nil
}

// Helper methods

// allowRequest checks if a request should be allowed
func (cb *circuitBreakerImpl) allowRequest() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if enough time has passed to try half-open
		if time.Since(cb.lastStateChange) >= cb.config.OpenTimeout {
			cb.mu.RUnlock()
			cb.mu.Lock()
			// Double-check after acquiring write lock
			if cb.state == StateOpen && time.Since(cb.lastStateChange) >= cb.config.OpenTimeout {
				cb.setState(StateHalfOpen)
			}
			cb.mu.Unlock()
			cb.mu.RLock()
			return cb.state == StateHalfOpen
		}
		return false
	case StateHalfOpen:
		return true
	default:
		return false
	}
}

// recordResult records the result of an operation
func (cb *circuitBreakerImpl) recordResult(success bool, duration time.Duration) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	// Update statistics
	cb.stats.TotalRequests++
	if success {
		cb.stats.SuccessfulRequests++
		cb.stats.LastSuccessTime = time.Now()
		cb.consecutiveFailures = 0
		cb.consecutiveSuccesses++
	} else {
		cb.stats.FailedRequests++
		cb.stats.LastFailureTime = time.Now()
		cb.consecutiveFailures++
		cb.consecutiveSuccesses = 0
	}
	
	// Record request for failure rate calculation
	cb.requestsMu.Lock()
	cb.requests = append(cb.requests, requestRecord{
		timestamp: time.Now(),
		success:   success,
	})
	cb.requestsMu.Unlock()
	
	// Update state based on result
	cb.updateState(success)
}

// updateState updates the circuit breaker state based on recent results
func (cb *circuitBreakerImpl) updateState(lastSuccess bool) {
	switch cb.state {
	case StateClosed:
		if !lastSuccess && cb.shouldOpen() {
			cb.setState(StateOpen)
		}
	case StateHalfOpen:
		if lastSuccess {
			if cb.consecutiveSuccesses >= int64(cb.config.SuccessThreshold) {
				cb.setState(StateClosed)
			}
		} else {
			cb.setState(StateOpen)
		}
	case StateOpen:
		// State transitions are handled in allowRequest()
	}
}

// shouldOpen determines if the circuit breaker should open
func (cb *circuitBreakerImpl) shouldOpen() bool {
	// Check consecutive failures threshold
	if cb.consecutiveFailures >= int64(cb.config.FailureThreshold) {
		return true
	}
	
	// Check failure rate threshold
	if cb.stats.TotalRequests >= int64(cb.config.MinimumRequests) {
		failureRate := cb.calculateFailureRate()
		if failureRate >= cb.config.FailureRate {
			return true
		}
	}
	
	return false
}

// calculateFailureRate calculates the current failure rate
func (cb *circuitBreakerImpl) calculateFailureRate() float64 {
	cb.requestsMu.Lock()
	defer cb.requestsMu.Unlock()
	
	if len(cb.requests) == 0 {
		return 0.0
	}
	
	// Clean old requests outside monitoring window
	cutoff := time.Now().Add(-cb.config.MonitoringWindow)
	validRequests := make([]requestRecord, 0)
	
	for _, req := range cb.requests {
		if req.timestamp.After(cutoff) {
			validRequests = append(validRequests, req)
		}
	}
	
	cb.requests = validRequests
	
	if len(validRequests) == 0 {
		return 0.0
	}
	
	// Calculate failure rate
	failures := 0
	for _, req := range validRequests {
		if !req.success {
			failures++
		}
	}
	
	return float64(failures) / float64(len(validRequests))
}

// setState changes the circuit breaker state
func (cb *circuitBreakerImpl) setState(newState CircuitBreakerState) {
	if cb.state != newState {
		cb.state = newState
		cb.lastStateChange = time.Now()
		cb.stats.State = newState
		cb.stats.StateChanges++
		cb.stats.LastStateChange = cb.lastStateChange
	}
}

// monitoringLoop runs background monitoring
func (cb *circuitBreakerImpl) monitoringLoop() {
	ticker := time.NewTicker(cb.config.MonitoringWindow / 10) // Check 10 times per window
	defer ticker.Stop()
	
	for {
		select {
		case <-cb.ctx.Done():
			return
		case <-ticker.C:
			cb.performHealthCheck()
		}
	}
}

// performHealthCheck performs periodic health checks
func (cb *circuitBreakerImpl) performHealthCheck() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	// Check for state transitions based on time
	switch cb.state {
	case StateOpen:
		if time.Since(cb.lastStateChange) >= cb.config.OpenTimeout {
			cb.setState(StateHalfOpen)
		}
	case StateHalfOpen:
		if time.Since(cb.lastStateChange) >= cb.config.HalfOpenTimeout {
			// If no requests in half-open state, go back to open
			if cb.consecutiveSuccesses == 0 {
				cb.setState(StateOpen)
			}
		}
	}
	
	// Clean old request records
	cb.requestsMu.Lock()
	cutoff := time.Now().Add(-cb.config.MonitoringWindow)
	validRequests := make([]requestRecord, 0)
	
	for _, req := range cb.requests {
		if req.timestamp.After(cutoff) {
			validRequests = append(validRequests, req)
		}
	}
	
	cb.requests = validRequests
	cb.requestsMu.Unlock()
}

// AuthenticationCircuitBreaker provides circuit breaker specifically for authentication
type AuthenticationCircuitBreaker struct {
	circuitBreaker CircuitBreaker
	fallbackAuth   func(context.Context, *AuthInfo) (*CachedAuthResult, error)
	config         *AuthCircuitBreakerConfig
}

// AuthCircuitBreakerConfig holds configuration for authentication circuit breaker
type AuthCircuitBreakerConfig struct {
	CircuitBreakerConfig *CircuitBreakerConfig `json:"circuit_breaker_config"`
	EnableFallback       bool                  `json:"enable_fallback"`
	FallbackCacheTTL     time.Duration         `json:"fallback_cache_ttl"`
	MaxFallbackAge       time.Duration         `json:"max_fallback_age"`
}

// DefaultAuthCircuitBreakerConfig returns default authentication circuit breaker configuration
func DefaultAuthCircuitBreakerConfig() *AuthCircuitBreakerConfig {
	return &AuthCircuitBreakerConfig{
		CircuitBreakerConfig: DefaultCircuitBreakerConfig(),
		EnableFallback:       true,
		FallbackCacheTTL:     10 * time.Minute,
		MaxFallbackAge:       1 * time.Hour,
	}
}

// NewAuthenticationCircuitBreaker creates a new authentication circuit breaker
func NewAuthenticationCircuitBreaker(
	config *AuthCircuitBreakerConfig,
	fallbackAuth func(context.Context, *AuthInfo) (*CachedAuthResult, error),
) *AuthenticationCircuitBreaker {
	if config == nil {
		config = DefaultAuthCircuitBreakerConfig()
	}
	
	return &AuthenticationCircuitBreaker{
		circuitBreaker: NewCircuitBreaker(config.CircuitBreakerConfig),
		fallbackAuth:   fallbackAuth,
		config:         config,
	}
}

// Authenticate performs authentication with circuit breaker protection
func (acb *AuthenticationCircuitBreaker) Authenticate(
	ctx context.Context,
	authInfo *AuthInfo,
	primaryAuth func(context.Context, *AuthInfo) (*CachedAuthResult, error),
) (*CachedAuthResult, error) {
	
	// Try primary authentication with circuit breaker protection
	var result *CachedAuthResult
	var primaryErr error
	
	err := acb.circuitBreaker.ExecuteWithContext(ctx, func(ctx context.Context) error {
		var err error
		result, err = primaryAuth(ctx, authInfo)
		primaryErr = err
		return err
	})
	
	// If primary authentication succeeded, return result
	if err == nil && result != nil {
		return result, nil
	}
	
	// If circuit breaker is open or primary auth failed, try fallback
	if acb.config.EnableFallback && acb.fallbackAuth != nil {
		fallbackResult, fallbackErr := acb.fallbackAuth(ctx, authInfo)
		if fallbackErr == nil && fallbackResult != nil {
			// Mark as fallback result
			fallbackResult.Permissions = map[string]interface{}{
				"fallback": true,
				"limited":  true,
			}
			return fallbackResult, nil
		}
	}
	
	// Return original error if fallback also failed
	if primaryErr != nil {
		return nil, primaryErr
	}
	
	return nil, err
}

// GetState returns the circuit breaker state
func (acb *AuthenticationCircuitBreaker) GetState() CircuitBreakerState {
	return acb.circuitBreaker.GetState()
}

// GetStats returns circuit breaker statistics
func (acb *AuthenticationCircuitBreaker) GetStats() *CircuitBreakerStats {
	return acb.circuitBreaker.GetStats()
}

// Reset resets the circuit breaker
func (acb *AuthenticationCircuitBreaker) Reset() error {
	return acb.circuitBreaker.Reset()
}

// Start starts the authentication circuit breaker
func (acb *AuthenticationCircuitBreaker) Start() error {
	return acb.circuitBreaker.Start()
}

// Stop stops the authentication circuit breaker
func (acb *AuthenticationCircuitBreaker) Stop() error {
	return acb.circuitBreaker.Stop()
}