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
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrAllProvidersUnhealthy = errors.New("all external providers are unhealthy")
	ErrFallbackNotConfigured = errors.New("fallback authentication not configured")
)

// ProviderHealthStatus represents the health status of a provider
type ProviderHealthStatus struct {
	Name         string    `json:"name"`
	Healthy      bool      `json:"healthy"`
	LastChecked  time.Time `json:"last_checked"`
	LastError    string    `json:"last_error,omitempty"`
	ResponseTime time.Duration `json:"response_time"`
}

// FallbackConfig contains configuration for fallback mechanisms
type FallbackConfig struct {
	// EnableFallback enables fallback authentication when external providers fail
	EnableFallback bool `json:"enable_fallback"`
	
	// FallbackProvider is the name of the provider to use as fallback (e.g., "internal")
	FallbackProvider string `json:"fallback_provider"`
	
	// HealthCheckInterval is how often to check provider health
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	
	// HealthCheckTimeout is the timeout for health checks
	HealthCheckTimeout time.Duration `json:"health_check_timeout"`
	
	// MaxRetries is the maximum number of retries before marking a provider as unhealthy
	MaxRetries int `json:"max_retries"`
	
	// RetryDelay is the delay between retries
	RetryDelay time.Duration `json:"retry_delay"`
	
	// UnhealthyThreshold is the number of consecutive failures before marking as unhealthy
	UnhealthyThreshold int `json:"unhealthy_threshold"`
	
	// HealthyThreshold is the number of consecutive successes before marking as healthy
	HealthyThreshold int `json:"healthy_threshold"`
	
	// SessionInvalidationOnLogout invalidates sessions when external provider logout is detected
	SessionInvalidationOnLogout bool `json:"session_invalidation_on_logout"`
}

// FallbackManager manages fallback mechanisms for external providers
type FallbackManager struct {
	mu                    sync.RWMutex
	config                *FallbackConfig
	providerManager       ExternalProviderManager
	fallbackIAM           IAMService
	healthStatus          map[string]*ProviderHealthStatus
	failureCount          map[string]int
	successCount          map[string]int
	healthCheckTicker     *time.Ticker
	ctx                   context.Context
	cancel                context.CancelFunc
	sessionManager        SessionManager
}

// NewFallbackManager creates a new fallback manager
func NewFallbackManager(config *FallbackConfig, providerManager ExternalProviderManager, fallbackIAM IAMService, sessionManager SessionManager) *FallbackManager {
	if config == nil {
		config = &FallbackConfig{
			EnableFallback:              true,
			HealthCheckInterval:         30 * time.Second,
			HealthCheckTimeout:          10 * time.Second,
			MaxRetries:                  3,
			RetryDelay:                  5 * time.Second,
			UnhealthyThreshold:          3,
			HealthyThreshold:            2,
			SessionInvalidationOnLogout: true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	fm := &FallbackManager{
		config:          config,
		providerManager: providerManager,
		fallbackIAM:     fallbackIAM,
		sessionManager:  sessionManager,
		healthStatus:    make(map[string]*ProviderHealthStatus),
		failureCount:    make(map[string]int),
		successCount:    make(map[string]int),
		ctx:             ctx,
		cancel:          cancel,
	}

	// Start health checking if enabled
	if config.HealthCheckInterval > 0 {
		fm.startHealthChecking()
	}

	return fm
}

// AuthenticateWithFallback attempts authentication with external providers and falls back if needed
func (fm *FallbackManager) AuthenticateWithFallback(providerName string, credentials interface{}) (*ExternalUser, error) {
	// Try the requested provider first
	if providerName != "" {
		if fm.isProviderHealthy(providerName) {
			user, err := fm.authenticateWithProvider(providerName, credentials)
			if err == nil {
				fm.recordSuccess(providerName)
				return user, nil
			}
			fm.recordFailure(providerName, err)
		}
	}

	// Try other healthy providers
	healthyProviders := fm.getHealthyProviders()
	for _, name := range healthyProviders {
		if name == providerName {
			continue // Already tried
		}
		
		user, err := fm.authenticateWithProvider(name, credentials)
		if err == nil {
			fm.recordSuccess(name)
			return user, nil
		}
		fm.recordFailure(name, err)
	}

	// Fall back to internal authentication if configured
	if fm.config.EnableFallback && fm.fallbackIAM != nil {
		return fm.authenticateWithFallback(credentials)
	}

	return nil, ErrAllProvidersUnhealthy
}

// ValidateTokenWithFallback validates a token with fallback support
func (fm *FallbackManager) ValidateTokenWithFallback(providerName string, token string) (*TokenClaims, error) {
	// Try the requested provider first
	if providerName != "" {
		if fm.isProviderHealthy(providerName) {
			claims, err := fm.validateTokenWithProvider(providerName, token)
			if err == nil {
				fm.recordSuccess(providerName)
				return claims, nil
			}
			fm.recordFailure(providerName, err)
		}
	}

	// Try other healthy providers
	healthyProviders := fm.getHealthyProviders()
	for _, name := range healthyProviders {
		if name == providerName {
			continue // Already tried
		}
		
		claims, err := fm.validateTokenWithProvider(name, token)
		if err == nil {
			fm.recordSuccess(name)
			return claims, nil
		}
		fm.recordFailure(name, err)
	}

	return nil, ErrAllProvidersUnhealthy
}

// GetProviderHealthStatus returns the health status of all providers
func (fm *FallbackManager) GetProviderHealthStatus() map[string]*ProviderHealthStatus {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	result := make(map[string]*ProviderHealthStatus)
	for name, status := range fm.healthStatus {
		// Create a copy to avoid race conditions
		result[name] = &ProviderHealthStatus{
			Name:         status.Name,
			Healthy:      status.Healthy,
			LastChecked:  status.LastChecked,
			LastError:    status.LastError,
			ResponseTime: status.ResponseTime,
		}
	}

	return result
}

// InvalidateSessionsOnLogout invalidates sessions when external provider logout is detected
func (fm *FallbackManager) InvalidateSessionsOnLogout(providerName, userID string) error {
	if !fm.config.SessionInvalidationOnLogout || fm.sessionManager == nil {
		return nil
	}

	// Invalidate all sessions for the user
	return fm.sessionManager.InvalidateUserSessions(userID)
}

// Shutdown gracefully shuts down the fallback manager
func (fm *FallbackManager) Shutdown() error {
	if fm.cancel != nil {
		fm.cancel()
	}
	if fm.healthCheckTicker != nil {
		fm.healthCheckTicker.Stop()
	}
	return nil
}

// startHealthChecking starts the background health checking process
func (fm *FallbackManager) startHealthChecking() {
	fm.healthCheckTicker = time.NewTicker(fm.config.HealthCheckInterval)
	
	go func() {
		// Initial health check
		fm.performHealthChecks()
		
		for {
			select {
			case <-fm.ctx.Done():
				return
			case <-fm.healthCheckTicker.C:
				fm.performHealthChecks()
			}
		}
	}()
}

// performHealthChecks checks the health of all registered providers
func (fm *FallbackManager) performHealthChecks() {
	providers := fm.providerManager.ListProviders()
	
	for name, provider := range providers {
		go fm.checkProviderHealth(name, provider)
	}
}

// checkProviderHealth checks the health of a single provider
func (fm *FallbackManager) checkProviderHealth(name string, provider ExternalProvider) {
	start := time.Now()
	
	ctx, cancel := context.WithTimeout(fm.ctx, fm.config.HealthCheckTimeout)
	defer cancel()
	
	healthy := false
	var lastError string
	
	// Create a channel to receive the health check result
	healthChan := make(chan bool, 1)
	
	go func() {
		healthChan <- provider.IsHealthy()
	}()
	
	select {
	case healthy = <-healthChan:
		// Health check completed
	case <-ctx.Done():
		// Health check timed out
		healthy = false
		lastError = "health check timeout"
	}
	
	responseTime := time.Since(start)
	
	fm.updateProviderHealth(name, healthy, lastError, responseTime)
}

// updateProviderHealth updates the health status of a provider
func (fm *FallbackManager) updateProviderHealth(name string, healthy bool, lastError string, responseTime time.Duration) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	
	status, exists := fm.healthStatus[name]
	if !exists {
		status = &ProviderHealthStatus{
			Name: name,
		}
		fm.healthStatus[name] = status
	}
	
	status.LastChecked = time.Now()
	status.LastError = lastError
	status.ResponseTime = responseTime
	
	if healthy {
		fm.successCount[name]++
		fm.failureCount[name] = 0
		
		// Mark as healthy if we have enough consecutive successes
		if fm.successCount[name] >= fm.config.HealthyThreshold {
			status.Healthy = true
		}
	} else {
		fm.failureCount[name]++
		fm.successCount[name] = 0
		
		// Mark as unhealthy if we have enough consecutive failures
		if fm.failureCount[name] >= fm.config.UnhealthyThreshold {
			status.Healthy = false
		}
	}
}

// isProviderHealthy checks if a provider is currently healthy
func (fm *FallbackManager) isProviderHealthy(name string) bool {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	
	status, exists := fm.healthStatus[name]
	if !exists {
		// If we don't have health status, assume healthy initially
		return true
	}
	
	return status.Healthy
}

// getHealthyProviders returns a list of healthy provider names
func (fm *FallbackManager) getHealthyProviders() []string {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	
	var healthy []string
	providers := fm.providerManager.ListProviders()
	
	for name := range providers {
		if status, exists := fm.healthStatus[name]; exists {
			if status.Healthy {
				healthy = append(healthy, name)
			}
		} else {
			// If no health status, assume healthy
			healthy = append(healthy, name)
		}
	}
	
	return healthy
}

// authenticateWithProvider attempts authentication with a specific provider
func (fm *FallbackManager) authenticateWithProvider(name string, credentials interface{}) (*ExternalUser, error) {
	provider, err := fm.providerManager.GetProvider(name)
	if err != nil {
		return nil, err
	}
	
	return provider.Authenticate(credentials)
}

// validateTokenWithProvider validates a token with a specific provider
func (fm *FallbackManager) validateTokenWithProvider(name string, token string) (*TokenClaims, error) {
	provider, err := fm.providerManager.GetProvider(name)
	if err != nil {
		return nil, err
	}
	
	return provider.ValidateToken(token)
}

// authenticateWithFallback attempts authentication using the fallback IAM service
func (fm *FallbackManager) authenticateWithFallback(credentials interface{}) (*ExternalUser, error) {
	if fm.fallbackIAM == nil {
		return nil, ErrFallbackNotConfigured
	}
	
	// Convert credentials to access key if possible
	var accessKey string
	switch creds := credentials.(type) {
	case string:
		accessKey = creds
	case map[string]interface{}:
		if key, ok := creds["access_key"].(string); ok {
			accessKey = key
		}
	default:
		return nil, errors.New("unsupported credentials format for fallback authentication")
	}
	
	if accessKey == "" {
		return nil, errors.New("access key required for fallback authentication")
	}
	
	// Get account from fallback IAM
	account, err := fm.fallbackIAM.GetUserAccount(accessKey)
	if err != nil {
		return nil, fmt.Errorf("fallback authentication failed: %w", err)
	}
	
	// Convert IAM account to external user
	user := &ExternalUser{
		ID:       account.Access,
		Name:     account.Access,
		Provider: fm.config.FallbackProvider,
		Attributes: map[string]interface{}{
			"role":     string(account.Role),
			"user_id":  account.UserID,
			"group_id": account.GroupID,
		},
	}
	
	return user, nil
}

// recordSuccess records a successful operation for a provider
func (fm *FallbackManager) recordSuccess(name string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	
	fm.successCount[name]++
	fm.failureCount[name] = 0
}

// recordFailure records a failed operation for a provider
func (fm *FallbackManager) recordFailure(name string, err error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	
	fm.failureCount[name]++
	fm.successCount[name] = 0
	
	// Update health status with error
	if status, exists := fm.healthStatus[name]; exists {
		status.LastError = err.Error()
	}
}

// ForceHealthCheck forces an immediate health check of all providers
func (fm *FallbackManager) ForceHealthCheck() {
	fm.performHealthChecks()
}

// SetProviderHealthy manually sets a provider's health status (for testing/admin purposes)
func (fm *FallbackManager) SetProviderHealthy(name string, healthy bool) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	
	status, exists := fm.healthStatus[name]
	if !exists {
		status = &ProviderHealthStatus{
			Name: name,
		}
		fm.healthStatus[name] = status
	}
	
	status.Healthy = healthy
	status.LastChecked = time.Now()
	
	if healthy {
		fm.successCount[name] = fm.config.HealthyThreshold
		fm.failureCount[name] = 0
	} else {
		fm.failureCount[name] = fm.config.UnhealthyThreshold
		fm.successCount[name] = 0
	}
}