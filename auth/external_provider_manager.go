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
	"errors"
	"fmt"
	"sync"
)

var (
	ErrProviderNotFound      = errors.New("provider not found")
	ErrProviderAlreadyExists = errors.New("provider already exists")
	ErrProviderNotHealthy    = errors.New("provider is not healthy")
)

// DefaultExternalProviderManager implements ExternalProviderManager
type DefaultExternalProviderManager struct {
	mu        sync.RWMutex
	providers map[string]ExternalProvider
}

// NewExternalProviderManager creates a new external provider manager
func NewExternalProviderManager() *DefaultExternalProviderManager {
	return &DefaultExternalProviderManager{
		providers: make(map[string]ExternalProvider),
	}
}

// RegisterProvider registers a new external provider
func (m *DefaultExternalProviderManager) RegisterProvider(name string, provider ExternalProvider) error {
	if name == "" {
		return errors.New("provider name cannot be empty")
	}
	if provider == nil {
		return errors.New("provider cannot be nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[name]; exists {
		return ErrProviderAlreadyExists
	}

	m.providers[name] = provider
	return nil
}

// GetProvider retrieves a provider by name
func (m *DefaultExternalProviderManager) GetProvider(name string) (ExternalProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provider, exists := m.providers[name]
	if !exists {
		return nil, ErrProviderNotFound
	}

	return provider, nil
}

// ListProviders returns all registered providers
func (m *DefaultExternalProviderManager) ListProviders() map[string]ExternalProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a copy to avoid race conditions
	result := make(map[string]ExternalProvider)
	for name, provider := range m.providers {
		result[name] = provider
	}

	return result
}

// AuthenticateWithProvider attempts authentication with a specific provider
func (m *DefaultExternalProviderManager) AuthenticateWithProvider(providerName string, credentials interface{}) (*ExternalUser, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	if !provider.IsHealthy() {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotHealthy, providerName)
	}

	return provider.Authenticate(credentials)
}

// ValidateTokenWithProvider validates a token with a specific provider
func (m *DefaultExternalProviderManager) ValidateTokenWithProvider(providerName string, token string) (*TokenClaims, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	if !provider.IsHealthy() {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotHealthy, providerName)
	}

	return provider.ValidateToken(token)
}

// GetHealthyProviders returns providers that are currently healthy
func (m *DefaultExternalProviderManager) GetHealthyProviders() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var healthy []string
	for name, provider := range m.providers {
		if provider.IsHealthy() {
			healthy = append(healthy, name)
		}
	}

	return healthy
}

// RemoveProvider removes a provider from the manager
func (m *DefaultExternalProviderManager) RemoveProvider(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[name]; !exists {
		return ErrProviderNotFound
	}

	delete(m.providers, name)
	return nil
}

// GetProviderInfo returns information about a specific provider
func (m *DefaultExternalProviderManager) GetProviderInfo(name string) (*ProviderInfo, error) {
	provider, err := m.GetProvider(name)
	if err != nil {
		return nil, err
	}

	return provider.GetProviderInfo(), nil
}

// GetAllProviderInfo returns information about all registered providers
func (m *DefaultExternalProviderManager) GetAllProviderInfo() map[string]*ProviderInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*ProviderInfo)
	for name, provider := range m.providers {
		result[name] = provider.GetProviderInfo()
	}

	return result
}

// HealthCheck performs health checks on all providers and returns status
func (m *DefaultExternalProviderManager) HealthCheck() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]bool)
	for name, provider := range m.providers {
		result[name] = provider.IsHealthy()
	}

	return result
}