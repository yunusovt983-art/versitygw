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
	"testing"
)

// MockExternalProvider implements ExternalProvider for testing
type MockExternalProvider struct {
	name        string
	providerType ProviderType
	healthy     bool
	authResult  *ExternalUser
	authError   error
	tokenResult *TokenClaims
	tokenError  error
}

func (m *MockExternalProvider) Authenticate(credentials interface{}) (*ExternalUser, error) {
	return m.authResult, m.authError
}

func (m *MockExternalProvider) ValidateToken(token string) (*TokenClaims, error) {
	return m.tokenResult, m.tokenError
}

func (m *MockExternalProvider) GetProviderInfo() *ProviderInfo {
	return &ProviderInfo{
		Name:        m.name,
		Type:        m.providerType,
		Description: "Mock provider for testing",
		Endpoint:    "https://mock.example.com",
		Enabled:     true,
	}
}

func (m *MockExternalProvider) IsHealthy() bool {
	return m.healthy
}

func (m *MockExternalProvider) GetProviderType() ProviderType {
	return m.providerType
}

func TestNewExternalProviderManager(t *testing.T) {
	manager := NewExternalProviderManager()
	if manager == nil {
		t.Error("expected non-nil manager")
	}

	providers := manager.ListProviders()
	if len(providers) != 0 {
		t.Errorf("expected empty provider list, got %d providers", len(providers))
	}
}

func TestExternalProviderManager_RegisterProvider(t *testing.T) {
	manager := NewExternalProviderManager()

	t.Run("valid provider", func(t *testing.T) {
		provider := &MockExternalProvider{
			name:        "test-provider",
			providerType: ProviderTypeSAML,
			healthy:     true,
		}

		err := manager.RegisterProvider("test-provider", provider)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Verify provider was registered
		retrievedProvider, err := manager.GetProvider("test-provider")
		if err != nil {
			t.Errorf("failed to retrieve registered provider: %v", err)
		}
		if retrievedProvider != provider {
			t.Error("retrieved provider does not match registered provider")
		}
	})

	t.Run("empty name", func(t *testing.T) {
		provider := &MockExternalProvider{}
		err := manager.RegisterProvider("", provider)
		if err == nil {
			t.Error("expected error for empty provider name")
		}
	})

	t.Run("nil provider", func(t *testing.T) {
		err := manager.RegisterProvider("nil-provider", nil)
		if err == nil {
			t.Error("expected error for nil provider")
		}
	})

	t.Run("duplicate provider", func(t *testing.T) {
		provider1 := &MockExternalProvider{name: "duplicate"}
		provider2 := &MockExternalProvider{name: "duplicate"}

		err := manager.RegisterProvider("duplicate", provider1)
		if err != nil {
			t.Errorf("unexpected error registering first provider: %v", err)
		}

		err = manager.RegisterProvider("duplicate", provider2)
		if err != ErrProviderAlreadyExists {
			t.Errorf("expected ErrProviderAlreadyExists, got %v", err)
		}
	})
}

func TestExternalProviderManager_GetProvider(t *testing.T) {
	manager := NewExternalProviderManager()

	t.Run("existing provider", func(t *testing.T) {
		provider := &MockExternalProvider{name: "existing"}
		manager.RegisterProvider("existing", provider)

		retrieved, err := manager.GetProvider("existing")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if retrieved != provider {
			t.Error("retrieved provider does not match registered provider")
		}
	})

	t.Run("non-existing provider", func(t *testing.T) {
		_, err := manager.GetProvider("non-existing")
		if err != ErrProviderNotFound {
			t.Errorf("expected ErrProviderNotFound, got %v", err)
		}
	})
}

func TestExternalProviderManager_ListProviders(t *testing.T) {
	manager := NewExternalProviderManager()

	// Register multiple providers
	provider1 := &MockExternalProvider{name: "provider1"}
	provider2 := &MockExternalProvider{name: "provider2"}

	manager.RegisterProvider("provider1", provider1)
	manager.RegisterProvider("provider2", provider2)

	providers := manager.ListProviders()
	if len(providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(providers))
	}

	if providers["provider1"] != provider1 {
		t.Error("provider1 not found in list")
	}
	if providers["provider2"] != provider2 {
		t.Error("provider2 not found in list")
	}
}

func TestExternalProviderManager_AuthenticateWithProvider(t *testing.T) {
	manager := NewExternalProviderManager()

	t.Run("successful authentication", func(t *testing.T) {
		expectedUser := &ExternalUser{
			ID:    "test-user",
			Email: "test@example.com",
		}
		provider := &MockExternalProvider{
			name:       "auth-provider",
			healthy:    true,
			authResult: expectedUser,
		}

		manager.RegisterProvider("auth-provider", provider)

		user, err := manager.AuthenticateWithProvider("auth-provider", "test-credentials")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if user != expectedUser {
			t.Error("returned user does not match expected user")
		}
	})

	t.Run("provider not found", func(t *testing.T) {
		_, err := manager.AuthenticateWithProvider("non-existing", "credentials")
		if err != ErrProviderNotFound {
			t.Errorf("expected ErrProviderNotFound, got %v", err)
		}
	})

	t.Run("unhealthy provider", func(t *testing.T) {
		provider := &MockExternalProvider{
			name:    "unhealthy-provider",
			healthy: false,
		}

		manager.RegisterProvider("unhealthy-provider", provider)

		_, err := manager.AuthenticateWithProvider("unhealthy-provider", "credentials")
		if err == nil {
			t.Error("expected error for unhealthy provider")
		}
		if !errors.Is(err, ErrProviderNotHealthy) {
			t.Errorf("expected ErrProviderNotHealthy, got %v", err)
		}
	})

	t.Run("authentication error", func(t *testing.T) {
		expectedError := errors.New("authentication failed")
		provider := &MockExternalProvider{
			name:      "error-provider",
			healthy:   true,
			authError: expectedError,
		}

		manager.RegisterProvider("error-provider", provider)

		_, err := manager.AuthenticateWithProvider("error-provider", "credentials")
		if err != expectedError {
			t.Errorf("expected authentication error, got %v", err)
		}
	})
}

func TestExternalProviderManager_ValidateTokenWithProvider(t *testing.T) {
	manager := NewExternalProviderManager()

	t.Run("successful token validation", func(t *testing.T) {
		expectedClaims := &TokenClaims{
			Subject: "test-user",
			Email:   "test@example.com",
		}
		provider := &MockExternalProvider{
			name:        "token-provider",
			healthy:     true,
			tokenResult: expectedClaims,
		}

		manager.RegisterProvider("token-provider", provider)

		claims, err := manager.ValidateTokenWithProvider("token-provider", "test-token")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if claims != expectedClaims {
			t.Error("returned claims do not match expected claims")
		}
	})

	t.Run("provider not found", func(t *testing.T) {
		_, err := manager.ValidateTokenWithProvider("non-existing", "token")
		if err != ErrProviderNotFound {
			t.Errorf("expected ErrProviderNotFound, got %v", err)
		}
	})

	t.Run("unhealthy provider", func(t *testing.T) {
		provider := &MockExternalProvider{
			name:    "unhealthy-token-provider",
			healthy: false,
		}

		manager.RegisterProvider("unhealthy-token-provider", provider)

		_, err := manager.ValidateTokenWithProvider("unhealthy-token-provider", "token")
		if err == nil {
			t.Error("expected error for unhealthy provider")
		}
		if !errors.Is(err, ErrProviderNotHealthy) {
			t.Errorf("expected ErrProviderNotHealthy, got %v", err)
		}
	})

	t.Run("token validation error", func(t *testing.T) {
		expectedError := errors.New("token validation failed")
		provider := &MockExternalProvider{
			name:       "token-error-provider",
			healthy:    true,
			tokenError: expectedError,
		}

		manager.RegisterProvider("token-error-provider", provider)

		_, err := manager.ValidateTokenWithProvider("token-error-provider", "token")
		if err != expectedError {
			t.Errorf("expected token validation error, got %v", err)
		}
	})
}

func TestExternalProviderManager_GetHealthyProviders(t *testing.T) {
	manager := NewExternalProviderManager()

	// Register providers with different health statuses
	healthyProvider := &MockExternalProvider{name: "healthy", healthy: true}
	unhealthyProvider := &MockExternalProvider{name: "unhealthy", healthy: false}

	manager.RegisterProvider("healthy", healthyProvider)
	manager.RegisterProvider("unhealthy", unhealthyProvider)

	healthyProviders := manager.GetHealthyProviders()
	if len(healthyProviders) != 1 {
		t.Errorf("expected 1 healthy provider, got %d", len(healthyProviders))
	}
	if healthyProviders[0] != "healthy" {
		t.Errorf("expected 'healthy' provider, got '%s'", healthyProviders[0])
	}
}

func TestExternalProviderManager_RemoveProvider(t *testing.T) {
	manager := NewExternalProviderManager()

	t.Run("remove existing provider", func(t *testing.T) {
		provider := &MockExternalProvider{name: "to-remove"}
		manager.RegisterProvider("to-remove", provider)

		err := manager.RemoveProvider("to-remove")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Verify provider was removed
		_, err = manager.GetProvider("to-remove")
		if err != ErrProviderNotFound {
			t.Errorf("expected ErrProviderNotFound after removal, got %v", err)
		}
	})

	t.Run("remove non-existing provider", func(t *testing.T) {
		err := manager.RemoveProvider("non-existing")
		if err != ErrProviderNotFound {
			t.Errorf("expected ErrProviderNotFound, got %v", err)
		}
	})
}

func TestExternalProviderManager_GetProviderInfo(t *testing.T) {
	manager := NewExternalProviderManager()

	t.Run("existing provider", func(t *testing.T) {
		provider := &MockExternalProvider{
			name:        "info-provider",
			providerType: ProviderTypeSAML,
		}
		manager.RegisterProvider("info-provider", provider)

		info, err := manager.GetProviderInfo("info-provider")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if info.Name != "info-provider" {
			t.Errorf("expected name 'info-provider', got '%s'", info.Name)
		}
		if info.Type != ProviderTypeSAML {
			t.Errorf("expected type '%s', got '%s'", ProviderTypeSAML, info.Type)
		}
	})

	t.Run("non-existing provider", func(t *testing.T) {
		_, err := manager.GetProviderInfo("non-existing")
		if err != ErrProviderNotFound {
			t.Errorf("expected ErrProviderNotFound, got %v", err)
		}
	})
}

func TestExternalProviderManager_GetAllProviderInfo(t *testing.T) {
	manager := NewExternalProviderManager()

	provider1 := &MockExternalProvider{name: "provider1", providerType: ProviderTypeSAML}
	provider2 := &MockExternalProvider{name: "provider2", providerType: ProviderTypeOAuth2}

	manager.RegisterProvider("provider1", provider1)
	manager.RegisterProvider("provider2", provider2)

	allInfo := manager.GetAllProviderInfo()
	if len(allInfo) != 2 {
		t.Errorf("expected 2 provider infos, got %d", len(allInfo))
	}

	if allInfo["provider1"].Type != ProviderTypeSAML {
		t.Errorf("expected provider1 type '%s', got '%s'", ProviderTypeSAML, allInfo["provider1"].Type)
	}
	if allInfo["provider2"].Type != ProviderTypeOAuth2 {
		t.Errorf("expected provider2 type '%s', got '%s'", ProviderTypeOAuth2, allInfo["provider2"].Type)
	}
}

func TestExternalProviderManager_HealthCheck(t *testing.T) {
	manager := NewExternalProviderManager()

	healthyProvider := &MockExternalProvider{name: "healthy", healthy: true}
	unhealthyProvider := &MockExternalProvider{name: "unhealthy", healthy: false}

	manager.RegisterProvider("healthy", healthyProvider)
	manager.RegisterProvider("unhealthy", unhealthyProvider)

	healthStatus := manager.HealthCheck()
	if len(healthStatus) != 2 {
		t.Errorf("expected 2 health statuses, got %d", len(healthStatus))
	}

	if !healthStatus["healthy"] {
		t.Error("expected 'healthy' provider to be healthy")
	}
	if healthStatus["unhealthy"] {
		t.Error("expected 'unhealthy' provider to be unhealthy")
	}
}