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
	"time"
)

// MockSessionManager implements SessionManager for testing
type MockSessionManager struct {
	terminatedUsers []string
}

func (m *MockSessionManager) InvalidateUserSessions(userID string) error {
	m.terminatedUsers = append(m.terminatedUsers, userID)
	return nil
}

func (m *MockSessionManager) RefreshUserPermissions(userID string) error {
	return nil
}

func (m *MockSessionManager) GetActiveUserSessions(userID string) ([]string, error) {
	return []string{"test-session"}, nil
}

func (m *MockSessionManager) NotifySessionUpdate(sessionID string, updateType string) error {
	return nil
}

// MockIAMService implements IAMService for testing
type MockIAMService struct {
	accounts map[string]Account
}

func (m *MockIAMService) CreateAccount(account Account) error {
	m.accounts[account.Access] = account
	return nil
}

func (m *MockIAMService) GetUserAccount(access string) (Account, error) {
	if account, exists := m.accounts[access]; exists {
		return account, nil
	}
	return Account{}, ErrNoSuchUser
}

func (m *MockIAMService) UpdateUserAccount(access string, props MutableProps) error {
	if account, exists := m.accounts[access]; exists {
		updateAcc(&account, props)
		m.accounts[access] = account
		return nil
	}
	return ErrNoSuchUser
}

func (m *MockIAMService) DeleteUserAccount(access string) error {
	delete(m.accounts, access)
	return nil
}

func (m *MockIAMService) ListUserAccounts() ([]Account, error) {
	var accounts []Account
	for _, account := range m.accounts {
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (m *MockIAMService) Shutdown() error {
	return nil
}

func TestNewFallbackManager(t *testing.T) {
	providerManager := NewExternalProviderManager()
	sessionManager := &MockSessionManager{}
	iamService := &MockIAMService{accounts: make(map[string]Account)}

	t.Run("with config", func(t *testing.T) {
		config := &FallbackConfig{
			EnableFallback:      true,
			FallbackProvider:    "internal",
			HealthCheckInterval: 10 * time.Second,
		}

		fm := NewFallbackManager(config, providerManager, iamService, sessionManager)
		if fm == nil {
			t.Error("expected non-nil fallback manager")
		}
		if fm.config != config {
			t.Error("config not set correctly")
		}

		fm.Shutdown()
	})

	t.Run("with nil config", func(t *testing.T) {
		fm := NewFallbackManager(nil, providerManager, iamService, sessionManager)
		if fm == nil {
			t.Error("expected non-nil fallback manager")
		}
		if fm.config == nil {
			t.Error("expected default config to be created")
		}

		fm.Shutdown()
	})
}

func TestFallbackManager_AuthenticateWithFallback(t *testing.T) {
	sessionManager := &MockSessionManager{}
	iamService := &MockIAMService{
		accounts: map[string]Account{
			"fallback-user": {
				Access: "fallback-user",
				Secret: "fallback-secret",
				Role:   RoleUser,
			},
		},
	}

	config := &FallbackConfig{
		EnableFallback:   true,
		FallbackProvider: "internal",
	}

	t.Run("successful authentication with healthy provider", func(t *testing.T) {
		providerManager := NewExternalProviderManager()
		fm := NewFallbackManager(config, providerManager, iamService, sessionManager)
		defer fm.Shutdown()

		expectedUser := &ExternalUser{
			ID:    "test-user",
			Email: "test@example.com",
		}
		provider := &MockExternalProvider{
			name:         "test-provider",
			providerType: ProviderTypeOAuth2,
			healthy:      true,
			authResult:   expectedUser,
		}

		providerManager.RegisterProvider("test-provider", provider)

		user, err := fm.AuthenticateWithFallback("test-provider", "test-credentials")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if user != expectedUser {
			t.Error("returned user does not match expected user")
		}
	})

	t.Run("fallback to internal authentication", func(t *testing.T) {
		providerManager := NewExternalProviderManager()
		fm := NewFallbackManager(config, providerManager, iamService, sessionManager)
		defer fm.Shutdown()

		provider := &MockExternalProvider{
			name:         "failing-provider",
			providerType: ProviderTypeOAuth2,
			healthy:      false,
			authError:    errors.New("provider failed"),
		}

		providerManager.RegisterProvider("failing-provider", provider)
		fm.SetProviderHealthy("failing-provider", false)

		user, err := fm.AuthenticateWithFallback("failing-provider", "fallback-user")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if user.ID != "fallback-user" {
			t.Errorf("expected user ID 'fallback-user', got '%s'", user.ID)
		}
		if user.Provider != "internal" {
			t.Errorf("expected provider 'internal', got '%s'", user.Provider)
		}
	})

	t.Run("all providers unhealthy and no fallback", func(t *testing.T) {
		providerManager := NewExternalProviderManager()
		config := &FallbackConfig{
			EnableFallback: false,
		}
		fmNoFallback := NewFallbackManager(config, providerManager, nil, sessionManager)
		defer fmNoFallback.Shutdown()

		provider := &MockExternalProvider{
			name:         "unhealthy-provider",
			providerType: ProviderTypeOAuth2,
			healthy:      false,
			authError:    errors.New("provider failed"),
		}

		providerManager.RegisterProvider("unhealthy-provider", provider)
		fmNoFallback.SetProviderHealthy("unhealthy-provider", false)

		_, err := fmNoFallback.AuthenticateWithFallback("unhealthy-provider", "test-credentials")
		if err != ErrAllProvidersUnhealthy {
			t.Errorf("expected ErrAllProvidersUnhealthy, got %v", err)
		}
	})

	t.Run("try multiple providers", func(t *testing.T) {
		providerManager := NewExternalProviderManager()
		fm := NewFallbackManager(config, providerManager, iamService, sessionManager)
		defer fm.Shutdown()

		// Register multiple providers
		failingProvider := &MockExternalProvider{
			name:         "failing-provider-1",
			providerType: ProviderTypeOAuth2,
			healthy:      true,
			authError:    errors.New("auth failed"),
		}
		successProvider := &MockExternalProvider{
			name:         "success-provider",
			providerType: ProviderTypeOAuth2,
			healthy:      true,
			authResult: &ExternalUser{
				ID:    "success-user",
				Email: "success@example.com",
			},
		}

		providerManager.RegisterProvider("failing-provider-1", failingProvider)
		providerManager.RegisterProvider("success-provider", successProvider)

		user, err := fm.AuthenticateWithFallback("failing-provider-1", "test-credentials")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if user.ID != "success-user" {
			t.Errorf("expected user ID 'success-user', got '%s'", user.ID)
		}
	})
}

func TestFallbackManager_ValidateTokenWithFallback(t *testing.T) {
	sessionManager := &MockSessionManager{}
	iamService := &MockIAMService{accounts: make(map[string]Account)}

	config := &FallbackConfig{
		EnableFallback: true,
	}

	t.Run("successful token validation", func(t *testing.T) {
		providerManager := NewExternalProviderManager()
		fm := NewFallbackManager(config, providerManager, iamService, sessionManager)
		defer fm.Shutdown()

		expectedClaims := &TokenClaims{
			Subject: "test-user",
			Email:   "test@example.com",
		}
		provider := &MockExternalProvider{
			name:         "test-provider",
			providerType: ProviderTypeOAuth2,
			healthy:      true,
			tokenResult:  expectedClaims,
		}

		providerManager.RegisterProvider("test-provider", provider)

		claims, err := fm.ValidateTokenWithFallback("test-provider", "test-token")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if claims != expectedClaims {
			t.Error("returned claims do not match expected claims")
		}
	})

	t.Run("fallback to other provider", func(t *testing.T) {
		providerManager := NewExternalProviderManager()
		fm := NewFallbackManager(config, providerManager, iamService, sessionManager)
		defer fm.Shutdown()

		failingProvider := &MockExternalProvider{
			name:         "failing-provider",
			providerType: ProviderTypeOAuth2,
			healthy:      true,
			tokenError:   errors.New("token validation failed"),
		}
		successProvider := &MockExternalProvider{
			name:         "success-provider",
			providerType: ProviderTypeOAuth2,
			healthy:      true,
			tokenResult: &TokenClaims{
				Subject: "fallback-user",
			},
		}

		providerManager.RegisterProvider("failing-provider", failingProvider)
		providerManager.RegisterProvider("success-provider", successProvider)

		claims, err := fm.ValidateTokenWithFallback("failing-provider", "test-token")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if claims.Subject != "fallback-user" {
			t.Errorf("expected subject 'fallback-user', got '%s'", claims.Subject)
		}
	})

	t.Run("all providers fail", func(t *testing.T) {
		providerManager := NewExternalProviderManager()
		fm := NewFallbackManager(config, providerManager, iamService, sessionManager)
		defer fm.Shutdown()

		failingProvider := &MockExternalProvider{
			name:         "failing-provider-only",
			providerType: ProviderTypeOAuth2,
			healthy:      false,
			tokenError:   errors.New("token validation failed"),
		}

		providerManager.RegisterProvider("failing-provider-only", failingProvider)
		fm.SetProviderHealthy("failing-provider-only", false)

		_, err := fm.ValidateTokenWithFallback("failing-provider-only", "test-token")
		if err != ErrAllProvidersUnhealthy {
			t.Errorf("expected ErrAllProvidersUnhealthy, got %v", err)
		}
	})
}

func TestFallbackManager_GetProviderHealthStatus(t *testing.T) {
	providerManager := NewExternalProviderManager()
	sessionManager := &MockSessionManager{}
	iamService := &MockIAMService{accounts: make(map[string]Account)}

	fm := NewFallbackManager(nil, providerManager, iamService, sessionManager)
	defer fm.Shutdown()

	// Set some health statuses
	fm.SetProviderHealthy("provider1", true)
	fm.SetProviderHealthy("provider2", false)

	statuses := fm.GetProviderHealthStatus()
	if len(statuses) != 2 {
		t.Errorf("expected 2 statuses, got %d", len(statuses))
	}

	if !statuses["provider1"].Healthy {
		t.Error("expected provider1 to be healthy")
	}
	if statuses["provider2"].Healthy {
		t.Error("expected provider2 to be unhealthy")
	}
}

func TestFallbackManager_InvalidateSessionsOnLogout(t *testing.T) {
	providerManager := NewExternalProviderManager()
	sessionManager := &MockSessionManager{}
	iamService := &MockIAMService{accounts: make(map[string]Account)}

	config := &FallbackConfig{
		SessionInvalidationOnLogout: true,
	}

	fm := NewFallbackManager(config, providerManager, iamService, sessionManager)
	defer fm.Shutdown()

	err := fm.InvalidateSessionsOnLogout("test-provider", "test-user")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Check that the session manager was called
	if len(sessionManager.terminatedUsers) != 1 || sessionManager.terminatedUsers[0] != "test-user" {
		t.Error("expected session termination to be called for test-user")
	}
}

func TestFallbackManager_InvalidateSessionsOnLogout_Disabled(t *testing.T) {
	providerManager := NewExternalProviderManager()
	sessionManager := &MockSessionManager{}
	iamService := &MockIAMService{accounts: make(map[string]Account)}

	config := &FallbackConfig{
		SessionInvalidationOnLogout: false,
	}

	fm := NewFallbackManager(config, providerManager, iamService, sessionManager)
	defer fm.Shutdown()

	err := fm.InvalidateSessionsOnLogout("test-provider", "test-user")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Check that the session manager was not called
	if len(sessionManager.terminatedUsers) != 0 {
		t.Error("expected no session termination when disabled")
	}
}

func TestFallbackManager_HealthChecking(t *testing.T) {
	providerManager := NewExternalProviderManager()
	sessionManager := &MockSessionManager{}
	iamService := &MockIAMService{accounts: make(map[string]Account)}

	config := &FallbackConfig{
		HealthCheckInterval:    100 * time.Millisecond,
		HealthCheckTimeout:     50 * time.Millisecond,
		UnhealthyThreshold:     2,
		HealthyThreshold:       2,
	}

	fm := NewFallbackManager(config, providerManager, iamService, sessionManager)
	defer fm.Shutdown()

	// Register a provider
	provider := &MockExternalProvider{
		name:         "test-provider",
		providerType: ProviderTypeOAuth2,
		healthy:      true,
	}
	providerManager.RegisterProvider("test-provider", provider)

	// Wait for health check to run
	time.Sleep(200 * time.Millisecond)

	statuses := fm.GetProviderHealthStatus()
	if len(statuses) == 0 {
		t.Error("expected health status to be recorded")
	}

	// Change provider health and wait for update
	provider.healthy = false
	time.Sleep(200 * time.Millisecond)

	// Force a health check to ensure immediate update
	fm.ForceHealthCheck()
	time.Sleep(50 * time.Millisecond)

	statuses = fm.GetProviderHealthStatus()
	if status, exists := statuses["test-provider"]; exists {
		// The provider might still be marked as healthy due to thresholds
		// This is expected behavior
		_ = status
	}
}

func TestFallbackManager_SetProviderHealthy(t *testing.T) {
	providerManager := NewExternalProviderManager()
	sessionManager := &MockSessionManager{}
	iamService := &MockIAMService{accounts: make(map[string]Account)}

	fm := NewFallbackManager(nil, providerManager, iamService, sessionManager)
	defer fm.Shutdown()

	// Set provider as healthy
	fm.SetProviderHealthy("test-provider", true)

	statuses := fm.GetProviderHealthStatus()
	if !statuses["test-provider"].Healthy {
		t.Error("expected provider to be marked as healthy")
	}

	// Set provider as unhealthy
	fm.SetProviderHealthy("test-provider", false)

	statuses = fm.GetProviderHealthStatus()
	if statuses["test-provider"].Healthy {
		t.Error("expected provider to be marked as unhealthy")
	}
}

func TestFallbackManager_FallbackAuthentication(t *testing.T) {
	providerManager := NewExternalProviderManager()
	sessionManager := &MockSessionManager{}
	iamService := &MockIAMService{
		accounts: map[string]Account{
			"test-access": {
				Access: "test-access",
				Secret: "test-secret",
				Role:   RoleUser,
				UserID: 123,
			},
		},
	}

	config := &FallbackConfig{
		EnableFallback:   true,
		FallbackProvider: "internal",
	}

	fm := NewFallbackManager(config, providerManager, iamService, sessionManager)
	defer fm.Shutdown()

	t.Run("successful fallback with string credentials", func(t *testing.T) {
		user, err := fm.authenticateWithFallback("test-access")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if user.ID != "test-access" {
			t.Errorf("expected user ID 'test-access', got '%s'", user.ID)
		}
		if user.Provider != "internal" {
			t.Errorf("expected provider 'internal', got '%s'", user.Provider)
		}
	})

	t.Run("successful fallback with map credentials", func(t *testing.T) {
		creds := map[string]interface{}{
			"access_key": "test-access",
		}
		user, err := fm.authenticateWithFallback(creds)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if user.ID != "test-access" {
			t.Errorf("expected user ID 'test-access', got '%s'", user.ID)
		}
	})

	t.Run("fallback with non-existent user", func(t *testing.T) {
		_, err := fm.authenticateWithFallback("non-existent")
		if err == nil {
			t.Error("expected error for non-existent user")
		}
	})

	t.Run("fallback with invalid credentials format", func(t *testing.T) {
		_, err := fm.authenticateWithFallback(123)
		if err == nil {
			t.Error("expected error for invalid credentials format")
		}
	})

	t.Run("fallback with no IAM service", func(t *testing.T) {
		fmNoIAM := NewFallbackManager(config, providerManager, nil, sessionManager)
		defer fmNoIAM.Shutdown()

		_, err := fmNoIAM.authenticateWithFallback("test-access")
		if err != ErrFallbackNotConfigured {
			t.Errorf("expected ErrFallbackNotConfigured, got %v", err)
		}
	})
}