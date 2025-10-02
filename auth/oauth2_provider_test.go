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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNewOAuth2Provider(t *testing.T) {
	tests := []struct {
		name        string
		config      *OAuth2Config
		expectError bool
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "missing name",
			config: &OAuth2Config{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				AuthorizeURL: "https://example.com/auth",
				TokenURL:     "https://example.com/token",
			},
			expectError: true,
		},
		{
			name: "missing client ID",
			config: &OAuth2Config{
				Name:         "test-provider",
				ClientSecret: "test-secret",
				AuthorizeURL: "https://example.com/auth",
				TokenURL:     "https://example.com/token",
			},
			expectError: true,
		},
		{
			name: "missing client secret",
			config: &OAuth2Config{
				Name:         "test-provider",
				ClientID:     "test-client",
				AuthorizeURL: "https://example.com/auth",
				TokenURL:     "https://example.com/token",
			},
			expectError: true,
		},
		{
			name: "missing authorize URL",
			config: &OAuth2Config{
				Name:         "test-provider",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				TokenURL:     "https://example.com/token",
			},
			expectError: true,
		},
		{
			name: "missing token URL",
			config: &OAuth2Config{
				Name:         "test-provider",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				AuthorizeURL: "https://example.com/auth",
			},
			expectError: true,
		},
		{
			name: "invalid authorize URL",
			config: &OAuth2Config{
				Name:         "test-provider",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				AuthorizeURL: "://invalid-url",
				TokenURL:     "https://example.com/token",
			},
			expectError: true,
		},
		{
			name: "valid config",
			config: &OAuth2Config{
				Name:         "test-provider",
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				AuthorizeURL: "https://example.com/auth",
				TokenURL:     "https://example.com/token",
				Enabled:      true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewOAuth2Provider(tt.config)
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if provider != nil {
					t.Error("expected nil provider on error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if provider == nil {
					t.Error("expected provider but got nil")
				}
			}
		})
	}
}

func TestOAuth2Provider_GetProviderInfo(t *testing.T) {
	config := &OAuth2Config{
		Name:         "test-oauth2",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		AuthorizeURL: "https://example.com/auth",
		TokenURL:     "https://example.com/token",
		Issuer:       "https://example.com",
		Enabled:      true,
	}

	provider, err := NewOAuth2Provider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	info := provider.GetProviderInfo()
	if info.Name != "test-oauth2" {
		t.Errorf("expected name 'test-oauth2', got '%s'", info.Name)
	}
	if info.Type != ProviderTypeOAuth2 {
		t.Errorf("expected type '%s', got '%s'", ProviderTypeOAuth2, info.Type)
	}
	if info.Endpoint != "https://example.com/auth" {
		t.Errorf("expected endpoint 'https://example.com/auth', got '%s'", info.Endpoint)
	}
	if !info.Enabled {
		t.Error("expected provider to be enabled")
	}
}

func TestOAuth2Provider_GetProviderType(t *testing.T) {
	config := &OAuth2Config{
		Name:         "test-oauth2",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		AuthorizeURL: "https://example.com/auth",
		TokenURL:     "https://example.com/token",
		Enabled:      true,
	}

	provider, err := NewOAuth2Provider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	if provider.GetProviderType() != ProviderTypeOAuth2 {
		t.Errorf("expected provider type '%s', got '%s'", ProviderTypeOAuth2, provider.GetProviderType())
	}
}

func TestOAuth2Provider_IsHealthy(t *testing.T) {
	// Test with disabled provider
	config := &OAuth2Config{
		Name:         "test-oauth2",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		AuthorizeURL: "https://example.com/auth",
		TokenURL:     "https://example.com/token",
		Enabled:      false,
	}

	provider, err := NewOAuth2Provider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	if provider.IsHealthy() {
		t.Error("expected disabled provider to be unhealthy")
	}

	// Test with enabled provider and mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config.TokenURL = server.URL
	config.Enabled = true

	provider, err = NewOAuth2Provider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	if !provider.IsHealthy() {
		t.Error("expected enabled provider with reachable endpoint to be healthy")
	}

	// Test with unreachable endpoint
	config.TokenURL = "https://unreachable.example.com"
	provider, err = NewOAuth2Provider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	if provider.IsHealthy() {
		t.Error("expected provider with unreachable endpoint to be unhealthy")
	}
}

func TestOAuth2Provider_GenerateAuthURL(t *testing.T) {
	config := &OAuth2Config{
		Name:         "test-oauth2",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		AuthorizeURL: "https://example.com/auth",
		TokenURL:     "https://example.com/token",
		RedirectURL:  "https://app.example.com/callback",
		Scopes:       []string{"openid", "profile", "email"},
		Enabled:      true,
	}

	provider, err := NewOAuth2Provider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	t.Run("disabled provider", func(t *testing.T) {
		disabledConfig := &OAuth2Config{
			Name:         "test-oauth2",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			AuthorizeURL: "https://example.com/auth",
			TokenURL:     "https://example.com/token",
			Enabled:      false,
		}
		disabledProvider, _ := NewOAuth2Provider(disabledConfig)

		_, err := disabledProvider.GenerateAuthURL("test-state")
		if err != ErrOAuth2ProviderNotReady {
			t.Errorf("expected ErrOAuth2ProviderNotReady, got %v", err)
		}
	})

	t.Run("with state", func(t *testing.T) {
		authURL, err := provider.GenerateAuthURL("test-state")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		parsedURL, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("failed to parse auth URL: %v", err)
		}

		params := parsedURL.Query()
		if params.Get("response_type") != "code" {
			t.Errorf("expected response_type 'code', got '%s'", params.Get("response_type"))
		}
		if params.Get("client_id") != "test-client" {
			t.Errorf("expected client_id 'test-client', got '%s'", params.Get("client_id"))
		}
		if params.Get("state") != "test-state" {
			t.Errorf("expected state 'test-state', got '%s'", params.Get("state"))
		}
		if params.Get("scope") != "openid profile email" {
			t.Errorf("expected scope 'openid profile email', got '%s'", params.Get("scope"))
		}
		if params.Get("redirect_uri") != "https://app.example.com/callback" {
			t.Errorf("expected redirect_uri 'https://app.example.com/callback', got '%s'", params.Get("redirect_uri"))
		}
	})

	t.Run("without state", func(t *testing.T) {
		authURL, err := provider.GenerateAuthURL("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		parsedURL, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("failed to parse auth URL: %v", err)
		}

		params := parsedURL.Query()
		if params.Get("state") != "" {
			t.Errorf("expected empty state, got '%s'", params.Get("state"))
		}
	})
}

func TestOAuth2Provider_Authenticate(t *testing.T) {
	// Create mock servers for token and userinfo endpoints
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tokenResponse := TokenResponse{
			AccessToken:  "test-access-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "test-refresh-token",
			Scope:        "openid profile email",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse)
	}))
	defer tokenServer.Close()

	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userInfo := UserInfo{
			Sub:           "test-user-id",
			Name:          "Test User",
			Email:         "test@example.com",
			EmailVerified: true,
			Groups:        []string{"group1", "group2"},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer userInfoServer.Close()

	config := &OAuth2Config{
		Name:         "test-oauth2",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		AuthorizeURL: "https://example.com/auth",
		TokenURL:     tokenServer.URL,
		UserInfoURL:  userInfoServer.URL,
		Enabled:      true,
	}

	provider, err := NewOAuth2Provider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	t.Run("disabled provider", func(t *testing.T) {
		disabledConfig := &OAuth2Config{
			Name:         "test-oauth2",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			AuthorizeURL: "https://example.com/auth",
			TokenURL:     tokenServer.URL,
			UserInfoURL:  userInfoServer.URL,
			Enabled:      false,
		}
		disabledProvider, _ := NewOAuth2Provider(disabledConfig)

		_, err := disabledProvider.Authenticate(&OAuth2Credentials{})
		if err != ErrOAuth2ProviderNotReady {
			t.Errorf("expected ErrOAuth2ProviderNotReady, got %v", err)
		}
	})

	t.Run("invalid credentials type", func(t *testing.T) {
		_, err := provider.Authenticate("invalid")
		if err == nil {
			t.Error("expected error for invalid credentials type")
		}
	})

	t.Run("missing code and access token", func(t *testing.T) {
		creds := &OAuth2Credentials{}
		_, err := provider.Authenticate(creds)
		if err == nil {
			t.Error("expected error for missing code and access token")
		}
	})

	t.Run("authenticate with code", func(t *testing.T) {
		creds := &OAuth2Credentials{
			Code:        "test-auth-code",
			RedirectURI: "https://app.example.com/callback",
		}

		user, err := provider.Authenticate(creds)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user.ID != "test-user-id" {
			t.Errorf("expected user ID 'test-user-id', got '%s'", user.ID)
		}
		if user.Email != "test@example.com" {
			t.Errorf("expected email 'test@example.com', got '%s'", user.Email)
		}
		if user.Name != "Test User" {
			t.Errorf("expected name 'Test User', got '%s'", user.Name)
		}
		if len(user.Groups) != 2 || user.Groups[0] != "group1" || user.Groups[1] != "group2" {
			t.Errorf("expected groups ['group1', 'group2'], got %v", user.Groups)
		}
		if user.Provider != "test-oauth2" {
			t.Errorf("expected provider 'test-oauth2', got '%s'", user.Provider)
		}
	})

	t.Run("authenticate with access token", func(t *testing.T) {
		creds := &OAuth2Credentials{
			AccessToken: "test-access-token",
		}

		user, err := provider.Authenticate(creds)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user.ID != "test-user-id" {
			t.Errorf("expected user ID 'test-user-id', got '%s'", user.ID)
		}
	})
}

func TestOAuth2Provider_ValidateToken(t *testing.T) {
	config := &OAuth2Config{
		Name:         "test-oauth2",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		AuthorizeURL: "https://example.com/auth",
		TokenURL:     "https://example.com/token",
		Enabled:      true,
	}

	provider, err := NewOAuth2Provider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	t.Run("disabled provider", func(t *testing.T) {
		disabledConfig := &OAuth2Config{
			Name:         "test-oauth2",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			AuthorizeURL: "https://example.com/auth",
			TokenURL:     "https://example.com/token",
			Enabled:      false,
		}
		disabledProvider, _ := NewOAuth2Provider(disabledConfig)

		_, err := disabledProvider.ValidateToken("test-token")
		if err != ErrOAuth2ProviderNotReady {
			t.Errorf("expected ErrOAuth2ProviderNotReady, got %v", err)
		}
	})

	t.Run("oauth2 access token", func(t *testing.T) {
		// Test with non-JWT token (OAuth2 access token)
		claims, err := provider.ValidateToken("opaque-access-token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if claims.Subject != "unknown" {
			t.Errorf("expected subject 'unknown', got '%s'", claims.Subject)
		}
	})

	t.Run("invalid JWT token", func(t *testing.T) {
		// Test with invalid JWT token
		_, err := provider.ValidateToken("invalid.jwt.token")
		if err == nil {
			t.Error("expected error for invalid JWT token")
		}
	})
}

func TestValidateOAuth2Config(t *testing.T) {
	tests := []struct {
		name        string
		config      *OAuth2Config
		expectError bool
	}{
		{
			name: "valid config",
			config: &OAuth2Config{
				Name:         "test",
				ClientID:     "client",
				ClientSecret: "secret",
				AuthorizeURL: "https://example.com/auth",
				TokenURL:     "https://example.com/token",
			},
			expectError: false,
		},
		{
			name: "missing name",
			config: &OAuth2Config{
				ClientID:     "client",
				ClientSecret: "secret",
				AuthorizeURL: "https://example.com/auth",
				TokenURL:     "https://example.com/token",
			},
			expectError: true,
		},
		{
			name: "missing client ID",
			config: &OAuth2Config{
				Name:         "test",
				ClientSecret: "secret",
				AuthorizeURL: "https://example.com/auth",
				TokenURL:     "https://example.com/token",
			},
			expectError: true,
		},
		{
			name: "missing client secret",
			config: &OAuth2Config{
				Name:         "test",
				ClientID:     "client",
				AuthorizeURL: "https://example.com/auth",
				TokenURL:     "https://example.com/token",
			},
			expectError: true,
		},
		{
			name: "missing authorize URL",
			config: &OAuth2Config{
				Name:         "test",
				ClientID:     "client",
				ClientSecret: "secret",
				TokenURL:     "https://example.com/token",
			},
			expectError: true,
		},
		{
			name: "missing token URL",
			config: &OAuth2Config{
				Name:         "test",
				ClientID:     "client",
				ClientSecret: "secret",
				AuthorizeURL: "https://example.com/auth",
			},
			expectError: true,
		},
		{
			name: "invalid authorize URL",
			config: &OAuth2Config{
				Name:         "test",
				ClientID:     "client",
				ClientSecret: "secret",
				AuthorizeURL: "://not-a-url",
				TokenURL:     "https://example.com/token",
			},
			expectError: true,
		},
		{
			name: "invalid token URL",
			config: &OAuth2Config{
				Name:         "test",
				ClientID:     "client",
				ClientSecret: "secret",
				AuthorizeURL: "https://example.com/auth",
				TokenURL:     "://not-a-url",
			},
			expectError: true,
		},
		{
			name: "config with defaults applied",
			config: &OAuth2Config{
				Name:         "test",
				ClientID:     "client",
				ClientSecret: "secret",
				AuthorizeURL: "https://example.com/auth",
				TokenURL:     "https://example.com/token",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOAuth2Config(tt.config)
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check that defaults are applied for valid configs
			if !tt.expectError && err == nil {
				if tt.config.AllowedClockSkew == 0 {
					t.Error("expected AllowedClockSkew to be set to default")
				}
				if tt.config.TokenCacheTTL == 0 {
					t.Error("expected TokenCacheTTL to be set to default")
				}
				if tt.config.JWKSCacheTTL == 0 {
					t.Error("expected JWKSCacheTTL to be set to default")
				}
				if len(tt.config.Scopes) == 0 {
					t.Error("expected Scopes to be set to default")
				}
			}
		})
	}
}