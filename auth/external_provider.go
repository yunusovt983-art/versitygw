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
	"time"
)

// ExternalProvider defines the interface for external identity providers
type ExternalProvider interface {
	// Authenticate validates credentials and returns external user info
	Authenticate(credentials interface{}) (*ExternalUser, error)
	// ValidateToken validates an external token and returns claims
	ValidateToken(token string) (*TokenClaims, error)
	// GetProviderInfo returns information about this provider
	GetProviderInfo() *ProviderInfo
	// IsHealthy checks if the provider is available
	IsHealthy() bool
	// GetProviderType returns the type of this provider
	GetProviderType() ProviderType
}

// ProviderType represents the type of external provider
type ProviderType string

const (
	ProviderTypeSAML   ProviderType = "saml"
	ProviderTypeOAuth2 ProviderType = "oauth2"
	ProviderTypeOIDC   ProviderType = "oidc"
)

// ExternalUser represents a user from an external identity provider
type ExternalUser struct {
	ID         string                 `json:"id"`
	Email      string                 `json:"email"`
	Name       string                 `json:"name"`
	Groups     []string               `json:"groups"`
	Attributes map[string]interface{} `json:"attributes"`
	Provider   string                 `json:"provider"`
}

// TokenClaims represents claims from an external token
type TokenClaims struct {
	Subject   string                 `json:"sub"`
	Email     string                 `json:"email"`
	Name      string                 `json:"name"`
	Groups    []string               `json:"groups"`
	ExpiresAt time.Time              `json:"exp"`
	IssuedAt  time.Time              `json:"iat"`
	Issuer    string                 `json:"iss"`
	Audience  []string               `json:"aud"`
	Claims    map[string]interface{} `json:"claims"`
}

// ProviderInfo contains metadata about an external provider
type ProviderInfo struct {
	Name        string       `json:"name"`
	Type        ProviderType `json:"type"`
	Description string       `json:"description"`
	Endpoint    string       `json:"endpoint"`
	Enabled     bool         `json:"enabled"`
}

// ExternalProviderManager manages multiple external identity providers
type ExternalProviderManager interface {
	// RegisterProvider registers a new external provider
	RegisterProvider(name string, provider ExternalProvider) error
	// GetProvider retrieves a provider by name
	GetProvider(name string) (ExternalProvider, error)
	// ListProviders returns all registered providers
	ListProviders() map[string]ExternalProvider
	// AuthenticateWithProvider attempts authentication with a specific provider
	AuthenticateWithProvider(providerName string, credentials interface{}) (*ExternalUser, error)
	// ValidateTokenWithProvider validates a token with a specific provider
	ValidateTokenWithProvider(providerName string, token string) (*TokenClaims, error)
	// GetHealthyProviders returns providers that are currently healthy
	GetHealthyProviders() []string
}