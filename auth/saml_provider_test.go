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
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewSAMLProvider(t *testing.T) {
	tests := []struct {
		name        string
		config      *SAMLConfig
		expectError bool
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "missing name",
			config: &SAMLConfig{
				EntityID: "test-entity",
				SSOURL:   "https://example.com/sso",
			},
			expectError: true,
		},
		{
			name: "missing entity ID",
			config: &SAMLConfig{
				Name:   "test-provider",
				SSOURL: "https://example.com/sso",
			},
			expectError: true,
		},
		{
			name: "missing SSO URL",
			config: &SAMLConfig{
				Name:     "test-provider",
				EntityID: "test-entity",
			},
			expectError: true,
		},
		{
			name: "invalid SSO URL",
			config: &SAMLConfig{
				Name:     "test-provider",
				EntityID: "test-entity",
				SSOURL:   "invalid-url",
			},
			expectError: true,
		},
		{
			name: "valid config",
			config: &SAMLConfig{
				Name:     "test-provider",
				EntityID: "test-entity",
				SSOURL:   "https://example.com/sso",
				Enabled:  true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewSAMLProvider(tt.config)
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

func TestSAMLProvider_GetProviderInfo(t *testing.T) {
	config := &SAMLConfig{
		Name:     "test-saml",
		EntityID: "test-entity",
		SSOURL:   "https://example.com/sso",
		Enabled:  true,
	}

	provider, err := NewSAMLProvider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	info := provider.GetProviderInfo()
	if info.Name != "test-saml" {
		t.Errorf("expected name 'test-saml', got '%s'", info.Name)
	}
	if info.Type != ProviderTypeSAML {
		t.Errorf("expected type '%s', got '%s'", ProviderTypeSAML, info.Type)
	}
	if info.Endpoint != "https://example.com/sso" {
		t.Errorf("expected endpoint 'https://example.com/sso', got '%s'", info.Endpoint)
	}
	if !info.Enabled {
		t.Error("expected provider to be enabled")
	}
}

func TestSAMLProvider_GetProviderType(t *testing.T) {
	config := &SAMLConfig{
		Name:     "test-saml",
		EntityID: "test-entity",
		SSOURL:   "https://example.com/sso",
		Enabled:  true,
	}

	provider, err := NewSAMLProvider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	if provider.GetProviderType() != ProviderTypeSAML {
		t.Errorf("expected provider type '%s', got '%s'", ProviderTypeSAML, provider.GetProviderType())
	}
}

func TestSAMLProvider_IsHealthy(t *testing.T) {
	// Test with disabled provider
	config := &SAMLConfig{
		Name:     "test-saml",
		EntityID: "test-entity",
		SSOURL:   "https://example.com/sso",
		Enabled:  false,
	}

	provider, err := NewSAMLProvider(config)
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

	config.SSOURL = server.URL
	config.Enabled = true

	provider, err = NewSAMLProvider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	if !provider.IsHealthy() {
		t.Error("expected enabled provider with reachable endpoint to be healthy")
	}

	// Test with unreachable endpoint
	config.SSOURL = "https://unreachable.example.com"
	provider, err = NewSAMLProvider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	if provider.IsHealthy() {
		t.Error("expected provider with unreachable endpoint to be unhealthy")
	}
}

func TestSAMLProvider_ValidateToken(t *testing.T) {
	config := &SAMLConfig{
		Name:     "test-saml",
		EntityID: "test-entity",
		SSOURL:   "https://example.com/sso",
		Enabled:  true,
	}

	provider, err := NewSAMLProvider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// SAML provider should not support token validation
	_, err = provider.ValidateToken("test-token")
	if err == nil {
		t.Error("expected error for token validation in SAML provider")
	}
}

func TestSAMLProvider_Authenticate(t *testing.T) {
	config := &SAMLConfig{
		Name:     "test-saml",
		EntityID: "test-entity",
		SSOURL:   "https://example.com/sso",
		Enabled:  true,
		AttributeMapping: AttributeMap{
			UserID: "urn:oid:0.9.2342.19200300.100.1.1",
			Email:  "urn:oid:0.9.2342.19200300.100.1.3",
			Name:   "urn:oid:2.5.4.3",
			Groups: "urn:oid:1.3.6.1.4.1.5923.1.5.1.1",
		},
		AllowedClockSkew: 5 * time.Minute,
	}

	provider, err := NewSAMLProvider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	t.Run("disabled provider", func(t *testing.T) {
		disabledConfig := &SAMLConfig{
			Name:     "test-saml",
			EntityID: "test-entity",
			SSOURL:   "https://example.com/sso",
			Enabled:  false,
			AttributeMapping: AttributeMap{
				UserID: "urn:oid:0.9.2342.19200300.100.1.1",
				Email:  "urn:oid:0.9.2342.19200300.100.1.3",
				Name:   "urn:oid:2.5.4.3",
				Groups: "urn:oid:1.3.6.1.4.1.5923.1.5.1.1",
			},
			AllowedClockSkew: 5 * time.Minute,
		}
		disabledProvider, _ := NewSAMLProvider(disabledConfig)
		
		_, err := disabledProvider.Authenticate(&SAMLCredentials{})
		if err != ErrSAMLProviderNotReady {
			t.Errorf("expected ErrSAMLProviderNotReady, got %v", err)
		}
	})

	t.Run("invalid credentials type", func(t *testing.T) {
		_, err := provider.Authenticate("invalid")
		if err == nil {
			t.Error("expected error for invalid credentials type")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		creds := &SAMLCredentials{
			SAMLResponse: "invalid-base64!@#",
		}
		_, err := provider.Authenticate(creds)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("invalid XML", func(t *testing.T) {
		invalidXML := base64.StdEncoding.EncodeToString([]byte("invalid xml"))
		creds := &SAMLCredentials{
			SAMLResponse: invalidXML,
		}
		_, err := provider.Authenticate(creds)
		if err == nil {
			t.Error("expected error for invalid XML")
		}
	})

	t.Run("valid SAML response", func(t *testing.T) {
		// Create a valid SAML response
		now := time.Now()
		issueTime := now.Format(time.RFC3339)
		notBefore := now.Add(-1 * time.Minute).Format(time.RFC3339)
		notOnOrAfter := now.Add(10 * time.Minute).Format(time.RFC3339)

		samlResponse := SAMLResponse{
			ID:        "test-response-id",
			Version:   "2.0",
			IssueTime: issueTime,
			Status: Status{
				StatusCode: struct {
					Value string `xml:"Value,attr"`
				}{
					Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
				},
			},
			Assertion: SAMLAssertion{
				ID:        "test-assertion-id",
				Version:   "2.0",
				IssueTime: issueTime,
				Issuer:    "test-issuer",
				Subject: Subject{
					NameID: struct {
						Format string `xml:"Format,attr"`
						Value  string `xml:",chardata"`
					}{
						Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
						Value:  "test@example.com",
					},
				},
				Conditions: struct {
					NotBefore    string `xml:"NotBefore,attr"`
					NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
				}{
					NotBefore:    notBefore,
					NotOnOrAfter: notOnOrAfter,
				},
				AttributeStatement: AttributeStatement{
					Attributes: []Attribute{
						{
							Name: "urn:oid:0.9.2342.19200300.100.1.1",
							Values: []AttributeValue{
								{Value: "testuser"},
							},
						},
						{
							Name: "urn:oid:0.9.2342.19200300.100.1.3",
							Values: []AttributeValue{
								{Value: "test@example.com"},
							},
						},
						{
							Name: "urn:oid:2.5.4.3",
							Values: []AttributeValue{
								{Value: "Test User"},
							},
						},
						{
							Name: "urn:oid:1.3.6.1.4.1.5923.1.5.1.1",
							Values: []AttributeValue{
								{Value: "group1"},
								{Value: "group2"},
							},
						},
					},
				},
			},
		}

		xmlData, err := xml.Marshal(samlResponse)
		if err != nil {
			t.Fatalf("failed to marshal SAML response: %v", err)
		}

		encodedResponse := base64.StdEncoding.EncodeToString(xmlData)
		creds := &SAMLCredentials{
			SAMLResponse: encodedResponse,
			RelayState:   "test-relay-state",
		}

		user, err := provider.Authenticate(creds)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user.ID != "testuser" {
			t.Errorf("expected user ID 'testuser', got '%s'", user.ID)
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
		if user.Provider != "test-saml" {
			t.Errorf("expected provider 'test-saml', got '%s'", user.Provider)
		}
	})
}

func TestSAMLProvider_GenerateAuthRequest(t *testing.T) {
	config := &SAMLConfig{
		Name:     "test-saml",
		EntityID: "test-entity",
		SSOURL:   "https://example.com/sso",
		Enabled:  true,
	}

	provider, err := NewSAMLProvider(config)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	t.Run("disabled provider", func(t *testing.T) {
		disabledConfig := &SAMLConfig{
			Name:     "test-saml",
			EntityID: "test-entity",
			SSOURL:   "https://example.com/sso",
			Enabled:  false,
		}
		disabledProvider, _ := NewSAMLProvider(disabledConfig)
		
		_, err := disabledProvider.GenerateAuthRequest("test-relay")
		if err != ErrSAMLProviderNotReady {
			t.Errorf("expected ErrSAMLProviderNotReady, got %v", err)
		}
	})

	t.Run("with relay state", func(t *testing.T) {
		url, err := provider.GenerateAuthRequest("test-relay-state")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if url == "" {
			t.Error("expected non-empty URL")
		}
		// URL should contain the SSO URL
		if !contains(url, "https://example.com/sso") {
			t.Errorf("expected URL to contain SSO URL, got: %s", url)
		}
	})

	t.Run("without relay state", func(t *testing.T) {
		url, err := provider.GenerateAuthRequest("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if url == "" {
			t.Error("expected non-empty URL")
		}
	})
}

func TestValidateSAMLConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *SAMLConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: &SAMLConfig{
				Name:     "test",
				EntityID: "entity",
				SSOURL:   "https://example.com/sso",
			},
			expectError: false,
		},
		{
			name: "missing name",
			config: &SAMLConfig{
				EntityID: "entity",
				SSOURL:   "https://example.com/sso",
			},
			expectError: true,
		},
		{
			name: "missing entity ID",
			config: &SAMLConfig{
				Name:   "test",
				SSOURL: "https://example.com/sso",
			},
			expectError: true,
		},
		{
			name: "missing SSO URL",
			config: &SAMLConfig{
				Name:     "test",
				EntityID: "entity",
			},
			expectError: true,
		},
		{
			name: "invalid SSO URL",
			config: &SAMLConfig{
				Name:     "test",
				EntityID: "entity",
				SSOURL:   "not-a-url",
			},
			expectError: true,
		},
		{
			name: "invalid SLO URL",
			config: &SAMLConfig{
				Name:     "test",
				EntityID: "entity",
				SSOURL:   "https://example.com/sso",
				SLOUrl:   "not-a-url",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSAMLConfig(tt.config)
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())))
}