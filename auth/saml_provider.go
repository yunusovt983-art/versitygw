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
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalidSAMLAssertion = errors.New("invalid SAML assertion")
	ErrSAMLProviderNotReady = errors.New("SAML provider not ready")
	ErrInvalidSAMLResponse  = errors.New("invalid SAML response")
)

// SAMLProvider implements ExternalProvider for SAML authentication
type SAMLProvider struct {
	config *SAMLConfig
	client *http.Client
}

// SAMLConfig contains configuration for SAML provider
type SAMLConfig struct {
	Name                string        `json:"name"`
	EntityID            string        `json:"entity_id"`
	SSOURL              string        `json:"sso_url"`
	SLOUrl              string        `json:"slo_url"`
	Certificate         string        `json:"certificate"`
	PrivateKey          string        `json:"private_key"`
	IDPMetadataURL      string        `json:"idp_metadata_url"`
	IDPCertificate      string        `json:"idp_certificate"`
	AttributeMapping    AttributeMap  `json:"attribute_mapping"`
	SignRequests        bool          `json:"sign_requests"`
	ValidateSignatures  bool          `json:"validate_signatures"`
	AllowedClockSkew    time.Duration `json:"allowed_clock_skew"`
	SessionTimeout      time.Duration `json:"session_timeout"`
	Enabled             bool          `json:"enabled"`
}

// AttributeMap defines how SAML attributes map to user fields
type AttributeMap struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Groups string `json:"groups"`
}

// SAMLCredentials represents SAML authentication credentials
type SAMLCredentials struct {
	SAMLResponse string `json:"saml_response"`
	RelayState   string `json:"relay_state"`
}

// SAMLAssertion represents a parsed SAML assertion
type SAMLAssertion struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID         string   `xml:"ID,attr"`
	Version    string   `xml:"Version,attr"`
	IssueTime  string   `xml:"IssueInstant,attr"`
	Issuer     string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject    Subject  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions struct {
		NotBefore    string `xml:"NotBefore,attr"`
		NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AttributeStatement AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

// Subject represents SAML assertion subject
type Subject struct {
	NameID struct {
		Format string `xml:"Format,attr"`
		Value  string `xml:",chardata"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
}

// AttributeStatement contains SAML attributes
type AttributeStatement struct {
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// Attribute represents a SAML attribute
type Attribute struct {
	Name   string           `xml:"Name,attr"`
	Values []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

// AttributeValue represents a SAML attribute value
type AttributeValue struct {
	Value string `xml:",chardata"`
}

// SAMLResponse represents the top-level SAML response
type SAMLResponse struct {
	XMLName   xml.Name      `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID        string        `xml:"ID,attr"`
	Version   string        `xml:"Version,attr"`
	IssueTime string        `xml:"IssueInstant,attr"`
	Status    Status        `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Assertion SAMLAssertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

// Status represents SAML response status
type Status struct {
	StatusCode struct {
		Value string `xml:"Value,attr"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

// NewSAMLProvider creates a new SAML provider instance
func NewSAMLProvider(config *SAMLConfig) (*SAMLProvider, error) {
	if config == nil {
		return nil, errors.New("SAML config cannot be nil")
	}

	if err := validateSAMLConfig(config); err != nil {
		return nil, fmt.Errorf("invalid SAML config: %w", err)
	}

	provider := &SAMLProvider{
		config: config,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	return provider, nil
}

// validateSAMLConfig validates the SAML configuration
func validateSAMLConfig(config *SAMLConfig) error {
	if config.Name == "" {
		return errors.New("name is required")
	}
	if config.EntityID == "" {
		return errors.New("entity_id is required")
	}
	if config.SSOURL == "" {
		return errors.New("sso_url is required")
	}

	// Validate URLs
	if _, err := url.Parse(config.SSOURL); err != nil {
		return fmt.Errorf("invalid sso_url: %w", err)
	}
	if config.SLOUrl != "" {
		if _, err := url.Parse(config.SLOUrl); err != nil {
			return fmt.Errorf("invalid slo_url: %w", err)
		}
	}

	// Set defaults
	if config.AllowedClockSkew == 0 {
		config.AllowedClockSkew = 5 * time.Minute
	}
	if config.SessionTimeout == 0 {
		config.SessionTimeout = 24 * time.Hour
	}

	return nil
}

// Authenticate validates SAML credentials and returns user information
func (p *SAMLProvider) Authenticate(credentials interface{}) (*ExternalUser, error) {
	if !p.config.Enabled {
		return nil, ErrSAMLProviderNotReady
	}

	samlCreds, ok := credentials.(*SAMLCredentials)
	if !ok {
		return nil, errors.New("invalid credentials type for SAML provider")
	}

	// Decode base64 SAML response
	samlResponseData, err := base64.StdEncoding.DecodeString(samlCreds.SAMLResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAML response: %w", err)
	}

	// Parse SAML response
	var samlResponse SAMLResponse
	if err := xml.Unmarshal(samlResponseData, &samlResponse); err != nil {
		return nil, fmt.Errorf("failed to parse SAML response: %w", err)
	}

	// Validate SAML response
	if err := p.validateSAMLResponse(&samlResponse); err != nil {
		return nil, fmt.Errorf("SAML response validation failed: %w", err)
	}

	// Extract user information from assertion
	user, err := p.extractUserFromAssertion(&samlResponse.Assertion)
	if err != nil {
		return nil, fmt.Errorf("failed to extract user from assertion: %w", err)
	}

	user.Provider = p.config.Name
	return user, nil
}

// ValidateToken validates a SAML token (not typically used in SAML flow)
func (p *SAMLProvider) ValidateToken(token string) (*TokenClaims, error) {
	// SAML doesn't typically use tokens in the same way as OAuth2/OIDC
	// This method is included for interface compliance but may not be used
	return nil, errors.New("token validation not supported for SAML provider")
}

// GetProviderInfo returns information about this SAML provider
func (p *SAMLProvider) GetProviderInfo() *ProviderInfo {
	return &ProviderInfo{
		Name:        p.config.Name,
		Type:        ProviderTypeSAML,
		Description: fmt.Sprintf("SAML provider for %s", p.config.EntityID),
		Endpoint:    p.config.SSOURL,
		Enabled:     p.config.Enabled,
	}
}

// IsHealthy checks if the SAML provider is healthy
func (p *SAMLProvider) IsHealthy() bool {
	if !p.config.Enabled {
		return false
	}

	// Check if we can reach the SSO URL
	resp, err := p.client.Head(p.config.SSOURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode < 400
}

// GetProviderType returns the provider type
func (p *SAMLProvider) GetProviderType() ProviderType {
	return ProviderTypeSAML
}

// validateSAMLResponse validates the SAML response structure and timing
func (p *SAMLProvider) validateSAMLResponse(response *SAMLResponse) error {
	// Check status
	if response.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return fmt.Errorf("SAML response status not successful: %s", response.Status.StatusCode.Value)
	}

	// Validate assertion timing
	assertion := &response.Assertion
	
	// Parse issue time
	issueTime, err := time.Parse(time.RFC3339, assertion.IssueTime)
	if err != nil {
		return fmt.Errorf("invalid assertion issue time: %w", err)
	}

	// Check if assertion is not too old or from the future
	now := time.Now()
	if now.Sub(issueTime) > p.config.AllowedClockSkew {
		if issueTime.Sub(now) > p.config.AllowedClockSkew {
			return errors.New("assertion issue time is too far in the future")
		}
	}

	// Validate conditions if present
	if assertion.Conditions.NotBefore != "" {
		notBefore, err := time.Parse(time.RFC3339, assertion.Conditions.NotBefore)
		if err != nil {
			return fmt.Errorf("invalid NotBefore time: %w", err)
		}
		if now.Before(notBefore.Add(-p.config.AllowedClockSkew)) {
			return errors.New("assertion not yet valid")
		}
	}

	if assertion.Conditions.NotOnOrAfter != "" {
		notOnOrAfter, err := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter)
		if err != nil {
			return fmt.Errorf("invalid NotOnOrAfter time: %w", err)
		}
		if now.After(notOnOrAfter.Add(p.config.AllowedClockSkew)) {
			return errors.New("assertion has expired")
		}
	}

	return nil
}

// extractUserFromAssertion extracts user information from SAML assertion
func (p *SAMLProvider) extractUserFromAssertion(assertion *SAMLAssertion) (*ExternalUser, error) {
	user := &ExternalUser{
		ID:         assertion.Subject.NameID.Value,
		Attributes: make(map[string]interface{}),
	}

	// Extract attributes based on mapping configuration
	for _, attr := range assertion.AttributeStatement.Attributes {
		values := make([]string, len(attr.Values))
		for i, val := range attr.Values {
			values[i] = val.Value
		}

		// Map attributes to user fields
		switch attr.Name {
		case p.config.AttributeMapping.Email:
			if len(values) > 0 {
				user.Email = values[0]
			}
		case p.config.AttributeMapping.Name:
			if len(values) > 0 {
				user.Name = values[0]
			}
		case p.config.AttributeMapping.Groups:
			user.Groups = values
		case p.config.AttributeMapping.UserID:
			if len(values) > 0 {
				user.ID = values[0]
			}
		}

		// Store all attributes for potential future use
		if len(values) == 1 {
			user.Attributes[attr.Name] = values[0]
		} else {
			user.Attributes[attr.Name] = values
		}
	}

	// Validate required fields
	if user.ID == "" {
		return nil, errors.New("user ID not found in SAML assertion")
	}

	return user, nil
}

// GenerateAuthRequest generates a SAML authentication request URL
func (p *SAMLProvider) GenerateAuthRequest(relayState string) (string, error) {
	if !p.config.Enabled {
		return "", ErrSAMLProviderNotReady
	}

	// Create basic auth request parameters
	params := url.Values{}
	params.Set("SAMLRequest", "")  // This would be a proper SAML AuthnRequest in a full implementation
	if relayState != "" {
		params.Set("RelayState", relayState)
	}

	authURL := p.config.SSOURL
	if strings.Contains(authURL, "?") {
		authURL += "&" + params.Encode()
	} else {
		authURL += "?" + params.Encode()
	}

	return authURL, nil
}

// ValidateCertificate validates the IDP certificate if configured
func (p *SAMLProvider) ValidateCertificate(certData []byte) error {
	if p.config.IDPCertificate == "" {
		return nil // Certificate validation not configured
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is expired
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("certificate is not valid for current time")
	}

	return nil
}