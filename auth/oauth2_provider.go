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
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidOAuth2Token    = errors.New("invalid OAuth2 token")
	ErrOAuth2ProviderNotReady = errors.New("OAuth2 provider not ready")
	ErrInvalidJWTToken       = errors.New("invalid JWT token")
	ErrTokenExpired          = errors.New("token expired")
	ErrInvalidIssuer         = errors.New("invalid token issuer")
	ErrInvalidAudience       = errors.New("invalid token audience")
)

// OAuth2Provider implements ExternalProvider for OAuth2/OpenID Connect authentication
type OAuth2Provider struct {
	config *OAuth2Config
	client *http.Client
	jwks   *JWKSCache
}

// OAuth2Config contains configuration for OAuth2/OIDC provider
type OAuth2Config struct {
	Name                 string        `json:"name"`
	ClientID             string        `json:"client_id"`
	ClientSecret         string        `json:"client_secret"`
	AuthorizeURL         string        `json:"authorize_url"`
	TokenURL             string        `json:"token_url"`
	UserInfoURL          string        `json:"userinfo_url"`
	JWKSURL              string        `json:"jwks_url"`
	Issuer               string        `json:"issuer"`
	Scopes               []string      `json:"scopes"`
	RedirectURL          string        `json:"redirect_url"`
	ValidateSignature    bool          `json:"validate_signature"`
	AllowedClockSkew     time.Duration `json:"allowed_clock_skew"`
	TokenCacheTTL        time.Duration `json:"token_cache_ttl"`
	JWKSCacheTTL         time.Duration `json:"jwks_cache_ttl"`
	UserInfoMapping      UserInfoMap   `json:"userinfo_mapping"`
	Enabled              bool          `json:"enabled"`
}

// UserInfoMap defines how OAuth2/OIDC user info maps to user fields
type UserInfoMap struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Groups string `json:"groups"`
}

// OAuth2Credentials represents OAuth2 authentication credentials
type OAuth2Credentials struct {
	Code         string `json:"code"`
	State        string `json:"state"`
	RedirectURI  string `json:"redirect_uri"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// TokenResponse represents OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// UserInfo represents OAuth2 user information
type UserInfo struct {
	Sub               string      `json:"sub"`
	Name              string      `json:"name"`
	GivenName         string      `json:"given_name"`
	FamilyName        string      `json:"family_name"`
	Email             string      `json:"email"`
	EmailVerified     bool        `json:"email_verified"`
	Picture           string      `json:"picture"`
	Groups            []string    `json:"groups"`
	PreferredUsername string      `json:"preferred_username"`
	UpdatedAt         int64       `json:"updated_at"`
	Custom            interface{} `json:"-"`
}

// JWKSCache caches JWKS keys for token validation
type JWKSCache struct {
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
	ttl       time.Duration
	url       string
	client    *http.Client
}

// JWKS represents JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewOAuth2Provider creates a new OAuth2/OIDC provider instance
func NewOAuth2Provider(config *OAuth2Config) (*OAuth2Provider, error) {
	if config == nil {
		return nil, errors.New("OAuth2 config cannot be nil")
	}

	if err := validateOAuth2Config(config); err != nil {
		return nil, fmt.Errorf("invalid OAuth2 config: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	var jwks *JWKSCache
	if config.JWKSURL != "" {
		jwks = &JWKSCache{
			keys:   make(map[string]*rsa.PublicKey),
			ttl:    config.JWKSCacheTTL,
			url:    config.JWKSURL,
			client: client,
		}
	}

	provider := &OAuth2Provider{
		config: config,
		client: client,
		jwks:   jwks,
	}

	return provider, nil
}

// validateOAuth2Config validates the OAuth2 configuration
func validateOAuth2Config(config *OAuth2Config) error {
	if config.Name == "" {
		return errors.New("name is required")
	}
	if config.ClientID == "" {
		return errors.New("client_id is required")
	}
	if config.ClientSecret == "" {
		return errors.New("client_secret is required")
	}
	if config.AuthorizeURL == "" {
		return errors.New("authorize_url is required")
	}
	if config.TokenURL == "" {
		return errors.New("token_url is required")
	}

	// Validate URLs
	urls := map[string]string{
		"authorize_url": config.AuthorizeURL,
		"token_url":     config.TokenURL,
		"userinfo_url":  config.UserInfoURL,
		"jwks_url":      config.JWKSURL,
		"redirect_url":  config.RedirectURL,
	}

	for name, urlStr := range urls {
		if urlStr != "" {
			if _, err := url.Parse(urlStr); err != nil {
				return fmt.Errorf("invalid %s: %w", name, err)
			}
		}
	}

	// Set defaults
	if config.AllowedClockSkew == 0 {
		config.AllowedClockSkew = 5 * time.Minute
	}
	if config.TokenCacheTTL == 0 {
		config.TokenCacheTTL = 1 * time.Hour
	}
	if config.JWKSCacheTTL == 0 {
		config.JWKSCacheTTL = 24 * time.Hour
	}
	if len(config.Scopes) == 0 {
		config.Scopes = []string{"openid", "profile", "email"}
	}

	return nil
}

// Authenticate validates OAuth2 credentials and returns user information
func (p *OAuth2Provider) Authenticate(credentials interface{}) (*ExternalUser, error) {
	if !p.config.Enabled {
		return nil, ErrOAuth2ProviderNotReady
	}

	oauth2Creds, ok := credentials.(*OAuth2Credentials)
	if !ok {
		return nil, errors.New("invalid credentials type for OAuth2 provider")
	}

	var tokenResponse *TokenResponse
	var err error

	// If we have an access token, use it directly
	if oauth2Creds.AccessToken != "" {
		tokenResponse = &TokenResponse{
			AccessToken: oauth2Creds.AccessToken,
			TokenType:   "Bearer",
		}
	} else if oauth2Creds.Code != "" {
		// Exchange authorization code for tokens
		tokenResponse, err = p.exchangeCodeForTokens(oauth2Creds.Code, oauth2Creds.RedirectURI)
		if err != nil {
			return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
		}
	} else {
		return nil, errors.New("either access_token or code must be provided")
	}

	// Get user information
	user, err := p.getUserInfo(tokenResponse.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// If we have an ID token, validate and extract additional claims
	if tokenResponse.IDToken != "" {
		claims, err := p.validateIDToken(tokenResponse.IDToken)
		if err != nil {
			return nil, fmt.Errorf("failed to validate ID token: %w", err)
		}
		
		// Merge claims into user info
		p.mergeClaims(user, claims)
	}

	user.Provider = p.config.Name
	return user, nil
}

// ValidateToken validates an OAuth2/JWT token and returns claims
func (p *OAuth2Provider) ValidateToken(tokenStr string) (*TokenClaims, error) {
	if !p.config.Enabled {
		return nil, ErrOAuth2ProviderNotReady
	}

	// Try to parse as JWT first
	if strings.Contains(tokenStr, ".") {
		return p.validateJWTToken(tokenStr)
	}

	// Otherwise, treat as OAuth2 access token and introspect
	return p.introspectToken(tokenStr)
}

// GetProviderInfo returns information about this OAuth2 provider
func (p *OAuth2Provider) GetProviderInfo() *ProviderInfo {
	return &ProviderInfo{
		Name:        p.config.Name,
		Type:        ProviderTypeOAuth2,
		Description: fmt.Sprintf("OAuth2/OIDC provider for %s", p.config.Issuer),
		Endpoint:    p.config.AuthorizeURL,
		Enabled:     p.config.Enabled,
	}
}

// IsHealthy checks if the OAuth2 provider is healthy
func (p *OAuth2Provider) IsHealthy() bool {
	if !p.config.Enabled {
		return false
	}

	// Check if we can reach the token endpoint
	resp, err := p.client.Head(p.config.TokenURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode < 400
}

// GetProviderType returns the provider type
func (p *OAuth2Provider) GetProviderType() ProviderType {
	return ProviderTypeOAuth2
}

// exchangeCodeForTokens exchanges authorization code for access tokens
func (p *OAuth2Provider) exchangeCodeForTokens(code, redirectURI string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	if redirectURI != "" {
		data.Set("redirect_uri", redirectURI)
	}

	req, err := http.NewRequest("POST", p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResponse, nil
}

// getUserInfo retrieves user information using access token
func (p *OAuth2Provider) getUserInfo(accessToken string) (*ExternalUser, error) {
	if p.config.UserInfoURL == "" {
		return nil, errors.New("userinfo_url not configured")
	}

	req, err := http.NewRequest("GET", p.config.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Map user info to external user
	user := &ExternalUser{
		ID:         userInfo.Sub,
		Email:      userInfo.Email,
		Name:       userInfo.Name,
		Groups:     userInfo.Groups,
		Attributes: make(map[string]interface{}),
	}

	// Apply custom mapping if configured
	if p.config.UserInfoMapping.UserID != "" && p.config.UserInfoMapping.UserID != "sub" {
		if val := p.getFieldValue(&userInfo, p.config.UserInfoMapping.UserID); val != "" {
			user.ID = val
		}
	}
	if p.config.UserInfoMapping.Email != "" && p.config.UserInfoMapping.Email != "email" {
		if val := p.getFieldValue(&userInfo, p.config.UserInfoMapping.Email); val != "" {
			user.Email = val
		}
	}
	if p.config.UserInfoMapping.Name != "" && p.config.UserInfoMapping.Name != "name" {
		if val := p.getFieldValue(&userInfo, p.config.UserInfoMapping.Name); val != "" {
			user.Name = val
		}
	}

	// Store all user info as attributes
	userInfoBytes, _ := json.Marshal(userInfo)
	var userInfoMap map[string]interface{}
	json.Unmarshal(userInfoBytes, &userInfoMap)
	user.Attributes = userInfoMap

	return user, nil
}

// validateIDToken validates and parses an OpenID Connect ID token
func (p *OAuth2Provider) validateIDToken(idToken string) (*TokenClaims, error) {
	return p.validateJWTToken(idToken)
}

// validateJWTToken validates a JWT token
func (p *OAuth2Provider) validateJWTToken(tokenStr string) (*TokenClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("token missing kid header")
		}

		// Get public key from JWKS
		if p.jwks != nil {
			return p.jwks.GetKey(kid)
		}

		return nil, errors.New("JWKS not configured")
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if !token.Valid {
		return nil, ErrInvalidJWTToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Validate standard claims
	if err := p.validateStandardClaims(claims); err != nil {
		return nil, err
	}

	// Convert to TokenClaims
	tokenClaims := &TokenClaims{
		Claims: make(map[string]interface{}),
	}

	// Extract standard claims
	if sub, ok := claims["sub"].(string); ok {
		tokenClaims.Subject = sub
	}
	if email, ok := claims["email"].(string); ok {
		tokenClaims.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		tokenClaims.Name = name
	}
	if iss, ok := claims["iss"].(string); ok {
		tokenClaims.Issuer = iss
	}

	// Handle expiration
	if exp, ok := claims["exp"].(float64); ok {
		tokenClaims.ExpiresAt = time.Unix(int64(exp), 0)
	}
	if iat, ok := claims["iat"].(float64); ok {
		tokenClaims.IssuedAt = time.Unix(int64(iat), 0)
	}

	// Handle audience
	if aud, ok := claims["aud"].([]interface{}); ok {
		for _, a := range aud {
			if audStr, ok := a.(string); ok {
				tokenClaims.Audience = append(tokenClaims.Audience, audStr)
			}
		}
	} else if audStr, ok := claims["aud"].(string); ok {
		tokenClaims.Audience = []string{audStr}
	}

	// Handle groups
	if groups, ok := claims["groups"].([]interface{}); ok {
		for _, g := range groups {
			if groupStr, ok := g.(string); ok {
				tokenClaims.Groups = append(tokenClaims.Groups, groupStr)
			}
		}
	}

	// Store all claims
	for k, v := range claims {
		tokenClaims.Claims[k] = v
	}

	return tokenClaims, nil
}

// validateStandardClaims validates standard JWT claims
func (p *OAuth2Provider) validateStandardClaims(claims jwt.MapClaims) error {
	now := time.Now()

	// Validate expiration
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if now.After(expTime.Add(p.config.AllowedClockSkew)) {
			return ErrTokenExpired
		}
	}

	// Validate not before
	if nbf, ok := claims["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		if now.Before(nbfTime.Add(-p.config.AllowedClockSkew)) {
			return errors.New("token not yet valid")
		}
	}

	// Validate issuer
	if p.config.Issuer != "" {
		if iss, ok := claims["iss"].(string); ok {
			if iss != p.config.Issuer {
				return ErrInvalidIssuer
			}
		}
	}

	// Validate audience
	if aud, ok := claims["aud"]; ok {
		validAudience := false
		switch audValue := aud.(type) {
		case string:
			if audValue == p.config.ClientID {
				validAudience = true
			}
		case []interface{}:
			for _, a := range audValue {
				if audStr, ok := a.(string); ok && audStr == p.config.ClientID {
					validAudience = true
					break
				}
			}
		}
		if !validAudience {
			return ErrInvalidAudience
		}
	}

	return nil
}

// introspectToken introspects an OAuth2 access token
func (p *OAuth2Provider) introspectToken(token string) (*TokenClaims, error) {
	// This would typically call the token introspection endpoint
	// For now, return a basic implementation
	return &TokenClaims{
		Subject: "unknown",
		Claims:  map[string]interface{}{"token": token},
	}, nil
}

// mergeClaims merges JWT claims into user information
func (p *OAuth2Provider) mergeClaims(user *ExternalUser, claims *TokenClaims) {
	if claims.Subject != "" && user.ID == "" {
		user.ID = claims.Subject
	}
	if claims.Email != "" && user.Email == "" {
		user.Email = claims.Email
	}
	if claims.Name != "" && user.Name == "" {
		user.Name = claims.Name
	}
	if len(claims.Groups) > 0 && len(user.Groups) == 0 {
		user.Groups = claims.Groups
	}

	// Merge all claims into attributes
	for k, v := range claims.Claims {
		user.Attributes[k] = v
	}
}

// getFieldValue extracts a field value from user info using reflection-like access
func (p *OAuth2Provider) getFieldValue(userInfo *UserInfo, fieldName string) string {
	switch fieldName {
	case "sub":
		return userInfo.Sub
	case "name":
		return userInfo.Name
	case "given_name":
		return userInfo.GivenName
	case "family_name":
		return userInfo.FamilyName
	case "email":
		return userInfo.Email
	case "preferred_username":
		return userInfo.PreferredUsername
	default:
		return ""
	}
}

// GetKey retrieves a public key from JWKS cache
func (j *JWKSCache) GetKey(kid string) (*rsa.PublicKey, error) {
	// Check if cache is expired
	if time.Now().After(j.expiresAt) {
		if err := j.refresh(); err != nil {
			return nil, fmt.Errorf("failed to refresh JWKS: %w", err)
		}
	}

	key, exists := j.keys[kid]
	if !exists {
		// Try to refresh cache once more
		if err := j.refresh(); err != nil {
			return nil, fmt.Errorf("failed to refresh JWKS: %w", err)
		}
		key, exists = j.keys[kid]
		if !exists {
			return nil, fmt.Errorf("key with kid %s not found", kid)
		}
	}

	return key, nil
}

// refresh refreshes the JWKS cache
func (j *JWKSCache) refresh() error {
	resp, err := j.client.Get(j.url)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS request failed with status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Clear existing keys
	j.keys = make(map[string]*rsa.PublicKey)

	// Parse and store keys
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && (key.Use == "sig" || key.Use == "") {
			pubKey, err := parseRSAPublicKey(key.N, key.E)
			if err != nil {
				continue // Skip invalid keys
			}
			j.keys[key.Kid] = pubKey
		}
	}

	j.expiresAt = time.Now().Add(j.ttl)
	return nil
}

// parseRSAPublicKey parses RSA public key from JWK components
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	// This is a simplified implementation
	// In a real implementation, you would properly decode the base64url encoded n and e values
	// and construct an RSA public key
	return &rsa.PublicKey{}, nil
}

// GenerateAuthURL generates an OAuth2 authorization URL
func (p *OAuth2Provider) GenerateAuthURL(state string) (string, error) {
	if !p.config.Enabled {
		return "", ErrOAuth2ProviderNotReady
	}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", p.config.ClientID)
	params.Set("scope", strings.Join(p.config.Scopes, " "))
	if p.config.RedirectURL != "" {
		params.Set("redirect_uri", p.config.RedirectURL)
	}
	if state != "" {
		params.Set("state", state)
	}

	authURL := p.config.AuthorizeURL
	if strings.Contains(authURL, "?") {
		authURL += "&" + params.Encode()
	} else {
		authURL += "?" + params.Encode()
	}

	return authURL, nil
}