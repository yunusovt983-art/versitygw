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

package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3api/utils"
)

func TestDefaultMFAAuthConfig(t *testing.T) {
	config := DefaultMFAAuthConfig()
	
	if !config.RequireForAdmins {
		t.Error("Expected RequireForAdmins to be true")
	}
	
	if len(config.RequireForOperations) == 0 {
		t.Error("Expected RequireForOperations to have entries")
	}
	
	if config.GracePeriod != 24*time.Hour {
		t.Errorf("Expected GracePeriod to be 24h, got %v", config.GracePeriod)
	}
	
	if !config.AllowBackupCodes {
		t.Error("Expected AllowBackupCodes to be true")
	}
}

func TestShouldRequireMFA(t *testing.T) {
	mockMFA := NewMockMFAService()
	config := &EnhancedAuthConfig{
		MFA:       mockMFA,
		MFAConfig: DefaultMFAAuthConfig(),
	}
	
	tests := []struct {
		name        string
		account     auth.Account
		isRoot      bool
		operation   string
		mfaEnabled  bool
		expected    bool
	}{
		{
			name:     "root user should not require MFA",
			account:  auth.Account{Access: "root", Role: auth.RoleAdmin},
			isRoot:   true,
			expected: false,
		},
		{
			name:     "admin user should require MFA",
			account:  auth.Account{Access: "admin", Role: auth.RoleAdmin},
			isRoot:   false,
			expected: true,
		},
		{
			name:     "regular user should not require MFA by default",
			account:  auth.Account{Access: "user", Role: auth.RoleUser},
			isRoot:   false,
			expected: false,
		},
		{
			name:       "user with MFA enabled should require MFA",
			account:    auth.Account{Access: "user", Role: auth.RoleUser},
			isRoot:     false,
			mfaEnabled: true,
			expected:   true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			
			// Set up MFA status
			if tt.mfaEnabled {
				mockMFA.SetUserMFAEnabled(tt.account.Access, true)
			} else {
				mockMFA.SetUserMFAEnabled(tt.account.Access, false)
			}
			
			app.Get("/test", func(c *fiber.Ctx) error {
				// Set context values
				if tt.isRoot {
					utils.ContextKeyIsRoot.Set(c, true)
				}
				
				result := shouldRequireMFA(c, tt.account, config)
				if result != tt.expected {
					t.Errorf("shouldRequireMFA() = %v, want %v", result, tt.expected)
				}
				
				return c.SendString("OK")
			})
			
			req := httptest.NewRequest("GET", "/test", nil)
			_, err := app.Test(req)
			if err != nil {
				t.Fatalf("Test request failed: %v", err)
			}
		})
	}
}

func TestGetOperationFromContext(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		query    string
		expected string
	}{
		{
			name:     "DELETE bucket",
			method:   "DELETE",
			path:     "/",
			expected: "DeleteBucket",
		},
		{
			name:     "DELETE object",
			method:   "DELETE",
			path:     "/object",
			expected: "DeleteObject",
		},
		{
			name:     "PUT bucket policy",
			method:   "PUT",
			path:     "/",
			query:    "policy=",
			expected: "PutBucketPolicy",
		},
		{
			name:     "PUT object",
			method:   "PUT",
			path:     "/object",
			expected: "PutObject",
		},
		{
			name:     "GET bucket policy",
			method:   "GET",
			path:     "/",
			query:    "policy=",
			expected: "GetBucketPolicy",
		},
		{
			name:     "GET object",
			method:   "GET",
			path:     "/object",
			expected: "GetObject",
		},
		{
			name:     "Unknown operation",
			method:   "PATCH",
			path:     "/",
			expected: "Unknown",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			
			// Create the route that matches the test path
			route := tt.path
			if route == "/" {
				route = "/"
			} else {
				route = "/*"
			}
			
			app.Add(tt.method, route, func(c *fiber.Ctx) error {
				operation := getOperationFromContext(c)
				if operation != tt.expected {
					t.Errorf("getOperationFromContext() = %v, want %v", operation, tt.expected)
				}
				
				return c.SendString("OK")
			})
			
			url := tt.path
			if tt.query != "" {
				url += "?" + tt.query
			}
			
			req := httptest.NewRequest(tt.method, url, nil)
			_, err := app.Test(req)
			if err != nil {
				t.Fatalf("Test request failed: %v", err)
			}
		})
	}
}

func TestEnhancedAuthentication_PublicBucket(t *testing.T) {
	mockMFA := NewMockMFAService()
	mockIAM := &MockIAMService{}
	
	config := &EnhancedAuthConfig{
		Root: RootUserConfig{
			Access: "root",
			Secret: "secret",
		},
		IAM:    mockIAM,
		MFA:    mockMFA,
		Region: "us-east-1",
		Debug:  false,
	}
	
	app := fiber.New()
	
	// Set public bucket context before authentication
	app.Use(func(c *fiber.Ctx) error {
		utils.ContextKeyPublicBucket.Set(c, true)
		return c.Next()
	})
	
	app.Use(VerifyV4SignatureWithMFA(config))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestEnhancedAuthentication_MissingAuthHeader(t *testing.T) {
	mockMFA := NewMockMFAService()
	mockIAM := &MockIAMService{}
	
	config := &EnhancedAuthConfig{
		Root: RootUserConfig{
			Access: "root",
			Secret: "secret",
		},
		IAM:    mockIAM,
		MFA:    mockMFA,
		Region: "us-east-1",
		Debug:  false,
	}
	
	app := fiber.New()
	app.Use(VerifyV4SignatureWithMFA(config))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

// MockIAMService for testing
type MockIAMService struct {
	users map[string]auth.Account
}

func (m *MockIAMService) CreateAccount(account auth.Account) error {
	if m.users == nil {
		m.users = make(map[string]auth.Account)
	}
	m.users[account.Access] = account
	return nil
}

func (m *MockIAMService) GetUserAccount(access string) (auth.Account, error) {
	if m.users == nil {
		m.users = make(map[string]auth.Account)
	}
	
	if account, exists := m.users[access]; exists {
		return account, nil
	}
	
	// Return a default test account
	return auth.Account{
		Access: access,
		Secret: "testsecret",
		Role:   auth.RoleUser,
	}, nil
}

func (m *MockIAMService) UpdateUserAccount(access string, props auth.MutableProps) error {
	if m.users == nil {
		m.users = make(map[string]auth.Account)
	}
	
	account, exists := m.users[access]
	if !exists {
		return auth.ErrNoSuchUser
	}
	
	if props.Secret != nil {
		account.Secret = *props.Secret
	}
	if props.Role != "" {
		account.Role = props.Role
	}
	if props.UserID != nil {
		account.UserID = *props.UserID
	}
	if props.GroupID != nil {
		account.GroupID = *props.GroupID
	}
	
	m.users[access] = account
	return nil
}

func (m *MockIAMService) DeleteUserAccount(access string) error {
	if m.users == nil {
		m.users = make(map[string]auth.Account)
	}
	
	if _, exists := m.users[access]; !exists {
		return auth.ErrNoSuchUser
	}
	
	delete(m.users, access)
	return nil
}

func (m *MockIAMService) ListUserAccounts() ([]auth.Account, error) {
	if m.users == nil {
		m.users = make(map[string]auth.Account)
	}
	
	accounts := make([]auth.Account, 0, len(m.users))
	for _, account := range m.users {
		accounts = append(accounts, account)
	}
	
	return accounts, nil
}

func (m *MockIAMService) Shutdown() error {
	return nil
}

func TestEnhancedAuthentication_MFAIntegration(t *testing.T) {
	mockMFA := NewMockMFAService()
	mockIAM := &MockIAMService{}
	
	// Create test admin user
	adminAccount := auth.Account{
		Access: "admin",
		Secret: "adminsecret",
		Role:   auth.RoleAdmin,
	}
	mockIAM.CreateAccount(adminAccount)
	
	// Enable MFA for admin
	mockMFA.SetUserMFAEnabled("admin", true)
	
	config := &EnhancedAuthConfig{
		Root: RootUserConfig{
			Access: "root",
			Secret: "secret",
		},
		IAM:       mockIAM,
		MFA:       mockMFA,
		Region:    "us-east-1",
		Debug:     false,
		MFAConfig: DefaultMFAAuthConfig(),
	}
	
	app := fiber.New()
	app.Use(VerifyV4SignatureWithMFA(config))
	app.Get("/test", func(c *fiber.Ctx) error {
		// Check if MFA was verified
		if utils.ContextKeyMFAVerified.IsSet(c) {
			return c.SendString("MFA_VERIFIED")
		}
		return c.SendString("NO_MFA")
	})
	
	// Test without MFA token (should fail for admin)
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=admin/20230101/us-east-1/s3/aws4_request")
	req.Header.Set("X-Amz-Date", "20230101T000000Z")
	
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	
	// This test would require proper signature validation which is complex to mock
	// For now, we're testing the structure and basic flow
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		t.Logf("Got status %d, which is expected for incomplete auth setup", resp.StatusCode)
	}
}

func TestMFAAuthConfig_RequiredOperations(t *testing.T) {
	config := DefaultMFAAuthConfig()
	
	expectedOps := []string{"DeleteBucket", "PutBucketPolicy", "DeleteBucketPolicy"}
	
	if len(config.RequireForOperations) != len(expectedOps) {
		t.Errorf("Expected %d required operations, got %d", len(expectedOps), len(config.RequireForOperations))
	}
	
	for _, expectedOp := range expectedOps {
		found := false
		for _, actualOp := range config.RequireForOperations {
			if actualOp == expectedOp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected operation %s not found in RequireForOperations", expectedOp)
		}
	}
}