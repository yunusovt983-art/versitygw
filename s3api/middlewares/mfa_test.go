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

// MockMFAService implements the MFAService interface for testing
type MockMFAService struct {
	users           map[string]*auth.MFAUserData
	requiredForRole map[auth.Role]bool
	requiredForUser map[string]bool
}

func NewMockMFAService() *MockMFAService {
	return &MockMFAService{
		users:           make(map[string]*auth.MFAUserData),
		requiredForRole: make(map[auth.Role]bool),
		requiredForUser: make(map[string]bool),
	}
}

func (m *MockMFAService) GenerateSecret(userID string) (*auth.MFASecret, error) {
	return &auth.MFASecret{
		Secret:      "TESTSECRET123456",
		BackupCodes: []string{"CODE1", "CODE2"},
		Issuer:      "Test",
		AccountName: userID,
	}, nil
}

func (m *MockMFAService) ValidateTOTP(userID, token string) error {
	user, exists := m.users[userID]
	if !exists {
		return auth.ErrMFANotEnabled
	}
	
	if !user.Enabled {
		return auth.ErrMFANotEnabled
	}
	
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return auth.ErrMFAUserLocked
	}
	
	// Simple mock validation - accept "123456" as valid token
	if token == "123456" {
		return nil
	}
	
	return auth.ErrMFAInvalidToken
}

func (m *MockMFAService) IsMFARequired(userID string) bool {
	return m.requiredForUser[userID]
}

func (m *MockMFAService) IsMFARequiredForRole(userID string, role auth.Role) bool {
	if m.requiredForUser[userID] {
		return true
	}
	return m.requiredForRole[role]
}

func (m *MockMFAService) EnableMFA(userID string, secret *auth.MFASecret) error {
	m.users[userID] = &auth.MFAUserData{
		UserID:         userID,
		Secret:         secret.Secret,
		Enabled:        true,
		SetupCompleted: true,
	}
	return nil
}

func (m *MockMFAService) DisableMFA(userID string) error {
	delete(m.users, userID)
	return nil
}

func (m *MockMFAService) GetMFAStatus(userID string) (*auth.MFAStatus, error) {
	user, exists := m.users[userID]
	if !exists {
		return &auth.MFAStatus{
			Enabled:        false,
			SetupCompleted: false,
		}, nil
	}
	
	return &auth.MFAStatus{
		Enabled:              user.Enabled,
		LastUsed:             user.LastUsed,
		BackupCodesRemaining: len(user.BackupCodes),
		SetupCompleted:       user.SetupCompleted,
		FailedAttempts:       user.FailedAttempts,
		LockedUntil:          user.LockedUntil,
	}, nil
}

func (m *MockMFAService) ValidateBackupCode(userID, code string) error {
	user, exists := m.users[userID]
	if !exists {
		return auth.ErrMFANotEnabled
	}
	
	if !user.Enabled {
		return auth.ErrMFANotEnabled
	}
	
	// Simple mock validation - accept "BACKUP1" as valid code
	if code == "BACKUP1" {
		return nil
	}
	
	return auth.ErrMFAInvalidBackupCode
}

func (m *MockMFAService) RegenerateBackupCodes(userID string) ([]string, error) {
	user, exists := m.users[userID]
	if !exists {
		return nil, auth.ErrMFANotEnabled
	}
	
	if !user.Enabled {
		return nil, auth.ErrMFANotEnabled
	}
	
	codes := []string{"NEWCODE1", "NEWCODE2", "NEWCODE3"}
	user.BackupCodes = codes
	return codes, nil
}

// Helper functions for testing
func (m *MockMFAService) SetUserMFAEnabled(userID string, enabled bool) {
	if enabled {
		m.users[userID] = &auth.MFAUserData{
			UserID:         userID,
			Secret:         "TESTSECRET",
			Enabled:        true,
			SetupCompleted: true,
		}
	} else {
		delete(m.users, userID)
	}
}

func (m *MockMFAService) SetMFARequiredForRole(role auth.Role, required bool) {
	m.requiredForRole[role] = required
}

func (m *MockMFAService) SetMFARequiredForUser(userID string, required bool) {
	m.requiredForUser[userID] = required
}

func (m *MockMFAService) SetUserLocked(userID string, lockedUntil *time.Time) {
	if user, exists := m.users[userID]; exists {
		user.LockedUntil = lockedUntil
	}
}

func TestMFAMiddleware_VerifyMFA_PublicBucket(t *testing.T) {
	app := fiber.New()
	mockMFA := NewMockMFAService()
	middleware := NewMFAMiddleware(mockMFA, nil, nil)
	
	app.Use(middleware.VerifyMFA())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	
	// Set public bucket context
	app.Use(func(c *fiber.Ctx) error {
		utils.ContextKeyPublicBucket.Set(c, true)
		return c.Next()
	})
	
	req = httptest.NewRequest("GET", "/test", nil)
	resp, err = app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestMFAMiddleware_VerifyMFA_NoAccount(t *testing.T) {
	app := fiber.New()
	mockMFA := NewMockMFAService()
	middleware := NewMFAMiddleware(mockMFA, nil, nil)
	
	app.Use(middleware.VerifyMFA())
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

func TestMFAMiddleware_VerifyMFA_MFANotRequired(t *testing.T) {
	app := fiber.New()
	mockMFA := NewMockMFAService()
	middleware := NewMFAMiddleware(mockMFA, nil, nil)
	
	// Set up middleware chain
	app.Use(func(c *fiber.Ctx) error {
		// Simulate authenticated user
		account := auth.Account{
			Access: "testuser",
			Role:   auth.RoleUser,
		}
		utils.ContextKeyAccount.Set(c, account)
		return c.Next()
	})
	
	app.Use(middleware.VerifyMFA())
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

func TestMFAMiddleware_VerifyMFA_MFARequired_NoToken(t *testing.T) {
	app := fiber.New()
	mockMFA := NewMockMFAService()
	middleware := NewMFAMiddleware(mockMFA, nil, nil)
	
	// Set MFA required for admin role
	mockMFA.SetMFARequiredForRole(auth.RoleAdmin, true)
	
	// Set up middleware chain
	app.Use(func(c *fiber.Ctx) error {
		// Simulate authenticated admin user
		account := auth.Account{
			Access: "adminuser",
			Role:   auth.RoleAdmin,
		}
		utils.ContextKeyAccount.Set(c, account)
		return c.Next()
	})
	
	app.Use(middleware.VerifyMFA())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

func TestMFAMiddleware_VerifyMFA_ValidToken(t *testing.T) {
	app := fiber.New()
	mockMFA := NewMockMFAService()
	middleware := NewMFAMiddleware(mockMFA, nil, nil)
	
	// Set MFA required for admin role and enable MFA for user
	mockMFA.SetMFARequiredForRole(auth.RoleAdmin, true)
	mockMFA.SetUserMFAEnabled("adminuser", true)
	
	// Set up middleware chain
	app.Use(func(c *fiber.Ctx) error {
		// Simulate authenticated admin user
		account := auth.Account{
			Access: "adminuser",
			Role:   auth.RoleAdmin,
		}
		utils.ContextKeyAccount.Set(c, account)
		return c.Next()
	})
	
	app.Use(middleware.VerifyMFA())
	app.Get("/test", func(c *fiber.Ctx) error {
		// Check if MFA verified flag is set
		if !utils.ContextKeyMFAVerified.IsSet(c) {
			return c.Status(500).SendString("MFA not verified")
		}
		return c.SendString("OK")
	})
	
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-MFA-Token", "123456") // Valid token in mock
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestMFAMiddleware_VerifyMFA_InvalidToken(t *testing.T) {
	app := fiber.New()
	mockMFA := NewMockMFAService()
	middleware := NewMFAMiddleware(mockMFA, nil, nil)
	
	// Set MFA required for admin role and enable MFA for user
	mockMFA.SetMFARequiredForRole(auth.RoleAdmin, true)
	mockMFA.SetUserMFAEnabled("adminuser", true)
	
	// Set up middleware chain
	app.Use(func(c *fiber.Ctx) error {
		// Simulate authenticated admin user
		account := auth.Account{
			Access: "adminuser",
			Role:   auth.RoleAdmin,
		}
		utils.ContextKeyAccount.Set(c, account)
		return c.Next()
	})
	
	app.Use(middleware.VerifyMFA())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-MFA-Token", "000000") // Invalid token
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

func TestMFAMiddleware_VerifyMFA_UserLocked(t *testing.T) {
	app := fiber.New()
	mockMFA := NewMockMFAService()
	middleware := NewMFAMiddleware(mockMFA, nil, nil)
	
	// Set MFA required for admin role and enable MFA for user
	mockMFA.SetMFARequiredForRole(auth.RoleAdmin, true)
	mockMFA.SetUserMFAEnabled("adminuser", true)
	
	// Lock the user
	lockTime := time.Now().Add(time.Hour)
	mockMFA.SetUserLocked("adminuser", &lockTime)
	
	// Set up middleware chain
	app.Use(func(c *fiber.Ctx) error {
		// Simulate authenticated admin user
		account := auth.Account{
			Access: "adminuser",
			Role:   auth.RoleAdmin,
		}
		utils.ContextKeyAccount.Set(c, account)
		return c.Next()
	})
	
	app.Use(middleware.VerifyMFA())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-MFA-Token", "123456") // Valid token but user is locked
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", resp.StatusCode)
	}
}

func TestMFAMiddleware_ExtractMFAToken(t *testing.T) {
	mockMFA := NewMockMFAService()
	middleware := NewMFAMiddleware(mockMFA, nil, nil)
	
	tests := []struct {
		name     string
		headers  map[string]string
		query    map[string]string
		expected string
	}{
		{
			name:     "X-Amz-MFA header",
			headers:  map[string]string{"X-Amz-MFA": "123456"},
			expected: "123456",
		},
		{
			name:     "X-MFA-Token header",
			headers:  map[string]string{"X-MFA-Token": "654321"},
			expected: "654321",
		},
		{
			name:     "Authorization header with MFA",
			headers:  map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=test MFA=789012"},
			expected: "789012",
		},
		{
			name:     "Query parameter",
			query:    map[string]string{"X-Amz-MFA": "111222"},
			expected: "111222",
		},
		{
			name:     "No token",
			headers:  map[string]string{},
			expected: "",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new app for each test
			app := fiber.New()
			
			app.Get("/test", func(c *fiber.Ctx) error {
				token := middleware.extractMFAToken(c)
				if token != tt.expected {
					t.Errorf("Expected token %s, got %s", tt.expected, token)
				}
				return c.SendString("OK")
			})
			
			// Build URL with query parameters
			url := "/test"
			if len(tt.query) > 0 {
				url += "?"
				first := true
				for key, value := range tt.query {
					if !first {
						url += "&"
					}
					url += key + "=" + value
					first = false
				}
			}
			
			req := httptest.NewRequest("GET", url, nil)
			
			// Set headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			
			_, err := app.Test(req)
			if err != nil {
				t.Fatalf("Test request failed: %v", err)
			}
		})
	}
}

func TestMFAMiddleware_RequireMFA(t *testing.T) {
	app := fiber.New()
	mockMFA := NewMockMFAService()
	middleware := NewMFAMiddleware(mockMFA, nil, nil)
	
	// Test case 1: MFA verified
	app.Use(func(c *fiber.Ctx) error {
		account := auth.Account{
			Access: "testuser",
			Role:   auth.RoleUser,
		}
		utils.ContextKeyAccount.Set(c, account)
		utils.ContextKeyMFAVerified.Set(c, true)
		return c.Next()
	})
	
	app.Use(middleware.RequireMFA())
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

func TestMFAMiddleware_RequireMFA_NotVerified(t *testing.T) {
	app := fiber.New()
	mockMFA := NewMockMFAService()
	middleware := NewMFAMiddleware(mockMFA, nil, nil)
	
	// Test case: MFA not verified
	app.Use(func(c *fiber.Ctx) error {
		account := auth.Account{
			Access: "testuser",
			Role:   auth.RoleUser,
		}
		utils.ContextKeyAccount.Set(c, account)
		// Don't set MFA verified flag
		return c.Next()
	})
	
	app.Use(middleware.RequireMFA())
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Test request failed: %v", err)
	}
	
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

func TestMFATokenValidator(t *testing.T) {
	mockMFA := NewMockMFAService()
	validator := NewMFATokenValidator(mockMFA)
	
	// Enable MFA for test user
	mockMFA.SetUserMFAEnabled("testuser", true)
	
	// Test valid token
	err := validator.ValidateTokenForUser("testuser", "123456")
	if err != nil {
		t.Errorf("Expected no error for valid token, got %v", err)
	}
	
	// Test invalid token
	err = validator.ValidateTokenForUser("testuser", "000000")
	if err != auth.ErrMFAInvalidToken {
		t.Errorf("Expected MFAInvalidToken error, got %v", err)
	}
	
	// Test empty user ID
	err = validator.ValidateTokenForUser("", "123456")
	if err == nil {
		t.Error("Expected error for empty user ID")
	}
	
	// Test empty token
	err = validator.ValidateTokenForUser("testuser", "")
	if err != auth.ErrMFAInvalidToken {
		t.Errorf("Expected MFAInvalidToken error for empty token, got %v", err)
	}
}

func TestMFATokenValidator_BackupCode(t *testing.T) {
	mockMFA := NewMockMFAService()
	validator := NewMFATokenValidator(mockMFA)
	
	// Enable MFA for test user
	mockMFA.SetUserMFAEnabled("testuser", true)
	
	// Test valid backup code
	err := validator.ValidateBackupCodeForUser("testuser", "BACKUP1")
	if err != nil {
		t.Errorf("Expected no error for valid backup code, got %v", err)
	}
	
	// Test invalid backup code
	err = validator.ValidateBackupCodeForUser("testuser", "INVALID")
	if err != auth.ErrMFAInvalidBackupCode {
		t.Errorf("Expected MFAInvalidBackupCode error, got %v", err)
	}
}

func TestMFATokenValidator_UserMFAStatus(t *testing.T) {
	mockMFA := NewMockMFAService()
	validator := NewMFATokenValidator(mockMFA)
	
	// Test user without MFA
	enabled, err := validator.IsUserMFAEnabled("testuser")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if enabled {
		t.Error("Expected MFA to be disabled")
	}
	
	// Enable MFA for test user
	mockMFA.SetUserMFAEnabled("testuser", true)
	
	// Test user with MFA
	enabled, err = validator.IsUserMFAEnabled("testuser")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !enabled {
		t.Error("Expected MFA to be enabled")
	}
	
	// Test get status
	status, err := validator.GetUserMFAStatus("testuser")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !status.Enabled {
		t.Error("Expected MFA status to show enabled")
	}
}