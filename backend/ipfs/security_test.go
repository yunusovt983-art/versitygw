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

package ipfs

import (
	"context"
	"testing"
	"time"

	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3err"
)

// Mock IAM Service for testing
type MockIAMService struct {
	accounts map[string]auth.Account
}

func NewMockIAMService() *MockIAMService {
	return &MockIAMService{
		accounts: make(map[string]auth.Account),
	}
}

func (m *MockIAMService) CreateAccount(account auth.Account) error {
	m.accounts[account.Access] = account
	return nil
}

func (m *MockIAMService) GetUserAccount(access string) (auth.Account, error) {
	account, exists := m.accounts[access]
	if !exists {
		return auth.Account{}, auth.ErrNoSuchUser
	}
	return account, nil
}

func (m *MockIAMService) UpdateUserAccount(access string, props auth.MutableProps) error {
	account, exists := m.accounts[access]
	if !exists {
		return auth.ErrNoSuchUser
	}
	// Update account with props
	m.accounts[access] = account
	return nil
}

func (m *MockIAMService) DeleteUserAccount(access string) error {
	delete(m.accounts, access)
	return nil
}

func (m *MockIAMService) ListUserAccounts() ([]auth.Account, error) {
	var accounts []auth.Account
	for _, account := range m.accounts {
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (m *MockIAMService) Shutdown() error {
	return nil
}

// Mock Role Manager for testing
type MockRoleManager struct {
	permissions map[string]*auth.PermissionSet
}

func NewMockRoleManager() *MockRoleManager {
	return &MockRoleManager{
		permissions: make(map[string]*auth.PermissionSet),
	}
}

func (m *MockRoleManager) CheckPermission(userID, resource, action string) (bool, error) {
	permSet, exists := m.permissions[userID]
	if !exists {
		return false, nil
	}
	
	// Simple permission check
	for _, perm := range permSet.Permissions {
		if perm.Resource == resource && perm.Action == action && perm.Effect == "allow" {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockRoleManager) GetEffectivePermissions(userID string) (*auth.PermissionSet, error) {
	permSet, exists := m.permissions[userID]
	if !exists {
		return &auth.PermissionSet{Permissions: make(map[string]*auth.Permission)}, nil
	}
	return permSet, nil
}

func (m *MockRoleManager) SetUserPermissions(userID string, permissions *auth.PermissionSet) {
	m.permissions[userID] = permissions
}

// Test Security Manager
func TestIPFSSecurityManager_ValidateAccess(t *testing.T) {
	iamService := NewMockIAMService()
	roleManager := NewMockRoleManager()
	
	// Create test accounts
	adminAccount := auth.Account{
		Access: "admin",
		Secret: "secret",
		Role:   auth.RoleAdmin,
		UserID: 1,
	}
	userAccount := auth.Account{
		Access: "user",
		Secret: "secret",
		Role:   auth.RoleUser,
		UserID: 2,
	}
	
	iamService.CreateAccount(adminAccount)
	iamService.CreateAccount(userAccount)
	
	config := DefaultSecurityConfig()
	config.EnableFineGrainedPermissions = true
	
	securityManager, err := NewIPFSSecurityManager(iamService, roleManager, config)
	if err != nil {
		t.Fatalf("Failed to create security manager: %v", err)
	}
	defer securityManager.Shutdown()
	
	tests := []struct {
		name        string
		secCtx      *SecurityContext
		permission  IPFSPermission
		expectError bool
	}{
		{
			name: "Root user access",
			secCtx: &SecurityContext{
				UserID:  "root",
				Account: adminAccount,
				IsRoot:  true,
			},
			permission:  IPFSPermissionPinCreate,
			expectError: false,
		},
		{
			name: "Admin user access",
			secCtx: &SecurityContext{
				UserID:  "admin",
				Account: adminAccount,
				IsRoot:  false,
			},
			permission:  IPFSPermissionPinCreate,
			expectError: false,
		},
		{
			name: "Regular user read access",
			secCtx: &SecurityContext{
				UserID:  "user",
				Account: userAccount,
				IsRoot:  false,
			},
			permission:  IPFSPermissionPinRead,
			expectError: false,
		},
		{
			name: "Regular user write access denied",
			secCtx: &SecurityContext{
				UserID:  "user",
				Account: userAccount,
				IsRoot:  false,
			},
			permission:  IPFSPermissionPinCreate,
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := securityManager.ValidateAccess(context.Background(), tt.secCtx, tt.permission)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// Test Encryption
func TestIPFSSecurityManager_Encryption(t *testing.T) {
	iamService := NewMockIAMService()
	config := DefaultSecurityConfig()
	config.EnableClientSideEncryption = true
	
	securityManager, err := NewIPFSSecurityManager(iamService, nil, config)
	if err != nil {
		t.Fatalf("Failed to create security manager: %v", err)
	}
	defer securityManager.Shutdown()
	
	originalData := []byte("Hello, IPFS World!")
	metadata := map[string]string{
		"content-type": "text/plain",
	}
	
	// Test encryption
	encryptedData, encryptedMetadata, err := securityManager.EncryptData(originalData, metadata)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}
	
	// Verify encryption metadata is added
	if encryptedMetadata["x-ipfs-encryption"] != "AES-256-GCM" {
		t.Errorf("Expected encryption metadata to be set")
	}
	
	// Verify data is actually encrypted (different from original)
	if string(encryptedData) == string(originalData) {
		t.Errorf("Data should be encrypted and different from original")
	}
	
	// Test decryption
	decryptedData, err := securityManager.DecryptData(encryptedData, encryptedMetadata)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}
	
	// Verify decrypted data matches original
	if string(decryptedData) != string(originalData) {
		t.Errorf("Decrypted data doesn't match original. Got: %s, Expected: %s", 
			string(decryptedData), string(originalData))
	}
}

// Test Rate Limiter
func TestRateLimiter(t *testing.T) {
	rateLimiter := NewRateLimiter(time.Minute)
	
	// Test basic rate limiting
	key := "test-user"
	limit := 5
	
	// Should allow up to limit
	for i := 0; i < limit; i++ {
		if !rateLimiter.Allow(key, limit) {
			t.Errorf("Should allow request %d", i+1)
		}
	}
	
	// Should deny after limit
	if rateLimiter.Allow(key, limit) {
		t.Errorf("Should deny request after limit")
	}
	
	// Test usage tracking
	used, capacity := rateLimiter.GetUsage(key)
	if capacity != limit {
		t.Errorf("Expected capacity %d, got %d", limit, capacity)
	}
	if used != limit {
		t.Errorf("Expected used %d, got %d", limit, used)
	}
}

// Test Adaptive Rate Limiter
func TestAdaptiveRateLimiter(t *testing.T) {
	config := DefaultRateLimitConfig()
	rateLimiter := NewAdaptiveRateLimiter(time.Minute, config)
	
	// Test normal load
	rateLimiter.UpdateSystemLoad(0.5)
	factor := rateLimiter.GetAdaptiveFactor()
	if factor != 1.0 {
		t.Errorf("Expected adaptive factor 1.0 for normal load, got %f", factor)
	}
	
	// Test high load
	rateLimiter.UpdateSystemLoad(0.9)
	factor = rateLimiter.GetAdaptiveFactor()
	if factor != 0.5 {
		t.Errorf("Expected adaptive factor 0.5 for high load, got %f", factor)
	}
	
	// Test low load
	rateLimiter.UpdateSystemLoad(0.2)
	factor = rateLimiter.GetAdaptiveFactor()
	if factor != 1.5 {
		t.Errorf("Expected adaptive factor 1.5 for low load, got %f", factor)
	}
}

// Test IPFS Role Manager
func TestIPFSRoleManager(t *testing.T) {
	baseRoleManager := NewMockRoleManager()
	ipfsRoleManager := NewIPFSRoleManager(baseRoleManager)
	
	userID := "test-user"
	resource := "arn:aws:ipfs:::bucket/test"
	action := "ipfs:pin:create"
	
	// Test granting permission
	err := ipfsRoleManager.GrantIPFSPermission(userID, resource, action, nil)
	if err != nil {
		t.Fatalf("Failed to grant permission: %v", err)
	}
	
	// Test checking permission
	allowed, err := ipfsRoleManager.CheckPermission(userID, resource, action)
	if err != nil {
		t.Fatalf("Failed to check permission: %v", err)
	}
	if !allowed {
		t.Errorf("Expected permission to be allowed")
	}
	
	// Test revoking permission
	err = ipfsRoleManager.RevokeIPFSPermission(userID, resource, action)
	if err != nil {
		t.Fatalf("Failed to revoke permission: %v", err)
	}
	
	// Test checking revoked permission
	allowed, err = ipfsRoleManager.CheckPermission(userID, resource, action)
	if err != nil {
		t.Fatalf("Failed to check permission: %v", err)
	}
	if allowed {
		t.Errorf("Expected permission to be denied after revocation")
	}
}

// Test Permission Templates
func TestPermissionTemplates(t *testing.T) {
	baseRoleManager := NewMockRoleManager()
	ipfsRoleManager := NewIPFSRoleManager(baseRoleManager)
	
	userID := "test-user"
	
	// Test applying readonly template
	err := ipfsRoleManager.ApplyPermissionTemplate(userID, IPFSReadOnlyPermissions)
	if err != nil {
		t.Fatalf("Failed to apply readonly template: %v", err)
	}
	
	// Test readonly permissions
	allowed, err := ipfsRoleManager.CheckPermission(userID, "*", "ipfs:pin:read")
	if err != nil {
		t.Fatalf("Failed to check permission: %v", err)
	}
	if !allowed {
		t.Errorf("Expected read permission to be allowed")
	}
	
	// Test write permissions should be denied
	allowed, err = ipfsRoleManager.CheckPermission(userID, "*", "ipfs:pin:create")
	if err != nil {
		t.Fatalf("Failed to check permission: %v", err)
	}
	if allowed {
		t.Errorf("Expected write permission to be denied for readonly template")
	}
}

// Test Security Integration
func TestSecurityIntegration(t *testing.T) {
	iamService := NewMockIAMService()
	baseRoleManager := NewMockRoleManager()
	
	config := &SecurityIntegrationConfig{
		EnableSecurity:      true,
		EnableEncryption:    true,
		EnableRateLimiting:  true,
		EnableAuditLogging:  true,
		EnableRoleBasedAuth: true,
		StrictMode:         false,
	}
	
	integration, err := NewSecurityIntegration(iamService, baseRoleManager, config)
	if err != nil {
		t.Fatalf("Failed to create security integration: %v", err)
	}
	defer integration.Shutdown()
	
	// Create test account
	account := auth.Account{
		Access: "test-user",
		Secret: "secret",
		Role:   auth.RoleAdmin,
		UserID: 1,
	}
	iamService.CreateAccount(account)
	
	// Test pin operation validation
	pinReq := &PinOperationRequest{
		UserID:    "test-user",
		Account:   account,
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
		RequestID: "req-123",
		Operation: "pin",
		CID:       "QmTest123",
		S3Key:     "test-object",
		Bucket:    "test-bucket",
		IsRoot:    false,
	}
	
	err = integration.ValidatePinOperation(context.Background(), pinReq)
	if err != nil {
		t.Errorf("Expected pin operation to be allowed for admin user: %v", err)
	}
	
	// Test metadata operation validation
	metaReq := &MetadataOperationRequest{
		UserID:    "test-user",
		Account:   account,
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
		RequestID: "req-124",
		Operation: "read",
		S3Key:     "test-object",
		Bucket:    "test-bucket",
		CID:       "QmTest123",
		IsRoot:    false,
	}
	
	err = integration.ValidateMetadataOperation(context.Background(), metaReq)
	if err != nil {
		t.Errorf("Expected metadata operation to be allowed for admin user: %v", err)
	}
	
	// Test encryption/decryption
	originalData := []byte("test data")
	metadata := map[string]string{"test": "value"}
	
	encryptedData, encryptedMetadata, err := integration.EncryptObjectData(originalData, metadata)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}
	
	decryptedData, err := integration.DecryptObjectData(encryptedData, encryptedMetadata)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}
	
	if string(decryptedData) != string(originalData) {
		t.Errorf("Decrypted data doesn't match original")
	}
}

// Benchmark tests
func BenchmarkSecurityValidation(b *testing.B) {
	iamService := NewMockIAMService()
	baseRoleManager := NewMockRoleManager()
	
	config := &SecurityIntegrationConfig{
		EnableSecurity:      true,
		EnableEncryption:    false, // Disable for benchmark
		EnableRateLimiting:  true,
		EnableAuditLogging:  false, // Disable for benchmark
		EnableRoleBasedAuth: true,
		StrictMode:         false,
	}
	
	integration, err := NewSecurityIntegration(iamService, baseRoleManager, config)
	if err != nil {
		b.Fatalf("Failed to create security integration: %v", err)
	}
	defer integration.Shutdown()
	
	// Create test account
	account := auth.Account{
		Access: "test-user",
		Secret: "secret",
		Role:   auth.RoleAdmin,
		UserID: 1,
	}
	iamService.CreateAccount(account)
	
	pinReq := &PinOperationRequest{
		UserID:    "test-user",
		Account:   account,
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
		RequestID: "req-123",
		Operation: "pin",
		CID:       "QmTest123",
		S3Key:     "test-object",
		Bucket:    "test-bucket",
		IsRoot:    false,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := integration.ValidatePinOperation(context.Background(), pinReq)
		if err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

func BenchmarkEncryption(b *testing.B) {
	iamService := NewMockIAMService()
	config := DefaultSecurityConfig()
	config.EnableClientSideEncryption = true
	
	securityManager, err := NewIPFSSecurityManager(iamService, nil, config)
	if err != nil {
		b.Fatalf("Failed to create security manager: %v", err)
	}
	defer securityManager.Shutdown()
	
	data := make([]byte, 1024) // 1KB test data
	for i := range data {
		data[i] = byte(i % 256)
	}
	
	metadata := map[string]string{"test": "value"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := securityManager.EncryptData(data, metadata)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkRateLimiter(b *testing.B) {
	rateLimiter := NewRateLimiter(time.Minute)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rateLimiter.Allow("test-user", 1000)
	}
}