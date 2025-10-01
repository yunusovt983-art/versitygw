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
	"os"
	"testing"
	"time"

	"github.com/versity/versitygw/auth"
)

// MockIAMService implements auth.IAMService for testing
type MockIAMService struct {
	accounts map[string]auth.Account
}

func NewMockIAMService() *MockIAMService {
	return &MockIAMService{
		accounts: make(map[string]auth.Account),
	}
}

func (m *MockIAMService) GetUserAccount(accessKey string) (auth.Account, error) {
	account, exists := m.accounts[accessKey]
	if !exists {
		return auth.Account{}, auth.ErrUserNotFound
	}
	return account, nil
}

func (m *MockIAMService) CreateAccount(account auth.Account) error {
	m.accounts[account.Access] = account
	return nil
}

func (m *MockIAMService) DeleteUserAccount(accessKey string) error {
	delete(m.accounts, accessKey)
	return nil
}

func (m *MockIAMService) ListUserAccounts() ([]auth.Account, error) {
	accounts := make([]auth.Account, 0, len(m.accounts))
	for _, account := range m.accounts {
		accounts = append(accounts, account)
	}
	return accounts, nil
}

// MockRoleManager implements auth.RoleManager for testing
type MockRoleManager struct {
	permissions map[string]*auth.PermissionSet
}

func NewMockRoleManager() *MockRoleManager {
	return &MockRoleManager{
		permissions: make(map[string]*auth.PermissionSet),
	}
}

func (m *MockRoleManager) GetEffectivePermissions(userID string) (*auth.PermissionSet, error) {
	perms, exists := m.permissions[userID]
	if !exists {
		return &auth.PermissionSet{
			Permissions: []auth.Permission{},
		}, nil
	}
	return perms, nil
}

func (m *MockRoleManager) CheckPermission(userID, resource, action string) (bool, error) {
	perms, err := m.GetEffectivePermissions(userID)
	if err != nil {
		return false, err
	}

	for _, perm := range perms.Permissions {
		if (perm.Resource == "*" || perm.Resource == resource) &&
		   (perm.Action == "*" || perm.Action == action) {
			return perm.Effect == "allow", nil
		}
	}

	return false, nil
}

func TestSecurityIntegration_NewSecurityIntegration(t *testing.T) {
	iamService := NewMockIAMService()
	roleManager := NewMockRoleManager()

	config := DefaultSecurityIntegrationConfig()
	config.ConfigPath = "/tmp/test_security_config.json"

	integration, err := NewSecurityIntegration(iamService, roleManager, config)
	if err != nil {
		t.Fatalf("Failed to create security integration: %v", err)
	}

	if integration == nil {
		t.Fatal("Security integration is nil")
	}

	// Cleanup
	defer func() {
		integration.Stop()
		os.Remove(config.ConfigPath)
	}()

	// Test that all components are initialized
	if config.EnableSecurityManager && integration.securityManager == nil {
		t.Error("Security manager should be initialized")
	}

	if config.EnableIAMIntegration && integration.iamIntegration == nil {
		t.Error("IAM integration should be initialized")
	}

	if config.EnableAuditLogging && integration.auditLogger == nil {
		t.Error("Audit logger should be initialized")
	}

	if config.EnableRateLimiting && integration.rateLimiter == nil {
		t.Error("Rate limiter should be initialized")
	}

	if config.EnableConfigManager && integration.configManager == nil {
		t.Error("Config manager should be initialized")
	}
}

func TestSecurityIntegration_ValidatePinOperation(t *testing.T) {
	iamService := NewMockIAMService()
	roleManager := NewMockRoleManager()

	// Create test user
	testAccount := auth.Account{
		Access: "testuser",
		Secret: "testsecret",
		Role:   auth.RoleUser,
	}
	iamService.CreateAccount(testAccount)

	config := DefaultSecurityIntegrationConfig()
	config.ConfigPath = "/tmp/test_security_config.json"

	integration, err := NewSecurityIntegration(iamService, roleManager, config)
	if err != nil {
		t.Fatalf("Failed to create security integration: %v", err)
	}
	defer func() {
		integration.Stop()
		os.Remove(config.ConfigPath)
	}()

	ctx := context.Background()
	req := &PinOperationRequest{
		UserID:    "testuser",
		Account:   testAccount,
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
		RequestID: "test-request-1",
		Operation: "pin",
		CID:       "QmTest123",
		S3Key:     "test/object.txt",
		Bucket:    "test-bucket",
		IsRoot:    false,
	}

	// Test validation (should fail due to lack of permissions)
	err = integration.ValidatePinOperation(ctx, req)
	if err == nil {
		t.Error("Expected validation to fail for user without permissions")
	}

	// Grant IPFS permissions to user
	if integration.iamIntegration != nil {
		err = integration.iamIntegration.AssignIPFSRole(ctx, "testuser", "ipfs-user")
		if err != nil {
			t.Fatalf("Failed to assign IPFS role: %v", err)
		}

		// Test validation again (should pass now)
		err = integration.ValidatePinOperation(ctx, req)
		if err != nil {
			t.Errorf("Expected validation to pass after granting permissions: %v", err)
		}
	}
}

func TestSecurityIntegration_ValidateMetadataOperation(t *testing.T) {
	iamService := NewMockIAMService()
	roleManager := NewMockRoleManager()

	// Create test user
	testAccount := auth.Account{
		Access: "testuser",
		Secret: "testsecret",
		Role:   auth.RoleUser,
	}
	iamService.CreateAccount(testAccount)

	config := DefaultSecurityIntegrationConfig()
	config.ConfigPath = "/tmp/test_security_config.json"

	integration, err := NewSecurityIntegration(iamService, roleManager, config)
	if err != nil {
		t.Fatalf("Failed to create security integration: %v", err)
	}
	defer func() {
		integration.Stop()
		os.Remove(config.ConfigPath)
	}()

	ctx := context.Background()
	req := &MetadataOperationRequest{
		UserID:    "testuser",
		Account:   testAccount,
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
		RequestID: "test-request-1",
		Operation: "read",
		S3Key:     "test/object.txt",
		Bucket:    "test-bucket",
		CID:       "QmTest123",
		IsRoot:    false,
	}

	// Test validation
	err = integration.ValidateMetadataOperation(ctx, req)
	if err == nil {
		t.Error("Expected validation to fail for user without permissions")
	}

	// Grant IPFS permissions to user
	if integration.iamIntegration != nil {
		err = integration.iamIntegration.AssignIPFSRole(ctx, "testuser", "ipfs-readonly")
		if err != nil {
			t.Fatalf("Failed to assign IPFS role: %v", err)
		}

		// Test validation again (should pass for read operation)
		err = integration.ValidateMetadataOperation(ctx, req)
		if err != nil {
			t.Errorf("Expected validation to pass for read operation: %v", err)
		}

		// Test write operation (should fail for readonly user)
		req.Operation = "update"
		err = integration.ValidateMetadataOperation(ctx, req)
		if err == nil {
			t.Error("Expected validation to fail for write operation with readonly permissions")
		}
	}
}

func TestSecurityIntegration_RateLimiting(t *testing.T) {
	iamService := NewMockIAMService()
	roleManager := NewMockRoleManager()

	config := DefaultSecurityIntegrationConfig()
	config.ConfigPath = "/tmp/test_security_config.json"
	config.RateLimitConfig.PinOperations = 2 // Very low limit for testing

	integration, err := NewSecurityIntegration(iamService, roleManager, config)
	if err != nil {
		t.Fatalf("Failed to create security integration: %v", err)
	}
	defer func() {
		integration.Stop()
		os.Remove(config.ConfigPath)
	}()

	userID := "testuser"

	// First request should pass
	err = integration.CheckRateLimit(userID, "pin")
	if err != nil {
		t.Errorf("First request should pass: %v", err)
	}

	// Second request should pass
	err = integration.CheckRateLimit(userID, "pin")
	if err != nil {
		t.Errorf("Second request should pass: %v", err)
	}

	// Third request should fail (rate limit exceeded)
	err = integration.CheckRateLimit(userID, "pin")
	if err == nil {
		t.Error("Third request should fail due to rate limit")
	}
}

func TestSecurityIntegration_EncryptionDecryption(t *testing.T) {
	iamService := NewMockIAMService()
	roleManager := NewMockRoleManager()

	config := DefaultSecurityIntegrationConfig()
	config.ConfigPath = "/tmp/test_security_config.json"
	config.SecurityManagerConfig.EnableClientSideEncryption = true

	integration, err := NewSecurityIntegration(iamService, roleManager, config)
	if err != nil {
		t.Fatalf("Failed to create security integration: %v", err)
	}
	defer func() {
		integration.Stop()
		os.Remove(config.ConfigPath)
	}()

	originalData := []byte("Hello, IPFS Security!")
	metadata := map[string]string{
		"content-type": "text/plain",
	}

	// Test encryption
	encryptedData, encryptedMetadata, err := integration.EncryptData(originalData, metadata)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Encrypted data should be different from original
	if string(encryptedData) == string(originalData) {
		t.Error("Encrypted data should be different from original")
	}

	// Metadata should contain encryption information
	if encryptedMetadata["x-ipfs-encryption"] != "AES-256-GCM" {
		t.Error("Metadata should contain encryption information")
	}

	// Test decryption
	decryptedData, err := integration.DecryptData(encryptedData, encryptedMetadata)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	// Decrypted data should match original
	if string(decryptedData) != string(originalData) {
		t.Errorf("Decrypted data doesn't match original. Expected: %s, Got: %s", 
			string(originalData), string(decryptedData))
	}
}

func TestSecurityIntegration_AuditLogging(t *testing.T) {
	iamService := NewMockIAMService()
	roleManager := NewMockRoleManager()

	config := DefaultSecurityIntegrationConfig()
	config.ConfigPath = "/tmp/test_security_config.json"
	config.AuditConfig.LogFile = "/tmp/test_audit.log"

	integration, err := NewSecurityIntegration(iamService, roleManager, config)
	if err != nil {
		t.Fatalf("Failed to create security integration: %v", err)
	}
	defer func() {
		integration.Stop()
		os.Remove(config.ConfigPath)
		os.Remove(config.AuditConfig.LogFile)
	}()

	// Create test user
	testAccount := auth.Account{
		Access: "testuser",
		Secret: "testsecret",
		Role:   auth.RoleUser,
	}

	// Test pin operation logging
	pinReq := &PinOperationRequest{
		UserID:    "testuser",
		Account:   testAccount,
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
		RequestID: "test-request-1",
		Operation: "pin",
		CID:       "QmTest123",
		S3Key:     "test/object.txt",
		Bucket:    "test-bucket",
		IsRoot:    false,
	}

	integration.LogPinOperation(pinReq, true, 100*time.Millisecond, nil)

	// Test metadata operation logging
	metaReq := &MetadataOperationRequest{
		UserID:    "testuser",
		Account:   testAccount,
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
		RequestID: "test-request-2",
		Operation: "read",
		S3Key:     "test/object.txt",
		Bucket:    "test-bucket",
		CID:       "QmTest123",
		IsRoot:    false,
	}

	integration.LogMetadataOperation(metaReq, true, 50*time.Millisecond, nil)

	// Give some time for async logging
	time.Sleep(100 * time.Millisecond)

	// Check if audit log file was created
	if _, err := os.Stat(config.AuditConfig.LogFile); os.IsNotExist(err) {
		t.Error("Audit log file should be created")
	}

	// Get metrics to verify logging
	if integration.auditLogger != nil {
		metrics := integration.auditLogger.GetMetrics()
		if metrics.TotalEvents < 2 {
			t.Errorf("Expected at least 2 audit events, got %d", metrics.TotalEvents)
		}
	}
}

func TestSecurityIntegration_GetSecurityMetrics(t *testing.T) {
	iamService := NewMockIAMService()
	roleManager := NewMockRoleManager()

	config := DefaultSecurityIntegrationConfig()
	config.ConfigPath = "/tmp/test_security_config.json"

	integration, err := NewSecurityIntegration(iamService, roleManager, config)
	if err != nil {
		t.Fatalf("Failed to create security integration: %v", err)
	}
	defer func() {
		integration.Stop()
		os.Remove(config.ConfigPath)
	}()

	// Get security metrics
	metrics, err := integration.GetSecurityMetrics()
	if err != nil {
		t.Fatalf("Failed to get security metrics: %v", err)
	}

	if metrics == nil {
		t.Fatal("Security metrics should not be nil")
	}

	// Check that metrics contain expected fields
	if metrics.Timestamp.IsZero() {
		t.Error("Metrics timestamp should be set")
	}

	// If audit logging is enabled, audit metrics should be present
	if config.EnableAuditLogging && metrics.AuditMetrics == nil {
		t.Error("Audit metrics should be present when audit logging is enabled")
	}

	// If rate limiting is enabled, rate limiting metrics should be present
	if config.EnableRateLimiting && metrics.RateLimitingMetrics == nil {
		t.Error("Rate limiting metrics should be present when rate limiting is enabled")
	}
}

func TestSecurityIntegration_ConfigurationManagement(t *testing.T) {
	iamService := NewMockIAMService()
	roleManager := NewMockRoleManager()

	config := DefaultSecurityIntegrationConfig()
	config.ConfigPath = "/tmp/test_security_config.json"

	integration, err := NewSecurityIntegration(iamService, roleManager, config)
	if err != nil {
		t.Fatalf("Failed to create security integration: %v", err)
	}
	defer func() {
		integration.Stop()
		os.Remove(config.ConfigPath)
	}()

	// Test getting configuration
	currentConfig, err := integration.GetConfiguration()
	if err != nil {
		t.Fatalf("Failed to get configuration: %v", err)
	}

	if currentConfig == nil {
		t.Fatal("Configuration should not be nil")
	}

	// Test updating configuration
	err = integration.UpdateConfiguration(func(cfg *ComprehensiveSecurityConfig) error {
		cfg.StrictMode = true
		cfg.RateLimiting.GlobalRateLimit = 5000
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to update configuration: %v", err)
	}

	// Verify configuration was updated
	updatedConfig, err := integration.GetConfiguration()
	if err != nil {
		t.Fatalf("Failed to get updated configuration: %v", err)
	}

	if !updatedConfig.StrictMode {
		t.Error("StrictMode should be true after update")
	}

	if updatedConfig.RateLimiting.GlobalRateLimit != 5000 {
		t.Errorf("GlobalRateLimit should be 5000 after update, got %d", 
			updatedConfig.RateLimiting.GlobalRateLimit)
	}
}

func TestSecurityIntegration_StartStop(t *testing.T) {
	iamService := NewMockIAMService()
	roleManager := NewMockRoleManager()

	config := DefaultSecurityIntegrationConfig()
	config.ConfigPath = "/tmp/test_security_config.json"

	integration, err := NewSecurityIntegration(iamService, roleManager, config)
	if err != nil {
		t.Fatalf("Failed to create security integration: %v", err)
	}
	defer os.Remove(config.ConfigPath)

	// Test starting
	err = integration.Start()
	if err != nil {
		t.Fatalf("Failed to start security integration: %v", err)
	}

	// Test starting again (should fail)
	err = integration.Start()
	if err == nil {
		t.Error("Starting already started integration should fail")
	}

	// Test stopping
	err = integration.Stop()
	if err != nil {
		t.Fatalf("Failed to stop security integration: %v", err)
	}

	// Test stopping again (should not fail)
	err = integration.Stop()
	if err != nil {
		t.Errorf("Stopping already stopped integration should not fail: %v", err)
	}
}

// Benchmark tests

func BenchmarkSecurityIntegration_ValidatePinOperation(b *testing.B) {
	iamService := NewMockIAMService()
	roleManager := NewMockRoleManager()

	testAccount := auth.Account{
		Access: "testuser",
		Secret: "testsecret",
		Role:   auth.RoleUser,
	}
	iamService.CreateAccount(testAccount)

	config := DefaultSecurityIntegrationConfig()
	config.ConfigPath = "/tmp/bench_security_config.json"

	integration, err := NewSecurityIntegration(iamService, roleManager, config)
	if err != nil {
		b.Fatalf("Failed to create security integration: %v", err)
	}
	defer func() {
		integration.Stop()
		os.Remove(config.ConfigPath)
	}()

	ctx := context.Background()
	req := &PinOperationRequest{
		UserID:    "testuser",
		Account:   testAccount,
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
		RequestID: "test-request-1",
		Operation: "pin",
		CID:       "QmTest123",
		S3Key:     "test/object.txt",
		Bucket:    "test-bucket",
		IsRoot:    false,
	}

	// Grant permissions
	if integration.iamIntegration != nil {
		integration.iamIntegration.AssignIPFSRole(ctx, "testuser", "ipfs-user")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integration.ValidatePinOperation(ctx, req)
	}
}

func BenchmarkSecurityIntegration_EncryptDecrypt(b *testing.B) {
	iamService := NewMockIAMService()
	roleManager := NewMockRoleManager()

	config := DefaultSecurityIntegrationConfig()
	config.ConfigPath = "/tmp/bench_security_config.json"
	config.SecurityManagerConfig.EnableClientSideEncryption = true

	integration, err := NewSecurityIntegration(iamService, roleManager, config)
	if err != nil {
		b.Fatalf("Failed to create security integration: %v", err)
	}
	defer func() {
		integration.Stop()
		os.Remove(config.ConfigPath)
	}()

	data := []byte("Hello, IPFS Security! This is a test message for encryption benchmarking.")
	metadata := map[string]string{"content-type": "text/plain"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptedData, encryptedMetadata, err := integration.EncryptData(data, metadata)
		if err != nil {
			b.Fatal(err)
		}

		_, err = integration.DecryptData(encryptedData, encryptedMetadata)
		if err != nil {
			b.Fatal(err)
		}
	}
}