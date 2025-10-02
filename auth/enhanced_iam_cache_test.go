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
	"regexp"
	"testing"
	"time"
)

// mockIAMService implements IAMService for testing
type mockIAMService struct {
	accounts    map[string]Account
	shouldError bool
	errorMsg    string
}

func newMockIAMService() *mockIAMService {
	return &mockIAMService{
		accounts: make(map[string]Account),
	}
}

func (m *mockIAMService) CreateAccount(account Account) error {
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	m.accounts[account.Access] = account
	return nil
}

func (m *mockIAMService) GetUserAccount(access string) (Account, error) {
	if m.shouldError {
		return Account{}, errors.New(m.errorMsg)
	}
	if account, exists := m.accounts[access]; exists {
		return account, nil
	}
	return Account{}, ErrNoSuchUser
}

func (m *mockIAMService) UpdateUserAccount(access string, props MutableProps) error {
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	if account, exists := m.accounts[access]; exists {
		updateAcc(&account, props)
		m.accounts[access] = account
		return nil
	}
	return ErrNoSuchUser
}

func (m *mockIAMService) DeleteUserAccount(access string) error {
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	delete(m.accounts, access)
	return nil
}

func (m *mockIAMService) ListUserAccounts() ([]Account, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	accounts := make([]Account, 0, len(m.accounts))
	for _, account := range m.accounts {
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (m *mockIAMService) Shutdown() error {
	return nil
}

func (m *mockIAMService) setError(shouldError bool, errorMsg string) {
	m.shouldError = shouldError
	m.errorMsg = errorMsg
}

func TestEnhancedIAMCache_BasicOperations(t *testing.T) {
	mockService := newMockIAMService()
	cache := NewEnhancedIAMCache(mockService, nil)
	defer cache.Shutdown()

	testAccount := Account{
		Access: "test-access",
		Secret: "test-secret",
		Role:   RoleUser,
		UserID: 1001,
	}

	// Test CreateAccount
	err := cache.CreateAccount(testAccount)
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Test GetUserAccount (should hit cache)
	account, err := cache.GetUserAccount("test-access")
	if err != nil {
		t.Fatalf("Failed to get account: %v", err)
	}

	if account.Access != testAccount.Access {
		t.Fatalf("Expected access %s, got %s", testAccount.Access, account.Access)
	}

	// Verify it was cached by checking stats
	stats := cache.GetCacheStats()
	if stats.Hits == 0 {
		t.Fatal("Expected cache hit")
	}
}

func TestEnhancedIAMCache_FallbackMechanism(t *testing.T) {
	mockService := newMockIAMService()
	cache := NewEnhancedIAMCache(mockService, nil)
	defer cache.Shutdown()

	testAccount := Account{
		Access: "fallback-test",
		Secret: "fallback-secret",
		Role:   RoleUser,
	}

	// First, create and cache the account
	err := cache.CreateAccount(testAccount)
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Clear primary cache to simulate cache miss
	key := "user:fallback-test"
	cache.cache.Invalidate("^" + regexp.QuoteMeta(key) + "$")

	// Now make the service return errors
	mockService.setError(true, "service unavailable")

	// Should still be able to get account from fallback cache
	account, err := cache.GetUserAccount("fallback-test")
	if err != nil {
		t.Fatalf("Expected fallback to work, got error: %v", err)
	}

	if account.Access != testAccount.Access {
		t.Fatalf("Expected access %s, got %s", testAccount.Access, account.Access)
	}

	// Verify fallback mode is active
	stats := cache.GetCacheStats()
	if !stats.FallbackActive {
		t.Fatal("Expected fallback mode to be active")
	}
}

func TestEnhancedIAMCache_UpdateInvalidation(t *testing.T) {
	mockService := newMockIAMService()
	cache := NewEnhancedIAMCache(mockService, nil)
	defer cache.Shutdown()

	testAccount := Account{
		Access: "update-test",
		Secret: "original-secret",
		Role:   RoleUser,
	}

	// Create and cache account
	err := cache.CreateAccount(testAccount)
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Get account to ensure it's cached
	_, err = cache.GetUserAccount("update-test")
	if err != nil {
		t.Fatalf("Failed to get account: %v", err)
	}

	// Update account
	newSecret := "updated-secret"
	props := MutableProps{
		Secret: &newSecret,
		Role:   RoleAdmin,
	}

	err = cache.UpdateUserAccount("update-test", props)
	if err != nil {
		t.Fatalf("Failed to update account: %v", err)
	}

	// Get account again - should have updated values
	account, err := cache.GetUserAccount("update-test")
	if err != nil {
		t.Fatalf("Failed to get updated account: %v", err)
	}

	if account.Secret != newSecret {
		t.Fatalf("Expected secret %s, got %s", newSecret, account.Secret)
	}

	if account.Role != RoleAdmin {
		t.Fatalf("Expected role %s, got %s", RoleAdmin, account.Role)
	}
}

func TestEnhancedIAMCache_DeleteInvalidation(t *testing.T) {
	mockService := newMockIAMService()
	cache := NewEnhancedIAMCache(mockService, nil)
	defer cache.Shutdown()

	testAccount := Account{
		Access: "delete-test",
		Secret: "delete-secret",
		Role:   RoleUser,
	}

	// Create and cache account
	err := cache.CreateAccount(testAccount)
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Verify account exists
	_, err = cache.GetUserAccount("delete-test")
	if err != nil {
		t.Fatalf("Failed to get account before deletion: %v", err)
	}

	// Delete account
	err = cache.DeleteUserAccount("delete-test")
	if err != nil {
		t.Fatalf("Failed to delete account: %v", err)
	}

	// Account should no longer exist
	_, err = cache.GetUserAccount("delete-test")
	if err == nil {
		t.Fatal("Expected error when getting deleted account")
	}
}

func TestEnhancedIAMCache_HealthCheck(t *testing.T) {
	mockService := newMockIAMService()
	cache := NewEnhancedIAMCache(mockService, nil)
	defer cache.Shutdown()

	// Initially healthy
	if !cache.IsHealthy() {
		t.Fatal("Expected service to be healthy initially")
	}

	// Make service unhealthy
	mockService.setError(true, "service down")

	if cache.IsHealthy() {
		t.Fatal("Expected service to be unhealthy")
	}

	// Restore service health
	mockService.setError(false, "")

	if !cache.IsHealthy() {
		t.Fatal("Expected service to be healthy again")
	}
}

func TestEnhancedIAMCache_CacheInvalidationMethods(t *testing.T) {
	mockService := newMockIAMService()
	cache := NewEnhancedIAMCache(mockService, nil)
	defer cache.Shutdown()

	// Create test accounts
	accounts := []Account{
		{Access: "user1", Secret: "secret1", Role: RoleUser},
		{Access: "user2", Secret: "secret2", Role: RoleAdmin},
		{Access: "admin1", Secret: "secret3", Role: RoleAdmin},
	}

	for _, account := range accounts {
		err := cache.CreateAccount(account)
		if err != nil {
			t.Fatalf("Failed to create account %s: %v", account.Access, err)
		}
	}

	// Test InvalidateUser
	err := cache.InvalidateUser("user1")
	if err != nil {
		t.Fatalf("Failed to invalidate user: %v", err)
	}

	// Test InvalidatePattern
	err = cache.InvalidatePattern("^user:")
	if err != nil {
		t.Fatalf("Failed to invalidate pattern: %v", err)
	}

	// Test InvalidateType
	err = cache.InvalidateType(UserCredentials)
	if err != nil {
		t.Fatalf("Failed to invalidate type: %v", err)
	}
}

func TestEnhancedIAMCache_FallbackCacheStats(t *testing.T) {
	mockService := newMockIAMService()
	cache := NewEnhancedIAMCache(mockService, nil)
	defer cache.Shutdown()

	// Get fallback cache stats
	fallbackStats := cache.GetFallbackCacheStats()

	// Should have default values
	if fallbackStats.MaxSize == 0 {
		t.Fatal("Expected fallback cache to have max size > 0")
	}
}

func TestEnhancedIAMCache_ConfigurableTTL(t *testing.T) {
	mockService := newMockIAMService()
	
	config := &EnhancedIAMCacheConfig{
		CacheConfig: &EnhancedCacheConfig{
			MaxSize:         100,
			CleanupInterval: 1 * time.Minute,
			DefaultTTLs: map[CacheEntryType]time.Duration{
				UserCredentials: 10 * time.Millisecond, // Very short for testing
			},
		},
		FallbackEnabled: true,
	}

	cache := NewEnhancedIAMCache(mockService, config)
	defer cache.Shutdown()

	testAccount := Account{
		Access: "ttl-test",
		Secret: "ttl-secret",
		Role:   RoleUser,
	}

	// Create account
	err := cache.CreateAccount(testAccount)
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Should be available immediately
	_, err = cache.GetUserAccount("ttl-test")
	if err != nil {
		t.Fatalf("Failed to get account immediately: %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(20 * time.Millisecond)

	// Clear the underlying service to force cache lookup
	mockService.setError(true, "service unavailable")

	// Should still work due to fallback cache (longer TTL)
	_, err = cache.GetUserAccount("ttl-test")
	if err != nil {
		t.Fatalf("Expected fallback cache to work: %v", err)
	}
}

func TestEnhancedIAMCache_ListUserAccountsPassthrough(t *testing.T) {
	mockService := newMockIAMService()
	cache := NewEnhancedIAMCache(mockService, nil)
	defer cache.Shutdown()

	// Add some accounts to mock service
	testAccounts := []Account{
		{Access: "list1", Secret: "secret1", Role: RoleUser},
		{Access: "list2", Secret: "secret2", Role: RoleAdmin},
	}

	for _, account := range testAccounts {
		mockService.accounts[account.Access] = account
	}

	// List accounts should pass through to service
	accounts, err := cache.ListUserAccounts()
	if err != nil {
		t.Fatalf("Failed to list accounts: %v", err)
	}

	if len(accounts) != len(testAccounts) {
		t.Fatalf("Expected %d accounts, got %d", len(testAccounts), len(accounts))
	}
}

func TestEnhancedIAMCache_SetFallbackMode(t *testing.T) {
	mockService := newMockIAMService()
	cache := NewEnhancedIAMCache(mockService, nil)
	defer cache.Shutdown()

	// Test setting fallback mode
	cache.SetFallbackMode(true)

	stats := cache.GetCacheStats()
	if !stats.FallbackActive {
		t.Fatal("Expected fallback mode to be active")
	}

	cache.SetFallbackMode(false)

	stats = cache.GetCacheStats()
	if stats.FallbackActive {
		t.Fatal("Expected fallback mode to be inactive")
	}
}