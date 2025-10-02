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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

// TestStandaloneEncryption tests encryption functionality without auth dependencies
func TestStandaloneEncryption(t *testing.T) {
	// Test AES-256-GCM encryption (same as used in security manager)
	key := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	originalData := []byte("Hello, IPFS Security World!")

	// Encrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, originalData, nil)

	// Verify data is encrypted (different from original)
	if string(ciphertext) == string(originalData) {
		t.Errorf("Data should be encrypted and different from original")
	}

	// Decrypt
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		t.Fatalf("Ciphertext too short")
	}

	extractedNonce, extractedCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, extractedNonce, extractedCiphertext, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify decrypted data matches original
	if string(plaintext) != string(originalData) {
		t.Errorf("Decrypted data doesn't match original. Got: %s, Expected: %s",
			string(plaintext), string(originalData))
	}
}

// TestStandaloneRateLimiter tests rate limiter without auth dependencies
func TestStandaloneRateLimiter(t *testing.T) {
	// Test token bucket implementation
	bucket := &TokenBucket{
		tokens:     10,
		capacity:   10,
		lastRefill: time.Now(),
	}

	// Should allow consumption up to capacity
	for i := 0; i < 10; i++ {
		if !bucket.consume() {
			t.Errorf("Should allow consumption %d", i+1)
		}
	}

	// Should deny after capacity is exhausted
	if bucket.consume() {
		t.Errorf("Should deny consumption after capacity exhausted")
	}

	// Test refill after time passes
	bucket.lastRefill = time.Now().Add(-2 * time.Second) // Simulate 2 seconds ago
	bucket.refill()

	// Should have refilled some tokens
	if bucket.tokens <= 0 {
		t.Errorf("Expected tokens to be refilled, got %d", bucket.tokens)
	}
}

// TestStandalonePermissionMatching tests permission matching logic
func TestStandalonePermissionMatching(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		value    string
		expected bool
	}{
		{
			name:     "Exact match",
			pattern:  "ipfs:pin:create",
			value:    "ipfs:pin:create",
			expected: true,
		},
		{
			name:     "Wildcard match",
			pattern:  "*",
			value:    "ipfs:pin:create",
			expected: true,
		},
		{
			name:     "Prefix wildcard",
			pattern:  "ipfs:*",
			value:    "ipfs:pin:create",
			expected: true,
		},
		{
			name:     "Suffix wildcard",
			pattern:  "*:create",
			value:    "ipfs:pin:create",
			expected: true,
		},
		{
			name:     "No match",
			pattern:  "ipfs:pin:read",
			value:    "ipfs:pin:create",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesPattern(tt.pattern, tt.value)
			if result != tt.expected {
				t.Errorf("Expected %t, got %t for pattern %s and value %s",
					tt.expected, result, tt.pattern, tt.value)
			}
		})
	}
}

// Helper function for pattern matching (extracted from the main code)
func matchesPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}

	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(value) >= len(prefix) && value[:len(prefix)] == prefix
	}

	if len(pattern) > 0 && pattern[0] == '*' {
		suffix := pattern[1:]
		return len(value) >= len(suffix) && value[len(value)-len(suffix):] == suffix
	}

	return pattern == value
}

// TestStandaloneAuditEventGeneration tests audit event generation
func TestStandaloneAuditEventGeneration(t *testing.T) {
	// Test creating a pin audit event
	event := &PinAuditEvent{
		EventID:           "test-123",
		Timestamp:         time.Now(),
		UserID:            "test-user",
		IPAddress:         "192.168.1.100",
		UserAgent:         "test-agent",
		RequestID:         "req-123",
		Operation:         "pin",
		CID:               "QmTest123",
		S3Key:             "test-object.txt",
		Bucket:            "test-bucket",
		ObjectSize:        1024,
		ReplicationFactor: 3,
		PinnedNodes:       []string{"node1", "node2", "node3"},
		Success:           true,
		Duration:          100 * time.Millisecond,
	}

	// Verify event fields
	if event.EventID != "test-123" {
		t.Errorf("Expected EventID test-123, got %s", event.EventID)
	}

	if event.Operation != "pin" {
		t.Errorf("Expected Operation pin, got %s", event.Operation)
	}

	if event.ObjectSize != 1024 {
		t.Errorf("Expected ObjectSize 1024, got %d", event.ObjectSize)
	}

	if !event.Success {
		t.Errorf("Expected Success true, got %t", event.Success)
	}

	if len(event.PinnedNodes) != 3 {
		t.Errorf("Expected 3 pinned nodes, got %d", len(event.PinnedNodes))
	}
}

// TestStandaloneSecurityConfig tests security configuration
func TestStandaloneSecurityConfig(t *testing.T) {
	// Test default security configuration
	config := DefaultComprehensiveSecurityConfig()

	if !config.Enabled {
		t.Errorf("Expected security to be enabled by default")
	}

	if config.Authentication == nil {
		t.Errorf("Expected authentication config to be non-nil")
	}

	if config.Encryption == nil {
		t.Errorf("Expected encryption config to be non-nil")
	}

	if config.RateLimiting == nil {
		t.Errorf("Expected rate limiting config to be non-nil")
	}

	if config.AuditLogging == nil {
		t.Errorf("Expected audit logging config to be non-nil")
	}

	// Test encryption settings
	if !config.Encryption.Enabled {
		t.Errorf("Expected encryption to be enabled by default")
	}

	if config.Encryption.Algorithm != "AES-256-GCM" {
		t.Errorf("Expected AES-256-GCM algorithm, got %s", config.Encryption.Algorithm)
	}

	if config.Encryption.KeySize != 256 {
		t.Errorf("Expected key size 256, got %d", config.Encryption.KeySize)
	}

	// Test rate limiting settings
	if !config.RateLimiting.Enabled {
		t.Errorf("Expected rate limiting to be enabled by default")
	}

	if config.RateLimiting.PinOperationLimit <= 0 {
		t.Errorf("Expected positive pin operation limit, got %d", config.RateLimiting.PinOperationLimit)
	}

	// Test audit logging settings
	if !config.AuditLogging.Enabled {
		t.Errorf("Expected audit logging to be enabled by default")
	}

	if config.AuditLogging.LogFile == "" {
		t.Errorf("Expected audit log file to be specified")
	}
}

// TestStandalonePermissionTemplates tests permission templates
func TestStandalonePermissionTemplates(t *testing.T) {
	// Test readonly template
	readonlyPerms := GetPermissionTemplate("readonly")
	if len(readonlyPerms) == 0 {
		t.Errorf("Expected readonly permissions to be non-empty")
	}

	// Verify readonly permissions only allow read operations
	hasReadPermission := false
	hasWritePermission := false

	for _, perm := range readonlyPerms {
		if perm.Action == "ipfs:pin:read" || perm.Action == "ipfs:metadata:read" {
			hasReadPermission = true
		}
		if perm.Action == "ipfs:pin:create" || perm.Action == "ipfs:metadata:write" {
			hasWritePermission = true
		}
	}

	if !hasReadPermission {
		t.Errorf("Expected readonly template to have read permissions")
	}

	if hasWritePermission {
		t.Errorf("Expected readonly template to not have write permissions")
	}

	// Test user template
	userPerms := GetPermissionTemplate("user")
	if len(userPerms) == 0 {
		t.Errorf("Expected user permissions to be non-empty")
	}

	// Test admin template
	adminPerms := GetPermissionTemplate("admin")
	if len(adminPerms) == 0 {
		t.Errorf("Expected admin permissions to be non-empty")
	}

	// Admin should have wildcard permissions
	hasWildcard := false
	for _, perm := range adminPerms {
		if perm.Action == "*" {
			hasWildcard = true
			break
		}
	}

	if !hasWildcard {
		t.Errorf("Expected admin template to have wildcard permissions")
	}
}

// Benchmark tests
func BenchmarkStandaloneEncryption(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	data := make([]byte, 1024) // 1KB test data
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)
		gcm.Seal(nonce, nonce, data, nil)
	}
}

func BenchmarkStandaloneTokenBucket(b *testing.B) {
	bucket := &TokenBucket{
		tokens:     1000,
		capacity:   1000,
		lastRefill: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bucket.consume()
	}
}

func BenchmarkStandalonePatternMatching(b *testing.B) {
	pattern := "ipfs:*"
	value := "ipfs:pin:create"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matchesPattern(pattern, value)
	}
}