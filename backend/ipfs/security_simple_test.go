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
	"testing"
	"time"
)

// TestRateLimiterBasic tests basic rate limiter functionality
func TestRateLimiterBasic(t *testing.T) {
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

// TestAdaptiveRateLimiterBasic tests basic adaptive rate limiter functionality
func TestAdaptiveRateLimiterBasic(t *testing.T) {
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

// TestSecurityConfigManager tests basic security configuration management
func TestSecurityConfigManager(t *testing.T) {
	// Create a temporary config file path
	configPath := "/tmp/test_security_config.json"
	
	// Create config manager
	manager, err := NewSecurityConfigManager(configPath)
	if err != nil {
		t.Fatalf("Failed to create security config manager: %v", err)
	}
	
	// Test getting config
	config := manager.GetConfig()
	if config == nil {
		t.Errorf("Expected config to be non-nil")
	}
	
	if !config.Enabled {
		t.Errorf("Expected security to be enabled by default")
	}
	
	// Test updating config
	err = manager.UpdateConfig(func(c *ComprehensiveSecurityConfig) error {
		c.StrictMode = true
		return nil
	})
	if err != nil {
		t.Errorf("Failed to update config: %v", err)
	}
	
	// Verify update
	updatedConfig := manager.GetConfig()
	if !updatedConfig.StrictMode {
		t.Errorf("Expected strict mode to be enabled after update")
	}
}

// TestIPFSPermissionValidation tests IPFS permission validation
func TestIPFSPermissionValidation(t *testing.T) {
	tests := []struct {
		name        string
		rule        *IPFSPermRule
		expectError bool
	}{
		{
			name: "Valid permission rule",
			rule: &IPFSPermRule{
				Action:   "ipfs:pin:create",
				Resource: "arn:aws:ipfs:::bucket/*",
				Effect:   "allow",
			},
			expectError: false,
		},
		{
			name: "Empty action",
			rule: &IPFSPermRule{
				Action:   "",
				Resource: "arn:aws:ipfs:::bucket/*",
				Effect:   "allow",
			},
			expectError: true,
		},
		{
			name: "Empty resource",
			rule: &IPFSPermRule{
				Action:   "ipfs:pin:create",
				Resource: "",
				Effect:   "allow",
			},
			expectError: true,
		},
		{
			name: "Invalid effect",
			rule: &IPFSPermRule{
				Action:   "ipfs:pin:create",
				Resource: "arn:aws:ipfs:::bucket/*",
				Effect:   "invalid",
			},
			expectError: true,
		},
		{
			name: "Invalid action format",
			rule: &IPFSPermRule{
				Action:   "invalid:action",
				Resource: "arn:aws:ipfs:::bucket/*",
				Effect:   "allow",
			},
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPFSPermission(tt.rule)
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// TestPermissionTemplates tests permission template functionality
func TestPermissionTemplates(t *testing.T) {
	tests := []struct {
		name         string
		templateName string
		expectEmpty  bool
	}{
		{
			name:         "Readonly template",
			templateName: "readonly",
			expectEmpty:  false,
		},
		{
			name:         "User template",
			templateName: "user",
			expectEmpty:  false,
		},
		{
			name:         "Admin template",
			templateName: "admin",
			expectEmpty:  false,
		},
		{
			name:         "Unknown template",
			templateName: "unknown",
			expectEmpty:  false, // Should return readonly as default
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := GetPermissionTemplate(tt.templateName)
			if tt.expectEmpty && len(template) > 0 {
				t.Errorf("Expected empty template but got %d permissions", len(template))
			}
			if !tt.expectEmpty && len(template) == 0 {
				t.Errorf("Expected non-empty template but got empty")
			}
		})
	}
}

// Benchmark tests
func BenchmarkRateLimiter_Allow(b *testing.B) {
	rateLimiter := NewRateLimiter(time.Minute)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rateLimiter.Allow("test-user", 1000)
	}
}

func BenchmarkAdaptiveRateLimiter_Allow(b *testing.B) {
	config := DefaultRateLimitConfig()
	rateLimiter := NewAdaptiveRateLimiter(time.Minute, config)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rateLimiter.Allow("test-user", "pin")
	}
}

func BenchmarkSecurityConfigManager_GetConfig(b *testing.B) {
	configPath := "/tmp/bench_security_config.json"
	manager, err := NewSecurityConfigManager(configPath)
	if err != nil {
		b.Fatalf("Failed to create security config manager: %v", err)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.GetConfig()
	}
}