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
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/versity/versitygw/s3err"
)

// TestEnhancedAuthSystemEndToEnd tests the complete authentication flow
func TestEnhancedAuthSystemEndToEnd(t *testing.T) {
	// Setup complete auth system
	system := setupCompleteAuthSystem(t)
	defer system.cleanup()

	// Test scenarios
	testScenarios := []struct {
		name        string
		description string
		testFunc    func(t *testing.T, system *IntegratedAuthSystem)
	}{
		{
			name:        "BasicAuthenticationFlow",
			description: "Test basic user authentication with caching",
			testFunc:    testBasicAuthenticationFlow,
		},
		{
			name:        "MFAAuthenticationFlow",
			description: "Test MFA-enabled authentication flow",
			testFunc:    testMFAAuthenticationFlow,
		},
		{
			name:        "RoleBasedAccessControl",
			description: "Test role-based access control with multiple roles",
			testFunc:    testRoleBasedAccessControl,
		},
		{
			name:        "SessionManagement",
			description: "Test session creation, validation, and termination",
			testFunc:    testSessionManagement,
		},
		{
			name:        "ExternalProviderIntegration",
			description: "Test external identity provider integration",
			testFunc:    testExternalProviderIntegration,
		},
		{
			name:        "SecurityAuditingAndAlerting",
			description: "Test security auditing and alerting system",
			testFunc:    testSecurityAuditingAndAlerting,
		},
		{
			name:        "CachePerformanceAndFallback",
			description: "Test cache performance and fallback mechanisms",
			testFunc:    testCachePerformanceAndFallback,
		},
		{
			name:        "ConfigurationManagement",
			description: "Test dynamic configuration management",
			testFunc:    testConfigurationManagement,
		},
	}

	for _, scenario := range testScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("Running scenario: %s - %s", scenario.name, scenario.description)
			scenario.testFunc(t, system)
		})
	}
}

// IntegratedAuthSystem represents a complete auth system for testing
type IntegratedAuthSystem struct {
	Backend              *MockBackend
	Cache                EnhancedCache
	MFAService           MFAService
	RoleManager          EnhancedRoleManager
	SessionManager       SessionManager
	ExternalProviders    *ExternalProviderManager
	SecurityAuditLogger  SecurityAuditLogger
	ConfigManager        *ConfigManager
	SuspiciousDetector   *SuspiciousActivityDetector
	SecurityAlertSystem  *SecurityAlertSystem
	PerformanceMonitor   *PerformanceMonitor
	SystemStatusMonitor  *SystemStatusMonitor
	cleanup              func()
}

func setupCompleteAuthSystem(t *testing.T) *IntegratedAuthSystem {
	// Create mock backend
	backend := NewMockBackend()

	// Create enhanced cache
	cacheConfig := &CacheConfig{
		DefaultTTL:      5 * time.Minute,
		MaxSize:         1000,
		EvictionPolicy:  "lru",
		FallbackEnabled: true,
	}
	cache := NewEnhancedIAMCache(cacheConfig)

	// Create MFA service
	mfaConfig := &MFAConfig{
		Required:    false,
		TOTPWindow:  30,
		BackupCodes: 10,
		GracePeriod: 5 * time.Minute,
	}
	mfaService := NewMFAService(mfaConfig)

	// Create role manager
	roleManager := NewInMemoryRoleManager()

	// Create session manager
	sessionConfig := &SessionConfig{
		DefaultTTL:    24 * time.Hour,
		MaxSessions:   100,
		CleanupPeriod: 1 * time.Hour,
	}
	auditLogger := &MockSecurityAuditLoggerForIntegration{}
	sessionManager := NewSessionManager(sessionConfig, auditLogger)

	// Create external provider manager
	providerManager := NewExternalProviderManager()

	// Create security audit logger
	securityAuditLogger := &MockSecurityAuditLoggerForIntegration{}

	// Create config manager
	configManager := NewConfigManager()

	// Create suspicious activity detector
	suspiciousDetector := NewSuspiciousActivityDetector(securityAuditLogger)

	// Create security alert system
	alertSystem := NewSecurityAlertSystem(securityAuditLogger)

	// Create performance monitor
	perfMonitor := NewPerformanceMonitor()

	// Create system status monitor
	statusMonitor := NewSystemStatusMonitor()

	// Setup test data
	setupTestData(t, roleManager, mfaService)

	return &IntegratedAuthSystem{
		Backend:              backend,
		Cache:                cache,
		MFAService:           mfaService,
		RoleManager:          roleManager,
		SessionManager:       sessionManager,
		ExternalProviders:    providerManager,
		SecurityAuditLogger:  securityAuditLogger,
		ConfigManager:        configManager,
		SuspiciousDetector:   suspiciousDetector,
		SecurityAlertSystem:  alertSystem,
		PerformanceMonitor:   perfMonitor,
		SystemStatusMonitor:  statusMonitor,
		cleanup: func() {
			// Cleanup resources
			sessionManager.Stop()
			suspiciousDetector.Stop()
			alertSystem.Stop()
			perfMonitor.Stop()
			statusMonitor.Stop()
		},
	}
}

func setupTestData(t *testing.T, roleManager EnhancedRoleManager, mfaService MFAService) {
	// Create test roles
	roles := []*EnhancedRole{
		{
			ID:          "read-only",
			Name:        "Read Only",
			Description: "Read-only access to all buckets",
			Permissions: []DetailedPermission{
				{
					Resource: "arn:aws:s3:::*/*",
					Action:   "s3:GetObject",
					Effect:   PermissionAllow,
				},
				{
					Resource: "arn:aws:s3:::*",
					Action:   "s3:ListBucket",
					Effect:   PermissionAllow,
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "read-write",
			Name:        "Read Write",
			Description: "Read-write access to specific buckets",
			Permissions: []DetailedPermission{
				{
					Resource: "arn:aws:s3:::user-bucket/*",
					Action:   "s3:*",
					Effect:   PermissionAllow,
				},
			},
			ParentRoles: []string{"read-only"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "admin",
			Name:        "Administrator",
			Description: "Full administrative access",
			Permissions: []DetailedPermission{
				{
					Resource: "arn:aws:s3:::*",
					Action:   "*",
					Effect:   PermissionAllow,
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	for _, role := range roles {
		if err := roleManager.CreateRole(role); err != nil {
			t.Fatalf("Failed to create role %s: %v", role.ID, err)
		}
	}

	// Create test users with roles
	testUsers := []struct {
		userID string
		roles  []string
		mfa    bool
	}{
		{"test-user-1", []string{"read-only"}, false},
		{"test-user-2", []string{"read-write"}, true},
		{"test-admin", []string{"admin"}, true},
		{"multi-role-user", []string{"read-only", "read-write"}, false},
	}

	for _, user := range testUsers {
		for _, roleID := range user.roles {
			if err := roleManager.AssignRole(user.userID, roleID, "system"); err != nil {
				t.Fatalf("Failed to assign role %s to user %s: %v", roleID, user.userID, err)
			}
		}

		if user.mfa {
			secret, err := mfaService.GenerateSecret(user.userID)
			if err != nil {
				t.Fatalf("Failed to generate MFA secret for user %s: %v", user.userID, err)
			}
			if err := mfaService.EnableMFA(user.userID, secret); err != nil {
				t.Fatalf("Failed to enable MFA for user %s: %v", user.userID, err)
			}
		}
	}
}

// MockSecurityAuditLoggerForIntegration for integration testing
type MockSecurityAuditLoggerForIntegration struct {
	mu                sync.RWMutex
	authEvents        []*AuthEvent
	authzEvents       []*AuthzEvent
	securityAlerts    []*SecurityAlert
	sessionEvents     []*SessionEvent
	auditRecords      []*AuditRecord
	securityReports   []*SecurityReport
}

func (m *MockSecurityAuditLoggerForIntegration) LogAuthenticationAttempt(event *AuthEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authEvents = append(m.authEvents, event)
	return nil
}

func (m *MockSecurityAuditLoggerForIntegration) LogAuthorizationCheck(event *AuthzEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authzEvents = append(m.authzEvents, event)
	return nil
}

func (m *MockSecurityAuditLoggerForIntegration) LogSecurityAlert(alert *SecurityAlert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.securityAlerts = append(m.securityAlerts, alert)
	return nil
}

func (m *MockSecurityAuditLoggerForIntegration) LogSessionEvent(event *SessionEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessionEvents = append(m.sessionEvents, event)
	return nil
}

func (m *MockSecurityAuditLoggerForIntegration) QueryAuditLogs(query *AuditQuery) ([]*AuditRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.auditRecords, nil
}

func (m *MockSecurityAuditLoggerForIntegration) GenerateSecurityReport(params *ReportParams) (*SecurityReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	report := &SecurityReport{
		GeneratedAt:        time.Now(),
		Period:             params.Period,
		TotalAuthAttempts:  len(m.authEvents),
		FailedAuthAttempts: 0,
		SecurityAlerts:     len(m.securityAlerts),
		ActiveSessions:     len(m.sessionEvents),
	}

	for _, event := range m.authEvents {
		if !event.Success {
			report.FailedAuthAttempts++
		}
	}

	return report, nil
}

func (m *MockSecurityAuditLoggerForIntegration) GetAuthEvents() []*AuthEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	events := make([]*AuthEvent, len(m.authEvents))
	copy(events, m.authEvents)
	return events
}

func (m *MockSecurityAuditLoggerForIntegration) GetSecurityAlerts() []*SecurityAlert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	alerts := make([]*SecurityAlert, len(m.securityAlerts))
	copy(alerts, m.securityAlerts)
	return alerts
}

func (m *MockSecurityAuditLoggerForIntegration) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authEvents = nil
	m.authzEvents = nil
	m.securityAlerts = nil
	m.sessionEvents = nil
	m.auditRecords = nil
	m.securityReports = nil
}

// testBasicAuthenticationFlow tests the basic authentication flow with caching
func testBasicAuthenticationFlow(t *testing.T, system *IntegratedAuthSystem) {
	ctx := context.Background()
	userID := "test-user-1"

	// Test authentication without cache
	opts := AccessOptions{
		RoleManager: system.RoleManager,
		IsRoot:      false,
		Acc: Account{
			Access: userID,
			Role:   RoleUser,
		},
		Bucket: "test-bucket",
		Object: "test-object",
		Action: GetObjectAction,
	}

	// First access - should hit backend and cache result
	start := time.Now()
	err := VerifyAccess(ctx, system.Backend, opts)
	firstAccessTime := time.Since(start)

	if err != nil {
		t.Errorf("Expected access to be allowed, got error: %v", err)
	}

	// Second access - should hit cache and be faster
	start = time.Now()
	err = VerifyAccess(ctx, system.Backend, opts)
	secondAccessTime := time.Since(start)

	if err != nil {
		t.Errorf("Expected cached access to be allowed, got error: %v", err)
	}

	// Cache should make second access faster
	if secondAccessTime >= firstAccessTime {
		t.Logf("Warning: Cache may not be working optimally. First: %v, Second: %v", 
			firstAccessTime, secondAccessTime)
	}

	// Test cache statistics
	stats := system.Cache.GetStats()
	if stats.Hits == 0 {
		t.Error("Expected cache hits but got 0")
	}

	t.Logf("Cache stats - Hits: %d, Misses: %d, Hit Rate: %.2f%%", 
		stats.Hits, stats.Misses, stats.HitRate*100)
}

// testMFAAuthenticationFlow tests MFA-enabled authentication
func testMFAAuthenticationFlow(t *testing.T, system *IntegratedAuthSystem) {
	userID := "test-user-2"

	// Verify MFA is enabled for user
	status, err := system.MFAService.GetMFAStatus(userID)
	if err != nil {
		t.Fatalf("Failed to get MFA status: %v", err)
	}
	if !status.Enabled {
		t.Fatal("Expected MFA to be enabled for test-user-2")
	}

	// Test authentication without MFA token (should fail)
	ctx := context.Background()
	opts := AccessOptions{
		RoleManager: system.RoleManager,
		IsRoot:      false,
		Acc: Account{
			Access: userID,
			Role:   RoleUser,
		},
		Bucket: "user-bucket",
		Object: "test-object",
		Action: GetObjectAction,
		// No MFA token provided
	}

	err = VerifyAccess(ctx, system.Backend, opts)
	if err == nil {
		t.Error("Expected access to be denied without MFA token")
	}

	// Generate valid TOTP token
	secret, err := system.MFAService.GenerateSecret(userID)
	if err != nil {
		t.Fatalf("Failed to generate TOTP secret: %v", err)
	}

	// Simulate TOTP validation (in real scenario, user would provide token)
	err = system.MFAService.ValidateTOTP(userID, "123456") // Mock token
	if err == nil {
		t.Error("Expected invalid TOTP to fail")
	}

	// Test with valid MFA context (simulated)
	opts.MFAVerified = true
	err = VerifyAccess(ctx, system.Backend, opts)
	if err != nil {
		t.Errorf("Expected access to be allowed with MFA verification: %v", err)
	}
}

// testRoleBasedAccessControl tests role-based access control
func testRoleBasedAccessControl(t *testing.T, system *IntegratedAuthSystem) {
	ctx := context.Background()

	testCases := []struct {
		name        string
		userID      string
		bucket      string
		object      string
		action      Action
		expectAllow bool
		description string
	}{
		{
			name:        "ReadOnlyUserGetObject",
			userID:      "test-user-1",
			bucket:      "any-bucket",
			object:      "test-object",
			action:      GetObjectAction,
			expectAllow: true,
			description: "Read-only user should be able to get objects",
		},
		{
			name:        "ReadOnlyUserPutObject",
			userID:      "test-user-1",
			bucket:      "any-bucket",
			object:      "test-object",
			action:      PutObjectAction,
			expectAllow: false,
			description: "Read-only user should not be able to put objects",
		},
		{
			name:        "ReadWriteUserPutObject",
			userID:      "test-user-2",
			bucket:      "user-bucket",
			object:      "test-object",
			action:      PutObjectAction,
			expectAllow: true,
			description: "Read-write user should be able to put objects in allowed bucket",
		},
		{
			name:        "ReadWriteUserPutObjectDeniedBucket",
			userID:      "test-user-2",
			bucket:      "restricted-bucket",
			object:      "test-object",
			action:      PutObjectAction,
			expectAllow: false,
			description: "Read-write user should not be able to put objects in non-allowed bucket",
		},
		{
			name:        "AdminUserFullAccess",
			userID:      "test-admin",
			bucket:      "any-bucket",
			object:      "test-object",
			action:      DeleteObjectAction,
			expectAllow: true,
			description: "Admin user should have full access",
		},
		{
			name:        "MultiRoleUserCombinedPermissions",
			userID:      "multi-role-user",
			bucket:      "user-bucket",
			object:      "test-object",
			action:      PutObjectAction,
			expectAllow: true,
			description: "Multi-role user should have combined permissions",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := AccessOptions{
				RoleManager: system.RoleManager,
				IsRoot:      false,
				Acc: Account{
					Access: tc.userID,
					Role:   RoleUser,
				},
				Bucket: tc.bucket,
				Object: tc.object,
				Action: tc.action,
			}

			err := VerifyAccess(ctx, system.Backend, opts)

			if tc.expectAllow {
				if err != nil {
					t.Errorf("Expected access to be allowed but got error: %v. %s", err, tc.description)
				}
			} else {
				if err == nil {
					t.Errorf("Expected access to be denied but got no error. %s", tc.description)
				}
			}
		})
	}
}

// testSessionManagement tests session creation, validation, and termination
func testSessionManagement(t *testing.T, system *IntegratedAuthSystem) {
	userID := "test-user-1"

	// Create session
	metadata := &SessionMetadata{
		IPAddress: "192.168.1.100",
		UserAgent: "TestClient/1.0",
		LoginMethod: "password",
	}

	session, err := system.SessionManager.CreateSession(userID, metadata)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if session.UserID != userID {
		t.Errorf("Expected session user ID %s, got %s", userID, session.UserID)
	}

	// Validate session
	validatedSession, err := system.SessionManager.ValidateSession(session.ID)
	if err != nil {
		t.Fatalf("Failed to validate session: %v", err)
	}

	if validatedSession.ID != session.ID {
		t.Errorf("Expected session ID %s, got %s", session.ID, validatedSession.ID)
	}

	// Get active sessions
	activeSessions, err := system.SessionManager.GetActiveSessions(userID)
	if err != nil {
		t.Fatalf("Failed to get active sessions: %v", err)
	}

	if len(activeSessions) == 0 {
		t.Error("Expected at least one active session")
	}

	// Create multiple sessions for the same user
	for i := 0; i < 3; i++ {
		_, err := system.SessionManager.CreateSession(userID, metadata)
		if err != nil {
			t.Fatalf("Failed to create additional session %d: %v", i, err)
		}
	}

	// Check total active sessions
	activeSessions, err = system.SessionManager.GetActiveSessions(userID)
	if err != nil {
		t.Fatalf("Failed to get active sessions after creating multiple: %v", err)
	}

	if len(activeSessions) != 4 { // Original + 3 additional
		t.Errorf("Expected 4 active sessions, got %d", len(activeSessions))
	}

	// Terminate specific session
	err = system.SessionManager.TerminateSession(session.ID)
	if err != nil {
		t.Fatalf("Failed to terminate session: %v", err)
	}

	// Verify session is terminated
	_, err = system.SessionManager.ValidateSession(session.ID)
	if err == nil {
		t.Error("Expected terminated session to be invalid")
	}

	// Terminate all user sessions
	err = system.SessionManager.TerminateAllUserSessions(userID)
	if err != nil {
		t.Fatalf("Failed to terminate all user sessions: %v", err)
	}

	// Verify all sessions are terminated
	activeSessions, err = system.SessionManager.GetActiveSessions(userID)
	if err != nil {
		t.Fatalf("Failed to get active sessions after terminating all: %v", err)
	}

	if len(activeSessions) != 0 {
		t.Errorf("Expected 0 active sessions after terminating all, got %d", len(activeSessions))
	}
}

// testExternalProviderIntegration tests external identity provider integration
func testExternalProviderIntegration(t *testing.T, system *IntegratedAuthSystem) {
	// Create mock SAML provider
	samlProvider := &MockSAMLProvider{
		name:     "test-saml",
		healthy:  true,
		users:    make(map[string]*ExternalUser),
	}

	// Add test user to SAML provider
	samlProvider.users["external-user-1"] = &ExternalUser{
		ID:    "external-user-1",
		Email: "user1@example.com",
		Name:  "External User 1",
		Groups: []string{"developers", "users"},
		Attributes: map[string]interface{}{
			"department": "engineering",
		},
	}

	// Register provider
	err := system.ExternalProviders.RegisterProvider("test-saml", samlProvider)
	if err != nil {
		t.Fatalf("Failed to register SAML provider: %v", err)
	}

	// Test authentication through external provider
	credentials := &SAMLCredentials{
		Assertion: "mock-saml-assertion",
		UserID:    "external-user-1",
	}

	externalUser, err := samlProvider.Authenticate(credentials)
	if err != nil {
		t.Fatalf("Failed to authenticate through SAML provider: %v", err)
	}

	if externalUser.ID != "external-user-1" {
		t.Errorf("Expected user ID 'external-user-1', got '%s'", externalUser.ID)
	}

	// Test provider health check
	if !samlProvider.IsHealthy() {
		t.Error("Expected SAML provider to be healthy")
	}

	// Test fallback when provider is unhealthy
	samlProvider.healthy = false
	if samlProvider.IsHealthy() {
		t.Error("Expected SAML provider to be unhealthy")
	}

	// Test OAuth2 provider
	oauth2Provider := &MockOAuth2Provider{
		name:    "test-oauth2",
		healthy: true,
		tokens:  make(map[string]*TokenClaims),
	}

	oauth2Provider.tokens["valid-token"] = &TokenClaims{
		Subject:   "oauth-user-1",
		Email:     "oauth1@example.com",
		Name:      "OAuth User 1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err = system.ExternalProviders.RegisterProvider("test-oauth2", oauth2Provider)
	if err != nil {
		t.Fatalf("Failed to register OAuth2 provider: %v", err)
	}

	// Test token validation
	claims, err := oauth2Provider.ValidateToken("valid-token")
	if err != nil {
		t.Fatalf("Failed to validate OAuth2 token: %v", err)
	}

	if claims.Subject != "oauth-user-1" {
		t.Errorf("Expected subject 'oauth-user-1', got '%s'", claims.Subject)
	}

	// Test invalid token
	_, err = oauth2Provider.ValidateToken("invalid-token")
	if err == nil {
		t.Error("Expected invalid token to fail validation")
	}
}

// testSecurityAuditingAndAlerting tests security auditing and alerting
func testSecurityAuditingAndAlerting(t *testing.T, system *IntegratedAuthSystem) {
	userID := "test-user-1"
	auditLogger := system.SecurityAuditLogger.(*MockSecurityAuditLoggerForIntegration)

	// Reset audit logger
	auditLogger.Reset()

	// Generate authentication events
	authEvent := &AuthEvent{
		UserID:    userID,
		Action:    "login",
		Success:   true,
		IPAddress: "192.168.1.100",
		UserAgent: "TestClient/1.0",
		MFAUsed:   false,
		Provider:  "internal",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"method": "password",
		},
	}

	err := auditLogger.LogAuthenticationAttempt(authEvent)
	if err != nil {
		t.Fatalf("Failed to log authentication event: %v", err)
	}

	// Generate failed authentication events to trigger alerts
	for i := 0; i < 5; i++ {
		failedEvent := &AuthEvent{
			UserID:    userID,
			Action:    "login",
			Success:   false,
			IPAddress: "192.168.1.100",
			UserAgent: "TestClient/1.0",
			MFAUsed:   false,
			Provider:  "internal",
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"method": "password",
				"reason": "invalid_credentials",
			},
		}

		err := auditLogger.LogAuthenticationAttempt(failedEvent)
		if err != nil {
			t.Fatalf("Failed to log failed authentication event: %v", err)
		}
	}

	// Process events through suspicious activity detector
	events := auditLogger.GetAuthEvents()
	for _, event := range events {
		system.SuspiciousDetector.ProcessAuthEvent(event)
	}

	// Check for security alerts
	time.Sleep(100 * time.Millisecond) // Allow processing time
	alerts := auditLogger.GetSecurityAlerts()

	if len(alerts) == 0 {
		t.Error("Expected security alerts to be generated for multiple failed attempts")
	}

	// Generate security report
	reportParams := &ReportParams{
		Period:    "1h",
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now(),
	}

	report, err := auditLogger.GenerateSecurityReport(reportParams)
	if err != nil {
		t.Fatalf("Failed to generate security report: %v", err)
	}

	if report.TotalAuthAttempts == 0 {
		t.Error("Expected non-zero total authentication attempts in report")
	}

	if report.FailedAuthAttempts == 0 {
		t.Error("Expected non-zero failed authentication attempts in report")
	}

	t.Logf("Security Report - Total: %d, Failed: %d, Alerts: %d", 
		report.TotalAuthAttempts, report.FailedAuthAttempts, report.SecurityAlerts)
}

// testCachePerformanceAndFallback tests cache performance and fallback mechanisms
func testCachePerformanceAndFallback(t *testing.T, system *IntegratedAuthSystem) {
	userID := "test-user-1"

	// Test cache performance
	iterations := 100
	var totalTime time.Duration

	for i := 0; i < iterations; i++ {
		start := time.Now()
		
		// Simulate cache lookup
		key := fmt.Sprintf("user:%s:permissions", userID)
		_, found := system.Cache.Get(key, UserRoles)
		
		if !found {
			// Simulate expensive operation
			permissions := &PermissionSet{
				Permissions: []DetailedPermission{
					{
						Resource: "arn:aws:s3:::*/*",
						Action:   "s3:GetObject",
						Effect:   PermissionAllow,
					},
				},
			}
			system.Cache.Set(key, permissions, 5*time.Minute, UserRoles)
		}
		
		totalTime += time.Since(start)
	}

	avgTime := totalTime / time.Duration(iterations)
	t.Logf("Average cache operation time: %v", avgTime)

	// Test cache statistics
	stats := system.Cache.GetStats()
	t.Logf("Cache stats - Hits: %d, Misses: %d, Hit Rate: %.2f%%, Size: %d", 
		stats.Hits, stats.Misses, stats.HitRate*100, stats.Size)

	// Test cache eviction
	maxSize := 10
	for i := 0; i < maxSize*2; i++ {
		key := fmt.Sprintf("test-key-%d", i)
		system.Cache.Set(key, fmt.Sprintf("value-%d", i), 5*time.Minute, UserCredentials)
	}

	// Verify LRU eviction occurred
	finalStats := system.Cache.GetStats()
	if finalStats.Size > maxSize {
		t.Errorf("Expected cache size to be limited to %d, got %d", maxSize, finalStats.Size)
	}

	// Test fallback mode
	system.Cache.SetFallbackMode(true)
	
	// Simulate backend failure and verify fallback works
	key := "fallback-test-key"
	testValue := "fallback-test-value"
	system.Cache.Set(key, testValue, 5*time.Minute, UserCredentials)
	
	value, found := system.Cache.Get(key, UserCredentials)
	if !found {
		t.Error("Expected fallback cache to return cached value")
	}
	
	if value != testValue {
		t.Errorf("Expected fallback value '%s', got '%v'", testValue, value)
	}
}

// testConfigurationManagement tests dynamic configuration management
func testConfigurationManagement(t *testing.T, system *IntegratedAuthSystem) {
	// Test initial configuration
	config := system.ConfigManager.GetCurrentConfig()
	if config == nil {
		t.Fatal("Expected initial configuration to be available")
	}

	// Test configuration update
	newConfig := &AuthConfig{
		Cache: CacheConfig{
			DefaultTTL:      10 * time.Minute,
			MaxSize:         2000,
			EvictionPolicy:  "lru",
			FallbackEnabled: true,
		},
		MFA: MFAConfig{
			Required:    true,
			TOTPWindow:  60,
			BackupCodes: 5,
			GracePeriod: 10 * time.Minute,
		},
		Session: SessionConfig{
			DefaultTTL:    12 * time.Hour,
			MaxSessions:   50,
			CleanupPeriod: 30 * time.Minute,
		},
	}

	err := system.ConfigManager.UpdateConfig(newConfig)
	if err != nil {
		t.Fatalf("Failed to update configuration: %v", err)
	}

	// Verify configuration was updated
	updatedConfig := system.ConfigManager.GetCurrentConfig()
	if updatedConfig.Cache.DefaultTTL != 10*time.Minute {
		t.Errorf("Expected cache TTL to be updated to 10m, got %v", updatedConfig.Cache.DefaultTTL)
	}

	if !updatedConfig.MFA.Required {
		t.Error("Expected MFA to be required after configuration update")
	}

	// Test configuration validation
	invalidConfig := &AuthConfig{
		Cache: CacheConfig{
			DefaultTTL: -1 * time.Minute, // Invalid negative TTL
		},
	}

	err = system.ConfigManager.UpdateConfig(invalidConfig)
	if err == nil {
		t.Error("Expected invalid configuration to be rejected")
	}

	// Test configuration rollback
	err = system.ConfigManager.RollbackConfig()
	if err != nil {
		t.Fatalf("Failed to rollback configuration: %v", err)
	}

	rolledBackConfig := system.ConfigManager.GetCurrentConfig()
	if rolledBackConfig.MFA.Required {
		t.Error("Expected MFA requirement to be rolled back")
	}
}

// Mock providers for testing

// MockSAMLProvider implements ExternalProvider for SAML testing
type MockSAMLProvider struct {
	name     string
	healthy  bool
	users    map[string]*ExternalUser
}

func (m *MockSAMLProvider) Authenticate(credentials interface{}) (*ExternalUser, error) {
	samlCreds, ok := credentials.(*SAMLCredentials)
	if !ok {
		return nil, fmt.Errorf("invalid credentials type")
	}

	if !m.healthy {
		return nil, fmt.Errorf("SAML provider is unhealthy")
	}

	user, exists := m.users[samlCreds.UserID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

func (m *MockSAMLProvider) ValidateToken(token string) (*TokenClaims, error) {
	return nil, fmt.Errorf("SAML provider does not support token validation")
}

func (m *MockSAMLProvider) GetProviderInfo() *ProviderInfo {
	return &ProviderInfo{
		Name:         m.name,
		Type:         "saml",
		Description:  "Mock SAML Provider for testing",
		Capabilities: []string{"authentication"},
	}
}

func (m *MockSAMLProvider) IsHealthy() bool {
	return m.healthy
}

// MockOAuth2Provider implements ExternalProvider for OAuth2 testing
type MockOAuth2Provider struct {
	name    string
	healthy bool
	tokens  map[string]*TokenClaims
}

func (m *MockOAuth2Provider) Authenticate(credentials interface{}) (*ExternalUser, error) {
	return nil, fmt.Errorf("OAuth2 provider does not support direct authentication")
}

func (m *MockOAuth2Provider) ValidateToken(token string) (*TokenClaims, error) {
	if !m.healthy {
		return nil, fmt.Errorf("OAuth2 provider is unhealthy")
	}

	claims, exists := m.tokens[token]
	if !exists {
		return nil, fmt.Errorf("invalid token")
	}

	if time.Now().After(claims.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	return claims, nil
}

func (m *MockOAuth2Provider) GetProviderInfo() *ProviderInfo {
	return &ProviderInfo{
		Name:         m.name,
		Type:         "oauth2",
		Description:  "Mock OAuth2 Provider for testing",
		Capabilities: []string{"token_validation"},
	}
}

func (m *MockOAuth2Provider) IsHealthy() bool {
	return m.healthy
}

// Additional test data structures

type SAMLCredentials struct {
	Assertion string
	UserID    string
}

type TokenClaims struct {
	Subject   string
	Email     string
	Name      string
	ExpiresAt time.Time
}

type ExternalUser struct {
	ID         string
	Email      string
	Name       string
	Groups     []string
	Attributes map[string]interface{}
}

type ProviderInfo struct {
	Name         string
	Type         string
	Description  string
	Capabilities []string
}

type SessionMetadata struct {
	IPAddress   string
	UserAgent   string
	LoginMethod string
}

type AuthzEvent struct {
	UserID    string
	Resource  string
	Action    string
	Decision  string
	Timestamp time.Time
}

type SecurityAlert struct {
	Type        AlertType
	Severity    AlertSeverity
	UserID      string
	Description string
	Metadata    map[string]interface{}
	Timestamp   time.Time
}

type SessionEvent struct {
	SessionID string
	UserID    string
	Action    string
	Timestamp time.Time
}

type AuditRecord struct {
	ID        string
	Type      string
	UserID    string
	Action    string
	Resource  string
	Timestamp time.Time
	Details   map[string]interface{}
}

type SecurityReport struct {
	GeneratedAt        time.Time
	Period             string
	TotalAuthAttempts  int
	FailedAuthAttempts int
	SecurityAlerts     int
	ActiveSessions     int
}

type ReportParams struct {
	Period    string
	StartTime time.Time
	EndTime   time.Time
}

type AuditQuery struct {
	UserID    string
	Action    string
	StartTime time.Time
	EndTime   time.Time
	Limit     int
}

type AlertType int
const (
	AlertTypeMultipleFailedLogins AlertType = iota
	AlertTypeSuspiciousActivity
	AlertTypeUnauthorizedAccess
	AlertTypeAccountLockout
)

type AlertSeverity int
const (
	AlertSeverityLow AlertSeverity = iota
	AlertSeverityMedium
	AlertSeverityHigh
	AlertSeverityCritical
)

type PermissionSet struct {
	Permissions []DetailedPermission
	UpdatedAt   time.Time
}

type CacheStats struct {
	Hits     int64
	Misses   int64
	Size     int64
	HitRate  float64
}

// Test concurrent authentication scenarios
func TestConcurrentAuthenticationScenarios(t *testing.T) {
	system := setupCompleteAuthSystem(t)
	defer system.cleanup()

	// Test concurrent user authentication
	t.Run("ConcurrentUserAuthentication", func(t *testing.T) {
		testConcurrentUserAuthentication(t, system)
	})

	// Test concurrent session management
	t.Run("ConcurrentSessionManagement", func(t *testing.T) {
		testConcurrentSessionManagement(t, system)
	})

	// Test concurrent role updates
	t.Run("ConcurrentRoleUpdates", func(t *testing.T) {
		testConcurrentRoleUpdates(t, system)
	})

	// Test concurrent cache operations
	t.Run("ConcurrentCacheOperations", func(t *testing.T) {
		testConcurrentCacheOperations(t, system)
	})
}

func testConcurrentUserAuthentication(t *testing.T, system *IntegratedAuthSystem) {
	ctx := context.Background()
	numUsers := 10
	numConcurrentRequests := 5

	var wg sync.WaitGroup
	errors := make(chan error, numUsers*numConcurrentRequests)

	// Create test users
	for i := 0; i < numUsers; i++ {
		userID := fmt.Sprintf("concurrent-user-%d", i)
		err := system.RoleManager.AssignRole(userID, "read-only", "system")
		if err != nil {
			t.Fatalf("Failed to assign role to user %s: %v", userID, err)
		}
	}

	// Simulate concurrent authentication requests
	for i := 0; i < numUsers; i++ {
		for j := 0; j < numConcurrentRequests; j++ {
			wg.Add(1)
			go func(userIndex, requestIndex int) {
				defer wg.Done()

				userID := fmt.Sprintf("concurrent-user-%d", userIndex)
				opts := AccessOptions{
					RoleManager: system.RoleManager,
					IsRoot:      false,
					Acc: Account{
						Access: userID,
						Role:   RoleUser,
					},
					Bucket: "test-bucket",
					Object: fmt.Sprintf("object-%d-%d", userIndex, requestIndex),
					Action: GetObjectAction,
				}

				err := VerifyAccess(ctx, system.Backend, opts)
				if err != nil {
					errors <- fmt.Errorf("user %s request %d failed: %v", userID, requestIndex, err)
				}
			}(i, j)
		}
	}

	wg.Wait()
	close(errors)

	// Check for errors
	var errorCount int
	for err := range errors {
		t.Errorf("Concurrent authentication error: %v", err)
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("Got %d errors out of %d concurrent requests", errorCount, numUsers*numConcurrentRequests)
	}

	// Verify cache performance under load
	stats := system.Cache.GetStats()
	t.Logf("Concurrent auth cache stats - Hits: %d, Misses: %d, Hit Rate: %.2f%%", 
		stats.Hits, stats.Misses, stats.HitRate*100)
}

func testConcurrentSessionManagement(t *testing.T, system *IntegratedAuthSystem) {
	numUsers := 5
	sessionsPerUser := 3

	var wg sync.WaitGroup
	errors := make(chan error, numUsers*sessionsPerUser*2) // *2 for create and terminate

	// Concurrent session creation and termination
	for i := 0; i < numUsers; i++ {
		wg.Add(1)
		go func(userIndex int) {
			defer wg.Done()

			userID := fmt.Sprintf("session-user-%d", userIndex)
			var sessions []*Session

			// Create multiple sessions
			for j := 0; j < sessionsPerUser; j++ {
				metadata := &SessionMetadata{
					IPAddress:   fmt.Sprintf("192.168.1.%d", userIndex+100),
					UserAgent:   fmt.Sprintf("TestClient/%d.%d", userIndex, j),
					LoginMethod: "password",
				}

				session, err := system.SessionManager.CreateSession(userID, metadata)
				if err != nil {
					errors <- fmt.Errorf("failed to create session for user %s: %v", userID, err)
					continue
				}
				sessions = append(sessions, session)
			}

			// Validate sessions concurrently
			var validateWg sync.WaitGroup
			for _, session := range sessions {
				validateWg.Add(1)
				go func(s *Session) {
					defer validateWg.Done()
					_, err := system.SessionManager.ValidateSession(s.ID)
					if err != nil {
						errors <- fmt.Errorf("failed to validate session %s: %v", s.ID, err)
					}
				}(session)
			}
			validateWg.Wait()

			// Terminate sessions
			for _, session := range sessions {
				err := system.SessionManager.TerminateSession(session.ID)
				if err != nil {
					errors <- fmt.Errorf("failed to terminate session %s: %v", session.ID, err)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	var errorCount int
	for err := range errors {
		t.Errorf("Concurrent session management error: %v", err)
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("Got %d errors in concurrent session management", errorCount)
	}
}

func testConcurrentRoleUpdates(t *testing.T, system *IntegratedAuthSystem) {
	numWorkers := 5
	operationsPerWorker := 10

	var wg sync.WaitGroup
	errors := make(chan error, numWorkers*operationsPerWorker)

	// Concurrent role operations
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerIndex int) {
			defer wg.Done()

			for j := 0; j < operationsPerWorker; j++ {
				roleID := fmt.Sprintf("concurrent-role-%d-%d", workerIndex, j)
				userID := fmt.Sprintf("concurrent-user-%d-%d", workerIndex, j)

				// Create role
				role := &EnhancedRole{
					ID:          roleID,
					Name:        fmt.Sprintf("Concurrent Role %d-%d", workerIndex, j),
					Description: "Role for concurrent testing",
					Permissions: []DetailedPermission{
						{
							Resource: fmt.Sprintf("arn:aws:s3:::bucket-%d/*", workerIndex),
							Action:   "s3:GetObject",
							Effect:   PermissionAllow,
						},
					},
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}

				err := system.RoleManager.CreateRole(role)
				if err != nil {
					errors <- fmt.Errorf("worker %d: failed to create role %s: %v", workerIndex, roleID, err)
					continue
				}

				// Assign role to user
				err = system.RoleManager.AssignRole(userID, roleID, "system")
				if err != nil {
					errors <- fmt.Errorf("worker %d: failed to assign role %s to user %s: %v", workerIndex, roleID, userID, err)
					continue
				}

				// Get user roles
				_, err = system.RoleManager.GetUserRoles(userID)
				if err != nil {
					errors <- fmt.Errorf("worker %d: failed to get roles for user %s: %v", workerIndex, userID, err)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	var errorCount int
	for err := range errors {
		t.Errorf("Concurrent role update error: %v", err)
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("Got %d errors in concurrent role updates", errorCount)
	}
}

func testConcurrentCacheOperations(t *testing.T, system *IntegratedAuthSystem) {
	numWorkers := 10
	operationsPerWorker := 100

	var wg sync.WaitGroup
	errors := make(chan error, numWorkers*operationsPerWorker)

	// Concurrent cache operations
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerIndex int) {
			defer wg.Done()

			for j := 0; j < operationsPerWorker; j++ {
				key := fmt.Sprintf("cache-key-%d-%d", workerIndex, j)
				value := fmt.Sprintf("cache-value-%d-%d", workerIndex, j)

				// Set value
				system.Cache.Set(key, value, 1*time.Minute, UserCredentials)

				// Get value
				retrievedValue, found := system.Cache.Get(key, UserCredentials)
				if !found {
					errors <- fmt.Errorf("worker %d: failed to retrieve cached value for key %s", workerIndex, key)
					continue
				}

				if retrievedValue != value {
					errors <- fmt.Errorf("worker %d: cache value mismatch for key %s: expected %s, got %v", 
						workerIndex, key, value, retrievedValue)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	var errorCount int
	for err := range errors {
		t.Errorf("Concurrent cache operation error: %v", err)
		errorCount++
	}

	if errorCount > 0 {
		t.Errorf("Got %d errors in concurrent cache operations", errorCount)
	}

	// Verify final cache state
	stats := system.Cache.GetStats()
	t.Logf("Final cache stats - Hits: %d, Misses: %d, Hit Rate: %.2f%%, Size: %d", 
		stats.Hits, stats.Misses, stats.HitRate*100, stats.Size)
}