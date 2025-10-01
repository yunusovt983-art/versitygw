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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/s3err"
)

// IPFSSecurityMiddleware provides security middleware for IPFS operations
type IPFSSecurityMiddleware struct {
	security *SecurityIntegration
	config   *MiddlewareConfig
}

// MiddlewareConfig contains configuration for the security middleware
type MiddlewareConfig struct {
	EnableSecurityHeaders bool     `json:"enable_security_headers"`
	AllowedOrigins       []string `json:"allowed_origins"`
	MaxRequestSize       int64    `json:"max_request_size"`
	EnableCSRFProtection bool     `json:"enable_csrf_protection"`
	EnableCORS           bool     `json:"enable_cors"`
	TrustedProxies       []string `json:"trusted_proxies"`
	RateLimitByIP        bool     `json:"rate_limit_by_ip"`
}

// DefaultMiddlewareConfig returns default middleware configuration
func DefaultMiddlewareConfig() *MiddlewareConfig {
	return &MiddlewareConfig{
		EnableSecurityHeaders: true,
		AllowedOrigins:       []string{"*"},
		MaxRequestSize:       100 * 1024 * 1024, // 100MB
		EnableCSRFProtection: true,
		EnableCORS:           true,
		TrustedProxies:       []string{"127.0.0.1", "::1"},
		RateLimitByIP:        true,
	}
}

// NewIPFSSecurityMiddleware creates a new IPFS security middleware
func NewIPFSSecurityMiddleware(security *SecurityIntegration, config *MiddlewareConfig) *IPFSSecurityMiddleware {
	if config == nil {
		config = DefaultMiddlewareConfig()
	}

	return &IPFSSecurityMiddleware{
		security: security,
		config:   config,
	}
}

// Handler returns a Fiber middleware handler for IPFS security
func (m *IPFSSecurityMiddleware) Handler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Skip security for health checks and internal endpoints
		if m.shouldSkipSecurity(c) {
			return c.Next()
		}

		// Apply security headers
		if m.config.EnableSecurityHeaders {
			m.applySecurityHeaders(c)
		}

		// Check request size limits
		if err := m.checkRequestSize(c); err != nil {
			return err
		}

		// Extract user context
		userCtx, err := m.extractUserContext(c)
		if err != nil {
			return m.handleSecurityError(c, err, "authentication_failed")
		}

		// Check rate limits
		if err := m.checkRateLimits(c, userCtx); err != nil {
			return m.handleSecurityError(c, err, "rate_limit_exceeded")
		}

		// Validate IPFS operation permissions
		if err := m.validateIPFSOperation(c, userCtx); err != nil {
			return m.handleSecurityError(c, err, "permission_denied")
		}

		// Store user context for downstream handlers
		c.Locals("ipfs_user_context", userCtx)

		return c.Next()
	}
}

// PinOperationMiddleware provides specific middleware for pin operations
func (m *IPFSSecurityMiddleware) PinOperationMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		userCtx := c.Locals("ipfs_user_context").(*IPFSUserContext)
		if userCtx == nil {
			return m.handleSecurityError(c, fmt.Errorf("user context not found"), "invalid_context")
		}

		// Extract pin operation details
		operation := m.extractPinOperation(c)
		if operation == "" {
			return m.handleSecurityError(c, fmt.Errorf("invalid pin operation"), "invalid_operation")
		}

		// Create pin operation request
		pinReq := &PinOperationRequest{
			UserID:    userCtx.UserID,
			Account:   userCtx.Account,
			IPAddress: c.IP(),
			UserAgent: c.Get("User-Agent"),
			RequestID: c.Get("X-Request-ID"),
			Operation: operation,
			CID:       c.Params("cid"),
			S3Key:     c.Query("s3key"),
			Bucket:    c.Query("bucket"),
			IsRoot:    userCtx.IsRoot,
		}

		// Validate pin operation
		startTime := time.Now()
		err := m.security.ValidatePinOperation(c.Context(), pinReq)
		if err != nil {
			m.security.LogPinOperation(pinReq, false, time.Since(startTime), err)
			return m.handleSecurityError(c, err, "pin_operation_denied")
		}

		// Store pin request for logging
		c.Locals("ipfs_pin_request", pinReq)
		c.Locals("ipfs_operation_start", startTime)

		return c.Next()
	}
}

// MetadataOperationMiddleware provides specific middleware for metadata operations
func (m *IPFSSecurityMiddleware) MetadataOperationMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		userCtx := c.Locals("ipfs_user_context").(*IPFSUserContext)
		if userCtx == nil {
			return m.handleSecurityError(c, fmt.Errorf("user context not found"), "invalid_context")
		}

		// Extract metadata operation details
		operation := m.extractMetadataOperation(c)
		if operation == "" {
			return m.handleSecurityError(c, fmt.Errorf("invalid metadata operation"), "invalid_operation")
		}

		// Create metadata operation request
		metaReq := &MetadataOperationRequest{
			UserID:    userCtx.UserID,
			Account:   userCtx.Account,
			IPAddress: c.IP(),
			UserAgent: c.Get("User-Agent"),
			RequestID: c.Get("X-Request-ID"),
			Operation: operation,
			S3Key:     c.Params("key"),
			Bucket:    c.Params("bucket"),
			CID:       c.Query("cid"),
			IsRoot:    userCtx.IsRoot,
		}

		// Validate metadata operation
		startTime := time.Now()
		err := m.security.ValidateMetadataOperation(c.Context(), metaReq)
		if err != nil {
			m.security.LogMetadataOperation(metaReq, false, time.Since(startTime), err)
			return m.handleSecurityError(c, err, "metadata_operation_denied")
		}

		// Store metadata request for logging
		c.Locals("ipfs_metadata_request", metaReq)
		c.Locals("ipfs_operation_start", startTime)

		return c.Next()
	}
}

// AuditLoggingMiddleware provides audit logging for completed operations
func (m *IPFSSecurityMiddleware) AuditLoggingMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Process the request
		err := c.Next()

		// Log the operation result
		m.logOperationResult(c, err)

		return err
	}
}

// Helper methods

func (m *IPFSSecurityMiddleware) shouldSkipSecurity(c *fiber.Ctx) bool {
	path := c.Path()
	
	// Skip security for health checks and metrics
	skipPaths := []string{
		"/health",
		"/metrics",
		"/status",
		"/_internal",
	}

	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	return false
}

func (m *IPFSSecurityMiddleware) applySecurityHeaders(c *fiber.Ctx) {
	// Security headers
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("X-Frame-Options", "DENY")
	c.Set("X-XSS-Protection", "1; mode=block")
	c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	c.Set("Content-Security-Policy", "default-src 'self'")

	// CORS headers if enabled
	if m.config.EnableCORS {
		origin := c.Get("Origin")
		if m.isAllowedOrigin(origin) {
			c.Set("Access-Control-Allow-Origin", origin)
			c.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
			c.Set("Access-Control-Max-Age", "86400")
		}
	}
}

func (m *IPFSSecurityMiddleware) isAllowedOrigin(origin string) bool {
	if len(m.config.AllowedOrigins) == 0 {
		return false
	}

	for _, allowed := range m.config.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}

	return false
}

func (m *IPFSSecurityMiddleware) checkRequestSize(c *fiber.Ctx) error {
	if m.config.MaxRequestSize <= 0 {
		return nil
	}

	contentLength := c.Request().Header.ContentLength()
	if contentLength > int(m.config.MaxRequestSize) {
		return fiber.NewError(http.StatusRequestEntityTooLarge, "Request entity too large")
	}

	return nil
}

func (m *IPFSSecurityMiddleware) extractUserContext(c *fiber.Ctx) (*IPFSUserContext, error) {
	// Extract authentication information from headers or context
	// This would typically integrate with the existing VersityGW auth system
	
	// For now, we'll extract from standard auth headers
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	// Parse the authorization header (this is a simplified example)
	// In a real implementation, this would integrate with the IAM service
	userID := c.Get("X-User-ID")
	if userID == "" {
		userID = "anonymous"
	}

	// Create a basic user context
	// In a real implementation, this would be populated from the IAM service
	userCtx := &IPFSUserContext{
		UserID:    userID,
		Account:   auth.Account{Access: userID, Role: auth.RoleUser},
		IPAddress: c.IP(),
		UserAgent: c.Get("User-Agent"),
		RequestID: c.Get("X-Request-ID"),
		IsRoot:    userID == "root",
	}

	return userCtx, nil
}

func (m *IPFSSecurityMiddleware) checkRateLimits(c *fiber.Ctx, userCtx *IPFSUserContext) error {
	if m.security == nil {
		return nil
	}

	// Determine operation type from path
	operationType := m.getOperationTypeFromPath(c.Path())
	
	// Check user-based rate limit
	if err := m.security.CheckRateLimit(userCtx.UserID, operationType); err != nil {
		return err
	}

	// Check IP-based rate limit if enabled
	if m.config.RateLimitByIP {
		if err := m.security.CheckRateLimit(c.IP(), operationType); err != nil {
			return err
		}
	}

	return nil
}

func (m *IPFSSecurityMiddleware) validateIPFSOperation(c *fiber.Ctx, userCtx *IPFSUserContext) error {
	// Basic validation - specific operation validation is done in operation-specific middleware
	path := c.Path()
	method := c.Method()

	// Check if this is an IPFS-related operation
	if !strings.Contains(path, "/ipfs/") {
		return nil // Not an IPFS operation
	}

	// Validate basic access to IPFS endpoints
	if method == "POST" || method == "PUT" || method == "DELETE" {
		// Write operations require at least user role
		if userCtx.Account.Role == "" {
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}
	}

	return nil
}

func (m *IPFSSecurityMiddleware) extractPinOperation(c *fiber.Ctx) string {
	method := c.Method()
	path := c.Path()

	if strings.Contains(path, "/pin") {
		switch method {
		case "POST":
			return "pin"
		case "DELETE":
			return "unpin"
		case "GET":
			if strings.Contains(path, "/status") {
				return "status"
			}
			return "list"
		}
	}

	return ""
}

func (m *IPFSSecurityMiddleware) extractMetadataOperation(c *fiber.Ctx) string {
	method := c.Method()
	path := c.Path()

	if strings.Contains(path, "/metadata") {
		switch method {
		case "POST":
			return "create"
		case "PUT":
			return "update"
		case "GET":
			return "read"
		case "DELETE":
			return "delete"
		}
	}

	if strings.Contains(path, "/list") {
		return "list"
	}

	return ""
}

func (m *IPFSSecurityMiddleware) getOperationTypeFromPath(path string) string {
	if strings.Contains(path, "/pin") {
		return "pin"
	}
	if strings.Contains(path, "/metadata") {
		return "metadata"
	}
	if strings.Contains(path, "/list") {
		return "list"
	}
	return "general"
}

func (m *IPFSSecurityMiddleware) handleSecurityError(c *fiber.Ctx, err error, eventType string) error {
	// Log security event
	if m.security != nil && m.security.auditLogger != nil {
		userID := "unknown"
		if userCtx := c.Locals("ipfs_user_context"); userCtx != nil {
			if ctx, ok := userCtx.(*IPFSUserContext); ok {
				userID = ctx.UserID
			}
		}

		m.security.auditLogger.LogPinEvent(&PinAuditEvent{
			UserID:       userID,
			IPAddress:    c.IP(),
			UserAgent:    c.Get("User-Agent"),
			RequestID:    c.Get("X-Request-ID"),
			Operation:    eventType,
			Success:      false,
			ErrorMessage: err.Error(),
			Duration:     0,
		})
	}

	// Return appropriate HTTP error
	if strings.Contains(err.Error(), "rate limit") {
		return fiber.NewError(http.StatusTooManyRequests, "Rate limit exceeded")
	}
	if strings.Contains(err.Error(), "access denied") || strings.Contains(err.Error(), "permission") {
		return fiber.NewError(http.StatusForbidden, "Access denied")
	}
	if strings.Contains(err.Error(), "authentication") {
		return fiber.NewError(http.StatusUnauthorized, "Authentication required")
	}

	return fiber.NewError(http.StatusBadRequest, err.Error())
}

func (m *IPFSSecurityMiddleware) logOperationResult(c *fiber.Ctx, err error) {
	if m.security == nil {
		return
	}

	success := err == nil
	duration := time.Duration(0)

	if startTime := c.Locals("ipfs_operation_start"); startTime != nil {
		if start, ok := startTime.(time.Time); ok {
			duration = time.Since(start)
		}
	}

	// Log pin operation if present
	if pinReq := c.Locals("ipfs_pin_request"); pinReq != nil {
		if req, ok := pinReq.(*PinOperationRequest); ok {
			m.security.LogPinOperation(req, success, duration, err)
		}
	}

	// Log metadata operation if present
	if metaReq := c.Locals("ipfs_metadata_request"); metaReq != nil {
		if req, ok := metaReq.(*MetadataOperationRequest); ok {
			m.security.LogMetadataOperation(req, success, duration, err)
		}
	}
}

// IPFSUserContext contains user context information for IPFS operations
type IPFSUserContext struct {
	UserID    string
	Account   auth.Account
	IPAddress string
	UserAgent string
	RequestID string
	IsRoot    bool
}

// SecurityMiddlewareChain creates a complete security middleware chain for IPFS
func (m *IPFSSecurityMiddleware) SecurityMiddlewareChain() []fiber.Handler {
	return []fiber.Handler{
		m.Handler(),                      // Basic security
		m.PinOperationMiddleware(),       // Pin operation validation
		m.MetadataOperationMiddleware(),  // Metadata operation validation
		m.AuditLoggingMiddleware(),       // Audit logging
	}
}

// CreateSecurityRouter creates a Fiber router with security middleware applied
func CreateSecurityRouter(security *SecurityIntegration, config *MiddlewareConfig) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}

			return c.Status(code).JSON(fiber.Map{
				"error":   true,
				"message": err.Error(),
				"code":    code,
			})
		},
	})

	// Create security middleware
	securityMiddleware := NewIPFSSecurityMiddleware(security, config)

	// Apply security middleware to all IPFS routes
	ipfsGroup := app.Group("/ipfs", securityMiddleware.Handler())

	// Pin operations
	pinGroup := ipfsGroup.Group("/pin", securityMiddleware.PinOperationMiddleware())
	pinGroup.Post("/:cid", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Pin operation would be handled here"})
	})
	pinGroup.Delete("/:cid", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Unpin operation would be handled here"})
	})
	pinGroup.Get("/status/:cid", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Pin status would be returned here"})
	})

	// Metadata operations
	metaGroup := ipfsGroup.Group("/metadata", securityMiddleware.MetadataOperationMiddleware())
	metaGroup.Get("/:bucket/:key", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Metadata would be returned here"})
	})
	metaGroup.Put("/:bucket/:key", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Metadata would be updated here"})
	})
	metaGroup.Delete("/:bucket/:key", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Metadata would be deleted here"})
	})

	// Apply audit logging to all routes
	app.Use(securityMiddleware.AuditLoggingMiddleware())

	return app
}