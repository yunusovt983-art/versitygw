package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// AdminAPI provides HTTP API for authentication system administration
type AdminAPI interface {
	// Server management
	Start(ctx context.Context, address string) error
	Stop() error
	
	// Route registration
	RegisterRoutes(app *fiber.App)
	
	// Middleware
	AuthenticationMiddleware() fiber.Handler
	AuthorizationMiddleware(requiredRole string) fiber.Handler
}

// AdminAPIConfig holds configuration for the admin API
type AdminAPIConfig struct {
	EnableAuthentication bool          `json:"enable_authentication"`
	EnableAuthorization  bool          `json:"enable_authorization"`
	EnableCORS          bool          `json:"enable_cors"`
	EnableLogging       bool          `json:"enable_logging"`
	RequestTimeout      time.Duration `json:"request_timeout"`
	MaxRequestSize      int64         `json:"max_request_size"`
	RateLimitRequests   int           `json:"rate_limit_requests"`
	RateLimitWindow     time.Duration `json:"rate_limit_window"`
}

// DefaultAdminAPIConfig returns default admin API configuration
func DefaultAdminAPIConfig() *AdminAPIConfig {
	return &AdminAPIConfig{
		EnableAuthentication: true,
		EnableAuthorization:  true,
		EnableCORS:          true,
		EnableLogging:       true,
		RequestTimeout:      30 * time.Second,
		MaxRequestSize:      10 * 1024 * 1024, // 10MB
		RateLimitRequests:   100,
		RateLimitWindow:     1 * time.Hour,
	}
}

// adminAPIImpl implements AdminAPI
type adminAPIImpl struct {
	config           *AdminAPIConfig
	configManager    ConfigManager
	statusMonitor    SystemStatusMonitor
	healthChecker    HealthChecker
	app              *fiber.App
	server           *http.Server
}

// NewAdminAPI creates a new admin API instance
func NewAdminAPI(config *AdminAPIConfig, configManager ConfigManager, statusMonitor SystemStatusMonitor, healthChecker HealthChecker) AdminAPI {
	if config == nil {
		config = DefaultAdminAPIConfig()
	}
	
	return &adminAPIImpl{
		config:        config,
		configManager: configManager,
		statusMonitor: statusMonitor,
		healthChecker: healthChecker,
	}
}

// Start starts the admin API server
func (api *adminAPIImpl) Start(ctx context.Context, address string) error {
	// Create Fiber app
	app := fiber.New(fiber.Config{
		ReadTimeout:  api.config.RequestTimeout,
		WriteTimeout: api.config.RequestTimeout,
		BodyLimit:    int(api.config.MaxRequestSize),
		ErrorHandler: api.errorHandler,
	})
	
	// Add middleware
	if api.config.EnableLogging {
		app.Use(logger.New())
	}
	
	app.Use(recover.New())
	
	if api.config.EnableCORS {
		app.Use(cors.New(cors.Config{
			AllowOrigins: "*",
			AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
			AllowHeaders: "Origin,Content-Type,Accept,Authorization",
		}))
	}
	
	// Register routes
	api.RegisterRoutes(app)
	
	api.app = app
	
	// Start server
	go func() {
		if err := app.Listen(address); err != nil {
			fmt.Printf("Failed to start admin API server: %v\n", err)
		}
	}()
	
	// Wait for context cancellation
	<-ctx.Done()
	return api.Stop()
}

// Stop stops the admin API server
func (api *adminAPIImpl) Stop() error {
	if api.app != nil {
		return api.app.Shutdown()
	}
	return nil
}

// RegisterRoutes registers all API routes
func (api *adminAPIImpl) RegisterRoutes(app *fiber.App) {
	// API version prefix
	v1 := app.Group("/api/v1")
	
	// Health check endpoint (no auth required)
	v1.Get("/health", api.handleHealthCheck)
	
	// Apply authentication middleware to protected routes
	protected := v1
	if api.config.EnableAuthentication {
		protected.Use(api.AuthenticationMiddleware())
	}
	
	// Configuration endpoints
	configGroup := protected.Group("/config")
	configGroup.Get("/", api.handleGetConfig)
	configGroup.Put("/", api.handleUpdateConfig)
	configGroup.Post("/validate", api.handleValidateConfig)
	configGroup.Post("/reload", api.handleReloadConfig)
	configGroup.Get("/history", api.handleGetConfigHistory)
	configGroup.Get("/schema", api.handleGetConfigSchema)
	
	// System status endpoints
	statusGroup := protected.Group("/status")
	statusGroup.Get("/", api.handleGetSystemStatus)
	statusGroup.Get("/detailed", api.handleGetDetailedSystemReport)
	statusGroup.Get("/components", api.handleGetComponentStatuses)
	statusGroup.Get("/components/:name", api.handleGetComponentStatus)
	statusGroup.Get("/alerts", api.handleGetActiveAlerts)
	statusGroup.Get("/history", api.handleGetStatusHistory)
	
	// Health endpoints
	healthGroup := protected.Group("/health")
	healthGroup.Get("/system", api.handleGetSystemHealth)
	healthGroup.Get("/components", api.handleGetComponentHealths)
	healthGroup.Get("/components/:name", api.handleGetComponentHealth)
	healthGroup.Get("/components/:name/history", api.handleGetComponentHealthHistory)
	healthGroup.Post("/components/:name/check", api.handleCheckComponentHealth)
	
	// Diagnostic endpoints
	diagGroup := protected.Group("/diagnostics")
	diagGroup.Get("/performance", api.handleGetPerformanceDiagnostics)
	diagGroup.Get("/security", api.handleGetSecurityDiagnostics)
	diagGroup.Get("/dependencies", api.handleGetDependenciesDiagnostics)
	diagGroup.Get("/trends/:component", api.handleGetComponentTrends)
	
	// Administrative endpoints (require admin role)
	adminGroup := protected.Group("/admin")
	if api.config.EnableAuthorization {
		adminGroup.Use(api.AuthorizationMiddleware("admin"))
	}
	adminGroup.Post("/monitoring/start", api.handleStartMonitoring)
	adminGroup.Post("/monitoring/stop", api.handleStopMonitoring)
	adminGroup.Get("/monitoring/status", api.handleGetMonitoringStatus)
}

// AuthenticationMiddleware provides authentication for API endpoints
func (api *adminAPIImpl) AuthenticationMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authorization header required",
			})
		}
		
		// Parse bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid authorization header format",
			})
		}
		
		token := parts[1]
		
		// Validate token (this would integrate with your authentication system)
		// For now, we'll use a simple token validation
		if !api.validateToken(token) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}
		
		// Store user info in context
		c.Locals("user", api.getUserFromToken(token))
		
		return c.Next()
	}
}

// AuthorizationMiddleware provides authorization for API endpoints
func (api *adminAPIImpl) AuthorizationMiddleware(requiredRole string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user")
		if user == nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "User not authenticated",
			})
		}
		
		// Check if user has required role
		if !api.userHasRole(user, requiredRole) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": fmt.Sprintf("Required role: %s", requiredRole),
			})
		}
		
		return c.Next()
	}
}

// API Handlers

// handleHealthCheck handles health check requests
func (api *adminAPIImpl) handleHealthCheck(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
	})
}

// handleGetConfig handles get configuration requests
func (api *adminAPIImpl) handleGetConfig(c *fiber.Ctx) error {
	if api.configManager == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Configuration manager not available",
		})
	}
	
	config := api.configManager.GetConfig()
	return c.JSON(config)
}

// handleUpdateConfig handles update configuration requests
func (api *adminAPIImpl) handleUpdateConfig(c *fiber.Ctx) error {
	if api.configManager == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Configuration manager not available",
		})
	}
	
	var config AuthSystemConfig
	if err := c.BodyParser(&config); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("Invalid request body: %v", err),
		})
	}
	
	if err := api.configManager.UpdateConfig(&config); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to update configuration: %v", err),
		})
	}
	
	return c.JSON(fiber.Map{
		"message": "Configuration updated successfully",
	})
}

// handleValidateConfig handles validate configuration requests
func (api *adminAPIImpl) handleValidateConfig(c *fiber.Ctx) error {
	if api.configManager == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Configuration manager not available",
		})
	}
	
	var config AuthSystemConfig
	if err := c.BodyParser(&config); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("Invalid request body: %v", err),
		})
	}
	
	if err := api.configManager.ValidateConfig(&config); err != nil {
		return c.JSON(fiber.Map{
			"valid": false,
			"error": err.Error(),
		})
	}
	
	return c.JSON(fiber.Map{
		"valid": true,
	})
}

// handleReloadConfig handles reload configuration requests
func (api *adminAPIImpl) handleReloadConfig(c *fiber.Ctx) error {
	if api.configManager == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Configuration manager not available",
		})
	}
	
	if err := api.configManager.ReloadConfig(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to reload configuration: %v", err),
		})
	}
	
	return c.JSON(fiber.Map{
		"message": "Configuration reloaded successfully",
	})
}

// handleGetConfigHistory handles get configuration history requests
func (api *adminAPIImpl) handleGetConfigHistory(c *fiber.Ctx) error {
	if api.configManager == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Configuration manager not available",
		})
	}
	
	history := api.configManager.GetConfigHistory()
	return c.JSON(history)
}

// handleGetConfigSchema handles get configuration schema requests
func (api *adminAPIImpl) handleGetConfigSchema(c *fiber.Ctx) error {
	schema := GetConfigSchema()
	return c.JSON(schema)
}

// handleGetSystemStatus handles get system status requests
func (api *adminAPIImpl) handleGetSystemStatus(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	status, err := api.statusMonitor.GetSystemStatus()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get system status: %v", err),
		})
	}
	
	return c.JSON(status)
}

// handleGetDetailedSystemReport handles get detailed system report requests
func (api *adminAPIImpl) handleGetDetailedSystemReport(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	report, err := api.statusMonitor.GetDetailedSystemReport()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get detailed system report: %v", err),
		})
	}
	
	return c.JSON(report)
}

// handleGetComponentStatuses handles get component statuses requests
func (api *adminAPIImpl) handleGetComponentStatuses(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	status, err := api.statusMonitor.GetSystemStatus()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get system status: %v", err),
		})
	}
	
	return c.JSON(status.Components)
}

// handleGetComponentStatus handles get component status requests
func (api *adminAPIImpl) handleGetComponentStatus(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	componentName := c.Params("name")
	if componentName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Component name required",
		})
	}
	
	status, err := api.statusMonitor.GetComponentStatus(componentName)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get component status: %v", err),
		})
	}
	
	return c.JSON(status)
}

// handleGetActiveAlerts handles get active alerts requests
func (api *adminAPIImpl) handleGetActiveAlerts(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	alerts, err := api.statusMonitor.GetActiveAlerts()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get active alerts: %v", err),
		})
	}
	
	return c.JSON(alerts)
}

// handleGetStatusHistory handles get status history requests
func (api *adminAPIImpl) handleGetStatusHistory(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	// Parse duration parameter
	durationStr := c.Query("duration", "1h")
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("Invalid duration: %v", err),
		})
	}
	
	history, err := api.statusMonitor.GetStatusHistory(duration)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get status history: %v", err),
		})
	}
	
	return c.JSON(history)
}

// handleGetSystemHealth handles get system health requests
func (api *adminAPIImpl) handleGetSystemHealth(c *fiber.Ctx) error {
	if api.healthChecker == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Health checker not available",
		})
	}
	
	health, err := api.healthChecker.GetSystemHealth()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get system health: %v", err),
		})
	}
	
	return c.JSON(health)
}

// handleGetComponentHealths handles get component healths requests
func (api *adminAPIImpl) handleGetComponentHealths(c *fiber.Ctx) error {
	if api.healthChecker == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Health checker not available",
		})
	}
	
	health, err := api.healthChecker.GetSystemHealth()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get system health: %v", err),
		})
	}
	
	return c.JSON(health.Components)
}

// handleGetComponentHealth handles get component health requests
func (api *adminAPIImpl) handleGetComponentHealth(c *fiber.Ctx) error {
	if api.healthChecker == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Health checker not available",
		})
	}
	
	componentName := c.Params("name")
	if componentName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Component name required",
		})
	}
	
	health, err := api.healthChecker.GetComponentHealth(componentName)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get component health: %v", err),
		})
	}
	
	return c.JSON(health)
}

// handleGetComponentHealthHistory handles get component health history requests
func (api *adminAPIImpl) handleGetComponentHealthHistory(c *fiber.Ctx) error {
	if api.healthChecker == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Health checker not available",
		})
	}
	
	componentName := c.Params("name")
	if componentName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Component name required",
		})
	}
	
	// Parse duration parameter
	durationStr := c.Query("duration", "1h")
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("Invalid duration: %v", err),
		})
	}
	
	history, err := api.healthChecker.GetHealthHistory(componentName, duration)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get health history: %v", err),
		})
	}
	
	return c.JSON(history)
}

// handleCheckComponentHealth handles check component health requests
func (api *adminAPIImpl) handleCheckComponentHealth(c *fiber.Ctx) error {
	if api.healthChecker == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Health checker not available",
		})
	}
	
	componentName := c.Params("name")
	if componentName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Component name required",
		})
	}
	
	health, err := api.healthChecker.CheckHealth(componentName)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to check component health: %v", err),
		})
	}
	
	return c.JSON(health)
}

// handleGetPerformanceDiagnostics handles get performance diagnostics requests
func (api *adminAPIImpl) handleGetPerformanceDiagnostics(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	report, err := api.statusMonitor.GetDetailedSystemReport()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get system report: %v", err),
		})
	}
	
	return c.JSON(report.PerformanceReport)
}

// handleGetSecurityDiagnostics handles get security diagnostics requests
func (api *adminAPIImpl) handleGetSecurityDiagnostics(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	report, err := api.statusMonitor.GetDetailedSystemReport()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get system report: %v", err),
		})
	}
	
	return c.JSON(report.SecurityReport)
}

// handleGetDependenciesDiagnostics handles get dependencies diagnostics requests
func (api *adminAPIImpl) handleGetDependenciesDiagnostics(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	report, err := api.statusMonitor.GetDetailedSystemReport()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get system report: %v", err),
		})
	}
	
	return c.JSON(report.Dependencies)
}

// handleGetComponentTrends handles get component trends requests
func (api *adminAPIImpl) handleGetComponentTrends(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	componentName := c.Params("component")
	if componentName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Component name required",
		})
	}
	
	// Parse duration parameter
	durationStr := c.Query("duration", "1h")
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("Invalid duration: %v", err),
		})
	}
	
	trends, err := api.statusMonitor.GetComponentTrends(componentName, duration)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to get component trends: %v", err),
		})
	}
	
	return c.JSON(trends)
}

// handleStartMonitoring handles start monitoring requests
func (api *adminAPIImpl) handleStartMonitoring(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	ctx := context.Background()
	if err := api.statusMonitor.StartMonitoring(ctx); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to start monitoring: %v", err),
		})
	}
	
	return c.JSON(fiber.Map{
		"message": "Monitoring started successfully",
	})
}

// handleStopMonitoring handles stop monitoring requests
func (api *adminAPIImpl) handleStopMonitoring(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	if err := api.statusMonitor.StopMonitoring(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to stop monitoring: %v", err),
		})
	}
	
	return c.JSON(fiber.Map{
		"message": "Monitoring stopped successfully",
	})
}

// handleGetMonitoringStatus handles get monitoring status requests
func (api *adminAPIImpl) handleGetMonitoringStatus(c *fiber.Ctx) error {
	if api.statusMonitor == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Status monitor not available",
		})
	}
	
	isMonitoring := api.statusMonitor.IsMonitoring()
	
	return c.JSON(fiber.Map{
		"monitoring": isMonitoring,
		"timestamp": time.Now(),
	})
}

// Helper methods

// errorHandler handles Fiber errors
func (api *adminAPIImpl) errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}
	
	return c.Status(code).JSON(fiber.Map{
		"error":     err.Error(),
		"timestamp": time.Now(),
	})
}

// validateToken validates an authentication token
func (api *adminAPIImpl) validateToken(token string) bool {
	// This would integrate with your authentication system
	// For now, we'll use a simple validation
	return token != "" && len(token) > 10
}

// getUserFromToken extracts user information from token
func (api *adminAPIImpl) getUserFromToken(token string) interface{} {
	// This would extract actual user information from the token
	// For now, return a mock user
	return map[string]interface{}{
		"id":    "admin",
		"roles": []string{"admin", "user"},
	}
}

// userHasRole checks if user has the required role
func (api *adminAPIImpl) userHasRole(user interface{}, requiredRole string) bool {
	userMap, ok := user.(map[string]interface{})
	if !ok {
		return false
	}
	
	roles, ok := userMap["roles"].([]string)
	if !ok {
		return false
	}
	
	for _, role := range roles {
		if role == requiredRole {
			return true
		}
	}
	
	return false
}