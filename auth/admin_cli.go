package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// AdminCLI provides command-line interface for authentication system administration
type AdminCLI interface {
	// Command execution
	ExecuteCommand(args []string) error
	
	// Help and usage
	PrintUsage()
	PrintCommandHelp(command string)
	
	// Configuration management
	ConfigCommands() []CLICommand
	
	// System management
	SystemCommands() []CLICommand
	
	// Diagnostic commands
	DiagnosticCommands() []CLICommand
}

// CLICommand represents a CLI command
type CLICommand struct {
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Usage       string                    `json:"usage"`
	Examples    []string                  `json:"examples"`
	Handler     func(args []string) error `json:"-"`
}

// AdminCLIConfig holds configuration for the admin CLI
type AdminCLIConfig struct {
	ConfigPath       string `json:"config_path"`
	OutputFormat     string `json:"output_format"` // json, yaml, table
	Verbose          bool   `json:"verbose"`
	TimeoutDuration  time.Duration `json:"timeout_duration"`
}

// adminCLIImpl implements AdminCLI
type adminCLIImpl struct {
	config           *AdminCLIConfig
	configManager    ConfigManager
	statusMonitor    SystemStatusMonitor
	healthChecker    HealthChecker
	commands         map[string]*CLICommand
}

// NewAdminCLI creates a new admin CLI instance
func NewAdminCLI(config *AdminCLIConfig, configManager ConfigManager, statusMonitor SystemStatusMonitor, healthChecker HealthChecker) AdminCLI {
	if config == nil {
		config = &AdminCLIConfig{
			OutputFormat:    "table",
			Verbose:         false,
			TimeoutDuration: 30 * time.Second,
		}
	}
	
	cli := &adminCLIImpl{
		config:        config,
		configManager: configManager,
		statusMonitor: statusMonitor,
		healthChecker: healthChecker,
		commands:      make(map[string]*CLICommand),
	}
	
	cli.registerCommands()
	return cli
}

// ExecuteCommand executes a CLI command
func (cli *adminCLIImpl) ExecuteCommand(args []string) error {
	if len(args) == 0 {
		cli.PrintUsage()
		return nil
	}
	
	commandName := args[0]
	commandArgs := args[1:]
	
	// Handle help command
	if commandName == "help" {
		if len(commandArgs) > 0 {
			cli.PrintCommandHelp(commandArgs[0])
		} else {
			cli.PrintUsage()
		}
		return nil
	}
	
	// Find and execute command
	command, exists := cli.commands[commandName]
	if !exists {
		return fmt.Errorf("unknown command: %s", commandName)
	}
	
	if command.Handler == nil {
		return fmt.Errorf("command handler not implemented: %s", commandName)
	}
	
	return command.Handler(commandArgs)
}

// PrintUsage prints general usage information
func (cli *adminCLIImpl) PrintUsage() {
	fmt.Println("Authentication System Admin CLI")
	fmt.Println()
	fmt.Println("Usage: auth-admin <command> [options]")
	fmt.Println()
	fmt.Println("Available commands:")
	
	// Group commands by category
	configCommands := cli.ConfigCommands()
	systemCommands := cli.SystemCommands()
	diagnosticCommands := cli.DiagnosticCommands()
	
	if len(configCommands) > 0 {
		fmt.Println("\nConfiguration Management:")
		for _, cmd := range configCommands {
			fmt.Printf("  %-20s %s\n", cmd.Name, cmd.Description)
		}
	}
	
	if len(systemCommands) > 0 {
		fmt.Println("\nSystem Management:")
		for _, cmd := range systemCommands {
			fmt.Printf("  %-20s %s\n", cmd.Name, cmd.Description)
		}
	}
	
	if len(diagnosticCommands) > 0 {
		fmt.Println("\nDiagnostics:")
		for _, cmd := range diagnosticCommands {
			fmt.Printf("  %-20s %s\n", cmd.Name, cmd.Description)
		}
	}
	
	fmt.Println("\nUse 'auth-admin help <command>' for more information about a command.")
}

// PrintCommandHelp prints help for a specific command
func (cli *adminCLIImpl) PrintCommandHelp(commandName string) {
	command, exists := cli.commands[commandName]
	if !exists {
		fmt.Printf("Unknown command: %s\n", commandName)
		return
	}
	
	fmt.Printf("Command: %s\n", command.Name)
	fmt.Printf("Description: %s\n", command.Description)
	fmt.Printf("Usage: %s\n", command.Usage)
	
	if len(command.Examples) > 0 {
		fmt.Println("\nExamples:")
		for _, example := range command.Examples {
			fmt.Printf("  %s\n", example)
		}
	}
}

// ConfigCommands returns configuration management commands
func (cli *adminCLIImpl) ConfigCommands() []CLICommand {
	var commands []CLICommand
	
	for _, cmd := range cli.commands {
		if strings.HasPrefix(cmd.Name, "config-") {
			commands = append(commands, *cmd)
		}
	}
	
	return commands
}

// SystemCommands returns system management commands
func (cli *adminCLIImpl) SystemCommands() []CLICommand {
	var commands []CLICommand
	
	for _, cmd := range cli.commands {
		if strings.HasPrefix(cmd.Name, "system-") {
			commands = append(commands, *cmd)
		}
	}
	
	return commands
}

// DiagnosticCommands returns diagnostic commands
func (cli *adminCLIImpl) DiagnosticCommands() []CLICommand {
	var commands []CLICommand
	
	for _, cmd := range cli.commands {
		if strings.HasPrefix(cmd.Name, "diag-") || cmd.Name == "status" || cmd.Name == "health" {
			commands = append(commands, *cmd)
		}
	}
	
	return commands
}

// registerCommands registers all available CLI commands
func (cli *adminCLIImpl) registerCommands() {
	// Configuration commands
	cli.commands["config-show"] = &CLICommand{
		Name:        "config-show",
		Description: "Show current configuration",
		Usage:       "auth-admin config-show [--format json|yaml|table]",
		Examples: []string{
			"auth-admin config-show",
			"auth-admin config-show --format json",
		},
		Handler: cli.handleConfigShow,
	}
	
	cli.commands["config-validate"] = &CLICommand{
		Name:        "config-validate",
		Description: "Validate configuration",
		Usage:       "auth-admin config-validate [config-file]",
		Examples: []string{
			"auth-admin config-validate",
			"auth-admin config-validate /path/to/config.json",
		},
		Handler: cli.handleConfigValidate,
	}
	
	cli.commands["config-reload"] = &CLICommand{
		Name:        "config-reload",
		Description: "Reload configuration from file",
		Usage:       "auth-admin config-reload",
		Examples: []string{
			"auth-admin config-reload",
		},
		Handler: cli.handleConfigReload,
	}
	
	cli.commands["config-history"] = &CLICommand{
		Name:        "config-history",
		Description: "Show configuration change history",
		Usage:       "auth-admin config-history [--limit N]",
		Examples: []string{
			"auth-admin config-history",
			"auth-admin config-history --limit 10",
		},
		Handler: cli.handleConfigHistory,
	}
	
	// System commands
	cli.commands["system-status"] = &CLICommand{
		Name:        "system-status",
		Description: "Show system status",
		Usage:       "auth-admin system-status [--detailed]",
		Examples: []string{
			"auth-admin system-status",
			"auth-admin system-status --detailed",
		},
		Handler: cli.handleSystemStatus,
	}
	
	cli.commands["system-report"] = &CLICommand{
		Name:        "system-report",
		Description: "Generate comprehensive system report",
		Usage:       "auth-admin system-report [--output file]",
		Examples: []string{
			"auth-admin system-report",
			"auth-admin system-report --output report.json",
		},
		Handler: cli.handleSystemReport,
	}
	
	cli.commands["system-alerts"] = &CLICommand{
		Name:        "system-alerts",
		Description: "Show active system alerts",
		Usage:       "auth-admin system-alerts [--severity level]",
		Examples: []string{
			"auth-admin system-alerts",
			"auth-admin system-alerts --severity critical",
		},
		Handler: cli.handleSystemAlerts,
	}
	
	// Health commands
	cli.commands["health"] = &CLICommand{
		Name:        "health",
		Description: "Check system health",
		Usage:       "auth-admin health [component]",
		Examples: []string{
			"auth-admin health",
			"auth-admin health cache",
		},
		Handler: cli.handleHealth,
	}
	
	cli.commands["health-history"] = &CLICommand{
		Name:        "health-history",
		Description: "Show health check history",
		Usage:       "auth-admin health-history <component> [--duration 1h]",
		Examples: []string{
			"auth-admin health-history cache",
			"auth-admin health-history session --duration 24h",
		},
		Handler: cli.handleHealthHistory,
	}
	
	// Diagnostic commands
	cli.commands["diag-performance"] = &CLICommand{
		Name:        "diag-performance",
		Description: "Run performance diagnostics",
		Usage:       "auth-admin diag-performance",
		Examples: []string{
			"auth-admin diag-performance",
		},
		Handler: cli.handleDiagPerformance,
	}
	
	cli.commands["diag-security"] = &CLICommand{
		Name:        "diag-security",
		Description: "Run security diagnostics",
		Usage:       "auth-admin diag-security",
		Examples: []string{
			"auth-admin diag-security",
		},
		Handler: cli.handleDiagSecurity,
	}
	
	cli.commands["diag-dependencies"] = &CLICommand{
		Name:        "diag-dependencies",
		Description: "Check system dependencies",
		Usage:       "auth-admin diag-dependencies",
		Examples: []string{
			"auth-admin diag-dependencies",
		},
		Handler: cli.handleDiagDependencies,
	}
}

// Command handlers

// handleConfigShow shows current configuration
func (cli *adminCLIImpl) handleConfigShow(args []string) error {
	if cli.configManager == nil {
		return fmt.Errorf("configuration manager not available")
	}
	
	config := cli.configManager.GetConfig()
	return cli.outputData(config, "Configuration")
}

// handleConfigValidate validates configuration
func (cli *adminCLIImpl) handleConfigValidate(args []string) error {
	var configPath string
	
	if len(args) > 0 {
		configPath = args[0]
	} else if cli.config.ConfigPath != "" {
		configPath = cli.config.ConfigPath
	} else {
		return fmt.Errorf("no configuration file specified")
	}
	
	// Validate configuration file
	errors, err := ValidateConfigFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to validate configuration: %w", err)
	}
	
	if len(errors) == 0 {
		fmt.Println("Configuration is valid")
		return nil
	}
	
	fmt.Printf("Configuration validation failed with %d error(s):\n", len(errors))
	for i, validationError := range errors {
		fmt.Printf("%d. Field '%s': %s\n", i+1, validationError.Field, validationError.Message)
	}
	
	return fmt.Errorf("configuration validation failed")
}

// handleConfigReload reloads configuration
func (cli *adminCLIImpl) handleConfigReload(args []string) error {
	if cli.configManager == nil {
		return fmt.Errorf("configuration manager not available")
	}
	
	err := cli.configManager.ReloadConfig()
	if err != nil {
		return fmt.Errorf("failed to reload configuration: %w", err)
	}
	
	fmt.Println("Configuration reloaded successfully")
	return nil
}

// handleConfigHistory shows configuration change history
func (cli *adminCLIImpl) handleConfigHistory(args []string) error {
	if cli.configManager == nil {
		return fmt.Errorf("configuration manager not available")
	}
	
	limit := 20 // default limit
	
	// Parse arguments
	for i, arg := range args {
		if arg == "--limit" && i+1 < len(args) {
			var err error
			limit, err = strconv.Atoi(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid limit value: %s", args[i+1])
			}
		}
	}
	
	history := cli.configManager.GetConfigHistory()
	
	if len(history) == 0 {
		fmt.Println("No configuration history available")
		return nil
	}
	
	// Limit results
	if len(history) > limit {
		history = history[len(history)-limit:]
	}
	
	return cli.outputData(history, "Configuration History")
}

// handleSystemStatus shows system status
func (cli *adminCLIImpl) handleSystemStatus(args []string) error {
	if cli.statusMonitor == nil {
		return fmt.Errorf("status monitor not available")
	}
	
	detailed := false
	for _, arg := range args {
		if arg == "--detailed" {
			detailed = true
			break
		}
	}
	
	if detailed {
		report, err := cli.statusMonitor.GetDetailedSystemReport()
		if err != nil {
			return fmt.Errorf("failed to get detailed system report: %w", err)
		}
		return cli.outputData(report, "Detailed System Report")
	} else {
		status, err := cli.statusMonitor.GetSystemStatus()
		if err != nil {
			return fmt.Errorf("failed to get system status: %w", err)
		}
		return cli.outputData(status, "System Status")
	}
}

// handleSystemReport generates comprehensive system report
func (cli *adminCLIImpl) handleSystemReport(args []string) error {
	if cli.statusMonitor == nil {
		return fmt.Errorf("status monitor not available")
	}
	
	var outputFile string
	for i, arg := range args {
		if arg == "--output" && i+1 < len(args) {
			outputFile = args[i+1]
			break
		}
	}
	
	report, err := cli.statusMonitor.GetDetailedSystemReport()
	if err != nil {
		return fmt.Errorf("failed to generate system report: %w", err)
	}
	
	if outputFile != "" {
		// Write to file
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal report: %w", err)
		}
		
		err = os.WriteFile(outputFile, data, 0644)
		if err != nil {
			return fmt.Errorf("failed to write report to file: %w", err)
		}
		
		fmt.Printf("System report written to %s\n", outputFile)
		return nil
	}
	
	return cli.outputData(report, "System Report")
}

// handleSystemAlerts shows active system alerts
func (cli *adminCLIImpl) handleSystemAlerts(args []string) error {
	if cli.statusMonitor == nil {
		return fmt.Errorf("status monitor not available")
	}
	
	var severityFilter string
	for i, arg := range args {
		if arg == "--severity" && i+1 < len(args) {
			severityFilter = args[i+1]
			break
		}
	}
	
	alerts, err := cli.statusMonitor.GetActiveAlerts()
	if err != nil {
		return fmt.Errorf("failed to get active alerts: %w", err)
	}
	
	// Filter by severity if specified
	if severityFilter != "" {
		var filteredAlerts []*SystemAlert
		for _, alert := range alerts {
			if strings.ToLower(alert.Severity.String()) == strings.ToLower(severityFilter) {
				filteredAlerts = append(filteredAlerts, alert)
			}
		}
		alerts = filteredAlerts
	}
	
	if len(alerts) == 0 {
		fmt.Println("No active alerts")
		return nil
	}
	
	return cli.outputData(alerts, "Active Alerts")
}

// handleHealth checks system health
func (cli *adminCLIImpl) handleHealth(args []string) error {
	if cli.healthChecker == nil {
		return fmt.Errorf("health checker not available")
	}
	
	if len(args) > 0 {
		// Check specific component
		componentName := args[0]
		health, err := cli.healthChecker.CheckHealth(componentName)
		if err != nil {
			return fmt.Errorf("failed to check component health: %w", err)
		}
		return cli.outputData(health, fmt.Sprintf("Component Health: %s", componentName))
	} else {
		// Check all components
		health, err := cli.healthChecker.CheckAllHealth()
		if err != nil {
			return fmt.Errorf("failed to check system health: %w", err)
		}
		return cli.outputData(health, "System Health")
	}
}

// handleHealthHistory shows health check history
func (cli *adminCLIImpl) handleHealthHistory(args []string) error {
	if cli.healthChecker == nil {
		return fmt.Errorf("health checker not available")
	}
	
	if len(args) == 0 {
		return fmt.Errorf("component name required")
	}
	
	componentName := args[0]
	duration := 1 * time.Hour // default
	
	// Parse duration argument
	for i, arg := range args {
		if arg == "--duration" && i+1 < len(args) {
			var err error
			duration, err = time.ParseDuration(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid duration: %s", args[i+1])
			}
		}
	}
	
	history, err := cli.healthChecker.GetHealthHistory(componentName, duration)
	if err != nil {
		return fmt.Errorf("failed to get health history: %w", err)
	}
	
	if len(history) == 0 {
		fmt.Printf("No health history available for component: %s\n", componentName)
		return nil
	}
	
	return cli.outputData(history, fmt.Sprintf("Health History: %s", componentName))
}

// handleDiagPerformance runs performance diagnostics
func (cli *adminCLIImpl) handleDiagPerformance(args []string) error {
	if cli.statusMonitor == nil {
		return fmt.Errorf("status monitor not available")
	}
	
	report, err := cli.statusMonitor.GetDetailedSystemReport()
	if err != nil {
		return fmt.Errorf("failed to get system report: %w", err)
	}
	
	if report.PerformanceReport == nil {
		return fmt.Errorf("performance report not available")
	}
	
	return cli.outputData(report.PerformanceReport, "Performance Diagnostics")
}

// handleDiagSecurity runs security diagnostics
func (cli *adminCLIImpl) handleDiagSecurity(args []string) error {
	if cli.statusMonitor == nil {
		return fmt.Errorf("status monitor not available")
	}
	
	report, err := cli.statusMonitor.GetDetailedSystemReport()
	if err != nil {
		return fmt.Errorf("failed to get system report: %w", err)
	}
	
	if report.SecurityReport == nil {
		return fmt.Errorf("security report not available")
	}
	
	return cli.outputData(report.SecurityReport, "Security Diagnostics")
}

// handleDiagDependencies checks system dependencies
func (cli *adminCLIImpl) handleDiagDependencies(args []string) error {
	if cli.statusMonitor == nil {
		return fmt.Errorf("status monitor not available")
	}
	
	report, err := cli.statusMonitor.GetDetailedSystemReport()
	if err != nil {
		return fmt.Errorf("failed to get system report: %w", err)
	}
	
	if report.Dependencies == nil {
		return fmt.Errorf("dependencies report not available")
	}
	
	return cli.outputData(report.Dependencies, "Dependencies Diagnostics")
}

// outputData outputs data in the specified format
func (cli *adminCLIImpl) outputData(data interface{}, title string) error {
	switch cli.config.OutputFormat {
	case "json":
		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	case "table":
		// For table format, we'd need a more sophisticated table formatter
		// For now, fall back to JSON with a title
		fmt.Printf("=== %s ===\n", title)
		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	default:
		return fmt.Errorf("unsupported output format: %s", cli.config.OutputFormat)
	}
	
	return nil
}

// CLIMain is the main entry point for the CLI application
func CLIMain(args []string) {
	// Parse global flags
	config := &AdminCLIConfig{
		OutputFormat:    "table",
		Verbose:         false,
		TimeoutDuration: 30 * time.Second,
	}
	
	var filteredArgs []string
	for i, arg := range args {
		switch arg {
		case "--format":
			if i+1 < len(args) {
				config.OutputFormat = args[i+1]
				i++ // skip next arg
			}
		case "--verbose", "-v":
			config.Verbose = true
		case "--config":
			if i+1 < len(args) {
				config.ConfigPath = args[i+1]
				i++ // skip next arg
			}
		case "--timeout":
			if i+1 < len(args) {
				if duration, err := time.ParseDuration(args[i+1]); err == nil {
					config.TimeoutDuration = duration
				}
				i++ // skip next arg
			}
		default:
			filteredArgs = append(filteredArgs, arg)
		}
	}
	
	// Initialize components
	var configManager ConfigManager
	var statusMonitor SystemStatusMonitor
	var healthChecker HealthChecker
	
	if config.ConfigPath != "" {
		configManager = NewConfigManager(nil)
		if err := configManager.LoadConfig(config.ConfigPath); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
			os.Exit(1)
		}
		
		statusMonitor = NewSystemStatusMonitor(nil, configManager)
		healthChecker = NewHealthChecker(nil)
	}
	
	// Create CLI and execute command
	cli := NewAdminCLI(config, configManager, statusMonitor, healthChecker)
	
	if err := cli.ExecuteCommand(filteredArgs); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}