# IPFS Backend Configuration System

This document describes the configuration system implemented for the IPFS-Cluster integration in VersityGW (Task 15).

## Features

The configuration system provides the following capabilities:

1. **Configuration Structure with Validation** - Comprehensive validation of all configuration parameters
2. **Hot-Reload Support** - Configuration changes without service restart
3. **Environment Variables Support** - Override configuration via environment variables
4. **Configuration File Support** - JSON and YAML configuration files
5. **Configuration Management API** - HTTP API for dynamic configuration changes
6. **Startup Validation** - Configuration validation during application startup

## Configuration Structure

The IPFS backend configuration is defined in the `IPFSConfig` struct with the following sections:

### Cluster Connection Settings
- `cluster_endpoints`: List of IPFS-Cluster API endpoints
- `username`: Optional authentication username
- `password`: Optional authentication password
- `connect_timeout`: Connection timeout duration
- `request_timeout`: Request timeout duration
- `max_retries`: Maximum number of retry attempts
- `retry_delay`: Delay between retry attempts

### Performance Settings
- `max_concurrent_pins`: Maximum concurrent pin operations
- `pin_timeout`: Timeout for pin operations
- `chunk_size`: Size of data chunks for large files
- `compression_enabled`: Enable/disable compression

### Replication Settings
- `replication_min`: Minimum number of replicas
- `replication_max`: Maximum number of replicas

### Metadata Database Settings
- `metadata_db_type`: Type of metadata database (memory, ydb, scylla, postgres, mysql)
- `metadata_db_endpoints`: List of metadata database endpoints

### Cache Settings
- `cache_enabled`: Enable/disable caching
- `cache_endpoints`: List of cache endpoints (Redis)

### Monitoring Settings
- `metrics_enabled`: Enable/disable metrics collection
- `log_level`: Logging level (debug, info, warn, error, fatal)

### Replica Manager Settings
- `replica_manager_enabled`: Enable/disable intelligent replication
- `analysis_interval`: Interval for access pattern analysis
- `rebalancing_interval`: Interval for replica rebalancing
- `geographic_optimization`: Enable geographic optimization
- `load_balancing_enabled`: Enable load balancing
- `hot_data_threshold`: Threshold for hot data classification
- `warm_data_threshold`: Threshold for warm data classification
- `cold_data_threshold`: Threshold for cold data classification

## Configuration Files

### JSON Configuration Example

```json
{
  "cluster_endpoints": [
    "http://ipfs-cluster-node1:9094",
    "http://ipfs-cluster-node2:9094"
  ],
  "connect_timeout": "30s",
  "request_timeout": "60s",
  "max_concurrent_pins": 100,
  "pin_timeout": "300s",
  "replication_min": 1,
  "replication_max": 3,
  "metadata_db_type": "ydb",
  "cache_enabled": true,
  "metrics_enabled": true,
  "replica_manager_enabled": true
}
```

### YAML Configuration Example

```yaml
cluster_endpoints:
  - "http://ipfs-cluster-node1:9094"
  - "http://ipfs-cluster-node2:9094"

connect_timeout: "30s"
request_timeout: "60s"
max_concurrent_pins: 100
pin_timeout: "300s"

replication_min: 1
replication_max: 3

metadata_db_type: "ydb"
cache_enabled: true
metrics_enabled: true
replica_manager_enabled: true
```

## Environment Variables

All configuration parameters can be overridden using environment variables with the `IPFS_` prefix:

- `IPFS_CLUSTER_ENDPOINTS`: Comma-separated list of cluster endpoints
- `IPFS_CLUSTER_USERNAME`: Authentication username
- `IPFS_CLUSTER_PASSWORD`: Authentication password
- `IPFS_CONNECT_TIMEOUT`: Connection timeout (e.g., "30s")
- `IPFS_REQUEST_TIMEOUT`: Request timeout (e.g., "60s")
- `IPFS_PIN_TIMEOUT`: Pin operation timeout (e.g., "300s")
- `IPFS_MAX_RETRIES`: Maximum retry attempts (integer)
- `IPFS_MAX_CONCURRENT_PINS`: Maximum concurrent pins (integer)
- `IPFS_CHUNK_SIZE`: Chunk size in bytes (integer)
- `IPFS_REPLICATION_MIN`: Minimum replicas (integer)
- `IPFS_REPLICATION_MAX`: Maximum replicas (integer)
- `IPFS_COMPRESSION_ENABLED`: Enable compression (true/false)
- `IPFS_CACHE_ENABLED`: Enable caching (true/false)
- `IPFS_METRICS_ENABLED`: Enable metrics (true/false)
- `IPFS_METADATA_DB_TYPE`: Metadata database type
- `IPFS_METADATA_DB_ENDPOINTS`: Comma-separated database endpoints
- `IPFS_CACHE_ENDPOINTS`: Comma-separated cache endpoints
- `IPFS_LOG_LEVEL`: Log level (debug, info, warn, error, fatal)
- `IPFS_REPLICA_MANAGER_ENABLED`: Enable replica manager (true/false)

## Hot-Reload Configuration

The configuration system supports hot-reload for most configuration parameters. When a configuration file is modified, the system automatically:

1. Detects the file change using filesystem watchers
2. Reloads and validates the new configuration
3. Applies changes to running components
4. Triggers registered callbacks for configuration changes

### Hot-Reload Supported Parameters

- Cluster endpoints (with automatic reconnection)
- Connection timeouts
- Pin management settings
- Replication settings
- Replica manager settings
- Logging levels

### Parameters Requiring Restart

Some configuration changes require a service restart:
- Metadata database type and endpoints
- Cache system configuration (major changes)
- Metrics system configuration

## Configuration Management API

The system provides an HTTP API for dynamic configuration management:

### API Endpoints

- `GET /api/v1/config` - Get current configuration
- `PUT /api/v1/config` - Update entire configuration
- `POST /api/v1/config/validate` - Validate configuration
- `POST /api/v1/config/reload` - Reload configuration from file
- `POST /api/v1/config/save` - Save current configuration to file
- `GET /api/v1/health` - Health check

### Specific Configuration Sections

- `GET/PUT /api/v1/config/cluster-endpoints` - Cluster endpoints
- `GET/PUT /api/v1/config/replication` - Replication settings
- `GET/PUT /api/v1/config/timeouts` - Timeout settings
- `GET/PUT /api/v1/config/performance` - Performance settings
- `GET/PUT /api/v1/config/cache` - Cache settings
- `GET/PUT /api/v1/config/metadata` - Metadata database settings
- `GET/PUT /api/v1/config/replica-manager` - Replica manager settings

### API Configuration

The API server can be configured using environment variables:
- `IPFS_CONFIG_API_ENABLED`: Enable/disable API (true/false)
- `IPFS_CONFIG_API_PORT`: API server port (default: 8081)

## Usage Examples

### Creating a Configuration Manager

```go
opts := ConfigManagerOptions{
    ConfigPath:      "/etc/versitygw/ipfs-config.json",
    ConfigFormat:    ConfigFormatJSON,
    EnableHotReload: true,
    EnableAPI:       true,
    APIPort:         8081,
    Logger:          logger,
}

configManager, err := NewConfigManager(opts)
if err != nil {
    return err
}

err = configManager.Start()
if err != nil {
    return err
}
defer configManager.Stop()
```

### Registering Configuration Change Callbacks

```go
configManager.RegisterCallback(func(oldConfig, newConfig *IPFSConfig) error {
    log.Printf("Configuration changed: max_concurrent_pins %d -> %d",
        oldConfig.MaxConcurrentPins, newConfig.MaxConcurrentPins)
    
    // Apply configuration changes to your components
    return applyConfigChanges(oldConfig, newConfig)
})
```

### Using with IPFS Backend

```go
// The IPFS backend automatically integrates with the configuration system
backend, err := ipfs.New(initialConfig, ipfs.IPFSOptions{
    Logger:  logger,
    Context: ctx,
})
if err != nil {
    return err
}

// Access configuration manager
configManager := backend.GetConfigManager()

// Update configuration dynamically
newConfig := backend.GetCurrentConfig()
newConfig.MaxConcurrentPins = 200
err = backend.UpdateConfiguration(newConfig)
```

## Configuration Validation

The system performs comprehensive validation of all configuration parameters:

### Validation Rules

1. **Required Fields**: Cluster endpoints must be specified
2. **Positive Values**: Timeouts, retry counts, and sizes must be positive
3. **Range Validation**: Replication min/max must be valid ranges
4. **Enum Validation**: Database types and log levels must be valid values
5. **Dependency Validation**: Related settings must be consistent

### Validation Response

```go
type ConfigValidationResult struct {
    Valid  bool
    Errors []ConfigValidationError
}

type ConfigValidationError struct {
    Field   string
    Value   interface{}
    Message string
}
```

## Integration with VersityGW

The configuration system is fully integrated with the IPFS backend:

1. **Initialization**: Configuration manager is created during backend initialization
2. **Hot-Reload**: Configuration changes are automatically applied to running components
3. **API Integration**: Configuration API is available alongside the main VersityGW API
4. **Monitoring**: Configuration changes are logged and can be monitored

## Best Practices

1. **Use Environment Variables**: For deployment-specific settings
2. **Enable Hot-Reload**: For production environments requiring zero-downtime updates
3. **Monitor Configuration Changes**: Log and alert on configuration modifications
4. **Validate Before Apply**: Always validate configuration before applying changes
5. **Backup Configuration**: Save configuration files before making changes
6. **Use API for Automation**: Integrate configuration management into deployment pipelines

## Troubleshooting

### Common Issues

1. **File Permission Errors**: Ensure the service has read/write access to configuration files
2. **Invalid JSON/YAML**: Use validation tools to check configuration file syntax
3. **Port Conflicts**: Ensure the configuration API port is not in use
4. **Environment Variable Precedence**: Remember that environment variables override file settings

### Debugging

Enable debug logging to troubleshoot configuration issues:
```bash
export IPFS_LOG_LEVEL=debug
```

Check configuration validation:
```bash
curl http://localhost:8081/api/v1/config/validate -X POST -d @config.json
```

## Security Considerations

1. **API Access**: Secure the configuration API with authentication/authorization
2. **File Permissions**: Restrict access to configuration files
3. **Sensitive Data**: Avoid storing passwords in configuration files
4. **Network Security**: Use TLS for configuration API in production
5. **Audit Logging**: Log all configuration changes for security auditing

This configuration system provides a robust, flexible, and production-ready solution for managing IPFS backend configuration in VersityGW.