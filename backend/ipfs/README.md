# IPFS Backend for VersityGW

This package provides an IPFS-Cluster backend implementation for VersityGW, enabling S3-compatible access to IPFS storage with support for trillion-scale pin management.

## Overview

The IPFS backend integrates VersityGW with IPFS-Cluster to provide:

- S3 API compatibility for IPFS storage
- Scalable pin management for trillion-scale deployments
- Intelligent replication and caching
- High availability and fault tolerance
- Comprehensive monitoring and analytics

## Current Implementation Status

This is the basic infrastructure implementation (Task 1) that provides:

- ✅ Basic IPFSBackend structure inheriting from backend.BackendUnsupported
- ✅ IPFSConfig structure with cluster connection parameters
- ✅ Initialization and shutdown methods
- ✅ Basic logging and error handling
- ✅ Comprehensive test coverage

## Configuration

### Basic Configuration

```go
config := &ipfs.IPFSConfig{
    ClusterEndpoints: []string{
        "http://localhost:9094",
        "http://localhost:9095",
    },
    ConnectTimeout:     30 * time.Second,
    RequestTimeout:     60 * time.Second,
    MaxRetries:         3,
    MaxConcurrentPins:  100,
    PinTimeout:         5 * time.Minute,
    ReplicationMin:     1,
    ReplicationMax:     3,
    MetadataDBType:     "memory",
    LogLevel:          "info",
}
```

### Advanced Configuration

```go
config := &ipfs.IPFSConfig{
    // Cluster settings
    ClusterEndpoints: []string{
        "https://cluster1.example.com:9094",
        "https://cluster2.example.com:9094",
        "https://cluster3.example.com:9094",
    },
    Username: "cluster-user",
    Password: "cluster-password",
    
    // Connection settings
    ConnectTimeout:  10 * time.Second,
    RequestTimeout:  30 * time.Second,
    MaxRetries:      5,
    RetryDelay:      2 * time.Second,
    
    // Performance settings
    MaxConcurrentPins: 1000,
    PinTimeout:        10 * time.Minute,
    ChunkSize:         2 * 1024 * 1024, // 2MB
    
    // Replication settings
    ReplicationMin: 2,
    ReplicationMax: 5,
    
    // Storage settings
    CompressionEnabled: true,
    
    // Metadata database
    MetadataDBType: "scylladb",
    MetadataDBEndpoints: []string{
        "scylla1.example.com:9042",
        "scylla2.example.com:9042",
        "scylla3.example.com:9042",
    },
    
    // Cache settings
    CacheEnabled: true,
    CacheEndpoints: []string{
        "redis1.example.com:6379",
        "redis2.example.com:6379",
        "redis3.example.com:6379",
    },
    
    // Monitoring
    MetricsEnabled: true,
    LogLevel:      "debug",
}
```

## Usage

### Creating a Backend Instance

```go
package main

import (
    "context"
    "log"
    "time"
    
    "github.com/versity/versitygw/backend/ipfs"
)

func main() {
    // Create configuration
    config := &ipfs.IPFSConfig{
        ClusterEndpoints: []string{"http://localhost:9094"},
        LogLevel:        "info",
    }
    
    // Create backend with options
    opts := ipfs.IPFSOptions{
        Logger:  log.Default(),
        Context: context.Background(),
    }
    
    backend, err := ipfs.New(config, opts)
    if err != nil {
        log.Fatalf("Failed to create IPFS backend: %v", err)
    }
    defer backend.Shutdown()
    
    // Check backend health
    if !backend.IsHealthy() {
        log.Println("Backend is not healthy")
        return
    }
    
    // Get backend statistics
    stats := backend.GetStats()
    log.Printf("Backend stats: %+v", stats)
    
    // Backend is ready to use with VersityGW
    log.Println("IPFS backend initialized successfully")
}
```

### Error Handling

```go
// Check if an error is an IPFS-specific error
if ipfs.IsIPFSError(err) {
    ipfsErr, _ := ipfs.GetIPFSError(err)
    log.Printf("IPFS Error: %s (Code: %s, Retryable: %t)", 
        ipfsErr.Message, ipfsErr.Code.String(), ipfsErr.IsRetryable())
}

// Create custom IPFS errors
err := ipfs.NewIPFSErrorWithContext(
    ipfs.ErrPinTimeout,
    "Pin operation timed out",
    "QmExampleCID123",
    "my-bucket",
    "path/to/object.txt",
    originalError,
)
```

### Logging

```go
// Create logger from config
logger := ipfs.NewLoggerFromConfig(config)

// Set custom log level
logger.SetLevel(ipfs.LogLevelDebug)

// Log operations
logger.LogOperation("PutObject", "QmCID123", "bucket", "key", 150, nil)

// Log IPFS errors
ipfsErr := ipfs.NewIPFSError(ipfs.ErrPinTimeout, "timeout occurred")
logger.LogError(ipfsErr)
```

## Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ClusterEndpoints` | `[]string` | Required | IPFS-Cluster API endpoints |
| `Username` | `string` | "" | Authentication username |
| `Password` | `string` | "" | Authentication password |
| `ConnectTimeout` | `time.Duration` | 30s | Connection timeout |
| `RequestTimeout` | `time.Duration` | 60s | Request timeout |
| `MaxRetries` | `int` | 3 | Maximum retry attempts |
| `RetryDelay` | `time.Duration` | 1s | Delay between retries |
| `MaxConcurrentPins` | `int` | 100 | Maximum concurrent pin operations |
| `PinTimeout` | `time.Duration` | 5m | Pin operation timeout |
| `ChunkSize` | `int64` | 1MB | Chunk size for large objects |
| `ReplicationMin` | `int` | 1 | Minimum replication factor |
| `ReplicationMax` | `int` | 3 | Maximum replication factor |
| `CompressionEnabled` | `bool` | false | Enable compression |
| `MetadataDBType` | `string` | "memory" | Metadata database type |
| `MetadataDBEndpoints` | `[]string` | [] | Metadata database endpoints |
| `CacheEnabled` | `bool` | false | Enable caching |
| `CacheEndpoints` | `[]string` | [] | Cache endpoints |
| `MetricsEnabled` | `bool` | false | Enable metrics collection |
| `LogLevel` | `string` | "info" | Logging level |

## Error Codes

The backend defines comprehensive error codes for different failure scenarios:

- **Connection Errors**: `ErrIPFSNodeUnavailable`, `ErrClusterUnavailable`, `ErrConnectionTimeout`
- **Pin Errors**: `ErrPinTimeout`, `ErrPinFailed`, `ErrInsufficientReplicas`
- **Data Errors**: `ErrCIDNotFound`, `ErrDataCorruption`, `ErrChecksumMismatch`
- **Metadata Errors**: `ErrMetadataCorruption`, `ErrMetadataNotFound`
- **Cluster Errors**: `ErrClusterSplit`, `ErrNodeSyncFailed`
- **Resource Errors**: `ErrStorageQuotaExceeded`, `ErrTooManyRequests`

## Future Implementation

This basic infrastructure will be extended with additional components:

- **Task 2**: IPFS-Cluster client implementation
- **Task 3**: Metadata storage system
- **Task 4**: Pin management service
- **Task 5**: Multi-level caching system
- **Tasks 6-20**: Full S3 API implementation and advanced features

## Testing

Run the test suite:

```bash
go test -v ./backend/ipfs/
```

Run with coverage:

```bash
go test -v -cover ./backend/ipfs/
```

## Requirements Satisfied

This implementation satisfies the following requirements from the specification:

- **Requirement 1.1**: Basic IPFS backend structure with S3 API compatibility foundation
- **Requirement 1.2**: Configuration system for cluster connection parameters
- **Requirement 1.3**: Initialization and shutdown lifecycle management

## Architecture

The IPFS backend follows a modular architecture:

```
IPFSBackend
├── Configuration (IPFSConfig)
├── Error Handling (IPFSError)
├── Logging (Logger)
├── Health Monitoring (IsHealthy, GetStats)
└── Lifecycle Management (initialize, Shutdown)
```

Future components will be added as separate modules that integrate with this foundation.