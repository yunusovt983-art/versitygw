# IPFS Backend API Documentation

## Overview

The IPFS Backend provides seamless integration between VersityGW S3 API and IPFS-Cluster, enabling distributed storage of objects with automatic pinning and intelligent replication management.

## Core Components

### IPFSBackend

The main backend implementation that handles S3 operations through IPFS-Cluster.

```go
type IPFSBackend struct {
    backend.BackendUnsupported
    
    clusterClient  *cluster.Client
    pinManager     *PinManager
    metadataStore  MetadataStore
    cacheLayer     CacheLayer
    config         *IPFSConfig
}
```

#### Methods

##### PutObject
Stores an object in IPFS-Cluster and creates appropriate pins.

```go
func (b *IPFSBackend) PutObject(ctx context.Context, bucket, key string, data io.Reader, size int64, metadata map[string]string) error
```

**Parameters:**
- `ctx`: Request context
- `bucket`: S3 bucket name
- `key`: S3 object key
- `data`: Object data stream
- `size`: Object size in bytes
- `metadata`: Object metadata

**Returns:**
- `error`: Error if operation fails

**Behavior:**
1. Uploads data to IPFS and gets CID
2. Creates pin with specified replication factor
3. Stores S3Key → CID mapping in metadata store
4. Updates cache with object information

##### GetObject
Retrieves an object from IPFS using its S3 key.

```go
func (b *IPFSBackend) GetObject(ctx context.Context, bucket, key string, rangeSpec *RangeSpec) (io.ReadCloser, error)
```

**Parameters:**
- `ctx`: Request context
- `bucket`: S3 bucket name
- `key`: S3 object key
- `rangeSpec`: Optional byte range specification

**Returns:**
- `io.ReadCloser`: Object data stream
- `error`: Error if operation fails

**Behavior:**
1. Looks up CID from S3 key in metadata store
2. Retrieves object from IPFS using CID
3. Updates access statistics for intelligent replication
4. Returns data stream with proper range handling

##### DeleteObject
Removes an object from IPFS and unpins it.

```go
func (b *IPFSBackend) DeleteObject(ctx context.Context, bucket, key string) error
```

**Parameters:**
- `ctx`: Request context
- `bucket`: S3 bucket name
- `key`: S3 object key

**Returns:**
- `error`: Error if operation fails

**Behavior:**
1. Looks up CID from S3 key
2. Unpins object from IPFS-Cluster
3. Removes metadata mapping
4. Clears cache entries

### Pin Manager

Manages pin operations with high throughput and reliability.

```go
type PinManager struct {
    clusterAPI     cluster.API
    metadataStore  MetadataStore
    replicaManager *ReplicaManager
    pinQueue       chan PinRequest
    unpinQueue     chan UnpinRequest
}
```

#### Methods

##### PinObject
Asynchronously pins an object in IPFS-Cluster.

```go
func (pm *PinManager) PinObject(ctx context.Context, cid string, metadata PinMetadata) error
```

**Parameters:**
- `ctx`: Request context
- `cid`: IPFS Content Identifier
- `metadata`: Pin metadata including replication factor

**Returns:**
- `error`: Error if operation fails

##### UnpinObject
Asynchronously unpins an object from IPFS-Cluster.

```go
func (pm *PinManager) UnpinObject(ctx context.Context, cid string) error
```

**Parameters:**
- `ctx`: Request context
- `cid`: IPFS Content Identifier

**Returns:**
- `error`: Error if operation fails

##### GetPinStatus
Retrieves current pin status for an object.

```go
func (pm *PinManager) GetPinStatus(ctx context.Context, cid string) (*PinStatus, error)
```

**Parameters:**
- `ctx`: Request context
- `cid`: IPFS Content Identifier

**Returns:**
- `*PinStatus`: Current pin status information
- `error`: Error if operation fails

### Metadata Store

Handles S3Key → IPFS CID mappings and object metadata.

```go
type MetadataStore interface {
    StoreMapping(s3Key, bucket, cid string, metadata ObjectMetadata) error
    GetMapping(s3Key, bucket string) (*ObjectMapping, error)
    DeleteMapping(s3Key, bucket string) error
    StoreMappingBatch(mappings []ObjectMapping) error
    GetMappingBatch(keys []S3Key) ([]ObjectMapping, error)
}
```

#### Methods

##### StoreMapping
Stores S3Key to IPFS CID mapping with metadata.

```go
func StoreMapping(s3Key, bucket, cid string, metadata ObjectMetadata) error
```

##### GetMapping
Retrieves IPFS CID and metadata for S3 key.

```go
func GetMapping(s3Key, bucket string) (*ObjectMapping, error)
```

##### Batch Operations
Efficient batch operations for high-throughput scenarios.

```go
func StoreMappingBatch(mappings []ObjectMapping) error
func GetMappingBatch(keys []S3Key) ([]ObjectMapping, error)
```

## IPFS-Specific Headers

The IPFS backend adds custom headers to S3 responses:

### Response Headers

- `X-IPFS-CID`: The IPFS Content Identifier for the object
- `X-IPFS-Pin-Status`: Current pin status (pinned, pending, failed)
- `X-IPFS-Replication-Count`: Number of replicas in the cluster
- `X-IPFS-Access-Count`: Number of times object has been accessed
- `X-IPFS-Last-Access`: Timestamp of last access

### Request Headers

- `X-IPFS-Replication-Factor`: Desired replication factor (default: 3)
- `X-IPFS-Pin-Priority`: Pin priority (high, normal, low)
- `X-IPFS-Encryption`: Enable client-side encryption (true/false)

## Error Codes

### IPFS-Specific Error Codes

- `IPFSNodeUnavailable`: IPFS cluster node is unavailable
- `PinTimeout`: Pin operation timed out
- `InsufficientReplicas`: Cannot achieve desired replication factor
- `CIDNotFound`: IPFS CID not found in cluster
- `ClusterSplit`: IPFS cluster is in split-brain state

### Error Response Format

```json
{
  "error": {
    "code": "IPFSNodeUnavailable",
    "message": "IPFS cluster node is unavailable",
    "cid": "QmXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "s3_key": "bucket/object-key",
    "timestamp": "2024-01-01T12:00:00Z",
    "retry_after": 30
  }
}
```

## Performance Considerations

### Caching Strategy

The IPFS backend implements a three-tier caching system:

1. **L1 Cache (Memory)**: Hot data with sub-millisecond access
2. **L2 Cache (Redis)**: Warm data with millisecond access
3. **L3 Cache (Distributed)**: Cold data with network access

### Batch Operations

For high-throughput scenarios, use batch operations:

```go
// Batch pin operations
pinRequests := []PinRequest{
    {CID: "Qm...", ReplicationFactor: 3},
    {CID: "Qm...", ReplicationFactor: 5},
}
err := pinManager.PinBatch(ctx, pinRequests)
```

### Async Processing

Pin and unpin operations are processed asynchronously:

```go
// Non-blocking pin operation
err := backend.PutObject(ctx, bucket, key, data, size, metadata)
// Object is immediately available, pinning happens in background
```

## Monitoring and Metrics

### Available Metrics

- `ipfs_pin_operations_total`: Total pin operations
- `ipfs_pin_duration_seconds`: Pin operation duration
- `ipfs_cache_hit_ratio`: Cache hit ratio
- `ipfs_replication_factor`: Current replication factors
- `ipfs_cluster_nodes_available`: Available cluster nodes

### Health Checks

```go
// Check IPFS backend health
health := backend.HealthCheck(ctx)
if health.Status != "healthy" {
    log.Printf("IPFS backend unhealthy: %s", health.Message)
}
```

## Migration from Other Backends

### Data Migration

```go
// Migrate existing objects to IPFS
migrator := NewIPFSMigrator(sourceBackend, ipfsBackend)
err := migrator.MigrateObjects(ctx, migrationConfig)
```

### Compatibility Mode

The IPFS backend maintains compatibility with existing S3 clients:

```go
config := &IPFSConfig{
    CompatibilityMode: true,  // Enables S3 compatibility features
    LegacyHeaders:     true,  // Includes legacy S3 headers
}
```

## Security Features

### Encryption

```go
// Enable client-side encryption
metadata := map[string]string{
    "X-IPFS-Encryption": "AES256",
    "X-IPFS-Key-ID":     "key-12345",
}
```

### Access Control

```go
// IPFS-specific permissions
permissions := &IPFSPermissions{
    AllowPin:   true,
    AllowUnpin: false,
    MaxReplicas: 10,
}
```

This API documentation provides comprehensive coverage of all IPFS-specific functions and their usage patterns for developers integrating with the VersityGW IPFS backend.