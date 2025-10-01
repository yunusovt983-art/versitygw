# Enhanced Cache System

This document describes the enhanced caching system implemented for the Versity S3 Gateway authentication module. The enhanced cache provides significant improvements over the basic cache implementation with advanced features for production environments.

## Features

### 1. LRU Eviction Policy
- Implements Least Recently Used (LRU) eviction when cache reaches maximum capacity
- Automatically removes least recently accessed entries to make room for new ones
- Configurable maximum cache size

### 2. Configurable TTL per Entry Type
- Different cache entry types can have different Time-To-Live (TTL) values
- Supported entry types:
  - `UserCredentials`: User authentication data
  - `UserRoles`: User role assignments
  - `Permissions`: User permissions
  - `MFASettings`: Multi-factor authentication settings
  - `SessionData`: Session information

### 3. Advanced Cache Invalidation
- **Pattern-based invalidation**: Remove entries matching regex patterns
- **User-based invalidation**: Remove all entries for a specific user
- **Type-based invalidation**: Remove all entries of a specific type
- **Selective invalidation**: Target specific cache entries

### 4. Fallback Mechanism
- Separate fallback cache with longer TTL for emergency situations
- Automatic fallback when IAM service is unavailable
- Graceful degradation with stale data when primary service fails
- Health monitoring and automatic recovery

### 5. Comprehensive Statistics
- Hit/miss ratios and counts
- Cache size and eviction statistics
- Fallback mode status
- Performance metrics

### 6. Thread Safety
- All operations are thread-safe using read-write mutexes
- Concurrent access support for high-performance scenarios
- Lock-free read operations where possible

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   S3 Gateway    │───▶│ Enhanced IAM     │───▶│ Base IAM        │
│                 │    │ Cache            │    │ Service         │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │ Enhanced Cache   │
                       │ - Primary Cache  │
                       │ - Fallback Cache │
                       └──────────────────┘
```

## Usage

### Basic Enhanced Cache

```go
// Create configuration
config := &EnhancedCacheConfig{
    MaxSize:         1000,
    CleanupInterval: 5 * time.Minute,
    DefaultTTLs: map[CacheEntryType]time.Duration{
        UserCredentials: 15 * time.Minute,
        UserRoles:       30 * time.Minute,
        Permissions:     1 * time.Hour,
        MFASettings:     2 * time.Hour,
        SessionData:     10 * time.Minute,
    },
}

// Create cache
cache := NewEnhancedCache(config)
defer cache.Shutdown()

// Store data
cache.Set("user:alice", userData, 0, UserCredentials)

// Retrieve data
if data, found := cache.Get("user:alice", UserCredentials); found {
    // Use data
}

// Invalidate user data
cache.InvalidateUser("alice")
```

### Enhanced IAM Cache

```go
// Create configuration
config := &EnhancedIAMCacheConfig{
    CacheConfig: &EnhancedCacheConfig{
        MaxSize:         500,
        CleanupInterval: 5 * time.Minute,
        DefaultTTLs: map[CacheEntryType]time.Duration{
            UserCredentials: 15 * time.Minute,
        },
    },
    FallbackEnabled: true,
}

// Create enhanced IAM cache
iamCache := NewEnhancedIAMCache(baseIAMService, config)
defer iamCache.Shutdown()

// Use like regular IAM service
account, err := iamCache.GetUserAccount("username")
if err != nil {
    // Handle error
}

// Check cache statistics
stats := iamCache.GetCacheStats()
fmt.Printf("Hit rate: %.2f%%\n", stats.HitRate())
```

## Configuration Options

### EnhancedCacheConfig

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `MaxSize` | `int` | Maximum number of entries in cache | 1000 |
| `CleanupInterval` | `time.Duration` | How often to clean expired entries | 5 minutes |
| `DefaultTTLs` | `map[CacheEntryType]time.Duration` | TTL for each entry type | See defaults |

### Default TTL Values

| Entry Type | Default TTL |
|------------|-------------|
| `UserCredentials` | 15 minutes |
| `UserRoles` | 30 minutes |
| `Permissions` | 1 hour |
| `MFASettings` | 2 hours |
| `SessionData` | 10 minutes |

### EnhancedIAMCacheConfig

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `CacheConfig` | `*EnhancedCacheConfig` | Primary cache configuration | Default config |
| `FallbackCacheConfig` | `*EnhancedCacheConfig` | Fallback cache configuration | Default config with 4x TTL |
| `FallbackEnabled` | `bool` | Enable fallback cache | true |

## Cache Invalidation Patterns

### User-based Invalidation
```go
// Remove all entries for user "alice"
cache.InvalidateUser("alice")
```

### Pattern-based Invalidation
```go
// Remove all session entries
cache.Invalidate("^session:")

// Remove all entries for a specific user
cache.Invalidate("^user:alice:")
```

### Type-based Invalidation
```go
// Remove all user credentials
cache.InvalidateType(UserCredentials)

// Remove all MFA settings
cache.InvalidateType(MFASettings)
```

## Monitoring and Statistics

### Cache Statistics

```go
stats := cache.GetStats()

fmt.Printf("Hits: %d\n", stats.Hits)
fmt.Printf("Misses: %d\n", stats.Misses)
fmt.Printf("Hit Rate: %.2f%%\n", stats.HitRate())
fmt.Printf("Evictions: %d\n", stats.Evictions)
fmt.Printf("Current Size: %d\n", stats.Size)
fmt.Printf("Max Size: %d\n", stats.MaxSize)
fmt.Printf("Fallback Active: %t\n", stats.FallbackActive)
fmt.Printf("Last Cleanup: %v\n", stats.LastCleanup)
```

### Health Monitoring

```go
// Check if IAM service is healthy
if iamCache.IsHealthy() {
    fmt.Println("Service is healthy")
} else {
    fmt.Println("Service is unhealthy - using fallback")
}
```

## Integration with Existing System

The enhanced cache system is designed to be a drop-in replacement for the existing cache implementation:

```go
func New(o *Opts) (IAMService, error) {
    // ... create base service ...
    
    if o.CacheDisable {
        return svc, nil
    }

    // Use enhanced cache instead of basic cache
    if o.UseEnhancedCache { // New config option
        config := &EnhancedIAMCacheConfig{
            CacheConfig: &EnhancedCacheConfig{
                MaxSize:         1000,
                CleanupInterval: time.Duration(o.CachePrune) * time.Second,
                DefaultTTLs: map[CacheEntryType]time.Duration{
                    UserCredentials: time.Duration(o.CacheTTL) * time.Second,
                },
            },
            FallbackEnabled: true,
        }
        return NewEnhancedIAMCache(svc, config), nil
    }

    // Fall back to existing implementation
    return NewCache(svc,
        time.Duration(o.CacheTTL)*time.Second,
        time.Duration(o.CachePrune)*time.Second), nil
}
```

## Performance Considerations

### Memory Usage
- LRU eviction prevents unbounded memory growth
- Configurable maximum cache size
- Automatic cleanup of expired entries

### Concurrency
- Read-write mutexes for optimal concurrent performance
- Lock-free operations where possible
- Thread-safe for high-concurrency scenarios

### Network Resilience
- Fallback cache provides service continuity during outages
- Configurable fallback TTL (typically 4x primary TTL)
- Automatic recovery when service becomes available

## Testing

The enhanced cache system includes comprehensive tests:

```bash
# Run all enhanced cache tests
go test -v ./auth -run "Enhanced"

# Run specific test categories
go test -v ./auth -run "TestEnhancedCache"
go test -v ./auth -run "TestEnhancedIAMCache"
```

## Migration from Basic Cache

1. **Backward Compatibility**: The enhanced cache implements the same `IAMService` interface
2. **Configuration**: Add enhanced cache configuration options
3. **Gradual Migration**: Can be enabled/disabled via configuration
4. **Monitoring**: Use statistics to verify improved performance

## Best Practices

1. **TTL Configuration**: Set appropriate TTLs based on data sensitivity and change frequency
2. **Cache Size**: Size cache based on expected user count and memory constraints
3. **Monitoring**: Regularly monitor hit rates and adjust configuration as needed
4. **Invalidation**: Use specific invalidation patterns to minimize cache churn
5. **Fallback**: Enable fallback cache for production environments

## Troubleshooting

### Low Hit Rate
- Check if TTLs are too short
- Verify cache size is adequate
- Monitor eviction rate

### High Memory Usage
- Reduce maximum cache size
- Decrease TTL values
- Increase cleanup frequency

### Service Unavailability
- Check fallback cache statistics
- Verify fallback mode is enabled
- Monitor service health checks