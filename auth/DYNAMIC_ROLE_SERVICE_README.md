# Dynamic Role Service

The Dynamic Role Service provides real-time role management with automatic propagation of role changes to active sessions. It implements the "deny by default" principle for conflict resolution and supports event-driven architecture for role change notifications.

## Features

- **Real-time Role Updates**: Role changes are immediately propagated to active user sessions
- **Conflict Resolution**: Implements "deny by default" principle when roles have conflicting permissions
- **Event-driven Architecture**: Supports listeners for role change events
- **Session Integration**: Automatically updates session permissions when roles change
- **Cache Integration**: Invalidates relevant cache entries when roles are modified

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Dynamic Role    │    │ Role Manager     │    │ Session Manager │
│ Service         │───▶│ (CRUD ops)       │    │ (Session ops)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                                               │
         ▼                                               ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Event Queue     │    │ Conflict         │    │ Cache Layer     │
│ (Async proc.)   │    │ Resolver         │    │ (Invalidation)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐
│ Role Change     │
│ Listeners       │
└─────────────────┘
```

## Usage

### Basic Setup

```go
// Create components
roleManager := NewInMemoryRoleManager()
cache := NewEnhancedCache(DefaultEnhancedCacheConfig())
sessionManager := NewInMemorySessionManager(cache)

// Create dynamic role service
service := NewDynamicRoleService(
    roleManager, 
    sessionManager, 
    cache, 
    DefaultDynamicRoleServiceConfig(),
)
defer service.Shutdown()
```

### Role Assignment with Propagation

```go
// Assign role - automatically propagates to active sessions
err := service.AssignRoleWithPropagation("user123", "admin-role", "system-admin")
if err != nil {
    log.Printf("Failed to assign role: %v", err)
}
```

### Role Updates with Propagation

```go
// Update role - affects all users with this role
updates := &RoleUpdates{
    Description: &"Updated role description",
}

err := service.UpdateRoleWithPropagation("admin-role", updates)
if err != nil {
    log.Printf("Failed to update role: %v", err)
}
```

### Permission Checking with Conflict Resolution

```go
// Check permission with automatic conflict resolution
allowed, err := service.CheckPermissionWithConflictResolution(
    "user123", 
    "bucket/file.txt", 
    "s3:GetObject",
)
if err != nil {
    log.Printf("Failed to check permission: %v", err)
}

if allowed {
    // User has permission
} else {
    // Access denied
}
```

### Event Listeners

```go
// Implement a role change listener
type AuditListener struct{}

func (l *AuditListener) OnRoleChange(event *RoleChangeEvent) error {
    log.Printf("Role change: %s for user %s, role %s", 
        event.Type, event.UserID, event.RoleID)
    
    // Perform audit logging, notifications, etc.
    return nil
}

// Add listener to service
listener := &AuditListener{}
service.AddListener(listener)
```

## Conflict Resolution

The service implements a "deny by default" conflict resolution strategy:

1. **Explicit Deny Wins**: If any role denies access, the final result is deny
2. **Allow if No Deny**: If no role explicitly denies and at least one allows, the result is allow
3. **Default Deny**: If no explicit permissions exist, access is denied

### Example

```go
// Role 1: Allow s3:GetObject on bucket/*
// Role 2: Deny s3:GetObject on bucket/secret.txt

// Result for bucket/secret.txt: DENY (explicit deny wins)
// Result for bucket/public.txt: ALLOW (no conflict)
```

## Event Types

The service supports the following role change event types:

- `RoleAssigned`: A role was assigned to a user
- `RoleRevoked`: A role was revoked from a user  
- `RoleUpdated`: A role's definition was updated
- `RoleDeleted`: A role was deleted

## Session Integration

When roles change, the service automatically:

1. **Invalidates Cache**: Removes stale permission data from cache
2. **Updates Sessions**: Notifies active sessions about role changes
3. **Refreshes Permissions**: Updates permission hashes in sessions
4. **Queues Updates**: Adds pending updates to session metadata

### Checking Session Updates

```go
// Get pending updates for a session
updates, err := sessionManager.GetSessionUpdates(sessionID)
if err != nil {
    log.Printf("Failed to get session updates: %v", err)
}

for _, update := range updates {
    log.Printf("Update: %s at %s", update.Type, update.Timestamp)
}

// Clear updates after processing
err = sessionManager.ClearSessionUpdates(sessionID)
```

## Configuration

### Service Configuration

```go
config := &DynamicRoleServiceConfig{
    EventQueueSize:     1000,           // Max queued events
    ProcessorWorkers:   3,              // Event processor goroutines
    PropagationTimeout: 30 * time.Second, // Max time for propagation
}

service := NewDynamicRoleService(roleManager, sessionManager, cache, config)
```

### Cache Configuration

```go
cacheConfig := &EnhancedCacheConfig{
    MaxSize:         1000,
    CleanupInterval: 5 * time.Minute,
    DefaultTTLs: map[CacheEntryType]time.Duration{
        UserRoles:   30 * time.Minute,
        Permissions: 1 * time.Hour,
    },
}

cache := NewEnhancedCache(cacheConfig)
```

## Best Practices

### 1. Use Specific Permissions

```go
// Good: Specific resource and action
{
    Resource: "bucket/sensitive/*",
    Action:   "s3:GetObject",
    Effect:   PermissionDeny,
}

// Avoid: Overly broad permissions
{
    Resource: "*",
    Action:   "s3:*",
    Effect:   PermissionAllow,
}
```

### 2. Implement Proper Error Handling

```go
err := service.AssignRoleWithPropagation(userID, roleID, assignedBy)
if err != nil {
    // Log error and handle appropriately
    log.Printf("Role assignment failed: %v", err)
    return fmt.Errorf("failed to assign role: %w", err)
}
```

### 3. Monitor Event Processing

```go
// Implement monitoring listener
type MonitoringListener struct{}

func (l *MonitoringListener) OnRoleChange(event *RoleChangeEvent) error {
    // Update metrics, send to monitoring system
    metrics.IncrementCounter("role_changes", map[string]string{
        "type": event.Type.String(),
    })
    return nil
}
```

### 4. Handle Service Shutdown Gracefully

```go
// Ensure proper cleanup
defer func() {
    if err := service.Shutdown(); err != nil {
        log.Printf("Error shutting down service: %v", err)
    }
}()
```

## Testing

The service includes comprehensive tests covering:

- Role assignment and revocation with propagation
- Role updates affecting multiple users
- Conflict resolution scenarios
- Session integration
- Event listener functionality

Run tests with:

```bash
go test -v ./auth -run TestDynamicRoleService
```

## Performance Considerations

1. **Event Queue Size**: Configure based on expected role change frequency
2. **Worker Count**: Adjust processor workers based on system resources
3. **Cache TTL**: Balance between performance and data freshness
4. **Batch Operations**: Consider batching role changes when possible

## Security Considerations

1. **Audit Logging**: Always implement audit listeners for compliance
2. **Permission Validation**: Validate all role definitions before creation
3. **Session Security**: Ensure session updates are properly authenticated
4. **Conflict Resolution**: Understand that deny always wins in conflicts

## Integration with Existing Systems

The Dynamic Role Service integrates with:

- **Enhanced Cache**: For performance optimization
- **Session Manager**: For real-time session updates  
- **Role Manager**: For persistent role storage
- **Audit Systems**: Through event listeners
- **Monitoring**: Through custom listeners

## Troubleshooting

### Common Issues

1. **Events Not Processing**: Check event queue size and worker count
2. **Cache Not Invalidating**: Verify cache integration is properly configured
3. **Sessions Not Updating**: Ensure session manager is properly integrated
4. **Permission Conflicts**: Review role definitions and conflict resolution logic

### Debug Logging

Enable debug logging to troubleshoot issues:

```go
// Add debug listener
type DebugListener struct{}

func (l *DebugListener) OnRoleChange(event *RoleChangeEvent) error {
    log.Printf("DEBUG: Role change event: %+v", event)
    return nil
}

service.AddListener(&DebugListener{})
```