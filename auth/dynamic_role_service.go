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
	"time"
)

// RoleChangeEvent represents a role change that needs to be propagated
type RoleChangeEvent struct {
	Type      RoleChangeType
	UserID    string
	RoleID    string
	Timestamp time.Time
	Details   map[string]interface{}
}

// RoleChangeType defines the type of role change
type RoleChangeType int

const (
	RoleAssigned RoleChangeType = iota
	RoleRevoked
	RoleUpdated
	RoleDeleted
)

func (rct RoleChangeType) String() string {
	switch rct {
	case RoleAssigned:
		return "RoleAssigned"
	case RoleRevoked:
		return "RoleRevoked"
	case RoleUpdated:
		return "RoleUpdated"
	case RoleDeleted:
		return "RoleDeleted"
	default:
		return "Unknown"
	}
}

// RoleChangeListener defines the interface for components that need to be notified of role changes
type RoleChangeListener interface {
	OnRoleChange(event *RoleChangeEvent) error
}

// SessionManager defines the interface for session management operations
type SessionManager interface {
	InvalidateUserSessions(userID string) error
	RefreshUserPermissions(userID string) error
	GetActiveUserSessions(userID string) ([]string, error)
	NotifySessionUpdate(sessionID string, updateType string) error
}

// DynamicRoleService provides real-time role management with change propagation
type DynamicRoleService struct {
	roleManager     RoleManager
	sessionManager  SessionManager
	cache           EnhancedCache
	listeners       []RoleChangeListener
	eventQueue      chan *RoleChangeEvent
	mu              sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
	conflictResolver *RoleConflictResolver
}

// DynamicRoleServiceConfig holds configuration for the dynamic role service
type DynamicRoleServiceConfig struct {
	EventQueueSize   int
	ProcessorWorkers int
	PropagationTimeout time.Duration
}

// DefaultDynamicRoleServiceConfig returns a default configuration
func DefaultDynamicRoleServiceConfig() *DynamicRoleServiceConfig {
	return &DynamicRoleServiceConfig{
		EventQueueSize:     1000,
		ProcessorWorkers:   3,
		PropagationTimeout: 30 * time.Second,
	}
}

// NewDynamicRoleService creates a new dynamic role service
func NewDynamicRoleService(
	roleManager RoleManager,
	sessionManager SessionManager,
	cache EnhancedCache,
	config *DynamicRoleServiceConfig,
) *DynamicRoleService {
	if config == nil {
		config = DefaultDynamicRoleServiceConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	service := &DynamicRoleService{
		roleManager:      roleManager,
		sessionManager:   sessionManager,
		cache:            cache,
		listeners:        make([]RoleChangeListener, 0),
		eventQueue:       make(chan *RoleChangeEvent, config.EventQueueSize),
		ctx:              ctx,
		cancel:           cancel,
		conflictResolver: NewRoleConflictResolver(),
	}

	// Start event processors
	for i := 0; i < config.ProcessorWorkers; i++ {
		go service.eventProcessor()
	}

	return service
}

// AddListener adds a role change listener
func (s *DynamicRoleService) AddListener(listener RoleChangeListener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = append(s.listeners, listener)
}

// RemoveListener removes a role change listener
func (s *DynamicRoleService) RemoveListener(listener RoleChangeListener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	for i, l := range s.listeners {
		if l == listener {
			s.listeners = append(s.listeners[:i], s.listeners[i+1:]...)
			break
		}
	}
}

// AssignRoleWithPropagation assigns a role and propagates changes to active sessions
func (s *DynamicRoleService) AssignRoleWithPropagation(userID, roleID, assignedBy string) error {
	// First, assign the role using the underlying role manager
	if err := s.roleManager.AssignRole(userID, roleID, assignedBy); err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	// Create and queue the change event
	event := &RoleChangeEvent{
		Type:      RoleAssigned,
		UserID:    userID,
		RoleID:    roleID,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"assigned_by": assignedBy,
		},
	}

	return s.queueRoleChangeEvent(event)
}

// RevokeRoleWithPropagation revokes a role and propagates changes to active sessions
func (s *DynamicRoleService) RevokeRoleWithPropagation(userID, roleID string) error {
	// First, revoke the role using the underlying role manager
	if err := s.roleManager.RevokeRole(userID, roleID); err != nil {
		return fmt.Errorf("failed to revoke role: %w", err)
	}

	// Create and queue the change event
	event := &RoleChangeEvent{
		Type:      RoleRevoked,
		UserID:    userID,
		RoleID:    roleID,
		Timestamp: time.Now(),
	}

	return s.queueRoleChangeEvent(event)
}

// UpdateRoleWithPropagation updates a role and propagates changes to all affected users
func (s *DynamicRoleService) UpdateRoleWithPropagation(roleID string, updates *RoleUpdates) error {
	// Get all users with this role before updating
	affectedUsers, err := s.getUsersWithRole(roleID)
	if err != nil {
		return fmt.Errorf("failed to get users with role %s: %w", roleID, err)
	}

	// Update the role using the underlying role manager
	if err := s.roleManager.UpdateRole(roleID, updates); err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	// Create and queue change events for all affected users
	for _, userID := range affectedUsers {
		event := &RoleChangeEvent{
			Type:      RoleUpdated,
			UserID:    userID,
			RoleID:    roleID,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"updates": updates,
			},
		}

		if err := s.queueRoleChangeEvent(event); err != nil {
			// Log error but continue with other users
			fmt.Printf("Failed to queue role change event for user %s: %v\n", userID, err)
		}
	}

	return nil
}

// DeleteRoleWithPropagation deletes a role and handles all affected users
func (s *DynamicRoleService) DeleteRoleWithPropagation(roleID string) error {
	// Get all users with this role before deleting
	affectedUsers, err := s.getUsersWithRole(roleID)
	if err != nil {
		return fmt.Errorf("failed to get users with role %s: %w", roleID, err)
	}

	// Delete the role using the underlying role manager
	if err := s.roleManager.DeleteRole(roleID); err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	// Create and queue change events for all affected users
	for _, userID := range affectedUsers {
		event := &RoleChangeEvent{
			Type:      RoleDeleted,
			UserID:    userID,
			RoleID:    roleID,
			Timestamp: time.Now(),
		}

		if err := s.queueRoleChangeEvent(event); err != nil {
			// Log error but continue with other users
			fmt.Printf("Failed to queue role change event for user %s: %v\n", userID, err)
		}
	}

	return nil
}

// GetEffectivePermissionsWithConflictResolution computes effective permissions with conflict resolution
func (s *DynamicRoleService) GetEffectivePermissionsWithConflictResolution(userID string) (*PermissionSet, error) {
	// Get user roles
	roles, err := s.roleManager.GetUserRoles(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Resolve conflicts using the conflict resolver
	resolvedPermissions, err := s.conflictResolver.ResolvePermissionConflicts(roles)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve permission conflicts: %w", err)
	}

	return &PermissionSet{
		Permissions: resolvedPermissions,
		ComputedAt:  time.Now(),
	}, nil
}

// CheckPermissionWithConflictResolution checks permission with conflict resolution
func (s *DynamicRoleService) CheckPermissionWithConflictResolution(userID, resource, action string) (bool, error) {
	permissions, err := s.GetEffectivePermissionsWithConflictResolution(userID)
	if err != nil {
		return false, fmt.Errorf("failed to get effective permissions: %w", err)
	}

	return permissions.HasPermission(resource, action), nil
}

// queueRoleChangeEvent queues a role change event for processing
func (s *DynamicRoleService) queueRoleChangeEvent(event *RoleChangeEvent) error {
	select {
	case s.eventQueue <- event:
		return nil
	case <-s.ctx.Done():
		return fmt.Errorf("service is shutting down")
	default:
		return fmt.Errorf("event queue is full")
	}
}

// eventProcessor processes role change events
func (s *DynamicRoleService) eventProcessor() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case event := <-s.eventQueue:
			if err := s.processRoleChangeEvent(event); err != nil {
				fmt.Printf("Failed to process role change event: %v\n", err)
			}
		}
	}
}

// processRoleChangeEvent processes a single role change event
func (s *DynamicRoleService) processRoleChangeEvent(event *RoleChangeEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Invalidate cache entries for the affected user
	if err := s.invalidateUserCache(event.UserID); err != nil {
		fmt.Printf("Failed to invalidate cache for user %s: %v\n", event.UserID, err)
	}

	// Propagate to active sessions
	if err := s.propagateToSessions(event); err != nil {
		fmt.Printf("Failed to propagate to sessions for user %s: %v\n", event.UserID, err)
	}

	// Notify listeners
	s.mu.RLock()
	listeners := make([]RoleChangeListener, len(s.listeners))
	copy(listeners, s.listeners)
	s.mu.RUnlock()

	for _, listener := range listeners {
		if err := listener.OnRoleChange(event); err != nil {
			fmt.Printf("Listener failed to process role change event: %v\n", err)
		}
	}

	return nil
}

// invalidateUserCache invalidates all cache entries for a user
func (s *DynamicRoleService) invalidateUserCache(userID string) error {
	if s.cache == nil {
		return nil
	}

	// Invalidate user roles cache
	if err := s.cache.InvalidateUser(userID); err != nil {
		return fmt.Errorf("failed to invalidate user cache: %w", err)
	}

	// Invalidate permissions cache
	if err := s.cache.InvalidateType(Permissions); err != nil {
		return fmt.Errorf("failed to invalidate permissions cache: %w", err)
	}

	return nil
}

// propagateToSessions propagates role changes to active sessions
func (s *DynamicRoleService) propagateToSessions(event *RoleChangeEvent) error {
	if s.sessionManager == nil {
		return nil
	}

	// Get active sessions for the user
	sessionIDs, err := s.sessionManager.GetActiveUserSessions(event.UserID)
	if err != nil {
		return fmt.Errorf("failed to get active sessions: %w", err)
	}

	// Notify each session about the role change
	for _, sessionID := range sessionIDs {
		if err := s.sessionManager.NotifySessionUpdate(sessionID, "role_change"); err != nil {
			fmt.Printf("Failed to notify session %s: %v\n", sessionID, err)
		}
	}

	// Refresh user permissions in session manager
	if err := s.sessionManager.RefreshUserPermissions(event.UserID); err != nil {
		return fmt.Errorf("failed to refresh user permissions: %w", err)
	}

	return nil
}

// getUsersWithRole gets all users that have a specific role assigned
func (s *DynamicRoleService) getUsersWithRole(roleID string) ([]string, error) {
	return s.roleManager.GetUsersWithRole(roleID)
}

// Shutdown gracefully shuts down the dynamic role service
func (s *DynamicRoleService) Shutdown() error {
	s.cancel()
	
	// Drain the event queue
	close(s.eventQueue)
	for event := range s.eventQueue {
		if err := s.processRoleChangeEvent(event); err != nil {
			fmt.Printf("Failed to process queued event during shutdown: %v\n", err)
		}
	}
	
	return nil
}

// RoleConflictResolver handles permission conflicts using "deny by default" principle
type RoleConflictResolver struct{}

// NewRoleConflictResolver creates a new role conflict resolver
func NewRoleConflictResolver() *RoleConflictResolver {
	return &RoleConflictResolver{}
}

// ResolvePermissionConflicts resolves conflicts between permissions from multiple roles
func (r *RoleConflictResolver) ResolvePermissionConflicts(roles []*EnhancedRole) ([]DetailedPermission, error) {
	if len(roles) == 0 {
		return []DetailedPermission{}, nil
	}

	// Collect all permissions from all roles
	var allPermissions []DetailedPermission
	for _, role := range roles {
		allPermissions = append(allPermissions, role.Permissions...)
	}

	// Group permissions by resource:action combination
	permissionGroups := make(map[string][]DetailedPermission)
	for _, perm := range allPermissions {
		key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
		permissionGroups[key] = append(permissionGroups[key], perm)
	}

	// Resolve conflicts for each group
	var resolvedPermissions []DetailedPermission
	for _, group := range permissionGroups {
		resolved := r.resolvePermissionGroup(group)
		if resolved != nil {
			resolvedPermissions = append(resolvedPermissions, *resolved)
		}
	}

	return resolvedPermissions, nil
}

// resolvePermissionGroup resolves conflicts within a group of permissions for the same resource:action
func (r *RoleConflictResolver) resolvePermissionGroup(permissions []DetailedPermission) *DetailedPermission {
	if len(permissions) == 0 {
		return nil
	}

	if len(permissions) == 1 {
		return &permissions[0]
	}

	// Apply "deny by default" principle
	// If any permission in the group is DENY, the result is DENY
	for _, perm := range permissions {
		if perm.Effect == PermissionDeny {
			return &perm
		}
	}

	// If no DENY permissions, return the first ALLOW permission
	for _, perm := range permissions {
		if perm.Effect == PermissionAllow {
			return &perm
		}
	}

	// This should not happen, but return the first permission as fallback
	return &permissions[0]
}

// ValidateRoleConflicts validates that a set of roles doesn't have irresolvable conflicts
func (r *RoleConflictResolver) ValidateRoleConflicts(roles []*EnhancedRole) error {
	// For now, we consider all conflicts resolvable using "deny by default"
	// In the future, we might add more sophisticated conflict detection
	
	resolvedPermissions, err := r.ResolvePermissionConflicts(roles)
	if err != nil {
		return fmt.Errorf("failed to resolve conflicts: %w", err)
	}

	// Validate that the resolved permissions are consistent
	permissionMap := make(map[string]PermissionEffect)
	for _, perm := range resolvedPermissions {
		key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
		if existingEffect, exists := permissionMap[key]; exists {
			if existingEffect != perm.Effect {
				return fmt.Errorf("unresolvable conflict for %s", key)
			}
		}
		permissionMap[key] = perm.Effect
	}

	return nil
}

// InMemorySessionManager provides a simple in-memory implementation of SessionManager for testing
type InMemorySessionManager struct {
	mu       sync.RWMutex
	sessions map[string][]string // userID -> sessionIDs
	cache    EnhancedCache
}

// NewInMemorySessionManager creates a new in-memory session manager
func NewInMemorySessionManager(cache EnhancedCache) *InMemorySessionManager {
	return &InMemorySessionManager{
		sessions: make(map[string][]string),
		cache:    cache,
	}
}

// InvalidateUserSessions invalidates all sessions for a specific user
func (m *InMemorySessionManager) InvalidateUserSessions(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Remove all sessions for the user
	delete(m.sessions, userID)
	
	// Invalidate cache entries for the user if cache is available
	if m.cache != nil {
		return m.cache.InvalidateUser(userID)
	}
	
	return nil
}

// RefreshUserPermissions refreshes permissions for all user sessions
func (m *InMemorySessionManager) RefreshUserPermissions(userID string) error {
	m.mu.RLock()
	sessionIDs, exists := m.sessions[userID]
	m.mu.RUnlock()
	
	if !exists {
		return nil // No sessions to refresh
	}
	
	// Notify all sessions about permission refresh
	for _, sessionID := range sessionIDs {
		if err := m.NotifySessionUpdate(sessionID, "permission_refresh"); err != nil {
			return fmt.Errorf("failed to notify session %s: %w", sessionID, err)
		}
	}
	
	return nil
}

// GetActiveUserSessions returns active session IDs for a user
func (m *InMemorySessionManager) GetActiveUserSessions(userID string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	sessionIDs, exists := m.sessions[userID]
	if !exists {
		return []string{}, nil
	}
	
	// Return a copy to avoid race conditions
	result := make([]string, len(sessionIDs))
	copy(result, sessionIDs)
	
	return result, nil
}

// NotifySessionUpdate notifies about session updates
func (m *InMemorySessionManager) NotifySessionUpdate(sessionID string, updateType string) error {
	// In a real implementation, this would send notifications to the session
	// For testing purposes, we just log the notification
	fmt.Printf("Session %s notified of update: %s\n", sessionID, updateType)
	return nil
}

// AddSession adds a session for a user (helper method for testing)
func (m *InMemorySessionManager) AddSession(userID, sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if _, exists := m.sessions[userID]; !exists {
		m.sessions[userID] = []string{}
	}
	
	m.sessions[userID] = append(m.sessions[userID], sessionID)
}

// RemoveSession removes a session for a user (helper method for testing)
func (m *InMemorySessionManager) RemoveSession(userID, sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	sessionIDs, exists := m.sessions[userID]
	if !exists {
		return
	}
	
	// Remove the session ID
	for i, id := range sessionIDs {
		if id == sessionID {
			m.sessions[userID] = append(sessionIDs[:i], sessionIDs[i+1:]...)
			break
		}
	}
	
	// Remove the user entry if no sessions left
	if len(m.sessions[userID]) == 0 {
		delete(m.sessions, userID)
	}
}

// Session represents a user session (for testing)
type Session struct {
	ID       string                 `json:"id"`
	UserID   string                 `json:"user_id"`
	Metadata map[string]interface{} `json:"metadata"`
	Updates  []SessionUpdate        `json:"updates"`
}

// SessionUpdate represents a session update
type SessionUpdate struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Details   map[string]interface{} `json:"details"`
}

// CreateSession creates a new session for a user
func (m *InMemorySessionManager) CreateSession(userID string, metadata map[string]interface{}) (*Session, error) {
	sessionID := fmt.Sprintf("session-%s-%d", userID, time.Now().UnixNano())
	
	session := &Session{
		ID:       sessionID,
		UserID:   userID,
		Metadata: metadata,
		Updates:  []SessionUpdate{},
	}
	
	m.AddSession(userID, sessionID)
	
	return session, nil
}

// GetSession retrieves a session by ID
func (m *InMemorySessionManager) GetSession(sessionID string) (*Session, error) {
	// In a real implementation, this would retrieve the session from storage
	// For testing, we create a mock session
	return &Session{
		ID:      sessionID,
		UserID:  "mock-user",
		Updates: []SessionUpdate{},
	}, nil
}

// GetSessionUpdates retrieves pending updates for a session
func (m *InMemorySessionManager) GetSessionUpdates(sessionID string) ([]SessionUpdate, error) {
	// In a real implementation, this would retrieve actual updates
	// For testing, we return empty updates
	return []SessionUpdate{}, nil
}