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
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// DistributedSessionStore provides distributed session storage capabilities
type DistributedSessionStore interface {
	// Session operations
	StoreSession(session *UserSession) error
	GetSession(sessionID string) (*UserSession, error)
	UpdateSession(session *UserSession) error
	DeleteSession(sessionID string) error
	
	// User session operations
	GetUserSessions(userID string) ([]*UserSession, error)
	DeleteUserSessions(userID string) error
	
	// Cluster operations
	SyncSession(session *UserSession) error
	InvalidateSession(sessionID string) error
	BroadcastSessionUpdate(sessionID string, updateType SessionUpdateType) error
	
	// Health and maintenance
	Cleanup() error
	GetStats() *DistributedStoreStats
	Close() error
}

// SessionUpdateType defines types of session updates for cluster synchronization
type SessionUpdateType int

const (
	SessionCreated SessionUpdateType = iota
	SessionUpdated
	SessionDeleted
	SessionExpired
	UserSessionsDeleted
)

// String returns string representation of SessionUpdateType
func (s SessionUpdateType) String() string {
	switch s {
	case SessionCreated:
		return "created"
	case SessionUpdated:
		return "updated"
	case SessionDeleted:
		return "deleted"
	case SessionExpired:
		return "expired"
	case UserSessionsDeleted:
		return "user_sessions_deleted"
	default:
		return "unknown"
	}
}

// DistributedStoreStats provides statistics about distributed store operations
type DistributedStoreStats struct {
	TotalSessions      int           `json:"total_sessions"`
	LocalSessions      int           `json:"local_sessions"`
	RemoteSessions     int           `json:"remote_sessions"`
	SyncOperations     int64         `json:"sync_operations"`
	SyncErrors         int64         `json:"sync_errors"`
	LastSync           time.Time     `json:"last_sync"`
	ClusterNodes       int           `json:"cluster_nodes"`
	NetworkLatency     time.Duration `json:"network_latency"`
}

// DistributedStoreConfig holds configuration for distributed session store
type DistributedStoreConfig struct {
	NodeID              string        `json:"node_id"`
	ClusterNodes        []string      `json:"cluster_nodes"`
	SyncInterval        time.Duration `json:"sync_interval"`
	ReplicationFactor   int           `json:"replication_factor"`
	ConsistencyLevel    string        `json:"consistency_level"` // "eventual", "strong"
	NetworkTimeout      time.Duration `json:"network_timeout"`
	RetryAttempts       int           `json:"retry_attempts"`
	EnableCompression   bool          `json:"enable_compression"`
	EncryptionEnabled   bool          `json:"encryption_enabled"`
}

// DefaultDistributedStoreConfig returns default configuration
func DefaultDistributedStoreConfig() *DistributedStoreConfig {
	return &DistributedStoreConfig{
		NodeID:            generateNodeID(),
		SyncInterval:      30 * time.Second,
		ReplicationFactor: 2,
		ConsistencyLevel:  "eventual",
		NetworkTimeout:    5 * time.Second,
		RetryAttempts:     3,
		EnableCompression: true,
		EncryptionEnabled: true,
	}
}

// distributedSessionStoreImpl implements DistributedSessionStore
type distributedSessionStoreImpl struct {
	config      *DistributedStoreConfig
	localStore  map[string]*UserSession
	nodeStores  map[string]map[string]*UserSession // nodeID -> sessions
	mu          sync.RWMutex
	stats       *DistributedStoreStats
	
	// Cluster communication
	clusterManager *ClusterManager
	syncChan       chan *SessionSyncMessage
	
	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// SessionSyncMessage represents a session synchronization message
type SessionSyncMessage struct {
	NodeID      string            `json:"node_id"`
	SessionID   string            `json:"session_id"`
	Session     *UserSession      `json:"session,omitempty"`
	UpdateType  SessionUpdateType `json:"update_type"`
	Timestamp   time.Time         `json:"timestamp"`
	UserID      string            `json:"user_id,omitempty"`
}

// NewDistributedSessionStore creates a new distributed session store
func NewDistributedSessionStore(config *DistributedStoreConfig, clusterManager *ClusterManager) DistributedSessionStore {
	if config == nil {
		config = DefaultDistributedStoreConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	store := &distributedSessionStoreImpl{
		config:     config,
		localStore: make(map[string]*UserSession),
		nodeStores: make(map[string]map[string]*UserSession),
		stats: &DistributedStoreStats{
			ClusterNodes: len(config.ClusterNodes),
		},
		clusterManager: clusterManager,
		syncChan:       make(chan *SessionSyncMessage, 1000),
		ctx:            ctx,
		cancel:         cancel,
	}
	
	// Initialize node stores
	for _, nodeID := range config.ClusterNodes {
		store.nodeStores[nodeID] = make(map[string]*UserSession)
	}
	
	// Start background sync processes
	go store.syncLoop()
	go store.processSyncMessages()
	
	return store
}

// StoreSession stores a session locally and replicates to cluster
func (d *distributedSessionStoreImpl) StoreSession(session *UserSession) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	
	d.mu.Lock()
	defer d.mu.Unlock()
	
	// Store locally
	d.localStore[session.ID] = session
	d.stats.LocalSessions = len(d.localStore)
	d.stats.TotalSessions = d.calculateTotalSessions()
	
	// Replicate to cluster
	syncMsg := &SessionSyncMessage{
		NodeID:     d.config.NodeID,
		SessionID:  session.ID,
		Session:    session,
		UpdateType: SessionCreated,
		Timestamp:  time.Now(),
		UserID:     session.UserID,
	}
	
	select {
	case d.syncChan <- syncMsg:
	default:
		// Channel full, log warning but don't block
		d.stats.SyncErrors++
	}
	
	return nil
}

// GetSession retrieves a session from local or remote stores
func (d *distributedSessionStoreImpl) GetSession(sessionID string) (*UserSession, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}
	
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	// Check local store first
	if session, exists := d.localStore[sessionID]; exists {
		return session, nil
	}
	
	// Check remote stores
	for nodeID, nodeStore := range d.nodeStores {
		if nodeID == d.config.NodeID {
			continue // Skip own node
		}
		
		if session, exists := nodeStore[sessionID]; exists {
			return session, nil
		}
	}
	
	return nil, fmt.Errorf("session not found: %s", sessionID)
}

// UpdateSession updates a session and syncs to cluster
func (d *distributedSessionStoreImpl) UpdateSession(session *UserSession) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	
	d.mu.Lock()
	defer d.mu.Unlock()
	
	// Update locally if exists
	if _, exists := d.localStore[session.ID]; exists {
		d.localStore[session.ID] = session
		
		// Sync update to cluster
		syncMsg := &SessionSyncMessage{
			NodeID:     d.config.NodeID,
			SessionID:  session.ID,
			Session:    session,
			UpdateType: SessionUpdated,
			Timestamp:  time.Now(),
			UserID:     session.UserID,
		}
		
		select {
		case d.syncChan <- syncMsg:
		default:
			d.stats.SyncErrors++
		}
		
		return nil
	}
	
	return fmt.Errorf("session not found locally: %s", session.ID)
}

// DeleteSession removes a session from local and remote stores
func (d *distributedSessionStoreImpl) DeleteSession(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}
	
	d.mu.Lock()
	defer d.mu.Unlock()
	
	var userID string
	
	// Delete from local store
	if session, exists := d.localStore[sessionID]; exists {
		userID = session.UserID
		delete(d.localStore, sessionID)
		d.stats.LocalSessions = len(d.localStore)
	}
	
	// Delete from remote stores
	for _, nodeStore := range d.nodeStores {
		if session, exists := nodeStore[sessionID]; exists {
			if userID == "" {
				userID = session.UserID
			}
			delete(nodeStore, sessionID)
		}
	}
	
	d.stats.TotalSessions = d.calculateTotalSessions()
	
	// Sync deletion to cluster
	syncMsg := &SessionSyncMessage{
		NodeID:     d.config.NodeID,
		SessionID:  sessionID,
		UpdateType: SessionDeleted,
		Timestamp:  time.Now(),
		UserID:     userID,
	}
	
	select {
	case d.syncChan <- syncMsg:
	default:
		d.stats.SyncErrors++
	}
	
	return nil
}

// GetUserSessions retrieves all sessions for a user from all stores
func (d *distributedSessionStoreImpl) GetUserSessions(userID string) ([]*UserSession, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}
	
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	var sessions []*UserSession
	sessionIDs := make(map[string]bool) // Deduplicate sessions
	
	// Check local store
	for _, session := range d.localStore {
		if session.UserID == userID {
			sessions = append(sessions, session)
			sessionIDs[session.ID] = true
		}
	}
	
	// Check remote stores
	for _, nodeStore := range d.nodeStores {
		for _, session := range nodeStore {
			if session.UserID == userID && !sessionIDs[session.ID] {
				sessions = append(sessions, session)
				sessionIDs[session.ID] = true
			}
		}
	}
	
	return sessions, nil
}

// DeleteUserSessions removes all sessions for a user
func (d *distributedSessionStoreImpl) DeleteUserSessions(userID string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}
	
	d.mu.Lock()
	defer d.mu.Unlock()
	
	var deletedSessions []string
	
	// Delete from local store
	for sessionID, session := range d.localStore {
		if session.UserID == userID {
			delete(d.localStore, sessionID)
			deletedSessions = append(deletedSessions, sessionID)
		}
	}
	
	// Delete from remote stores
	for _, nodeStore := range d.nodeStores {
		for sessionID, session := range nodeStore {
			if session.UserID == userID {
				delete(nodeStore, sessionID)
			}
		}
	}
	
	d.stats.LocalSessions = len(d.localStore)
	d.stats.TotalSessions = d.calculateTotalSessions()
	
	// Sync user session deletion to cluster
	syncMsg := &SessionSyncMessage{
		NodeID:     d.config.NodeID,
		UpdateType: UserSessionsDeleted,
		Timestamp:  time.Now(),
		UserID:     userID,
	}
	
	select {
	case d.syncChan <- syncMsg:
	default:
		d.stats.SyncErrors++
	}
	
	return nil
}

// SyncSession synchronizes a session across the cluster
func (d *distributedSessionStoreImpl) SyncSession(session *UserSession) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	
	syncMsg := &SessionSyncMessage{
		NodeID:     d.config.NodeID,
		SessionID:  session.ID,
		Session:    session,
		UpdateType: SessionUpdated,
		Timestamp:  time.Now(),
		UserID:     session.UserID,
	}
	
	return d.broadcastSyncMessage(syncMsg)
}

// InvalidateSession invalidates a session across the cluster
func (d *distributedSessionStoreImpl) InvalidateSession(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}
	
	syncMsg := &SessionSyncMessage{
		NodeID:     d.config.NodeID,
		SessionID:  sessionID,
		UpdateType: SessionExpired,
		Timestamp:  time.Now(),
	}
	
	return d.broadcastSyncMessage(syncMsg)
}

// BroadcastSessionUpdate broadcasts a session update to the cluster
func (d *distributedSessionStoreImpl) BroadcastSessionUpdate(sessionID string, updateType SessionUpdateType) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}
	
	syncMsg := &SessionSyncMessage{
		NodeID:     d.config.NodeID,
		SessionID:  sessionID,
		UpdateType: updateType,
		Timestamp:  time.Now(),
	}
	
	return d.broadcastSyncMessage(syncMsg)
}

// Cleanup removes expired sessions and performs maintenance
func (d *distributedSessionStoreImpl) Cleanup() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	now := time.Now()
	var expiredSessions []string
	
	// Clean local store
	for sessionID, session := range d.localStore {
		if now.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
			delete(d.localStore, sessionID)
		}
	}
	
	// Clean remote stores
	for _, nodeStore := range d.nodeStores {
		for sessionID, session := range nodeStore {
			if now.After(session.ExpiresAt) {
				delete(nodeStore, sessionID)
			}
		}
	}
	
	d.stats.LocalSessions = len(d.localStore)
	d.stats.TotalSessions = d.calculateTotalSessions()
	
	// Broadcast expired sessions
	for _, sessionID := range expiredSessions {
		syncMsg := &SessionSyncMessage{
			NodeID:     d.config.NodeID,
			SessionID:  sessionID,
			UpdateType: SessionExpired,
			Timestamp:  now,
		}
		
		select {
		case d.syncChan <- syncMsg:
		default:
			d.stats.SyncErrors++
		}
	}
	
	return nil
}

// GetStats returns distributed store statistics
func (d *distributedSessionStoreImpl) GetStats() *DistributedStoreStats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	stats := *d.stats
	stats.LocalSessions = len(d.localStore)
	stats.TotalSessions = d.calculateTotalSessions()
	stats.RemoteSessions = stats.TotalSessions - stats.LocalSessions
	
	return &stats
}

// Close shuts down the distributed store
func (d *distributedSessionStoreImpl) Close() error {
	if d.cancel != nil {
		d.cancel()
	}
	
	close(d.syncChan)
	
	d.mu.Lock()
	defer d.mu.Unlock()
	
	// Clear all stores
	d.localStore = make(map[string]*UserSession)
	d.nodeStores = make(map[string]map[string]*UserSession)
	
	return nil
}

// Helper methods

// calculateTotalSessions calculates total sessions across all nodes
func (d *distributedSessionStoreImpl) calculateTotalSessions() int {
	total := len(d.localStore)
	for _, nodeStore := range d.nodeStores {
		total += len(nodeStore)
	}
	return total
}

// syncLoop periodically syncs with cluster nodes
func (d *distributedSessionStoreImpl) syncLoop() {
	ticker := time.NewTicker(d.config.SyncInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.performFullSync()
		}
	}
}

// processSyncMessages processes incoming sync messages
func (d *distributedSessionStoreImpl) processSyncMessages() {
	for {
		select {
		case <-d.ctx.Done():
			return
		case msg := <-d.syncChan:
			if msg != nil {
				d.handleSyncMessage(msg)
			}
		}
	}
}

// handleSyncMessage handles a single sync message
func (d *distributedSessionStoreImpl) handleSyncMessage(msg *SessionSyncMessage) {
	if msg.NodeID == d.config.NodeID {
		// Don't process our own messages
		return
	}
	
	d.mu.Lock()
	defer d.mu.Unlock()
	
	// Ensure node store exists
	if _, exists := d.nodeStores[msg.NodeID]; !exists {
		d.nodeStores[msg.NodeID] = make(map[string]*UserSession)
	}
	
	nodeStore := d.nodeStores[msg.NodeID]
	
	switch msg.UpdateType {
	case SessionCreated, SessionUpdated:
		if msg.Session != nil {
			nodeStore[msg.SessionID] = msg.Session
		}
	case SessionDeleted, SessionExpired:
		delete(nodeStore, msg.SessionID)
	case UserSessionsDeleted:
		// Remove all sessions for the user from this node
		for sessionID, session := range nodeStore {
			if session.UserID == msg.UserID {
				delete(nodeStore, sessionID)
			}
		}
	}
	
	d.stats.SyncOperations++
	d.stats.LastSync = time.Now()
	d.stats.TotalSessions = d.calculateTotalSessions()
}

// performFullSync performs a full synchronization with cluster nodes
func (d *distributedSessionStoreImpl) performFullSync() {
	if d.clusterManager == nil {
		return
	}
	
	// Request full sync from all nodes
	for _, nodeID := range d.config.ClusterNodes {
		if nodeID == d.config.NodeID {
			continue
		}
		
		// This would typically send a network request to the node
		// For now, we'll just update the last sync time
		d.mu.Lock()
		d.stats.LastSync = time.Now()
		d.mu.Unlock()
	}
}

// broadcastSyncMessage broadcasts a sync message to all cluster nodes
func (d *distributedSessionStoreImpl) broadcastSyncMessage(msg *SessionSyncMessage) error {
	if d.clusterManager == nil {
		return fmt.Errorf("cluster manager not available")
	}
	
	// Serialize message
	data, err := json.Marshal(msg)
	if err != nil {
		d.stats.SyncErrors++
		return fmt.Errorf("failed to serialize sync message: %w", err)
	}
	
	// Broadcast to cluster
	return d.clusterManager.Broadcast("session_sync", data)
}

// generateNodeID generates a unique node identifier
func generateNodeID() string {
	// In a real implementation, this would generate a unique node ID
	// based on hostname, MAC address, or other unique identifiers
	return fmt.Sprintf("node-%d", time.Now().UnixNano())
}