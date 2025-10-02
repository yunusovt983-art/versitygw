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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/versity/versitygw/s3log"
)

// IPFSAuditLogger provides comprehensive audit logging for IPFS operations
type IPFSAuditLogger struct {
	config          *AuditConfig
	file            *os.File
	events          []*IPFSAuditEvent
	metrics         *IPFSAuditMetrics
	alertManager    *AuditAlertManager
	mu              sync.RWMutex
	eventChan       chan *IPFSAuditEvent
	stopChan        chan bool
	wg              sync.WaitGroup
}

// AuditConfig contains configuration for IPFS audit logging
type AuditConfig struct {
	LogFile              string        `json:"log_file"`
	MaxEvents            int           `json:"max_events"`
	RetentionPeriod      time.Duration `json:"retention_period"`
	EnableRealTimeAlerts bool          `json:"enable_real_time_alerts"`
	EnableMetrics        bool          `json:"enable_metrics"`
	MetricsInterval      time.Duration `json:"metrics_interval"`
	BufferSize           int           `json:"buffer_size"`
	FlushInterval        time.Duration `json:"flush_interval"`
	CompressLogs         bool          `json:"compress_logs"`
	EncryptLogs          bool          `json:"encrypt_logs"`
}

// DefaultAuditConfig returns default audit configuration
func DefaultAuditConfig() *AuditConfig {
	return &AuditConfig{
		LogFile:              "/var/log/versitygw/ipfs_audit.log",
		MaxEvents:            100000,
		RetentionPeriod:      90 * 24 * time.Hour, // 90 days
		EnableRealTimeAlerts: true,
		EnableMetrics:        true,
		MetricsInterval:      5 * time.Minute,
		BufferSize:           1000,
		FlushInterval:        30 * time.Second,
		CompressLogs:         true,
		EncryptLogs:          false,
	}
}

// IPFSAuditEvent represents an IPFS operation audit event
type IPFSAuditEvent struct {
	EventID       string                 `json:"event_id"`
	Timestamp     time.Time              `json:"timestamp"`
	EventType     IPFSEventType          `json:"event_type"`
	UserID        string                 `json:"user_id"`
	SessionID     string                 `json:"session_id,omitempty"`
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	RequestID     string                 `json:"request_id"`
	
	// IPFS-specific fields
	Operation     IPFSOperation          `json:"operation"`
	Resource      IPFSResource           `json:"resource"`
	CID           string                 `json:"cid,omitempty"`
	S3Key         string                 `json:"s3_key,omitempty"`
	Bucket        string                 `json:"bucket,omitempty"`
	
	// Operation details
	Success       bool                   `json:"success"`
	ErrorCode     string                 `json:"error_code,omitempty"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
	Duration      time.Duration          `json:"duration"`
	BytesProcessed int64                 `json:"bytes_processed,omitempty"`
	
	// Security context
	Permissions   []string               `json:"permissions"`
	RoleID        string                 `json:"role_id,omitempty"`
	AuthMethod    string                 `json:"auth_method"`
	RiskScore     int                    `json:"risk_score,omitempty"`
	
	// Additional context
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
	
	// Compliance fields
	ComplianceFlags []string             `json:"compliance_flags,omitempty"`
	DataClassification string            `json:"data_classification,omitempty"`
	RetentionPolicy string               `json:"retention_policy,omitempty"`
}

// IPFSEventType defines types of IPFS events
type IPFSEventType string

const (
	IPFSEventTypePinOperation      IPFSEventType = "pin_operation"
	IPFSEventTypeUnpinOperation    IPFSEventType = "unpin_operation"
	IPFSEventTypeMetadataOperation IPFSEventType = "metadata_operation"
	IPFSEventTypeClusterOperation  IPFSEventType = "cluster_operation"
	IPFSEventTypeSecurityEvent     IPFSEventType = "security_event"
	IPFSEventTypeSystemEvent       IPFSEventType = "system_event"
)

// IPFSOperation defines specific IPFS operations
type IPFSOperation string

const (
	IPFSOpPinAdd         IPFSOperation = "pin_add"
	IPFSOpPinRemove      IPFSOperation = "pin_remove"
	IPFSOpPinList        IPFSOperation = "pin_list"
	IPFSOpPinStatus      IPFSOperation = "pin_status"
	IPFSOpMetadataRead   IPFSOperation = "metadata_read"
	IPFSOpMetadataWrite  IPFSOperation = "metadata_write"
	IPFSOpMetadataDelete IPFSOperation = "metadata_delete"
	IPFSOpClusterStatus  IPFSOperation = "cluster_status"
	IPFSOpClusterPeers   IPFSOperation = "cluster_peers"
	IPFSOpReplication    IPFSOperation = "replication"
	IPFSOpEncryption     IPFSOperation = "encryption"
	IPFSOpDecryption     IPFSOperation = "decryption"
)

// IPFSResource defines the resource being accessed
type IPFSResource struct {
	Type       string `json:"type"`        // "cid", "bucket", "metadata", "cluster"
	Identifier string `json:"identifier"`  // The actual resource identifier
	Path       string `json:"path,omitempty"`
	Size       int64  `json:"size,omitempty"`
}

// IPFSAuditMetrics contains audit metrics
type IPFSAuditMetrics struct {
	TotalEvents           int64                    `json:"total_events"`
	EventsByType          map[IPFSEventType]int64  `json:"events_by_type"`
	EventsByOperation     map[IPFSOperation]int64  `json:"events_by_operation"`
	SuccessfulOperations  int64                    `json:"successful_operations"`
	FailedOperations      int64                    `json:"failed_operations"`
	AverageResponseTime   time.Duration            `json:"average_response_time"`
	TopUsers              map[string]int64         `json:"top_users"`
	TopIPAddresses        map[string]int64         `json:"top_ip_addresses"`
	SecurityEvents        int64                    `json:"security_events"`
	ComplianceViolations  int64                    `json:"compliance_violations"`
	DataProcessed         int64                    `json:"data_processed"`
	LastUpdated           time.Time                `json:"last_updated"`
}

// NewIPFSAuditLogger creates a new IPFS audit logger
func NewIPFSAuditLogger(config *AuditConfig) (*IPFSAuditLogger, error) {
	if config == nil {
		config = DefaultAuditConfig()
	}

	var file *os.File
	var err error

	if config.LogFile != "" {
		file, err = os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log file: %w", err)
		}
	}

	logger := &IPFSAuditLogger{
		config:       config,
		file:         file,
		events:       make([]*IPFSAuditEvent, 0),
		metrics:      &IPFSAuditMetrics{
			EventsByType:      make(map[IPFSEventType]int64),
			EventsByOperation: make(map[IPFSOperation]int64),
			TopUsers:          make(map[string]int64),
			TopIPAddresses:    make(map[string]int64),
		},
		alertManager: NewAuditAlertManager(),
		eventChan:    make(chan *IPFSAuditEvent, config.BufferSize),
		stopChan:     make(chan bool, 1),
	}

	// Start background processing
	logger.wg.Add(1)
	go logger.processEvents()

	// Start metrics collection if enabled
	if config.EnableMetrics {
		logger.wg.Add(1)
		go logger.metricsCollectionRoutine()
	}

	return logger, nil
}

// LogPinOperation logs a pin operation
func (ial *IPFSAuditLogger) LogPinOperation(ctx context.Context, userID, cid, s3Key, bucket string, operation IPFSOperation, success bool, duration time.Duration, err error) {
	event := &IPFSAuditEvent{
		EventID:       generateAuditEventID(),
		Timestamp:     time.Now(),
		EventType:     IPFSEventTypePinOperation,
		UserID:        userID,
		IPAddress:     extractIPFromContext(ctx),
		UserAgent:     extractUserAgentFromContext(ctx),
		RequestID:     extractRequestIDFromContext(ctx),
		Operation:     operation,
		Resource: IPFSResource{
			Type:       "cid",
			Identifier: cid,
			Path:       fmt.Sprintf("%s/%s", bucket, s3Key),
		},
		CID:     cid,
		S3Key:   s3Key,
		Bucket:  bucket,
		Success: success,
		Duration: duration,
		AuthMethod: "iam",
	}

	if err != nil {
		event.ErrorMessage = err.Error()
		event.ErrorCode = "IPFS_PIN_ERROR"
	}

	ial.logEvent(event)
}

// LogMetadataOperation logs a metadata operation
func (ial *IPFSAuditLogger) LogMetadataOperation(ctx context.Context, userID, s3Key, bucket string, operation IPFSOperation, success bool, bytesProcessed int64, err error) {
	event := &IPFSAuditEvent{
		EventID:       generateAuditEventID(),
		Timestamp:     time.Now(),
		EventType:     IPFSEventTypeMetadataOperation,
		UserID:        userID,
		IPAddress:     extractIPFromContext(ctx),
		UserAgent:     extractUserAgentFromContext(ctx),
		RequestID:     extractRequestIDFromContext(ctx),
		Operation:     operation,
		Resource: IPFSResource{
			Type:       "metadata",
			Identifier: fmt.Sprintf("%s/%s", bucket, s3Key),
			Size:       bytesProcessed,
		},
		S3Key:          s3Key,
		Bucket:         bucket,
		Success:        success,
		BytesProcessed: bytesProcessed,
		AuthMethod:     "iam",
	}

	if err != nil {
		event.ErrorMessage = err.Error()
		event.ErrorCode = "IPFS_METADATA_ERROR"
	}

	ial.logEvent(event)
}

// LogSecurityEvent logs a security-related event
func (ial *IPFSAuditLogger) LogSecurityEvent(ctx context.Context, userID string, eventType string, riskScore int, details map[string]interface{}) {
	event := &IPFSAuditEvent{
		EventID:    generateAuditEventID(),
		Timestamp:  time.Now(),
		EventType:  IPFSEventTypeSecurityEvent,
		UserID:     userID,
		IPAddress:  extractIPFromContext(ctx),
		UserAgent:  extractUserAgentFromContext(ctx),
		RequestID:  extractRequestIDFromContext(ctx),
		Operation:  IPFSOperation(eventType),
		Success:    true, // Security events are informational
		RiskScore:  riskScore,
		AuthMethod: "iam",
		Metadata:   details,
	}

	// Add security tags
	event.Tags = []string{"security", "audit"}
	if riskScore > 70 {
		event.Tags = append(event.Tags, "high-risk")
	}

	ial.logEvent(event)
}

// LogClusterOperation logs a cluster operation
func (ial *IPFSAuditLogger) LogClusterOperation(ctx context.Context, userID string, operation IPFSOperation, success bool, duration time.Duration, err error) {
	event := &IPFSAuditEvent{
		EventID:   generateAuditEventID(),
		Timestamp: time.Now(),
		EventType: IPFSEventTypeClusterOperation,
		UserID:    userID,
		IPAddress: extractIPFromContext(ctx),
		UserAgent: extractUserAgentFromContext(ctx),
		RequestID: extractRequestIDFromContext(ctx),
		Operation: operation,
		Resource: IPFSResource{
			Type:       "cluster",
			Identifier: "ipfs-cluster",
		},
		Success:    success,
		Duration:   duration,
		AuthMethod: "iam",
	}

	if err != nil {
		event.ErrorMessage = err.Error()
		event.ErrorCode = "IPFS_CLUSTER_ERROR"
	}

	ial.logEvent(event)
}

// LogEncryptionOperation logs encryption/decryption operations
func (ial *IPFSAuditLogger) LogEncryptionOperation(ctx context.Context, userID, s3Key, bucket string, operation IPFSOperation, bytesProcessed int64, success bool, err error) {
	event := &IPFSAuditEvent{
		EventID:       generateAuditEventID(),
		Timestamp:     time.Now(),
		EventType:     IPFSEventTypeSystemEvent,
		UserID:        userID,
		IPAddress:     extractIPFromContext(ctx),
		UserAgent:     extractUserAgentFromContext(ctx),
		RequestID:     extractRequestIDFromContext(ctx),
		Operation:     operation,
		Resource: IPFSResource{
			Type:       "object",
			Identifier: fmt.Sprintf("%s/%s", bucket, s3Key),
			Size:       bytesProcessed,
		},
		S3Key:          s3Key,
		Bucket:         bucket,
		Success:        success,
		BytesProcessed: bytesProcessed,
		AuthMethod:     "iam",
		Tags:           []string{"encryption", "security"},
	}

	if err != nil {
		event.ErrorMessage = err.Error()
		event.ErrorCode = "IPFS_ENCRYPTION_ERROR"
	}

	// Add compliance flags for encryption
	event.ComplianceFlags = []string{"data-encryption", "privacy-protection"}

	ial.logEvent(event)
}

// logEvent adds an event to the processing queue
func (ial *IPFSAuditLogger) logEvent(event *IPFSAuditEvent) {
	select {
	case ial.eventChan <- event:
		// Event queued successfully
	default:
		// Channel is full, log error
		log.Printf("AUDIT_ERROR: Event channel is full, dropping event: %s", event.EventID)
	}
}

// processEvents processes events from the queue
func (ial *IPFSAuditLogger) processEvents() {
	defer ial.wg.Done()

	flushTicker := time.NewTicker(ial.config.FlushInterval)
	defer flushTicker.Stop()

	var pendingEvents []*IPFSAuditEvent

	for {
		select {
		case event := <-ial.eventChan:
			pendingEvents = append(pendingEvents, event)
			
			// Process event immediately for real-time alerts
			if ial.config.EnableRealTimeAlerts {
				ial.checkAlerts(event)
			}
			
			// Flush if buffer is full
			if len(pendingEvents) >= ial.config.BufferSize {
				ial.flushEvents(pendingEvents)
				pendingEvents = nil
			}

		case <-flushTicker.C:
			// Periodic flush
			if len(pendingEvents) > 0 {
				ial.flushEvents(pendingEvents)
				pendingEvents = nil
			}

		case <-ial.stopChan:
			// Flush remaining events before stopping
			if len(pendingEvents) > 0 {
				ial.flushEvents(pendingEvents)
			}
			return
		}
	}
}

// flushEvents writes events to storage and updates metrics
func (ial *IPFSAuditLogger) flushEvents(events []*IPFSAuditEvent) {
	ial.mu.Lock()
	defer ial.mu.Unlock()

	for _, event := range events {
		// Add to in-memory storage
		ial.events = append(ial.events, event)
		
		// Update metrics
		ial.updateMetrics(event)
		
		// Write to file
		if ial.file != nil {
			ial.writeEventToFile(event)
		}
	}

	// Cleanup old events
	ial.cleanupEvents()
	
	// Sync file
	if ial.file != nil {
		ial.file.Sync()
	}
}

// writeEventToFile writes an event to the log file
func (ial *IPFSAuditLogger) writeEventToFile(event *IPFSAuditEvent) {
	jsonData, err := json.Marshal(event)
	if err != nil {
		log.Printf("AUDIT_ERROR: Failed to marshal event: %v", err)
		return
	}

	_, err = ial.file.WriteString(string(jsonData) + "\n")
	if err != nil {
		log.Printf("AUDIT_ERROR: Failed to write event to file: %v", err)
	}
}

// updateMetrics updates audit metrics
func (ial *IPFSAuditLogger) updateMetrics(event *IPFSAuditEvent) {
	ial.metrics.TotalEvents++
	ial.metrics.EventsByType[event.EventType]++
	ial.metrics.EventsByOperation[event.Operation]++
	ial.metrics.TopUsers[event.UserID]++
	ial.metrics.TopIPAddresses[event.IPAddress]++
	
	if event.Success {
		ial.metrics.SuccessfulOperations++
	} else {
		ial.metrics.FailedOperations++
	}
	
	if event.BytesProcessed > 0 {
		ial.metrics.DataProcessed += event.BytesProcessed
	}
	
	if event.EventType == IPFSEventTypeSecurityEvent {
		ial.metrics.SecurityEvents++
	}
	
	if len(event.ComplianceFlags) > 0 {
		ial.metrics.ComplianceViolations++
	}
	
	ial.metrics.LastUpdated = time.Now()
}

// cleanupEvents removes old events based on retention policy
func (ial *IPFSAuditLogger) cleanupEvents() {
	if len(ial.events) <= ial.config.MaxEvents {
		return
	}

	// Remove oldest events
	excess := len(ial.events) - ial.config.MaxEvents
	ial.events = ial.events[excess:]
}

// checkAlerts checks for alert conditions
func (ial *IPFSAuditLogger) checkAlerts(event *IPFSAuditEvent) {
	if ial.alertManager == nil {
		return
	}

	// Check for high-risk events
	if event.RiskScore > 80 {
		ial.alertManager.TriggerAlert("high_risk_operation", "high", map[string]interface{}{
			"user_id":    event.UserID,
			"operation":  event.Operation,
			"risk_score": event.RiskScore,
			"event_id":   event.EventID,
		})
	}

	// Check for failed operations
	if !event.Success && event.EventType == IPFSEventTypePinOperation {
		ial.alertManager.TriggerAlert("pin_operation_failed", "medium", map[string]interface{}{
			"user_id":      event.UserID,
			"operation":    event.Operation,
			"error_code":   event.ErrorCode,
			"error_message": event.ErrorMessage,
			"event_id":     event.EventID,
		})
	}

	// Check for compliance violations
	if len(event.ComplianceFlags) > 0 {
		ial.alertManager.TriggerAlert("compliance_violation", "medium", map[string]interface{}{
			"user_id":          event.UserID,
			"compliance_flags": event.ComplianceFlags,
			"event_id":         event.EventID,
		})
	}
}

// metricsCollectionRoutine periodically updates metrics
func (ial *IPFSAuditLogger) metricsCollectionRoutine() {
	defer ial.wg.Done()

	ticker := time.NewTicker(ial.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ial.collectMetrics()
		case <-ial.stopChan:
			return
		}
	}
}

// collectMetrics collects and calculates metrics
func (ial *IPFSAuditLogger) collectMetrics() {
	ial.mu.RLock()
	defer ial.mu.RUnlock()

	// Calculate average response time
	if len(ial.events) > 0 {
		totalDuration := time.Duration(0)
		count := 0
		
		for _, event := range ial.events {
			if event.Duration > 0 {
				totalDuration += event.Duration
				count++
			}
		}
		
		if count > 0 {
			ial.metrics.AverageResponseTime = totalDuration / time.Duration(count)
		}
	}
}

// GetMetrics returns current audit metrics
func (ial *IPFSAuditLogger) GetMetrics() *IPFSAuditMetrics {
	ial.mu.RLock()
	defer ial.mu.RUnlock()
	
	// Return a copy of metrics
	metricsCopy := *ial.metrics
	return &metricsCopy
}

// GetEvents returns events based on filter criteria
func (ial *IPFSAuditLogger) GetEvents(filter *AuditEventFilter) ([]*IPFSAuditEvent, error) {
	ial.mu.RLock()
	defer ial.mu.RUnlock()

	var filtered []*IPFSAuditEvent

	for _, event := range ial.events {
		if ial.matchesFilter(event, filter) {
			filtered = append(filtered, event)
		}
	}

	// Apply limit if specified
	if filter != nil && filter.Limit > 0 && len(filtered) > filter.Limit {
		filtered = filtered[:filter.Limit]
	}

	return filtered, nil
}

// AuditEventFilter defines filter criteria for audit events
type AuditEventFilter struct {
	UserID      string        `json:"user_id,omitempty"`
	EventType   IPFSEventType `json:"event_type,omitempty"`
	Operation   IPFSOperation `json:"operation,omitempty"`
	Success     *bool         `json:"success,omitempty"`
	StartTime   *time.Time    `json:"start_time,omitempty"`
	EndTime     *time.Time    `json:"end_time,omitempty"`
	IPAddress   string        `json:"ip_address,omitempty"`
	CID         string        `json:"cid,omitempty"`
	Bucket      string        `json:"bucket,omitempty"`
	Limit       int           `json:"limit,omitempty"`
}

// matchesFilter checks if an event matches the filter criteria
func (ial *IPFSAuditLogger) matchesFilter(event *IPFSAuditEvent, filter *AuditEventFilter) bool {
	if filter == nil {
		return true
	}

	if filter.UserID != "" && event.UserID != filter.UserID {
		return false
	}

	if filter.EventType != "" && event.EventType != filter.EventType {
		return false
	}

	if filter.Operation != "" && event.Operation != filter.Operation {
		return false
	}

	if filter.Success != nil && event.Success != *filter.Success {
		return false
	}

	if filter.IPAddress != "" && event.IPAddress != filter.IPAddress {
		return false
	}

	if filter.CID != "" && event.CID != filter.CID {
		return false
	}

	if filter.Bucket != "" && event.Bucket != filter.Bucket {
		return false
	}

	if filter.StartTime != nil && event.Timestamp.Before(*filter.StartTime) {
		return false
	}

	if filter.EndTime != nil && event.Timestamp.After(*filter.EndTime) {
		return false
	}

	return true
}

// Shutdown gracefully shuts down the audit logger
func (ial *IPFSAuditLogger) Shutdown() error {
	// Signal stop
	ial.stopChan <- true
	
	// Wait for goroutines to finish
	ial.wg.Wait()
	
	// Close file
	if ial.file != nil {
		return ial.file.Close()
	}
	
	return nil
}

// Helper functions

func generateAuditEventID() string {
	return fmt.Sprintf("ipfs_audit_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%1000)
}

// AuditAlertManager manages audit alerts
type AuditAlertManager struct {
	alerts []AuditAlert
	mu     sync.RWMutex
}

// AuditAlert represents an audit alert
type AuditAlert struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Severity  string                 `json:"severity"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details"`
}

// NewAuditAlertManager creates a new audit alert manager
func NewAuditAlertManager() *AuditAlertManager {
	return &AuditAlertManager{
		alerts: make([]AuditAlert, 0),
	}
}

// TriggerAlert triggers an audit alert
func (aam *AuditAlertManager) TriggerAlert(alertType, severity string, details map[string]interface{}) {
	aam.mu.Lock()
	defer aam.mu.Unlock()

	alert := AuditAlert{
		ID:        generateAuditEventID(),
		Type:      alertType,
		Severity:  severity,
		Timestamp: time.Now(),
		Details:   details,
	}

	aam.alerts = append(aam.alerts, alert)

	// Log alert
	log.Printf("AUDIT_ALERT: [%s] %s - %+v", severity, alertType, details)
}

// GetAlerts returns recent alerts
func (aam *AuditAlertManager) GetAlerts(limit int) []AuditAlert {
	aam.mu.RLock()
	defer aam.mu.RUnlock()

	if limit <= 0 || limit > len(aam.alerts) {
		limit = len(aam.alerts)
	}

	// Return most recent alerts
	start := len(aam.alerts) - limit
	if start < 0 {
		start = 0
	}

	return aam.alerts[start:]
}