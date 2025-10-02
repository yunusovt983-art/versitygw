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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ReportType represents the type of security report
type ReportType string

const (
	ReportTypeAccessSummary      ReportType = "access_summary"
	ReportTypeAuthenticationLog  ReportType = "authentication_log"
	ReportTypeSecurityAlerts     ReportType = "security_alerts"
	ReportTypeUserActivity       ReportType = "user_activity"
	ReportTypeAuditTrail         ReportType = "audit_trail"
	ReportTypeComplianceReport   ReportType = "compliance_report"
	ReportTypeRiskAssessment     ReportType = "risk_assessment"
	ReportTypeIncidentReport     ReportType = "incident_report"
)

// ReportFormat represents the output format for reports
type ReportFormat string

const (
	ReportFormatJSON ReportFormat = "json"
	ReportFormatCSV  ReportFormat = "csv"
	ReportFormatHTML ReportFormat = "html"
	ReportFormatPDF  ReportFormat = "pdf"
)

// SecurityReport represents a generated security report
type SecurityReport struct {
	ID          string                 `json:"id"`
	Type        ReportType             `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	GeneratedAt time.Time              `json:"generated_at"`
	GeneratedBy string                 `json:"generated_by"`
	TimeRange   *TimeRange             `json:"time_range"`
	Format      ReportFormat           `json:"format"`
	Data        interface{}            `json:"data"`
	Metadata    map[string]interface{} `json:"metadata"`
	FilePath    string                 `json:"file_path,omitempty"`
	Size        int64                  `json:"size,omitempty"`
}

// TimeRange represents a time range for queries
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ReportRequest represents a request for generating a report
type ReportRequest struct {
	Type        ReportType             `json:"type"`
	Format      ReportFormat           `json:"format"`
	TimeRange   *TimeRange             `json:"time_range"`
	Filters     map[string]interface{} `json:"filters,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	RequestedBy string                 `json:"requested_by"`
}

// AccessSummaryReport contains access summary data
type AccessSummaryReport struct {
	TotalAccesses         int64                    `json:"total_accesses"`
	SuccessfulAccesses    int64                    `json:"successful_accesses"`
	FailedAccesses        int64                    `json:"failed_accesses"`
	UniqueUsers           int64                    `json:"unique_users"`
	UniqueIPs             int64                    `json:"unique_ips"`
	TopUsers              []UserAccessSummary      `json:"top_users"`
	TopIPs                []IPAccessSummary        `json:"top_ips"`
	AccessByHour          map[string]int64         `json:"access_by_hour"`
	AccessByDay           map[string]int64         `json:"access_by_day"`
	AuthMethodDistribution map[string]int64        `json:"auth_method_distribution"`
	FailureReasons        map[string]int64         `json:"failure_reasons"`
}

// UserAccessSummary contains access summary for a specific user
type UserAccessSummary struct {
	UserID            string    `json:"user_id"`
	TotalAccesses     int64     `json:"total_accesses"`
	SuccessfulAccesses int64    `json:"successful_accesses"`
	FailedAccesses    int64     `json:"failed_accesses"`
	LastAccess        time.Time `json:"last_access"`
	UniqueIPs         int64     `json:"unique_ips"`
	RiskScore         int       `json:"risk_score"`
}

// IPAccessSummary contains access summary for a specific IP
type IPAccessSummary struct {
	IPAddress         string    `json:"ip_address"`
	TotalAccesses     int64     `json:"total_accesses"`
	SuccessfulAccesses int64    `json:"successful_accesses"`
	FailedAccesses    int64     `json:"failed_accesses"`
	LastAccess        time.Time `json:"last_access"`
	UniqueUsers       int64     `json:"unique_users"`
	GeoLocation       string    `json:"geo_location,omitempty"`
	RiskScore         int       `json:"risk_score"`
}

// AuditTrailReport contains audit trail data
type AuditTrailReport struct {
	TotalEvents       int64                `json:"total_events"`
	EventsByType      map[string]int64     `json:"events_by_type"`
	EventsBySeverity  map[string]int64     `json:"events_by_severity"`
	Events            []AuditTrailEntry    `json:"events"`
	ComplianceFlags   []string             `json:"compliance_flags"`
	DataClassifications []string           `json:"data_classifications"`
}

// AuditTrailEntry represents a single audit trail entry
type AuditTrailEntry struct {
	ID                string                 `json:"id"`
	Timestamp         time.Time              `json:"timestamp"`
	EventType         string                 `json:"event_type"`
	Severity          string                 `json:"severity"`
	UserID            string                 `json:"user_id,omitempty"`
	IPAddress         string                 `json:"ip_address,omitempty"`
	Resource          string                 `json:"resource,omitempty"`
	Action            string                 `json:"action,omitempty"`
	Result            string                 `json:"result"`
	Details           map[string]interface{} `json:"details,omitempty"`
	ComplianceFlags   []string               `json:"compliance_flags,omitempty"`
	DataClassification string                `json:"data_classification,omitempty"`
}

// ComplianceReport contains compliance-related data
type ComplianceReport struct {
	ComplianceFramework string                     `json:"compliance_framework"`
	OverallScore        float64                    `json:"overall_score"`
	Requirements        []ComplianceRequirement    `json:"requirements"`
	Violations          []ComplianceViolation      `json:"violations"`
	Recommendations     []string                   `json:"recommendations"`
	CertificationStatus string                     `json:"certification_status"`
}

// ComplianceRequirement represents a compliance requirement
type ComplianceRequirement struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Status      string  `json:"status"` // "compliant", "non_compliant", "partial"
	Score       float64 `json:"score"`
	Evidence    []string `json:"evidence,omitempty"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	ID          string    `json:"id"`
	Requirement string    `json:"requirement"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	DetectedAt  time.Time `json:"detected_at"`
	Status      string    `json:"status"` // "open", "resolved", "acknowledged"
	Remediation string    `json:"remediation,omitempty"`
}

// SecurityReportingSystem manages security reports and audit trails
type SecurityReportingSystem struct {
	mu                sync.RWMutex
	auditLogger       SecurityAuditLogger
	alertSystem       *SecurityAlertSystem
	metricsCollector  *SecurityMetricsCollector
	config            *ReportingConfig
	reports           map[string]*SecurityReport
	auditTrail        []AuditTrailEntry
}

// ReportingConfig contains configuration for the reporting system
type ReportingConfig struct {
	MaxReports          int           `json:"max_reports"`
	ReportRetention     time.Duration `json:"report_retention"`
	AuditTrailRetention time.Duration `json:"audit_trail_retention"`
	MaxAuditEntries     int           `json:"max_audit_entries"`
	OutputDirectory     string        `json:"output_directory"`
	EnableAutoReports   bool          `json:"enable_auto_reports"`
	AutoReportInterval  time.Duration `json:"auto_report_interval"`
}

// DefaultReportingConfig returns default reporting configuration
func DefaultReportingConfig() *ReportingConfig {
	return &ReportingConfig{
		MaxReports:          1000,
		ReportRetention:     90 * 24 * time.Hour, // 90 days
		AuditTrailRetention: 365 * 24 * time.Hour, // 1 year
		MaxAuditEntries:     100000,
		OutputDirectory:     "/var/log/versitygw/reports",
		EnableAutoReports:   true,
		AutoReportInterval:  24 * time.Hour, // Daily
	}
}

// NewSecurityReportingSystem creates a new security reporting system
func NewSecurityReportingSystem(auditLogger SecurityAuditLogger, alertSystem *SecurityAlertSystem, metricsCollector *SecurityMetricsCollector, config *ReportingConfig) *SecurityReportingSystem {
	if config == nil {
		config = DefaultReportingConfig()
	}

	system := &SecurityReportingSystem{
		auditLogger:      auditLogger,
		alertSystem:      alertSystem,
		metricsCollector: metricsCollector,
		config:           config,
		reports:          make(map[string]*SecurityReport),
		auditTrail:       make([]AuditTrailEntry, 0),
	}

	// Start automatic report generation if enabled
	if config.EnableAutoReports {
		go system.autoReportRoutine()
	}

	return system
}

// GenerateReport generates a security report based on the request
func (s *SecurityReportingSystem) GenerateReport(request *ReportRequest) (*SecurityReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	report := &SecurityReport{
		ID:          generateReportID(),
		Type:        request.Type,
		GeneratedAt: time.Now(),
		GeneratedBy: request.RequestedBy,
		TimeRange:   request.TimeRange,
		Format:      request.Format,
		Metadata:    make(map[string]interface{}),
	}

	// Generate report data based on type
	var err error
	switch request.Type {
	case ReportTypeAccessSummary:
		report.Title = "Access Summary Report"
		report.Description = "Summary of access patterns and authentication statistics"
		report.Data, err = s.generateAccessSummaryReport(request)
	case ReportTypeAuthenticationLog:
		report.Title = "Authentication Log Report"
		report.Description = "Detailed authentication events and attempts"
		report.Data, err = s.generateAuthenticationLogReport(request)
	case ReportTypeSecurityAlerts:
		report.Title = "Security Alerts Report"
		report.Description = "Security alerts and incidents"
		report.Data, err = s.generateSecurityAlertsReport(request)
	case ReportTypeUserActivity:
		report.Title = "User Activity Report"
		report.Description = "Detailed user activity and behavior analysis"
		report.Data, err = s.generateUserActivityReport(request)
	case ReportTypeAuditTrail:
		report.Title = "Audit Trail Report"
		report.Description = "Complete audit trail of security events"
		report.Data, err = s.generateAuditTrailReport(request)
	case ReportTypeComplianceReport:
		report.Title = "Compliance Report"
		report.Description = "Compliance status and violations"
		report.Data, err = s.generateComplianceReport(request)
	case ReportTypeRiskAssessment:
		report.Title = "Risk Assessment Report"
		report.Description = "Security risk analysis and recommendations"
		report.Data, err = s.generateRiskAssessmentReport(request)
	case ReportTypeIncidentReport:
		report.Title = "Incident Report"
		report.Description = "Security incidents and response actions"
		report.Data, err = s.generateIncidentReport(request)
	default:
		return nil, fmt.Errorf("unsupported report type: %s", request.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate report data: %w", err)
	}

	// Store the report
	s.reports[report.ID] = report
	s.cleanupOldReports()

	// Add to audit trail
	s.addAuditEntry(AuditTrailEntry{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		EventType: "report_generated",
		Severity:  "info",
		UserID:    request.RequestedBy,
		Action:    "generate_report",
		Result:    "success",
		Details: map[string]interface{}{
			"report_id":   report.ID,
			"report_type": report.Type,
			"format":      report.Format,
		},
	})

	return report, nil
}

// GetReport retrieves a report by ID
func (s *SecurityReportingSystem) GetReport(reportID string) (*SecurityReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	report, exists := s.reports[reportID]
	if !exists {
		return nil, fmt.Errorf("report not found: %s", reportID)
	}

	return report, nil
}

// ListReports returns a list of available reports
func (s *SecurityReportingSystem) ListReports(filters map[string]interface{}) []*SecurityReport {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var reports []*SecurityReport
	for _, report := range s.reports {
		if s.matchesReportFilters(report, filters) {
			reports = append(reports, report)
		}
	}

	// Sort by generation time (newest first)
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].GeneratedAt.After(reports[j].GeneratedAt)
	})

	return reports
}

// ExportReport exports a report in the specified format
func (s *SecurityReportingSystem) ExportReport(reportID string, format ReportFormat) ([]byte, error) {
	report, err := s.GetReport(reportID)
	if err != nil {
		return nil, err
	}

	switch format {
	case ReportFormatJSON:
		return json.MarshalIndent(report, "", "  ")
	case ReportFormatCSV:
		return s.exportReportAsCSV(report)
	case ReportFormatHTML:
		return s.exportReportAsHTML(report)
	case ReportFormatPDF:
		return s.exportReportAsPDF(report)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// GetAuditTrail returns audit trail entries based on filters
func (s *SecurityReportingSystem) GetAuditTrail(filters map[string]interface{}) []AuditTrailEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var entries []AuditTrailEntry
	for _, entry := range s.auditTrail {
		if s.matchesAuditFilters(&entry, filters) {
			entries = append(entries, entry)
		}
	}

	// Sort by timestamp (newest first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	return entries
}

// AddAuditEntry adds an entry to the audit trail
func (s *SecurityReportingSystem) AddAuditEntry(entry AuditTrailEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addAuditEntry(entry)
}

// Report generation methods

func (s *SecurityReportingSystem) generateAccessSummaryReport(request *ReportRequest) (*AccessSummaryReport, error) {
	// Get authentication events from audit logger
	filter := &SecurityEventFilter{}
	if request.TimeRange != nil {
		filter.StartTime = &request.TimeRange.Start
		filter.EndTime = &request.TimeRange.End
	}

	events, err := s.auditLogger.GetSecurityEvents(filter)
	if err != nil {
		return nil, err
	}

	report := &AccessSummaryReport{
		TopUsers:               make([]UserAccessSummary, 0),
		TopIPs:                 make([]IPAccessSummary, 0),
		AccessByHour:           make(map[string]int64),
		AccessByDay:            make(map[string]int64),
		AuthMethodDistribution: make(map[string]int64),
		FailureReasons:         make(map[string]int64),
	}

	userStats := make(map[string]*UserAccessSummary)
	ipStats := make(map[string]*IPAccessSummary)
	uniqueUsers := make(map[string]bool)
	uniqueIPs := make(map[string]bool)

	for _, event := range events {
		if event.Type == EventTypeAuthAttempt || event.Type == EventTypeAuthSuccess || event.Type == EventTypeAuthFailure {
			report.TotalAccesses++
			
			if event.Success {
				report.SuccessfulAccesses++
			} else {
				report.FailedAccesses++
			}

			// Track unique users and IPs
			if event.UserID != "" {
				uniqueUsers[event.UserID] = true
			}
			if event.IPAddress != "" {
				uniqueIPs[event.IPAddress] = true
			}

			// Update user statistics
			if event.UserID != "" {
				if _, exists := userStats[event.UserID]; !exists {
					userStats[event.UserID] = &UserAccessSummary{
						UserID: event.UserID,
					}
				}
				userStats[event.UserID].TotalAccesses++
				if event.Success {
					userStats[event.UserID].SuccessfulAccesses++
				} else {
					userStats[event.UserID].FailedAccesses++
				}
				userStats[event.UserID].LastAccess = event.Timestamp
			}

			// Update IP statistics
			if event.IPAddress != "" {
				if _, exists := ipStats[event.IPAddress]; !exists {
					ipStats[event.IPAddress] = &IPAccessSummary{
						IPAddress: event.IPAddress,
					}
				}
				ipStats[event.IPAddress].TotalAccesses++
				if event.Success {
					ipStats[event.IPAddress].SuccessfulAccesses++
				} else {
					ipStats[event.IPAddress].FailedAccesses++
				}
				ipStats[event.IPAddress].LastAccess = event.Timestamp
			}

			// Track access by hour and day
			hour := event.Timestamp.Format("15")
			day := event.Timestamp.Format("2006-01-02")
			report.AccessByHour[hour]++
			report.AccessByDay[day]++

			// Track authentication methods and failure reasons
			if authMethod, ok := event.Details["auth_method"].(string); ok {
				report.AuthMethodDistribution[authMethod]++
			}
			if !event.Success && event.Message != "" {
				report.FailureReasons[event.Message]++
			}
		}
	}

	report.UniqueUsers = int64(len(uniqueUsers))
	report.UniqueIPs = int64(len(uniqueIPs))

	// Convert maps to sorted slices
	for _, userStat := range userStats {
		report.TopUsers = append(report.TopUsers, *userStat)
	}
	for _, ipStat := range ipStats {
		report.TopIPs = append(report.TopIPs, *ipStat)
	}

	// Sort by total accesses (descending)
	sort.Slice(report.TopUsers, func(i, j int) bool {
		return report.TopUsers[i].TotalAccesses > report.TopUsers[j].TotalAccesses
	})
	sort.Slice(report.TopIPs, func(i, j int) bool {
		return report.TopIPs[i].TotalAccesses > report.TopIPs[j].TotalAccesses
	})

	// Limit to top 10
	if len(report.TopUsers) > 10 {
		report.TopUsers = report.TopUsers[:10]
	}
	if len(report.TopIPs) > 10 {
		report.TopIPs = report.TopIPs[:10]
	}

	return report, nil
}

func (s *SecurityReportingSystem) generateAuthenticationLogReport(request *ReportRequest) (interface{}, error) {
	// This would return detailed authentication events
	filter := &SecurityEventFilter{}
	if request.TimeRange != nil {
		filter.StartTime = &request.TimeRange.Start
		filter.EndTime = &request.TimeRange.End
	}

	events, err := s.auditLogger.GetSecurityEvents(filter)
	if err != nil {
		return nil, err
	}

	// Filter for authentication events only
	var authEvents []*SecurityEvent
	for _, event := range events {
		if event.Type == EventTypeAuthAttempt || event.Type == EventTypeAuthSuccess || event.Type == EventTypeAuthFailure {
			authEvents = append(authEvents, event)
		}
	}

	return authEvents, nil
}

func (s *SecurityReportingSystem) generateSecurityAlertsReport(request *ReportRequest) (interface{}, error) {
	if s.alertSystem == nil {
		return nil, fmt.Errorf("alert system not available")
	}

	filter := &AlertFilter{}
	if request.TimeRange != nil {
		filter.StartTime = &request.TimeRange.Start
		filter.EndTime = &request.TimeRange.End
	}

	alerts := s.alertSystem.GetAlerts(filter)
	return alerts, nil
}

func (s *SecurityReportingSystem) generateUserActivityReport(request *ReportRequest) (interface{}, error) {
	// This would generate detailed user activity analysis
	return s.generateAccessSummaryReport(request)
}

func (s *SecurityReportingSystem) generateAuditTrailReport(request *ReportRequest) (*AuditTrailReport, error) {
	filters := make(map[string]interface{})
	if request.TimeRange != nil {
		filters["start_time"] = request.TimeRange.Start
		filters["end_time"] = request.TimeRange.End
	}

	// Get audit trail entries without additional locking (we're already locked)
	var entries []AuditTrailEntry
	for _, entry := range s.auditTrail {
		if s.matchesAuditFilters(&entry, filters) {
			entries = append(entries, entry)
		}
	}

	report := &AuditTrailReport{
		TotalEvents:         int64(len(entries)),
		EventsByType:        make(map[string]int64),
		EventsBySeverity:    make(map[string]int64),
		Events:              entries,
		ComplianceFlags:     make([]string, 0),
		DataClassifications: make([]string, 0),
	}

	complianceFlags := make(map[string]bool)
	dataClassifications := make(map[string]bool)

	for _, entry := range entries {
		report.EventsByType[entry.EventType]++
		report.EventsBySeverity[entry.Severity]++

		for _, flag := range entry.ComplianceFlags {
			complianceFlags[flag] = true
		}
		if entry.DataClassification != "" {
			dataClassifications[entry.DataClassification] = true
		}
	}

	for flag := range complianceFlags {
		report.ComplianceFlags = append(report.ComplianceFlags, flag)
	}
	for classification := range dataClassifications {
		report.DataClassifications = append(report.DataClassifications, classification)
	}

	return report, nil
}

func (s *SecurityReportingSystem) generateComplianceReport(request *ReportRequest) (*ComplianceReport, error) {
	// This would generate compliance analysis based on audit data
	report := &ComplianceReport{
		ComplianceFramework: "SOC2",
		OverallScore:        85.5,
		Requirements:        make([]ComplianceRequirement, 0),
		Violations:          make([]ComplianceViolation, 0),
		Recommendations:     make([]string, 0),
		CertificationStatus: "Compliant",
	}

	// Add sample compliance requirements
	report.Requirements = append(report.Requirements, ComplianceRequirement{
		ID:          "CC6.1",
		Name:        "Logical and Physical Access Controls",
		Description: "Access controls are implemented to protect information assets",
		Status:      "compliant",
		Score:       90.0,
		Evidence:    []string{"Authentication logs", "Access control policies"},
	})

	return report, nil
}

func (s *SecurityReportingSystem) generateRiskAssessmentReport(request *ReportRequest) (interface{}, error) {
	// This would generate risk analysis based on security events and metrics
	if s.metricsCollector == nil {
		return nil, fmt.Errorf("metrics collector not available")
	}

	metrics := s.metricsCollector.GetCurrentMetrics()
	
	riskAssessment := map[string]interface{}{
		"overall_risk_score":    metrics.AverageRiskScore,
		"authentication_risk":   calculateAuthenticationRisk(metrics),
		"access_pattern_risk":   calculateAccessPatternRisk(metrics),
		"security_posture":      calculateSecurityPosture(metrics),
		"recommendations":       generateRiskRecommendations(metrics),
	}

	return riskAssessment, nil
}

func (s *SecurityReportingSystem) generateIncidentReport(request *ReportRequest) (interface{}, error) {
	// This would generate incident analysis based on security alerts
	if s.alertSystem == nil {
		return nil, fmt.Errorf("alert system not available")
	}

	filter := &AlertFilter{
		Severity: AlertSeverityHigh,
	}
	if request.TimeRange != nil {
		filter.StartTime = &request.TimeRange.Start
		filter.EndTime = &request.TimeRange.End
	}

	incidents := s.alertSystem.GetAlerts(filter)
	return incidents, nil
}

// Helper methods

func (s *SecurityReportingSystem) addAuditEntry(entry AuditTrailEntry) {
	if entry.ID == "" {
		entry.ID = generateAuditID()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	s.auditTrail = append(s.auditTrail, entry)
	s.cleanupAuditTrail()
}

func (s *SecurityReportingSystem) cleanupOldReports() {
	if len(s.reports) <= s.config.MaxReports {
		return
	}

	// Convert to slice for sorting
	var reports []*SecurityReport
	for _, report := range s.reports {
		reports = append(reports, report)
	}

	// Sort by generation time (oldest first)
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].GeneratedAt.Before(reports[j].GeneratedAt)
	})

	// Remove oldest reports
	excess := len(reports) - s.config.MaxReports
	for i := 0; i < excess; i++ {
		delete(s.reports, reports[i].ID)
	}
}

func (s *SecurityReportingSystem) cleanupAuditTrail() {
	if len(s.auditTrail) <= s.config.MaxAuditEntries {
		return
	}

	// Remove oldest entries
	excess := len(s.auditTrail) - s.config.MaxAuditEntries
	s.auditTrail = s.auditTrail[excess:]
}

func (s *SecurityReportingSystem) matchesReportFilters(report *SecurityReport, filters map[string]interface{}) bool {
	if filters == nil {
		return true
	}

	if reportType, ok := filters["type"].(ReportType); ok && report.Type != reportType {
		return false
	}

	if generatedBy, ok := filters["generated_by"].(string); ok && report.GeneratedBy != generatedBy {
		return false
	}

	if startTime, ok := filters["start_time"].(time.Time); ok && report.GeneratedAt.Before(startTime) {
		return false
	}

	if endTime, ok := filters["end_time"].(time.Time); ok && report.GeneratedAt.After(endTime) {
		return false
	}

	return true
}

func (s *SecurityReportingSystem) matchesAuditFilters(entry *AuditTrailEntry, filters map[string]interface{}) bool {
	if filters == nil {
		return true
	}

	if eventType, ok := filters["event_type"].(string); ok && entry.EventType != eventType {
		return false
	}

	if userID, ok := filters["user_id"].(string); ok && entry.UserID != userID {
		return false
	}

	if severity, ok := filters["severity"].(string); ok && entry.Severity != severity {
		return false
	}

	if startTime, ok := filters["start_time"].(time.Time); ok && entry.Timestamp.Before(startTime) {
		return false
	}

	if endTime, ok := filters["end_time"].(time.Time); ok && entry.Timestamp.After(endTime) {
		return false
	}

	return true
}

func (s *SecurityReportingSystem) autoReportRoutine() {
	ticker := time.NewTicker(s.config.AutoReportInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Generate daily access summary report
		request := &ReportRequest{
			Type:   ReportTypeAccessSummary,
			Format: ReportFormatJSON,
			TimeRange: &TimeRange{
				Start: time.Now().Add(-24 * time.Hour),
				End:   time.Now(),
			},
			RequestedBy: "system",
		}

		_, err := s.GenerateReport(request)
		if err != nil {
			// Log error but continue
			fmt.Printf("Failed to generate automatic report: %v\n", err)
		}
	}
}

// Export methods

func (s *SecurityReportingSystem) exportReportAsCSV(report *SecurityReport) ([]byte, error) {
	var records [][]string
	
	// Add header
	records = append(records, []string{"Field", "Value"})
	records = append(records, []string{"Report ID", report.ID})
	records = append(records, []string{"Type", string(report.Type)})
	records = append(records, []string{"Generated At", report.GeneratedAt.Format(time.RFC3339)})
	records = append(records, []string{"Generated By", report.GeneratedBy})

	// Convert data to CSV format (simplified)
	if data, ok := report.Data.(*AccessSummaryReport); ok {
		records = append(records, []string{"Total Accesses", fmt.Sprintf("%d", data.TotalAccesses)})
		records = append(records, []string{"Successful Accesses", fmt.Sprintf("%d", data.SuccessfulAccesses)})
		records = append(records, []string{"Failed Accesses", fmt.Sprintf("%d", data.FailedAccesses)})
		records = append(records, []string{"Unique Users", fmt.Sprintf("%d", data.UniqueUsers)})
		records = append(records, []string{"Unique IPs", fmt.Sprintf("%d", data.UniqueIPs)})
	}

	// Convert to CSV bytes
	var output strings.Builder
	writer := csv.NewWriter(&output)
	
	for _, record := range records {
		if err := writer.Write(record); err != nil {
			return nil, err
		}
	}
	
	writer.Flush()
	return []byte(output.String()), nil
}

func (s *SecurityReportingSystem) exportReportAsHTML(report *SecurityReport) ([]byte, error) {
	// This would generate HTML report
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>%s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .content { margin-top: 20px; }
        table { border-collapse: collapse; width: 100%%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>%s</h1>
        <p><strong>Generated:</strong> %s</p>
        <p><strong>Generated By:</strong> %s</p>
        <p><strong>Description:</strong> %s</p>
    </div>
    <div class="content">
        <pre>%s</pre>
    </div>
</body>
</html>
`, report.Title, report.Title, report.GeneratedAt.Format(time.RFC3339), report.GeneratedBy, report.Description, "Report data would be formatted here")

	return []byte(html), nil
}

func (s *SecurityReportingSystem) exportReportAsPDF(report *SecurityReport) ([]byte, error) {
	// This would generate PDF report using a PDF library
	// For now, return a placeholder
	return []byte("PDF export not implemented"), nil
}

// Risk calculation helpers

func calculateAuthenticationRisk(metrics *SecurityMetricsSnapshot) float64 {
	if metrics.AuthAttempts == 0 {
		return 0
	}
	
	failureRate := float64(metrics.AuthFailures) / float64(metrics.AuthAttempts) * 100
	if failureRate > 20 {
		return 80.0 // High risk
	} else if failureRate > 10 {
		return 50.0 // Medium risk
	}
	return 20.0 // Low risk
}

func calculateAccessPatternRisk(metrics *SecurityMetricsSnapshot) float64 {
	// Simple risk calculation based on suspicious activities
	if metrics.SuspiciousActivities > 10 {
		return 90.0
	} else if metrics.SuspiciousActivities > 5 {
		return 60.0
	}
	return 30.0
}

func calculateSecurityPosture(metrics *SecurityMetricsSnapshot) string {
	avgRisk := (calculateAuthenticationRisk(metrics) + calculateAccessPatternRisk(metrics)) / 2
	
	if avgRisk > 70 {
		return "Poor"
	} else if avgRisk > 40 {
		return "Fair"
	} else if avgRisk > 20 {
		return "Good"
	}
	return "Excellent"
}

func generateRiskRecommendations(metrics *SecurityMetricsSnapshot) []string {
	recommendations := make([]string, 0)
	
	if metrics.AuthFailures > metrics.AuthSuccesses {
		recommendations = append(recommendations, "High authentication failure rate detected - review authentication policies")
	}
	
	if metrics.CurrentLockedUsers > 5 {
		recommendations = append(recommendations, "Multiple users locked - investigate potential security incident")
	}
	
	if metrics.SuspiciousActivities > 10 {
		recommendations = append(recommendations, "High suspicious activity - enhance monitoring and alerting")
	}
	
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Security posture is good - maintain current practices")
	}
	
	return recommendations
}

// Utility functions

func generateReportID() string {
	return fmt.Sprintf("report_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%1000)
}

func generateAuditID() string {
	return fmt.Sprintf("audit_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond()%1000)
}