package auth

import (
	"fmt"
	"time"
)

// ConfigurationValidationReport represents a comprehensive configuration validation report
type ConfigurationValidationReport struct {
	Valid                bool                                    `json:"valid"`
	Timestamp            time.Time                               `json:"timestamp"`
	OverallSeverity      ErrorSeverity                           `json:"overall_severity"`
	TotalErrors          int                                     `json:"total_errors"`
	TotalWarnings        int                                     `json:"total_warnings"`
	Errors               []*ConfigurationError                   `json:"errors,omitempty"`
	Warnings             []*ConfigurationWarning                 `json:"warnings,omitempty"`
	ComponentValidations map[string]*ComponentConfigValidation   `json:"component_validations,omitempty"`
	Summary              *ConfigValidationSummary                `json:"summary"`
}

// ComponentConfigValidation represents validation results for a component
type ComponentConfigValidation struct {
	ComponentName    string                    `json:"component_name"`
	Valid            bool                      `json:"valid"`
	LastValidated    time.Time                 `json:"last_validated"`
	Errors           []*ConfigurationError     `json:"errors,omitempty"`
	Warnings         []*ConfigurationWarning   `json:"warnings,omitempty"`
	Recommendations  []*ConfigRecommendation   `json:"recommendations,omitempty"`
}

// ConfigValidationSummary provides a summary of configuration validation
type ConfigValidationSummary struct {
	TotalComponents      int `json:"total_components"`
	ValidComponents      int `json:"valid_components"`
	InvalidComponents    int `json:"invalid_components"`
	ComponentsWithWarnings int `json:"components_with_warnings"`
	CriticalErrors       int `json:"critical_errors"`
	HighSeverityErrors   int `json:"high_severity_errors"`
	MediumSeverityErrors int `json:"medium_severity_errors"`
	LowSeverityErrors    int `json:"low_severity_errors"`
}

// ConfigRecommendation represents a configuration recommendation
type ConfigRecommendation struct {
	Field        string                   `json:"field"`
	Current      interface{}              `json:"current"`
	Recommended  interface{}              `json:"recommended"`
	Reason       string                   `json:"reason"`
	Impact       string                   `json:"impact"`
	Priority     RecommendationPriority   `json:"priority"`
}

// PerformanceReport provides system performance analysis
type PerformanceReport struct {
	Timestamp        time.Time                        `json:"timestamp"`
	OverallScore     float64                          `json:"overall_score"` // 0-100
	SystemMetrics    *SystemMetrics                   `json:"system_metrics"`
	ComponentMetrics map[string]*ComponentMetrics     `json:"component_metrics"`
	Bottlenecks      []*PerformanceBottleneck         `json:"bottlenecks,omitempty"`
	Trends           *PerformanceTrends               `json:"trends,omitempty"`
	Recommendations  []*PerformanceRecommendation     `json:"recommendations,omitempty"`
}

// PerformanceBottleneck identifies performance bottlenecks
type PerformanceBottleneck struct {
	Component    string                   `json:"component"`
	Type         BottleneckType           `json:"type"`
	Severity     BottleneckSeverity       `json:"severity"`
	Description  string                   `json:"description"`
	Impact       string                   `json:"impact"`
	Suggestion   string                   `json:"suggestion"`
	Metrics      map[string]interface{}   `json:"metrics"`
}

// PerformanceTrends provides performance trend analysis
type PerformanceTrends struct {
	Period           time.Duration            `json:"period"`
	ResponseTime     *MetricTrend             `json:"response_time"`
	Throughput       *MetricTrend             `json:"throughput"`
	ErrorRate        *MetricTrend             `json:"error_rate"`
	ResourceUsage    *MetricTrend             `json:"resource_usage"`
}

// MetricTrend represents a trend for a specific metric
type MetricTrend struct {
	Direction        TrendDirection           `json:"direction"`
	ChangePercentage float64                  `json:"change_percentage"`
	Current          float64                  `json:"current"`
	Previous         float64                  `json:"previous"`
	Peak             float64                  `json:"peak"`
	Average          float64                  `json:"average"`
}

// PerformanceRecommendation provides performance improvement recommendations
type PerformanceRecommendation struct {
	Component    string                   `json:"component"`
	Type         RecommendationType       `json:"type"`
	Priority     RecommendationPriority   `json:"priority"`
	Title        string                   `json:"title"`
	Description  string                   `json:"description"`
	Action       string                   `json:"action"`
	ExpectedGain string                   `json:"expected_gain"`
	Effort       string                   `json:"effort"`
}

// SecurityStatusReport provides security status analysis
type SecurityStatusReport struct {
	Timestamp        time.Time                    `json:"timestamp"`
	SecurityScore    float64                      `json:"security_score"` // 0-100
	ThreatLevel      ThreatLevel                  `json:"threat_level"`
	ActiveThreats    []*SecurityThreat            `json:"active_threats,omitempty"`
	Vulnerabilities  []*SecurityVulnerability     `json:"vulnerabilities,omitempty"`
	ComplianceStatus *ComplianceStatus            `json:"compliance_status"`
	SecurityMetrics  *SecurityMetrics             `json:"security_metrics"`
	Recommendations  []*SecurityRecommendation    `json:"recommendations,omitempty"`
}

// SecurityThreat represents an active security threat
type SecurityThreat struct {
	ID           string                   `json:"id"`
	Type         ThreatType               `json:"type"`
	Severity     ThreatSeverity           `json:"severity"`
	Source       string                   `json:"source"`
	Target       string                   `json:"target"`
	Description  string                   `json:"description"`
	FirstSeen    time.Time                `json:"first_seen"`
	LastSeen     time.Time                `json:"last_seen"`
	Count        int                      `json:"count"`
	Status       ThreatStatus             `json:"status"`
	Details      map[string]interface{}   `json:"details"`
}

// SecurityVulnerability represents a security vulnerability
type SecurityVulnerability struct {
	ID           string                   `json:"id"`
	Component    string                   `json:"component"`
	Type         VulnerabilityType        `json:"type"`
	Severity     VulnerabilitySeverity    `json:"severity"`
	Title        string                   `json:"title"`
	Description  string                   `json:"description"`
	Impact       string                   `json:"impact"`
	Solution     string                   `json:"solution"`
	References   []string                 `json:"references,omitempty"`
	DiscoveredAt time.Time                `json:"discovered_at"`
	Status       VulnerabilityStatus      `json:"status"`
}

// ComplianceStatus represents compliance status
type ComplianceStatus struct {
	Overall      ComplianceLevel          `json:"overall"`
	Standards    map[string]*StandardCompliance `json:"standards"`
	LastAssessed time.Time                `json:"last_assessed"`
}

// StandardCompliance represents compliance with a specific standard
type StandardCompliance struct {
	Standard     string                   `json:"standard"`
	Level        ComplianceLevel          `json:"level"`
	Score        float64                  `json:"score"` // 0-100
	Requirements []*ComplianceRequirement `json:"requirements"`
}

// ComplianceRequirement represents a compliance requirement
type ComplianceRequirement struct {
	ID           string                   `json:"id"`
	Title        string                   `json:"title"`
	Status       ComplianceStatus         `json:"status"`
	Evidence     []string                 `json:"evidence,omitempty"`
	Gaps         []string                 `json:"gaps,omitempty"`
}

// SecurityRecommendation provides security improvement recommendations
type SecurityRecommendation struct {
	ID           string                   `json:"id"`
	Type         RecommendationType       `json:"type"`
	Priority     RecommendationPriority   `json:"priority"`
	Component    string                   `json:"component,omitempty"`
	Title        string                   `json:"title"`
	Description  string                   `json:"description"`
	Action       string                   `json:"action"`
	Impact       string                   `json:"impact"`
	References   []string                 `json:"references,omitempty"`
}

// ResourceUsageReport provides resource usage analysis
type ResourceUsageReport struct {
	Timestamp        time.Time                    `json:"timestamp"`
	SystemResources  *SystemResourceUsage         `json:"system_resources"`
	ComponentUsage   map[string]*ComponentResourceUsage `json:"component_usage"`
	Trends           *ResourceUsageTrends         `json:"trends,omitempty"`
	Predictions      *ResourceUsagePredictions    `json:"predictions,omitempty"`
	Recommendations  []*ResourceRecommendation    `json:"recommendations,omitempty"`
}

// SystemResourceUsage represents system-level resource usage
type SystemResourceUsage struct {
	CPU          *ResourceMetric          `json:"cpu"`
	Memory       *ResourceMetric          `json:"memory"`
	Disk         *ResourceMetric          `json:"disk"`
	Network      *ResourceMetric          `json:"network"`
	FileHandles  *ResourceMetric          `json:"file_handles"`
	Connections  *ResourceMetric          `json:"connections"`
}

// ComponentResourceUsage represents component-level resource usage
type ComponentResourceUsage struct {
	ComponentName string                   `json:"component_name"`
	CPU          *ResourceMetric          `json:"cpu"`
	Memory       *ResourceMetric          `json:"memory"`
	Connections  *ResourceMetric          `json:"connections"`
	Requests     *ResourceMetric          `json:"requests"`
}

// ResourceMetric represents a resource usage metric
type ResourceMetric struct {
	Current      float64                  `json:"current"`
	Maximum      float64                  `json:"maximum"`
	Average      float64                  `json:"average"`
	Peak         float64                  `json:"peak"`
	Utilization  float64                  `json:"utilization"` // 0-100
	Trend        TrendDirection           `json:"trend"`
}

// ResourceUsageTrends provides resource usage trend analysis
type ResourceUsageTrends struct {
	Period       time.Duration            `json:"period"`
	CPU          *MetricTrend             `json:"cpu"`
	Memory       *MetricTrend             `json:"memory"`
	Disk         *MetricTrend             `json:"disk"`
	Network      *MetricTrend             `json:"network"`
}

// ResourceUsagePredictions provides resource usage predictions
type ResourceUsagePredictions struct {
	TimeHorizon  time.Duration            `json:"time_horizon"`
	CPU          *ResourcePrediction      `json:"cpu"`
	Memory       *ResourcePrediction      `json:"memory"`
	Disk         *ResourcePrediction      `json:"disk"`
	Confidence   float64                  `json:"confidence"` // 0-100
}

// ResourcePrediction represents a resource usage prediction
type ResourcePrediction struct {
	Predicted    float64                  `json:"predicted"`
	Lower        float64                  `json:"lower"`
	Upper        float64                  `json:"upper"`
	Threshold    float64                  `json:"threshold"`
	TimeToThreshold time.Duration         `json:"time_to_threshold"`
}

// ResourceRecommendation provides resource optimization recommendations
type ResourceRecommendation struct {
	Type         RecommendationType       `json:"type"`
	Priority     RecommendationPriority   `json:"priority"`
	Resource     string                   `json:"resource"`
	Component    string                   `json:"component,omitempty"`
	Title        string                   `json:"title"`
	Description  string                   `json:"description"`
	Action       string                   `json:"action"`
	ExpectedSaving string                 `json:"expected_saving"`
}

// DependencyReport provides system dependency analysis
type DependencyReport struct {
	Timestamp    time.Time                    `json:"timestamp"`
	Dependencies []*SystemDependency          `json:"dependencies"`
	Graph        *DependencyGraph             `json:"graph"`
	CriticalPath []*DependencyNode            `json:"critical_path"`
	Risks        []*DependencyRisk            `json:"risks,omitempty"`
}

// SystemDependency represents a system dependency
type SystemDependency struct {
	Name         string                   `json:"name"`
	Type         DependencyType           `json:"type"`
	Status       DependencyStatus         `json:"status"`
	Version      string                   `json:"version"`
	Required     bool                     `json:"required"`
	Health       HealthStatus             `json:"health"`
	LastChecked  time.Time                `json:"last_checked"`
	Details      map[string]interface{}   `json:"details"`
}

// DependencyGraph represents the dependency graph
type DependencyGraph struct {
	Nodes []*DependencyNode            `json:"nodes"`
	Edges []*DependencyEdge            `json:"edges"`
}

// DependencyNode represents a node in the dependency graph
type DependencyNode struct {
	ID           string                   `json:"id"`
	Name         string                   `json:"name"`
	Type         DependencyType           `json:"type"`
	Critical     bool                     `json:"critical"`
	Status       DependencyStatus         `json:"status"`
}

// DependencyEdge represents an edge in the dependency graph
type DependencyEdge struct {
	From         string                   `json:"from"`
	To           string                   `json:"to"`
	Type         DependencyRelationType   `json:"type"`
	Required     bool                     `json:"required"`
}

// DependencyRisk represents a dependency-related risk
type DependencyRisk struct {
	Dependency   string                   `json:"dependency"`
	Type         RiskType                 `json:"type"`
	Severity     RiskSeverity             `json:"severity"`
	Description  string                   `json:"description"`
	Impact       string                   `json:"impact"`
	Mitigation   string                   `json:"mitigation"`
	Probability  float64                  `json:"probability"` // 0-1
}

// Enums for report types

// BottleneckType represents the type of performance bottleneck
type BottleneckType int

const (
	BottleneckCPU BottleneckType = iota
	BottleneckMemory
	BottleneckDisk
	BottleneckNetwork
	BottleneckDatabase
	BottleneckCache
	BottleneckLock
)

func (b BottleneckType) String() string {
	switch b {
	case BottleneckCPU:
		return "cpu"
	case BottleneckMemory:
		return "memory"
	case BottleneckDisk:
		return "disk"
	case BottleneckNetwork:
		return "network"
	case BottleneckDatabase:
		return "database"
	case BottleneckCache:
		return "cache"
	case BottleneckLock:
		return "lock"
	default:
		return "unknown"
	}
}

// BottleneckSeverity represents the severity of a bottleneck
type BottleneckSeverity int

const (
	BottleneckSeverityLow BottleneckSeverity = iota
	BottleneckSeverityMedium
	BottleneckSeverityHigh
	BottleneckSeverityCritical
)

func (b BottleneckSeverity) String() string {
	switch b {
	case BottleneckSeverityLow:
		return "low"
	case BottleneckSeverityMedium:
		return "medium"
	case BottleneckSeverityHigh:
		return "high"
	case BottleneckSeverityCritical:
		return "critical"
	default:
		return "low"
	}
}

// ThreatLevel represents the overall threat level
type ThreatLevel int

const (
	ThreatLevelLow ThreatLevel = iota
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

func (t ThreatLevel) String() string {
	switch t {
	case ThreatLevelLow:
		return "low"
	case ThreatLevelMedium:
		return "medium"
	case ThreatLevelHigh:
		return "high"
	case ThreatLevelCritical:
		return "critical"
	default:
		return "low"
	}
}

// ThreatType represents the type of security threat
type ThreatType int

const (
	ThreatTypeBruteForce ThreatType = iota
	ThreatTypeInjection
	ThreatTypeXSS
	ThreatTypeCSRF
	ThreatTypeDDoS
	ThreatTypePrivilegeEscalation
	ThreatTypeDataBreach
)

func (t ThreatType) String() string {
	switch t {
	case ThreatTypeBruteForce:
		return "brute_force"
	case ThreatTypeInjection:
		return "injection"
	case ThreatTypeXSS:
		return "xss"
	case ThreatTypeCSRF:
		return "csrf"
	case ThreatTypeDDoS:
		return "ddos"
	case ThreatTypePrivilegeEscalation:
		return "privilege_escalation"
	case ThreatTypeDataBreach:
		return "data_breach"
	default:
		return "unknown"
	}
}

// ThreatSeverity represents the severity of a threat
type ThreatSeverity int

const (
	ThreatSeverityLow ThreatSeverity = iota
	ThreatSeverityMedium
	ThreatSeverityHigh
	ThreatSeverityCritical
)

func (t ThreatSeverity) String() string {
	switch t {
	case ThreatSeverityLow:
		return "low"
	case ThreatSeverityMedium:
		return "medium"
	case ThreatSeverityHigh:
		return "high"
	case ThreatSeverityCritical:
		return "critical"
	default:
		return "low"
	}
}

// ThreatStatus represents the status of a threat
type ThreatStatus int

const (
	ThreatStatusActive ThreatStatus = iota
	ThreatStatusMitigated
	ThreatStatusResolved
	ThreatStatusIgnored
)

func (t ThreatStatus) String() string {
	switch t {
	case ThreatStatusActive:
		return "active"
	case ThreatStatusMitigated:
		return "mitigated"
	case ThreatStatusResolved:
		return "resolved"
	case ThreatStatusIgnored:
		return "ignored"
	default:
		return "active"
	}
}

// VulnerabilityType represents the type of vulnerability
type VulnerabilityType int

const (
	VulnerabilityTypeConfiguration VulnerabilityType = iota
	VulnerabilityTypeSoftware
	VulnerabilityTypeAccess
	VulnerabilityTypeEncryption
	VulnerabilityTypeAuthentication
	VulnerabilityTypeAuthorization
)

func (v VulnerabilityType) String() string {
	switch v {
	case VulnerabilityTypeConfiguration:
		return "configuration"
	case VulnerabilityTypeSoftware:
		return "software"
	case VulnerabilityTypeAccess:
		return "access"
	case VulnerabilityTypeEncryption:
		return "encryption"
	case VulnerabilityTypeAuthentication:
		return "authentication"
	case VulnerabilityTypeAuthorization:
		return "authorization"
	default:
		return "unknown"
	}
}

// VulnerabilitySeverity represents the severity of a vulnerability
type VulnerabilitySeverity int

const (
	VulnerabilitySeverityLow VulnerabilitySeverity = iota
	VulnerabilitySeverityMedium
	VulnerabilitySeverityHigh
	VulnerabilitySeverityCritical
)

func (v VulnerabilitySeverity) String() string {
	switch v {
	case VulnerabilitySeverityLow:
		return "low"
	case VulnerabilitySeverityMedium:
		return "medium"
	case VulnerabilitySeverityHigh:
		return "high"
	case VulnerabilitySeverityCritical:
		return "critical"
	default:
		return "low"
	}
}

// VulnerabilityStatus represents the status of a vulnerability
type VulnerabilityStatus int

const (
	VulnerabilityStatusOpen VulnerabilityStatus = iota
	VulnerabilityStatusInProgress
	VulnerabilityStatusFixed
	VulnerabilityStatusAccepted
	VulnerabilityStatusFalsePositive
)

func (v VulnerabilityStatus) String() string {
	switch v {
	case VulnerabilityStatusOpen:
		return "open"
	case VulnerabilityStatusInProgress:
		return "in_progress"
	case VulnerabilityStatusFixed:
		return "fixed"
	case VulnerabilityStatusAccepted:
		return "accepted"
	case VulnerabilityStatusFalsePositive:
		return "false_positive"
	default:
		return "open"
	}
}

// ComplianceLevel represents the level of compliance
type ComplianceLevel int

const (
	ComplianceLevelNone ComplianceLevel = iota
	ComplianceLevelPartial
	ComplianceLevelSubstantial
	ComplianceLevelFull
)

func (c ComplianceLevel) String() string {
	switch c {
	case ComplianceLevelNone:
		return "none"
	case ComplianceLevelPartial:
		return "partial"
	case ComplianceLevelSubstantial:
		return "substantial"
	case ComplianceLevelFull:
		return "full"
	default:
		return "none"
	}
}

// DependencyType represents the type of dependency
type DependencyType int

const (
	DependencyTypeService DependencyType = iota
	DependencyTypeDatabase
	DependencyTypeCache
	DependencyTypeQueue
	DependencyTypeStorage
	DependencyTypeExternal
	DependencyTypeLibrary
)

func (d DependencyType) String() string {
	switch d {
	case DependencyTypeService:
		return "service"
	case DependencyTypeDatabase:
		return "database"
	case DependencyTypeCache:
		return "cache"
	case DependencyTypeQueue:
		return "queue"
	case DependencyTypeStorage:
		return "storage"
	case DependencyTypeExternal:
		return "external"
	case DependencyTypeLibrary:
		return "library"
	default:
		return "unknown"
	}
}

// DependencyStatus represents the status of a dependency
type DependencyStatus int

const (
	DependencyStatusAvailable DependencyStatus = iota
	DependencyStatusUnavailable
	DependencyStatusDegraded
	DependencyStatusUnknown
)

func (d DependencyStatus) String() string {
	switch d {
	case DependencyStatusAvailable:
		return "available"
	case DependencyStatusUnavailable:
		return "unavailable"
	case DependencyStatusDegraded:
		return "degraded"
	case DependencyStatusUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// DependencyRelationType represents the type of dependency relationship
type DependencyRelationType int

const (
	DependencyRelationRequires DependencyRelationType = iota
	DependencyRelationOptional
	DependencyRelationProvides
	DependencyRelationConflicts
)

func (d DependencyRelationType) String() string {
	switch d {
	case DependencyRelationRequires:
		return "requires"
	case DependencyRelationOptional:
		return "optional"
	case DependencyRelationProvides:
		return "provides"
	case DependencyRelationConflicts:
		return "conflicts"
	default:
		return "unknown"
	}
}

// RiskType represents the type of risk
type RiskType int

const (
	RiskTypeAvailability RiskType = iota
	RiskTypePerformance
	RiskTypeSecurity
	RiskTypeCompliance
	RiskTypeOperational
)

func (r RiskType) String() string {
	switch r {
	case RiskTypeAvailability:
		return "availability"
	case RiskTypePerformance:
		return "performance"
	case RiskTypeSecurity:
		return "security"
	case RiskTypeCompliance:
		return "compliance"
	case RiskTypeOperational:
		return "operational"
	default:
		return "unknown"
	}
}

// RiskSeverity represents the severity of a risk
type RiskSeverity int

const (
	RiskSeverityLow RiskSeverity = iota
	RiskSeverityMedium
	RiskSeverityHigh
	RiskSeverityCritical
)

func (r RiskSeverity) String() string {
	switch r {
	case RiskSeverityLow:
		return "low"
	case RiskSeverityMedium:
		return "medium"
	case RiskSeverityHigh:
		return "high"
	case RiskSeverityCritical:
		return "critical"
	default:
		return "low"
	}
}