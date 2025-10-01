package ipfs

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ReplicationPolicyEngine manages replication policies for different types of data
type ReplicationPolicyEngine struct {
	policies      map[string]*ReplicationPolicy
	defaultPolicy *ReplicationPolicy
	policyMutex   sync.RWMutex
	
	// Policy matching
	matchers      []*PolicyMatcher
	matcherMutex  sync.RWMutex
}

// ReplicationPolicy defines how objects should be replicated
type ReplicationPolicy struct {
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	
	// Basic replication settings
	BaseReplicas        int                    `json:"base_replicas"`
	MinReplicas         int                    `json:"min_replicas"`
	MaxReplicas         int                    `json:"max_replicas"`
	
	// Access-based scaling
	AccessScaling       *AccessScalingPolicy   `json:"access_scaling,omitempty"`
	
	// Geographic distribution
	GeographicPolicy    *GeographicPolicy      `json:"geographic_policy,omitempty"`
	
	// Time-based policies
	TimeBasedPolicy     *TimeBasedPolicy       `json:"time_based_policy,omitempty"`
	
	// Performance requirements
	PerformancePolicy   *PerformancePolicy     `json:"performance_policy,omitempty"`
	
	// Cost optimization
	CostPolicy          *CostPolicy            `json:"cost_policy,omitempty"`
	
	// Lifecycle management
	LifecyclePolicy     *LifecyclePolicy       `json:"lifecycle_policy,omitempty"`
	
	// Metadata
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
	Version             int                    `json:"version"`
	IsActive            bool                   `json:"is_active"`
}

// AccessScalingPolicy defines how replication scales with access patterns
type AccessScalingPolicy struct {
	Enabled             bool                   `json:"enabled"`
	
	// Scaling thresholds
	LowAccessThreshold  int64                  `json:"low_access_threshold"`
	HighAccessThreshold int64                  `json:"high_access_threshold"`
	
	// Scaling factors
	LowAccessMultiplier float64                `json:"low_access_multiplier"`
	HighAccessMultiplier float64               `json:"high_access_multiplier"`
	
	// Trend-based scaling
	TrendScaling        map[AccessTrend]float64 `json:"trend_scaling"`
	
	// Time windows for analysis
	ShortTermWindow     time.Duration          `json:"short_term_window"`
	LongTermWindow      time.Duration          `json:"long_term_window"`
}

// GeographicPolicy defines geographic distribution requirements
type GeographicPolicy struct {
	Enabled             bool                   `json:"enabled"`
	
	// Distribution strategy
	Strategy            GeographicStrategy     `json:"strategy"`
	
	// Region requirements
	RequiredRegions     []string               `json:"required_regions"`
	PreferredRegions    []string               `json:"preferred_regions"`
	ExcludedRegions     []string               `json:"excluded_regions"`
	
	// Distance constraints
	MinDistanceKm       float64                `json:"min_distance_km"`
	MaxDistanceKm       float64                `json:"max_distance_km"`
	
	// Regional weights
	RegionWeights       map[string]float64     `json:"region_weights"`
	
	// Latency requirements
	MaxLatencyMs        int                    `json:"max_latency_ms"`
}

// GeographicStrategy defines how replicas are distributed geographically
type GeographicStrategy int

const (
	GeoStrategyBalanced GeographicStrategy = iota // Distribute evenly across regions
	GeoStrategyLatency                            // Optimize for low latency
	GeoStrategyCompliance                         // Follow data residency requirements
	GeoStrategyCustom                             // Use custom weights
)

// TimeBasedPolicy defines time-based replication behavior
type TimeBasedPolicy struct {
	Enabled             bool                   `json:"enabled"`
	
	// Scheduled scaling
	ScheduledScaling    []*ScheduledScale      `json:"scheduled_scaling"`
	
	// Seasonal adjustments
	SeasonalAdjustments []*SeasonalAdjustment  `json:"seasonal_adjustments"`
	
	// Time zone considerations
	TimeZone            string                 `json:"time_zone"`
}

// ScheduledScale defines scheduled replication changes
type ScheduledScale struct {
	Name                string                 `json:"name"`
	CronExpression      string                 `json:"cron_expression"`
	ReplicaMultiplier   float64                `json:"replica_multiplier"`
	Duration            time.Duration          `json:"duration"`
	Enabled             bool                   `json:"enabled"`
}

// SeasonalAdjustment defines seasonal replication adjustments
type SeasonalAdjustment struct {
	Name                string                 `json:"name"`
	StartDate           string                 `json:"start_date"` // MM-DD format
	EndDate             string                 `json:"end_date"`   // MM-DD format
	ReplicaMultiplier   float64                `json:"replica_multiplier"`
	Enabled             bool                   `json:"enabled"`
}

// PerformancePolicy defines performance-based replication requirements
type PerformancePolicy struct {
	Enabled             bool                   `json:"enabled"`
	
	// Latency requirements
	MaxLatency          time.Duration          `json:"max_latency"`
	TargetLatency       time.Duration          `json:"target_latency"`
	
	// Throughput requirements
	MinThroughputMBps   float64                `json:"min_throughput_mbps"`
	TargetThroughputMBps float64               `json:"target_throughput_mbps"`
	
	// Availability requirements
	TargetAvailability  float64                `json:"target_availability"` // 0.0 to 1.0
	
	// Error tolerance
	MaxErrorRate        float64                `json:"max_error_rate"` // 0.0 to 1.0
}

// CostPolicy defines cost optimization settings
type CostPolicy struct {
	Enabled             bool                   `json:"enabled"`
	
	// Budget constraints
	MaxMonthlyCost      float64                `json:"max_monthly_cost"`
	CostPerGBMonth      float64                `json:"cost_per_gb_month"`
	
	// Cost optimization strategies
	PreferCheapRegions  bool                   `json:"prefer_cheap_regions"`
	RegionCosts         map[string]float64     `json:"region_costs"`
	
	// Trade-offs
	AcceptHigherLatency bool                   `json:"accept_higher_latency"`
	AcceptLowerAvailability bool               `json:"accept_lower_availability"`
}

// LifecyclePolicy defines lifecycle management for replicas
type LifecyclePolicy struct {
	Enabled             bool                   `json:"enabled"`
	
	// Age-based policies
	AgeBasedScaling     []*AgeBasedScale       `json:"age_based_scaling"`
	
	// Access-based lifecycle
	InactiveThreshold   time.Duration          `json:"inactive_threshold"`
	InactiveAction      LifecycleAction        `json:"inactive_action"`
	
	// Archival policies
	ArchivalRules       []*ArchivalRule        `json:"archival_rules"`
}

// AgeBasedScale defines replication changes based on object age
type AgeBasedScale struct {
	Name                string                 `json:"name"`
	MinAge              time.Duration          `json:"min_age"`
	MaxAge              time.Duration          `json:"max_age"`
	ReplicaMultiplier   float64                `json:"replica_multiplier"`
	Enabled             bool                   `json:"enabled"`
}

// LifecycleAction defines what action to take during lifecycle management
type LifecycleAction int

const (
	ActionReduceReplicas LifecycleAction = iota
	ActionArchive
	ActionDelete
	ActionNoAction
)

// ArchivalRule defines rules for archiving objects
type ArchivalRule struct {
	Name                string                 `json:"name"`
	Condition           string                 `json:"condition"` // Expression to evaluate
	ArchivalTier        string                 `json:"archival_tier"`
	ReplicaReduction    int                    `json:"replica_reduction"`
	Enabled             bool                   `json:"enabled"`
}

// PolicyMatcher matches objects to policies based on various criteria
type PolicyMatcher struct {
	Name                string                 `json:"name"`
	PolicyName          string                 `json:"policy_name"`
	Priority            int                    `json:"priority"`
	
	// Matching criteria
	BucketPattern       string                 `json:"bucket_pattern,omitempty"`
	KeyPattern          string                 `json:"key_pattern,omitempty"`
	ContentTypePattern  string                 `json:"content_type_pattern,omitempty"`
	SizeMin             int64                  `json:"size_min,omitempty"`
	SizeMax             int64                  `json:"size_max,omitempty"`
	
	// Metadata matching
	MetadataMatchers    map[string]string      `json:"metadata_matchers,omitempty"`
	TagMatchers         map[string]string      `json:"tag_matchers,omitempty"`
	
	// Compiled patterns
	bucketRegex         *regexp.Regexp
	keyRegex            *regexp.Regexp
	contentTypeRegex    *regexp.Regexp
	
	Enabled             bool                   `json:"enabled"`
}

// NewReplicationPolicyEngine creates a new replication policy engine
func NewReplicationPolicyEngine(config *ReplicaConfig) *ReplicationPolicyEngine {
	engine := &ReplicationPolicyEngine{
		policies: make(map[string]*ReplicationPolicy),
		matchers: make([]*PolicyMatcher, 0),
	}
	
	// Create default policy
	engine.defaultPolicy = &ReplicationPolicy{
		Name:         "default",
		Description:  "Default replication policy",
		BaseReplicas: config.DefaultReplicas,
		MinReplicas:  config.MinReplicas,
		MaxReplicas:  config.MaxReplicas,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Version:      1,
		IsActive:     true,
	}
	
	engine.policies["default"] = engine.defaultPolicy
	
	// Initialize with common policies
	engine.initializeCommonPolicies()
	
	return engine
}

// initializeCommonPolicies creates common replication policies
func (rpe *ReplicationPolicyEngine) initializeCommonPolicies() {
	// High availability policy
	highAvailPolicy := &ReplicationPolicy{
		Name:         "high-availability",
		Description:  "High availability policy for critical data",
		BaseReplicas: 5,
		MinReplicas:  3,
		MaxReplicas:  10,
		AccessScaling: &AccessScalingPolicy{
			Enabled:             true,
			LowAccessThreshold:  10,
			HighAccessThreshold: 1000,
			LowAccessMultiplier: 0.8,
			HighAccessMultiplier: 1.5,
			TrendScaling: map[AccessTrend]float64{
				TrendIncreasing: 1.3,
				TrendDecreasing: 0.9,
				TrendSpiky:      1.4,
				TrendSeasonal:   1.1,
				TrendStable:     1.0,
			},
			ShortTermWindow: 1 * time.Hour,
			LongTermWindow:  24 * time.Hour,
		},
		GeographicPolicy: &GeographicPolicy{
			Enabled:         true,
			Strategy:        GeoStrategyBalanced,
			RequiredRegions: []string{"us-east", "us-west", "eu-west"},
			MinDistanceKm:   500.0,
			MaxLatencyMs:    100,
		},
		PerformancePolicy: &PerformancePolicy{
			Enabled:              true,
			MaxLatency:           50 * time.Millisecond,
			TargetLatency:        20 * time.Millisecond,
			MinThroughputMBps:    100.0,
			TargetThroughputMBps: 500.0,
			TargetAvailability:   0.9999,
			MaxErrorRate:         0.0001,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Version:   1,
		IsActive:  true,
	}
	rpe.policies["high-availability"] = highAvailPolicy
	
	// Cost-optimized policy
	costOptimizedPolicy := &ReplicationPolicy{
		Name:         "cost-optimized",
		Description:  "Cost-optimized policy for less critical data",
		BaseReplicas: 2,
		MinReplicas:  2,
		MaxReplicas:  4,
		AccessScaling: &AccessScalingPolicy{
			Enabled:             true,
			LowAccessThreshold:  5,
			HighAccessThreshold: 100,
			LowAccessMultiplier: 1.0, // Don't reduce below minimum
			HighAccessMultiplier: 1.2, // Conservative scaling
			ShortTermWindow: 6 * time.Hour,
			LongTermWindow:  7 * 24 * time.Hour,
		},
		GeographicPolicy: &GeographicPolicy{
			Enabled:         true,
			Strategy:        GeoStrategyCustom,
			PreferredRegions: []string{"us-central", "eu-central"},
			MinDistanceKm:   100.0,
			MaxLatencyMs:    500,
		},
		CostPolicy: &CostPolicy{
			Enabled:                 true,
			MaxMonthlyCost:          100.0,
			CostPerGBMonth:          0.02,
			PreferCheapRegions:      true,
			AcceptHigherLatency:     true,
			AcceptLowerAvailability: true,
		},
		LifecyclePolicy: &LifecyclePolicy{
			Enabled: true,
			AgeBasedScaling: []*AgeBasedScale{
				{
					Name:              "reduce-old-data",
					MinAge:            30 * 24 * time.Hour,
					MaxAge:            365 * 24 * time.Hour,
					ReplicaMultiplier: 0.5,
					Enabled:           true,
				},
			},
			InactiveThreshold: 7 * 24 * time.Hour,
			InactiveAction:    ActionReduceReplicas,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Version:   1,
		IsActive:  true,
	}
	rpe.policies["cost-optimized"] = costOptimizedPolicy
	
	// Archive policy
	archivePolicy := &ReplicationPolicy{
		Name:         "archive",
		Description:  "Archive policy for long-term storage",
		BaseReplicas: 3,
		MinReplicas:  2,
		MaxReplicas:  3,
		AccessScaling: &AccessScalingPolicy{
			Enabled:             false, // No scaling for archive data
		},
		GeographicPolicy: &GeographicPolicy{
			Enabled:         true,
			Strategy:        GeoStrategyBalanced,
			RequiredRegions: []string{"us-central", "eu-central"},
			MinDistanceKm:   1000.0,
		},
		CostPolicy: &CostPolicy{
			Enabled:                 true,
			PreferCheapRegions:      true,
			AcceptHigherLatency:     true,
			AcceptLowerAvailability: true,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Version:   1,
		IsActive:  true,
	}
	rpe.policies["archive"] = archivePolicy
}

// GetPolicy returns a policy by name
func (rpe *ReplicationPolicyEngine) GetPolicy(name string) *ReplicationPolicy {
	rpe.policyMutex.RLock()
	defer rpe.policyMutex.RUnlock()
	
	if policy, exists := rpe.policies[name]; exists {
		return policy
	}
	
	return rpe.defaultPolicy
}

// SetPolicy adds or updates a replication policy
func (rpe *ReplicationPolicyEngine) SetPolicy(policy *ReplicationPolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name cannot be empty")
	}
	
	// Validate policy
	if err := rpe.validatePolicy(policy); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}
	
	rpe.policyMutex.Lock()
	defer rpe.policyMutex.Unlock()
	
	// Update timestamps
	if existing, exists := rpe.policies[policy.Name]; exists {
		policy.CreatedAt = existing.CreatedAt
		policy.Version = existing.Version + 1
	} else {
		policy.CreatedAt = time.Now()
		policy.Version = 1
	}
	policy.UpdatedAt = time.Now()
	
	rpe.policies[policy.Name] = policy
	return nil
}

// DeletePolicy removes a policy
func (rpe *ReplicationPolicyEngine) DeletePolicy(name string) error {
	if name == "default" {
		return fmt.Errorf("cannot delete default policy")
	}
	
	rpe.policyMutex.Lock()
	defer rpe.policyMutex.Unlock()
	
	delete(rpe.policies, name)
	return nil
}

// ListPolicies returns all policies
func (rpe *ReplicationPolicyEngine) ListPolicies() map[string]*ReplicationPolicy {
	rpe.policyMutex.RLock()
	defer rpe.policyMutex.RUnlock()
	
	// Return a copy
	policies := make(map[string]*ReplicationPolicy)
	for name, policy := range rpe.policies {
		policies[name] = policy
	}
	
	return policies
}

// MatchPolicy finds the best matching policy for an object
func (rpe *ReplicationPolicyEngine) MatchPolicy(bucket, key, contentType string, size int64, metadata, tags map[string]string) *ReplicationPolicy {
	rpe.matcherMutex.RLock()
	defer rpe.matcherMutex.RUnlock()
	
	// Sort matchers by priority (higher priority first)
	matchers := make([]*PolicyMatcher, len(rpe.matchers))
	copy(matchers, rpe.matchers)
	
	for i := 0; i < len(matchers)-1; i++ {
		for j := i + 1; j < len(matchers); j++ {
			if matchers[i].Priority < matchers[j].Priority {
				matchers[i], matchers[j] = matchers[j], matchers[i]
			}
		}
	}
	
	// Find first matching policy
	for _, matcher := range matchers {
		if !matcher.Enabled {
			continue
		}
		
		if rpe.matchesCriteria(matcher, bucket, key, contentType, size, metadata, tags) {
			return rpe.GetPolicy(matcher.PolicyName)
		}
	}
	
	// Return default policy if no match
	return rpe.defaultPolicy
}

// matchesCriteria checks if an object matches a policy matcher's criteria
func (rpe *ReplicationPolicyEngine) matchesCriteria(matcher *PolicyMatcher, bucket, key, contentType string, size int64, metadata, tags map[string]string) bool {
	// Check bucket pattern
	if matcher.BucketPattern != "" {
		if matcher.bucketRegex == nil {
			regex, err := regexp.Compile(matcher.BucketPattern)
			if err != nil {
				return false
			}
			matcher.bucketRegex = regex
		}
		if !matcher.bucketRegex.MatchString(bucket) {
			return false
		}
	}
	
	// Check key pattern
	if matcher.KeyPattern != "" {
		if matcher.keyRegex == nil {
			regex, err := regexp.Compile(matcher.KeyPattern)
			if err != nil {
				return false
			}
			matcher.keyRegex = regex
		}
		if !matcher.keyRegex.MatchString(key) {
			return false
		}
	}
	
	// Check content type pattern
	if matcher.ContentTypePattern != "" {
		if matcher.contentTypeRegex == nil {
			regex, err := regexp.Compile(matcher.ContentTypePattern)
			if err != nil {
				return false
			}
			matcher.contentTypeRegex = regex
		}
		if !matcher.contentTypeRegex.MatchString(contentType) {
			return false
		}
	}
	
	// Check size constraints
	if matcher.SizeMin > 0 && size < matcher.SizeMin {
		return false
	}
	if matcher.SizeMax > 0 && size > matcher.SizeMax {
		return false
	}
	
	// Check metadata matchers
	for key, pattern := range matcher.MetadataMatchers {
		value, exists := metadata[key]
		if !exists {
			return false
		}
		matched, err := regexp.MatchString(pattern, value)
		if err != nil || !matched {
			return false
		}
	}
	
	// Check tag matchers
	for key, pattern := range matcher.TagMatchers {
		value, exists := tags[key]
		if !exists {
			return false
		}
		matched, err := regexp.MatchString(pattern, value)
		if err != nil || !matched {
			return false
		}
	}
	
	return true
}

// AddPolicyMatcher adds a new policy matcher
func (rpe *ReplicationPolicyEngine) AddPolicyMatcher(matcher *PolicyMatcher) error {
	if matcher.Name == "" {
		return fmt.Errorf("matcher name cannot be empty")
	}
	if matcher.PolicyName == "" {
		return fmt.Errorf("policy name cannot be empty")
	}
	
	// Validate that the policy exists
	if _, exists := rpe.policies[matcher.PolicyName]; !exists {
		return fmt.Errorf("policy %s does not exist", matcher.PolicyName)
	}
	
	rpe.matcherMutex.Lock()
	defer rpe.matcherMutex.Unlock()
	
	// Remove existing matcher with same name
	for i, existing := range rpe.matchers {
		if existing.Name == matcher.Name {
			rpe.matchers = append(rpe.matchers[:i], rpe.matchers[i+1:]...)
			break
		}
	}
	
	rpe.matchers = append(rpe.matchers, matcher)
	return nil
}

// RemovePolicyMatcher removes a policy matcher
func (rpe *ReplicationPolicyEngine) RemovePolicyMatcher(name string) error {
	rpe.matcherMutex.Lock()
	defer rpe.matcherMutex.Unlock()
	
	for i, matcher := range rpe.matchers {
		if matcher.Name == name {
			rpe.matchers = append(rpe.matchers[:i], rpe.matchers[i+1:]...)
			return nil
		}
	}
	
	return fmt.Errorf("matcher %s not found", name)
}

// ListPolicyMatchers returns all policy matchers
func (rpe *ReplicationPolicyEngine) ListPolicyMatchers() []*PolicyMatcher {
	rpe.matcherMutex.RLock()
	defer rpe.matcherMutex.RUnlock()
	
	// Return a copy
	matchers := make([]*PolicyMatcher, len(rpe.matchers))
	copy(matchers, rpe.matchers)
	
	return matchers
}

// validatePolicy validates a replication policy
func (rpe *ReplicationPolicyEngine) validatePolicy(policy *ReplicationPolicy) error {
	if policy.BaseReplicas < 1 {
		return fmt.Errorf("base replicas must be at least 1")
	}
	if policy.MinReplicas < 1 {
		return fmt.Errorf("min replicas must be at least 1")
	}
	if policy.MaxReplicas < policy.MinReplicas {
		return fmt.Errorf("max replicas must be >= min replicas")
	}
	if policy.BaseReplicas < policy.MinReplicas || policy.BaseReplicas > policy.MaxReplicas {
		return fmt.Errorf("base replicas must be between min and max replicas")
	}
	
	// Validate access scaling policy
	if policy.AccessScaling != nil && policy.AccessScaling.Enabled {
		if policy.AccessScaling.LowAccessThreshold >= policy.AccessScaling.HighAccessThreshold {
			return fmt.Errorf("low access threshold must be < high access threshold")
		}
		if policy.AccessScaling.LowAccessMultiplier <= 0 || policy.AccessScaling.HighAccessMultiplier <= 0 {
			return fmt.Errorf("access multipliers must be positive")
		}
	}
	
	// Validate geographic policy
	if policy.GeographicPolicy != nil && policy.GeographicPolicy.Enabled {
		if policy.GeographicPolicy.MinDistanceKm < 0 {
			return fmt.Errorf("min distance cannot be negative")
		}
		if policy.GeographicPolicy.MaxDistanceKm > 0 && policy.GeographicPolicy.MaxDistanceKm < policy.GeographicPolicy.MinDistanceKm {
			return fmt.Errorf("max distance must be >= min distance")
		}
	}
	
	// Validate performance policy
	if policy.PerformancePolicy != nil && policy.PerformancePolicy.Enabled {
		if policy.PerformancePolicy.TargetAvailability < 0 || policy.PerformancePolicy.TargetAvailability > 1 {
			return fmt.Errorf("target availability must be between 0 and 1")
		}
		if policy.PerformancePolicy.MaxErrorRate < 0 || policy.PerformancePolicy.MaxErrorRate > 1 {
			return fmt.Errorf("max error rate must be between 0 and 1")
		}
	}
	
	return nil
}

// ExportPolicies exports all policies to JSON
func (rpe *ReplicationPolicyEngine) ExportPolicies() ([]byte, error) {
	rpe.policyMutex.RLock()
	defer rpe.policyMutex.RUnlock()
	
	return json.MarshalIndent(rpe.policies, "", "  ")
}

// ImportPolicies imports policies from JSON
func (rpe *ReplicationPolicyEngine) ImportPolicies(data []byte) error {
	var policies map[string]*ReplicationPolicy
	if err := json.Unmarshal(data, &policies); err != nil {
		return fmt.Errorf("failed to unmarshal policies: %w", err)
	}
	
	// Validate all policies before importing
	for name, policy := range policies {
		policy.Name = name // Ensure name matches key
		if err := rpe.validatePolicy(policy); err != nil {
			return fmt.Errorf("invalid policy %s: %w", name, err)
		}
	}
	
	// Import policies
	rpe.policyMutex.Lock()
	defer rpe.policyMutex.Unlock()
	
	for name, policy := range policies {
		if name != "default" { // Don't overwrite default policy
			rpe.policies[name] = policy
		}
	}
	
	return nil
}

// GetPolicyRecommendation recommends a policy based on object characteristics and access patterns
func (rpe *ReplicationPolicyEngine) GetPolicyRecommendation(bucket, key, contentType string, size int64, accessPattern *AccessPattern) string {
	// Analyze object characteristics
	isLargeFile := size > 100*1024*1024 // 100MB
	isFrequentlyAccessed := accessPattern != nil && accessPattern.RecentAccesses > 100
	isGloballyAccessed := accessPattern != nil && len(accessPattern.GeographicAccess) > 2
	
	// Determine file type
	isMediaFile := strings.HasPrefix(contentType, "image/") || strings.HasPrefix(contentType, "video/") || strings.HasPrefix(contentType, "audio/")
	isDocumentFile := strings.HasPrefix(contentType, "application/pdf") || strings.HasPrefix(contentType, "application/msword")
	isArchiveFile := strings.Contains(key, "archive/") || strings.Contains(key, "backup/")
	
	// Make recommendation based on characteristics
	if isArchiveFile {
		return "archive"
	}
	
	if isFrequentlyAccessed && isGloballyAccessed {
		return "high-availability"
	}
	
	if isLargeFile && !isFrequentlyAccessed {
		return "cost-optimized"
	}
	
	if isMediaFile && isFrequentlyAccessed {
		return "high-availability"
	}
	
	// Default recommendation
	return "default"
}