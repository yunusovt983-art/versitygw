package ipfs

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReplicationPolicyEngine_NewReplicationPolicyEngine tests policy engine creation
func TestReplicationPolicyEngine_NewReplicationPolicyEngine(t *testing.T) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine := NewReplicationPolicyEngine(config)
	
	assert.NotNil(t, engine)
	assert.NotNil(t, engine.policies)
	assert.NotNil(t, engine.defaultPolicy)
	assert.NotNil(t, engine.matchers)
	
	// Check default policy
	defaultPolicy := engine.GetPolicy("default")
	assert.Equal(t, "default", defaultPolicy.Name)
	assert.Equal(t, config.DefaultReplicas, defaultPolicy.BaseReplicas)
	assert.Equal(t, config.MinReplicas, defaultPolicy.MinReplicas)
	assert.Equal(t, config.MaxReplicas, defaultPolicy.MaxReplicas)
	
	// Check that common policies were created
	policies := engine.ListPolicies()
	assert.Contains(t, policies, "default")
	assert.Contains(t, policies, "high-availability")
	assert.Contains(t, policies, "cost-optimized")
	assert.Contains(t, policies, "archive")
}

// TestReplicationPolicyEngine_SetAndGetPolicy tests policy management
func TestReplicationPolicyEngine_SetAndGetPolicy(t *testing.T) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine := NewReplicationPolicyEngine(config)
	
	// Create a custom policy
	customPolicy := &ReplicationPolicy{
		Name:         "custom-test",
		Description:  "Custom test policy",
		BaseReplicas: 4,
		MinReplicas:  2,
		MaxReplicas:  8,
		AccessScaling: &AccessScalingPolicy{
			Enabled:             true,
			LowAccessThreshold:  5,
			HighAccessThreshold: 500,
			LowAccessMultiplier: 0.8,
			HighAccessMultiplier: 1.4,
		},
		IsActive: true,
	}
	
	// Set the policy
	err := engine.SetPolicy(customPolicy)
	assert.NoError(t, err)
	
	// Get the policy
	retrievedPolicy := engine.GetPolicy("custom-test")
	assert.NotNil(t, retrievedPolicy)
	assert.Equal(t, "custom-test", retrievedPolicy.Name)
	assert.Equal(t, "Custom test policy", retrievedPolicy.Description)
	assert.Equal(t, 4, retrievedPolicy.BaseReplicas)
	assert.Equal(t, 2, retrievedPolicy.MinReplicas)
	assert.Equal(t, 8, retrievedPolicy.MaxReplicas)
	assert.True(t, retrievedPolicy.IsActive)
	assert.NotZero(t, retrievedPolicy.CreatedAt)
	assert.NotZero(t, retrievedPolicy.UpdatedAt)
	assert.Equal(t, 1, retrievedPolicy.Version)
	
	// Update the policy
	customPolicy.Description = "Updated custom test policy"
	err = engine.SetPolicy(customPolicy)
	assert.NoError(t, err)
	
	// Verify version was incremented
	updatedPolicy := engine.GetPolicy("custom-test")
	assert.Equal(t, "Updated custom test policy", updatedPolicy.Description)
	assert.Equal(t, 2, updatedPolicy.Version)
}

// TestReplicationPolicyEngine_ValidatePolicy tests policy validation
func TestReplicationPolicyEngine_ValidatePolicy(t *testing.T) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine := NewReplicationPolicyEngine(config)
	
	tests := []struct {
		name        string
		policy      *ReplicationPolicy
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid policy",
			policy: &ReplicationPolicy{
				Name:         "valid",
				BaseReplicas: 3,
				MinReplicas:  2,
				MaxReplicas:  5,
			},
			expectError: false,
		},
		{
			name: "Invalid base replicas (zero)",
			policy: &ReplicationPolicy{
				Name:         "invalid-base",
				BaseReplicas: 0,
				MinReplicas:  2,
				MaxReplicas:  5,
			},
			expectError: true,
			errorMsg:    "base replicas must be at least 1",
		},
		{
			name: "Invalid min replicas (zero)",
			policy: &ReplicationPolicy{
				Name:         "invalid-min",
				BaseReplicas: 3,
				MinReplicas:  0,
				MaxReplicas:  5,
			},
			expectError: true,
			errorMsg:    "min replicas must be at least 1",
		},
		{
			name: "Max replicas less than min",
			policy: &ReplicationPolicy{
				Name:         "invalid-max",
				BaseReplicas: 3,
				MinReplicas:  5,
				MaxReplicas:  3,
			},
			expectError: true,
			errorMsg:    "max replicas must be >= min replicas",
		},
		{
			name: "Base replicas out of range",
			policy: &ReplicationPolicy{
				Name:         "invalid-base-range",
				BaseReplicas: 10,
				MinReplicas:  2,
				MaxReplicas:  5,
			},
			expectError: true,
			errorMsg:    "base replicas must be between min and max replicas",
		},
		{
			name: "Invalid access scaling thresholds",
			policy: &ReplicationPolicy{
				Name:         "invalid-access-scaling",
				BaseReplicas: 3,
				MinReplicas:  2,
				MaxReplicas:  5,
				AccessScaling: &AccessScalingPolicy{
					Enabled:             true,
					LowAccessThreshold:  100,
					HighAccessThreshold: 50,
				},
			},
			expectError: true,
			errorMsg:    "low access threshold must be < high access threshold",
		},
		{
			name: "Invalid access multipliers",
			policy: &ReplicationPolicy{
				Name:         "invalid-multipliers",
				BaseReplicas: 3,
				MinReplicas:  2,
				MaxReplicas:  5,
				AccessScaling: &AccessScalingPolicy{
					Enabled:              true,
					LowAccessThreshold:   10,
					HighAccessThreshold:  100,
					LowAccessMultiplier:  0,
					HighAccessMultiplier: 1.5,
				},
			},
			expectError: true,
			errorMsg:    "access multipliers must be positive",
		},
		{
			name: "Invalid geographic distance",
			policy: &ReplicationPolicy{
				Name:         "invalid-geo-distance",
				BaseReplicas: 3,
				MinReplicas:  2,
				MaxReplicas:  5,
				GeographicPolicy: &GeographicPolicy{
					Enabled:       true,
					MinDistanceKm: 1000,
					MaxDistanceKm: 500,
				},
			},
			expectError: true,
			errorMsg:    "max distance must be >= min distance",
		},
		{
			name: "Invalid availability",
			policy: &ReplicationPolicy{
				Name:         "invalid-availability",
				BaseReplicas: 3,
				MinReplicas:  2,
				MaxReplicas:  5,
				PerformancePolicy: &PerformancePolicy{
					Enabled:            true,
					TargetAvailability: 1.5,
				},
			},
			expectError: true,
			errorMsg:    "target availability must be between 0 and 1",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.validatePolicy(tt.policy)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestReplicationPolicyEngine_DeletePolicy tests policy deletion
func TestReplicationPolicyEngine_DeletePolicy(t *testing.T) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine := NewReplicationPolicyEngine(config)
	
	// Try to delete default policy (should fail)
	err := engine.DeletePolicy("default")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete default policy")
	
	// Create and delete a custom policy
	customPolicy := &ReplicationPolicy{
		Name:         "deletable",
		BaseReplicas: 3,
		MinReplicas:  2,
		MaxReplicas:  5,
	}
	
	err = engine.SetPolicy(customPolicy)
	assert.NoError(t, err)
	
	// Verify it exists
	policy := engine.GetPolicy("deletable")
	assert.Equal(t, "deletable", policy.Name)
	
	// Delete it
	err = engine.DeletePolicy("deletable")
	assert.NoError(t, err)
	
	// Verify it returns default policy now
	policy = engine.GetPolicy("deletable")
	assert.Equal(t, "default", policy.Name)
}

// TestReplicationPolicyEngine_PolicyMatchers tests policy matching
func TestReplicationPolicyEngine_PolicyMatchers(t *testing.T) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine := NewReplicationPolicyEngine(config)
	
	// Add policy matchers
	matchers := []*PolicyMatcher{
		{
			Name:               "high-priority-images",
			PolicyName:         "high-availability",
			Priority:           100,
			BucketPattern:      "important-.*",
			ContentTypePattern: "image/.*",
			SizeMin:            1024 * 1024, // 1MB
			Enabled:            true,
		},
		{
			Name:          "archive-bucket",
			PolicyName:    "archive",
			Priority:      50,
			BucketPattern: "archive",
			Enabled:       true,
		},
		{
			Name:       "large-files",
			PolicyName: "cost-optimized",
			Priority:   25,
			SizeMin:    100 * 1024 * 1024, // 100MB
			Enabled:    true,
		},
	}
	
	for _, matcher := range matchers {
		err := engine.AddPolicyMatcher(matcher)
		assert.NoError(t, err)
	}
	
	tests := []struct {
		name            string
		bucket          string
		key             string
		contentType     string
		size            int64
		expectedPolicy  string
	}{
		{
			name:           "High priority image",
			bucket:         "important-photos",
			key:            "photo.jpg",
			contentType:    "image/jpeg",
			size:           2 * 1024 * 1024,
			expectedPolicy: "high-availability",
		},
		{
			name:           "Archive bucket",
			bucket:         "archive",
			key:            "old-data.txt",
			contentType:    "text/plain",
			size:           1024,
			expectedPolicy: "archive",
		},
		{
			name:           "Large file",
			bucket:         "data",
			key:            "large-dataset.csv",
			contentType:    "text/csv",
			size:           200 * 1024 * 1024,
			expectedPolicy: "cost-optimized",
		},
		{
			name:           "No match - default",
			bucket:         "regular",
			key:            "document.pdf",
			contentType:    "application/pdf",
			size:           1024,
			expectedPolicy: "default",
		},
		{
			name:           "Small image - no match",
			bucket:         "important-photos",
			key:            "thumbnail.jpg",
			contentType:    "image/jpeg",
			size:           512, // Too small
			expectedPolicy: "default",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := engine.MatchPolicy(tt.bucket, tt.key, tt.contentType, tt.size, nil, nil)
			assert.Equal(t, tt.expectedPolicy, policy.Name)
		})
	}
}

// TestReplicationPolicyEngine_PolicyMatcherValidation tests matcher validation
func TestReplicationPolicyEngine_PolicyMatcherValidation(t *testing.T) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine := NewReplicationPolicyEngine(config)
	
	tests := []struct {
		name        string
		matcher     *PolicyMatcher
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid matcher",
			matcher: &PolicyMatcher{
				Name:       "valid-matcher",
				PolicyName: "default",
				Priority:   50,
				Enabled:    true,
			},
			expectError: false,
		},
		{
			name: "Empty name",
			matcher: &PolicyMatcher{
				PolicyName: "default",
				Priority:   50,
				Enabled:    true,
			},
			expectError: true,
			errorMsg:    "matcher name cannot be empty",
		},
		{
			name: "Empty policy name",
			matcher: &PolicyMatcher{
				Name:     "test-matcher",
				Priority: 50,
				Enabled:  true,
			},
			expectError: true,
			errorMsg:    "policy name cannot be empty",
		},
		{
			name: "Non-existent policy",
			matcher: &PolicyMatcher{
				Name:       "test-matcher",
				PolicyName: "non-existent",
				Priority:   50,
				Enabled:    true,
			},
			expectError: true,
			errorMsg:    "policy non-existent does not exist",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.AddPolicyMatcher(tt.matcher)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestReplicationPolicyEngine_MetadataAndTagMatching tests metadata and tag matching
func TestReplicationPolicyEngine_MetadataAndTagMatching(t *testing.T) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine := NewReplicationPolicyEngine(config)
	
	// Add matcher with metadata and tag patterns
	matcher := &PolicyMatcher{
		Name:       "metadata-matcher",
		PolicyName: "high-availability",
		Priority:   100,
		MetadataMatchers: map[string]string{
			"importance": "high|critical",
			"department": "engineering",
		},
		TagMatchers: map[string]string{
			"environment": "production",
			"backup":      "required",
		},
		Enabled: true,
	}
	
	err := engine.AddPolicyMatcher(matcher)
	assert.NoError(t, err)
	
	tests := []struct {
		name            string
		metadata        map[string]string
		tags            map[string]string
		expectedPolicy  string
	}{
		{
			name: "Matching metadata and tags",
			metadata: map[string]string{
				"importance": "high",
				"department": "engineering",
			},
			tags: map[string]string{
				"environment": "production",
				"backup":      "required",
			},
			expectedPolicy: "high-availability",
		},
		{
			name: "Missing metadata",
			metadata: map[string]string{
				"importance": "high",
				// Missing department
			},
			tags: map[string]string{
				"environment": "production",
				"backup":      "required",
			},
			expectedPolicy: "default",
		},
		{
			name: "Non-matching metadata value",
			metadata: map[string]string{
				"importance": "low",
				"department": "engineering",
			},
			tags: map[string]string{
				"environment": "production",
				"backup":      "required",
			},
			expectedPolicy: "default",
		},
		{
			name: "Missing tags",
			metadata: map[string]string{
				"importance": "critical",
				"department": "engineering",
			},
			tags: map[string]string{
				"environment": "production",
				// Missing backup tag
			},
			expectedPolicy: "default",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := engine.MatchPolicy("test-bucket", "test-key", "text/plain", 1024, tt.metadata, tt.tags)
			assert.Equal(t, tt.expectedPolicy, policy.Name)
		})
	}
}

// TestReplicationPolicyEngine_ExportImportPolicies tests policy export/import
func TestReplicationPolicyEngine_ExportImportPolicies(t *testing.T) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine1 := NewReplicationPolicyEngine(config)
	
	// Add a custom policy
	customPolicy := &ReplicationPolicy{
		Name:         "export-test",
		Description:  "Policy for export test",
		BaseReplicas: 4,
		MinReplicas:  2,
		MaxReplicas:  8,
		AccessScaling: &AccessScalingPolicy{
			Enabled:             true,
			LowAccessThreshold:  10,
			HighAccessThreshold: 1000,
			LowAccessMultiplier: 0.8,
			HighAccessMultiplier: 1.5,
		},
		IsActive: true,
	}
	
	err := engine1.SetPolicy(customPolicy)
	assert.NoError(t, err)
	
	// Export policies
	exportData, err := engine1.ExportPolicies()
	assert.NoError(t, err)
	assert.NotEmpty(t, exportData)
	
	// Verify export data is valid JSON
	var exportedPolicies map[string]*ReplicationPolicy
	err = json.Unmarshal(exportData, &exportedPolicies)
	assert.NoError(t, err)
	assert.Contains(t, exportedPolicies, "export-test")
	
	// Create new engine and import policies
	engine2 := NewReplicationPolicyEngine(config)
	
	err = engine2.ImportPolicies(exportData)
	assert.NoError(t, err)
	
	// Verify imported policy
	importedPolicy := engine2.GetPolicy("export-test")
	assert.Equal(t, "export-test", importedPolicy.Name)
	assert.Equal(t, "Policy for export test", importedPolicy.Description)
	assert.Equal(t, 4, importedPolicy.BaseReplicas)
	assert.NotNil(t, importedPolicy.AccessScaling)
	assert.True(t, importedPolicy.AccessScaling.Enabled)
	assert.Equal(t, int64(10), importedPolicy.AccessScaling.LowAccessThreshold)
}

// TestReplicationPolicyEngine_GetPolicyRecommendation tests policy recommendations
func TestReplicationPolicyEngine_GetPolicyRecommendation(t *testing.T) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine := NewReplicationPolicyEngine(config)
	
	tests := []struct {
		name               string
		bucket             string
		key                string
		contentType        string
		size               int64
		accessPattern      *AccessPattern
		expectedPolicy     string
	}{
		{
			name:           "Archive file",
			bucket:         "data",
			key:            "archive/old-data.txt",
			contentType:    "text/plain",
			size:           1024,
			accessPattern:  nil,
			expectedPolicy: "archive",
		},
		{
			name:        "High access global file",
			bucket:      "content",
			key:         "popular-image.jpg",
			contentType: "image/jpeg",
			size:        2 * 1024 * 1024,
			accessPattern: &AccessPattern{
				RecentAccesses: 500,
				GeographicAccess: map[string]int64{
					"us-east": 200,
					"us-west": 200,
					"eu-west": 100,
				},
			},
			expectedPolicy: "high-availability",
		},
		{
			name:        "Large infrequent file",
			bucket:      "storage",
			key:         "large-dataset.csv",
			contentType: "text/csv",
			size:        500 * 1024 * 1024,
			accessPattern: &AccessPattern{
				RecentAccesses: 5,
			},
			expectedPolicy: "cost-optimized",
		},
		{
			name:        "Frequent media file",
			bucket:      "media",
			key:         "video.mp4",
			contentType: "video/mp4",
			size:        50 * 1024 * 1024,
			accessPattern: &AccessPattern{
				RecentAccesses: 200,
			},
			expectedPolicy: "high-availability",
		},
		{
			name:           "Regular file",
			bucket:         "documents",
			key:            "report.pdf",
			contentType:    "application/pdf",
			size:           1024 * 1024,
			accessPattern:  nil,
			expectedPolicy: "default",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recommendation := engine.GetPolicyRecommendation(tt.bucket, tt.key, tt.contentType, tt.size, tt.accessPattern)
			assert.Equal(t, tt.expectedPolicy, recommendation)
		})
	}
}

// TestReplicationPolicyEngine_RemovePolicyMatcher tests matcher removal
func TestReplicationPolicyEngine_RemovePolicyMatcher(t *testing.T) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine := NewReplicationPolicyEngine(config)
	
	// Add a matcher
	matcher := &PolicyMatcher{
		Name:       "test-matcher",
		PolicyName: "default",
		Priority:   50,
		Enabled:    true,
	}
	
	err := engine.AddPolicyMatcher(matcher)
	assert.NoError(t, err)
	
	// Verify it was added
	matchers := engine.ListPolicyMatchers()
	assert.Len(t, matchers, 1)
	assert.Equal(t, "test-matcher", matchers[0].Name)
	
	// Remove it
	err = engine.RemovePolicyMatcher("test-matcher")
	assert.NoError(t, err)
	
	// Verify it was removed
	matchers = engine.ListPolicyMatchers()
	assert.Len(t, matchers, 0)
	
	// Try to remove non-existent matcher
	err = engine.RemovePolicyMatcher("non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "matcher non-existent not found")
}

// TestReplicationPolicyEngine_MatcherPriority tests matcher priority ordering
func TestReplicationPolicyEngine_MatcherPriority(t *testing.T) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine := NewReplicationPolicyEngine(config)
	
	// Add matchers with different priorities
	matchers := []*PolicyMatcher{
		{
			Name:          "low-priority",
			PolicyName:    "cost-optimized",
			Priority:      10,
			BucketPattern: "test",
			Enabled:       true,
		},
		{
			Name:          "high-priority",
			PolicyName:    "high-availability",
			Priority:      100,
			BucketPattern: "test",
			Enabled:       true,
		},
		{
			Name:          "medium-priority",
			PolicyName:    "archive",
			Priority:      50,
			BucketPattern: "test",
			Enabled:       true,
		},
	}
	
	for _, matcher := range matchers {
		err := engine.AddPolicyMatcher(matcher)
		assert.NoError(t, err)
	}
	
	// Test that highest priority matcher wins
	policy := engine.MatchPolicy("test", "file.txt", "text/plain", 1024, nil, nil)
	assert.Equal(t, "high-availability", policy.Name)
}

// BenchmarkReplicationPolicyEngine_MatchPolicy benchmarks policy matching
func BenchmarkReplicationPolicyEngine_MatchPolicy(b *testing.B) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine := NewReplicationPolicyEngine(config)
	
	// Add several matchers
	for i := 0; i < 10; i++ {
		matcher := &PolicyMatcher{
			Name:          "matcher-" + string(rune(i)),
			PolicyName:    "default",
			Priority:      i * 10,
			BucketPattern: "bucket-" + string(rune(i)),
			Enabled:       true,
		}
		engine.AddPolicyMatcher(matcher)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		engine.MatchPolicy("test-bucket", "test-key", "text/plain", 1024, nil, nil)
	}
}

// BenchmarkReplicationPolicyEngine_ValidatePolicy benchmarks policy validation
func BenchmarkReplicationPolicyEngine_ValidatePolicy(b *testing.B) {
	config := &ReplicaConfig{
		MinReplicas:     2,
		MaxReplicas:     10,
		DefaultReplicas: 3,
	}
	
	engine := NewReplicationPolicyEngine(config)
	
	policy := &ReplicationPolicy{
		Name:         "benchmark-policy",
		BaseReplicas: 3,
		MinReplicas:  2,
		MaxReplicas:  5,
		AccessScaling: &AccessScalingPolicy{
			Enabled:             true,
			LowAccessThreshold:  10,
			HighAccessThreshold: 1000,
			LowAccessMultiplier: 0.8,
			HighAccessMultiplier: 1.5,
		},
		GeographicPolicy: &GeographicPolicy{
			Enabled:       true,
			MinDistanceKm: 100,
			MaxDistanceKm: 5000,
		},
		PerformancePolicy: &PerformancePolicy{
			Enabled:            true,
			TargetAvailability: 0.999,
			MaxErrorRate:       0.001,
		},
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		engine.validatePolicy(policy)
	}
}