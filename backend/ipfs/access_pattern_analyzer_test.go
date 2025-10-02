package ipfs

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAccessPatternAnalyzer(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	analysisWindow := 24 * time.Hour

	apa := NewAccessPatternAnalyzer(mockMetadata, analysisWindow, logger)

	assert.NotNil(t, apa)
	assert.Equal(t, mockMetadata, apa.metadataStore)
	assert.Equal(t, analysisWindow, apa.analysisWindow)
	assert.NotNil(t, apa.accessPatterns)
	assert.NotNil(t, apa.accessHistory)
	assert.NotNil(t, apa.statistics)
}

func TestAccessPatternAnalyzer_RecordAccess(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	cid := "QmTest123"
	event := AccessEvent{
		Timestamp:     time.Now(),
		ClientIP:      "192.168.1.1",
		UserAgent:     "test-agent",
		GeographicLoc: "US",
		AccessType:    AccessTypeRead,
		ResponseTime:  100 * time.Millisecond,
		BytesServed:   1024,
	}

	apa.RecordAccess(cid, event)

	// Verify pattern was created
	pattern, err := apa.GetAccessPattern(cid)
	assert.NoError(t, err)
	assert.NotNil(t, pattern)

	assert.Equal(t, cid, pattern.CID)
	assert.Equal(t, int64(1), pattern.AccessCount)
	assert.Equal(t, event.Timestamp, pattern.LastAccess)
	assert.Equal(t, event.Timestamp, pattern.FirstAccess)
	assert.Equal(t, int64(1), pattern.GeographicAccess["US"])
	assert.Equal(t, int64(1), pattern.UserAgentPatterns["test-agent"])

	// Record another access
	event2 := AccessEvent{
		Timestamp:     time.Now().Add(1 * time.Hour),
		ClientIP:      "192.168.1.2",
		UserAgent:     "test-agent",
		GeographicLoc: "US",
		AccessType:    AccessTypeRead,
	}

	apa.RecordAccess(cid, event2)

	pattern, err = apa.GetAccessPattern(cid)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), pattern.AccessCount)
	assert.Equal(t, int64(2), pattern.GeographicAccess["US"])
	assert.Equal(t, int64(2), pattern.UserAgentPatterns["test-agent"])
}

func TestAccessPatternAnalyzer_GetHotObjects(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	// Create test patterns with different access counts
	patterns := map[string]int64{
		"QmHot1":    1000,
		"QmHot2":    800,
		"QmWarm1":   500,
		"QmWarm2":   300,
		"QmCold1":   50,
		"QmCold2":   10,
	}

	for cid, accessCount := range patterns {
		apa.accessPatterns[cid] = &AccessPattern{
			CID:         cid,
			AccessCount: accessCount,
			LastAccess:  time.Now(),
		}
	}

	// Get top 3 hot objects
	hotObjects := apa.GetHotObjects(3)
	assert.Len(t, hotObjects, 3)

	// Verify they're sorted by access count (descending)
	assert.Equal(t, "QmHot1", hotObjects[0].CID)
	assert.Equal(t, int64(1000), hotObjects[0].AccessCount)
	assert.Equal(t, "QmHot2", hotObjects[1].CID)
	assert.Equal(t, int64(800), hotObjects[1].AccessCount)
	assert.Equal(t, "QmWarm1", hotObjects[2].CID)
	assert.Equal(t, int64(500), hotObjects[2].AccessCount)
}

func TestAccessPatternAnalyzer_GetColdObjects(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	// Create test patterns
	patterns := map[string]int64{
		"QmHot1":    1000,
		"QmWarm1":   500,
		"QmCold1":   50,
		"QmCold2":   10,
		"QmCold3":   5,
	}

	for cid, accessCount := range patterns {
		apa.accessPatterns[cid] = &AccessPattern{
			CID:         cid,
			AccessCount: accessCount,
			LastAccess:  time.Now(),
		}
	}

	// Get top 3 cold objects
	coldObjects := apa.GetColdObjects(3)
	assert.Len(t, coldObjects, 3)

	// Verify they're sorted by access count (ascending)
	assert.Equal(t, "QmCold3", coldObjects[0].CID)
	assert.Equal(t, int64(5), coldObjects[0].AccessCount)
	assert.Equal(t, "QmCold2", coldObjects[1].CID)
	assert.Equal(t, int64(10), coldObjects[1].AccessCount)
	assert.Equal(t, "QmCold1", coldObjects[2].CID)
	assert.Equal(t, int64(50), coldObjects[2].AccessCount)
}

func TestAccessPatternAnalyzer_PredictAccessPattern(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	cid := "QmPredict123"
	baseTime := time.Now().Add(-10 * time.Hour)

	// Create access pattern
	pattern := &AccessPattern{
		CID:         cid,
		AccessCount: 10,
		FirstAccess: baseTime,
		LastAccess:  time.Now(),
	}
	apa.accessPatterns[cid] = pattern

	// Create access history with increasing trend
	history := make([]AccessEvent, 10)
	for i := 0; i < 10; i++ {
		history[i] = AccessEvent{
			Timestamp:   baseTime.Add(time.Duration(i) * time.Hour),
			AccessType:  AccessTypeRead,
			ClientIP:    "192.168.1.1",
		}
	}
	apa.accessHistory[cid] = history

	prediction, err := apa.PredictAccessPattern(cid)
	assert.NoError(t, err)
	assert.NotNil(t, prediction)

	assert.Equal(t, cid, prediction.CID)
	assert.Greater(t, prediction.Confidence, 0.0)
	assert.Equal(t, 24*time.Hour, prediction.PredictionHorizon)
}

func TestAccessPatternAnalyzer_PredictAccessPattern_InsufficientData(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	cid := "QmPredict123"
	pattern := &AccessPattern{
		CID:         cid,
		AccessCount: 1,
		FirstAccess: time.Now(),
		LastAccess:  time.Now(),
	}
	apa.accessPatterns[cid] = pattern

	// Only one access event
	apa.accessHistory[cid] = []AccessEvent{
		{
			Timestamp:  time.Now(),
			AccessType: AccessTypeRead,
		},
	}

	prediction, err := apa.PredictAccessPattern(cid)
	assert.NoError(t, err)
	assert.NotNil(t, prediction)

	assert.Equal(t, 0.1, prediction.Confidence) // Low confidence for insufficient data
}

func TestAccessPatternAnalyzer_UpdateAccessFrequency(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	cid := "QmFreq123"
	baseTime := time.Now().Add(-2 * time.Hour)

	pattern := &AccessPattern{
		CID:         cid,
		AccessCount: 10,
		FirstAccess: baseTime,
		LastAccess:  time.Now(),
	}

	apa.updateAccessFrequency(pattern)

	// Should have frequency of 5 accesses per hour (10 accesses over 2 hours)
	assert.InDelta(t, 5.0, pattern.AccessFrequency, 0.1)
}

func TestAccessPatternAnalyzer_UpdateAccessTrend(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	cid := "QmTrend123"
	baseTime := time.Now().Add(-10 * time.Hour)

	pattern := &AccessPattern{
		CID: cid,
	}

	// Create increasing access pattern
	history := make([]AccessEvent, 20)
	for i := 0; i < 20; i++ {
		timestamp := baseTime.Add(time.Duration(i) * 30 * time.Minute)
		history[i] = AccessEvent{
			Timestamp:  timestamp,
			AccessType: AccessTypeRead,
		}
	}
	apa.accessHistory[cid] = history

	apa.updateAccessTrend(cid, pattern)

	// Should detect increasing trend (more recent accesses)
	assert.Equal(t, AccessTrendIncreasing, pattern.AccessTrend)
}

func TestAccessPatternAnalyzer_IsSpiky(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	// Create spiky access pattern (high activity in one hour, low in others)
	history := make([]AccessEvent, 50)
	baseTime := time.Now().Add(-24 * time.Hour)

	// 40 accesses in hour 10, 10 accesses spread across other hours
	for i := 0; i < 40; i++ {
		history[i] = AccessEvent{
			Timestamp: baseTime.Add(10*time.Hour + time.Duration(i)*time.Minute),
		}
	}
	for i := 40; i < 50; i++ {
		history[i] = AccessEvent{
			Timestamp: baseTime.Add(time.Duration(i-40)*time.Hour + 30*time.Minute),
		}
	}

	isSpiky := apa.isSpiky(history)
	assert.True(t, isSpiky)

	// Create non-spiky pattern (even distribution)
	evenHistory := make([]AccessEvent, 24)
	for i := 0; i < 24; i++ {
		evenHistory[i] = AccessEvent{
			Timestamp: baseTime.Add(time.Duration(i) * time.Hour),
		}
	}

	isSpiky = apa.isSpiky(evenHistory)
	assert.False(t, isSpiky)
}

func TestAccessPatternAnalyzer_IsSeasonal(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	// Create seasonal pattern (more weekday accesses than weekend)
	history := make([]AccessEvent, 140) // 20 weeks worth
	baseTime := time.Now().Add(-140 * 24 * time.Hour)

	eventIndex := 0
	for week := 0; week < 20; week++ {
		// 5 weekday accesses
		for day := 0; day < 5; day++ {
			if eventIndex < len(history) {
				history[eventIndex] = AccessEvent{
					Timestamp: baseTime.Add(time.Duration(week*7+day) * 24 * time.Hour),
				}
				eventIndex++
			}
		}
		// 1 weekend access
		if eventIndex < len(history) {
			history[eventIndex] = AccessEvent{
				Timestamp: baseTime.Add(time.Duration(week*7+5) * 24 * time.Hour),
			}
			eventIndex++
		}
	}

	// Fill remaining with weekday accesses
	for eventIndex < len(history) {
		history[eventIndex] = AccessEvent{
			Timestamp: baseTime.Add(time.Duration(eventIndex) * 24 * time.Hour),
		}
		eventIndex++
	}

	isSeasonal := apa.isSeasonal(history[:120]) // Use first 120 events
	assert.True(t, isSeasonal)
}

func TestAccessPatternAnalyzer_LinearRegression(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	// Test with perfect linear data: y = 2x + 1
	x := []float64{1, 2, 3, 4, 5}
	y := []float64{3, 5, 7, 9, 11}

	slope, intercept := apa.linearRegression(x, y)

	assert.InDelta(t, 2.0, slope, 0.001)
	assert.InDelta(t, 1.0, intercept, 0.001)
}

func TestAccessPatternAnalyzer_CalculateRSquared(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	// Perfect linear relationship
	x := []float64{1, 2, 3, 4, 5}
	y := []float64{3, 5, 7, 9, 11}
	slope := 2.0
	intercept := 1.0

	rSquared := apa.calculateRSquared(x, y, slope, intercept)
	assert.InDelta(t, 1.0, rSquared, 0.001) // Perfect fit should have R² = 1

	// No relationship
	yRandom := []float64{1, 8, 3, 12, 5}
	rSquaredRandom := apa.calculateRSquared(x, yRandom, slope, intercept)
	assert.Less(t, rSquaredRandom, 0.5) // Poor fit should have low R²
}

func TestAccessPatternAnalyzer_StartStop(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start analyzer
	err := apa.Start(ctx)
	assert.NoError(t, err)

	// Verify it's running
	apa.mu.RLock()
	assert.True(t, apa.isRunning)
	apa.mu.RUnlock()

	// Stop analyzer
	err = apa.Stop(ctx)
	assert.NoError(t, err)

	// Verify it's stopped
	apa.mu.RLock()
	assert.False(t, apa.isRunning)
	apa.mu.RUnlock()
}

func TestAccessPatternAnalyzer_RecordReplicationDecision(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	cid := "QmReplication123"
	pattern := &AccessPattern{
		CID:      cid,
		Metadata: make(map[string]interface{}),
	}
	apa.accessPatterns[cid] = pattern

	decision := &ReplicationDecision{
		CID:            cid,
		TargetReplicas: 5,
		Reason:         "hot data",
		Priority:       ReplicationPriorityHigh,
	}

	apa.RecordReplicationDecision(decision)

	// Verify decision was recorded in metadata
	assert.Contains(t, pattern.Metadata, "last_replication_decision")
	
	decisionData := pattern.Metadata["last_replication_decision"].(map[string]interface{})
	assert.Equal(t, 5, decisionData["target_replicas"])
	assert.Equal(t, "hot data", decisionData["reason"])
	assert.Equal(t, ReplicationPriorityHigh, decisionData["priority"])
}

// Benchmark tests

func BenchmarkAccessPatternAnalyzer_RecordAccess(b *testing.B) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	event := AccessEvent{
		Timestamp:     time.Now(),
		ClientIP:      "192.168.1.1",
		UserAgent:     "benchmark-agent",
		GeographicLoc: "US",
		AccessType:    AccessTypeRead,
		ResponseTime:  100 * time.Millisecond,
		BytesServed:   1024,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cid := fmt.Sprintf("QmBenchmark%d", i%1000) // Cycle through 1000 CIDs
		apa.RecordAccess(cid, event)
	}
}

func BenchmarkAccessPatternAnalyzer_GetAccessPattern(b *testing.B) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	// Pre-populate with patterns
	for i := 0; i < 1000; i++ {
		cid := fmt.Sprintf("QmBenchmark%d", i)
		apa.accessPatterns[cid] = &AccessPattern{
			CID:               cid,
			AccessCount:       int64(i),
			GeographicAccess:  make(map[string]int64),
			TimePatterns:      make(map[int]int64),
			UserAgentPatterns: make(map[string]int64),
			Metadata:          make(map[string]interface{}),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cid := fmt.Sprintf("QmBenchmark%d", i%1000)
		_, err := apa.GetAccessPattern(cid)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAccessPatternAnalyzer_PredictAccessPattern(b *testing.B) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()
	apa := NewAccessPatternAnalyzer(mockMetadata, 24*time.Hour, logger)

	cid := "QmBenchmark123"
	baseTime := time.Now().Add(-24 * time.Hour)

	// Create pattern and history
	pattern := &AccessPattern{
		CID:         cid,
		AccessCount: 100,
		FirstAccess: baseTime,
		LastAccess:  time.Now(),
	}
	apa.accessPatterns[cid] = pattern

	history := make([]AccessEvent, 100)
	for i := 0; i < 100; i++ {
		history[i] = AccessEvent{
			Timestamp:  baseTime.Add(time.Duration(i) * 15 * time.Minute),
			AccessType: AccessTypeRead,
		}
	}
	apa.accessHistory[cid] = history

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := apa.PredictAccessPattern(cid)
		if err != nil {
			b.Fatal(err)
		}
	}
}