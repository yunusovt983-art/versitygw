package ipfs

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// AccessPatternAnalyzer analyzes access patterns for objects to optimize replication
type AccessPatternAnalyzer struct {
	config       *ReplicaConfig
	accessStats  map[string]*AccessStats
	statsMutex   sync.RWMutex
	
	// Time windows for analysis
	shortWindow  time.Duration // Recent activity window
	mediumWindow time.Duration // Medium-term trend window
	longWindow   time.Duration // Long-term pattern window
	
	// Pattern detection
	patternCache map[string]*AccessPattern
	cacheMutex   sync.RWMutex
	cacheExpiry  time.Duration
}

// AccessStats holds raw access statistics for an object
type AccessStats struct {
	CID                string                    `json:"cid"`
	TotalAccesses      int64                     `json:"total_accesses"`
	AccessHistory      []AccessEvent             `json:"access_history"`
	GeographicAccess   map[string]int64          `json:"geographic_access"`
	PeerAccess         map[string]int64          `json:"peer_access"`
	HourlyAccess       map[int]int64             `json:"hourly_access"`
	DailyAccess        map[string]int64          `json:"daily_access"`
	WeeklyAccess       map[int]int64             `json:"weekly_access"`
	LastUpdated        time.Time                 `json:"last_updated"`
	
	// Performance metrics
	AverageLatency     time.Duration             `json:"average_latency"`
	LatencyHistory     []time.Duration           `json:"latency_history"`
	TransferSpeeds     []float64                 `json:"transfer_speeds"`
	ErrorCount         int64                     `json:"error_count"`
}

// AccessEvent represents a single access event
type AccessEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	PeerID       string    `json:"peer_id"`
	Region       string    `json:"region"`
	Latency      time.Duration `json:"latency"`
	TransferSize int64     `json:"transfer_size"`
	Success      bool      `json:"success"`
}

// NewAccessPatternAnalyzer creates a new access pattern analyzer
func NewAccessPatternAnalyzer(config *ReplicaConfig) *AccessPatternAnalyzer {
	return &AccessPatternAnalyzer{
		config:       config,
		accessStats:  make(map[string]*AccessStats),
		patternCache: make(map[string]*AccessPattern),
		shortWindow:  1 * time.Hour,
		mediumWindow: 24 * time.Hour,
		longWindow:   7 * 24 * time.Hour,
		cacheExpiry:  30 * time.Minute,
	}
}

// RecordAccess records an access event for analysis
func (apa *AccessPatternAnalyzer) RecordAccess(cid, peerID, region string, latency time.Duration, transferSize int64, success bool) {
	apa.statsMutex.Lock()
	defer apa.statsMutex.Unlock()
	
	stats, exists := apa.accessStats[cid]
	if !exists {
		stats = &AccessStats{
			CID:              cid,
			AccessHistory:    make([]AccessEvent, 0),
			GeographicAccess: make(map[string]int64),
			PeerAccess:       make(map[string]int64),
			HourlyAccess:     make(map[int]int64),
			DailyAccess:      make(map[string]int64),
			WeeklyAccess:     make(map[int]int64),
			LatencyHistory:   make([]time.Duration, 0),
			TransferSpeeds:   make([]float64, 0),
		}
		apa.accessStats[cid] = stats
	}
	
	// Record the access event
	event := AccessEvent{
		Timestamp:    time.Now(),
		PeerID:       peerID,
		Region:       region,
		Latency:      latency,
		TransferSize: transferSize,
		Success:      success,
	}
	
	stats.AccessHistory = append(stats.AccessHistory, event)
	stats.TotalAccesses++
	
	// Update geographic access
	if region != "" {
		stats.GeographicAccess[region]++
	}
	
	// Update peer access
	if peerID != "" {
		stats.PeerAccess[peerID]++
	}
	
	// Update time-based access patterns
	now := time.Now()
	hour := now.Hour()
	day := now.Format("2006-01-02")
	weekday := int(now.Weekday())
	
	stats.HourlyAccess[hour]++
	stats.DailyAccess[day]++
	stats.WeeklyAccess[weekday]++
	
	// Update performance metrics
	if success {
		stats.LatencyHistory = append(stats.LatencyHistory, latency)
		if transferSize > 0 && latency > 0 {
			speed := float64(transferSize) / latency.Seconds() // bytes per second
			stats.TransferSpeeds = append(stats.TransferSpeeds, speed)
		}
		
		// Update average latency
		totalLatency := time.Duration(0)
		for _, l := range stats.LatencyHistory {
			totalLatency += l
		}
		stats.AverageLatency = totalLatency / time.Duration(len(stats.LatencyHistory))
	} else {
		stats.ErrorCount++
	}
	
	stats.LastUpdated = now
	
	// Cleanup old data to prevent memory bloat
	apa.cleanupOldData(stats)
	
	// Invalidate pattern cache for this CID
	apa.cacheMutex.Lock()
	delete(apa.patternCache, cid)
	apa.cacheMutex.Unlock()
}

// AnalyzePattern analyzes access patterns for a given CID
func (apa *AccessPatternAnalyzer) AnalyzePattern(cid string, stats *AccessStats) (*AccessPattern, error) {
	// Check cache first
	apa.cacheMutex.RLock()
	if cached, exists := apa.patternCache[cid]; exists {
		if time.Since(cached.LastAnalyzed) < apa.cacheExpiry {
			apa.cacheMutex.RUnlock()
			return cached, nil
		}
	}
	apa.cacheMutex.RUnlock()
	
	if stats == nil {
		apa.statsMutex.RLock()
		var exists bool
		stats, exists = apa.accessStats[cid]
		apa.statsMutex.RUnlock()
		
		if !exists {
			return nil, fmt.Errorf("no access stats found for CID: %s", cid)
		}
	}
	
	pattern := &AccessPattern{
		TotalAccesses:     stats.TotalAccesses,
		GeographicAccess:  make(map[string]int64),
		PeerAccess:        make(map[string]int64),
		TimePattern:       make(map[int]int64),
		LastAnalyzed:      time.Now(),
	}
	
	// Copy geographic and peer access data
	for region, count := range stats.GeographicAccess {
		pattern.GeographicAccess[region] = count
	}
	for peer, count := range stats.PeerAccess {
		pattern.PeerAccess[peer] = count
	}
	for hour, count := range stats.HourlyAccess {
		pattern.TimePattern[hour] = count
	}
	
	// Analyze recent access patterns
	pattern.RecentAccesses = apa.calculateRecentAccesses(stats)
	pattern.AccessFrequency = apa.calculateAccessFrequency(stats)
	pattern.AccessTrend = apa.detectAccessTrend(stats)
	pattern.PredictedAccesses = apa.predictFutureAccesses(stats, pattern.AccessTrend)
	
	// Cache the pattern
	apa.cacheMutex.Lock()
	apa.patternCache[cid] = pattern
	apa.cacheMutex.Unlock()
	
	return pattern, nil
}

// calculateRecentAccesses calculates access count in the recent window
func (apa *AccessPatternAnalyzer) calculateRecentAccesses(stats *AccessStats) int64 {
	cutoff := time.Now().Add(-apa.shortWindow)
	recentCount := int64(0)
	
	for _, event := range stats.AccessHistory {
		if event.Timestamp.After(cutoff) && event.Success {
			recentCount++
		}
	}
	
	return recentCount
}

// calculateAccessFrequency calculates the access frequency (accesses per hour)
func (apa *AccessPatternAnalyzer) calculateAccessFrequency(stats *AccessStats) float64 {
	if len(stats.AccessHistory) == 0 {
		return 0.0
	}
	
	// Find the time span of recorded accesses
	oldest := stats.AccessHistory[0].Timestamp
	newest := stats.AccessHistory[len(stats.AccessHistory)-1].Timestamp
	
	timeSpan := newest.Sub(oldest)
	if timeSpan == 0 {
		return 0.0
	}
	
	// Calculate accesses per hour
	hours := timeSpan.Hours()
	if hours < 1 {
		hours = 1 // Minimum 1 hour for calculation
	}
	
	return float64(stats.TotalAccesses) / hours
}

// detectAccessTrend detects the trend in access patterns
func (apa *AccessPatternAnalyzer) detectAccessTrend(stats *AccessStats) AccessTrend {
	if len(stats.AccessHistory) < 10 {
		return TrendStable // Not enough data
	}
	
	// Analyze access patterns over different time windows
	shortAccesses := apa.getAccessesInWindow(stats, apa.shortWindow)
	mediumAccesses := apa.getAccessesInWindow(stats, apa.mediumWindow)
	longAccesses := apa.getAccessesInWindow(stats, apa.longWindow)
	
	// Calculate rates (accesses per hour)
	shortRate := float64(shortAccesses) / apa.shortWindow.Hours()
	mediumRate := float64(mediumAccesses) / apa.mediumWindow.Hours()
	longRate := float64(longAccesses) / apa.longWindow.Hours()
	
	// Detect trend based on rate changes
	if shortRate > mediumRate*1.5 && mediumRate > longRate*1.2 {
		return TrendIncreasing
	} else if shortRate < mediumRate*0.5 && mediumRate < longRate*0.8 {
		return TrendDecreasing
	}
	
	// Check for spiky behavior (high variance)
	variance := apa.calculateAccessVariance(stats)
	mean := apa.calculateAccessMean(stats)
	
	if variance > mean*2 {
		return TrendSpiky
	}
	
	// Check for seasonal patterns
	if apa.detectSeasonalPattern(stats) {
		return TrendSeasonal
	}
	
	return TrendStable
}

// getAccessesInWindow counts accesses within a time window
func (apa *AccessPatternAnalyzer) getAccessesInWindow(stats *AccessStats, window time.Duration) int64 {
	cutoff := time.Now().Add(-window)
	count := int64(0)
	
	for _, event := range stats.AccessHistory {
		if event.Timestamp.After(cutoff) && event.Success {
			count++
		}
	}
	
	return count
}

// calculateAccessVariance calculates variance in hourly access patterns
func (apa *AccessPatternAnalyzer) calculateAccessVariance(stats *AccessStats) float64 {
	if len(stats.HourlyAccess) == 0 {
		return 0.0
	}
	
	// Calculate mean
	sum := int64(0)
	for _, count := range stats.HourlyAccess {
		sum += count
	}
	mean := float64(sum) / float64(len(stats.HourlyAccess))
	
	// Calculate variance
	variance := 0.0
	for _, count := range stats.HourlyAccess {
		diff := float64(count) - mean
		variance += diff * diff
	}
	variance /= float64(len(stats.HourlyAccess))
	
	return variance
}

// calculateAccessMean calculates mean hourly access count
func (apa *AccessPatternAnalyzer) calculateAccessMean(stats *AccessStats) float64 {
	if len(stats.HourlyAccess) == 0 {
		return 0.0
	}
	
	sum := int64(0)
	for _, count := range stats.HourlyAccess {
		sum += count
	}
	
	return float64(sum) / float64(len(stats.HourlyAccess))
}

// detectSeasonalPattern detects seasonal patterns in access
func (apa *AccessPatternAnalyzer) detectSeasonalPattern(stats *AccessStats) bool {
	// Check for weekly patterns
	if len(stats.WeeklyAccess) < 7 {
		return false
	}
	
	// Calculate coefficient of variation for weekly pattern
	weeklyValues := make([]float64, 0, len(stats.WeeklyAccess))
	for _, count := range stats.WeeklyAccess {
		weeklyValues = append(weeklyValues, float64(count))
	}
	
	mean := 0.0
	for _, val := range weeklyValues {
		mean += val
	}
	mean /= float64(len(weeklyValues))
	
	variance := 0.0
	for _, val := range weeklyValues {
		diff := val - mean
		variance += diff * diff
	}
	variance /= float64(len(weeklyValues))
	
	stdDev := math.Sqrt(variance)
	coefficientOfVariation := stdDev / mean
	
	// If coefficient of variation is high, it indicates seasonal pattern
	return coefficientOfVariation > 0.5
}

// predictFutureAccesses predicts future access count based on trend
func (apa *AccessPatternAnalyzer) predictFutureAccesses(stats *AccessStats, trend AccessTrend) int64 {
	recentAccesses := apa.calculateRecentAccesses(stats)
	
	switch trend {
	case TrendIncreasing:
		return int64(float64(recentAccesses) * 1.5) // 50% increase
	case TrendDecreasing:
		return int64(float64(recentAccesses) * 0.7) // 30% decrease
	case TrendSpiky:
		return int64(float64(recentAccesses) * 2.0) // Prepare for spikes
	case TrendSeasonal:
		return apa.predictSeasonalAccesses(stats)
	default:
		return recentAccesses // Stable trend
	}
}

// predictSeasonalAccesses predicts accesses based on seasonal patterns
func (apa *AccessPatternAnalyzer) predictSeasonalAccesses(stats *AccessStats) int64 {
	now := time.Now()
	currentHour := now.Hour()
	currentWeekday := int(now.Weekday())
	
	// Use historical data for same time patterns
	hourlyAvg := stats.HourlyAccess[currentHour]
	weeklyAvg := stats.WeeklyAccess[currentWeekday]
	
	// Combine hourly and weekly patterns
	predicted := (hourlyAvg + weeklyAvg) / 2
	
	return predicted
}

// GetAccessStats returns access statistics for a CID
func (apa *AccessPatternAnalyzer) GetAccessStats(cid string) (*AccessStats, error) {
	apa.statsMutex.RLock()
	defer apa.statsMutex.RUnlock()
	
	stats, exists := apa.accessStats[cid]
	if !exists {
		return nil, fmt.Errorf("no access stats found for CID: %s", cid)
	}
	
	// Return a copy to avoid race conditions
	statsCopy := *stats
	statsCopy.GeographicAccess = make(map[string]int64)
	statsCopy.PeerAccess = make(map[string]int64)
	statsCopy.HourlyAccess = make(map[int]int64)
	statsCopy.DailyAccess = make(map[string]int64)
	statsCopy.WeeklyAccess = make(map[int]int64)
	
	for k, v := range stats.GeographicAccess {
		statsCopy.GeographicAccess[k] = v
	}
	for k, v := range stats.PeerAccess {
		statsCopy.PeerAccess[k] = v
	}
	for k, v := range stats.HourlyAccess {
		statsCopy.HourlyAccess[k] = v
	}
	for k, v := range stats.DailyAccess {
		statsCopy.DailyAccess[k] = v
	}
	for k, v := range stats.WeeklyAccess {
		statsCopy.WeeklyAccess[k] = v
	}
	
	return &statsCopy, nil
}

// cleanupOldData removes old access events to prevent memory bloat
func (apa *AccessPatternAnalyzer) cleanupOldData(stats *AccessStats) {
	cutoff := time.Now().Add(-apa.longWindow * 2) // Keep data for 2x long window
	
	// Clean up access history
	newHistory := make([]AccessEvent, 0)
	for _, event := range stats.AccessHistory {
		if event.Timestamp.After(cutoff) {
			newHistory = append(newHistory, event)
		}
	}
	stats.AccessHistory = newHistory
	
	// Clean up daily access data
	for day := range stats.DailyAccess {
		dayTime, err := time.Parse("2006-01-02", day)
		if err != nil || dayTime.Before(cutoff) {
			delete(stats.DailyAccess, day)
		}
	}
	
	// Limit latency history size
	maxLatencyHistory := 1000
	if len(stats.LatencyHistory) > maxLatencyHistory {
		stats.LatencyHistory = stats.LatencyHistory[len(stats.LatencyHistory)-maxLatencyHistory:]
	}
	
	// Limit transfer speeds history size
	maxSpeedHistory := 1000
	if len(stats.TransferSpeeds) > maxSpeedHistory {
		stats.TransferSpeeds = stats.TransferSpeeds[len(stats.TransferSpeeds)-maxSpeedHistory:]
	}
}

// GetTopAccessedObjects returns the most accessed objects
func (apa *AccessPatternAnalyzer) GetTopAccessedObjects(limit int) []string {
	apa.statsMutex.RLock()
	defer apa.statsMutex.RUnlock()
	
	type cidAccess struct {
		CID     string
		Accesses int64
	}
	
	cidList := make([]cidAccess, 0, len(apa.accessStats))
	for cid, stats := range apa.accessStats {
		cidList = append(cidList, cidAccess{
			CID:     cid,
			Accesses: stats.TotalAccesses,
		})
	}
	
	// Sort by access count
	sort.Slice(cidList, func(i, j int) bool {
		return cidList[i].Accesses > cidList[j].Accesses
	})
	
	// Return top CIDs
	result := make([]string, 0, limit)
	for i, ca := range cidList {
		if i >= limit {
			break
		}
		result = append(result, ca.CID)
	}
	
	return result
}

// GetAnalyticsSummary returns a summary of access analytics
func (apa *AccessPatternAnalyzer) GetAnalyticsSummary() *AnalyticsSummary {
	apa.statsMutex.RLock()
	defer apa.statsMutex.RUnlock()
	
	summary := &AnalyticsSummary{
		TotalObjects:      len(apa.accessStats),
		TotalAccesses:     0,
		UniqueRegions:     make(map[string]bool),
		UniquePeers:       make(map[string]bool),
		TrendDistribution: make(map[AccessTrend]int),
	}
	
	for _, stats := range apa.accessStats {
		summary.TotalAccesses += stats.TotalAccesses
		
		for region := range stats.GeographicAccess {
			summary.UniqueRegions[region] = true
		}
		
		for peer := range stats.PeerAccess {
			summary.UniquePeers[peer] = true
		}
	}
	
	// Analyze trends for all objects
	for cid := range apa.accessStats {
		pattern, err := apa.AnalyzePattern(cid, nil)
		if err == nil {
			summary.TrendDistribution[pattern.AccessTrend]++
		}
	}
	
	return summary
}

// AnalyticsSummary provides a summary of access analytics
type AnalyticsSummary struct {
	TotalObjects      int                    `json:"total_objects"`
	TotalAccesses     int64                  `json:"total_accesses"`
	UniqueRegions     map[string]bool        `json:"unique_regions"`
	UniquePeers       map[string]bool        `json:"unique_peers"`
	TrendDistribution map[AccessTrend]int    `json:"trend_distribution"`
}