package ipfs

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// GeographicManager manages geographic distribution of replicas
type GeographicManager struct {
	clusterClient ClusterClientInterface
	
	// Geographic data
	nodeLocations map[string]*NodeLocation
	regionNodes   map[string][]string
	locationMutex sync.RWMutex
	
	// Distance calculations
	distanceCache map[string]map[string]float64
	cacheMutex    sync.RWMutex
	
	// Configuration
	config *GeographicConfig
}

// GeographicConfig holds configuration for geographic management
type GeographicConfig struct {
	// Distance thresholds (in kilometers)
	MinDistanceBetweenReplicas float64 `json:"min_distance_between_replicas"`
	MaxDistanceForReplication  float64 `json:"max_distance_for_replication"`
	
	// Regional preferences
	PreferredRegions           []string `json:"preferred_regions"`
	RegionWeights             map[string]float64 `json:"region_weights"`
	
	// Performance considerations
	LatencyThreshold          time.Duration `json:"latency_threshold"`
	BandwidthThreshold        float64       `json:"bandwidth_threshold"` // MB/s
	
	// Rebalancing
	RebalanceDistanceThreshold float64 `json:"rebalance_distance_threshold"`
	MaxRebalanceDistance       float64 `json:"max_rebalance_distance"`
}

// NodeLocation represents the geographic location of a cluster node
type NodeLocation struct {
	NodeID    string  `json:"node_id"`
	Region    string  `json:"region"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	
	// Network characteristics
	Latency   time.Duration `json:"latency"`
	Bandwidth float64       `json:"bandwidth"` // MB/s
	
	// Capacity and load
	StorageCapacity int64   `json:"storage_capacity"`
	StorageUsed     int64   `json:"storage_used"`
	CPULoad         float64 `json:"cpu_load"`
	NetworkLoad     float64 `json:"network_load"`
	
	// Availability
	Uptime        float64   `json:"uptime"`
	LastSeen      time.Time `json:"last_seen"`
	IsHealthy     bool      `json:"is_healthy"`
}

// RegionInfo contains information about a geographic region
type RegionInfo struct {
	Name         string   `json:"name"`
	Nodes        []string `json:"nodes"`
	TotalCapacity int64   `json:"total_capacity"`
	UsedCapacity  int64   `json:"used_capacity"`
	AverageLatency time.Duration `json:"average_latency"`
	HealthyNodes  int     `json:"healthy_nodes"`
}

// PlacementStrategy defines how replicas should be placed geographically
type PlacementStrategy int

const (
	PlacementBalanced PlacementStrategy = iota // Balance across regions
	PlacementLatency                           // Minimize latency
	PlacementCapacity                          // Maximize available capacity
	PlacementCustom                            // Use custom weights
)

// NewGeographicManager creates a new geographic manager
func NewGeographicManager(clusterClient ClusterClientInterface, logger interface{}) *GeographicManager {
	gm := &GeographicManager{
		clusterClient: clusterClient,
		nodeLocations: make(map[string]*NodeLocation),
		regionNodes:   make(map[string][]string),
		distanceCache: make(map[string]map[string]float64),
		config: &GeographicConfig{
			MinDistanceBetweenReplicas: 100.0,  // 100 km
			MaxDistanceForReplication:  10000.0, // 10,000 km
			LatencyThreshold:          100 * time.Millisecond,
			BandwidthThreshold:        10.0, // 10 MB/s
			RebalanceDistanceThreshold: 50.0,  // 50 km
			MaxRebalanceDistance:      5000.0, // 5,000 km
			RegionWeights:             make(map[string]float64),
		},
	}
	
	// Initialize with default region weights
	gm.config.RegionWeights["us-east"] = 1.0
	gm.config.RegionWeights["us-west"] = 1.0
	gm.config.RegionWeights["eu-west"] = 1.0
	gm.config.RegionWeights["asia-pacific"] = 1.0
	
	return gm
}

// UpdateNodeLocation updates the location information for a node
func (gm *GeographicManager) UpdateNodeLocation(nodeID string, location *NodeLocation) error {
	gm.locationMutex.Lock()
	defer gm.locationMutex.Unlock()
	
	location.NodeID = nodeID
	gm.nodeLocations[nodeID] = location
	
	// Update region mapping
	if location.Region != "" {
		if _, exists := gm.regionNodes[location.Region]; !exists {
			gm.regionNodes[location.Region] = make([]string, 0)
		}
		
		// Remove from old region if it exists
		for region, nodes := range gm.regionNodes {
			for i, node := range nodes {
				if node == nodeID {
					gm.regionNodes[region] = append(nodes[:i], nodes[i+1:]...)
					break
				}
			}
		}
		
		// Add to new region
		gm.regionNodes[location.Region] = append(gm.regionNodes[location.Region], nodeID)
	}
	
	// Invalidate distance cache for this node
	gm.cacheMutex.Lock()
	delete(gm.distanceCache, nodeID)
	for nodeID2 := range gm.distanceCache {
		delete(gm.distanceCache[nodeID2], nodeID)
	}
	gm.cacheMutex.Unlock()
	
	return nil
}

// GetOptimalNodes returns the optimal nodes for placing replicas
func (gm *GeographicManager) GetOptimalNodes(accessPattern *AccessPattern, replicaCount int, strategy PlacementStrategy) ([]string, error) {
	gm.locationMutex.RLock()
	defer gm.locationMutex.RUnlock()
	
	if len(gm.nodeLocations) == 0 {
		return nil, fmt.Errorf("no node locations available")
	}
	
	// Get available healthy nodes
	availableNodes := gm.getHealthyNodes()
	if len(availableNodes) < replicaCount {
		return nil, fmt.Errorf("insufficient healthy nodes: need %d, have %d", replicaCount, len(availableNodes))
	}
	
	switch strategy {
	case PlacementBalanced:
		return gm.getBalancedPlacement(availableNodes, replicaCount)
	case PlacementLatency:
		return gm.getLatencyOptimizedPlacement(availableNodes, accessPattern, replicaCount)
	case PlacementCapacity:
		return gm.getCapacityOptimizedPlacement(availableNodes, replicaCount)
	case PlacementCustom:
		return gm.getCustomPlacement(availableNodes, accessPattern, replicaCount)
	default:
		return gm.getBalancedPlacement(availableNodes, replicaCount)
	}
}

// getHealthyNodes returns a list of healthy nodes
func (gm *GeographicManager) getHealthyNodes() []string {
	healthyNodes := make([]string, 0)
	
	for nodeID, location := range gm.nodeLocations {
		if location.IsHealthy && time.Since(location.LastSeen) < 5*time.Minute {
			healthyNodes = append(healthyNodes, nodeID)
		}
	}
	
	return healthyNodes
}

// getBalancedPlacement returns nodes distributed across regions
func (gm *GeographicManager) getBalancedPlacement(availableNodes []string, replicaCount int) ([]string, error) {
	// Group nodes by region
	regionNodes := make(map[string][]string)
	for _, nodeID := range availableNodes {
		if location, exists := gm.nodeLocations[nodeID]; exists {
			region := location.Region
			if region == "" {
				region = "unknown"
			}
			regionNodes[region] = append(regionNodes[region], nodeID)
		}
	}
	
	// Calculate nodes per region
	regions := make([]string, 0, len(regionNodes))
	for region := range regionNodes {
		regions = append(regions, region)
	}
	
	if len(regions) == 0 {
		return nil, fmt.Errorf("no regions available")
	}
	
	// Sort regions by preference and capacity
	sort.Slice(regions, func(i, j int) bool {
		weightI := gm.config.RegionWeights[regions[i]]
		weightJ := gm.config.RegionWeights[regions[j]]
		if weightI != weightJ {
			return weightI > weightJ
		}
		return len(regionNodes[regions[i]]) > len(regionNodes[regions[j]])
	})
	
	// Distribute replicas across regions
	selectedNodes := make([]string, 0, replicaCount)
	nodesPerRegion := replicaCount / len(regions)
	remainder := replicaCount % len(regions)
	
	for i, region := range regions {
		nodeCount := nodesPerRegion
		if i < remainder {
			nodeCount++
		}
		
		// Select best nodes from this region
		regionNodeList := regionNodes[region]
		if len(regionNodeList) < nodeCount {
			nodeCount = len(regionNodeList)
		}
		
		// Sort nodes by capacity and performance
		sort.Slice(regionNodeList, func(i, j int) bool {
			locI := gm.nodeLocations[regionNodeList[i]]
			locJ := gm.nodeLocations[regionNodeList[j]]
			
			// Prefer nodes with more available capacity
			availableI := locI.StorageCapacity - locI.StorageUsed
			availableJ := locJ.StorageCapacity - locJ.StorageUsed
			
			if availableI != availableJ {
				return availableI > availableJ
			}
			
			// Prefer nodes with lower load
			return locI.CPULoad < locJ.CPULoad
		})
		
		for j := 0; j < nodeCount && len(selectedNodes) < replicaCount; j++ {
			selectedNodes = append(selectedNodes, regionNodeList[j])
		}
		
		if len(selectedNodes) >= replicaCount {
			break
		}
	}
	
	// If we still need more nodes, add from any available region
	if len(selectedNodes) < replicaCount {
		for _, nodeID := range availableNodes {
			if !contains(selectedNodes, nodeID) {
				selectedNodes = append(selectedNodes, nodeID)
				if len(selectedNodes) >= replicaCount {
					break
				}
			}
		}
	}
	
	return selectedNodes, nil
}

// getLatencyOptimizedPlacement returns nodes optimized for low latency access
func (gm *GeographicManager) getLatencyOptimizedPlacement(availableNodes []string, accessPattern *AccessPattern, replicaCount int) ([]string, error) {
	if accessPattern == nil || len(accessPattern.GeographicAccess) == 0 {
		// Fall back to balanced placement
		return gm.getBalancedPlacement(availableNodes, replicaCount)
	}
	
	// Calculate weighted scores for each node based on access patterns
	nodeScores := make(map[string]float64)
	
	for _, nodeID := range availableNodes {
		location := gm.nodeLocations[nodeID]
		score := 0.0
		
		// Calculate score based on geographic access patterns
		for region, accessCount := range accessPattern.GeographicAccess {
			if accessCount > 0 {
				distance := gm.calculateRegionDistance(location.Region, region)
				latencyPenalty := distance / 1000.0 // Convert to latency penalty
				regionScore := float64(accessCount) / (1.0 + latencyPenalty)
				score += regionScore
			}
		}
		
		// Adjust for node performance characteristics
		if location.Latency > 0 {
			latencyFactor := float64(gm.config.LatencyThreshold) / float64(location.Latency)
			score *= latencyFactor
		}
		
		// Adjust for bandwidth
		if location.Bandwidth > 0 {
			bandwidthFactor := location.Bandwidth / gm.config.BandwidthThreshold
			if bandwidthFactor > 1.0 {
				score *= bandwidthFactor
			}
		}
		
		// Adjust for load
		loadFactor := 1.0 - location.CPULoad
		score *= loadFactor
		
		nodeScores[nodeID] = score
	}
	
	// Sort nodes by score
	sortedNodes := make([]string, 0, len(availableNodes))
	for nodeID := range nodeScores {
		sortedNodes = append(sortedNodes, nodeID)
	}
	
	sort.Slice(sortedNodes, func(i, j int) bool {
		return nodeScores[sortedNodes[i]] > nodeScores[sortedNodes[j]]
	})
	
	// Select top nodes, ensuring geographic diversity
	selectedNodes := make([]string, 0, replicaCount)
	usedRegions := make(map[string]bool)
	
	// First pass: select best nodes from different regions
	for _, nodeID := range sortedNodes {
		if len(selectedNodes) >= replicaCount {
			break
		}
		
		location := gm.nodeLocations[nodeID]
		if !usedRegions[location.Region] {
			selectedNodes = append(selectedNodes, nodeID)
			usedRegions[location.Region] = true
		}
	}
	
	// Second pass: fill remaining slots with best available nodes
	for _, nodeID := range sortedNodes {
		if len(selectedNodes) >= replicaCount {
			break
		}
		
		if !contains(selectedNodes, nodeID) {
			selectedNodes = append(selectedNodes, nodeID)
		}
	}
	
	return selectedNodes, nil
}

// getCapacityOptimizedPlacement returns nodes with the most available capacity
func (gm *GeographicManager) getCapacityOptimizedPlacement(availableNodes []string, replicaCount int) ([]string, error) {
	// Sort nodes by available capacity
	sort.Slice(availableNodes, func(i, j int) bool {
		locI := gm.nodeLocations[availableNodes[i]]
		locJ := gm.nodeLocations[availableNodes[j]]
		
		availableI := locI.StorageCapacity - locI.StorageUsed
		availableJ := locJ.StorageCapacity - locJ.StorageUsed
		
		return availableI > availableJ
	})
	
	// Select top nodes by capacity
	selectedCount := replicaCount
	if selectedCount > len(availableNodes) {
		selectedCount = len(availableNodes)
	}
	
	return availableNodes[:selectedCount], nil
}

// getCustomPlacement returns nodes based on custom weights and access patterns
func (gm *GeographicManager) getCustomPlacement(availableNodes []string, accessPattern *AccessPattern, replicaCount int) ([]string, error) {
	// Calculate custom scores for each node
	nodeScores := make(map[string]float64)
	
	for _, nodeID := range availableNodes {
		location := gm.nodeLocations[nodeID]
		score := 0.0
		
		// Base score from region weight
		if weight, exists := gm.config.RegionWeights[location.Region]; exists {
			score = weight
		} else {
			score = 1.0 // Default weight
		}
		
		// Adjust for access patterns if available
		if accessPattern != nil && len(accessPattern.GeographicAccess) > 0 {
			accessScore := 0.0
			for region, accessCount := range accessPattern.GeographicAccess {
				if region == location.Region {
					accessScore += float64(accessCount)
				} else {
					// Reduce score based on distance
					distance := gm.calculateRegionDistance(location.Region, region)
					distanceFactor := 1.0 / (1.0 + distance/1000.0)
					accessScore += float64(accessCount) * distanceFactor
				}
			}
			score *= (1.0 + accessScore/100.0) // Normalize access score
		}
		
		// Adjust for node characteristics
		capacityFactor := float64(location.StorageCapacity-location.StorageUsed) / float64(location.StorageCapacity)
		loadFactor := 1.0 - location.CPULoad
		uptimeFactor := location.Uptime
		
		score *= capacityFactor * loadFactor * uptimeFactor
		
		nodeScores[nodeID] = score
	}
	
	// Sort nodes by custom score
	sort.Slice(availableNodes, func(i, j int) bool {
		return nodeScores[availableNodes[i]] > nodeScores[availableNodes[j]]
	})
	
	// Select top nodes
	selectedCount := replicaCount
	if selectedCount > len(availableNodes) {
		selectedCount = len(availableNodes)
	}
	
	return availableNodes[:selectedCount], nil
}

// calculateRegionDistance calculates approximate distance between regions
func (gm *GeographicManager) calculateRegionDistance(region1, region2 string) float64 {
	if region1 == region2 {
		return 0.0
	}
	
	// Use cached distance if available
	gm.cacheMutex.RLock()
	if distances, exists := gm.distanceCache[region1]; exists {
		if distance, exists := distances[region2]; exists {
			gm.cacheMutex.RUnlock()
			return distance
		}
	}
	gm.cacheMutex.RUnlock()
	
	// Calculate distance based on representative nodes from each region
	nodes1 := gm.regionNodes[region1]
	nodes2 := gm.regionNodes[region2]
	
	if len(nodes1) == 0 || len(nodes2) == 0 {
		return 5000.0 // Default large distance
	}
	
	// Use first healthy node from each region as representative
	var loc1, loc2 *NodeLocation
	for _, nodeID := range nodes1 {
		if location := gm.nodeLocations[nodeID]; location.IsHealthy {
			loc1 = location
			break
		}
	}
	for _, nodeID := range nodes2 {
		if location := gm.nodeLocations[nodeID]; location.IsHealthy {
			loc2 = location
			break
		}
	}
	
	if loc1 == nil || loc2 == nil {
		return 5000.0 // Default large distance
	}
	
	// Calculate haversine distance
	distance := gm.haversineDistance(loc1.Latitude, loc1.Longitude, loc2.Latitude, loc2.Longitude)
	
	// Cache the result
	gm.cacheMutex.Lock()
	if _, exists := gm.distanceCache[region1]; !exists {
		gm.distanceCache[region1] = make(map[string]float64)
	}
	if _, exists := gm.distanceCache[region2]; !exists {
		gm.distanceCache[region2] = make(map[string]float64)
	}
	gm.distanceCache[region1][region2] = distance
	gm.distanceCache[region2][region1] = distance
	gm.cacheMutex.Unlock()
	
	return distance
}

// haversineDistance calculates the distance between two points on Earth
func (gm *GeographicManager) haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadius = 6371.0 // Earth's radius in kilometers
	
	// Convert degrees to radians
	lat1Rad := lat1 * math.Pi / 180
	lon1Rad := lon1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	lon2Rad := lon2 * math.Pi / 180
	
	// Calculate differences
	deltaLat := lat2Rad - lat1Rad
	deltaLon := lon2Rad - lon1Rad
	
	// Haversine formula
	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
	
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	
	return earthRadius * c
}

// GetRegionInfo returns information about all regions
func (gm *GeographicManager) GetRegionInfo() map[string]*RegionInfo {
	gm.locationMutex.RLock()
	defer gm.locationMutex.RUnlock()
	
	regionInfo := make(map[string]*RegionInfo)
	
	for region, nodes := range gm.regionNodes {
		info := &RegionInfo{
			Name:  region,
			Nodes: make([]string, len(nodes)),
		}
		copy(info.Nodes, nodes)
		
		// Calculate aggregate statistics
		totalLatency := time.Duration(0)
		healthyCount := 0
		
		for _, nodeID := range nodes {
			if location, exists := gm.nodeLocations[nodeID]; exists {
				info.TotalCapacity += location.StorageCapacity
				info.UsedCapacity += location.StorageUsed
				
				if location.IsHealthy {
					healthyCount++
					totalLatency += location.Latency
				}
			}
		}
		
		info.HealthyNodes = healthyCount
		if healthyCount > 0 {
			info.AverageLatency = totalLatency / time.Duration(healthyCount)
		}
		
		regionInfo[region] = info
	}
	
	return regionInfo
}

// ValidatePlacement validates if a set of nodes provides good geographic distribution
func (gm *GeographicManager) ValidatePlacement(nodeIDs []string) (*PlacementValidation, error) {
	gm.locationMutex.RLock()
	defer gm.locationMutex.RUnlock()
	
	validation := &PlacementValidation{
		IsValid:     true,
		Issues:      make([]string, 0),
		Suggestions: make([]string, 0),
		Metrics:     make(map[string]float64),
	}
	
	if len(nodeIDs) == 0 {
		validation.IsValid = false
		validation.Issues = append(validation.Issues, "No nodes provided")
		return validation, nil
	}
	
	// Check node health
	unhealthyNodes := 0
	regions := make(map[string]int)
	minDistance := math.MaxFloat64
	
	for i, nodeID := range nodeIDs {
		location, exists := gm.nodeLocations[nodeID]
		if !exists {
			validation.Issues = append(validation.Issues, fmt.Sprintf("Node %s location unknown", nodeID))
			continue
		}
		
		if !location.IsHealthy {
			unhealthyNodes++
		}
		
		regions[location.Region]++
		
		// Check distances between nodes
		for j := i + 1; j < len(nodeIDs); j++ {
			otherLocation, exists := gm.nodeLocations[nodeIDs[j]]
			if !exists {
				continue
			}
			
			distance := gm.haversineDistance(
				location.Latitude, location.Longitude,
				otherLocation.Latitude, otherLocation.Longitude,
			)
			
			if distance < minDistance {
				minDistance = distance
			}
		}
	}
	
	// Validate health
	if unhealthyNodes > 0 {
		validation.Issues = append(validation.Issues, 
			fmt.Sprintf("%d unhealthy nodes in placement", unhealthyNodes))
	}
	
	// Validate geographic distribution
	if len(regions) == 1 {
		validation.Issues = append(validation.Issues, "All replicas in same region")
		validation.Suggestions = append(validation.Suggestions, "Distribute replicas across multiple regions")
	}
	
	// Validate minimum distance
	if minDistance < gm.config.MinDistanceBetweenReplicas {
		validation.Issues = append(validation.Issues, 
			fmt.Sprintf("Minimum distance between replicas (%.1f km) below threshold (%.1f km)", 
				minDistance, gm.config.MinDistanceBetweenReplicas))
	}
	
	// Set metrics
	validation.Metrics["unhealthy_nodes"] = float64(unhealthyNodes)
	validation.Metrics["unique_regions"] = float64(len(regions))
	validation.Metrics["min_distance_km"] = minDistance
	
	// Determine overall validity
	if len(validation.Issues) > 0 {
		validation.IsValid = false
	}
	
	return validation, nil
}

// PlacementValidation contains the results of placement validation
type PlacementValidation struct {
	IsValid     bool                `json:"is_valid"`
	Issues      []string            `json:"issues"`
	Suggestions []string            `json:"suggestions"`
	Metrics     map[string]float64  `json:"metrics"`
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}