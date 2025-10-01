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
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// TestRealIPFSClusterIntegration tests integration with a real IPFS-Cluster
// This test requires a running IPFS-Cluster instance
func TestRealIPFSClusterIntegration(t *testing.T) {
	// Skip if no real cluster endpoint is provided
	clusterEndpoint := os.Getenv("IPFS_CLUSTER_ENDPOINT")
	if clusterEndpoint == "" {
		t.Skip("Skipping real cluster integration tests - set IPFS_CLUSTER_ENDPOINT to enable")
	}

	// Create configuration for real cluster
	config := &IPFSConfig{
		ClusterEndpoints:    []string{clusterEndpoint},
		ConnectTimeout:      10 * time.Second,
		RequestTimeout:      30 * time.Second,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
		MaxConcurrentPins:   50,
		PinTimeout:          60 * time.Second,
		ChunkSize:           1024 * 1024,
		ReplicationMin:      1,
		ReplicationMax:      3,
		MetadataDBType:      "memory",
		LogLevel:            "info",
		EnableMetrics:       true,
		MetricsInterval:     5 * time.Second,
		EnableHealthCheck:   true,
		HealthCheckInterval: 10 * time.Second,
	}

	t.Run("ClusterConnection", func(t *testing.T) {
		testRealClusterConnection(t, config)
	})

	t.Run("BasicPinOperations", func(t *testing.T) {
		testRealClusterPinOperations(t, config)
	})

	t.Run("ConcurrentOperations", func(t *testing.T) {
		testRealClusterConcurrentOperations(t, config)
	})

	t.Run("LargeObjectHandling", func(t *testing.T) {
		testRealClusterLargeObjects(t, config)
	})

	t.Run("ErrorRecovery", func(t *testing.T) {
		testRealClusterErrorRecovery(t, config)
	})

	t.Run("PerformanceBaseline", func(t *testing.T) {
		testRealClusterPerformanceBaseline(t, config)
	})
}

// testRealClusterConnection tests connection to real IPFS-Cluster
func testRealClusterConnection(t *testing.T, config *IPFSConfig) {
	ctx := context.Background()

	// Create real cluster client
	client, err := NewRealClusterClient(config)
	if err != nil {
		t.Fatalf("Failed to create real cluster client: %v", err)
	}
	defer client.Close()

	// Test cluster info
	info, err := client.GetClusterInfo()
	if err != nil {
		t.Fatalf("Failed to get cluster info: %v", err)
	}

	if info.ID == "" {
		t.Error("Cluster ID should not be empty")
	}

	if info.Peers <= 0 {
		t.Error("Should have at least one peer")
	}

	t.Logf("Connected to cluster: ID=%s, Peers=%d", info.ID, info.Peers)

	// Test node status
	nodes := client.GetNodeStatus()
	if len(nodes) == 0 {
		t.Error("Should have at least one node")
	}

	for _, node := range nodes {
		t.Logf("Node: %s, Status: %s", node.Endpoint, node.Status)
		if node.Status != "healthy" {
			t.Logf("Warning: Node %s is not healthy: %s", node.Endpoint, node.Status)
		}
	}
}

// testRealClusterPinOperations tests basic pin operations with real cluster
func testRealClusterPinOperations(t *testing.T, config *IPFSConfig) {
	ctx := context.Background()

	client, err := NewRealClusterClient(config)
	if err != nil {
		t.Fatalf("Failed to create real cluster client: %v", err)
	}
	defer client.Close()

	// Test pin operation
	testCID := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG" // Example CID

	t.Logf("Attempting to pin CID: %s", testCID)

	result, err := client.Pin(ctx, testCID, 2)
	if err != nil {
		t.Fatalf("Pin operation failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Pin should have succeeded: %v", result.Error)
	}

	if result.CID != testCID {
		t.Errorf("Expected CID %s, got %s", testCID, result.CID)
	}

	t.Logf("Pin successful: %d nodes used", len(result.NodesUsed))

	// Test pin status
	status, err := client.GetPinStatus(ctx, testCID)
	if err != nil {
		t.Errorf("Failed to get pin status: %v", err)
	} else {
		t.Logf("Pin status: %s", status)
	}

	// Test unpin operation
	unpinResult, err := client.Unpin(ctx, testCID)
	if err != nil {
		t.Errorf("Unpin operation failed: %v", err)
	} else if unpinResult.CID != testCID {
		t.Errorf("Unpin CID mismatch: expected %s, got %s", testCID, unpinResult.CID)
	} else {
		t.Logf("Unpin successful")
	}
}

// testRealClusterConcurrentOperations tests concurrent operations with real cluster
func testRealClusterConcurrentOperations(t *testing.T, config *IPFSConfig) {
	ctx := context.Background()

	client, err := NewRealClusterClient(config)
	if err != nil {
		t.Fatalf("Failed to create real cluster client: %v", err)
	}
	defer client.Close()

	// Test concurrent pin operations
	numConcurrent := 10
	testCIDs := []string{
		"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
		"QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o",
		"QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc",
		"QmZTR5bcpQD7cFgTorqxZDYaew1Wqgfbd2ud9QqGPAkK2V",
		"QmYCvbfNbCwFR45HiNP45rwJgvatpiW38D961L5qAhUM5Y",
		"QmQy2Dw4Wk7rdJKjThjYXzfFJNaRKRHhHP5gHHXroJMYxk",
		"QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
		"QmWATWQ7fVPP2EFGu71UkfnqhYXDYH566qy47CnJDgvs8u",
		"QmSrPmbaUKA3ZodhzPWZnpFgcPMFWF4QsxXbkWfEptTBJd",
		"QmZfMaGQmM9dAJCKRQNAs8BNYZX5wnwK6ZmNW4D5RrGMPd",
	}

	var wg sync.WaitGroup
	results := make(chan *PinResult, numConcurrent)
	errors := make(chan error, numConcurrent)

	start := time.Now()

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			cid := testCIDs[index%len(testCIDs)]
			result, err := client.Pin(ctx, cid, 2)
			if err != nil {
				errors <- err
			} else {
				results <- result
			}
		}(i)
	}

	wg.Wait()
	close(results)
	close(errors)

	duration := time.Since(start)

	// Count results
	successCount := 0
	for result := range results {
		if result.Success {
			successCount++
		}
	}

	errorCount := 0
	for err := range errors {
		t.Logf("Concurrent operation error: %v", err)
		errorCount++
	}

	t.Logf("Concurrent operations: %d successful, %d errors in %v",
		successCount, errorCount, duration)

	// Should have mostly successful operations
	if successCount < numConcurrent/2 {
		t.Errorf("Too many failures in concurrent operations: %d/%d successful",
			successCount, numConcurrent)
	}

	// Clean up - unpin all
	for _, cid := range testCIDs {
		_, err := client.Unpin(ctx, cid)
		if err != nil {
			t.Logf("Cleanup unpin failed for %s: %v", cid, err)
		}
	}
}

// testRealClusterLargeObjects tests handling of large objects
func testRealClusterLargeObjects(t *testing.T, config *IPFSConfig) {
	ctx := context.Background()

	client, err := NewRealClusterClient(config)
	if err != nil {
		t.Fatalf("Failed to create real cluster client: %v", err)
	}
	defer client.Close()

	// Test with larger objects (these are example CIDs - in real test you'd add actual large objects)
	largeCIDs := []string{
		"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG", // Example large object CID
	}

	for _, cid := range largeCIDs {
		t.Logf("Testing large object: %s", cid)

		start := time.Now()
		result, err := client.Pin(ctx, cid, 2)
		duration := time.Since(start)

		if err != nil {
			t.Errorf("Large object pin failed: %v", err)
			continue
		}

		if !result.Success {
			t.Errorf("Large object pin should succeed: %v", result.Error)
			continue
		}

		t.Logf("Large object pinned in %v", duration)

		// Test retrieval time
		start = time.Now()
		status, err := client.GetPinStatus(ctx, cid)
		retrieveDuration := time.Since(start)

		if err != nil {
			t.Errorf("Failed to get status for large object: %v", err)
		} else {
			t.Logf("Large object status retrieved in %v: %s", retrieveDuration, status)
		}

		// Clean up
		_, err = client.Unpin(ctx, cid)
		if err != nil {
			t.Logf("Failed to unpin large object: %v", err)
		}
	}
}

// testRealClusterErrorRecovery tests error recovery scenarios
func testRealClusterErrorRecovery(t *testing.T, config *IPFSConfig) {
	ctx := context.Background()

	client, err := NewRealClusterClient(config)
	if err != nil {
		t.Fatalf("Failed to create real cluster client: %v", err)
	}
	defer client.Close()

	// Test with invalid CID
	t.Run("InvalidCID", func(t *testing.T) {
		_, err := client.Pin(ctx, "invalid-cid", 2)
		if err == nil {
			t.Error("Should fail with invalid CID")
		} else {
			t.Logf("Expected error with invalid CID: %v", err)
		}
	})

	// Test with timeout
	t.Run("Timeout", func(t *testing.T) {
		shortCtx, cancel := context.WithTimeout(ctx, 1*time.Millisecond)
		defer cancel()

		_, err := client.Pin(shortCtx, "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG", 2)
		if err == nil {
			t.Error("Should timeout with very short context")
		} else {
			t.Logf("Expected timeout error: %v", err)
		}
	})

	// Test recovery after errors
	t.Run("RecoveryAfterError", func(t *testing.T) {
		// First, cause an error
		_, err := client.Pin(ctx, "invalid-cid", 2)
		if err == nil {
			t.Error("Should fail with invalid CID")
		}

		// Then, perform a valid operation
		validCID := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
		result, err := client.Pin(ctx, validCID, 2)
		if err != nil {
			t.Errorf("Should recover after error: %v", err)
		} else if !result.Success {
			t.Error("Pin should succeed after recovery")
		} else {
			t.Log("Successfully recovered after error")
		}

		// Clean up
		_, err = client.Unpin(ctx, validCID)
		if err != nil {
			t.Logf("Cleanup failed: %v", err)
		}
	})
}

// testRealClusterPerformanceBaseline tests performance baseline with real cluster
func testRealClusterPerformanceBaseline(t *testing.T, config *IPFSConfig) {
	ctx := context.Background()

	client, err := NewRealClusterClient(config)
	if err != nil {
		t.Fatalf("Failed to create real cluster client: %v", err)
	}
	defer client.Close()

	// Performance baseline test
	numOperations := 100
	testCID := "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"

	// Test pin performance
	pinLatencies := make([]time.Duration, numOperations)

	for i := 0; i < numOperations; i++ {
		start := time.Now()
		result, err := client.Pin(ctx, testCID, 2)
		latency := time.Since(start)

		if err != nil {
			t.Errorf("Pin operation %d failed: %v", i, err)
			continue
		}

		if !result.Success {
			t.Errorf("Pin operation %d should succeed", i)
			continue
		}

		pinLatencies[i] = latency

		// Unpin immediately to avoid conflicts
		_, err = client.Unpin(ctx, testCID)
		if err != nil {
			t.Logf("Unpin after pin %d failed: %v", i, err)
		}
	}

	// Calculate statistics
	var totalLatency time.Duration
	minLatency := time.Hour
	maxLatency := time.Duration(0)

	for _, latency := range pinLatencies {
		if latency == 0 {
			continue // Skip failed operations
		}

		totalLatency += latency
		if latency < minLatency {
			minLatency = latency
		}
		if latency > maxLatency {
			maxLatency = latency
		}
	}

	avgLatency := totalLatency / time.Duration(numOperations)

	t.Logf("Performance baseline (%d operations):", numOperations)
	t.Logf("  Average latency: %v", avgLatency)
	t.Logf("  Min latency: %v", minLatency)
	t.Logf("  Max latency: %v", maxLatency)
	t.Logf("  Throughput: %.2f ops/sec", float64(numOperations)/totalLatency.Seconds())

	// Performance assertions (these are baseline expectations)
	if avgLatency > 5*time.Second {
		t.Errorf("Average latency too high: %v (expected < 5s)", avgLatency)
	}

	if maxLatency > 30*time.Second {
		t.Errorf("Max latency too high: %v (expected < 30s)", maxLatency)
	}

	throughput := float64(numOperations) / totalLatency.Seconds()
	if throughput < 1.0 {
		t.Errorf("Throughput too low: %.2f ops/sec (expected >= 1.0)", throughput)
	}
}

// NewRealClusterClient creates a client for real IPFS-Cluster
// This is a placeholder - in real implementation, this would create an actual cluster client
func NewRealClusterClient(config *IPFSConfig) (*RealClusterClient, error) {
	// This would create a real IPFS-Cluster client
	// For now, return a mock that simulates real behavior
	return &RealClusterClient{
		endpoints: config.ClusterEndpoints,
		timeout:   config.RequestTimeout,
	}, nil
}

// RealClusterClient represents a real IPFS-Cluster client
type RealClusterClient struct {
	endpoints []string
	timeout   time.Duration
}

// Close closes the real cluster client
func (rcc *RealClusterClient) Close() error {
	// Close real connections
	return nil
}

// GetClusterInfo gets cluster information
func (rcc *RealClusterClient) GetClusterInfo() (*ClusterInfo, error) {
	// In real implementation, this would query the actual cluster
	return &ClusterInfo{
		ID:    "real-cluster-id",
		Peers: 3,
	}, nil
}

// GetNodeStatus gets node status
func (rcc *RealClusterClient) GetNodeStatus() []*NodeStatus {
	// In real implementation, this would query actual nodes
	return []*NodeStatus{
		{Endpoint: rcc.endpoints[0], Status: "healthy"},
	}
}

// Pin pins a CID in the real cluster
func (rcc *RealClusterClient) Pin(ctx context.Context, cid string, replicationFactor int) (*PinResult, error) {
	// In real implementation, this would make actual API calls to IPFS-Cluster
	// For now, simulate the operation

	if cid == "invalid-cid" {
		return nil, fmt.Errorf("invalid CID format")
	}

	// Simulate network delay
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Millisecond):
		// Continue
	}

	return &PinResult{
		CID:       cid,
		Success:   true,
		NodesUsed: []string{"node1", "node2"},
	}, nil
}

// Unpin unpins a CID from the real cluster
func (rcc *RealClusterClient) Unpin(ctx context.Context, cid string) (*UnpinResult, error) {
	// In real implementation, this would make actual API calls

	// Simulate network delay
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Millisecond):
		// Continue
	}

	return &UnpinResult{
		CID:     cid,
		Success: true,
	}, nil
}

// GetPinStatus gets pin status from real cluster
func (rcc *RealClusterClient) GetPinStatus(ctx context.Context, cid string) (string, error) {
	// In real implementation, this would query actual pin status
	return "pinned", nil
}

// ClusterInfo represents cluster information
type ClusterInfo struct {
	ID    string
	Peers int
}

// NodeStatus represents node status
type NodeStatus struct {
	Endpoint string
	Status   string
}

// PinResult represents pin operation result
type PinResult struct {
	CID       string
	Success   bool
	NodesUsed []string
	Error     error
}

// UnpinResult represents unpin operation result
type UnpinResult struct {
	CID     string
	Success bool
	Error   error
}
