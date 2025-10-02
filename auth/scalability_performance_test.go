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
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestDistributedSessionStoreScalability tests the scalability of distributed session store
func TestDistributedSessionStoreScalability(t *testing.T) {
	tests := []struct {
		name           string
		numNodes       int
		numSessions    int
		concurrency    int
		expectedMaxLatency time.Duration
	}{
		{
			name:           "Small cluster",
			numNodes:       3,
			numSessions:    1000,
			concurrency:    10,
			expectedMaxLatency: 50 * time.Millisecond,
		},
		{
			name:           "Medium cluster",
			numNodes:       5,
			numSessions:    10000,
			concurrency:    50,
			expectedMaxLatency: 100 * time.Millisecond,
		},
		{
			name:           "Large cluster",
			numNodes:       10,
			numSessions:    100000,
			concurrency:    100,
			expectedMaxLatency: 200 * time.Millisecond,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create cluster manager
			config := DefaultClusterConfig()
			config.NodeID = "test-node-1"
			clusterManager := NewClusterManager(config)
			
			// Create distributed session store
			storeConfig := DefaultDistributedStoreConfig()
			storeConfig.NodeID = "test-node-1"
			
			// Add cluster nodes
			for i := 2; i <= tt.numNodes; i++ {
				storeConfig.ClusterNodes = append(storeConfig.ClusterNodes, fmt.Sprintf("test-node-%d", i))
			}
			
			store := NewDistributedSessionStore(storeConfig, clusterManager)
			defer store.Close()
			
			// Test concurrent session operations
			var wg sync.WaitGroup
			latencies := make([]time.Duration, tt.numSessions)
			errors := make([]error, tt.numSessions)
			
			// Create sessions concurrently
			semaphore := make(chan struct{}, tt.concurrency)
			
			for i := 0; i < tt.numSessions; i++ {
				wg.Add(1)
				go func(index int) {
					defer wg.Done()
					
					semaphore <- struct{}{} // Acquire
					defer func() { <-semaphore }() // Release
					
					start := time.Now()
					
					session := &UserSession{
						ID:        fmt.Sprintf("session-%d", index),
						UserID:    fmt.Sprintf("user-%d", index%1000), // Simulate user distribution
						CreatedAt: time.Now(),
						ExpiresAt: time.Now().Add(1 * time.Hour),
						LastUsed:  time.Now(),
						IPAddress: "127.0.0.1",
						UserAgent: "test-agent",
					}
					
					err := store.StoreSession(session)
					latencies[index] = time.Since(start)
					errors[index] = err
				}(i)
			}
			
			wg.Wait()
			
			// Analyze results
			var totalLatency time.Duration
			var maxLatency time.Duration
			errorCount := 0
			
			for i := 0; i < tt.numSessions; i++ {
				if errors[i] != nil {
					errorCount++
				}
				
				totalLatency += latencies[i]
				if latencies[i] > maxLatency {
					maxLatency = latencies[i]
				}
			}
			
			avgLatency := totalLatency / time.Duration(tt.numSessions)
			
			t.Logf("Results for %s:", tt.name)
			t.Logf("  Sessions created: %d", tt.numSessions-errorCount)
			t.Logf("  Errors: %d", errorCount)
			t.Logf("  Average latency: %v", avgLatency)
			t.Logf("  Max latency: %v", maxLatency)
			
			// Assertions
			if errorCount > tt.numSessions/100 { // Allow 1% error rate
				t.Errorf("Too many errors: %d/%d", errorCount, tt.numSessions)
			}
			
			if maxLatency > tt.expectedMaxLatency {
				t.Errorf("Max latency too high: %v > %v", maxLatency, tt.expectedMaxLatency)
			}
			
			// Test retrieval performance
			start := time.Now()
			for i := 0; i < 1000; i++ {
				sessionID := fmt.Sprintf("session-%d", i)
				_, err := store.GetSession(sessionID)
				if err != nil {
					t.Errorf("Failed to retrieve session %s: %v", sessionID, err)
				}
			}
			retrievalTime := time.Since(start)
			
			t.Logf("  1000 retrievals took: %v", retrievalTime)
			
			if retrievalTime > 100*time.Millisecond {
				t.Errorf("Retrieval too slow: %v", retrievalTime)
			}
		})
	}
}

// TestLoadBalancerPerformance tests load balancer performance
func TestLoadBalancerPerformance(t *testing.T) {
	tests := []struct {
		name        string
		numNodes    int
		numRequests int
		strategy    LoadBalancingStrategy
	}{
		{
			name:        "Round Robin",
			numNodes:    5,
			numRequests: 10000,
			strategy:    RoundRobin,
		},
		{
			name:        "Least Connections",
			numNodes:    5,
			numRequests: 10000,
			strategy:    LeastConnections,
		},
		{
			name:        "Consistent Hashing",
			numNodes:    5,
			numRequests: 10000,
			strategy:    ConsistentHashing,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create cluster manager with nodes
			clusterManager := NewClusterManager(DefaultClusterConfig())
			
			// Register nodes
			for i := 1; i <= tt.numNodes; i++ {
				node := &NodeInfo{
					ID:      fmt.Sprintf("node-%d", i),
					Address: fmt.Sprintf("192.168.1.%d", i),
					Port:    8080,
					Status:  NodeStatusHealthy,
				}
				clusterManager.RegisterNode(node)
			}
			
			// Create load balancer
			config := DefaultLoadBalancerConfig()
			config.Strategy = tt.strategy
			lb := NewLoadBalancerSupport(config, clusterManager)
			
			err := lb.Start()
			if err != nil {
				t.Fatalf("Failed to start load balancer: %v", err)
			}
			defer lb.Stop()
			
			// Test node selection performance
			start := time.Now()
			nodeSelections := make(map[string]int)
			
			for i := 0; i < tt.numRequests; i++ {
				sessionID := fmt.Sprintf("session-%d", i)
				node, err := lb.SelectNode(sessionID)
				if err != nil {
					t.Errorf("Failed to select node: %v", err)
					continue
				}
				
				nodeSelections[node.ID]++
			}
			
			selectionTime := time.Since(start)
			avgSelectionTime := selectionTime / time.Duration(tt.numRequests)
			
			t.Logf("Results for %s:", tt.name)
			t.Logf("  Total selection time: %v", selectionTime)
			t.Logf("  Average selection time: %v", avgSelectionTime)
			t.Logf("  Requests per second: %.2f", float64(tt.numRequests)/selectionTime.Seconds())
			
			// Check distribution
			t.Logf("  Node distribution:")
			for nodeID, count := range nodeSelections {
				percentage := float64(count) / float64(tt.numRequests) * 100
				t.Logf("    %s: %d (%.2f%%)", nodeID, count, percentage)
			}
			
			// Performance assertions
			if avgSelectionTime > 1*time.Millisecond {
				t.Errorf("Node selection too slow: %v", avgSelectionTime)
			}
			
			// Distribution assertions (for round robin and least connections)
			if tt.strategy == RoundRobin {
				expectedPerNode := tt.numRequests / tt.numNodes
				tolerance := expectedPerNode / 10 // 10% tolerance
				
				for nodeID, count := range nodeSelections {
					if abs(count-expectedPerNode) > tolerance {
						t.Errorf("Poor distribution for node %s: got %d, expected ~%d", 
							nodeID, count, expectedPerNode)
					}
				}
			}
		})
	}
}

// TestClusterCommunicationPerformance tests cluster communication performance
func TestClusterCommunicationPerformance(t *testing.T) {
	numNodes := 5
	numMessages := 1000
	
	// Create cluster managers for each node
	managers := make([]ClusterManager, numNodes)
	
	for i := 0; i < numNodes; i++ {
		config := DefaultClusterConfig()
		config.NodeID = fmt.Sprintf("node-%d", i+1)
		config.ListenPort = 8080 + i
		
		managers[i] = NewClusterManager(config)
		
		// Start the manager
		err := managers[i].Start()
		if err != nil {
			t.Fatalf("Failed to start cluster manager %d: %v", i, err)
		}
		defer managers[i].Stop()
	}
	
	// Register all nodes with each other
	for i := 0; i < numNodes; i++ {
		for j := 0; j < numNodes; j++ {
			if i != j {
				node := &NodeInfo{
					ID:      fmt.Sprintf("node-%d", j+1),
					Address: "127.0.0.1",
					Port:    8080 + j,
					Status:  NodeStatusHealthy,
				}
				managers[i].RegisterNode(node)
			}
		}
	}
	
	// Wait for cluster to stabilize
	time.Sleep(1 * time.Second)
	
	// Test broadcast performance
	start := time.Now()
	
	for i := 0; i < numMessages; i++ {
		message := fmt.Sprintf("test-message-%d", i)
		err := managers[0].Broadcast("test", []byte(message))
		if err != nil {
			t.Errorf("Failed to broadcast message %d: %v", i, err)
		}
	}
	
	broadcastTime := time.Since(start)
	avgBroadcastTime := broadcastTime / time.Duration(numMessages)
	
	t.Logf("Broadcast performance:")
	t.Logf("  Total time: %v", broadcastTime)
	t.Logf("  Average per message: %v", avgBroadcastTime)
	t.Logf("  Messages per second: %.2f", float64(numMessages)/broadcastTime.Seconds())
	
	// Performance assertions
	if avgBroadcastTime > 10*time.Millisecond {
		t.Errorf("Broadcast too slow: %v", avgBroadcastTime)
	}
	
	// Test point-to-point communication performance
	start = time.Now()
	
	for i := 0; i < numMessages; i++ {
		message := fmt.Sprintf("p2p-message-%d", i)
		targetNode := fmt.Sprintf("node-%d", (i%4)+2) // Send to nodes 2-5
		err := managers[0].SendToNode(targetNode, "test", []byte(message))
		if err != nil {
			t.Errorf("Failed to send message %d to %s: %v", i, targetNode, err)
		}
	}
	
	p2pTime := time.Since(start)
	avgP2PTime := p2pTime / time.Duration(numMessages)
	
	t.Logf("Point-to-point performance:")
	t.Logf("  Total time: %v", p2pTime)
	t.Logf("  Average per message: %v", avgP2PTime)
	t.Logf("  Messages per second: %.2f", float64(numMessages)/p2pTime.Seconds())
	
	// Performance assertions
	if avgP2PTime > 5*time.Millisecond {
		t.Errorf("Point-to-point communication too slow: %v", avgP2PTime)
	}
}

// TestSessionSyncPerformance tests session synchronization performance
func TestSessionSyncPerformance(t *testing.T) {
	numNodes := 3
	numSessions := 5000
	
	// Create distributed stores for each node
	stores := make([]DistributedSessionStore, numNodes)
	clusterManagers := make([]ClusterManager, numNodes)
	
	for i := 0; i < numNodes; i++ {
		// Create cluster manager
		clusterConfig := DefaultClusterConfig()
		clusterConfig.NodeID = fmt.Sprintf("node-%d", i+1)
		clusterConfig.ListenPort = 9080 + i
		
		clusterManagers[i] = NewClusterManager(clusterConfig)
		clusterManagers[i].Start()
		defer clusterManagers[i].Stop()
		
		// Create distributed store
		storeConfig := DefaultDistributedStoreConfig()
		storeConfig.NodeID = fmt.Sprintf("node-%d", i+1)
		
		// Add other nodes
		for j := 0; j < numNodes; j++ {
			if i != j {
				storeConfig.ClusterNodes = append(storeConfig.ClusterNodes, fmt.Sprintf("node-%d", j+1))
			}
		}
		
		stores[i] = NewDistributedSessionStore(storeConfig, clusterManagers[i])
		defer stores[i].Close()
	}
	
	// Wait for cluster to stabilize
	time.Sleep(2 * time.Second)
	
	// Test session creation and synchronization performance
	start := time.Now()
	
	var wg sync.WaitGroup
	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			
			nodeIndex := index % numNodes
			session := &UserSession{
				ID:        fmt.Sprintf("session-%d", index),
				UserID:    fmt.Sprintf("user-%d", index%100),
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Hour),
				LastUsed:  time.Now(),
				IPAddress: "127.0.0.1",
				UserAgent: "test-agent",
			}
			
			err := stores[nodeIndex].StoreSession(session)
			if err != nil {
				t.Errorf("Failed to store session %d: %v", index, err)
			}
		}(i)
	}
	
	wg.Wait()
	creationTime := time.Since(start)
	
	t.Logf("Session creation performance:")
	t.Logf("  Total time: %v", creationTime)
	t.Logf("  Average per session: %v", creationTime/time.Duration(numSessions))
	t.Logf("  Sessions per second: %.2f", float64(numSessions)/creationTime.Seconds())
	
	// Wait for synchronization to complete
	time.Sleep(5 * time.Second)
	
	// Test cross-node session retrieval
	start = time.Now()
	retrievalErrors := 0
	
	for i := 0; i < 1000; i++ {
		sessionID := fmt.Sprintf("session-%d", i)
		nodeIndex := (i + 1) % numNodes // Retrieve from different node than created
		
		_, err := stores[nodeIndex].GetSession(sessionID)
		if err != nil {
			retrievalErrors++
		}
	}
	
	retrievalTime := time.Since(start)
	
	t.Logf("Cross-node retrieval performance:")
	t.Logf("  Total time: %v", retrievalTime)
	t.Logf("  Average per retrieval: %v", retrievalTime/1000)
	t.Logf("  Retrievals per second: %.2f", 1000.0/retrievalTime.Seconds())
	t.Logf("  Retrieval errors: %d/1000", retrievalErrors)
	
	// Performance assertions
	if creationTime/time.Duration(numSessions) > 5*time.Millisecond {
		t.Errorf("Session creation too slow: %v per session", creationTime/time.Duration(numSessions))
	}
	
	if retrievalTime/1000 > 10*time.Millisecond {
		t.Errorf("Cross-node retrieval too slow: %v per retrieval", retrievalTime/1000)
	}
	
	if retrievalErrors > 50 { // Allow 5% error rate for eventual consistency
		t.Errorf("Too many retrieval errors: %d/1000", retrievalErrors)
	}
	
	// Check synchronization stats
	for i, store := range stores {
		stats := store.GetStats()
		t.Logf("Node %d stats:", i+1)
		t.Logf("  Local sessions: %d", stats.LocalSessions)
		t.Logf("  Total sessions: %d", stats.TotalSessions)
		t.Logf("  Sync operations: %d", stats.SyncOperations)
		t.Logf("  Sync errors: %d", stats.SyncErrors)
	}
}

// BenchmarkDistributedSessionStore benchmarks distributed session store operations
func BenchmarkDistributedSessionStore(b *testing.B) {
	clusterManager := NewClusterManager(DefaultClusterConfig())
	store := NewDistributedSessionStore(DefaultDistributedStoreConfig(), clusterManager)
	defer store.Close()
	
	// Pre-populate some sessions
	for i := 0; i < 1000; i++ {
		session := &UserSession{
			ID:        fmt.Sprintf("session-%d", i),
			UserID:    fmt.Sprintf("user-%d", i%100),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			LastUsed:  time.Now(),
		}
		store.StoreSession(session)
	}
	
	b.Run("StoreSession", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			session := &UserSession{
				ID:        fmt.Sprintf("bench-session-%d", i),
				UserID:    fmt.Sprintf("bench-user-%d", i%100),
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Hour),
				LastUsed:  time.Now(),
			}
			store.StoreSession(session)
		}
	})
	
	b.Run("GetSession", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sessionID := fmt.Sprintf("session-%d", i%1000)
			store.GetSession(sessionID)
		}
	})
	
	b.Run("DeleteSession", func(b *testing.B) {
		// Pre-create sessions for deletion
		for i := 0; i < b.N; i++ {
			session := &UserSession{
				ID:        fmt.Sprintf("delete-session-%d", i),
				UserID:    fmt.Sprintf("delete-user-%d", i%100),
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Hour),
				LastUsed:  time.Now(),
			}
			store.StoreSession(session)
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sessionID := fmt.Sprintf("delete-session-%d", i)
			store.DeleteSession(sessionID)
		}
	})
}

// BenchmarkLoadBalancer benchmarks load balancer operations
func BenchmarkLoadBalancer(b *testing.B) {
	clusterManager := NewClusterManager(DefaultClusterConfig())
	
	// Register nodes
	for i := 1; i <= 10; i++ {
		node := &NodeInfo{
			ID:      fmt.Sprintf("node-%d", i),
			Address: fmt.Sprintf("192.168.1.%d", i),
			Port:    8080,
			Status:  NodeStatusHealthy,
		}
		clusterManager.RegisterNode(node)
	}
	
	strategies := []LoadBalancingStrategy{
		RoundRobin,
		LeastConnections,
		ConsistentHashing,
		IPHash,
	}
	
	for _, strategy := range strategies {
		b.Run(strategy.String(), func(b *testing.B) {
			config := DefaultLoadBalancerConfig()
			config.Strategy = strategy
			lb := NewLoadBalancerSupport(config, clusterManager)
			lb.Start()
			defer lb.Stop()
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sessionID := fmt.Sprintf("session-%d", i)
				lb.SelectNode(sessionID)
			}
		})
	}
}

// TestConcurrentOperations tests concurrent operations under load
func TestConcurrentOperations(t *testing.T) {
	clusterManager := NewClusterManager(DefaultClusterConfig())
	store := NewDistributedSessionStore(DefaultDistributedStoreConfig(), clusterManager)
	defer store.Close()
	
	numGoroutines := 100
	operationsPerGoroutine := 100
	
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*operationsPerGoroutine)
	
	start := time.Now()
	
	// Start concurrent operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerGoroutine; j++ {
				sessionID := fmt.Sprintf("session-%d-%d", goroutineID, j)
				userID := fmt.Sprintf("user-%d", (goroutineID*operationsPerGoroutine+j)%1000)
				
				// Create session
				session := &UserSession{
					ID:        sessionID,
					UserID:    userID,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(1 * time.Hour),
					LastUsed:  time.Now(),
				}
				
				if err := store.StoreSession(session); err != nil {
					errors <- fmt.Errorf("store error: %w", err)
					continue
				}
				
				// Retrieve session
				if _, err := store.GetSession(sessionID); err != nil {
					errors <- fmt.Errorf("get error: %w", err)
					continue
				}
				
				// Update session
				session.LastUsed = time.Now()
				if err := store.UpdateSession(session); err != nil {
					errors <- fmt.Errorf("update error: %w", err)
					continue
				}
				
				// Delete session (every 10th operation)
				if j%10 == 0 {
					if err := store.DeleteSession(sessionID); err != nil {
						errors <- fmt.Errorf("delete error: %w", err)
					}
				}
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	totalTime := time.Since(start)
	totalOperations := numGoroutines * operationsPerGoroutine * 3 // create, get, update
	
	// Count errors
	errorCount := 0
	for err := range errors {
		errorCount++
		if errorCount <= 10 { // Log first 10 errors
			t.Logf("Error: %v", err)
		}
	}
	
	t.Logf("Concurrent operations results:")
	t.Logf("  Total operations: %d", totalOperations)
	t.Logf("  Total time: %v", totalTime)
	t.Logf("  Operations per second: %.2f", float64(totalOperations)/totalTime.Seconds())
	t.Logf("  Errors: %d (%.2f%%)", errorCount, float64(errorCount)/float64(totalOperations)*100)
	
	// Performance assertions
	if totalTime > 30*time.Second {
		t.Errorf("Concurrent operations took too long: %v", totalTime)
	}
	
	if errorCount > totalOperations/100 { // Allow 1% error rate
		t.Errorf("Too many errors: %d/%d", errorCount, totalOperations)
	}
	
	// Check final stats
	stats := store.GetStats()
	t.Logf("Final stats:")
	t.Logf("  Total sessions: %d", stats.TotalSessions)
	t.Logf("  Sync operations: %d", stats.SyncOperations)
	t.Logf("  Sync errors: %d", stats.SyncErrors)
}

// Helper function
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}