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
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// TestIPFSBackend_Integration tests the integration between IPFS backend and cluster client
func TestIPFSBackend_Integration(t *testing.T) {
	// Create a mock IPFS cluster server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		} else if r.URL.Path == "/id" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": "test-cluster", "version": "1.0.0"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create IPFS backend configuration
	config := &IPFSConfig{
		ClusterEndpoints: []string{server.URL},
		ConnectTimeout:   5 * time.Second,
		RequestTimeout:   10 * time.Second,
		MaxRetries:       3,
		RetryDelay:       100 * time.Millisecond,
		ReplicationMin:   1,
		ReplicationMax:   3,
		MaxConcurrentPins: 100,
		PinTimeout:       60 * time.Second,
		ChunkSize:        1024 * 1024,
		CompressionEnabled: false,
		MetadataDBType:   "memory",
		CacheEnabled:     false,
		MetricsEnabled:   true,
		LogLevel:         "info",
	}

	// Create IPFS backend
	backend, err := New(config, IPFSOptions{
		Logger: log.New(os.Stdout, "TEST: ", log.LstdFlags),
	})
	if err != nil {
		t.Fatalf("failed to create IPFS backend: %v", err)
	}
	defer backend.Shutdown()

	// Wait for initialization
	time.Sleep(100 * time.Millisecond)

	// Test backend health
	if !backend.IsHealthy() {
		t.Errorf("backend should be healthy")
	}

	// Test cluster info
	clusterInfo, err := backend.GetClusterInfo()
	if err != nil {
		t.Errorf("failed to get cluster info: %v", err)
	}
	if clusterInfo == nil {
		t.Errorf("cluster info should not be nil")
	}

	// Test node status
	nodeStatus := backend.GetClusterNodeStatus()
	if len(nodeStatus) != 1 {
		t.Errorf("expected 1 node, got %d", len(nodeStatus))
	}
	if !nodeStatus[0].Healthy {
		t.Errorf("node should be healthy")
	}

	// Test metrics
	metrics := backend.GetClusterMetrics()
	if metrics == nil {
		t.Errorf("metrics should not be nil")
	}

	// Test stats
	stats := backend.GetStats()
	if stats["backend_type"] != "ipfs-cluster" {
		t.Errorf("expected backend_type to be 'ipfs-cluster', got %v", stats["backend_type"])
	}
	if stats["cluster_total_nodes"] != 1 {
		t.Errorf("expected 1 total node, got %v", stats["cluster_total_nodes"])
	}
	if stats["cluster_healthy_nodes"] != 1 {
		t.Errorf("expected 1 healthy node, got %v", stats["cluster_healthy_nodes"])
	}

	// Test force health check
	backend.ForceClusterHealthCheck()
	time.Sleep(50 * time.Millisecond)

	// Test enable/disable health checking
	backend.EnableClusterHealthChecking(false)
	backend.EnableClusterHealthChecking(true)
}

// TestIPFSBackend_MultipleNodes tests backend with multiple cluster nodes
func TestIPFSBackend_MultipleNodes(t *testing.T) {
	// Create multiple mock servers
	servers := make([]*httptest.Server, 3)
	endpoints := make([]string, 3)
	
	for i := 0; i < 3; i++ {
		serverID := i
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status": "ok"}`))
			} else if r.URL.Path == "/id" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"id": "cluster-` + string(rune('0'+serverID)) + `"}`))
			}
		}))
		endpoints[i] = servers[i].URL
	}
	
	// Clean up servers
	defer func() {
		for _, server := range servers {
			server.Close()
		}
	}()

	config := &IPFSConfig{
		ClusterEndpoints: endpoints,
		ConnectTimeout:   5 * time.Second,
		RequestTimeout:   10 * time.Second,
		MaxRetries:       2,
		RetryDelay:       50 * time.Millisecond,
		ReplicationMin:   1,
		ReplicationMax:   3,
	}

	backend, err := New(config, IPFSOptions{
		Logger: log.New(os.Stdout, "MULTI-TEST: ", log.LstdFlags),
	})
	if err != nil {
		t.Fatalf("failed to create IPFS backend: %v", err)
	}
	defer backend.Shutdown()

	// Wait for health checks
	time.Sleep(200 * time.Millisecond)

	// Verify all nodes are healthy
	nodeStatus := backend.GetClusterNodeStatus()
	if len(nodeStatus) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(nodeStatus))
	}

	healthyCount := 0
	for _, node := range nodeStatus {
		if node.Healthy {
			healthyCount++
		}
	}
	if healthyCount != 3 {
		t.Errorf("expected 3 healthy nodes, got %d", healthyCount)
	}

	// Test stats with multiple nodes
	stats := backend.GetStats()
	if stats["cluster_total_nodes"] != 3 {
		t.Errorf("expected 3 total nodes, got %v", stats["cluster_total_nodes"])
	}
	if stats["cluster_healthy_nodes"] != 3 {
		t.Errorf("expected 3 healthy nodes, got %v", stats["cluster_healthy_nodes"])
	}
}

// TestIPFSBackend_UnhealthyCluster tests backend behavior with unhealthy cluster
func TestIPFSBackend_UnhealthyCluster(t *testing.T) {
	// Create a server that always returns errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "server error"}`))
	}))
	defer server.Close()

	config := &IPFSConfig{
		ClusterEndpoints: []string{server.URL},
		ConnectTimeout:   1 * time.Second,
		RequestTimeout:   2 * time.Second,
		MaxRetries:       1,
		RetryDelay:       10 * time.Millisecond,
	}

	backend, err := New(config, IPFSOptions{
		Logger: log.New(os.Stdout, "UNHEALTHY-TEST: ", log.LstdFlags),
	})
	if err != nil {
		t.Fatalf("failed to create IPFS backend: %v", err)
	}
	defer backend.Shutdown()

	// Wait for health check
	time.Sleep(200 * time.Millisecond)

	// Backend should be unhealthy due to no healthy cluster nodes
	if backend.IsHealthy() {
		t.Errorf("backend should be unhealthy when cluster is unhealthy")
	}

	// Node should be marked as unhealthy
	nodeStatus := backend.GetClusterNodeStatus()
	if len(nodeStatus) != 1 {
		t.Errorf("expected 1 node, got %d", len(nodeStatus))
	}
	if nodeStatus[0].Healthy {
		t.Errorf("node should be unhealthy")
	}

	// Stats should reflect unhealthy state
	stats := backend.GetStats()
	if stats["cluster_healthy_nodes"] != 0 {
		t.Errorf("expected 0 healthy nodes, got %v", stats["cluster_healthy_nodes"])
	}
	if stats["healthy"] != false {
		t.Errorf("expected backend to be unhealthy")
	}
}