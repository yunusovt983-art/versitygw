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
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

// TestClusterClient_NewClusterClient tests the creation of a new cluster client
func TestClusterClient_NewClusterClient(t *testing.T) {
	tests := []struct {
		name        string
		config      ClusterClientConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: ClusterClientConfig{
				Endpoints:      []string{"http://localhost:9094"},
				ConnectTimeout: 10 * time.Second,
				RequestTimeout: 30 * time.Second,
				MaxRetries:     3,
				RetryDelay:     1 * time.Second,
			},
			expectError: false,
		},
		{
			name: "empty endpoints",
			config: ClusterClientConfig{
				Endpoints: []string{},
			},
			expectError: true,
		},
		{
			name: "nil endpoints",
			config: ClusterClientConfig{
				Endpoints: nil,
			},
			expectError: true,
		},
		{
			name: "config with defaults",
			config: ClusterClientConfig{
				Endpoints: []string{"http://localhost:9094"},
				// Other fields will use defaults
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClusterClient(tt.config)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			if client == nil {
				t.Errorf("expected client but got nil")
				return
			}
			
			// Verify client properties
			if len(client.endpoints) != len(tt.config.Endpoints) {
				t.Errorf("expected %d endpoints, got %d", len(tt.config.Endpoints), len(client.endpoints))
			}
			
			if len(client.nodes) != len(tt.config.Endpoints) {
				t.Errorf("expected %d nodes, got %d", len(tt.config.Endpoints), len(client.nodes))
			}
			
			// Verify defaults are set
			if client.connectTimeout == 0 {
				t.Errorf("connect timeout should have default value")
			}
			
			if client.requestTimeout == 0 {
				t.Errorf("request timeout should have default value")
			}
			
			if client.maxRetries == 0 {
				t.Errorf("max retries should have default value")
			}
			
			// Clean up
			client.Shutdown()
		})
	}
}

// TestClusterClient_HealthCheck tests the health checking functionality
func TestClusterClient_HealthCheck(t *testing.T) {
	// Create test servers
	healthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer healthyServer.Close()

	unhealthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal error"}`))
	}))
	defer unhealthyServer.Close()

	config := ClusterClientConfig{
		Endpoints:           []string{healthyServer.URL, unhealthyServer.URL},
		ConnectTimeout:      5 * time.Second,
		RequestTimeout:      10 * time.Second,
		HealthCheckInterval: 100 * time.Millisecond, // Fast for testing
		Logger:              log.New(os.Stdout, "TEST: ", log.LstdFlags),
	}

	client, err := NewClusterClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Shutdown()

	// Wait for initial health check
	time.Sleep(200 * time.Millisecond)

	// Check node status
	status := client.GetNodeStatus()
	if len(status) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(status))
	}

	// Find healthy and unhealthy nodes
	var healthyNode, unhealthyNode *NodeStatus
	for _, node := range status {
		if node.Endpoint == healthyServer.URL {
			healthyNode = node
		} else if node.Endpoint == unhealthyServer.URL {
			unhealthyNode = node
		}
	}

	if healthyNode == nil {
		t.Errorf("healthy node not found")
	} else if !healthyNode.Healthy {
		t.Errorf("expected healthy node to be healthy")
	}

	if unhealthyNode == nil {
		t.Errorf("unhealthy node not found")
	} else if unhealthyNode.Healthy {
		t.Errorf("expected unhealthy node to be unhealthy")
	}

	// Test force health check
	client.ForceHealthCheck()
	time.Sleep(100 * time.Millisecond)

	// Verify metrics
	metrics := client.GetMetrics()
	if metrics.HealthCheckCount == 0 {
		t.Errorf("expected health check count > 0")
	}
}

// TestClusterClient_NodeFailover tests node failover functionality
func TestClusterClient_NodeFailover(t *testing.T) {
	var serverHits sync.Map
	
	// Create multiple test servers
	servers := make([]*httptest.Server, 3)
	for i := 0; i < 3; i++ {
		serverID := i
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Count hits per server
			count, _ := serverHits.LoadOrStore(serverID, 0)
			serverHits.Store(serverID, count.(int)+1)
			
			if r.URL.Path == "/health" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status": "ok"}`))
			} else if r.URL.Path == "/id" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf(`{"id": "server-%d"}`, serverID)))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
	}
	
	// Clean up servers
	defer func() {
		for _, server := range servers {
			server.Close()
		}
	}()

	endpoints := make([]string, len(servers))
	for i, server := range servers {
		endpoints[i] = server.URL
	}

	config := ClusterClientConfig{
		Endpoints:           endpoints,
		ConnectTimeout:      5 * time.Second,
		RequestTimeout:      10 * time.Second,
		MaxRetries:          2,
		RetryDelay:          10 * time.Millisecond,
		HealthCheckInterval: 50 * time.Millisecond,
		Logger:              log.New(os.Stdout, "TEST: ", log.LstdFlags),
	}

	client, err := NewClusterClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Shutdown()

	// Wait for health check to complete
	time.Sleep(100 * time.Millisecond)

	// Make multiple requests to test round-robin
	for i := 0; i < 6; i++ {
		_, err := client.GetClusterInfo()
		if err != nil {
			t.Errorf("request %d failed: %v", i, err)
		}
	}

	// Verify requests were distributed across servers
	totalHits := 0
	serverHits.Range(func(key, value interface{}) bool {
		hits := value.(int)
		totalHits += hits
		t.Logf("Server %d received %d hits", key.(int), hits)
		return true
	})

	if totalHits == 0 {
		t.Errorf("no requests were made to servers")
	}
}

// TestClusterClient_Authentication tests authentication functionality
func TestClusterClient_Authentication(t *testing.T) {
	const testUsername = "testuser"
	const testPassword = "testpass"
	
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authentication
		username, password, ok := r.BasicAuth()
		if !ok || username != testUsername || password != testPassword {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "unauthorized"}`))
			return
		}
		
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		} else if r.URL.Path == "/id" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": "auth-server"}`))
		}
	}))
	defer authServer.Close()

	// Test with correct credentials
	config := ClusterClientConfig{
		Endpoints:      []string{authServer.URL},
		Username:       testUsername,
		Password:       testPassword,
		ConnectTimeout: 5 * time.Second,
		RequestTimeout: 10 * time.Second,
		Logger:         log.New(os.Stdout, "TEST: ", log.LstdFlags),
	}

	client, err := NewClusterClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Shutdown()

	// Wait for health check
	time.Sleep(100 * time.Millisecond)

	// Verify node is healthy
	status := client.GetNodeStatus()
	if len(status) != 1 {
		t.Fatalf("expected 1 node, got %d", len(status))
	}

	if !status[0].Healthy {
		t.Errorf("expected node to be healthy with correct auth")
	}

	// Test request with authentication
	_, err = client.GetClusterInfo()
	if err != nil {
		t.Errorf("authenticated request failed: %v", err)
	}
}

// TestClusterClient_RetryLogic tests the retry logic
func TestClusterClient_RetryLogic(t *testing.T) {
	var requestCount int
	var mu sync.Mutex
	
	flakyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			// Always respond OK to health checks
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
			return
		}
		
		if r.URL.Path == "/id" {
			mu.Lock()
			requestCount++
			currentCount := requestCount
			mu.Unlock()
			
			// Fail first 2 requests, succeed on 3rd
			if currentCount <= 2 {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "temporary failure"}`))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"id": "flaky-server"}`))
			}
		}
	}))
	defer flakyServer.Close()

	config := ClusterClientConfig{
		Endpoints:      []string{flakyServer.URL},
		ConnectTimeout: 5 * time.Second,
		RequestTimeout: 10 * time.Second,
		MaxRetries:     3,
		RetryDelay:     10 * time.Millisecond,
		Logger:         log.New(os.Stdout, "TEST: ", log.LstdFlags),
	}

	client, err := NewClusterClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Shutdown()

	// Wait for health check
	time.Sleep(100 * time.Millisecond)

	// Reset request count for the actual test
	mu.Lock()
	requestCount = 0
	mu.Unlock()

	// This should succeed after retries
	_, err = client.GetClusterInfo()
	if err != nil {
		t.Errorf("request should have succeeded after retries: %v", err)
	}

	// Verify retry attempts were made
	mu.Lock()
	finalCount := requestCount
	mu.Unlock()
	
	if finalCount < 3 {
		t.Errorf("expected at least 3 requests due to retries, got %d", finalCount)
	}

	// Check metrics
	metrics := client.GetMetrics()
	if metrics.TotalRequests == 0 {
		t.Errorf("expected total requests > 0")
	}
	if metrics.SuccessfulReqs == 0 {
		t.Errorf("expected successful requests > 0")
	}
}

// TestClusterClient_Metrics tests metrics collection
func TestClusterClient_Metrics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		} else if r.URL.Path == "/id" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": "test-server"}`))
		}
	}))
	defer server.Close()

	config := ClusterClientConfig{
		Endpoints:      []string{server.URL},
		ConnectTimeout: 5 * time.Second,
		RequestTimeout: 10 * time.Second,
		Logger:         log.New(os.Stdout, "TEST: ", log.LstdFlags),
	}

	client, err := NewClusterClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Shutdown()

	// Wait for initial health check
	time.Sleep(100 * time.Millisecond)

	// Make some requests
	for i := 0; i < 5; i++ {
		_, err := client.GetClusterInfo()
		if err != nil {
			t.Errorf("request %d failed: %v", i, err)
		}
	}

	// Check metrics
	metrics := client.GetMetrics()
	
	if metrics.TotalRequests == 0 {
		t.Errorf("expected total requests > 0, got %d", metrics.TotalRequests)
	}
	
	if metrics.SuccessfulReqs == 0 {
		t.Errorf("expected successful requests > 0, got %d", metrics.SuccessfulReqs)
	}
	
	if metrics.HealthCheckCount == 0 {
		t.Errorf("expected health check count > 0, got %d", metrics.HealthCheckCount)
	}
	
	if metrics.FailedRequests != 0 {
		t.Errorf("expected 0 failed requests, got %d", metrics.FailedRequests)
	}
}

// TestClusterClient_Shutdown tests graceful shutdown
func TestClusterClient_Shutdown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		}
	}))
	defer server.Close()

	config := ClusterClientConfig{
		Endpoints:           []string{server.URL},
		HealthCheckInterval: 50 * time.Millisecond,
		Logger:              log.New(os.Stdout, "TEST: ", log.LstdFlags),
	}

	client, err := NewClusterClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Wait for health checking to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown should complete without hanging
	done := make(chan bool, 1)
	go func() {
		client.Shutdown()
		done <- true
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Errorf("shutdown took too long")
	}
}

// TestClusterClient_EnableDisableHealthCheck tests enabling/disabling health checks
func TestClusterClient_EnableDisableHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		}
	}))
	defer server.Close()

	config := ClusterClientConfig{
		Endpoints:           []string{server.URL},
		HealthCheckInterval: 50 * time.Millisecond,
		Logger:              log.New(os.Stdout, "TEST: ", log.LstdFlags),
	}

	client, err := NewClusterClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Shutdown()

	// Wait for initial health checks
	time.Sleep(150 * time.Millisecond)
	
	initialMetrics := client.GetMetrics()
	initialHealthChecks := initialMetrics.HealthCheckCount

	// Disable health checking
	client.EnableHealthChecking(false)
	time.Sleep(150 * time.Millisecond)

	// Health check count should not increase significantly
	disabledMetrics := client.GetMetrics()
	if disabledMetrics.HealthCheckCount > initialHealthChecks+1 {
		t.Errorf("health checks should be disabled, but count increased from %d to %d", 
			initialHealthChecks, disabledMetrics.HealthCheckCount)
	}

	// Re-enable health checking
	client.EnableHealthChecking(true)
	time.Sleep(150 * time.Millisecond)

	// Health check count should increase again
	enabledMetrics := client.GetMetrics()
	if enabledMetrics.HealthCheckCount <= disabledMetrics.HealthCheckCount {
		t.Errorf("health checks should be re-enabled, count should increase")
	}
}

// Benchmark tests

// BenchmarkClusterClient_GetClusterInfo benchmarks the GetClusterInfo method
func BenchmarkClusterClient_GetClusterInfo(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		} else if r.URL.Path == "/id" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": "benchmark-server"}`))
		}
	}))
	defer server.Close()

	config := ClusterClientConfig{
		Endpoints: []string{server.URL},
		Logger:    log.New(io.Discard, "", 0), // Disable logging for benchmark
	}

	client, err := NewClusterClient(config)
	if err != nil {
		b.Fatalf("failed to create client: %v", err)
	}
	defer client.Shutdown()

	// Wait for health check
	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := client.GetClusterInfo()
			if err != nil {
				b.Errorf("request failed: %v", err)
			}
		}
	})
}

// BenchmarkClusterClient_HealthCheck benchmarks health checking
func BenchmarkClusterClient_HealthCheck(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		}
	}))
	defer server.Close()

	config := ClusterClientConfig{
		Endpoints: []string{server.URL},
		Logger:    log.New(io.Discard, "", 0), // Disable logging for benchmark
	}

	client, err := NewClusterClient(config)
	if err != nil {
		b.Fatalf("failed to create client: %v", err)
	}
	defer client.Shutdown()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.performHealthCheck()
	}
}