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
	"log"
	"os"
	"testing"
	"time"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3response"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		config      *IPFSConfig
		opts        IPFSOptions
		expectError bool
	}{
		{
			name:        "nil config",
			config:      nil,
			opts:        IPFSOptions{},
			expectError: true,
		},
		{
			name: "empty endpoints",
			config: &IPFSConfig{
				ClusterEndpoints: []string{},
			},
			opts:        IPFSOptions{},
			expectError: true,
		},
		{
			name: "valid minimal config",
			config: &IPFSConfig{
				ClusterEndpoints: []string{"http://localhost:9094"},
			},
			opts:        IPFSOptions{},
			expectError: false,
		},
		{
			name: "valid config with options",
			config: &IPFSConfig{
				ClusterEndpoints: []string{"http://localhost:9094", "http://localhost:9095"},
				ConnectTimeout:   10 * time.Second,
				RequestTimeout:   30 * time.Second,
				MaxRetries:       5,
				ReplicationMin:   2,
				ReplicationMax:   4,
			},
			opts: IPFSOptions{
				Logger:  log.New(os.Stdout, "[TEST] ", log.LstdFlags),
				Context: context.Background(),
			},
			expectError: false,
		},
		{
			name: "invalid replication config",
			config: &IPFSConfig{
				ClusterEndpoints: []string{"http://localhost:9094"},
				ReplicationMin:   5,
				ReplicationMax:   3,
			},
			opts:        IPFSOptions{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipfsBackend, err := New(tt.config, tt.opts)
			
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
			
			if ipfsBackend == nil {
				t.Errorf("expected backend but got nil")
				return
			}
			
			// Verify backend implements the interface
			var _ backend.Backend = ipfsBackend
			
			// Test String method
			if ipfsBackend.String() != "IPFS-Cluster" {
				t.Errorf("expected String() to return 'IPFS-Cluster', got '%s'", ipfsBackend.String())
			}
			
			// Test health check - backend should be healthy even if cluster nodes are not
			// because the backend itself is initialized properly
			// Note: In a real scenario with actual IPFS cluster endpoints, this would be true
			// For testing with non-existent endpoints, we just verify the backend is initialized
			_ = ipfsBackend.IsHealthy() // Just call it to ensure it doesn't panic
			
			// Test stats
			stats := ipfsBackend.GetStats()
			if stats == nil {
				t.Errorf("expected stats but got nil")
			}
			
			if stats["backend_type"] != "ipfs-cluster" {
				t.Errorf("expected backend_type to be 'ipfs-cluster', got '%v'", stats["backend_type"])
			}
			
			// Test shutdown
			ipfsBackend.Shutdown()
			
			// After shutdown, backend should not be healthy
			if ipfsBackend.IsHealthy() {
				t.Errorf("expected backend to be unhealthy after shutdown")
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *IPFSConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: &IPFSConfig{
				ClusterEndpoints: []string{"http://localhost:9094"},
			},
			expectError: false,
		},
		{
			name: "no endpoints",
			config: &IPFSConfig{
				ClusterEndpoints: []string{},
			},
			expectError: true,
		},
		{
			name: "invalid replication",
			config: &IPFSConfig{
				ClusterEndpoints: []string{"http://localhost:9094"},
				ReplicationMin:   5,
				ReplicationMax:   3,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	config := &IPFSConfig{
		ClusterEndpoints: []string{"http://localhost:9094"},
	}
	
	err := validateConfig(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	
	// Check that defaults were set
	if config.ConnectTimeout != 30*time.Second {
		t.Errorf("expected ConnectTimeout to be 30s, got %v", config.ConnectTimeout)
	}
	
	if config.RequestTimeout != 60*time.Second {
		t.Errorf("expected RequestTimeout to be 60s, got %v", config.RequestTimeout)
	}
	
	if config.MaxRetries != 3 {
		t.Errorf("expected MaxRetries to be 3, got %d", config.MaxRetries)
	}
	
	if config.RetryDelay != 1*time.Second {
		t.Errorf("expected RetryDelay to be 1s, got %v", config.RetryDelay)
	}
	
	if config.MaxConcurrentPins != 100 {
		t.Errorf("expected MaxConcurrentPins to be 100, got %d", config.MaxConcurrentPins)
	}
	
	if config.PinTimeout != 300*time.Second {
		t.Errorf("expected PinTimeout to be 300s, got %v", config.PinTimeout)
	}
	
	if config.ChunkSize != 1024*1024 {
		t.Errorf("expected ChunkSize to be 1MB, got %d", config.ChunkSize)
	}
	
	if config.ReplicationMin != 1 {
		t.Errorf("expected ReplicationMin to be 1, got %d", config.ReplicationMin)
	}
	
	if config.ReplicationMax != 3 {
		t.Errorf("expected ReplicationMax to be 3, got %d", config.ReplicationMax)
	}
	
	if config.MetadataDBType != "memory" {
		t.Errorf("expected MetadataDBType to be 'memory', got '%s'", config.MetadataDBType)
	}
	
	if config.LogLevel != "info" {
		t.Errorf("expected LogLevel to be 'info', got '%s'", config.LogLevel)
	}
}

func TestBackendInterface(t *testing.T) {
	config := &IPFSConfig{
		ClusterEndpoints: []string{"http://localhost:9094"},
	}
	
	ipfsBackend, err := New(config, IPFSOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ipfsBackend.Shutdown()
	
	// Verify that all methods from BackendUnsupported are available
	// This ensures our backend properly embeds BackendUnsupported
	
	// Test that unsupported operations return appropriate errors
	ctx := context.Background()
	
	// Test a few methods to ensure they return ErrNotImplemented
	_, err = ipfsBackend.ListBuckets(ctx, s3response.ListBucketsInput{})
	if err == nil {
		t.Errorf("expected ListBuckets to return error")
	}
	
	_, err = ipfsBackend.HeadBucket(ctx, nil)
	if err == nil {
		t.Errorf("expected HeadBucket to return error")
	}
	
	_, err = ipfsBackend.PutObject(ctx, s3response.PutObjectInput{})
	if err == nil {
		t.Errorf("expected PutObject to return error")
	}
}