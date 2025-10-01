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
	"log"
	"os"
	"testing"
	"time"
)

// TestObjectMapping tests the ObjectMapping struct and its methods
func TestObjectMapping(t *testing.T) {
	t.Run("NewObjectMapping", func(t *testing.T) {
		bucket := "test-bucket"
		s3Key := "test/object.txt"
		cid := "QmTestCID123"
		size := int64(1024)
		
		mapping := NewObjectMapping(bucket, s3Key, cid, size)
		
		if mapping.Bucket != bucket {
			t.Errorf("Expected bucket %s, got %s", bucket, mapping.Bucket)
		}
		if mapping.S3Key != s3Key {
			t.Errorf("Expected s3Key %s, got %s", s3Key, mapping.S3Key)
		}
		if mapping.CID != cid {
			t.Errorf("Expected CID %s, got %s", cid, mapping.CID)
		}
		if mapping.Size != size {
			t.Errorf("Expected size %d, got %d", size, mapping.Size)
		}
		if mapping.PinStatus != PinStatusPending {
			t.Errorf("Expected pin status %v, got %v", PinStatusPending, mapping.PinStatus)
		}
		if !mapping.IsLatest {
			t.Error("Expected IsLatest to be true")
		}
		if mapping.DeleteMarker {
			t.Error("Expected DeleteMarker to be false")
		}
	})
	
	t.Run("Validate", func(t *testing.T) {
		// Valid mapping
		mapping := NewObjectMapping("bucket", "key", "cid", 1024)
		if err := mapping.Validate(); err != nil {
			t.Errorf("Expected valid mapping to pass validation, got error: %v", err)
		}
		
		// Invalid mappings
		testCases := []struct {
			name     string
			modifier func(*ObjectMapping)
			wantErr  bool
		}{
			{
				name: "empty bucket",
				modifier: func(m *ObjectMapping) {
					m.Bucket = ""
				},
				wantErr: true,
			},
			{
				name: "empty s3 key",
				modifier: func(m *ObjectMapping) {
					m.S3Key = ""
				},
				wantErr: true,
			},
			{
				name: "empty CID",
				modifier: func(m *ObjectMapping) {
					m.CID = ""
				},
				wantErr: true,
			},
			{
				name: "negative size",
				modifier: func(m *ObjectMapping) {
					m.Size = -1
				},
				wantErr: true,
			},
			{
				name: "negative replication count",
				modifier: func(m *ObjectMapping) {
					m.ReplicationCount = -1
				},
				wantErr: true,
			},
			{
				name: "negative access count",
				modifier: func(m *ObjectMapping) {
					m.AccessCount = -1
				},
				wantErr: true,
			},
		}
		
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				mapping := NewObjectMapping("bucket", "key", "cid", 1024)
				tc.modifier(mapping)
				
				err := mapping.Validate()
				if tc.wantErr && err == nil {
					t.Error("Expected validation error, got nil")
				}
				if !tc.wantErr && err != nil {
					t.Errorf("Expected no validation error, got: %v", err)
				}
			})
		}
	})
	
	t.Run("UpdateAccessStats", func(t *testing.T) {
		mapping := NewObjectMapping("bucket", "key", "cid", 1024)
		originalAccessCount := mapping.AccessCount
		originalAccessTime := mapping.AccessedAt
		
		clientIP := "192.168.1.1"
		region := "us-east-1"
		
		mapping.UpdateAccessStats(clientIP, region)
		
		if mapping.AccessCount != originalAccessCount+1 {
			t.Errorf("Expected access count to increment by 1, got %d", mapping.AccessCount)
		}
		if mapping.LastAccessIP != clientIP {
			t.Errorf("Expected last access IP %s, got %s", clientIP, mapping.LastAccessIP)
		}
		if mapping.GeographicAccess[region] != 1 {
			t.Errorf("Expected geographic access count for %s to be 1, got %d", region, mapping.GeographicAccess[region])
		}
		if !mapping.AccessedAt.After(originalAccessTime) {
			t.Error("Expected accessed time to be updated")
		}
	})
	
	t.Run("UpdatePinStatus", func(t *testing.T) {
		mapping := NewObjectMapping("bucket", "key", "cid", 1024)
		originalUpdateTime := mapping.UpdatedAt
		
		newStatus := PinStatusPinned
		nodes := []string{"node1", "node2", "node3"}
		
		mapping.UpdatePinStatus(newStatus, nodes)
		
		if mapping.PinStatus != newStatus {
			t.Errorf("Expected pin status %v, got %v", newStatus, mapping.PinStatus)
		}
		if mapping.ReplicationCount != len(nodes) {
			t.Errorf("Expected replication count %d, got %d", len(nodes), mapping.ReplicationCount)
		}
		if len(mapping.PinnedNodes) != len(nodes) {
			t.Errorf("Expected %d pinned nodes, got %d", len(nodes), len(mapping.PinnedNodes))
		}
		for i, node := range nodes {
			if mapping.PinnedNodes[i] != node {
				t.Errorf("Expected pinned node %s at index %d, got %s", node, i, mapping.PinnedNodes[i])
			}
		}
		if !mapping.UpdatedAt.After(originalUpdateTime) {
			t.Error("Expected updated time to be updated")
		}
	})
	
	t.Run("IsExpired", func(t *testing.T) {
		mapping := NewObjectMapping("bucket", "key", "cid", 1024)
		
		// No expiration set
		if mapping.IsExpired() {
			t.Error("Expected mapping without expiration to not be expired")
		}
		
		// Future expiration
		future := time.Now().Add(time.Hour)
		mapping.ExpiresAt = &future
		if mapping.IsExpired() {
			t.Error("Expected mapping with future expiration to not be expired")
		}
		
		// Past expiration
		past := time.Now().Add(-time.Hour)
		mapping.ExpiresAt = &past
		if !mapping.IsExpired() {
			t.Error("Expected mapping with past expiration to be expired")
		}
	})
	
	t.Run("Clone", func(t *testing.T) {
		original := NewObjectMapping("bucket", "key", "cid", 1024)
		original.UserMetadata["custom"] = "value"
		original.Tags["env"] = "test"
		original.GeographicAccess["us-east-1"] = 5
		original.PinnedNodes = []string{"node1", "node2"}
		
		clone := original.Clone()
		
		// Verify clone is equal but separate
		if clone.Bucket != original.Bucket {
			t.Error("Clone bucket mismatch")
		}
		if clone.UserMetadata["custom"] != original.UserMetadata["custom"] {
			t.Error("Clone user metadata mismatch")
		}
		
		// Verify deep copy - modifying clone shouldn't affect original
		clone.UserMetadata["custom"] = "modified"
		if original.UserMetadata["custom"] == "modified" {
			t.Error("Clone modification affected original")
		}
		
		clone.PinnedNodes[0] = "modified"
		if original.PinnedNodes[0] == "modified" {
			t.Error("Clone slice modification affected original")
		}
	})
	
	t.Run("JSON Serialization", func(t *testing.T) {
		original := NewObjectMapping("bucket", "key", "cid", 1024)
		original.UserMetadata["custom"] = "value"
		original.Tags["env"] = "test"
		
		// Test ToJSON
		data, err := original.ToJSON()
		if err != nil {
			t.Fatalf("Failed to serialize to JSON: %v", err)
		}
		
		// Test FromJSON
		restored := &ObjectMapping{}
		err = restored.FromJSON(data)
		if err != nil {
			t.Fatalf("Failed to deserialize from JSON: %v", err)
		}
		
		// Verify restoration
		if restored.Bucket != original.Bucket {
			t.Error("JSON restoration bucket mismatch")
		}
		if restored.S3Key != original.S3Key {
			t.Error("JSON restoration s3Key mismatch")
		}
		if restored.CID != original.CID {
			t.Error("JSON restoration CID mismatch")
		}
		if restored.UserMetadata["custom"] != original.UserMetadata["custom"] {
			t.Error("JSON restoration user metadata mismatch")
		}
	})
}

// TestBucketMetadata tests the BucketMetadata struct and its methods
func TestBucketMetadata(t *testing.T) {
	t.Run("NewBucketMetadata", func(t *testing.T) {
		name := "test-bucket"
		owner := "test-owner"
		
		metadata := NewBucketMetadata(name, owner)
		
		if metadata.Name != name {
			t.Errorf("Expected name %s, got %s", name, metadata.Name)
		}
		if metadata.Owner != owner {
			t.Errorf("Expected owner %s, got %s", owner, metadata.Owner)
		}
		if metadata.Region != "us-east-1" {
			t.Errorf("Expected default region us-east-1, got %s", metadata.Region)
		}
		if metadata.StorageClass != "STANDARD" {
			t.Errorf("Expected default storage class STANDARD, got %s", metadata.StorageClass)
		}
		if metadata.VersioningStatus != "Suspended" {
			t.Errorf("Expected default versioning status Suspended, got %s", metadata.VersioningStatus)
		}
		if metadata.DefaultReplicationMin != 1 {
			t.Errorf("Expected default replication min 1, got %d", metadata.DefaultReplicationMin)
		}
		if metadata.DefaultReplicationMax != 3 {
			t.Errorf("Expected default replication max 3, got %d", metadata.DefaultReplicationMax)
		}
	})
	
	t.Run("Validate", func(t *testing.T) {
		// Valid metadata
		metadata := NewBucketMetadata("bucket", "owner")
		if err := metadata.Validate(); err != nil {
			t.Errorf("Expected valid metadata to pass validation, got error: %v", err)
		}
		
		// Invalid metadata
		testCases := []struct {
			name     string
			modifier func(*BucketMetadata)
			wantErr  bool
		}{
			{
				name: "empty name",
				modifier: func(m *BucketMetadata) {
					m.Name = ""
				},
				wantErr: true,
			},
			{
				name: "empty owner",
				modifier: func(m *BucketMetadata) {
					m.Owner = ""
				},
				wantErr: true,
			},
			{
				name: "negative object count",
				modifier: func(m *BucketMetadata) {
					m.ObjectCount = -1
				},
				wantErr: true,
			},
			{
				name: "negative total size",
				modifier: func(m *BucketMetadata) {
					m.TotalSize = -1
				},
				wantErr: true,
			},
			{
				name: "zero replication min",
				modifier: func(m *BucketMetadata) {
					m.DefaultReplicationMin = 0
				},
				wantErr: true,
			},
			{
				name: "replication max less than min",
				modifier: func(m *BucketMetadata) {
					m.DefaultReplicationMin = 3
					m.DefaultReplicationMax = 2
				},
				wantErr: true,
			},
		}
		
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				metadata := NewBucketMetadata("bucket", "owner")
				tc.modifier(metadata)
				
				err := metadata.Validate()
				if tc.wantErr && err == nil {
					t.Error("Expected validation error, got nil")
				}
				if !tc.wantErr && err != nil {
					t.Errorf("Expected no validation error, got: %v", err)
				}
			})
		}
	})
}

// TestPinStatus tests the PinStatus enum
func TestPinStatus(t *testing.T) {
	testCases := []struct {
		status   PinStatus
		expected string
	}{
		{PinStatusUnknown, "unknown"},
		{PinStatusPending, "pending"},
		{PinStatusPinned, "pinned"},
		{PinStatusFailed, "failed"},
		{PinStatusUnpinning, "unpinning"},
		{PinStatusUnpinned, "unpinned"},
		{PinStatusError, "error"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			if tc.status.String() != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, tc.status.String())
			}
		})
	}
}

// TestMetadataStoreFactoryIntegration tests the metadata store factory integration
func TestMetadataStoreFactoryIntegration(t *testing.T) {
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	factory := NewMetadataStoreFactory(logger)
	
	t.Run("CreateMemoryStore", func(t *testing.T) {
		config := &MetadataStoreConfig{
			Type:           "memory",
			BatchSize:      1000,
			QueryTimeout:   30 * time.Second,
			MetricsEnabled: true,
		}
		
		store, err := factory.CreateMetadataStore(config)
		if err != nil {
			t.Fatalf("Failed to create memory store: %v", err)
		}
		
		if store == nil {
			t.Fatal("Expected non-nil store")
		}
		
		// Test basic operations
		ctx := context.Background()
		
		// Test health check
		if err := store.HealthCheck(ctx); err != nil {
			t.Errorf("Health check failed: %v", err)
		}
		
		// Cleanup
		store.Shutdown(ctx)
	})
	
	t.Run("CreateScyllaStore", func(t *testing.T) {
		config := &MetadataStoreConfig{
			Type:              "scylla",
			Endpoints:         []string{"localhost:9042"},
			Keyspace:          "test_keyspace",
			ConnectTimeout:    30 * time.Second,
			RequestTimeout:    10 * time.Second,
			MaxConnections:    10,
			BatchSize:         100,
			ConsistencyLevel:  "QUORUM",
			ReplicationFactor: 1,
		}
		
		// Note: This will fail without a real ScyllaDB instance
		// but we can test the factory logic
		_, err := factory.CreateMetadataStore(config)
		// We expect this to fail since we don't have a real ScyllaDB instance
		if err == nil {
			t.Log("ScyllaDB store creation succeeded (unexpected in test environment)")
		} else {
			t.Logf("ScyllaDB store creation failed as expected: %v", err)
		}
	})
	
	t.Run("CreateYDBStore", func(t *testing.T) {
		config := &MetadataStoreConfig{
			Type:           "ydb",
			Endpoints:      []string{"grpc://localhost:2136"},
			Database:       "/local",
			ConnectTimeout: 30 * time.Second,
			RequestTimeout: 10 * time.Second,
			MaxConnections: 10,
			BatchSize:      100,
		}
		
		// Note: This will fail without a real YDB instance
		// but we can test the factory logic
		_, err := factory.CreateMetadataStore(config)
		// We expect this to fail since we don't have a real YDB instance
		if err == nil {
			t.Log("YDB store creation succeeded (unexpected in test environment)")
		} else {
			t.Logf("YDB store creation failed as expected: %v", err)
		}
	})
	
	t.Run("UnsupportedStoreType", func(t *testing.T) {
		config := &MetadataStoreConfig{
			Type: "unsupported",
		}
		
		_, err := factory.CreateMetadataStore(config)
		if err == nil {
			t.Error("Expected error for unsupported store type")
		}
	})
	
	t.Run("GetSupportedStoreTypes", func(t *testing.T) {
		types := factory.GetSupportedStoreTypes()
		if len(types) == 0 {
			t.Error("Expected at least one supported store type")
		}
		
		// Check that memory is supported
		found := false
		for _, storeType := range types {
			if storeType == MetadataStoreTypeMemory {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected memory store type to be supported")
		}
	})
	
	t.Run("GetImplementedStoreTypes", func(t *testing.T) {
		types := factory.GetImplementedStoreTypes()
		if len(types) == 0 {
			t.Error("Expected at least one implemented store type")
		}
		
		// Check that memory is implemented
		found := false
		for _, storeType := range types {
			if storeType == MetadataStoreTypeMemory {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected memory store type to be implemented")
		}
	})
	
	t.Run("IsStoreTypeSupported", func(t *testing.T) {
		if !factory.IsStoreTypeSupported("memory") {
			t.Error("Expected memory store type to be supported")
		}
		if factory.IsStoreTypeSupported("nonexistent") {
			t.Error("Expected nonexistent store type to not be supported")
		}
	})
	
	t.Run("IsStoreTypeImplemented", func(t *testing.T) {
		if !factory.IsStoreTypeImplemented("memory") {
			t.Error("Expected memory store type to be implemented")
		}
		if factory.IsStoreTypeImplemented("nonexistent") {
			t.Error("Expected nonexistent store type to not be implemented")
		}
	})
	
	t.Run("CreateDefaultConfig", func(t *testing.T) {
		config := factory.CreateDefaultConfig("memory")
		if config == nil {
			t.Fatal("Expected non-nil default config")
		}
		if config.Type != "memory" {
			t.Errorf("Expected type memory, got %s", config.Type)
		}
		if config.BatchSize == 0 {
			t.Error("Expected non-zero batch size in default config")
		}
	})
	
	t.Run("ValidateConfig", func(t *testing.T) {
		// Valid config
		config := &MetadataStoreConfig{
			Type:           "memory",
			BatchSize:      1000,
			QueryTimeout:   30 * time.Second,
			MetricsEnabled: true,
		}
		
		if err := factory.ValidateConfig(config); err != nil {
			t.Errorf("Expected valid config to pass validation, got error: %v", err)
		}
		
		// Invalid configs
		if err := factory.ValidateConfig(nil); err == nil {
			t.Error("Expected nil config to fail validation")
		}
		
		invalidConfig := &MetadataStoreConfig{
			Type: "",
		}
		if err := factory.ValidateConfig(invalidConfig); err == nil {
			t.Error("Expected empty type to fail validation")
		}
		
		unsupportedConfig := &MetadataStoreConfig{
			Type: "unsupported",
		}
		if err := factory.ValidateConfig(unsupportedConfig); err == nil {
			t.Error("Expected unsupported type to fail validation")
		}
	})
}

// BenchmarkObjectMapping benchmarks ObjectMapping operations
func BenchmarkObjectMapping(b *testing.B) {
	b.Run("NewObjectMapping", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = NewObjectMapping("bucket", fmt.Sprintf("key-%d", i), fmt.Sprintf("cid-%d", i), int64(i))
		}
	})
	
	b.Run("Validate", func(b *testing.B) {
		mapping := NewObjectMapping("bucket", "key", "cid", 1024)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = mapping.Validate()
		}
	})
	
	b.Run("Clone", func(b *testing.B) {
		mapping := NewObjectMapping("bucket", "key", "cid", 1024)
		mapping.UserMetadata["key1"] = "value1"
		mapping.UserMetadata["key2"] = "value2"
		mapping.Tags["tag1"] = "value1"
		mapping.Tags["tag2"] = "value2"
		mapping.PinnedNodes = []string{"node1", "node2", "node3"}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = mapping.Clone()
		}
	})
	
	b.Run("UpdateAccessStats", func(b *testing.B) {
		mapping := NewObjectMapping("bucket", "key", "cid", 1024)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mapping.UpdateAccessStats("192.168.1.1", "us-east-1")
		}
	})
	
	b.Run("ToJSON", func(b *testing.B) {
		mapping := NewObjectMapping("bucket", "key", "cid", 1024)
		mapping.UserMetadata["key1"] = "value1"
		mapping.Tags["tag1"] = "value1"
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = mapping.ToJSON()
		}
	})
	
	b.Run("FromJSON", func(b *testing.B) {
		mapping := NewObjectMapping("bucket", "key", "cid", 1024)
		mapping.UserMetadata["key1"] = "value1"
		mapping.Tags["tag1"] = "value1"
		
		data, _ := mapping.ToJSON()
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			restored := &ObjectMapping{}
			_ = restored.FromJSON(data)
		}
	})
}

// BenchmarkMetadataStoreFactoryIntegration benchmarks factory operations
func BenchmarkMetadataStoreFactoryIntegration(b *testing.B) {
	logger := log.New(os.Stdout, "bench: ", log.LstdFlags)
	factory := NewMetadataStoreFactory(logger)
	
	b.Run("CreateDefaultConfig", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = factory.CreateDefaultConfig("memory")
		}
	})
	
	b.Run("ValidateConfig", func(b *testing.B) {
		config := &MetadataStoreConfig{
			Type:           "memory",
			BatchSize:      1000,
			QueryTimeout:   30 * time.Second,
			MetricsEnabled: true,
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = factory.ValidateConfig(config)
		}
	})
	
	b.Run("IsStoreTypeSupported", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = factory.IsStoreTypeSupported("memory")
		}
	})
}