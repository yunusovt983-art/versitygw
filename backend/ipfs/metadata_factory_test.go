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
	"testing"
	"time"
)

func TestMetadataStoreFactory(t *testing.T) {
	factory := NewMetadataStoreFactory(nil)
	
	t.Run("CreateMemoryStore", func(t *testing.T) {
		config := &MetadataStoreConfig{
			Type:         "memory",
			BatchSize:    1000,
			QueryTimeout: 30 * time.Second,
		}
		
		store, err := factory.CreateMetadataStore(config)
		if err != nil {
			t.Fatalf("Failed to create memory store: %v", err)
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			store.Shutdown(ctx)
		}()
		
		// Test basic operations
		ctx := context.Background()
		if err := store.HealthCheck(ctx); err != nil {
			t.Errorf("Health check failed: %v", err)
		}
		
		// Test store operation
		mapping := NewObjectMapping("test-bucket", "test-key", "QmTestCID", 1024)
		if err := store.StoreMapping(ctx, mapping); err != nil {
			t.Errorf("Failed to store mapping: %v", err)
		}
		
		// Test retrieve operation
		retrieved, err := store.GetMapping(ctx, "test-key", "test-bucket")
		if err != nil {
			t.Errorf("Failed to get mapping: %v", err)
		}
		if retrieved.CID != "QmTestCID" {
			t.Errorf("Expected CID QmTestCID, got %s", retrieved.CID)
		}
	})
	
	t.Run("CreateScyllaStore", func(t *testing.T) {
		config := &MetadataStoreConfig{
			Type:              "scylla",
			Endpoints:         []string{"localhost:9042"},
			Keyspace:          "test_keyspace",
			ConnectTimeout:    30 * time.Second,
			RequestTimeout:    10 * time.Second,
			MaxConnections:    100,
			BatchSize:         1000,
			ConsistencyLevel:  "QUORUM",
			ReplicationFactor: 3,
		}
		
		// Note: This will fail without actual ScyllaDB instance
		// but we can test the factory creation logic
		store, err := factory.CreateMetadataStore(config)
		if err != nil {
			// Expected to fail without actual ScyllaDB
			t.Logf("ScyllaDB store creation failed as expected: %v", err)
			return
		}
		
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			store.Shutdown(ctx)
		}()
		
		// If we somehow got a store, test it
		ctx := context.Background()
		if err := store.HealthCheck(ctx); err != nil {
			t.Logf("ScyllaDB health check failed as expected: %v", err)
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
	
	t.Run("NilConfig", func(t *testing.T) {
		_, err := factory.CreateMetadataStore(nil)
		if err == nil {
			t.Error("Expected error for nil config")
		}
	})
}

func TestMetadataStoreFactorySupport(t *testing.T) {
	factory := NewMetadataStoreFactory(nil)
	
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
		testCases := []struct {
			storeType string
			supported bool
		}{
			{"memory", true},
			{"scylla", true},
			{"scylladb", true},
			{"ydb", true},
			{"cassandra", true},
			{"postgres", true},
			{"mongodb", true},
			{"unsupported", false},
			{"", false},
		}
		
		for _, tc := range testCases {
			t.Run(tc.storeType, func(t *testing.T) {
				supported := factory.IsStoreTypeSupported(tc.storeType)
				if supported != tc.supported {
					t.Errorf("Expected %s support to be %v, got %v", tc.storeType, tc.supported, supported)
				}
			})
		}
	})
	
	t.Run("IsStoreTypeImplemented", func(t *testing.T) {
		testCases := []struct {
			storeType   string
			implemented bool
		}{
			{"memory", true},
			{"scylla", true},
			{"scylladb", true},
			{"cassandra", true},
			{"ydb", false},      // Not yet implemented
			{"postgres", false}, // Not yet implemented
			{"mongodb", false},  // Not yet implemented
			{"unsupported", false},
		}
		
		for _, tc := range testCases {
			t.Run(tc.storeType, func(t *testing.T) {
				implemented := factory.IsStoreTypeImplemented(tc.storeType)
				if implemented != tc.implemented {
					t.Errorf("Expected %s implementation to be %v, got %v", tc.storeType, tc.implemented, implemented)
				}
			})
		}
	})
}

func TestMetadataStoreFactoryDefaultConfigs(t *testing.T) {
	factory := NewMetadataStoreFactory(nil)
	
	testCases := []struct {
		storeType string
		validate  func(*MetadataStoreConfig) error
	}{
		{
			storeType: "memory",
			validate: func(config *MetadataStoreConfig) error {
				if config.Type != "memory" {
					t.Errorf("Expected type 'memory', got %s", config.Type)
				}
				if config.BatchSize != 1000 {
					t.Errorf("Expected batch size 1000, got %d", config.BatchSize)
				}
				return nil
			},
		},
		{
			storeType: "scylla",
			validate: func(config *MetadataStoreConfig) error {
				if config.Type != "scylla" {
					t.Errorf("Expected type 'scylla', got %s", config.Type)
				}
				if config.Keyspace != "versitygw_ipfs" {
					t.Errorf("Expected keyspace 'versitygw_ipfs', got %s", config.Keyspace)
				}
				if config.ConsistencyLevel != "QUORUM" {
					t.Errorf("Expected consistency level 'QUORUM', got %s", config.ConsistencyLevel)
				}
				if config.ReplicationFactor != 3 {
					t.Errorf("Expected replication factor 3, got %d", config.ReplicationFactor)
				}
				return nil
			},
		},
		{
			storeType: "ydb",
			validate: func(config *MetadataStoreConfig) error {
				if config.Type != "ydb" {
					t.Errorf("Expected type 'ydb', got %s", config.Type)
				}
				if config.Database != "/local" {
					t.Errorf("Expected database '/local', got %s", config.Database)
				}
				return nil
			},
		},
		{
			storeType: "postgres",
			validate: func(config *MetadataStoreConfig) error {
				if config.Type != "postgres" {
					t.Errorf("Expected type 'postgres', got %s", config.Type)
				}
				if config.Database != "versitygw_ipfs" {
					t.Errorf("Expected database 'versitygw_ipfs', got %s", config.Database)
				}
				if config.Username != "postgres" {
					t.Errorf("Expected username 'postgres', got %s", config.Username)
				}
				return nil
			},
		},
		{
			storeType: "mongodb",
			validate: func(config *MetadataStoreConfig) error {
				if config.Type != "mongodb" {
					t.Errorf("Expected type 'mongodb', got %s", config.Type)
				}
				if config.Database != "versitygw_ipfs" {
					t.Errorf("Expected database 'versitygw_ipfs', got %s", config.Database)
				}
				return nil
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.storeType, func(t *testing.T) {
			config := factory.CreateDefaultConfig(tc.storeType)
			if config == nil {
				t.Fatal("Expected non-nil config")
			}
			
			if err := tc.validate(config); err != nil {
				t.Errorf("Config validation failed: %v", err)
			}
		})
	}
	
	t.Run("UnsupportedType", func(t *testing.T) {
		config := factory.CreateDefaultConfig("unsupported")
		if config == nil {
			t.Fatal("Expected non-nil config even for unsupported type")
		}
		
		// Should default to memory
		if config.Type != "memory" {
			t.Errorf("Expected default type 'memory', got %s", config.Type)
		}
	})
}

func TestMetadataStoreFactoryValidation(t *testing.T) {
	factory := NewMetadataStoreFactory(nil)
	
	t.Run("ValidateNilConfig", func(t *testing.T) {
		err := factory.ValidateConfig(nil)
		if err == nil {
			t.Error("Expected error for nil config")
		}
	})
	
	t.Run("ValidateEmptyType", func(t *testing.T) {
		config := &MetadataStoreConfig{}
		err := factory.ValidateConfig(config)
		if err == nil {
			t.Error("Expected error for empty type")
		}
	})
	
	t.Run("ValidateUnsupportedType", func(t *testing.T) {
		config := &MetadataStoreConfig{
			Type: "unsupported",
		}
		err := factory.ValidateConfig(config)
		if err == nil {
			t.Error("Expected error for unsupported type")
		}
	})
	
	t.Run("ValidateMemoryConfig", func(t *testing.T) {
		config := &MetadataStoreConfig{
			Type: "memory",
		}
		err := factory.ValidateConfig(config)
		if err != nil {
			t.Errorf("Expected no error for valid memory config, got: %v", err)
		}
		
		// Check defaults were set
		if config.BatchSize != 1000 {
			t.Errorf("Expected batch size 1000, got %d", config.BatchSize)
		}
		if config.QueryTimeout != 30*time.Second {
			t.Errorf("Expected query timeout 30s, got %v", config.QueryTimeout)
		}
	})
	
	t.Run("ValidateScyllaConfig", func(t *testing.T) {
		// Valid config
		config := &MetadataStoreConfig{
			Type:              "scylla",
			Endpoints:         []string{"localhost:9042"},
			Keyspace:          "test",
			ConsistencyLevel:  "QUORUM",
			ReplicationFactor: 3,
		}
		err := factory.ValidateConfig(config)
		if err != nil {
			t.Errorf("Expected no error for valid scylla config, got: %v", err)
		}
		
		// Invalid consistency level
		config.ConsistencyLevel = "INVALID"
		err = factory.ValidateConfig(config)
		if err == nil {
			t.Error("Expected error for invalid consistency level")
		}
		
		// No endpoints
		config.ConsistencyLevel = "QUORUM"
		config.Endpoints = []string{}
		err = factory.ValidateConfig(config)
		if err == nil {
			t.Error("Expected error for no endpoints")
		}
	})
	
	t.Run("ValidateYDBConfig", func(t *testing.T) {
		// Valid config
		config := &MetadataStoreConfig{
			Type:      "ydb",
			Endpoints: []string{"grpc://localhost:2136"},
			Database:  "/local",
		}
		err := factory.ValidateConfig(config)
		if err != nil {
			t.Errorf("Expected no error for valid YDB config, got: %v", err)
		}
		
		// No database
		config.Database = ""
		err = factory.ValidateConfig(config)
		if err == nil {
			t.Error("Expected error for no database")
		}
		
		// No endpoints
		config.Database = "/local"
		config.Endpoints = []string{}
		err = factory.ValidateConfig(config)
		if err == nil {
			t.Error("Expected error for no endpoints")
		}
	})
	
	t.Run("ValidatePostgresConfig", func(t *testing.T) {
		// Valid config
		config := &MetadataStoreConfig{
			Type:      "postgres",
			Endpoints: []string{"localhost:5432"},
			Database:  "test",
			Username:  "user",
		}
		err := factory.ValidateConfig(config)
		if err != nil {
			t.Errorf("Expected no error for valid Postgres config, got: %v", err)
		}
		
		// No username
		config.Username = ""
		err = factory.ValidateConfig(config)
		if err == nil {
			t.Error("Expected error for no username")
		}
		
		// No database
		config.Username = "user"
		config.Database = ""
		err = factory.ValidateConfig(config)
		if err == nil {
			t.Error("Expected error for no database")
		}
	})
	
	t.Run("ValidateMongoDBConfig", func(t *testing.T) {
		// Valid config
		config := &MetadataStoreConfig{
			Type:      "mongodb",
			Endpoints: []string{"localhost:27017"},
			Database:  "test",
		}
		err := factory.ValidateConfig(config)
		if err != nil {
			t.Errorf("Expected no error for valid MongoDB config, got: %v", err)
		}
		
		// No database
		config.Database = ""
		err = factory.ValidateConfig(config)
		if err == nil {
			t.Error("Expected error for no database")
		}
	})
}

func TestMetadataStoreFactoryTestConnection(t *testing.T) {
	factory := NewMetadataStoreFactory(nil)
	
	t.Run("TestMemoryConnection", func(t *testing.T) {
		config := factory.CreateDefaultConfig("memory")
		err := factory.TestConnection(config)
		if err != nil {
			t.Errorf("Expected successful connection test for memory store, got: %v", err)
		}
	})
	
	t.Run("TestInvalidConnection", func(t *testing.T) {
		config := &MetadataStoreConfig{
			Type: "invalid",
		}
		err := factory.TestConnection(config)
		if err == nil {
			t.Error("Expected error for invalid store type")
		}
	})
	
	t.Run("TestScyllaConnectionFailure", func(t *testing.T) {
		config := factory.CreateDefaultConfig("scylla")
		config.Endpoints = []string{"invalid:9042"}
		config.ConnectTimeout = 1 * time.Second // Short timeout for test
		
		err := factory.TestConnection(config)
		if err == nil {
			t.Error("Expected error for invalid ScyllaDB connection")
		}
		t.Logf("ScyllaDB connection test failed as expected: %v", err)
	})
}

func BenchmarkMetadataStoreFactory(b *testing.B) {
	factory := NewMetadataStoreFactory(nil)
	
	b.Run("CreateMemoryStore", func(b *testing.B) {
		config := factory.CreateDefaultConfig("memory")
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			store, err := factory.CreateMetadataStore(config)
			if err != nil {
				b.Fatalf("Failed to create store: %v", err)
			}
			
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			store.Shutdown(ctx)
			cancel()
		}
	})
	
	b.Run("ValidateConfig", func(b *testing.B) {
		config := factory.CreateDefaultConfig("memory")
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := factory.ValidateConfig(config)
			if err != nil {
				b.Fatalf("Failed to validate config: %v", err)
			}
		}
	})
}