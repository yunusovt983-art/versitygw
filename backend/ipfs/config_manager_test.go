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
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigManager_LoadConfig(t *testing.T) {
	tests := []struct {
		name           string
		configContent  string
		configFormat   ConfigFormat
		envVars        map[string]string
		expectedError  bool
		expectedConfig *IPFSConfig
	}{
		{
			name: "valid JSON config",
			configContent: `{
				"cluster_endpoints": ["http://localhost:9094"],
				"connect_timeout": "30s",
				"request_timeout": "60s",
				"max_retries": 3,
				"max_concurrent_pins": 100,
				"pin_timeout": "300s",
				"chunk_size": 1048576,
				"replication_min": 1,
				"replication_max": 3,
				"compression_enabled": false,
				"metadata_db_type": "memory",
				"cache_enabled": false,
				"metrics_enabled": false,
				"log_level": "info"
			}`,
			configFormat: ConfigFormatJSON,
			expectedConfig: &IPFSConfig{
				ClusterEndpoints:    []string{"http://localhost:9094"},
				ConnectTimeout:      30 * time.Second,
				RequestTimeout:      60 * time.Second,
				MaxRetries:          3,
				MaxConcurrentPins:   100,
				PinTimeout:          300 * time.Second,
				ChunkSize:           1048576,
				ReplicationMin:      1,
				ReplicationMax:      3,
				CompressionEnabled:  false,
				MetadataDBType:      "memory",
				CacheEnabled:        false,
				MetricsEnabled:      false,
				LogLevel:            "info",
			},
		},
		{
			name: "config with environment variable overrides",
			configContent: `{
				"cluster_endpoints": ["http://localhost:9094"],
				"max_concurrent_pins": 50
			}`,
			configFormat: ConfigFormatJSON,
			envVars: map[string]string{
				"IPFS_CLUSTER_ENDPOINTS":    "http://node1:9094,http://node2:9094",
				"IPFS_MAX_CONCURRENT_PINS":  "200",
				"IPFS_COMPRESSION_ENABLED":  "true",
				"IPFS_CACHE_ENABLED":        "true",
			},
			expectedConfig: &IPFSConfig{
				ClusterEndpoints:   []string{"http://node1:9094", "http://node2:9094"},
				MaxConcurrentPins:  200,
				CompressionEnabled: true,
				CacheEnabled:       true,
			},
		},
		{
			name: "invalid JSON config",
			configContent: `{
				"cluster_endpoints": ["http://localhost:9094"
			}`,
			configFormat:  ConfigFormatJSON,
			expectedError: true,
		},
		{
			name: "invalid replication config",
			configContent: `{
				"cluster_endpoints": ["http://localhost:9094"],
				"replication_min": 5,
				"replication_max": 3
			}`,
			configFormat:  ConfigFormatJSON,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tempDir, err := ioutil.TempDir("", "config_test")
			require.NoError(t, err)
			defer os.RemoveAll(tempDir)

			configPath := filepath.Join(tempDir, "config.json")
			err = ioutil.WriteFile(configPath, []byte(tt.configContent), 0644)
			require.NoError(t, err)

			// Set environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
				defer os.Unsetenv(key)
			}

			// Create config manager
			opts := ConfigManagerOptions{
				ConfigPath:      configPath,
				ConfigFormat:    tt.configFormat,
				EnableHotReload: false,
				EnableAPI:       false,
				Logger:          log.New(ioutil.Discard, "", 0),
			}

			cm, err := NewConfigManager(opts)
			if tt.expectedError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			defer cm.Stop()

			config := cm.GetConfig()
			
			if tt.expectedConfig != nil {
				if tt.expectedConfig.ClusterEndpoints != nil {
					assert.Equal(t, tt.expectedConfig.ClusterEndpoints, config.ClusterEndpoints)
				}
				if tt.expectedConfig.MaxConcurrentPins != 0 {
					assert.Equal(t, tt.expectedConfig.MaxConcurrentPins, config.MaxConcurrentPins)
				}
				if tt.expectedConfig.ConnectTimeout != 0 {
					assert.Equal(t, tt.expectedConfig.ConnectTimeout, config.ConnectTimeout)
				}
				assert.Equal(t, tt.expectedConfig.CompressionEnabled, config.CompressionEnabled)
				assert.Equal(t, tt.expectedConfig.CacheEnabled, config.CacheEnabled)
			}
		})
	}
}

func TestConfigManager_HotReload(t *testing.T) {
	// Create temporary config file
	tempDir, err := ioutil.TempDir("", "config_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.json")
	
	// Initial config
	initialConfig := map[string]interface{}{
		"cluster_endpoints":    []string{"http://localhost:9094"},
		"max_concurrent_pins":  100,
		"compression_enabled":  false,
	}
	
	data, err := json.MarshalIndent(initialConfig, "", "  ")
	require.NoError(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	require.NoError(t, err)

	// Create config manager with hot reload enabled
	opts := ConfigManagerOptions{
		ConfigPath:      configPath,
		ConfigFormat:    ConfigFormatJSON,
		EnableHotReload: true,
		EnableAPI:       false,
		Logger:          log.New(ioutil.Discard, "", 0),
	}

	cm, err := NewConfigManager(opts)
	require.NoError(t, err)
	defer cm.Stop()

	err = cm.Start()
	require.NoError(t, err)

	// Verify initial config
	config := cm.GetConfig()
	assert.Equal(t, 100, config.MaxConcurrentPins)
	assert.False(t, config.CompressionEnabled)

	// Set up callback to track config changes
	var callbackCalled bool
	var newConfigFromCallback *IPFSConfig
	
	cm.RegisterCallback(func(oldConfig, newConfig *IPFSConfig) error {
		callbackCalled = true
		newConfigFromCallback = newConfig
		return nil
	})

	// Update config file
	updatedConfig := map[string]interface{}{
		"cluster_endpoints":    []string{"http://localhost:9094"},
		"max_concurrent_pins":  200,
		"compression_enabled":  true,
	}
	
	data, err = json.MarshalIndent(updatedConfig, "", "  ")
	require.NoError(t, err)
	err = ioutil.WriteFile(configPath, data, 0644)
	require.NoError(t, err)

	// Wait for file watcher to detect change and reload config
	time.Sleep(500 * time.Millisecond)

	// Verify config was reloaded
	config = cm.GetConfig()
	assert.Equal(t, 200, config.MaxConcurrentPins)
	assert.True(t, config.CompressionEnabled)

	// Verify callback was called
	assert.True(t, callbackCalled)
	assert.NotNil(t, newConfigFromCallback)
	assert.Equal(t, 200, newConfigFromCallback.MaxConcurrentPins)
	assert.True(t, newConfigFromCallback.CompressionEnabled)
}

func TestConfigManager_UpdateConfig(t *testing.T) {
	// Create config manager with default config
	opts := ConfigManagerOptions{
		EnableHotReload: false,
		EnableAPI:       false,
		Logger:          log.New(ioutil.Discard, "", 0),
	}

	cm, err := NewConfigManager(opts)
	require.NoError(t, err)
	defer cm.Stop()

	// Get initial config
	initialConfig := cm.GetConfig()
	assert.Equal(t, 100, initialConfig.MaxConcurrentPins)

	// Update config
	newConfig := *initialConfig
	newConfig.MaxConcurrentPins = 500
	newConfig.CompressionEnabled = true

	err = cm.UpdateConfig(&newConfig)
	require.NoError(t, err)

	// Verify config was updated
	updatedConfig := cm.GetConfig()
	assert.Equal(t, 500, updatedConfig.MaxConcurrentPins)
	assert.True(t, updatedConfig.CompressionEnabled)

	// Test invalid config update
	invalidConfig := newConfig
	invalidConfig.ReplicationMin = 5
	invalidConfig.ReplicationMax = 3

	err = cm.UpdateConfig(&invalidConfig)
	assert.Error(t, err)

	// Verify config wasn't changed
	currentConfig := cm.GetConfig()
	assert.Equal(t, 500, currentConfig.MaxConcurrentPins)
	assert.Equal(t, 1, currentConfig.ReplicationMin)
	assert.Equal(t, 3, currentConfig.ReplicationMax)
}

func TestConfigManager_SaveConfig(t *testing.T) {
	// Create temporary config file
	tempDir, err := ioutil.TempDir("", "config_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.json")

	// Create config manager
	opts := ConfigManagerOptions{
		ConfigPath:      configPath,
		ConfigFormat:    ConfigFormatJSON,
		EnableHotReload: false,
		EnableAPI:       false,
		Logger:          log.New(ioutil.Discard, "", 0),
	}

	cm, err := NewConfigManager(opts)
	require.NoError(t, err)
	defer cm.Stop()

	// Update config
	config := cm.GetConfig()
	newConfig := *config
	newConfig.MaxConcurrentPins = 300
	newConfig.CompressionEnabled = true

	err = cm.UpdateConfig(&newConfig)
	require.NoError(t, err)

	// Save config to file
	err = cm.SaveConfig()
	require.NoError(t, err)

	// Verify file was written
	data, err := ioutil.ReadFile(configPath)
	require.NoError(t, err)

	var savedConfig IPFSConfig
	err = json.Unmarshal(data, &savedConfig)
	require.NoError(t, err)

	assert.Equal(t, 300, savedConfig.MaxConcurrentPins)
	assert.True(t, savedConfig.CompressionEnabled)
}

func TestConfigValidator_Validate(t *testing.T) {
	validator := NewConfigValidator(log.New(ioutil.Discard, "", 0))

	tests := []struct {
		name          string
		config        *IPFSConfig
		expectedValid bool
		expectedErrors int
	}{
		{
			name:          "valid config",
			config:        getDefaultIPFSConfig(),
			expectedValid: true,
			expectedErrors: 0,
		},
		{
			name: "empty cluster endpoints",
			config: &IPFSConfig{
				ClusterEndpoints: []string{},
				ConnectTimeout:   30 * time.Second,
				RequestTimeout:   60 * time.Second,
				MaxRetries:       3,
				MaxConcurrentPins: 100,
				PinTimeout:       300 * time.Second,
				ChunkSize:        1048576,
				ReplicationMin:   1,
				ReplicationMax:   3,
				MetadataDBType:   "memory",
				LogLevel:         "info",
			},
			expectedValid: false,
			expectedErrors: 1,
		},
		{
			name: "invalid replication settings",
			config: &IPFSConfig{
				ClusterEndpoints: []string{"http://localhost:9094"},
				ConnectTimeout:   30 * time.Second,
				RequestTimeout:   60 * time.Second,
				MaxRetries:       3,
				MaxConcurrentPins: 100,
				PinTimeout:       300 * time.Second,
				ChunkSize:        1048576,
				ReplicationMin:   5,
				ReplicationMax:   3,
				MetadataDBType:   "memory",
				LogLevel:         "info",
			},
			expectedValid: false,
			expectedErrors: 1,
		},
		{
			name: "multiple validation errors",
			config: &IPFSConfig{
				ClusterEndpoints: []string{},
				ConnectTimeout:   -1 * time.Second,
				RequestTimeout:   -1 * time.Second,
				MaxRetries:       -1,
				MaxConcurrentPins: -1,
				PinTimeout:       -1 * time.Second,
				ChunkSize:        -1,
				ReplicationMin:   -1,
				ReplicationMax:   -1,
				MetadataDBType:   "invalid",
				LogLevel:         "invalid",
			},
			expectedValid: false,
			expectedErrors: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.Validate(tt.config)
			assert.Equal(t, tt.expectedValid, result.Valid)
			assert.Equal(t, tt.expectedErrors, len(result.Errors))
		})
	}
}

func TestConfigManager_Callbacks(t *testing.T) {
	// Create config manager
	opts := ConfigManagerOptions{
		EnableHotReload: false,
		EnableAPI:       false,
		Logger:          log.New(ioutil.Discard, "", 0),
	}

	cm, err := NewConfigManager(opts)
	require.NoError(t, err)
	defer cm.Stop()

	// Register multiple callbacks
	var callback1Called, callback2Called bool
	var callback1OldConfig, callback1NewConfig *IPFSConfig
	var callback2OldConfig, callback2NewConfig *IPFSConfig

	cm.RegisterCallback(func(oldConfig, newConfig *IPFSConfig) error {
		callback1Called = true
		callback1OldConfig = oldConfig
		callback1NewConfig = newConfig
		return nil
	})

	cm.RegisterCallback(func(oldConfig, newConfig *IPFSConfig) error {
		callback2Called = true
		callback2OldConfig = oldConfig
		callback2NewConfig = newConfig
		return nil
	})

	// Update config
	config := cm.GetConfig()
	newConfig := *config
	newConfig.MaxConcurrentPins = 400

	err = cm.UpdateConfig(&newConfig)
	require.NoError(t, err)

	// Verify both callbacks were called
	assert.True(t, callback1Called)
	assert.True(t, callback2Called)

	// Verify callback parameters
	assert.NotNil(t, callback1OldConfig)
	assert.NotNil(t, callback1NewConfig)
	assert.Equal(t, 100, callback1OldConfig.MaxConcurrentPins)
	assert.Equal(t, 400, callback1NewConfig.MaxConcurrentPins)

	assert.NotNil(t, callback2OldConfig)
	assert.NotNil(t, callback2NewConfig)
	assert.Equal(t, 100, callback2OldConfig.MaxConcurrentPins)
	assert.Equal(t, 400, callback2NewConfig.MaxConcurrentPins)
}

func TestConfigManager_EnvironmentVariables(t *testing.T) {
	// Set environment variables
	envVars := map[string]string{
		"IPFS_CLUSTER_ENDPOINTS":         "http://node1:9094,http://node2:9094,http://node3:9094",
		"IPFS_CLUSTER_USERNAME":          "testuser",
		"IPFS_CLUSTER_PASSWORD":          "testpass",
		"IPFS_CONNECT_TIMEOUT":           "45s",
		"IPFS_REQUEST_TIMEOUT":           "90s",
		"IPFS_PIN_TIMEOUT":               "600s",
		"IPFS_MAX_RETRIES":               "5",
		"IPFS_MAX_CONCURRENT_PINS":       "250",
		"IPFS_CHUNK_SIZE":                "2097152",
		"IPFS_REPLICATION_MIN":           "2",
		"IPFS_REPLICATION_MAX":           "5",
		"IPFS_COMPRESSION_ENABLED":       "true",
		"IPFS_CACHE_ENABLED":             "true",
		"IPFS_METRICS_ENABLED":           "true",
		"IPFS_METADATA_DB_TYPE":          "ydb",
		"IPFS_METADATA_DB_ENDPOINTS":     "ydb1:2135,ydb2:2135",
		"IPFS_CACHE_ENDPOINTS":           "redis1:6379,redis2:6379",
		"IPFS_LOG_LEVEL":                 "debug",
		"IPFS_REPLICA_MANAGER_ENABLED":   "true",
	}

	for key, value := range envVars {
		os.Setenv(key, value)
		defer os.Unsetenv(key)
	}

	// Create config manager
	opts := ConfigManagerOptions{
		EnableHotReload: false,
		EnableAPI:       false,
		Logger:          log.New(ioutil.Discard, "", 0),
	}

	cm, err := NewConfigManager(opts)
	require.NoError(t, err)
	defer cm.Stop()

	config := cm.GetConfig()

	// Verify environment variables were applied
	assert.Equal(t, []string{"http://node1:9094", "http://node2:9094", "http://node3:9094"}, config.ClusterEndpoints)
	assert.Equal(t, "testuser", config.Username)
	assert.Equal(t, "testpass", config.Password)
	assert.Equal(t, 45*time.Second, config.ConnectTimeout)
	assert.Equal(t, 90*time.Second, config.RequestTimeout)
	assert.Equal(t, 600*time.Second, config.PinTimeout)
	assert.Equal(t, 5, config.MaxRetries)
	assert.Equal(t, 250, config.MaxConcurrentPins)
	assert.Equal(t, int64(2097152), config.ChunkSize)
	assert.Equal(t, 2, config.ReplicationMin)
	assert.Equal(t, 5, config.ReplicationMax)
	assert.True(t, config.CompressionEnabled)
	assert.True(t, config.CacheEnabled)
	assert.True(t, config.MetricsEnabled)
	assert.Equal(t, "ydb", config.MetadataDBType)
	assert.Equal(t, []string{"ydb1:2135", "ydb2:2135"}, config.MetadataDBEndpoints)
	assert.Equal(t, []string{"redis1:6379", "redis2:6379"}, config.CacheEndpoints)
	assert.Equal(t, "debug", config.LogLevel)
	assert.True(t, config.ReplicaManagerEnabled)
}

func TestConfigManager_DeepCopy(t *testing.T) {
	opts := ConfigManagerOptions{
		EnableHotReload: false,
		EnableAPI:       false,
		Logger:          log.New(ioutil.Discard, "", 0),
	}

	cm, err := NewConfigManager(opts)
	require.NoError(t, err)
	defer cm.Stop()

	// Get config and modify it
	config1 := cm.GetConfig()
	config1.MaxConcurrentPins = 999

	// Get config again and verify it wasn't affected
	config2 := cm.GetConfig()
	assert.Equal(t, 100, config2.MaxConcurrentPins) // Should be default value

	// Verify they are different instances
	assert.NotSame(t, config1, config2)
}

func TestConfigManager_Lifecycle(t *testing.T) {
	// Create config manager
	opts := ConfigManagerOptions{
		EnableHotReload: false,
		EnableAPI:       false,
		Logger:          log.New(ioutil.Discard, "", 0),
		Context:         context.Background(),
	}

	cm, err := NewConfigManager(opts)
	require.NoError(t, err)

	// Start and stop multiple times
	err = cm.Start()
	require.NoError(t, err)

	err = cm.Stop()
	require.NoError(t, err)

	err = cm.Start()
	require.NoError(t, err)

	err = cm.Stop()
	require.NoError(t, err)
}