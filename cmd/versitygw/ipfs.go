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

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend/ipfs"
)

var (
	// IPFS-Cluster connection settings
	ipfsClusterEndpoints string
	ipfsUsername         string
	ipfsPassword         string
	ipfsConnectTimeout   time.Duration
	ipfsRequestTimeout   time.Duration
	ipfsMaxRetries       int
	ipfsRetryDelay       time.Duration

	// Performance settings
	ipfsMaxConcurrentPins int
	ipfsPinTimeout        time.Duration
	ipfsChunkSize         int64

	// Replication settings
	ipfsReplicationMin int
	ipfsReplicationMax int

	// Storage settings
	ipfsCompressionEnabled bool

	// Metadata database settings
	ipfsMetadataDBType      string
	ipfsMetadataDBEndpoints string

	// Cache settings
	ipfsCacheEndpoints string
	ipfsCacheEnabled   bool

	// Monitoring settings
	ipfsMetricsEnabled bool
	ipfsLogLevel       string

	// Replica manager settings
	ipfsReplicaManagerEnabled  bool
	ipfsAnalysisInterval       time.Duration
	ipfsRebalancingInterval    time.Duration
	ipfsGeographicOptimization bool
	ipfsLoadBalancingEnabled   bool
	ipfsHotDataThreshold       int64
	ipfsWarmDataThreshold      int64
	ipfsColdDataThreshold      int64

	// Configuration file path
	ipfsConfigPath string
)

func ipfsCommand() *cli.Command {
	return &cli.Command{
		Name:  "ipfs",
		Usage: "IPFS-Cluster storage backend",
		Description: `IPFS-Cluster backend provides scalable, decentralized storage through IPFS
with cluster management capabilities. This backend can handle massive scale
operations including trillion-pin scenarios with intelligent replication,
caching, and performance optimization.

The backend integrates with IPFS-Cluster nodes to provide:
- Distributed pin management across cluster nodes
- Intelligent replication based on access patterns
- Multi-level caching for optimal performance
- Comprehensive monitoring and metrics
- Fault tolerance and automatic recovery

Configuration can be provided via command-line flags, environment variables,
or a configuration file. The backend supports hot-reload of configuration
changes without service restart.`,
		Action: runIPFS,
		Flags: []cli.Flag{
			// IPFS-Cluster connection settings
			&cli.StringFlag{
				Name:        "cluster-endpoints",
				Usage:       "comma-separated list of IPFS-Cluster API endpoints (e.g., 'http://node1:9094,http://node2:9094')",
				EnvVars:     []string{"VGW_IPFS_CLUSTER_ENDPOINTS"},
				Required:    true,
				Destination: &ipfsClusterEndpoints,
				Aliases:     []string{"endpoints", "e"},
			},
			&cli.StringFlag{
				Name:        "username",
				Usage:       "username for IPFS-Cluster authentication (optional)",
				EnvVars:     []string{"VGW_IPFS_USERNAME"},
				Destination: &ipfsUsername,
				Aliases:     []string{"u"},
			},
			&cli.StringFlag{
				Name:        "password",
				Usage:       "password for IPFS-Cluster authentication (optional)",
				EnvVars:     []string{"VGW_IPFS_PASSWORD"},
				Destination: &ipfsPassword,
				Aliases:     []string{"p"},
			},
			&cli.DurationFlag{
				Name:        "connect-timeout",
				Usage:       "timeout for connecting to IPFS-Cluster nodes",
				EnvVars:     []string{"VGW_IPFS_CONNECT_TIMEOUT"},
				Value:       30 * time.Second,
				Destination: &ipfsConnectTimeout,
			},
			&cli.DurationFlag{
				Name:        "request-timeout",
				Usage:       "timeout for IPFS-Cluster API requests",
				EnvVars:     []string{"VGW_IPFS_REQUEST_TIMEOUT"},
				Value:       60 * time.Second,
				Destination: &ipfsRequestTimeout,
			},
			&cli.IntFlag{
				Name:        "max-retries",
				Usage:       "maximum number of retries for failed operations",
				EnvVars:     []string{"VGW_IPFS_MAX_RETRIES"},
				Value:       3,
				Destination: &ipfsMaxRetries,
			},
			&cli.DurationFlag{
				Name:        "retry-delay",
				Usage:       "delay between retry attempts",
				EnvVars:     []string{"VGW_IPFS_RETRY_DELAY"},
				Value:       1 * time.Second,
				Destination: &ipfsRetryDelay,
			},

			// Performance settings
			&cli.IntFlag{
				Name:        "max-concurrent-pins",
				Usage:       "maximum number of concurrent pin operations",
				EnvVars:     []string{"VGW_IPFS_MAX_CONCURRENT_PINS"},
				Value:       100,
				Destination: &ipfsMaxConcurrentPins,
			},
			&cli.DurationFlag{
				Name:        "pin-timeout",
				Usage:       "timeout for individual pin operations",
				EnvVars:     []string{"VGW_IPFS_PIN_TIMEOUT"},
				Value:       300 * time.Second,
				Destination: &ipfsPinTimeout,
			},
			&cli.Int64Flag{
				Name:        "chunk-size",
				Usage:       "chunk size for large file processing (bytes)",
				EnvVars:     []string{"VGW_IPFS_CHUNK_SIZE"},
				Value:       1024 * 1024, // 1MB
				Destination: &ipfsChunkSize,
			},

			// Replication settings
			&cli.IntFlag{
				Name:        "replication-min",
				Usage:       "minimum number of replicas for each object",
				EnvVars:     []string{"VGW_IPFS_REPLICATION_MIN"},
				Value:       1,
				Destination: &ipfsReplicationMin,
			},
			&cli.IntFlag{
				Name:        "replication-max",
				Usage:       "maximum number of replicas for each object",
				EnvVars:     []string{"VGW_IPFS_REPLICATION_MAX"},
				Value:       3,
				Destination: &ipfsReplicationMax,
			},

			// Storage settings
			&cli.BoolFlag{
				Name:        "compression",
				Usage:       "enable compression for stored objects",
				EnvVars:     []string{"VGW_IPFS_COMPRESSION_ENABLED"},
				Value:       false,
				Destination: &ipfsCompressionEnabled,
			},

			// Metadata database settings
			&cli.StringFlag{
				Name:        "metadata-db-type",
				Usage:       "metadata database type (memory, ydb, scylla)",
				EnvVars:     []string{"VGW_IPFS_METADATA_DB_TYPE"},
				Value:       "memory",
				Destination: &ipfsMetadataDBType,
			},
			&cli.StringFlag{
				Name:        "metadata-db-endpoints",
				Usage:       "comma-separated list of metadata database endpoints",
				EnvVars:     []string{"VGW_IPFS_METADATA_DB_ENDPOINTS"},
				Destination: &ipfsMetadataDBEndpoints,
			},

			// Cache settings
			&cli.StringFlag{
				Name:        "cache-endpoints",
				Usage:       "comma-separated list of Redis cache endpoints",
				EnvVars:     []string{"VGW_IPFS_CACHE_ENDPOINTS"},
				Destination: &ipfsCacheEndpoints,
			},
			&cli.BoolFlag{
				Name:        "cache-enabled",
				Usage:       "enable multi-level caching",
				EnvVars:     []string{"VGW_IPFS_CACHE_ENABLED"},
				Value:       true,
				Destination: &ipfsCacheEnabled,
			},

			// Monitoring settings
			&cli.BoolFlag{
				Name:        "metrics-enabled",
				Usage:       "enable metrics collection and monitoring",
				EnvVars:     []string{"VGW_IPFS_METRICS_ENABLED"},
				Value:       true,
				Destination: &ipfsMetricsEnabled,
			},
			&cli.StringFlag{
				Name:        "log-level",
				Usage:       "logging level (debug, info, warn, error)",
				EnvVars:     []string{"VGW_IPFS_LOG_LEVEL"},
				Value:       "info",
				Destination: &ipfsLogLevel,
			},

			// Replica manager settings
			&cli.BoolFlag{
				Name:        "replica-manager-enabled",
				Usage:       "enable intelligent replica management",
				EnvVars:     []string{"VGW_IPFS_REPLICA_MANAGER_ENABLED"},
				Value:       true,
				Destination: &ipfsReplicaManagerEnabled,
			},
			&cli.DurationFlag{
				Name:        "analysis-interval",
				Usage:       "interval for access pattern analysis",
				EnvVars:     []string{"VGW_IPFS_ANALYSIS_INTERVAL"},
				Value:       15 * time.Minute,
				Destination: &ipfsAnalysisInterval,
			},
			&cli.DurationFlag{
				Name:        "rebalancing-interval",
				Usage:       "interval for replica rebalancing",
				EnvVars:     []string{"VGW_IPFS_REBALANCING_INTERVAL"},
				Value:       1 * time.Hour,
				Destination: &ipfsRebalancingInterval,
			},
			&cli.BoolFlag{
				Name:        "geographic-optimization",
				Usage:       "enable geographic replica optimization",
				EnvVars:     []string{"VGW_IPFS_GEOGRAPHIC_OPTIMIZATION"},
				Value:       true,
				Destination: &ipfsGeographicOptimization,
			},
			&cli.BoolFlag{
				Name:        "load-balancing-enabled",
				Usage:       "enable load balancing across cluster nodes",
				EnvVars:     []string{"VGW_IPFS_LOAD_BALANCING_ENABLED"},
				Value:       true,
				Destination: &ipfsLoadBalancingEnabled,
			},
			&cli.Int64Flag{
				Name:        "hot-data-threshold",
				Usage:       "access count threshold for hot data classification",
				EnvVars:     []string{"VGW_IPFS_HOT_DATA_THRESHOLD"},
				Value:       100,
				Destination: &ipfsHotDataThreshold,
			},
			&cli.Int64Flag{
				Name:        "warm-data-threshold",
				Usage:       "access count threshold for warm data classification",
				EnvVars:     []string{"VGW_IPFS_WARM_DATA_THRESHOLD"},
				Value:       50,
				Destination: &ipfsWarmDataThreshold,
			},
			&cli.Int64Flag{
				Name:        "cold-data-threshold",
				Usage:       "access count threshold for cold data classification",
				EnvVars:     []string{"VGW_IPFS_COLD_DATA_THRESHOLD"},
				Value:       10,
				Destination: &ipfsColdDataThreshold,
			},

			// Configuration file
			&cli.StringFlag{
				Name:        "config",
				Usage:       "path to IPFS backend configuration file (JSON/YAML)",
				EnvVars:     []string{"VGW_IPFS_CONFIG_PATH"},
				Destination: &ipfsConfigPath,
				Aliases:     []string{"c"},
			},
		},
	}
}

func runIPFS(ctx *cli.Context) error {
	// Parse cluster endpoints
	endpoints := strings.Split(ipfsClusterEndpoints, ",")
	for i, endpoint := range endpoints {
		endpoints[i] = strings.TrimSpace(endpoint)
	}

	// Parse metadata DB endpoints
	var metadataEndpoints []string
	if ipfsMetadataDBEndpoints != "" {
		metadataEndpoints = strings.Split(ipfsMetadataDBEndpoints, ",")
		for i, endpoint := range metadataEndpoints {
			metadataEndpoints[i] = strings.TrimSpace(endpoint)
		}
	}

	// Parse cache endpoints
	var cacheEndpoints []string
	if ipfsCacheEndpoints != "" {
		cacheEndpoints = strings.Split(ipfsCacheEndpoints, ",")
		for i, endpoint := range cacheEndpoints {
			cacheEndpoints[i] = strings.TrimSpace(endpoint)
		}
	}

	// Validate replication settings
	if ipfsReplicationMin > ipfsReplicationMax {
		return fmt.Errorf("replication-min (%d) cannot be greater than replication-max (%d)",
			ipfsReplicationMin, ipfsReplicationMax)
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[ipfsLogLevel] {
		return fmt.Errorf("invalid log level: %s (valid: debug, info, warn, error)", ipfsLogLevel)
	}

	// Validate metadata DB type
	validDBTypes := map[string]bool{
		"memory": true,
		"ydb":    true,
		"scylla": true,
	}
	if !validDBTypes[ipfsMetadataDBType] {
		return fmt.Errorf("invalid metadata DB type: %s (valid: memory, ydb, scylla)", ipfsMetadataDBType)
	}

	// Create IPFS configuration
	config := &ipfs.IPFSConfig{
		// Cluster connection settings
		ClusterEndpoints: endpoints,
		Username:         ipfsUsername,
		Password:         ipfsPassword,
		ConnectTimeout:   ipfsConnectTimeout,
		RequestTimeout:   ipfsRequestTimeout,
		MaxRetries:       ipfsMaxRetries,
		RetryDelay:       ipfsRetryDelay,

		// Performance settings
		MaxConcurrentPins: ipfsMaxConcurrentPins,
		PinTimeout:        ipfsPinTimeout,
		ChunkSize:         ipfsChunkSize,

		// Replication settings
		ReplicationMin: ipfsReplicationMin,
		ReplicationMax: ipfsReplicationMax,

		// Storage settings
		CompressionEnabled: ipfsCompressionEnabled,

		// Metadata database settings
		MetadataDBType:      ipfsMetadataDBType,
		MetadataDBEndpoints: metadataEndpoints,

		// Cache settings
		CacheEndpoints: cacheEndpoints,
		CacheEnabled:   ipfsCacheEnabled,

		// Monitoring settings
		MetricsEnabled: ipfsMetricsEnabled,
		LogLevel:       ipfsLogLevel,

		// Replica manager settings
		ReplicaManagerEnabled:  ipfsReplicaManagerEnabled,
		AnalysisInterval:       ipfsAnalysisInterval,
		RebalancingInterval:    ipfsRebalancingInterval,
		GeographicOptimization: ipfsGeographicOptimization,
		LoadBalancingEnabled:   ipfsLoadBalancingEnabled,
		HotDataThreshold:       ipfsHotDataThreshold,
		WarmDataThreshold:      ipfsWarmDataThreshold,
		ColdDataThreshold:      ipfsColdDataThreshold,
	}

	// Create IPFS backend options
	opts := ipfs.IPFSOptions{
		Context: ctx.Context,
	}

	// Initialize IPFS backend
	be, err := ipfs.New(config, opts)
	if err != nil {
		return fmt.Errorf("failed to initialize IPFS backend: %w", err)
	}

	// Run the gateway with IPFS backend
	return runGateway(ctx.Context, be)
}
