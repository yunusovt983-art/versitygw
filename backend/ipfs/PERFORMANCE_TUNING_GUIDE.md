# IPFS Backend Performance Tuning Guide

## Overview

This guide provides comprehensive performance optimization strategies for VersityGW with IPFS-Cluster backend, covering system-level tuning, application configuration, and operational best practices to achieve optimal performance at scale.

## Performance Baseline and Targets

### Performance Metrics

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| Pin Latency (P99) | < 2 seconds | `ipfs_pin_duration_seconds` |
| Get Object Latency (P99) | < 100ms | `s3_get_object_duration_seconds` |
| Put Object Throughput | > 1000 ops/sec | `s3_put_object_total` rate |
| Cache Hit Rate | > 85% | `ipfs_cache_hit_ratio` |
| Metadata Query Latency (P99) | < 10ms | `metadata_query_duration_seconds` |
| Cluster Availability | > 99.9% | `ipfs_cluster_nodes_available` |

### Baseline Testing

```bash
#!/bin/bash
# performance-baseline.sh

echo "=== VersityGW IPFS Performance Baseline ==="

# Test pin performance
echo "1. Pin Performance Test:"
time for i in {1..100}; do
    echo "test-data-$i" | ipfs add -q | xargs ipfs-cluster-ctl pin add
done

# Test S3 operations
echo "2. S3 Operations Test:"
s3-benchmark -bucket test-bucket -object-size 1MB -num-objects 1000 \
    -endpoint http://localhost:8080

# Test metadata performance
echo "3. Metadata Query Performance:"
ab -n 1000 -c 10 http://localhost:8081/admin/metadata/stats

# Test cache performance
echo "4. Cache Performance:"
redis-benchmark -h localhost -p 6379 -n 10000 -d 1024

echo "=== Baseline Complete ==="
```

## System-Level Optimizations

### Operating System Tuning

#### Kernel Parameters

```bash
# /etc/sysctl.d/99-versitygw-performance.conf

# Network optimizations
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 268435456
net.ipv4.tcp_wmem = 4096 65536 268435456
net.ipv4.tcp_congestion_control = bbr
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 8192

# File system optimizations
fs.file-max = 2097152
fs.nr_open = 2097152
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.swappiness = 1
vm.vfs_cache_pressure = 50

# Memory optimizations
vm.overcommit_memory = 1
vm.max_map_count = 262144

# Apply settings
sysctl -p /etc/sysctl.d/99-versitygw-performance.conf
```

#### Process Limits

```bash
# /etc/security/limits.d/versitygw.conf
versitygw soft nofile 65536
versitygw hard nofile 65536
versitygw soft nproc 32768
versitygw hard nproc 32768
versitygw soft memlock unlimited
versitygw hard memlock unlimited

# /etc/systemd/system/versitygw.service.d/limits.conf
[Service]
LimitNOFILE=65536
LimitNPROC=32768
LimitMEMLOCK=infinity
```

#### CPU Optimization

```bash
# Set CPU governor to performance
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Disable CPU frequency scaling
systemctl disable ondemand
systemctl disable cpufrequtils

# Set CPU affinity for critical processes
taskset -cp 0-7 $(pgrep versitygw)
taskset -cp 8-15 $(pgrep ipfs)
taskset -cp 16-23 $(pgrep ipfs-cluster-service)
```

### Storage Optimization

#### Disk Configuration

```bash
# Use high-performance filesystems
mkfs.ext4 -F -O ^has_journal /dev/nvme0n1p1  # For metadata
mkfs.xfs -f /dev/nvme1n1p1                   # For IPFS data

# Mount with performance options
# /etc/fstab
/dev/nvme0n1p1 /opt/versitygw/metadata ext4 noatime,nodiratime,nobarrier 0 0
/dev/nvme1n1p1 /opt/ipfs/data xfs noatime,nodiratime,nobarrier,largeio 0 0

# Set I/O scheduler
echo mq-deadline > /sys/block/nvme0n1/queue/scheduler
echo mq-deadline > /sys/block/nvme1n1/queue/scheduler

# Optimize I/O queue depth
echo 32 > /sys/block/nvme0n1/queue/nr_requests
echo 32 > /sys/block/nvme1n1/queue/nr_requests
```

#### RAID Configuration

```bash
# For high-throughput workloads, use RAID 0 or RAID 10
mdadm --create /dev/md0 --level=10 --raid-devices=4 \
    /dev/nvme0n1 /dev/nvme1n1 /dev/nvme2n1 /dev/nvme3n1

# Optimize RAID stripe size
echo 512 > /sys/block/md0/md/stripe_cache_size
```

## Application-Level Optimizations

### VersityGW Configuration

#### High-Performance Configuration

```yaml
# config/high-performance.yaml
backend:
  type: "ipfs"
  ipfs:
    # Connection optimization
    cluster_endpoints:
      - "http://cluster-1:9094"
      - "http://cluster-2:9094"
      - "http://cluster-3:9094"
    
    connection_timeout: "10s"
    request_timeout: "2m"
    max_concurrent_pins: 2000    # Increased concurrency
    pin_timeout: "90s"           # Optimized timeout
    unpin_timeout: "60s"
    
    # Chunking optimization
    chunk_size: 1048576          # 1MB chunks (optimal for most workloads)
    compression_enabled: true    # Enable compression
    deduplication_enabled: true  # Enable deduplication
    
    # Replication optimization
    default_replication_factor: 3
    min_replication_factor: 2
    max_replication_factor: 7
    
    # Metadata optimization
    metadata_db:
      type: "ydb"
      endpoints:
        - "grpc://ydb-1:2136"
        - "grpc://ydb-2:2136"
        - "grpc://ydb-3:2136"
      database: "/Root/versity"
      max_connections: 500       # Increased connection pool
      connection_timeout: "5s"
      query_timeout: "15s"
      
      # Connection pooling
      pool_settings:
        max_idle_connections: 100
        max_open_connections: 500
        connection_max_lifetime: "1h"
        connection_max_idle_time: "10m"
    
    # Multi-tier caching
    cache:
      # L1: Memory cache (hot data)
      memory:
        max_size: "16GB"         # Large memory cache
        ttl: "2h"
        cleanup_interval: "5m"
        eviction_policy: "lru"
        
        # Memory optimization
        gc_percentage: 10
        max_entries: 10000000
      
      # L2: Redis cluster (warm data)
      redis:
        endpoints:
          - "redis-1:7000"
          - "redis-2:7000"
          - "redis-3:7000"
          - "redis-4:7000"
          - "redis-5:7000"
          - "redis-6:7000"
        cluster_mode: true
        password: "redis-password"
        max_retries: 3
        pool_size: 500           # Large connection pool
        ttl: "24h"
        
        # Redis optimization
        pipeline_size: 100
        read_timeout: "1s"
        write_timeout: "1s"
      
      # Cache policies
      policies:
        metadata_ttl: "1h"
        pin_status_ttl: "5m"
        object_info_ttl: "30m"
        
        # Prefetching
        prefetch_enabled: true
        prefetch_threshold: 10   # Prefetch after 10 accesses
        prefetch_factor: 2       # Prefetch 2x replication

# Performance tuning
performance:
  # Worker pools (scale with CPU cores)
  pin_workers: 200             # 200 pin workers
  unpin_workers: 50            # 50 unpin workers
  metadata_workers: 100        # 100 metadata workers
  
  # Connection pools
  connection_pools:
    cluster_pool_size: 100
    metadata_pool_size: 200
    cache_pool_size: 300
  
  # Timeouts
  client_timeout: "30s"
  backend_timeout: "2m"
  
  # Limits
  max_object_size: "10TB"
  max_multipart_parts: 10000
  max_concurrent_requests: 50000  # High concurrency
  
  # Batch operations
  batch_operations:
    enabled: true
    batch_size: 5000           # Large batches
    batch_timeout: "5s"
    max_batch_memory: "1GB"
  
  # Circuit breaker
  circuit_breaker:
    enabled: true
    failure_threshold: 20
    recovery_timeout: "10s"
    half_open_max_requests: 10
  
  # Rate limiting
  rate_limiting:
    enabled: true
    requests_per_second: 10000
    burst_size: 20000

# Monitoring optimization
monitoring:
  metrics:
    enabled: true
    listen_address: "0.0.0.0:9090"
    collection_interval: "5s"   # Frequent collection
    
    # High-resolution metrics
    high_resolution_metrics:
      - "ipfs_pin_duration_seconds"
      - "s3_operation_duration_seconds"
      - "cache_hit_ratio"
      - "metadata_query_duration_seconds"
  
  logging:
    level: "info"              # Reduce log verbosity
    format: "json"
    output: "/var/log/versitygw/versitygw.log"
    
    # Async logging for performance
    async_logging: true
    buffer_size: 10000
    flush_interval: "1s"
```

### IPFS-Cluster Optimization

#### Cluster Configuration

```json
{
  "cluster": {
    "secret": "your-cluster-secret",
    "leave_on_shutdown": false,
    "listen_multiaddress": "/ip4/0.0.0.0/tcp/9096",
    "state_sync_interval": "2m0s",
    "ipfs_sync_interval": "1m0s",
    "replication_factor_min": 2,
    "replication_factor_max": 7,
    "monitor_ping_interval": "10s",
    "peer_watch_interval": "5s",
    "mdns_interval": "10s",
    "disable_repinning": false,
    "connection_manager": {
      "high_water": 400,
      "low_water": 100,
      "grace_period": "2m0s"
    }
  },
  "consensus": {
    "crdt": {
      "cluster_name": "versity-cluster",
      "trusted_peers": ["*"],
      "batching": {
        "max_batch_size": 1000,
        "max_batch_age": "5s"
      }
    }
  },
  "api": {
    "ipfsproxy": {
      "listen_multiaddress": "/ip4/0.0.0.0/tcp/9095",
      "read_timeout": "30s",
      "read_header_timeout": "5s",
      "write_timeout": "30s",
      "idle_timeout": "2m0s"
    },
    "restapi": {
      "http_listen_multiaddress": "/ip4/0.0.0.0/tcp/9094",
      "read_timeout": "30s",
      "read_header_timeout": "5s",
      "write_timeout": "30s",
      "idle_timeout": "2m0s",
      "max_header_bytes": 4096
    }
  },
  "ipfs_connector": {
    "ipfshttp": {
      "node_multiaddress": "/ip4/127.0.0.1/tcp/5001",
      "connect_swarms_delay": "7s",
      "ipfs_request_timeout": "2m0s",
      "pin_timeout": "90s",
      "unpin_timeout": "60s",
      "repinning_timeout": "2m0s"
    }
  },
  "pin_tracker": {
    "stateless": {
      "concurrent_pins": 50,
      "priority_pin_max_age": "12h0m0s",
      "priority_pin_max_retries": 10
    }
  },
  "monitor": {
    "pubsubmon": {
      "check_interval": "10s"
    }
  },
  "allocator": {
    "balanced": {
      "allocate_by": ["tag:region", "freespace", "pinqueue"]
    }
  },
  "informer": {
    "disk": {
      "metric_ttl": "10s",
      "metric_type": "freespace"
    },
    "pinqueue": {
      "metric_ttl": "5s",
      "weight_bucket_size": 100000
    },
    "tags": {
      "metric_ttl": "30s",
      "tags": {
        "region": "us-east-1",
        "zone": "us-east-1a",
        "instance_type": "c5.4xlarge"
      }
    }
  }
}
```

### IPFS Node Optimization

#### IPFS Configuration

```bash
# Optimize IPFS configuration
ipfs config --json Addresses.Swarm '[
  "/ip4/0.0.0.0/tcp/4001",
  "/ip6/::/tcp/4001",
  "/ip4/0.0.0.0/udp/4001/quic",
  "/ip6/::/udp/4001/quic"
]'

# Connection manager settings
ipfs config --json Swarm.ConnMgr.HighWater 2000
ipfs config --json Swarm.ConnMgr.LowWater 500
ipfs config --json Swarm.ConnMgr.GracePeriod '"2m"'

# Resource manager settings
ipfs config --json Swarm.ResourceMgr.MaxMemory '"8GB"'
ipfs config --json Swarm.ResourceMgr.MaxFD 8192

# Datastore settings
ipfs config --json Datastore.Spec.mounts '[
  {
    "child": {
      "type": "badgerds",
      "path": "badgerds",
      "syncWrites": false,
      "truncate": true
    },
    "mountpoint": "/blocks",
    "prefix": "badger.datastore",
    "type": "measure"
  },
  {
    "child": {
      "compression": "none",
      "path": "datastore",
      "type": "levelds"
    },
    "mountpoint": "/",
    "prefix": "leveldb.datastore",
    "type": "measure"
  }
]'

# Gateway settings
ipfs config --json Gateway.PublicGateways null
ipfs config --json Gateway.NoFetch true

# Experimental features
ipfs config --json Experimental.AcceleratedDHTClient true
ipfs config --json Experimental.OptimisticProvide true
ipfs config --json Experimental.OptimisticProvideJobsPoolSize 60
```

## Database Optimization

### YDB Optimization

#### YDB Configuration

```yaml
# YDB configuration for high performance
static_erasure: none
host_configs:
- drive:
  - path: /opt/ydb/data
    type: SSD
  host_config_id: 1

domains_config:
  domain:
  - name: Root
    storage_pool_types:
    - kind: ssd
      pool_config:
        box_id: 1
        erasure_species: none
        kind: ssd
        pdisk_filter:
        - property:
          - type: SSD
        vdisk_kind: Default

table_service_config:
  sql_version: 1
  compile_service_config:
    compile_query_cache_size: 1000
  resource_manager:
    query_memory_limit: 8589934592  # 8GB
    query_count_limit: 1000

grpc_config:
  max_message_size: 67108864      # 64MB
  max_session_count: 10000
  keep_alive_enable: true
  keep_alive_idle_timeout_ms: 30000
  keep_alive_probe_interval_ms: 10000

actor_system_config:
  executor:
  - name: System
    threads: 8
    type: BASIC
    spin_threshold: 20
  - name: User
    threads: 16
    type: BASIC
    spin_threshold: 20
  - name: Batch
    threads: 8
    type: BASIC
    spin_threshold: 20
  - name: IO
    threads: 4
    type: IO
    time_per_mailbox_micro_secs: 100
  - name: IC
    threads: 4
    type: BASIC
    spin_threshold: 10
    time_per_mailbox_micro_secs: 100
```

#### YDB Schema Optimization

```sql
-- Optimized table schema
CREATE TABLE object_mappings (
    bucket Utf8,
    s3_key Utf8,
    cid Utf8,
    size Uint64,
    content_type Utf8,
    content_encoding Utf8,
    user_metadata Json,
    tags Json,
    pin_status Uint32,
    replication_count Uint32,
    pinned_nodes Json,
    created_at Timestamp,
    updated_at Timestamp,
    accessed_at Timestamp,
    PRIMARY KEY (bucket, s3_key)
)
PARTITION BY HASH(bucket)
WITH (
    PARTITION_COUNT_LIMIT = 1000,
    AUTO_PARTITIONING_MIN_PARTITIONS_COUNT = 100,
    AUTO_PARTITIONING_MAX_PARTITIONS_COUNT = 1000,
    AUTO_PARTITIONING_PARTITION_SIZE_MB = 2048,
    AUTO_PARTITIONING_BY_SIZE = Enabled,
    AUTO_PARTITIONING_BY_LOAD = Enabled
);

-- Secondary indexes for performance
CREATE INDEX idx_object_mappings_cid ON object_mappings 
GLOBAL ON (cid) COVER (bucket, s3_key, size, pin_status);

CREATE INDEX idx_object_mappings_accessed ON object_mappings 
GLOBAL ON (accessed_at DESC) COVER (bucket, s3_key, cid);

-- Analytics table with column store
CREATE TABLE pin_analytics (
    cid Utf8,
    access_count Uint64,
    last_access_time Timestamp,
    average_access_time Double,
    geographic_access Json,
    peer_access_count Json,
    retrieval_latency Json,
    transfer_speed Json,
    optimal_replicas Uint32,
    current_replicas Uint32,
    recommended_nodes Json,
    PRIMARY KEY (cid)
)
WITH (
    STORE = COLUMN,
    AUTO_PARTITIONING_BY_SIZE = Enabled,
    AUTO_PARTITIONING_PARTITION_SIZE_MB = 1024
);
```

### Redis Optimization

#### Redis Cluster Configuration

```conf
# redis.conf optimizations
port 7000
cluster-enabled yes
cluster-config-file nodes.conf
cluster-node-timeout 5000
cluster-announce-ip 10.0.1.100
cluster-announce-port 7000
cluster-announce-bus-port 17000

# Memory optimization
maxmemory 32gb
maxmemory-policy allkeys-lru
maxmemory-samples 10

# Persistence optimization
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error no
rdbcompression yes
rdbchecksum yes

# Network optimization
tcp-keepalive 300
tcp-backlog 511
timeout 0

# Performance optimization
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-size -2
list-compress-depth 0
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64

# Threading (Redis 6.0+)
io-threads 4
io-threads-do-reads yes

# Memory usage optimization
activerehashing yes
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60

# Lazy freeing
lazyfree-lazy-eviction yes
lazyfree-lazy-expire yes
lazyfree-lazy-server-del yes
replica-lazy-flush yes
```

## Workload-Specific Optimizations

### High-Throughput Write Workloads

```yaml
# Optimized for high write throughput
performance:
  pin_workers: 500           # Many pin workers
  unpin_workers: 100
  metadata_workers: 200
  
  batch_operations:
    enabled: true
    batch_size: 10000        # Large batches
    batch_timeout: "10s"
    max_batch_memory: "2GB"

cache:
  # Smaller cache for write workloads
  memory:
    max_size: "4GB"
    ttl: "30m"
  
  # Write-through caching
  write_policy: "write_through"
  
backend:
  ipfs:
    # Optimized for writes
    chunk_size: 2097152      # 2MB chunks
    compression_enabled: false  # Disable for speed
    max_concurrent_pins: 5000
```

### High-Throughput Read Workloads

```yaml
# Optimized for high read throughput
cache:
  # Large cache for reads
  memory:
    max_size: "32GB"
    ttl: "4h"
  
  redis:
    ttl: "72h"               # Long TTL
  
  # Aggressive prefetching
  prefetch_enabled: true
  prefetch_threshold: 5
  prefetch_factor: 3

performance:
  # Fewer pin workers, more metadata workers
  pin_workers: 50
  unpin_workers: 20
  metadata_workers: 300
  
  # High concurrency for reads
  max_concurrent_requests: 100000

backend:
  ipfs:
    # Optimized for reads
    chunk_size: 524288       # 512KB chunks
    compression_enabled: true
```

### Mixed Workloads

```yaml
# Balanced configuration for mixed workloads
performance:
  pin_workers: 200
  unpin_workers: 50
  metadata_workers: 150
  
  # Adaptive batching
  batch_operations:
    enabled: true
    adaptive_batching: true
    min_batch_size: 100
    max_batch_size: 5000
    target_latency: "100ms"

cache:
  # Multi-tier caching
  memory:
    max_size: "16GB"
    ttl: "2h"
  
  redis:
    ttl: "24h"
  
  # Intelligent caching policies
  policies:
    hot_data_threshold: 10
    warm_data_threshold: 3
    cold_data_ttl: "7d"
```

## Monitoring and Profiling

### Performance Monitoring

```bash
#!/bin/bash
# performance-monitor.sh

# Collect performance metrics
echo "=== Performance Monitoring ==="

# System metrics
echo "1. System Resources:"
top -bn1 | head -20
iostat -x 1 1
free -h

# Application metrics
echo "2. VersityGW Metrics:"
curl -s http://localhost:9090/metrics | grep -E "(ipfs_pin_duration|s3_operation_duration|cache_hit_ratio)"

# Database metrics
echo "3. Database Performance:"
case "$METADATA_DB_TYPE" in
    "ydb")
        ydb -e "$YDB_ENDPOINT" -d "$YDB_DATABASE" monitoring get
        ;;
    "postgres")
        psql "$POSTGRES_CONNECTION" -c "SELECT * FROM pg_stat_database WHERE datname = 'versitygw';"
        ;;
esac

# Cache metrics
echo "4. Cache Performance:"
redis-cli info stats | grep -E "(keyspace_hits|keyspace_misses|used_memory)"

echo "=== Monitoring Complete ==="
```

### Profiling Tools

```bash
# CPU profiling
go tool pprof http://localhost:8081/debug/pprof/profile?seconds=30

# Memory profiling
go tool pprof http://localhost:8081/debug/pprof/heap

# Goroutine profiling
go tool pprof http://localhost:8081/debug/pprof/goroutine

# Block profiling
go tool pprof http://localhost:8081/debug/pprof/block

# Mutex profiling
go tool pprof http://localhost:8081/debug/pprof/mutex
```

## Load Testing

### Comprehensive Load Test

```bash
#!/bin/bash
# load-test.sh

echo "=== VersityGW IPFS Load Test ==="

# Test parameters
ENDPOINT="http://localhost:8080"
BUCKET="load-test-bucket"
CONCURRENT_USERS=100
TEST_DURATION="10m"
OBJECT_SIZE="1MB"

# Create test bucket
aws s3 mb s3://$BUCKET --endpoint-url $ENDPOINT

# Write load test
echo "1. Write Load Test:"
s3-benchmark \
    -endpoint $ENDPOINT \
    -bucket $BUCKET \
    -object-size $OBJECT_SIZE \
    -num-objects 10000 \
    -concurrent $CONCURRENT_USERS \
    -duration $TEST_DURATION \
    -operation put

# Read load test
echo "2. Read Load Test:"
s3-benchmark \
    -endpoint $ENDPOINT \
    -bucket $BUCKET \
    -object-size $OBJECT_SIZE \
    -num-objects 10000 \
    -concurrent $CONCURRENT_USERS \
    -duration $TEST_DURATION \
    -operation get

# Mixed load test
echo "3. Mixed Load Test:"
s3-benchmark \
    -endpoint $ENDPOINT \
    -bucket $BUCKET \
    -object-size $OBJECT_SIZE \
    -num-objects 10000 \
    -concurrent $CONCURRENT_USERS \
    -duration $TEST_DURATION \
    -operation mixed \
    -read-ratio 0.8

echo "=== Load Test Complete ==="
```

## Capacity Planning

### Scaling Guidelines

#### Vertical Scaling

| Component | CPU Cores | Memory | Storage | Network |
|-----------|-----------|---------|---------|---------|
| VersityGW | 32+ cores | 64+ GB | 1+ TB SSD | 25+ Gbps |
| IPFS-Cluster | 16+ cores | 32+ GB | 100+ TB | 10+ Gbps |
| Metadata DB | 32+ cores | 128+ GB | 10+ TB SSD | 25+ Gbps |
| Redis Cache | 16+ cores | 64+ GB | 1+ TB SSD | 10+ Gbps |

#### Horizontal Scaling

```bash
# Calculate required nodes based on throughput
REQUIRED_THROUGHPUT=10000  # ops/sec
NODE_THROUGHPUT=1000       # ops/sec per node
REQUIRED_NODES=$((REQUIRED_THROUGHPUT / NODE_THROUGHPUT))

echo "Required VersityGW nodes: $REQUIRED_NODES"

# Calculate storage requirements
TOTAL_OBJECTS=1000000000000  # 1 trillion objects
AVG_OBJECT_SIZE=1048576      # 1MB average
REPLICATION_FACTOR=3
TOTAL_STORAGE=$((TOTAL_OBJECTS * AVG_OBJECT_SIZE * REPLICATION_FACTOR))

echo "Total storage required: $((TOTAL_STORAGE / 1024 / 1024 / 1024 / 1024)) TB"
```

### Resource Monitoring

```yaml
# Prometheus alerting rules for capacity planning
groups:
- name: capacity-planning
  rules:
  - alert: HighCPUUsage
    expr: cpu_usage_percent > 80
    for: 5m
    annotations:
      summary: "High CPU usage detected"
      
  - alert: HighMemoryUsage
    expr: memory_usage_percent > 85
    for: 5m
    annotations:
      summary: "High memory usage detected"
      
  - alert: HighDiskUsage
    expr: disk_usage_percent > 90
    for: 1m
    annotations:
      summary: "High disk usage detected"
      
  - alert: HighNetworkUtilization
    expr: network_utilization_percent > 80
    for: 5m
    annotations:
      summary: "High network utilization detected"
```

This performance tuning guide provides comprehensive optimization strategies for achieving maximum performance with VersityGW IPFS backend at scale, covering all aspects from system-level tuning to application-specific optimizations.