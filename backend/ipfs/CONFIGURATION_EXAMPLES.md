# IPFS Backend Configuration Examples

## Overview

This document provides configuration examples for various deployment scenarios of VersityGW with IPFS-Cluster backend, from development environments to large-scale production deployments.

## Development Environment

### Single Node Development Setup

**File: `config/development.yaml`**

```yaml
# Development configuration for local testing
listen_address: "127.0.0.1:8080"
admin_listen_address: "127.0.0.1:8081"

backend:
  type: "ipfs"
  ipfs:
    # Local IPFS-Cluster
    cluster_endpoints:
      - "http://127.0.0.1:9094"
    
    connection_timeout: "10s"
    request_timeout: "1m"
    max_concurrent_pins: 10
    pin_timeout: "30s"
    unpin_timeout: "30s"
    
    # Minimal replication for development
    default_replication_factor: 1
    min_replication_factor: 1
    max_replication_factor: 1
    
    chunk_size: 262144  # 256KB chunks
    compression_enabled: false
    deduplication_enabled: true
    
    # In-memory metadata store for development
    metadata_db:
      type: "memory"
      max_entries: 10000
    
    # Simple memory cache only
    cache:
      memory:
        max_size: "100MB"
        ttl: "10m"
        cleanup_interval: "1m"

# Minimal security for development
security:
  tls:
    enabled: false
  iam:
    enabled: false

# Debug logging
monitoring:
  logging:
    level: "debug"
    format: "text"
    output: "stdout"

performance:
  pin_workers: 2
  unpin_workers: 1
  metadata_workers: 2
  max_concurrent_requests: 100
```

### Docker Compose Development

**File: `docker-compose.dev.yml`**

```yaml
version: '3.8'

services:
  ipfs:
    image: ipfs/kubo:v0.24.0
    ports:
      - "4001:4001"
      - "5001:5001"
      - "8080:8080"
    volumes:
      - ipfs_data:/data/ipfs
    environment:
      - IPFS_PROFILE=server
    command: |
      sh -c "
        ipfs config Addresses.API /ip4/0.0.0.0/tcp/5001
        ipfs config Addresses.Gateway /ip4/0.0.0.0/tcp/8080
        ipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin '[\"*\"]'
        ipfs daemon
      "

  ipfs-cluster:
    image: ipfs/ipfs-cluster:v1.0.8
    depends_on:
      - ipfs
    ports:
      - "9094:9094"
      - "9095:9095"
      - "9096:9096"
    volumes:
      - cluster_data:/data/ipfs-cluster
    environment:
      - CLUSTER_SECRET=your-32-byte-hex-secret-here
      - CLUSTER_IPFSHTTP_NODEMULTIADDRESS=/dns4/ipfs/tcp/5001
    command: |
      sh -c "
        echo '{
          \"cluster\": {
            \"secret\": \"${CLUSTER_SECRET}\",
            \"replication_factor_min\": 1,
            \"replication_factor_max\": 1
          }
        }' > /data/ipfs-cluster/service.json
        ipfs-cluster-service daemon
      "

  versitygw:
    build: .
    depends_on:
      - ipfs-cluster
    ports:
      - "8000:8080"
      - "8001:8081"
    volumes:
      - ./config/development.yaml:/etc/versitygw/config.yaml
    environment:
      - VERSITYGW_CONFIG=/etc/versitygw/config.yaml

volumes:
  ipfs_data:
  cluster_data:
```

## Small Production Environment

### Single Datacenter, 3-Node Cluster

**File: `config/small-production.yaml`**

```yaml
listen_address: "0.0.0.0:8080"
admin_listen_address: "0.0.0.0:8081"

backend:
  type: "ipfs"
  ipfs:
    # 3-node IPFS-Cluster
    cluster_endpoints:
      - "http://cluster-1.internal:9094"
      - "http://cluster-2.internal:9094"
      - "http://cluster-3.internal:9094"
    
    connection_timeout: "30s"
    request_timeout: "2m"
    max_concurrent_pins: 100
    pin_timeout: "1m"
    unpin_timeout: "1m"
    
    # Standard replication
    default_replication_factor: 3
    min_replication_factor: 2
    max_replication_factor: 5
    
    chunk_size: 1048576  # 1MB chunks
    compression_enabled: true
    deduplication_enabled: true
    
    # PostgreSQL metadata store
    metadata_db:
      type: "postgres"
      connection_string: "postgres://versity:password@postgres.internal:5432/versitygw?sslmode=require"
      max_connections: 50
      connection_timeout: "10s"
      query_timeout: "30s"
    
    # Redis cache
    cache:
      memory:
        max_size: "1GB"
        ttl: "1h"
        cleanup_interval: "10m"
      
      redis:
        endpoints:
          - "redis.internal:6379"
        password: "redis-password"
        db: 0
        max_retries: 3
        pool_size: 50
        ttl: "24h"

# Production security
security:
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/versitygw.crt"
    key_file: "/etc/ssl/private/versitygw.key"
  
  iam:
    enabled: true
    provider: "internal"
  
  ipfs_security:
    encryption_enabled: true
    default_encryption_algorithm: "AES256"

# Production monitoring
monitoring:
  metrics:
    enabled: true
    listen_address: "0.0.0.0:9090"
  
  logging:
    level: "info"
    format: "json"
    output: "/var/log/versitygw/versitygw.log"
    max_size: "100MB"
    max_backups: 10

performance:
  pin_workers: 20
  unpin_workers: 10
  metadata_workers: 15
  max_concurrent_requests: 1000
```

## Large Scale Production

### Multi-Datacenter, High Availability

**File: `config/large-production.yaml`**

```yaml
listen_address: "0.0.0.0:8080"
admin_listen_address: "0.0.0.0:8081"

backend:
  type: "ipfs"
  ipfs:
    # Multi-datacenter IPFS-Cluster
    cluster_endpoints:
      # US East
      - "http://cluster-us-east-1.internal:9094"
      - "http://cluster-us-east-2.internal:9094"
      - "http://cluster-us-east-3.internal:9094"
      # US West
      - "http://cluster-us-west-1.internal:9094"
      - "http://cluster-us-west-2.internal:9094"
      - "http://cluster-us-west-3.internal:9094"
      # Europe
      - "http://cluster-eu-west-1.internal:9094"
      - "http://cluster-eu-west-2.internal:9094"
      - "http://cluster-eu-west-3.internal:9094"
    
    connection_timeout: "30s"
    request_timeout: "5m"
    max_concurrent_pins: 1000
    pin_timeout: "2m"
    unpin_timeout: "3m"
    
    # High availability replication
    default_replication_factor: 5
    min_replication_factor: 3
    max_replication_factor: 15
    
    chunk_size: 1048576  # 1MB chunks
    compression_enabled: true
    deduplication_enabled: true
    
    # YDB distributed metadata store
    metadata_db:
      type: "ydb"
      endpoints:
        - "grpc://ydb-us-east-1.internal:2136"
        - "grpc://ydb-us-east-2.internal:2136"
        - "grpc://ydb-us-west-1.internal:2136"
        - "grpc://ydb-eu-west-1.internal:2136"
      database: "/Root/versity"
      connection_timeout: "10s"
      query_timeout: "30s"
      max_connections: 200
      
      # Sharding configuration
      sharding:
        enabled: true
        shard_count: 1000
        shard_key: "bucket"
    
    # Multi-tier caching
    cache:
      memory:
        max_size: "8GB"
        ttl: "2h"
        cleanup_interval: "15m"
      
      redis:
        # Redis Cluster
        endpoints:
          - "redis-cluster-1.internal:7000"
          - "redis-cluster-2.internal:7000"
          - "redis-cluster-3.internal:7000"
          - "redis-cluster-4.internal:7000"
          - "redis-cluster-5.internal:7000"
          - "redis-cluster-6.internal:7000"
        cluster_mode: true
        password: "redis-cluster-password"
        max_retries: 5
        pool_size: 200
        ttl: "48h"
      
      # Distributed cache tier
      distributed:
        enabled: true
        endpoints:
          - "dcache-1.internal:11211"
          - "dcache-2.internal:11211"
          - "dcache-3.internal:11211"
        ttl: "7d"
    
    # Intelligent replication
    replication:
      analytics_enabled: true
      geographic_optimization: true
      access_pattern_analysis: true
      rebalancing_interval: "1h"
      
      # Regional preferences
      regions:
        - name: "us-east"
          weight: 0.4
          nodes: ["cluster-us-east-1", "cluster-us-east-2", "cluster-us-east-3"]
        - name: "us-west"
          weight: 0.3
          nodes: ["cluster-us-west-1", "cluster-us-west-2", "cluster-us-west-3"]
        - name: "eu-west"
          weight: 0.3
          nodes: ["cluster-eu-west-1", "cluster-eu-west-2", "cluster-eu-west-3"]

# Enterprise security
security:
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/versitygw.crt"
    key_file: "/etc/ssl/private/versitygw.key"
    min_version: "1.3"
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
  
  iam:
    enabled: true
    provider: "ldap"
    ldap:
      server: "ldap://ldap.internal:389"
      bind_dn: "cn=versitygw,ou=services,dc=company,dc=com"
      bind_password: "ldap-password"
      user_base: "ou=users,dc=company,dc=com"
      group_base: "ou=groups,dc=company,dc=com"
  
  ipfs_security:
    encryption_enabled: true
    default_encryption_algorithm: "AES256"
    key_rotation_interval: "30d"
    key_management_service: "vault"
    vault:
      address: "https://vault.internal:8200"
      token: "vault-token"
      mount_path: "versitygw"

# Comprehensive monitoring
monitoring:
  metrics:
    enabled: true
    listen_address: "0.0.0.0:9090"
    path: "/metrics"
    
    # Custom metrics
    custom_metrics:
      - name: "ipfs_pin_queue_size"
        type: "gauge"
        help: "Current size of pin queue"
      - name: "ipfs_geographic_access"
        type: "counter"
        help: "Access count by geographic region"
        labels: ["region", "country"]
  
  logging:
    level: "info"
    format: "json"
    output: "/var/log/versitygw/versitygw.log"
    max_size: "500MB"
    max_backups: 30
    max_age: 90
    
    # Structured logging
    structured_logging:
      enabled: true
      fields:
        - "request_id"
        - "user_id"
        - "bucket"
        - "key"
        - "cid"
        - "operation"
        - "duration"
        - "status_code"
  
  # Distributed tracing
  tracing:
    enabled: true
    provider: "jaeger"
    jaeger:
      endpoint: "http://jaeger.internal:14268/api/traces"
      service_name: "versitygw-ipfs"
      sampler_type: "probabilistic"
      sampler_param: 0.1

# High performance settings
performance:
  pin_workers: 100
  unpin_workers: 50
  metadata_workers: 75
  
  # Connection pooling
  connection_pools:
    cluster_pool_size: 50
    metadata_pool_size: 100
    cache_pool_size: 200
  
  # Timeouts
  client_timeout: "30s"
  backend_timeout: "5m"
  
  # Limits
  max_object_size: "5TB"
  max_multipart_parts: 10000
  max_concurrent_requests: 10000
  
  # Optimization
  batch_operations:
    enabled: true
    batch_size: 1000
    batch_timeout: "5s"
  
  # Circuit breaker
  circuit_breaker:
    enabled: true
    failure_threshold: 10
    recovery_timeout: "30s"
    half_open_max_requests: 5
```

## Specialized Configurations

### High-Throughput Archival

**File: `config/archival.yaml`**

```yaml
# Optimized for high-throughput archival workloads
backend:
  type: "ipfs"
  ipfs:
    # Large chunks for archival data
    chunk_size: 10485760  # 10MB chunks
    compression_enabled: true
    deduplication_enabled: true
    
    # Conservative replication for cost optimization
    default_replication_factor: 2
    min_replication_factor: 2
    max_replication_factor: 3
    
    # Extended timeouts for large objects
    pin_timeout: "10m"
    unpin_timeout: "5m"
    request_timeout: "30m"
    
    # Batch-optimized settings
    max_concurrent_pins: 2000
    
    # Cold storage cache settings
    cache:
      memory:
        max_size: "500MB"  # Smaller memory cache
        ttl: "10m"         # Shorter TTL
      
      redis:
        ttl: "7d"          # Longer Redis TTL
      
      policies:
        metadata_ttl: "24h"
        pin_status_ttl: "1h"
        object_info_ttl: "6h"

performance:
  pin_workers: 200      # More workers for batch operations
  unpin_workers: 50
  metadata_workers: 100
  
  batch_operations:
    enabled: true
    batch_size: 5000    # Large batches
    batch_timeout: "30s"
```

### Content Distribution Network (CDN)

**File: `config/cdn.yaml`**

```yaml
# Optimized for CDN/content distribution
backend:
  type: "ipfs"
  ipfs:
    # Smaller chunks for better distribution
    chunk_size: 262144  # 256KB chunks
    
    # High replication for availability
    default_replication_factor: 7
    min_replication_factor: 5
    max_replication_factor: 20
    
    # Aggressive caching
    cache:
      memory:
        max_size: "16GB"  # Large memory cache
        ttl: "6h"
      
      redis:
        ttl: "72h"        # Extended Redis cache
      
      # Edge cache integration
      edge_cache:
        enabled: true
        providers:
          - "cloudflare"
          - "fastly"
        ttl: "24h"
    
    # Geographic optimization
    replication:
      geographic_optimization: true
      latency_optimization: true
      
      # CDN regions
      regions:
        - name: "north-america"
          weight: 0.4
          latency_target: "50ms"
        - name: "europe"
          weight: 0.3
          latency_target: "50ms"
        - name: "asia-pacific"
          weight: 0.3
          latency_target: "100ms"

performance:
  # Optimized for read-heavy workloads
  pin_workers: 50
  unpin_workers: 20
  metadata_workers: 30
  
  max_concurrent_requests: 50000  # High concurrency
  
  # Prefetching
  prefetch:
    enabled: true
    popular_content_threshold: 100
    prefetch_factor: 2
```

### Development with Mock Services

**File: `config/development-mock.yaml`**

```yaml
# Development with mocked external services
backend:
  type: "ipfs"
  ipfs:
    # Mock cluster endpoints
    cluster_endpoints:
      - "http://mock-cluster:9094"
    
    # Fast timeouts for development
    connection_timeout: "5s"
    request_timeout: "30s"
    pin_timeout: "10s"
    
    # Mock metadata store
    metadata_db:
      type: "mock"
      latency: "1ms"      # Simulated latency
      error_rate: 0.01    # 1% error rate for testing
    
    # Mock cache
    cache:
      type: "mock"
      hit_rate: 0.8       # 80% cache hit rate
      latency: "0.5ms"

# Mock external services
mock_services:
  cluster:
    enabled: true
    pin_success_rate: 0.95
    pin_latency: "100ms"
    storage_size: "1TB"
  
  metadata_db:
    enabled: true
    query_latency: "5ms"
    connection_errors: false
  
  cache:
    enabled: true
    hit_rate: 0.8
    eviction_rate: 0.1

monitoring:
  logging:
    level: "debug"
    format: "text"
    output: "stdout"
    
    # Mock service logging
    mock_logging:
      enabled: true
      log_requests: true
      log_responses: true
```

## Environment-Specific Overrides

### Environment Variables

```bash
# Production environment variables
export VERSITYGW_CLUSTER_ENDPOINTS="http://prod-cluster-1:9094,http://prod-cluster-2:9094"
export VERSITYGW_METADATA_DB_PASSWORD="prod-db-password"
export VERSITYGW_REDIS_PASSWORD="prod-redis-password"
export VERSITYGW_TLS_CERT_FILE="/etc/ssl/certs/prod-versitygw.crt"
export VERSITYGW_TLS_KEY_FILE="/etc/ssl/private/prod-versitygw.key"

# Staging environment variables
export VERSITYGW_CLUSTER_ENDPOINTS="http://staging-cluster-1:9094"
export VERSITYGW_METADATA_DB_PASSWORD="staging-db-password"
export VERSITYGW_LOG_LEVEL="debug"
```

### Configuration Templates

**File: `config/template.yaml`**

```yaml
# Configuration template with environment variable substitution
backend:
  type: "ipfs"
  ipfs:
    cluster_endpoints: ${CLUSTER_ENDPOINTS}
    
    metadata_db:
      type: ${METADATA_DB_TYPE:-postgres}
      connection_string: ${METADATA_DB_CONNECTION_STRING}
      password: ${METADATA_DB_PASSWORD}
    
    cache:
      redis:
        endpoints: ${REDIS_ENDPOINTS}
        password: ${REDIS_PASSWORD}

security:
  tls:
    enabled: ${TLS_ENABLED:-true}
    cert_file: ${TLS_CERT_FILE}
    key_file: ${TLS_KEY_FILE}

monitoring:
  logging:
    level: ${LOG_LEVEL:-info}
    output: ${LOG_OUTPUT:-/var/log/versitygw/versitygw.log}
```

## Configuration Validation

### Schema Validation

**File: `config/schema.json`**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["backend"],
  "properties": {
    "backend": {
      "type": "object",
      "required": ["type", "ipfs"],
      "properties": {
        "type": {
          "type": "string",
          "enum": ["ipfs"]
        },
        "ipfs": {
          "type": "object",
          "required": ["cluster_endpoints"],
          "properties": {
            "cluster_endpoints": {
              "type": "array",
              "minItems": 1,
              "items": {
                "type": "string",
                "format": "uri"
              }
            },
            "default_replication_factor": {
              "type": "integer",
              "minimum": 1,
              "maximum": 100
            },
            "chunk_size": {
              "type": "integer",
              "minimum": 1024,
              "maximum": 104857600
            }
          }
        }
      }
    }
  }
}
```

### Configuration Testing

```bash
#!/bin/bash
# validate-config.sh

CONFIG_FILE=$1
SCHEMA_FILE="config/schema.json"

if [ -z "$CONFIG_FILE" ]; then
    echo "Usage: $0 <config-file>"
    exit 1
fi

# Validate YAML syntax
yq eval '.' "$CONFIG_FILE" > /dev/null || {
    echo "ERROR: Invalid YAML syntax in $CONFIG_FILE"
    exit 1
}

# Convert YAML to JSON and validate against schema
yq eval -o=json "$CONFIG_FILE" | jsonschema -i /dev/stdin "$SCHEMA_FILE" || {
    echo "ERROR: Configuration validation failed for $CONFIG_FILE"
    exit 1
}

echo "Configuration $CONFIG_FILE is valid"
```

These configuration examples cover a wide range of deployment scenarios and provide a solid foundation for customizing VersityGW with IPFS-Cluster backend for specific use cases.