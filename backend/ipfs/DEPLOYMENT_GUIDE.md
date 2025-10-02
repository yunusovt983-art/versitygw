# IPFS Backend Production Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying VersityGW with IPFS-Cluster backend in production environments, including infrastructure setup, configuration, monitoring, and maintenance procedures.

## Prerequisites

### System Requirements

#### Minimum Requirements (Small Scale)
- **CPU**: 8 cores per VersityGW node
- **RAM**: 32 GB per VersityGW node
- **Storage**: 1 TB SSD for metadata and cache
- **Network**: 10 Gbps network connectivity

#### Recommended Requirements (Large Scale)
- **CPU**: 32 cores per VersityGW node
- **RAM**: 128 GB per VersityGW node
- **Storage**: 10 TB NVMe SSD for metadata and cache
- **Network**: 25+ Gbps network connectivity

#### IPFS-Cluster Requirements
- **CPU**: 16 cores per cluster node
- **RAM**: 64 GB per cluster node
- **Storage**: 100 TB+ for IPFS data storage
- **Network**: 10+ Gbps network connectivity

### Software Dependencies

- **Go**: 1.21 or later
- **IPFS**: 0.24.0 or later
- **IPFS-Cluster**: 1.0.8 or later
- **Database**: YDB, ScyllaDB, or PostgreSQL
- **Cache**: Redis Cluster 7.0+
- **Load Balancer**: HAProxy, NGINX, or cloud LB
- **Monitoring**: Prometheus, Grafana

## Infrastructure Setup

### 1. IPFS-Cluster Deployment

#### Single Datacenter Setup

```bash
# Install IPFS and IPFS-Cluster on each node
wget https://dist.ipfs.tech/kubo/v0.24.0/kubo_v0.24.0_linux-amd64.tar.gz
tar -xzf kubo_v0.24.0_linux-amd64.tar.gz
sudo ./kubo/install.sh

wget https://dist.ipfs.tech/ipfs-cluster-service/v1.0.8/ipfs-cluster-service_v1.0.8_linux-amd64.tar.gz
tar -xzf ipfs-cluster-service_v1.0.8_linux-amd64.tar.gz
sudo cp ipfs-cluster-service/ipfs-cluster-service /usr/local/bin/
sudo cp ipfs-cluster-service/ipfs-cluster-ctl /usr/local/bin/

# Initialize IPFS
ipfs init --profile server

# Configure IPFS for cluster use
ipfs config Addresses.API /ip4/0.0.0.0/tcp/5001
ipfs config Addresses.Gateway /ip4/0.0.0.0/tcp/8080
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin '["*"]'
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Methods '["PUT", "POST"]'

# Start IPFS daemon
systemctl enable ipfs
systemctl start ipfs
```

#### IPFS-Cluster Configuration

```bash
# Initialize cluster (on first node)
ipfs-cluster-service init

# Edit cluster configuration
vim ~/.ipfs-cluster/service.json
```

**Cluster Configuration Example:**

```json
{
  "cluster": {
    "secret": "YOUR_CLUSTER_SECRET_HERE",
    "leave_on_shutdown": false,
    "listen_multiaddress": "/ip4/0.0.0.0/tcp/9096",
    "state_sync_interval": "5m0s",
    "ipfs_sync_interval": "2m10s",
    "replication_factor_min": 2,
    "replication_factor_max": 5,
    "monitor_ping_interval": "15s"
  },
  "consensus": {
    "crdt": {
      "cluster_name": "versity-ipfs-cluster",
      "trusted_peers": ["*"]
    }
  },
  "api": {
    "ipfsproxy": {
      "listen_multiaddress": "/ip4/0.0.0.0/tcp/9095"
    },
    "restapi": {
      "http_listen_multiaddress": "/ip4/0.0.0.0/tcp/9094"
    }
  },
  "ipfs_connector": {
    "ipfshttp": {
      "node_multiaddress": "/ip4/127.0.0.1/tcp/5001",
      "connect_swarms_delay": "30s",
      "ipfs_request_timeout": "5m0s",
      "pin_timeout": "2m0s",
      "unpin_timeout": "3m0s"
    }
  },
  "pin_tracker": {
    "stateless": {
      "concurrent_pins": 10,
      "priority_pin_max_age": "24h0m0s",
      "priority_pin_max_retries": 5
    }
  },
  "monitor": {
    "pubsubmon": {
      "check_interval": "15s"
    }
  },
  "allocator": {
    "balanced": {
      "allocate_by": ["tag:region", "freespace"]
    }
  },
  "informer": {
    "disk": {
      "metric_ttl": "30s",
      "metric_type": "freespace"
    },
    "tags": {
      "metric_ttl": "30s",
      "tags": {
        "region": "us-east-1",
        "zone": "us-east-1a"
      }
    }
  }
}
```

### 2. Metadata Database Setup

#### YDB Deployment (Recommended)

```bash
# Install YDB
wget https://binaries.ydb.tech/release/23.3.13/ydbd-23.3.13-linux-amd64.tar.gz
tar -xzf ydbd-23.3.13-linux-amd64.tar.gz
sudo cp ydbd /usr/local/bin/

# Create YDB configuration
mkdir -p /opt/ydb/cfg
```

**YDB Configuration (`/opt/ydb/cfg/config.yaml`):**

```yaml
static_erasure: none
host_configs:
- drive:
  - path: /opt/ydb/data
    type: SSD
  host_config_id: 1

hosts:
- host: localhost
  host_config_id: 1
  port: 19001
  walle_location:
    body: 1
    data_center: 'dc1'
    rack: '1'

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
    state_storage:
    - ring:
        node: [1]
        nto_select: 1
      ssid: 1

table_service_config:
  sql_version: 1

actor_system_config:
  executor:
  - name: System
    spin_threshold: 0
    threads: 2
    type: BASIC
  - name: User
    spin_threshold: 0
    threads: 3
    type: BASIC
  - name: Batch
    spin_threshold: 0
    threads: 2
    type: BASIC
  - name: IO
    threads: 1
    time_per_mailbox_micro_secs: 100
    type: IO
  - name: IC
    spin_threshold: 10
    threads: 1
    time_per_mailbox_micro_secs: 100
    type: BASIC
  scheduler:
    progress_threshold: 10000
    resolution: 256
    spin_threshold: 0

blob_storage_config:
  service_set:
    groups:
    - erasure_species: none
      group_generation: 1
      group_id: 2181038080
      rings:
      - fail_domains:
        - vdisk_locations:
          - node_id: 1
            path: /opt/ydb/data/pdisk_001
            pdisk_category: 0
            pdisk_id: 1001
            vdisk_slot_id: 0
```

#### ScyllaDB Alternative

```bash
# Install ScyllaDB
wget -qO - https://downloads.scylladb.com/deb/ubuntu/scylla-5.2-$(lsb_release -s -c).list | sudo tee /etc/apt/sources.list.d/scylla.list
sudo apt-get update
sudo apt-get install scylla

# Configure ScyllaDB
sudo scylla_setup
```

### 3. Redis Cluster Setup

```bash
# Install Redis
sudo apt-get install redis-server

# Configure Redis for cluster mode
sudo vim /etc/redis/redis.conf
```

**Redis Cluster Configuration:**

```conf
port 7000
cluster-enabled yes
cluster-config-file nodes-7000.conf
cluster-node-timeout 5000
appendonly yes
appendfsync everysec
save 900 1
save 300 10
save 60 10000
maxmemory 8gb
maxmemory-policy allkeys-lru
```

### 4. VersityGW with IPFS Backend

#### Build VersityGW

```bash
# Clone and build VersityGW
git clone https://github.com/versity/versitygw.git
cd versitygw
go build -o versitygw cmd/versitygw/main.go
```

#### Configuration

Create `/etc/versitygw/config.yaml`:

```yaml
# VersityGW Configuration with IPFS Backend
listen_address: "0.0.0.0:8080"
admin_listen_address: "0.0.0.0:8081"

# Backend Configuration
backend:
  type: "ipfs"
  ipfs:
    # IPFS-Cluster endpoints
    cluster_endpoints:
      - "http://cluster-node-1:9094"
      - "http://cluster-node-2:9094"
      - "http://cluster-node-3:9094"
    
    # Connection settings
    connection_timeout: "30s"
    request_timeout: "5m"
    max_concurrent_pins: 1000
    pin_timeout: "2m"
    unpin_timeout: "3m"
    
    # Replication settings
    default_replication_factor: 3
    min_replication_factor: 2
    max_replication_factor: 10
    
    # Performance settings
    chunk_size: 1048576  # 1MB chunks
    compression_enabled: true
    deduplication_enabled: true
    
    # Metadata database
    metadata_db:
      type: "ydb"
      endpoints:
        - "grpc://ydb-node-1:2136"
        - "grpc://ydb-node-2:2136"
        - "grpc://ydb-node-3:2136"
      database: "/Root/versity"
      connection_timeout: "10s"
      query_timeout: "30s"
      max_connections: 100
    
    # Cache configuration
    cache:
      # L1 Memory cache
      memory:
        max_size: "2GB"
        ttl: "1h"
        cleanup_interval: "10m"
      
      # L2 Redis cache
      redis:
        endpoints:
          - "redis-node-1:7000"
          - "redis-node-2:7000"
          - "redis-node-3:7000"
        password: ""
        db: 0
        max_retries: 3
        pool_size: 100
        ttl: "24h"
      
      # Cache policies
      policies:
        metadata_ttl: "1h"
        pin_status_ttl: "5m"
        object_info_ttl: "30m"

# Security settings
security:
  tls:
    enabled: true
    cert_file: "/etc/versitygw/certs/server.crt"
    key_file: "/etc/versitygw/certs/server.key"
  
  # IAM integration
  iam:
    enabled: true
    provider: "internal"
  
  # IPFS-specific security
  ipfs_security:
    encryption_enabled: true
    default_encryption_algorithm: "AES256"
    key_rotation_interval: "30d"

# Monitoring and logging
monitoring:
  metrics:
    enabled: true
    listen_address: "0.0.0.0:9090"
    path: "/metrics"
  
  logging:
    level: "info"
    format: "json"
    output: "/var/log/versitygw/versitygw.log"
    max_size: "100MB"
    max_backups: 10
    max_age: 30

# Performance tuning
performance:
  # Worker pools
  pin_workers: 50
  unpin_workers: 20
  metadata_workers: 30
  
  # Timeouts
  client_timeout: "30s"
  backend_timeout: "5m"
  
  # Limits
  max_object_size: "5TB"
  max_multipart_parts: 10000
  max_concurrent_requests: 10000
```

## Deployment Steps

### 1. Infrastructure Preparation

```bash
# Create system users
sudo useradd -r -s /bin/false versitygw
sudo useradd -r -s /bin/false ipfs

# Create directories
sudo mkdir -p /opt/versitygw/{bin,config,logs,data}
sudo mkdir -p /opt/ipfs/{data,config}
sudo mkdir -p /var/log/versitygw

# Set permissions
sudo chown -R versitygw:versitygw /opt/versitygw
sudo chown -R ipfs:ipfs /opt/ipfs
sudo chown versitygw:versitygw /var/log/versitygw
```

### 2. Service Configuration

**Systemd Service for VersityGW (`/etc/systemd/system/versitygw.service`):**

```ini
[Unit]
Description=VersityGW S3 Gateway with IPFS Backend
After=network.target
Wants=network.target

[Service]
Type=simple
User=versitygw
Group=versitygw
ExecStart=/opt/versitygw/bin/versitygw -config /etc/versitygw/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
LimitNOFILE=65536
LimitNPROC=32768

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/versitygw /var/log/versitygw

[Install]
WantedBy=multi-user.target
```

**Systemd Service for IPFS-Cluster (`/etc/systemd/system/ipfs-cluster.service`):**

```ini
[Unit]
Description=IPFS Cluster Service
After=network.target ipfs.target
Wants=network.target ipfs.target

[Service]
Type=simple
User=ipfs
Group=ipfs
ExecStart=/usr/local/bin/ipfs-cluster-service daemon
ExecStop=/usr/local/bin/ipfs-cluster-ctl shutdown
Restart=always
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### 3. SSL/TLS Setup

```bash
# Generate SSL certificates (or use existing ones)
sudo mkdir -p /etc/versitygw/certs

# Self-signed certificate (for testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/versitygw/certs/server.key \
  -out /etc/versitygw/certs/server.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=versitygw.example.com"

# Set permissions
sudo chown versitygw:versitygw /etc/versitygw/certs/*
sudo chmod 600 /etc/versitygw/certs/server.key
sudo chmod 644 /etc/versitygw/certs/server.crt
```

### 4. Database Schema Setup

```bash
# Create YDB tables for metadata
ydb -e grpc://ydb-node-1:2136 -d /Root/versity scripting yql -f - <<EOF
CREATE TABLE object_mappings (
    s3_key Utf8,
    bucket Utf8,
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
);

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
);

CREATE TABLE bucket_metadata (
    bucket Utf8,
    created_at Timestamp,
    object_count Uint64,
    total_size Uint64,
    metadata Json,
    PRIMARY KEY (bucket)
);
EOF
```

### 5. Load Balancer Configuration

**HAProxy Configuration (`/etc/haproxy/haproxy.cfg`):**

```conf
global
    daemon
    maxconn 4096
    log stdout local0

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    option httplog

frontend versitygw_frontend
    bind *:443 ssl crt /etc/ssl/certs/versitygw.pem
    bind *:80
    redirect scheme https if !{ ssl_fc }
    default_backend versitygw_backend

backend versitygw_backend
    balance roundrobin
    option httpchk GET /health
    server versitygw1 versitygw-node-1:8080 check
    server versitygw2 versitygw-node-2:8080 check
    server versitygw3 versitygw-node-3:8080 check
```

## Monitoring Setup

### 1. Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'versitygw'
    static_configs:
      - targets: ['versitygw-node-1:9090', 'versitygw-node-2:9090', 'versitygw-node-3:9090']
  
  - job_name: 'ipfs-cluster'
    static_configs:
      - targets: ['cluster-node-1:8888', 'cluster-node-2:8888', 'cluster-node-3:8888']
  
  - job_name: 'ipfs'
    static_configs:
      - targets: ['ipfs-node-1:5001', 'ipfs-node-2:5001', 'ipfs-node-3:5001']
```

### 2. Grafana Dashboards

Import the provided Grafana dashboard JSON files:
- `grafana-dashboard-versitygw-ipfs.json`
- `grafana-dashboard-ipfs-cluster.json`

## Security Hardening

### 1. Network Security

```bash
# Configure firewall rules
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 8080/tcp  # VersityGW
sudo ufw allow 9094/tcp  # IPFS-Cluster API
sudo ufw allow 4001/tcp  # IPFS Swarm
sudo ufw enable
```

### 2. System Security

```bash
# Disable unnecessary services
sudo systemctl disable apache2
sudo systemctl disable nginx
sudo systemctl disable mysql

# Configure log rotation
sudo vim /etc/logrotate.d/versitygw
```

**Log Rotation Configuration:**

```conf
/var/log/versitygw/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 versitygw versitygw
    postrotate
        systemctl reload versitygw
    endscript
}
```

## Performance Tuning

### 1. System Tuning

```bash
# Increase file descriptor limits
echo "versitygw soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "versitygw hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize network settings
echo "net.core.rmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_rmem = 4096 87380 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_wmem = 4096 65536 134217728" | sudo tee -a /etc/sysctl.conf

sudo sysctl -p
```

### 2. Application Tuning

Monitor and adjust these parameters based on your workload:

- `max_concurrent_pins`: Increase for higher throughput
- `pin_workers`: Scale with CPU cores
- `cache.memory.max_size`: Increase with available RAM
- `chunk_size`: Optimize for your object sizes

## Backup and Recovery

### 1. Metadata Backup

```bash
#!/bin/bash
# backup-metadata.sh

BACKUP_DIR="/opt/backups/versitygw"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR/$DATE"

# Backup YDB data
ydb -e grpc://ydb-node-1:2136 -d /Root/versity export s3 \
  --s3-endpoint http://backup-s3:9000 \
  --s3-bucket versitygw-backups \
  --s3-prefix "metadata/$DATE/"

# Backup configuration
cp -r /etc/versitygw "$BACKUP_DIR/$DATE/"

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -type d -mtime +30 -exec rm -rf {} \;
```

### 2. Disaster Recovery

```bash
#!/bin/bash
# restore-metadata.sh

BACKUP_DATE=$1
BACKUP_DIR="/opt/backups/versitygw"

if [ -z "$BACKUP_DATE" ]; then
    echo "Usage: $0 <backup_date>"
    exit 1
fi

# Stop services
sudo systemctl stop versitygw

# Restore YDB data
ydb -e grpc://ydb-node-1:2136 -d /Root/versity import s3 \
  --s3-endpoint http://backup-s3:9000 \
  --s3-bucket versitygw-backups \
  --s3-prefix "metadata/$BACKUP_DATE/"

# Restore configuration
sudo cp -r "$BACKUP_DIR/$BACKUP_DATE/versitygw" /etc/

# Start services
sudo systemctl start versitygw
```

## Maintenance Procedures

### 1. Rolling Updates

```bash
#!/bin/bash
# rolling-update.sh

NODES=("versitygw-node-1" "versitygw-node-2" "versitygw-node-3")
NEW_VERSION=$1

for node in "${NODES[@]}"; do
    echo "Updating $node..."
    
    # Drain traffic from node
    ssh "$node" "sudo systemctl stop versitygw"
    
    # Update binary
    scp versitygw-"$NEW_VERSION" "$node":/opt/versitygw/bin/versitygw
    
    # Start service
    ssh "$node" "sudo systemctl start versitygw"
    
    # Wait for health check
    sleep 30
    
    # Verify node is healthy
    curl -f "http://$node:8080/health" || exit 1
    
    echo "$node updated successfully"
done
```

### 2. Cluster Maintenance

```bash
# Check cluster health
ipfs-cluster-ctl peers ls
ipfs-cluster-ctl status

# Rebalance pins
ipfs-cluster-ctl pin ls --filter replication-factor-min=1

# Clean up failed pins
ipfs-cluster-ctl recover
```

This deployment guide provides comprehensive instructions for setting up a production-ready VersityGW with IPFS-Cluster backend, including all necessary infrastructure components, security measures, and operational procedures.