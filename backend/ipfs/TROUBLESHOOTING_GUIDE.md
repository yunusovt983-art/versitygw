# IPFS Backend Troubleshooting Guide

## Overview

This guide provides comprehensive troubleshooting procedures for common issues encountered when running VersityGW with IPFS-Cluster backend. It includes diagnostic steps, common solutions, and preventive measures.

## Quick Diagnostic Commands

### System Health Check

```bash
#!/bin/bash
# health-check.sh - Quick system health verification

echo "=== VersityGW IPFS Backend Health Check ==="

# Check VersityGW service
echo "1. VersityGW Service Status:"
systemctl status versitygw
curl -f http://localhost:8080/health || echo "VersityGW health check failed"

# Check IPFS-Cluster
echo -e "\n2. IPFS-Cluster Status:"
ipfs-cluster-ctl peers ls
ipfs-cluster-ctl status

# Check IPFS nodes
echo -e "\n3. IPFS Node Status:"
ipfs swarm peers | wc -l
ipfs repo stat

# Check metadata database
echo -e "\n4. Metadata Database:"
case "$METADATA_DB_TYPE" in
    "ydb")
        ydb -e "$YDB_ENDPOINT" -d "$YDB_DATABASE" scheme ls
        ;;
    "postgres")
        psql "$POSTGRES_CONNECTION" -c "SELECT COUNT(*) FROM object_mappings;"
        ;;
esac

# Check cache
echo -e "\n5. Cache Status:"
redis-cli ping
redis-cli info memory

echo -e "\n=== Health Check Complete ==="
```

## Common Issues and Solutions

### 1. Pin Operation Failures

#### Symptoms
- Objects uploaded but not accessible
- Pin timeout errors in logs
- High pin failure rate

#### Diagnostic Steps

```bash
# Check pin status
ipfs-cluster-ctl status <CID>

# Check cluster connectivity
ipfs-cluster-ctl peers ls

# Check IPFS node connectivity
ipfs swarm peers

# Check pin queue status
curl http://localhost:8081/admin/pins/queue

# Check logs for pin errors
journalctl -u versitygw -f | grep -i "pin.*error"
```

#### Common Causes and Solutions

**Cause: IPFS-Cluster nodes unreachable**
```bash
# Solution: Check network connectivity
ping cluster-node-1
telnet cluster-node-1 9094

# Verify cluster configuration
cat ~/.ipfs-cluster/service.json | jq '.cluster.listen_multiaddress'

# Restart cluster service if needed
systemctl restart ipfs-cluster
```

**Cause: Insufficient cluster resources**
```bash
# Check cluster resource usage
ipfs-cluster-ctl status --filter pinned | wc -l
df -h /ipfs/data

# Solution: Add more cluster nodes or increase storage
# Add new cluster node:
ipfs-cluster-service init --consensus crdt
ipfs-cluster-service daemon
```

**Cause: Pin timeout too low**
```yaml
# Solution: Increase timeout in config
backend:
  ipfs:
    pin_timeout: "5m"  # Increase from default 2m
    max_concurrent_pins: 50  # Reduce concurrency if needed
```

### 2. Metadata Store Issues

#### Symptoms
- S3 operations fail with "mapping not found"
- Slow response times
- Database connection errors

#### Diagnostic Steps

```bash
# Check database connectivity
case "$METADATA_DB_TYPE" in
    "ydb")
        ydb -e "$YDB_ENDPOINT" -d "$YDB_DATABASE" scheme ls
        ;;
    "postgres")
        pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT"
        ;;
    "scylla")
        cqlsh "$SCYLLA_HOST" -e "DESCRIBE KEYSPACES;"
        ;;
esac

# Check table statistics
curl http://localhost:8081/admin/metadata/stats

# Check for corrupted mappings
curl http://localhost:8081/admin/metadata/validate
```

#### Common Solutions

**Database Connection Issues**
```bash
# Check connection pool settings
curl http://localhost:8081/admin/metadata/pool-stats

# Increase connection pool size
# In config.yaml:
metadata_db:
  max_connections: 200  # Increase from default
  connection_timeout: "30s"
```

**Slow Query Performance**
```sql
-- For PostgreSQL, add indexes
CREATE INDEX CONCURRENTLY idx_object_mappings_bucket_key 
ON object_mappings(bucket, s3_key);

CREATE INDEX CONCURRENTLY idx_object_mappings_cid 
ON object_mappings(cid);

CREATE INDEX CONCURRENTLY idx_object_mappings_accessed_at 
ON object_mappings(accessed_at DESC);
```

**Metadata Corruption**
```bash
# Run metadata validation
curl -X POST http://localhost:8081/admin/metadata/validate

# Repair corrupted entries
curl -X POST http://localhost:8081/admin/metadata/repair

# If severe corruption, restore from backup
./restore-metadata.sh 20240101_120000
```

### 3. Cache Performance Issues

#### Symptoms
- High cache miss rates
- Slow object retrieval
- Memory usage warnings

#### Diagnostic Steps

```bash
# Check cache statistics
curl http://localhost:8081/admin/cache/stats

# Check Redis cluster health
redis-cli cluster info
redis-cli cluster nodes

# Monitor cache hit rates
watch -n 5 'curl -s http://localhost:8081/admin/cache/stats | jq ".hit_rate"'
```

#### Solutions

**Low Cache Hit Rate**
```yaml
# Increase cache sizes and TTL
cache:
  memory:
    max_size: "4GB"  # Increase memory cache
    ttl: "2h"        # Increase TTL
  
  redis:
    ttl: "48h"       # Increase Redis TTL
    
  policies:
    metadata_ttl: "2h"      # Increase metadata TTL
    pin_status_ttl: "10m"   # Increase pin status TTL
```

**Redis Connection Issues**
```bash
# Check Redis cluster status
redis-cli --cluster check redis-node-1:7000

# Fix cluster issues
redis-cli --cluster fix redis-node-1:7000

# Restart Redis cluster if needed
systemctl restart redis-cluster
```

**Memory Pressure**
```bash
# Check memory usage
free -h
cat /proc/meminfo | grep -E "(MemTotal|MemAvailable|Cached)"

# Adjust cache eviction policy
redis-cli config set maxmemory-policy allkeys-lru
```

### 4. Network and Connectivity Issues

#### Symptoms
- Intermittent connection failures
- High latency operations
- Cluster split-brain scenarios

#### Diagnostic Steps

```bash
# Check network connectivity between nodes
for node in cluster-node-{1..3}; do
    echo "Testing $node:"
    ping -c 3 $node
    nc -zv $node 9094
    nc -zv $node 4001
done

# Check IPFS swarm connectivity
ipfs swarm peers | head -10
ipfs stats bw

# Check cluster consensus
ipfs-cluster-ctl peers ls
```

#### Solutions

**Network Partitions**
```bash
# Check for split-brain
ipfs-cluster-ctl peers ls | grep -c "trusted"

# Force cluster recovery
ipfs-cluster-ctl recover --local

# If severe, restart cluster with state recovery
systemctl stop ipfs-cluster
ipfs-cluster-service state cleanup
systemctl start ipfs-cluster
```

**High Latency**
```bash
# Check network latency between nodes
for node in cluster-node-{1..3}; do
    echo "$node latency:"
    ping -c 10 $node | tail -1
done

# Optimize network settings
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
sysctl -p
```

### 5. Performance Degradation

#### Symptoms
- Slow S3 operations
- High CPU/memory usage
- Queue backlog buildup

#### Diagnostic Steps

```bash
# Check system resources
top -p $(pgrep versitygw)
iostat -x 1 5
sar -u 1 5

# Check operation queues
curl http://localhost:8081/admin/queues/status

# Check worker utilization
curl http://localhost:8081/admin/workers/stats
```

#### Solutions

**High CPU Usage**
```yaml
# Reduce worker concurrency
performance:
  pin_workers: 20      # Reduce from higher values
  unpin_workers: 10
  metadata_workers: 15
  max_concurrent_requests: 1000
```

**Memory Issues**
```bash
# Check for memory leaks
pmap -x $(pgrep versitygw)

# Adjust garbage collection
export GOGC=100  # Default Go GC target
export GOMEMLIMIT=8GiB  # Set memory limit
```

**Queue Backlog**
```bash
# Check queue sizes
curl http://localhost:8081/admin/queues/status

# Increase worker pools temporarily
curl -X POST http://localhost:8081/admin/workers/scale \
  -d '{"pin_workers": 50, "unpin_workers": 25}'

# Process queue manually if needed
curl -X POST http://localhost:8081/admin/queues/process
```

## Error Code Reference

### IPFS-Specific Error Codes

| Error Code | Description | Common Causes | Solutions |
|------------|-------------|---------------|-----------|
| `IPFSNodeUnavailable` | IPFS cluster node unreachable | Network issues, node down | Check connectivity, restart node |
| `PinTimeout` | Pin operation timed out | Large object, slow network | Increase timeout, check resources |
| `InsufficientReplicas` | Cannot achieve replication factor | Not enough nodes, storage full | Add nodes, free storage |
| `CIDNotFound` | IPFS CID not found in cluster | Object not pinned, node failure | Check pin status, recover pins |
| `ClusterSplit` | Cluster in split-brain state | Network partition | Force consensus, restart cluster |
| `MetadataCorruption` | Metadata store corruption | Database issues, power failure | Validate and repair metadata |
| `CacheTimeout` | Cache operation timeout | Cache overload, network issues | Scale cache, check connectivity |

### Log Analysis

#### Common Log Patterns

**Pin Operation Failures**
```bash
# Search for pin failures
journalctl -u versitygw | grep -E "pin.*failed|pin.*error|pin.*timeout"

# Example error patterns:
# "pin operation failed: context deadline exceeded"
# "pin error: insufficient replicas available"
# "pin timeout: operation took longer than 2m0s"
```

**Metadata Issues**
```bash
# Search for metadata errors
journalctl -u versitygw | grep -E "metadata.*error|mapping.*not.*found"

# Example patterns:
# "metadata store error: connection refused"
# "mapping not found for key: bucket/object"
# "metadata validation failed: corrupted entry"
```

**Cache Problems**
```bash
# Search for cache issues
journalctl -u versitygw | grep -E "cache.*error|cache.*miss|redis.*error"

# Example patterns:
# "cache error: redis connection timeout"
# "high cache miss rate: 0.95"
# "cache eviction pressure detected"
```

## Monitoring and Alerting

### Key Metrics to Monitor

```yaml
# Prometheus alerting rules
groups:
- name: versitygw-ipfs
  rules:
  - alert: HighPinFailureRate
    expr: rate(ipfs_pin_failures_total[5m]) > 0.1
    for: 2m
    annotations:
      summary: "High pin failure rate detected"
      
  - alert: ClusterNodeDown
    expr: ipfs_cluster_nodes_available < 3
    for: 1m
    annotations:
      summary: "IPFS cluster node unavailable"
      
  - alert: MetadataStoreDown
    expr: up{job="metadata-store"} == 0
    for: 30s
    annotations:
      summary: "Metadata store unavailable"
      
  - alert: LowCacheHitRate
    expr: ipfs_cache_hit_rate < 0.7
    for: 5m
    annotations:
      summary: "Cache hit rate below threshold"
```

### Health Check Endpoints

```bash
# VersityGW health
curl http://localhost:8080/health

# Admin endpoints
curl http://localhost:8081/admin/health
curl http://localhost:8081/admin/metrics
curl http://localhost:8081/admin/status

# Component-specific health
curl http://localhost:8081/admin/ipfs/health
curl http://localhost:8081/admin/metadata/health
curl http://localhost:8081/admin/cache/health
```

## Recovery Procedures

### Emergency Recovery Steps

#### Complete System Recovery

```bash
#!/bin/bash
# emergency-recovery.sh

echo "Starting emergency recovery procedure..."

# 1. Stop all services
systemctl stop versitygw
systemctl stop ipfs-cluster
systemctl stop ipfs

# 2. Check filesystem integrity
fsck -f /dev/sdb1  # IPFS data partition
fsck -f /dev/sdc1  # Metadata partition

# 3. Restore from backup if needed
if [ "$RESTORE_FROM_BACKUP" = "true" ]; then
    ./restore-metadata.sh latest
    ./restore-ipfs-data.sh latest
fi

# 4. Start services in order
systemctl start ipfs
sleep 30
systemctl start ipfs-cluster
sleep 60
systemctl start versitygw

# 5. Verify recovery
./health-check.sh

echo "Emergency recovery complete"
```

#### Pin Recovery

```bash
#!/bin/bash
# recover-pins.sh

echo "Starting pin recovery..."

# Get list of objects without valid pins
curl -s http://localhost:8081/admin/pins/orphaned | jq -r '.[]' | while read cid; do
    echo "Recovering pin for CID: $cid"
    ipfs-cluster-ctl pin add "$cid"
done

# Verify pin recovery
ipfs-cluster-ctl status --filter error
ipfs-cluster-ctl recover

echo "Pin recovery complete"
```

## Performance Optimization

### Tuning Guidelines

#### System-Level Optimizations

```bash
# Increase file descriptor limits
echo "versitygw soft nofile 65536" >> /etc/security/limits.conf
echo "versitygw hard nofile 65536" >> /etc/security/limits.conf

# Optimize network settings
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 87380 134217728' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 65536 134217728' >> /etc/sysctl.conf
sysctl -p

# Optimize disk I/O
echo 'vm.dirty_ratio = 15' >> /etc/sysctl.conf
echo 'vm.dirty_background_ratio = 5' >> /etc/sysctl.conf
```

#### Application-Level Optimizations

```yaml
# Optimize worker pools based on workload
performance:
  # For write-heavy workloads
  pin_workers: 100
  unpin_workers: 25
  
  # For read-heavy workloads
  pin_workers: 25
  unpin_workers: 10
  metadata_workers: 50

# Optimize batch operations
batch_operations:
  enabled: true
  batch_size: 2000      # Increase for better throughput
  batch_timeout: "10s"  # Allow more time for batching

# Optimize caching
cache:
  memory:
    max_size: "8GB"     # Use more memory for cache
    ttl: "4h"           # Longer TTL for stable data
```

## Preventive Measures

### Regular Maintenance Tasks

```bash
#!/bin/bash
# maintenance.sh - Run weekly

# 1. Clean up old logs
find /var/log/versitygw -name "*.log" -mtime +30 -delete

# 2. Compact metadata database
case "$METADATA_DB_TYPE" in
    "postgres")
        psql "$POSTGRES_CONNECTION" -c "VACUUM ANALYZE object_mappings;"
        ;;
    "ydb")
        ydb -e "$YDB_ENDPOINT" -d "$YDB_DATABASE" table query execute \
            --query "PRAGMA TablePathPrefix('/Root/versity'); COMPACT TABLE object_mappings;"
        ;;
esac

# 3. Verify pin consistency
ipfs-cluster-ctl status --filter error
ipfs-cluster-ctl recover

# 4. Update cache statistics
curl -X POST http://localhost:8081/admin/cache/refresh-stats

# 5. Generate health report
./health-check.sh > "/var/log/versitygw/health-$(date +%Y%m%d).log"
```

### Monitoring Setup

```bash
# Set up log monitoring
tail -f /var/log/versitygw/versitygw.log | grep -E "(ERROR|WARN|FATAL)" | \
while read line; do
    echo "$line" | mail -s "VersityGW Alert" admin@company.com
done &

# Set up metric collection
curl -s http://localhost:8081/admin/metrics | \
prometheus-push-gateway --gateway=prometheus-gateway:9091 --job=versitygw
```

This troubleshooting guide provides comprehensive coverage of common issues and their solutions, enabling quick diagnosis and resolution of problems in production environments.