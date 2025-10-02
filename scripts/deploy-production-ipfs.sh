#!/bin/bash

# Production Deployment Script for VersityGW IPFS-Cluster Integration
# Copyright 2023 Versity Software
# Licensed under the Apache License, Version 2.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-production}"
CONFIG_DIR="${CONFIG_DIR:-/etc/versitygw}"
DATA_DIR="${DATA_DIR:-/var/lib/versitygw}"
LOG_DIR="${LOG_DIR:-/var/log/versitygw}"
SERVICE_USER="${SERVICE_USER:-versitygw}"
SERVICE_GROUP="${SERVICE_GROUP:-versitygw}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Error handling
error_exit() {
    log_error "$1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root for production deployment"
    fi
}

# Validate environment
validate_environment() {
    log_info "Validating deployment environment..."
    
    # Check required commands
    local required_commands=("docker" "docker-compose" "systemctl" "openssl" "curl" "jq")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error_exit "Required command not found: $cmd"
        fi
    done
    
    # Check system resources
    local min_memory_gb=8
    local available_memory_gb=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $available_memory_gb -lt $min_memory_gb ]]; then
        log_warning "Available memory ($available_memory_gb GB) is less than recommended ($min_memory_gb GB)"
    fi
    
    # Check disk space
    local min_disk_gb=100
    local available_disk_gb=$(df -BG "$DATA_DIR" 2>/dev/null | awk 'NR==2{gsub(/G/,"",$4); print $4}' || echo "0")
    if [[ $available_disk_gb -lt $min_disk_gb ]]; then
        log_warning "Available disk space ($available_disk_gb GB) is less than recommended ($min_disk_gb GB)"
    fi
    
    log_success "Environment validation completed"
}

# Create system user and directories
setup_system() {
    log_info "Setting up system user and directories..."
    
    # Create service user
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd --system --home-dir "$DATA_DIR" --shell /bin/false "$SERVICE_USER"
        log_success "Created service user: $SERVICE_USER"
    fi
    
    # Create directories
    local directories=("$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR" "$DATA_DIR/metadata" "$DATA_DIR/cache" "$DATA_DIR/pins")
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        chown "$SERVICE_USER:$SERVICE_GROUP" "$dir"
        chmod 750 "$dir"
    done
    
    log_success "System setup completed"
}

# Generate SSL certificates
generate_certificates() {
    log_info "Generating SSL certificates..."
    
    local cert_dir="$CONFIG_DIR/certs"
    mkdir -p "$cert_dir"
    
    if [[ ! -f "$cert_dir/server.crt" ]]; then
        # Generate private key
        openssl genrsa -out "$cert_dir/server.key" 4096
        
        # Generate certificate signing request
        openssl req -new -key "$cert_dir/server.key" -out "$cert_dir/server.csr" \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=versitygw"
        
        # Generate self-signed certificate (replace with proper CA-signed cert in production)
        openssl x509 -req -days 365 -in "$cert_dir/server.csr" \
            -signkey "$cert_dir/server.key" -out "$cert_dir/server.crt"
        
        # Set permissions
        chown -R "$SERVICE_USER:$SERVICE_GROUP" "$cert_dir"
        chmod 600 "$cert_dir/server.key"
        chmod 644 "$cert_dir/server.crt"
        
        log_success "SSL certificates generated"
    else
        log_info "SSL certificates already exist"
    fi
}

# Deploy IPFS Cluster
deploy_ipfs_cluster() {
    log_info "Deploying IPFS Cluster..."
    
    # Create IPFS Cluster configuration
    cat > "$CONFIG_DIR/ipfs-cluster-compose.yml" << 'EOF'
version: '3.8'

services:
  ipfs-cluster-0:
    image: ipfs/ipfs-cluster:latest
    container_name: ipfs-cluster-0
    environment:
      CLUSTER_PEERNAME: cluster0
      CLUSTER_SECRET: ${CLUSTER_SECRET}
      CLUSTER_IPFSHTTP_NODEMULTIADDRESS: /dns4/ipfs-0/tcp/5001
      CLUSTER_CRDT_TRUSTEDPEERS: '*'
      CLUSTER_RESTAPI_HTTPLISTENMULTIADDRESS: /ip4/0.0.0.0/tcp/9094
      CLUSTER_MONITORPINGINTERVAL: 2s
      CLUSTER_CRDT_REBROADCASTINTERVAL: 5s
    ports:
      - "9094:9094"
      - "9095:9095"
      - "9096:9096"
    volumes:
      - cluster0_data:/data/ipfs-cluster
    depends_on:
      - ipfs-0
    networks:
      - ipfs-cluster-net

  ipfs-cluster-1:
    image: ipfs/ipfs-cluster:latest
    container_name: ipfs-cluster-1
    environment:
      CLUSTER_PEERNAME: cluster1
      CLUSTER_SECRET: ${CLUSTER_SECRET}
      CLUSTER_IPFSHTTP_NODEMULTIADDRESS: /dns4/ipfs-1/tcp/5001
      CLUSTER_CRDT_TRUSTEDPEERS: '*'
      CLUSTER_RESTAPI_HTTPLISTENMULTIADDRESS: /ip4/0.0.0.0/tcp/9094
      CLUSTER_MONITORPINGINTERVAL: 2s
      CLUSTER_CRDT_REBROADCASTINTERVAL: 5s
    ports:
      - "9097:9094"
      - "9098:9095"
      - "9099:9096"
    volumes:
      - cluster1_data:/data/ipfs-cluster
    depends_on:
      - ipfs-1
    networks:
      - ipfs-cluster-net

  ipfs-cluster-2:
    image: ipfs/ipfs-cluster:latest
    container_name: ipfs-cluster-2
    environment:
      CLUSTER_PEERNAME: cluster2
      CLUSTER_SECRET: ${CLUSTER_SECRET}
      CLUSTER_IPFSHTTP_NODEMULTIADDRESS: /dns4/ipfs-2/tcp/5001
      CLUSTER_CRDT_TRUSTEDPEERS: '*'
      CLUSTER_RESTAPI_HTTPLISTENMULTIADDRESS: /ip4/0.0.0.0/tcp/9094
      CLUSTER_MONITORPINGINTERVAL: 2s
      CLUSTER_CRDT_REBROADCASTINTERVAL: 5s
    ports:
      - "9100:9094"
      - "9101:9095"
      - "9102:9096"
    volumes:
      - cluster2_data:/data/ipfs-cluster
    depends_on:
      - ipfs-2
    networks:
      - ipfs-cluster-net

  ipfs-0:
    image: ipfs/kubo:latest
    container_name: ipfs-0
    environment:
      IPFS_PROFILE: server
    ports:
      - "4001:4001"
      - "5001:5001"
      - "8080:8080"
    volumes:
      - ipfs0_data:/data/ipfs
      - ipfs0_staging:/export
    networks:
      - ipfs-cluster-net

  ipfs-1:
    image: ipfs/kubo:latest
    container_name: ipfs-1
    environment:
      IPFS_PROFILE: server
    ports:
      - "4002:4001"
      - "5002:5001"
      - "8081:8080"
    volumes:
      - ipfs1_data:/data/ipfs
      - ipfs1_staging:/export
    networks:
      - ipfs-cluster-net

  ipfs-2:
    image: ipfs/kubo:latest
    container_name: ipfs-2
    environment:
      IPFS_PROFILE: server
    ports:
      - "4003:4001"
      - "5003:5001"
      - "8082:8080"
    volumes:
      - ipfs2_data:/data/ipfs
      - ipfs2_staging:/export
    networks:
      - ipfs-cluster-net

  # YDB for metadata storage
  ydb:
    image: cr.yandex/yc/yandex-docker-local-ydb:latest
    container_name: ydb-metadata
    hostname: ydb-metadata
    environment:
      YDB_DEFAULT_LOG_LEVEL: NOTICE
      GRPC_TLS_PORT: 2135
      GRPC_PORT: 2136
      MON_PORT: 8765
    ports:
      - "2135:2135"
      - "2136:2136"
      - "8765:8765"
    volumes:
      - ydb_data:/ydb_data
    networks:
      - ipfs-cluster-net

  # Redis Cluster for caching
  redis-0:
    image: redis:7-alpine
    container_name: redis-0
    command: redis-server --cluster-enabled yes --cluster-config-file nodes.conf --cluster-node-timeout 5000 --appendonly yes
    ports:
      - "6379:6379"
    volumes:
      - redis0_data:/data
    networks:
      - ipfs-cluster-net

  redis-1:
    image: redis:7-alpine
    container_name: redis-1
    command: redis-server --cluster-enabled yes --cluster-config-file nodes.conf --cluster-node-timeout 5000 --appendonly yes
    ports:
      - "6380:6379"
    volumes:
      - redis1_data:/data
    networks:
      - ipfs-cluster-net

  redis-2:
    image: redis:7-alpine
    container_name: redis-2
    command: redis-server --cluster-enabled yes --cluster-config-file nodes.conf --cluster-node-timeout 5000 --appendonly yes
    ports:
      - "6381:6379"
    volumes:
      - redis2_data:/data
    networks:
      - ipfs-cluster-net

  # Monitoring stack
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    networks:
      - ipfs-cluster-net

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_PASSWORD:-admin}
    volumes:
      - grafana_data:/var/lib/grafana
    networks:
      - ipfs-cluster-net

volumes:
  cluster0_data:
  cluster1_data:
  cluster2_data:
  ipfs0_data:
  ipfs1_data:
  ipfs2_data:
  ipfs0_staging:
  ipfs1_staging:
  ipfs2_staging:
  ydb_data:
  redis0_data:
  redis1_data:
  redis2_data:
  prometheus_data:
  grafana_data:

networks:
  ipfs-cluster-net:
    driver: bridge
EOF

    # Generate cluster secret
    local cluster_secret
    cluster_secret=$(openssl rand -hex 32)
    
    # Create environment file
    cat > "$CONFIG_DIR/.env" << EOF
CLUSTER_SECRET=$cluster_secret
GRAFANA_PASSWORD=$(openssl rand -base64 32)
EOF
    
    chmod 600 "$CONFIG_DIR/.env"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/.env"
    
    log_success "IPFS Cluster configuration created"
}

# Create VersityGW configuration
create_versitygw_config() {
    log_info "Creating VersityGW configuration..."
    
    cat > "$CONFIG_DIR/versitygw.yaml" << EOF
# VersityGW Production Configuration with IPFS Backend

# Server configuration
server:
  address: "0.0.0.0:8080"
  tls:
    enabled: true
    cert_file: "$CONFIG_DIR/certs/server.crt"
    key_file: "$CONFIG_DIR/certs/server.key"
  
# Backend configuration
backend:
  type: "ipfs"
  ipfs:
    # IPFS Cluster endpoints
    cluster_endpoints:
      - "http://localhost:9094"
      - "http://localhost:9097"
      - "http://localhost:9100"
    
    # Connection settings
    connect_timeout: "30s"
    request_timeout: "2m"
    max_retries: 5
    retry_delay: "2s"
    
    # Pin management
    max_concurrent_pins: 1000
    pin_timeout: "10m"
    replication_min: 2
    replication_max: 5
    
    # Data handling
    chunk_size: 4194304  # 4MB
    compression_enabled: true
    
    # Metadata storage
    metadata_db:
      type: "ydb"
      endpoints:
        - "localhost:2136"
      database: "/local"
      table_prefix: "versitygw_"
      connection_timeout: "10s"
      query_timeout: "30s"
      max_connections: 100
    
    # Caching
    cache:
      enabled: true
      type: "redis_cluster"
      endpoints:
        - "localhost:6379"
        - "localhost:6380"
        - "localhost:6381"
      ttl: "1h"
      max_memory: "1GB"
      eviction_policy: "allkeys-lru"
    
    # Security
    security:
      enabled: true
      encryption_enabled: true
      audit_logging_enabled: true
      rate_limiting:
        enabled: true
        requests_per_second: 1000
        burst_size: 2000
    
    # Monitoring
    metrics:
      enabled: true
      endpoint: "/metrics"
      interval: "10s"
    
    # Health checks
    health_check:
      enabled: true
      interval: "30s"
      timeout: "10s"
    
    # Replica management
    replica_manager:
      enabled: true
      analysis_interval: "5m"
      rebalance_interval: "1h"
      min_access_count: 10
      geographic_optimization: true

# IAM configuration
iam:
  type: "internal"
  admin_user: "admin"
  admin_password_hash: "\$2a\$10\$..."  # bcrypt hash
  
# Logging
logging:
  level: "info"
  format: "json"
  output: "$LOG_DIR/versitygw.log"
  max_size: "100MB"
  max_backups: 10
  max_age: 30
  compress: true
  
  # Audit logging
  audit:
    enabled: true
    output: "$LOG_DIR/audit.log"
    max_size: "100MB"
    max_backups: 30
    max_age: 90

# Performance tuning
performance:
  max_concurrent_requests: 10000
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "60s"
  max_header_bytes: 1048576  # 1MB
  
  # Connection pooling
  connection_pool:
    max_idle_conns: 100
    max_idle_conns_per_host: 10
    idle_conn_timeout: "90s"
EOF

    chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/versitygw.yaml"
    chmod 640 "$CONFIG_DIR/versitygw.yaml"
    
    log_success "VersityGW configuration created"
}

# Create systemd service
create_systemd_service() {
    log_info "Creating systemd service..."
    
    cat > "/etc/systemd/system/versitygw.service" << EOF
[Unit]
Description=VersityGW S3 Gateway with IPFS Backend
Documentation=https://github.com/versity/versitygw
After=network.target docker.service
Requires=docker.service
StartLimitIntervalSec=0

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
ExecStart=/usr/local/bin/versitygw --config $CONFIG_DIR/versitygw.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=versitygw

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Environment
Environment=GOMAXPROCS=4
EnvironmentFile=-$CONFIG_DIR/.env

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service created"
}

# Build and install VersityGW
build_and_install() {
    log_info "Building and installing VersityGW..."
    
    cd "$PROJECT_ROOT"
    
    # Build the binary
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o versitygw ./cmd/versitygw
    
    # Install binary
    install -m 755 versitygw /usr/local/bin/versitygw
    
    # Create symlink for backward compatibility
    ln -sf /usr/local/bin/versitygw /usr/local/bin/versity-gw
    
    log_success "VersityGW built and installed"
}

# Start services
start_services() {
    log_info "Starting services..."
    
    # Start IPFS Cluster
    cd "$CONFIG_DIR"
    docker-compose -f ipfs-cluster-compose.yml up -d
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 30
    
    # Initialize Redis Cluster
    docker exec redis-0 redis-cli --cluster create \
        127.0.0.1:6379 127.0.0.1:6380 127.0.0.1:6381 \
        --cluster-replicas 0 --cluster-yes || true
    
    # Start VersityGW
    systemctl enable versitygw
    systemctl start versitygw
    
    log_success "Services started"
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check IPFS Cluster
    local cluster_health
    cluster_health=$(curl -s http://localhost:9094/health || echo "FAILED")
    if [[ "$cluster_health" == *"FAILED"* ]]; then
        log_warning "IPFS Cluster health check failed"
    else
        log_success "IPFS Cluster is healthy"
    fi
    
    # Check VersityGW
    local versitygw_status
    versitygw_status=$(systemctl is-active versitygw)
    if [[ "$versitygw_status" == "active" ]]; then
        log_success "VersityGW service is running"
    else
        log_error "VersityGW service is not running: $versitygw_status"
    fi
    
    # Check API endpoint
    local api_response
    api_response=$(curl -s -k https://localhost:8080/health || echo "FAILED")
    if [[ "$api_response" == *"FAILED"* ]]; then
        log_warning "VersityGW API health check failed"
    else
        log_success "VersityGW API is responding"
    fi
    
    log_success "Deployment verification completed"
}

# Create monitoring configuration
setup_monitoring() {
    log_info "Setting up monitoring..."
    
    cat > "$CONFIG_DIR/prometheus.yml" << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'versitygw'
    static_configs:
      - targets: ['host.docker.internal:8080']
    metrics_path: '/metrics'
    scheme: 'https'
    tls_config:
      insecure_skip_verify: true

  - job_name: 'ipfs-cluster'
    static_configs:
      - targets: ['ipfs-cluster-0:9095', 'ipfs-cluster-1:9095', 'ipfs-cluster-2:9095']

  - job_name: 'ipfs'
    static_configs:
      - targets: ['ipfs-0:5001', 'ipfs-1:5001', 'ipfs-2:5001']
    metrics_path: '/debug/metrics/prometheus'
EOF

    log_success "Monitoring configuration created"
}

# Create backup script
create_backup_script() {
    log_info "Creating backup script..."
    
    cat > "/usr/local/bin/versitygw-backup.sh" << 'EOF'
#!/bin/bash

# VersityGW Backup Script
set -euo pipefail

BACKUP_DIR="/var/backups/versitygw"
DATE=$(date +%Y%m%d_%H%M%S)
CONFIG_DIR="/etc/versitygw"
DATA_DIR="/var/lib/versitygw"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup configuration
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" -C "$CONFIG_DIR" .

# Backup metadata (YDB)
docker exec ydb-metadata ydb -e grpc://localhost:2136 -d /local scheme export --format proto > "$BACKUP_DIR/metadata_schema_$DATE.proto"

# Backup Redis data
for i in {0..2}; do
    docker exec "redis-$i" redis-cli BGSAVE
    docker cp "redis-$i:/data/dump.rdb" "$BACKUP_DIR/redis_${i}_$DATE.rdb"
done

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.tar.gz" -o -name "*.proto" -o -name "*.rdb" | head -n -90 | xargs rm -f

echo "Backup completed: $DATE"
EOF

    chmod +x /usr/local/bin/versitygw-backup.sh
    
    # Create cron job for daily backups
    cat > "/etc/cron.d/versitygw-backup" << 'EOF'
# Daily backup at 2 AM
0 2 * * * root /usr/local/bin/versitygw-backup.sh >> /var/log/versitygw/backup.log 2>&1
EOF

    log_success "Backup script created"
}

# Print deployment summary
print_summary() {
    log_info "Deployment Summary"
    echo "===================="
    echo "VersityGW with IPFS Backend has been deployed successfully!"
    echo ""
    echo "Services:"
    echo "  - VersityGW S3 API: https://localhost:8080"
    echo "  - IPFS Cluster API: http://localhost:9094, 9097, 9100"
    echo "  - IPFS Gateway: http://localhost:8080, 8081, 8082"
    echo "  - YDB Console: http://localhost:8765"
    echo "  - Prometheus: http://localhost:9090"
    echo "  - Grafana: http://localhost:3000"
    echo ""
    echo "Configuration:"
    echo "  - Config directory: $CONFIG_DIR"
    echo "  - Data directory: $DATA_DIR"
    echo "  - Log directory: $LOG_DIR"
    echo ""
    echo "Management:"
    echo "  - Service control: systemctl {start|stop|restart|status} versitygw"
    echo "  - Logs: journalctl -u versitygw -f"
    echo "  - Backup: /usr/local/bin/versitygw-backup.sh"
    echo ""
    echo "Next steps:"
    echo "  1. Configure your S3 client to use https://localhost:8080"
    echo "  2. Set up monitoring dashboards in Grafana"
    echo "  3. Configure proper SSL certificates for production"
    echo "  4. Review and adjust configuration as needed"
    echo ""
    log_success "Deployment completed successfully!"
}

# Main deployment function
main() {
    log_info "Starting VersityGW IPFS production deployment..."
    
    check_root
    validate_environment
    setup_system
    generate_certificates
    deploy_ipfs_cluster
    create_versitygw_config
    create_systemd_service
    build_and_install
    setup_monitoring
    create_backup_script
    start_services
    verify_deployment
    print_summary
}

# Run main function
main "$@"