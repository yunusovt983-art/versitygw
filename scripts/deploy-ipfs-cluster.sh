#!/bin/bash

# Copyright 2023 Versity Software
# This file is licensed under the Apache License, Version 2.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-versitygw-ipfs}"
NAMESPACE="${NAMESPACE:-default}"
CLUSTER_SIZE="${CLUSTER_SIZE:-3}"
IPFS_CLUSTER_VERSION="${IPFS_CLUSTER_VERSION:-latest}"
VERSITYGW_VERSION="${VERSITYGW_VERSION:-latest}"

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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed. Please install kubectl first."
        exit 1
    fi
    
    # Check if helm is installed
    if ! command -v helm &> /dev/null; then
        log_error "helm is not installed. Please install helm first."
        exit 1
    fi
    
    # Check if docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "docker is not installed. Please install docker first."
        exit 1
    fi
    
    # Check kubectl connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster. Please check your kubectl configuration."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Create namespace if it doesn't exist
create_namespace() {
    log_info "Creating namespace: $NAMESPACE"
    
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_warning "Namespace $NAMESPACE already exists"
    else
        kubectl create namespace "$NAMESPACE"
        log_success "Namespace $NAMESPACE created"
    fi
}

# Deploy IPFS Cluster
deploy_ipfs_cluster() {
    log_info "Deploying IPFS Cluster with $CLUSTER_SIZE nodes..."
    
    # Create IPFS Cluster configuration
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: ipfs-cluster-config
  namespace: $NAMESPACE
data:
  service.json: |
    {
      "cluster": {
        "secret": "$(openssl rand -hex 32)",
        "leave_on_shutdown": false,
        "listen_multiaddress": "/ip4/0.0.0.0/tcp/9096",
        "state_sync_interval": "5m0s",
        "ipfs_sync_interval": "2m10s",
        "replication_factor_min": 1,
        "replication_factor_max": 3,
        "monitor_ping_interval": "15s"
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
          "unpin_timeout": "3h0m0s"
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
      "informer": {
        "disk": {
          "metric_ttl": "30s",
          "metric_type": "freespace"
        },
        "numpin": {
          "metric_ttl": "10s"
        }
      }
    }
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: ipfs-cluster
  namespace: $NAMESPACE
spec:
  serviceName: ipfs-cluster
  replicas: $CLUSTER_SIZE
  selector:
    matchLabels:
      app: ipfs-cluster
  template:
    metadata:
      labels:
        app: ipfs-cluster
    spec:
      containers:
      - name: ipfs
        image: ipfs/go-ipfs:latest
        ports:
        - containerPort: 4001
          name: swarm
        - containerPort: 5001
          name: api
        - containerPort: 8080
          name: gateway
        volumeMounts:
        - name: ipfs-data
          mountPath: /data/ipfs
        env:
        - name: IPFS_PROFILE
          value: server
      - name: ipfs-cluster
        image: ipfs/ipfs-cluster:$IPFS_CLUSTER_VERSION
        ports:
        - containerPort: 9094
          name: api
        - containerPort: 9095
          name: proxy
        - containerPort: 9096
          name: cluster
        volumeMounts:
        - name: cluster-config
          mountPath: /data/ipfs-cluster
        - name: cluster-data
          mountPath: /data/ipfs-cluster/data
        env:
        - name: CLUSTER_PEERNAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: CLUSTER_SECRET
          valueFrom:
            configMapKeyRef:
              name: ipfs-cluster-config
              key: service.json
      volumes:
      - name: cluster-config
        configMap:
          name: ipfs-cluster-config
  volumeClaimTemplates:
  - metadata:
      name: ipfs-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 100Gi
  - metadata:
      name: cluster-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
---
apiVersion: v1
kind: Service
metadata:
  name: ipfs-cluster-api
  namespace: $NAMESPACE
spec:
  selector:
    app: ipfs-cluster
  ports:
  - name: api
    port: 9094
    targetPort: 9094
  - name: proxy
    port: 9095
    targetPort: 9095
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: ipfs-cluster-headless
  namespace: $NAMESPACE
spec:
  selector:
    app: ipfs-cluster
  ports:
  - name: cluster
    port: 9096
    targetPort: 9096
  clusterIP: None
EOF

    log_success "IPFS Cluster deployed"
}

# Build VersityGW Docker image
build_versitygw_image() {
    log_info "Building VersityGW Docker image..."
    
    cd "$PROJECT_ROOT"
    
    # Create Dockerfile for VersityGW with IPFS support
    cat <<EOF > Dockerfile.ipfs
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o versitygw ./cmd/versitygw

FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/versitygw .

EXPOSE 7070 8080

CMD ["./versitygw", "ipfs", "--cluster-endpoints", "http://ipfs-cluster-api:9094"]
EOF

    docker build -f Dockerfile.ipfs -t "versitygw-ipfs:$VERSITYGW_VERSION" .
    
    log_success "VersityGW Docker image built"
}

# Deploy VersityGW
deploy_versitygw() {
    log_info "Deploying VersityGW with IPFS backend..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: versitygw-config
  namespace: $NAMESPACE
data:
  config.yaml: |
    cluster_endpoints:
      - "http://ipfs-cluster-api:9094"
    metadata_db_type: "memory"
    cache_enabled: true
    metrics_enabled: true
    replica_manager_enabled: true
    replication_min: 1
    replication_max: 3
    max_concurrent_pins: 100
    pin_timeout: "5m"
    chunk_size: 1048576
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: versitygw-ipfs
  namespace: $NAMESPACE
spec:
  replicas: 3
  selector:
    matchLabels:
      app: versitygw-ipfs
  template:
    metadata:
      labels:
        app: versitygw-ipfs
    spec:
      containers:
      - name: versitygw
        image: versitygw-ipfs:$VERSITYGW_VERSION
        ports:
        - containerPort: 7070
          name: s3-api
        - containerPort: 8080
          name: admin
        env:
        - name: ROOT_ACCESS_KEY
          value: "minioadmin"
        - name: ROOT_SECRET_KEY
          value: "minioadmin"
        - name: VGW_IPFS_CLUSTER_ENDPOINTS
          value: "http://ipfs-cluster-api:9094"
        - name: VGW_IPFS_METADATA_DB_TYPE
          value: "memory"
        - name: VGW_IPFS_CACHE_ENABLED
          value: "true"
        - name: VGW_IPFS_METRICS_ENABLED
          value: "true"
        - name: VGW_IPFS_REPLICA_MANAGER_ENABLED
          value: "true"
        - name: VGW_IPFS_REPLICATION_MIN
          value: "1"
        - name: VGW_IPFS_REPLICATION_MAX
          value: "3"
        - name: VGW_IPFS_MAX_CONCURRENT_PINS
          value: "100"
        - name: VGW_IPFS_PIN_TIMEOUT
          value: "5m"
        volumeMounts:
        - name: config
          mountPath: /etc/versitygw
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 7070
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 7070
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: versitygw-config
---
apiVersion: v1
kind: Service
metadata:
  name: versitygw-ipfs
  namespace: $NAMESPACE
spec:
  selector:
    app: versitygw-ipfs
  ports:
  - name: s3-api
    port: 7070
    targetPort: 7070
  - name: admin
    port: 8080
    targetPort: 8080
  type: LoadBalancer
EOF

    log_success "VersityGW deployed"
}

# Wait for deployment to be ready
wait_for_deployment() {
    log_info "Waiting for deployments to be ready..."
    
    # Wait for IPFS Cluster
    kubectl wait --for=condition=ready pod -l app=ipfs-cluster -n "$NAMESPACE" --timeout=300s
    
    # Wait for VersityGW
    kubectl wait --for=condition=available deployment/versitygw-ipfs -n "$NAMESPACE" --timeout=300s
    
    log_success "All deployments are ready"
}

# Display deployment information
display_info() {
    log_info "Deployment completed successfully!"
    echo
    echo "Deployment Information:"
    echo "======================"
    echo "Namespace: $NAMESPACE"
    echo "IPFS Cluster nodes: $CLUSTER_SIZE"
    echo
    
    # Get service information
    echo "Services:"
    kubectl get services -n "$NAMESPACE"
    echo
    
    # Get VersityGW service endpoint
    VERSITYGW_IP=$(kubectl get service versitygw-ipfs -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
    if [ "$VERSITYGW_IP" != "pending" ] && [ -n "$VERSITYGW_IP" ]; then
        echo "VersityGW S3 API endpoint: http://$VERSITYGW_IP:7070"
        echo "VersityGW Admin endpoint: http://$VERSITYGW_IP:8080"
    else
        echo "VersityGW endpoints: Use 'kubectl port-forward' or wait for LoadBalancer IP"
        echo "  kubectl port-forward -n $NAMESPACE service/versitygw-ipfs 7070:7070"
    fi
    echo
    
    echo "Access credentials:"
    echo "  Access Key: minioadmin"
    echo "  Secret Key: minioadmin"
    echo
    
    echo "To test the deployment:"
    echo "  aws --endpoint-url http://$VERSITYGW_IP:7070 s3 mb s3://test-bucket"
    echo "  aws --endpoint-url http://$VERSITYGW_IP:7070 s3 cp /path/to/file s3://test-bucket/"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up deployment..."
    
    kubectl delete deployment versitygw-ipfs -n "$NAMESPACE" --ignore-not-found=true
    kubectl delete statefulset ipfs-cluster -n "$NAMESPACE" --ignore-not-found=true
    kubectl delete service versitygw-ipfs ipfs-cluster-api ipfs-cluster-headless -n "$NAMESPACE" --ignore-not-found=true
    kubectl delete configmap versitygw-config ipfs-cluster-config -n "$NAMESPACE" --ignore-not-found=true
    kubectl delete pvc -l app=ipfs-cluster -n "$NAMESPACE" --ignore-not-found=true
    
    if [ "$NAMESPACE" != "default" ]; then
        kubectl delete namespace "$NAMESPACE" --ignore-not-found=true
    fi
    
    log_success "Cleanup completed"
}

# Main function
main() {
    case "${1:-deploy}" in
        "deploy")
            check_prerequisites
            create_namespace
            deploy_ipfs_cluster
            build_versitygw_image
            deploy_versitygw
            wait_for_deployment
            display_info
            ;;
        "cleanup")
            cleanup
            ;;
        "status")
            kubectl get all -n "$NAMESPACE"
            ;;
        *)
            echo "Usage: $0 [deploy|cleanup|status]"
            echo "  deploy  - Deploy VersityGW with IPFS Cluster"
            echo "  cleanup - Remove the deployment"
            echo "  status  - Show deployment status"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"