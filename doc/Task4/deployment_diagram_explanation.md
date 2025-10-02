# Объяснение Deployment Diagram (deployment_diagram.puml)

## Назначение диаграммы

Deployment Diagram показывает физическое развертывание системы безопасности Task 4, включая серверы, сервисы, хранилища данных, сетевые соединения и инфраструктурные компоненты. Эта диаграмма помогает понять, как система будет развернута в производственной среде.

## Структура PlantUML файла

### Заголовок и импорты
```plantuml
@startuml Task4_Deployment_Diagram
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Deployment.puml

title Deployment Diagram - Security Audit & Monitoring System (Task 4)
```

**Объяснение:**
- Использование C4_Deployment.puml для элементов развертывания
- Фокус на физической архитектуре и инфраструктуре

## Основные узлы развертывания

### 1. Security Server (Сервер безопасности)
```plantuml
Deployment_Node(security_server, "Security Server", "Linux Server") {
    Deployment_Node(go_runtime, "Go Runtime", "Go 1.21+") {
        Container(security_audit_service, "Security Audit Service", "Go Application", "Main security monitoring service")
        Container(alert_service, "Alert Service", "Go Application", "Security alerting and user blocking")
        Container(reporting_service, "Reporting Service", "Go Application", "Security reporting and audit trails")
    }
    
    Deployment_Node(file_system, "File System", "Local Storage") {
        ContainerDb(audit_logs, "Audit Log Files", "JSON/Text Files", "Persistent security event storage")
        ContainerDb(report_storage, "Report Storage", "Files", "Generated security reports")
        ContainerDb(config_files, "Configuration", "YAML/JSON", "Security system configuration")
    }
}
```

**Детальные характеристики Security Server:**

#### Аппаратные требования:
- **CPU:** 8+ cores (Intel Xeon или AMD EPYC)
- **RAM:** 32GB+ (для обработки больших объемов событий)
- **Storage:** 1TB+ SSD (для быстрого доступа к логам)
- **Network:** 10Gbps+ (для высокой пропускной способности)

#### Операционная система:
- **Linux Distribution:** Ubuntu 22.04 LTS или CentOS 8+
- **Kernel:** 5.4+ для поддержки современных функций безопасности
- **Security:** SELinux/AppArmor для дополнительной защиты
- **Monitoring:** systemd для управления сервисами

#### Go Runtime Environment:
```bash
# Установка Go 1.21+
wget https://go.dev/dl/go1.21.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

**Переменные окружения:**
```bash
export GOMAXPROCS=8
export GOGC=100
export GOMEMLIMIT=16GB
```

#### Сервисы безопасности:

**1. Security Audit Service**
```yaml
# /etc/systemd/system/security-audit.service
[Unit]
Description=Security Audit Service
After=network.target

[Service]
Type=simple
User=security
Group=security
ExecStart=/opt/security/bin/security-audit-service
Restart=always
RestartSec=5
Environment=CONFIG_PATH=/etc/security/audit.yaml
Environment=LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
```

**Конфигурация:**
```yaml
# /etc/security/audit.yaml
server:
  port: 8080
  read_timeout: 30s
  write_timeout: 30s

storage:
  type: hybrid
  memory_limit: 1GB
  file_path: /var/log/security/events
  retention_days: 365

detection:
  enable_pattern_detection: true
  brute_force_threshold: 5
  time_window: 15m
```

**2. Alert Service**
```yaml
# /etc/systemd/system/security-alert.service
[Unit]
Description=Security Alert Service
After=network.target security-audit.service

[Service]
Type=simple
User=security
Group=security
ExecStart=/opt/security/bin/security-alert-service
Restart=always
RestartSec=5
Environment=CONFIG_PATH=/etc/security/alert.yaml

[Install]
WantedBy=multi-user.target
```

**3. Reporting Service**
```yaml
# /etc/systemd/system/security-reporting.service
[Unit]
Description=Security Reporting Service
After=network.target security-audit.service

[Service]
Type=simple
User=security
Group=security
ExecStart=/opt/security/bin/security-reporting-service
Restart=always
RestartSec=5
Environment=CONFIG_PATH=/etc/security/reporting.yaml

[Install]
WantedBy=multi-user.target
```

#### Файловая система и хранилище:

**Структура директорий:**
```
/opt/security/
├── bin/                    # Исполняемые файлы
├── config/                 # Конфигурационные файлы
└── scripts/               # Скрипты управления

/var/log/security/
├── events/                # Логи событий безопасности
│   ├── 2024/01/15/       # Партиционирование по дате
│   └── indexes/          # Индексы для быстрого поиска
├── reports/              # Сгенерированные отчеты
└── alerts/               # Логи оповещений

/etc/security/
├── audit.yaml            # Конфигурация аудита
├── alert.yaml            # Конфигурация оповещений
├── reporting.yaml        # Конфигурация отчетности
└── certificates/         # SSL сертификаты
```

**Настройки файловой системы:**
```bash
# Создание пользователя и группы
sudo useradd -r -s /bin/false security
sudo mkdir -p /var/log/security/{events,reports,alerts}
sudo chown -R security:security /var/log/security
sudo chmod 750 /var/log/security

# Настройка ротации логов
# /etc/logrotate.d/security
/var/log/security/events/*.log {
    daily
    rotate 365
    compress
    delaycompress
    missingok
    notifempty
    create 640 security security
}
```

### 2. S3 Storage Cluster (Кластер S3 хранилища)
```plantuml
Deployment_Node(s3_cluster, "S3 Storage Cluster", "Distributed Storage") {
    Deployment_Node(s3_node1, "S3 Node 1", "Storage Server") {
        Container(s3_service1, "S3 Service", "Go Application", "Object storage service")
        ContainerDb(object_store1, "Object Storage", "File System", "User data storage")
    }
    
    Deployment_Node(s3_node2, "S3 Node 2", "Storage Server") {
        Container(s3_service2, "S3 Service", "Go Application", "Object storage service")
        ContainerDb(object_store2, "Object Storage", "File System", "User data storage")
    }
}
```

**Детальные характеристики S3 Cluster:**

#### Архитектура кластера:
- **Тип:** Distributed Object Storage
- **Репликация:** 3x для обеспечения надежности
- **Консистентность:** Eventually consistent
- **Масштабирование:** Горизонтальное добавление узлов

#### Характеристики узлов:
**Аппаратные требования на узел:**
- **CPU:** 16+ cores для обработки множественных запросов
- **RAM:** 64GB+ для кэширования метаданных
- **Storage:** 10TB+ HDD/SSD для объектов
- **Network:** 25Gbps+ для межузлового трафика

#### S3 Service Configuration:
```yaml
# s3-config.yaml
cluster:
  node_id: "node-1"
  peers:
    - "s3-node-2:9000"
    - "s3-node-3:9000"

storage:
  data_dir: "/data/objects"
  metadata_dir: "/data/metadata"
  replication_factor: 3

security:
  enable_audit_logging: true
  audit_log_path: "/var/log/s3/access.log"
  enhanced_logging: true

integration:
  security_audit_endpoint: "https://security-server:8080/api/events"
  metrics_endpoint: "https://prometheus:9090/api/v1/write"
```

#### Мониторинг доступа:
```go
// Интеграция с системой безопасности
type S3AccessLogger struct {
    securityEndpoint string
    client          *http.Client
}

func (l *S3AccessLogger) LogAccess(request *S3Request) {
    event := &SecurityEvent{
        Type:      "s3_access",
        UserID:    request.UserID,
        IPAddress: request.ClientIP,
        Resource:  request.Bucket + "/" + request.Key,
        Action:    request.Method,
        Success:   request.StatusCode < 400,
        Timestamp: time.Now(),
    }
    
    l.sendToSecuritySystem(event)
}
```

### 3. Monitoring Infrastructure (Инфраструктура мониторинга)
```plantuml
Deployment_Node(monitoring_infrastructure, "Monitoring Infrastructure", "External Services") {
    Deployment_Node(metrics_server, "Metrics Server", "Monitoring Server") {
        Container(prometheus, "Prometheus", "Metrics Collection", "Time-series metrics database")
        Container(grafana, "Grafana", "Visualization", "Metrics dashboards and alerting")
    }
    
    Deployment_Node(notification_server, "Notification Server", "Alert Server") {
        Container(email_service, "Email Service", "SMTP", "Email notifications")
        Container(webhook_service, "Webhook Service", "HTTP", "Webhook notifications")
    }
}
```

**Детальные характеристики Monitoring Infrastructure:**

#### Metrics Server:

**Prometheus Configuration:**
```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "security_rules.yml"

scrape_configs:
  - job_name: 'security-services'
    static_configs:
      - targets: ['security-server:8080', 'security-server:8081', 'security-server:8082']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 's3-cluster'
    static_configs:
      - targets: ['s3-node-1:9000', 's3-node-2:9000']
    metrics_path: '/minio/v2/metrics/cluster'

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']
```

**Security Rules:**
```yaml
# security_rules.yml
groups:
  - name: security_alerts
    rules:
      - alert: HighAuthFailureRate
        expr: rate(auth_failures_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate detected"
          
      - alert: SuspiciousActivityDetected
        expr: suspicious_activity_total > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Suspicious activity pattern detected"
          
      - alert: UserLockoutSpike
        expr: rate(user_lockouts_total[10m]) > 5
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Unusual number of user lockouts"
```

**Grafana Dashboards:**
```json
{
  "dashboard": {
    "title": "Security Monitoring Dashboard",
    "panels": [
      {
        "title": "Authentication Events",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(auth_attempts_total[5m])",
            "legendFormat": "Auth Attempts/sec"
          },
          {
            "expr": "rate(auth_failures_total[5m])",
            "legendFormat": "Auth Failures/sec"
          }
        ]
      },
      {
        "title": "Security Alerts",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(security_alerts_total)",
            "legendFormat": "Total Alerts"
          }
        ]
      }
    ]
  }
}
```

#### Notification Server:

**Email Service Configuration:**
```yaml
# email-service.yaml
smtp:
  host: "smtp.company.com"
  port: 587
  username: "security-alerts@company.com"
  password: "${SMTP_PASSWORD}"
  tls: true

templates:
  security_alert: "/etc/templates/security_alert.html"
  user_lockout: "/etc/templates/user_lockout.html"

recipients:
  security_team:
    - "security-team@company.com"
    - "soc@company.com"
  administrators:
    - "admin@company.com"
```

**Webhook Service:**
```go
type WebhookService struct {
    endpoints map[string]WebhookConfig
    client    *http.Client
}

type WebhookConfig struct {
    URL     string            `yaml:"url"`
    Headers map[string]string `yaml:"headers"`
    Timeout time.Duration     `yaml:"timeout"`
}

func (w *WebhookService) SendAlert(alert *SecurityAlert) error {
    for name, config := range w.endpoints {
        payload := map[string]interface{}{
            "alert_type": alert.Type,
            "severity":   alert.Severity,
            "message":    alert.Message,
            "timestamp":  alert.Timestamp,
            "details":    alert.Details,
        }
        
        if err := w.sendWebhook(config, payload); err != nil {
            log.Printf("Failed to send webhook to %s: %v", name, err)
        }
    }
    return nil
}
```

### 4. Admin Workstation (Рабочее место администратора)
```plantuml
Deployment_Node(admin_workstation, "Admin Workstation", "Desktop/Laptop") {
    Container(admin_cli, "Security Admin CLI", "Go Binary", "Command-line security management")
    Container(web_browser, "Web Browser", "Browser", "Access to dashboards and reports")
}
```

**Детальные характеристики Admin Workstation:**

#### Security Admin CLI:
```bash
# Установка CLI инструмента
curl -L https://releases.company.com/security-cli/latest/security-cli-linux-amd64 -o security-cli
chmod +x security-cli
sudo mv security-cli /usr/local/bin/

# Конфигурация
security-cli config set endpoint https://security-server:8080
security-cli config set auth-token ${ADMIN_TOKEN}
```

**Основные команды CLI:**
```bash
# Просмотр событий безопасности
security-cli events list --last 1h --severity high

# Управление пользователями
security-cli users list --locked
security-cli users unlock user123

# Генерация отчетов
security-cli reports generate --type audit_trail --format pdf --output report.pdf

# Настройка политик
security-cli policies update --file security-policy.yaml

# Мониторинг в реальном времени
security-cli monitor --follow --filter "type=auth_failure"
```

#### Web Browser Access:
**Доступные интерфейсы:**
- **Grafana Dashboards:** https://grafana.company.com
- **Security Reports:** https://security-server:8080/reports
- **Alert Management:** https://security-server:8080/alerts
- **User Management:** https://security-server:8080/admin/users

## Сетевые соединения и безопасность

### Основные сетевые потоки:
```plantuml
Rel(security_audit_service, s3_service1, "Monitor access logs", "HTTPS")
Rel(security_audit_service, s3_service2, "Monitor access logs", "HTTPS")
Rel(alert_service, email_service, "Send alerts", "SMTP")
Rel(alert_service, webhook_service, "Send alerts", "HTTPS")
Rel(security_audit_service, prometheus, "Send metrics", "HTTP")
Rel(admin_cli, security_audit_service, "Manage security", "HTTPS/API")
Rel(web_browser, grafana, "View dashboards", "HTTPS")
Rel(web_browser, reporting_service, "Access reports", "HTTPS")
```

#### Сетевая безопасность:

**Firewall Rules:**
```bash
# Security Server
sudo ufw allow 8080/tcp  # Security API
sudo ufw allow 8081/tcp  # Alert Service
sudo ufw allow 8082/tcp  # Reporting Service
sudo ufw allow 22/tcp    # SSH (restricted IPs)

# S3 Cluster
sudo ufw allow 9000/tcp  # S3 API
sudo ufw allow 9001/tcp  # S3 Console

# Monitoring
sudo ufw allow 9090/tcp  # Prometheus
sudo ufw allow 3000/tcp  # Grafana
```

**SSL/TLS Configuration:**
```yaml
# tls-config.yaml
certificates:
  security_server:
    cert_file: "/etc/ssl/certs/security-server.crt"
    key_file: "/etc/ssl/private/security-server.key"
    ca_file: "/etc/ssl/certs/ca.crt"
  
  s3_cluster:
    cert_file: "/etc/ssl/certs/s3-cluster.crt"
    key_file: "/etc/ssl/private/s3-cluster.key"

tls_settings:
  min_version: "1.2"
  cipher_suites:
    - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
```

## Развертывание и управление

### Docker Containerization:
```dockerfile
# Dockerfile для Security Services
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o security-audit-service ./cmd/audit

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/security-audit-service .
COPY --from=builder /app/config ./config
EXPOSE 8080
CMD ["./security-audit-service"]
```

**Docker Compose для разработки:**
```yaml
# docker-compose.yml
version: '3.8'
services:
  security-audit:
    build: .
    ports:
      - "8080:8080"
    environment:
      - CONFIG_PATH=/app/config/audit.yaml
    volumes:
      - ./logs:/var/log/security
      
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

### Kubernetes Deployment:
```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-audit-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: security-audit
  template:
    metadata:
      labels:
        app: security-audit
    spec:
      containers:
      - name: security-audit
        image: company/security-audit:latest
        ports:
        - containerPort: 8080
        env:
        - name: CONFIG_PATH
          value: "/etc/config/audit.yaml"
        volumeMounts:
        - name: config
          mountPath: /etc/config
        - name: logs
          mountPath: /var/log/security
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
      volumes:
      - name: config
        configMap:
          name: security-config
      - name: logs
        persistentVolumeClaim:
          claimName: security-logs-pvc
```

## Мониторинг и обслуживание

### Health Checks:
```go
// Health check endpoints
func (s *SecurityAuditService) HealthCheck(c *fiber.Ctx) error {
    status := map[string]interface{}{
        "status":    "healthy",
        "timestamp": time.Now(),
        "version":   s.version,
        "uptime":    time.Since(s.startTime),
        "components": map[string]string{
            "database":  s.checkDatabase(),
            "detector":  s.checkDetector(),
            "storage":   s.checkStorage(),
        },
    }
    
    return c.JSON(status)
}
```

### Backup Strategy:
```bash
#!/bin/bash
# backup-security-data.sh

BACKUP_DIR="/backup/security/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup event logs
tar -czf $BACKUP_DIR/events.tar.gz /var/log/security/events/

# Backup configuration
cp -r /etc/security/ $BACKUP_DIR/config/

# Backup reports
tar -czf $BACKUP_DIR/reports.tar.gz /var/log/security/reports/

# Upload to remote storage
aws s3 sync $BACKUP_DIR s3://company-backups/security/$(date +%Y%m%d)/
```

## Масштабирование и производительность

### Горизонтальное масштабирование:
- **Security Services:** Load balancer + multiple instances
- **S3 Cluster:** Добавление новых узлов хранения
- **Monitoring:** Prometheus federation для больших кластеров

### Оптимизация производительности:
```yaml
# performance-tuning.yaml
security_audit:
  worker_pool_size: 100
  batch_size: 1000
  flush_interval: 5s
  
storage:
  write_buffer_size: 64MB
  compression: gzip
  index_cache_size: 256MB
  
detection:
  analysis_workers: 10
  pattern_cache_size: 1000
  cleanup_interval: 1h
```

## Соответствие требованиям Task 4

### 4.1 Улучшение аудит логирования
- **Централизованное хранение** на Security Server
- **Интеграция с S3** для мониторинга доступа
- **Структурированные логи** с индексированием

### 4.2 Система оповещений и блокировки
- **Real-time обработка** на Security Server
- **Множественные каналы уведомлений** (email, webhook)
- **Автоматическая блокировка** с настраиваемыми порогами

### 4.3 Система отчетности и аудиторского следа
- **Dedicated Reporting Service** для генерации отчетов
- **Множественные форматы экспорта** (JSON, CSV, HTML, PDF)
- **Долгосрочное хранение** для соответствия требованиям аудита

Deployment Diagram обеспечивает полное понимание физической архитектуры и служит руководством для развертывания системы в производственной среде.