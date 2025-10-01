# Подробное объяснение Deployment Diagram Task 3 - Enhanced RBAC System

## Назначение диаграммы

Deployment Diagram для Task 3 показывает физическое развертывание Enhanced RBAC системы в производственной среде, включая серверы, контейнеры, сетевую инфраструктуру и внешние интеграции. Эта диаграмма служит мостом между архитектурным дизайном и реальным развертыванием, обеспечивая практическое руководство для DevOps команд.

## Структура PlantUML и инфраструктурные решения

### Заголовок и общая архитектура
```plantuml
@startuml Task3_RBAC_Deployment_Diagram
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Deployment.puml
title Enhanced RBAC Deployment Architecture - Task 3
```

**Архитектурное значение:**
- Показывает полную инфраструктуру для Enhanced RBAC
- Демонстрирует масштабируемость и отказоустойчивость
- Определяет сетевые границы и безопасность

## Клиентская среда (Client Environment)

### Developer Workstation
```plantuml
Deployment_Node(workstation, "Developer Workstation", "Linux/macOS/Windows") {
    Container(s3_sdk, "AWS S3 SDK", "Python/Go/Java/etc", "S3 client applications")
    Container(admin_cli, "RBAC Admin CLI", "Go", "Command-line role management tools")
}
```

**Реализация клиентских инструментов:**
```go
// cmd/rbac-cli/main.go - CLI для управления ролями
package main

import (
    "encoding/json"
    "fmt"
    "os"
    "github.com/spf13/cobra"
    "github.com/company/s3-gateway/auth"
)

type CLIConfig struct {
    Endpoint    string `json:"endpoint"`
    APIKey      string `json:"api_key"`
    TLSEnabled  bool   `json:"tls_enabled"`
    TLSSkipVerify bool `json:"tls_skip_verify"`
}

var (
    config *CLIConfig
    rootCmd = &cobra.Command{
        Use:   "rbac-cli",
        Short: "Enhanced RBAC management CLI",
        Long:  "Command-line interface for managing Enhanced RBAC roles and permissions",
    }
)

func main() {
    // Загрузка конфигурации
    if err := loadConfig(); err != nil {
        fmt.Printf("Error loading config: %v\n", err)
        os.Exit(1)
    }
    
    // Добавление команд
    rootCmd.AddCommand(
        createRoleCmd(),
        listRolesCmd(),
        assignRoleCmd(),
        revokeRoleCmd(),
        getUserRolesCmd(),
        checkPermissionCmd(),
    )
    
    if err := rootCmd.Execute(); err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }
}

// Команда создания роли
func createRoleCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "create-role [role-file.json]",
        Short: "Create a new role from JSON file",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            roleFile := args[0]
            
            // Чтение файла роли
            data, err := os.ReadFile(roleFile)
            if err != nil {
                return fmt.Errorf("failed to read role file: %w", err)
            }
            
            var role auth.EnhancedRole
            if err := json.Unmarshal(data, &role); err != nil {
                return fmt.Errorf("failed to parse role JSON: %w", err)
            }
            
            // Отправка на сервер
            client := NewRBACClient(config)
            if err := client.CreateRole(&role); err != nil {
                return fmt.Errorf("failed to create role: %w", err)
            }
            
            fmt.Printf("Role '%s' created successfully\n", role.ID)
            return nil
        },
    }
    
    return cmd
}

// Клиент для взаимодействия с RBAC API
type RBACClient struct {
    endpoint   string
    apiKey     string
    httpClient *http.Client
}

func NewRBACClient(config *CLIConfig) *RBACClient {
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: config.TLSSkipVerify,
        },
    }
    
    return &RBACClient{
        endpoint: config.Endpoint,
        apiKey:   config.APIKey,
        httpClient: &http.Client{
            Transport: transport,
            Timeout:   30 * time.Second,
        },
    }
}

func (c *RBACClient) CreateRole(role *auth.EnhancedRole) error {
    data, err := json.Marshal(role)
    if err != nil {
        return err
    }
    
    req, err := http.NewRequest("POST", c.endpoint+"/api/v1/roles", bytes.NewBuffer(data))
    if err != nil {
        return err
    }
    
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-API-Key", c.apiKey)
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 201 {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
    }
    
    return nil
}
```

### Mobile Device Support
```plantuml
Deployment_Node(mobile_device, "Mobile Device", "iOS/Android") {
    Container(mobile_app, "Mobile S3 App", "React Native/Flutter", "Mobile S3 applications")
}
```

**Реализация мобильной интеграции:**
```javascript
// mobile/src/s3Client.js - React Native S3 клиент
import AWS from 'aws-sdk';
import { Platform } from 'react-native';

class S3Client {
    constructor(config) {
        this.config = config;
        this.s3 = new AWS.S3({
            endpoint: config.endpoint,
            accessKeyId: config.accessKeyId,
            secretAccessKey: config.secretAccessKey,
            s3ForcePathStyle: true,
            signatureVersion: 'v4',
            region: config.region || 'us-east-1'
        });
    }
    
    async uploadFile(bucket, key, file) {
        try {
            const params = {
                Bucket: bucket,
                Key: key,
                Body: file,
                ContentType: file.type || 'application/octet-stream'
            };
            
            const result = await this.s3.upload(params).promise();
            return result;
        } catch (error) {
            if (error.statusCode === 403) {
                throw new Error('Access denied. Check your permissions.');
            }
            throw error;
        }
    }
    
    async downloadFile(bucket, key) {
        try {
            const params = {
                Bucket: bucket,
                Key: key
            };
            
            const result = await this.s3.getObject(params).promise();
            return result.Body;
        } catch (error) {
            if (error.statusCode === 403) {
                throw new Error('Access denied. Check your permissions.');
            }
            throw error;
        }
    }
}

export default S3Client;
```## 
S3 Gateway Cluster (Основная инфраструктура)

### Gateway Nodes
```plantuml
Deployment_Node(gateway_node1, "Gateway Node 1", "Linux Container") {
    Container(s3_api_1, "S3 API Server", "Go/Fiber", "Primary S3 API endpoint")
    Container(rbac_engine_1, "RBAC Engine", "Go", "Enhanced role-based access control")
    Container(role_cache_1, "Role Cache", "Go/Memory", "In-memory role permissions cache")
}
```

**Реализация Gateway Node:**
```go
// cmd/gateway/main.go - основной сервер Gateway
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"
    
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/cors"
    "github.com/gofiber/fiber/v2/middleware/logger"
    "github.com/gofiber/fiber/v2/middleware/recover"
    
    "github.com/company/s3-gateway/auth"
    "github.com/company/s3-gateway/config"
    "github.com/company/s3-gateway/middleware"
)

type GatewayServer struct {
    app         *fiber.App
    config      *config.Config
    rbacEngine  *auth.RBACEngine
    roleManager auth.RoleManager
    cache       auth.Cache
}

func main() {
    // Загрузка конфигурации
    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }
    
    // Создание сервера
    server, err := NewGatewayServer(cfg)
    if err != nil {
        log.Fatalf("Failed to create server: %v", err)
    }
    
    // Запуск сервера
    if err := server.Start(); err != nil {
        log.Fatalf("Failed to start server: %v", err)
    }
}

func NewGatewayServer(cfg *config.Config) (*GatewayServer, error) {
    // Создание Fiber приложения
    app := fiber.New(fiber.Config{
        ReadTimeout:  cfg.Server.ReadTimeout,
        WriteTimeout: cfg.Server.WriteTimeout,
        IdleTimeout:  cfg.Server.IdleTimeout,
        ErrorHandler: customErrorHandler,
    })
    
    // Middleware
    app.Use(recover.New())
    app.Use(logger.New(logger.Config{
        Format: "${time} ${method} ${path} ${status} ${latency}\n",
    }))
    app.Use(cors.New(cors.Config{
        AllowOrigins: cfg.CORS.AllowOrigins,
        AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
        AllowHeaders: "Origin,Content-Type,Accept,Authorization,X-API-Key",
    }))
    
    // Создание компонентов RBAC
    cache := auth.NewLRUCache(cfg.RBAC.CacheSize)
    roleManager, err := auth.NewFileBasedRoleManager(cfg.RBAC.DataDir)
    if err != nil {
        return nil, fmt.Errorf("failed to create role manager: %w", err)
    }
    
    rbacEngine := auth.NewRBACEngine(roleManager, cache)
    
    server := &GatewayServer{
        app:         app,
        config:      cfg,
        rbacEngine:  rbacEngine,
        roleManager: roleManager,
        cache:       cache,
    }
    
    // Настройка маршрутов
    server.setupRoutes()
    
    return server, nil
}

func (gs *GatewayServer) setupRoutes() {
    // Health check
    gs.app.Get("/health", gs.healthCheck)
    
    // Metrics endpoint
    gs.app.Get("/metrics", gs.metricsHandler)
    
    // Admin API для управления ролями
    admin := gs.app.Group("/admin")
    admin.Use(middleware.AdminAuth(gs.config.Admin.APIKey))
    
    admin.Post("/roles", gs.createRole)
    admin.Get("/roles/:id", gs.getRole)
    admin.Put("/roles/:id", gs.updateRole)
    admin.Delete("/roles/:id", gs.deleteRole)
    admin.Post("/users/:userId/roles/:roleId", gs.assignRole)
    admin.Delete("/users/:userId/roles/:roleId", gs.revokeRole)
    
    // S3 API endpoints с RBAC middleware
    s3 := gs.app.Group("/")
    s3.Use(middleware.RBACAuth(gs.rbacEngine))
    
    // Bucket operations
    s3.Get("/:bucket", gs.listObjects)
    s3.Put("/:bucket", gs.createBucket)
    s3.Delete("/:bucket", gs.deleteBucket)
    
    // Object operations
    s3.Get("/:bucket/:object", gs.getObject)
    s3.Put("/:bucket/:object", gs.putObject)
    s3.Delete("/:bucket/:object", gs.deleteObject)
    s3.Head("/:bucket/:object", gs.headObject)
}

func (gs *GatewayServer) Start() error {
    // Запуск фоновых задач
    go gs.startBackgroundTasks()
    
    // Graceful shutdown
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    
    go func() {
        <-c
        log.Println("Shutting down server...")
        
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        
        if err := gs.app.ShutdownWithContext(ctx); err != nil {
            log.Printf("Error during shutdown: %v", err)
        }
    }()
    
    // Запуск сервера
    log.Printf("Starting server on port %d", gs.config.Server.Port)
    return gs.app.Listen(fmt.Sprintf(":%d", gs.config.Server.Port))
}

func (gs *GatewayServer) startBackgroundTasks() {
    // Очистка кэша
    go gs.cache.StartCleanup(5 * time.Minute)
    
    // Синхронизация ролей между узлами
    go gs.startRoleSync()
    
    // Сбор метрик
    go gs.startMetricsCollection()
}
```

### Load Balancer
```plantuml
Deployment_Node(load_balancer, "Load Balancer", "NGINX/HAProxy") {
    Container(lb_service, "Load Balancer", "NGINX", "Distributes requests across gateway nodes")
}
```

**Конфигурация NGINX Load Balancer:**
```nginx
# /etc/nginx/nginx.conf - конфигурация балансировщика
upstream s3_gateway_backend {
    least_conn;
    server gateway-node-1:8080 max_fails=3 fail_timeout=30s;
    server gateway-node-2:8080 max_fails=3 fail_timeout=30s;
    server gateway-node-3:8080 max_fails=3 fail_timeout=30s backup;
    
    # Health check
    keepalive 32;
}

upstream admin_backend {
    server gateway-node-1:8080;
    server gateway-node-2:8080 backup;
}

# Rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
limit_req_zone $binary_remote_addr zone=admin:10m rate=10r/s;

server {
    listen 80;
    listen 443 ssl http2;
    server_name s3-gateway.company.com;
    
    # SSL configuration
    ssl_certificate /etc/ssl/certs/s3-gateway.crt;
    ssl_certificate_key /etc/ssl/private/s3-gateway.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    # Redirect HTTP to HTTPS
    if ($scheme != "https") {
        return 301 https://$host$request_uri;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://s3_gateway_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Admin API with stricter rate limiting
    location /admin/ {
        limit_req zone=admin burst=5 nodelay;
        
        # IP whitelist for admin access
        allow 10.0.0.0/8;
        allow 192.168.0.0/16;
        deny all;
        
        proxy_pass http://admin_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Увеличенные таймауты для admin операций
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # S3 API endpoints
    location / {
        limit_req zone=api burst=20 nodelay;
        
        # CORS headers for S3 API
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS';
            add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
        
        proxy_pass http://s3_gateway_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # S3 specific headers
        proxy_set_header X-Amz-Content-Sha256 $http_x_amz_content_sha256;
        proxy_set_header X-Amz-Date $http_x_amz_date;
        proxy_set_header Authorization $http_authorization;
        
        # Таймауты для больших файлов
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        # Буферизация для производительности
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }
    
    # Логирование
    access_log /var/log/nginx/s3-gateway-access.log combined;
    error_log /var/log/nginx/s3-gateway-error.log warn;
}

# Upstream health check configuration
server {
    listen 8081;
    location /nginx_status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }
}
```

## Storage Tier (Уровень хранения)

### Role Storage
```plantuml
Deployment_Node(role_storage, "Role Storage", "File System/Database") {
    ContainerDb(role_db, "Role Database", "JSON Files/SQLite", "Persistent role and permission storage")
    ContainerDb(audit_logs, "Audit Logs", "Log Files", "RBAC access decision logs")
}
```

**Реализация файлового хранилища ролей:**
```go
// storage/file_storage.go - файловое хранилище
type FileRoleStorage struct {
    dataDir         string
    rolesFile       string
    assignmentsFile string
    auditLogFile    string
    mutex           sync.RWMutex
    
    // Конфигурация
    backupEnabled   bool
    backupInterval  time.Duration
    compressionEnabled bool
}

func NewFileRoleStorage(dataDir string) (*FileRoleStorage, error) {
    storage := &FileRoleStorage{
        dataDir:         dataDir,
        rolesFile:       filepath.Join(dataDir, "roles.json"),
        assignmentsFile: filepath.Join(dataDir, "assignments.json"),
        auditLogFile:    filepath.Join(dataDir, "audit.log"),
        backupEnabled:   true,
        backupInterval:  24 * time.Hour,
        compressionEnabled: true,
    }
    
    // Создание директории
    if err := os.MkdirAll(dataDir, 0755); err != nil {
        return nil, fmt.Errorf("failed to create data directory: %w", err)
    }
    
    // Запуск фоновых задач
    go storage.startBackgroundTasks()
    
    return storage, nil
}

func (fs *FileRoleStorage) SaveRole(role *auth.EnhancedRole) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()
    
    // Загрузка существующих ролей
    roles, err := fs.loadRoles()
    if err != nil {
        return fmt.Errorf("failed to load existing roles: %w", err)
    }
    
    // Создание резервной копии перед изменением
    if fs.backupEnabled {
        if err := fs.createBackup(); err != nil {
            log.Printf("Warning: failed to create backup: %v", err)
        }
    }
    
    // Обновление роли
    roles[role.ID] = role
    
    // Сохранение с атомарной записью
    if err := fs.atomicSave(fs.rolesFile, roles); err != nil {
        return fmt.Errorf("failed to save roles: %w", err)
    }
    
    // Логирование изменения
    fs.logAuditEvent("role_saved", role.ID, map[string]interface{}{
        "role_name": role.Name,
        "permissions_count": len(role.Permissions),
    })
    
    return nil
}

func (fs *FileRoleStorage) atomicSave(filename string, data interface{}) error {
    // Сериализация данных
    jsonData, err := json.MarshalIndent(data, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal data: %w", err)
    }
    
    // Сжатие если включено
    if fs.compressionEnabled {
        jsonData, err = fs.compress(jsonData)
        if err != nil {
            return fmt.Errorf("failed to compress data: %w", err)
        }
        filename += ".gz"
    }
    
    // Атомарная запись через временный файл
    tempFile := filename + ".tmp"
    if err := os.WriteFile(tempFile, jsonData, 0644); err != nil {
        return fmt.Errorf("failed to write temp file: %w", err)
    }
    
    // Атомарное переименование
    if err := os.Rename(tempFile, filename); err != nil {
        os.Remove(tempFile) // Очистка при ошибке
        return fmt.Errorf("failed to rename temp file: %w", err)
    }
    
    return nil
}

func (fs *FileRoleStorage) startBackgroundTasks() {
    // Периодическое создание резервных копий
    if fs.backupEnabled {
        ticker := time.NewTicker(fs.backupInterval)
        go func() {
            for range ticker.C {
                if err := fs.createBackup(); err != nil {
                    log.Printf("Backup failed: %v", err)
                }
            }
        }()
    }
    
    // Очистка старых резервных копий
    go func() {
        ticker := time.NewTicker(24 * time.Hour)
        for range ticker.C {
            fs.cleanupOldBackups(30) // Хранить 30 дней
        }
    }()
}

func (fs *FileRoleStorage) createBackup() error {
    timestamp := time.Now().Format("20060102_150405")
    backupDir := filepath.Join(fs.dataDir, "backups", timestamp)
    
    if err := os.MkdirAll(backupDir, 0755); err != nil {
        return fmt.Errorf("failed to create backup directory: %w", err)
    }
    
    // Копирование файлов
    files := []string{fs.rolesFile, fs.assignmentsFile}
    for _, file := range files {
        if _, err := os.Stat(file); os.IsNotExist(err) {
            continue
        }
        
        backupFile := filepath.Join(backupDir, filepath.Base(file))
        if err := fs.copyFile(file, backupFile); err != nil {
            return fmt.Errorf("failed to backup %s: %w", file, err)
        }
    }
    
    log.Printf("Backup created: %s", backupDir)
    return nil
}
```

## External Systems (Внешние системы)

### IAM Provider Integration
```plantuml
System_Ext(iam_provider, "IAM Provider", "External identity provider (LDAP/AD/OAuth)")
```

**Реализация интеграции с внешним IAM:**
```go
// integration/iam_provider.go - интеграция с внешним IAM
type IAMProvider interface {
    AuthenticateUser(username, password string) (*UserInfo, error)
    GetUserInfo(userID string) (*UserInfo, error)
    GetUserGroups(userID string) ([]string, error)
    ValidateToken(token string) (*TokenInfo, error)
}

// LDAP провайдер
type LDAPProvider struct {
    conn     *ldap.Conn
    baseDN   string
    bindDN   string
    bindPass string
    config   *LDAPConfig
}

type LDAPConfig struct {
    Server      string `json:"server"`
    Port        int    `json:"port"`
    BaseDN      string `json:"base_dn"`
    BindDN      string `json:"bind_dn"`
    BindPass    string `json:"bind_pass"`
    UserFilter  string `json:"user_filter"`
    GroupFilter string `json:"group_filter"`
    TLSEnabled  bool   `json:"tls_enabled"`
}

func NewLDAPProvider(config *LDAPConfig) (*LDAPProvider, error) {
    conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", config.Server, config.Port))
    if err != nil {
        return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
    }
    
    if config.TLSEnabled {
        if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: false}); err != nil {
            return nil, fmt.Errorf("failed to start TLS: %w", err)
        }
    }
    
    // Bind с административными учетными данными
    if err := conn.Bind(config.BindDN, config.BindPass); err != nil {
        return nil, fmt.Errorf("failed to bind: %w", err)
    }
    
    return &LDAPProvider{
        conn:     conn,
        baseDN:   config.BaseDN,
        bindDN:   config.BindDN,
        bindPass: config.BindPass,
        config:   config,
    }, nil
}

func (lp *LDAPProvider) AuthenticateUser(username, password string) (*UserInfo, error) {
    // Поиск пользователя
    searchRequest := ldap.NewSearchRequest(
        lp.baseDN,
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        0, 0, false,
        fmt.Sprintf(lp.config.UserFilter, username),
        []string{"dn", "cn", "mail", "memberOf"},
        nil,
    )
    
    sr, err := lp.conn.Search(searchRequest)
    if err != nil {
        return nil, fmt.Errorf("LDAP search failed: %w", err)
    }
    
    if len(sr.Entries) == 0 {
        return nil, errors.New("user not found")
    }
    
    userDN := sr.Entries[0].DN
    
    // Проверка пароля
    if err := lp.conn.Bind(userDN, password); err != nil {
        return nil, errors.New("invalid credentials")
    }
    
    // Восстановление административного bind
    if err := lp.conn.Bind(lp.bindDN, lp.bindPass); err != nil {
        return nil, fmt.Errorf("failed to restore admin bind: %w", err)
    }
    
    // Извлечение информации о пользователе
    entry := sr.Entries[0]
    userInfo := &UserInfo{
        UserID:      username,
        DisplayName: entry.GetAttributeValue("cn"),
        Email:       entry.GetAttributeValue("mail"),
        Groups:      entry.GetAttributeValues("memberOf"),
    }
    
    return userInfo, nil
}
```

Deployment Diagram Task 3 обеспечивает полное понимание физической архитектуры Enhanced RBAC системы и служит практическим руководством для развертывания в производственной среде, показывая как архитектурные компоненты размещаются на реальной инфраструктуре.