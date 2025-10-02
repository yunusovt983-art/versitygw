# Подробное объяснение Deployment Diagram Task 2 - MFA Enhanced S3 Gateway

## Назначение диаграммы

Deployment Diagram для Task 2 показывает физическое развертывание MFA Enhanced S3 Gateway системы в производственной среде, включая клиентские устройства, серверную инфраструктуру и внешние системы. Эта диаграмма служит мостом между архитектурным дизайном и реальным развертыванием MFA системы.

## Структура PlantUML и инфраструктурные решения

### Заголовок и общая архитектура
```plantuml
@startuml Task2_MFA_Deployment_Diagram
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Deployment.puml
title Deployment Diagram - MFA Enhanced S3 Gateway (Task 2)
```

**Архитектурное значение:**
- Показывает полную инфраструктуру для MFA Enhanced S3 Gateway
- Демонстрирует безопасность и отказоустойчивость
- Определяет сетевые границы и интеграции

## Client Environment (Клиентская среда)

### Mobile Device
```plantuml
Deployment_Node(mobile, "Mobile Device", "iOS/Android") {
    Container(totp_app, "TOTP Authenticator", "Mobile App", "Google Authenticator, Authy, etc.")
}
```

**Реализация мобильных TOTP приложений:**

#### Google Authenticator интеграция
```go
// Генерация QR кода для Google Authenticator
func (qg *QRCodeGenerator) GenerateForGoogleAuth(secret, accountName, issuer string) (string, error) {
    // Создание TOTP URI согласно стандарту Google Authenticator
    uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
        url.QueryEscape(issuer),
        url.QueryEscape(accountName),
        secret,
        url.QueryEscape(issuer),
    )
    
    // Генерация QR кода
    qr, err := qrcode.New(uri, qrcode.Medium)
    if err != nil {
        return "", fmt.Errorf("failed to generate QR code: %w", err)
    }
    
    // Конвертация в PNG и кодирование в Base64
    png, err := qr.PNG(256)
    if err != nil {
        return "", fmt.Errorf("failed to generate PNG: %w", err)
    }
    
    return base64.StdEncoding.EncodeToString(png), nil
}
```

#### Поддержка различных TOTP приложений
```go
// config/totp_apps.go - конфигурация для различных TOTP приложений
type TOTPAppConfig struct {
    Name        string `json:"name"`
    Algorithm   string `json:"algorithm"`   // SHA1, SHA256, SHA512
    Digits      int    `json:"digits"`      // 6 или 8
    Period      int    `json:"period"`      // 30 секунд обычно
    QRCodeSize  int    `json:"qr_code_size"`
    DeepLinkURL string `json:"deep_link_url,omitempty"`
}

var SupportedTOTPApps = map[string]TOTPAppConfig{
    "google_authenticator": {
        Name:       "Google Authenticator",
        Algorithm:  "SHA1",
        Digits:     6,
        Period:     30,
        QRCodeSize: 256,
    },
    "microsoft_authenticator": {
        Name:       "Microsoft Authenticator",
        Algorithm:  "SHA1",
        Digits:     6,
        Period:     30,
        QRCodeSize: 256,
    },
    "authy": {
        Name:       "Authy",
        Algorithm:  "SHA1",
        Digits:     6,
        Period:     30,
        QRCodeSize: 300,
        DeepLinkURL: "authy://",
    },
    "1password": {
        Name:       "1Password",
        Algorithm:  "SHA1",
        Digits:     6,
        Period:     30,
        QRCodeSize: 256,
    },
}

// Генерация QR кода с учетом специфики приложения
func (qg *QRCodeGenerator) GenerateForApp(appName, secret, accountName, issuer string) (string, error) {
    appConfig, exists := SupportedTOTPApps[appName]
    if !exists {
        appConfig = SupportedTOTPApps["google_authenticator"] // По умолчанию
    }
    
    uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
        url.QueryEscape(issuer),
        url.QueryEscape(accountName),
        secret,
        url.QueryEscape(issuer),
        appConfig.Algorithm,
        appConfig.Digits,
        appConfig.Period,
    )
    
    qr, err := qrcode.New(uri, qrcode.Medium)
    if err != nil {
        return "", err
    }
    
    png, err := qr.PNG(appConfig.QRCodeSize)
    if err != nil {
        return "", err
    }
    
    return base64.StdEncoding.EncodeToString(png), nil
}
```

### Client Workstation
```plantuml
Deployment_Node(workstation, "Client Workstation", "Desktop/Laptop") {
    Container(s3_client, "S3 Client", "AWS CLI/SDK", "S3 client with MFA token support")
}
```

**Реализация S3 клиентов с MFA поддержкой:**

#### AWS CLI с MFA
```bash
# ~/.aws/config - конфигурация AWS CLI с MFA
[profile mfa-enabled]
region = us-east-1
output = json
s3 =
    endpoint_url = https://s3-gateway.company.com
    signature_version = s3v4
    
[profile mfa-enabled-with-token]
source_profile = mfa-enabled
mfa_serial = arn:aws:iam::123456789012:mfa/user@company.com
```

```bash
# Скрипт для автоматического добавления MFA токена
#!/bin/bash
# mfa-s3-wrapper.sh

# Получение текущего TOTP токена (требует настроенного TOTP генератора)
MFA_TOKEN=$(totp-cli generate --account "user@company.com")

# Добавление MFA токена в заголовки AWS CLI
export AWS_CLI_MFA_TOKEN="$MFA_TOKEN"

# Выполнение AWS CLI команды с MFA токеном
aws s3 "$@" --cli-input-json "{\"Metadata\": {\"X-Amz-MFA\": \"$MFA_TOKEN\"}}"
```

#### Go SDK с MFA
```go
// client/aws_sdk_mfa.go - AWS SDK с MFA поддержкой
type MFACredentialsProvider struct {
    accessKeyID     string
    secretAccessKey string
    mfaTokenProvider MFATokenProvider
}

func (m *MFACredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
    mfaToken, err := m.mfaTokenProvider.GetCurrentMFAToken()
    if err != nil {
        return aws.Credentials{}, fmt.Errorf("failed to get MFA token: %w", err)
    }
    
    return aws.Credentials{
        AccessKeyID:     m.accessKeyID,
        SecretAccessKey: m.secretAccessKey,
        SessionToken:    mfaToken, // Используем SessionToken для передачи MFA токена
    }, nil
}

// Middleware для добавления MFA токена в заголовки
func AddMFATokenMiddleware(mfaToken string) func(*middleware.Stack) error {
    return func(stack *middleware.Stack) error {
        return stack.Finalize.Add(
            middleware.FinalizeMiddlewareFunc("AddMFAToken", func(
                ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler,
            ) (middleware.FinalizeOutput, middleware.Metadata, error) {
                req := in.Request.(*smithyhttp.Request)
                req.Header.Set("X-Amz-MFA", mfaToken)
                return next.HandleFinalize(ctx, in)
            }),
            middleware.After,
        )
    }
}
```

## Gateway Server (Сервер Gateway)

### S3 Gateway Application
```plantuml
Deployment_Node(gateway_server, "S3 Gateway Server", "Linux Server") {
    Deployment_Node(app_runtime, "Go Runtime", "Go 1.21+") {
        Container(s3_gateway, "Versity S3 Gateway", "Go Application", "Enhanced with MFA authentication")
        
        Component_Boundary(mfa_components, "MFA Components") {
            Component(mfa_service, "MFA Service", "Go Package", "Core MFA logic")
            Component(mfa_middleware, "MFA Middleware", "Go Package", "HTTP MFA validation")
            Component(totp_generator, "TOTP Generator", "Go Package", "RFC 6238 implementation")
            Component(qr_generator, "QR Generator", "Go Package", "Setup QR codes")
        }
    }
}
```

**Реализация развертывания Gateway сервера:**

#### Systemd Service Configuration
```ini
# /etc/systemd/system/s3-gateway-mfa.service
[Unit]
Description=S3 Gateway with MFA Support
After=network.target
Wants=network.target

[Service]
Type=simple
User=s3gateway
Group=s3gateway
WorkingDirectory=/opt/s3-gateway
ExecStart=/opt/s3-gateway/bin/s3-gateway-mfa
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# Environment variables
Environment=CONFIG_PATH=/etc/s3-gateway/config.yaml
Environment=MFA_DATA_DIR=/var/lib/s3-gateway/mfa
Environment=LOG_LEVEL=info
Environment=GOMAXPROCS=4

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/s3-gateway /var/log/s3-gateway

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

#### Docker Configuration
```dockerfile
# Dockerfile для S3 Gateway с MFA
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .

# Сборка приложения
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o s3-gateway-mfa ./cmd/gateway

FROM alpine:latest

# Установка необходимых пакетов
RUN apk --no-cache add ca-certificates tzdata

# Создание пользователя
RUN adduser -D -s /bin/sh s3gateway

WORKDIR /app

# Копирование бинарника и конфигурации
COPY --from=builder /app/s3-gateway-mfa .
COPY --from=builder /app/config ./config

# Создание директорий для данных
RUN mkdir -p /var/lib/s3-gateway/mfa /var/log/s3-gateway
RUN chown -R s3gateway:s3gateway /var/lib/s3-gateway /var/log/s3-gateway /app

USER s3gateway

EXPOSE 8080 8443

CMD ["./s3-gateway-mfa"]
```

#### Kubernetes Deployment
```yaml
# k8s/s3-gateway-mfa-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: s3-gateway-mfa
  labels:
    app: s3-gateway-mfa
spec:
  replicas: 3
  selector:
    matchLabels:
      app: s3-gateway-mfa
  template:
    metadata:
      labels:
        app: s3-gateway-mfa
    spec:
      containers:
      - name: s3-gateway-mfa
        image: company/s3-gateway-mfa:latest
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 8443
          name: https
        env:
        - name: CONFIG_PATH
          value: "/etc/config/config.yaml"
        - name: MFA_DATA_DIR
          value: "/var/lib/mfa"
        - name: LOG_LEVEL
          value: "info"
        volumeMounts:
        - name: config
          mountPath: /etc/config
        - name: mfa-data
          mountPath: /var/lib/mfa
        - name: tls-certs
          mountPath: /etc/ssl/certs
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: s3-gateway-config
      - name: mfa-data
        persistentVolumeClaim:
          claimName: s3-gateway-mfa-data
      - name: tls-certs
        secret:
          secretName: s3-gateway-tls
---
apiVersion: v1
kind: Service
metadata:
  name: s3-gateway-mfa-service
spec:
  selector:
    app: s3-gateway-mfa
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: https
    port: 443
    targetPort: 8443
  type: LoadBalancer
```

### File System Storage
```plantuml
Deployment_Node(file_system, "File System", "Local Storage") {
    ContainerDb(mfa_data, "MFA Data Store", "JSON Files", "User MFA configurations and secrets")
    ContainerDb(config_files, "Configuration", "YAML/JSON", "MFA policies and settings")
}
```

**Реализация файлового хранилища:**

#### MFA Data Storage Structure
```bash
# Структура директорий MFA данных
/var/lib/s3-gateway/mfa/
├── users/                    # Данные пользователей MFA
│   ├── user1@company.com.json
│   ├── user2@company.com.json
│   └── ...
├── policies/                 # Политики MFA
│   └── default.json
├── audit/                    # Аудит логи
│   ├── 2024/
│   │   ├── 01/
│   │   │   ├── mfa-audit-20240115.log
│   │   │   └── ...
│   │   └── ...
│   └── ...
├── backups/                  # Резервные копии
│   ├── daily/
│   ├── weekly/
│   └── monthly/
└── temp/                     # Временные файлы
```

#### File-based MFA Storage Implementation
```go
// storage/file_mfa_storage.go - файловое хранилище MFA
type FileMFAStorage struct {
    dataDir     string
    usersDir    string
    policiesDir string
    auditDir    string
    backupDir   string
    
    // Конфигурация
    fileMode    os.FileMode
    dirMode     os.FileMode
    
    // Синхронизация
    mutex       sync.RWMutex
    
    // Шифрование
    encryptor   *DataEncryptor
}

func NewFileMFAStorage(dataDir string, encryptionKey []byte) (*FileMFAStorage, error) {
    storage := &FileMFAStorage{
        dataDir:     dataDir,
        usersDir:    filepath.Join(dataDir, "users"),
        policiesDir: filepath.Join(dataDir, "policies"),
        auditDir:    filepath.Join(dataDir, "audit"),
        backupDir:   filepath.Join(dataDir, "backups"),
        fileMode:    0600, // Только владелец может читать/писать
        dirMode:     0700, // Только владелец может входить в директорию
        encryptor:   NewDataEncryptor(encryptionKey),
    }
    
    // Создание необходимых директорий
    dirs := []string{storage.usersDir, storage.policiesDir, storage.auditDir, storage.backupDir}
    for _, dir := range dirs {
        if err := os.MkdirAll(dir, storage.dirMode); err != nil {
            return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
        }
    }
    
    // Запуск фоновых задач
    go storage.startBackgroundTasks()
    
    return storage, nil
}

func (fs *FileMFAStorage) StoreMFAData(userID string, data *MFAUserData) error {
    fs.mutex.Lock()
    defer fs.mutex.Unlock()
    
    // Валидация данных
    if err := data.Validate(); err != nil {
        return fmt.Errorf("invalid MFA data: %w", err)
    }
    
    // Сериализация в JSON
    jsonData, err := json.MarshalIndent(data, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal MFA data: %w", err)
    }
    
    // Шифрование данных
    encryptedData, err := fs.encryptor.Encrypt(jsonData)
    if err != nil {
        return fmt.Errorf("failed to encrypt MFA data: %w", err)
    }
    
    // Определение пути к файлу
    filename := fs.getUserFilename(userID)
    
    // Создание резервной копии существующего файла
    if _, err := os.Stat(filename); err == nil {
        backupFilename := filename + ".backup." + time.Now().Format("20060102150405")
        if err := fs.copyFile(filename, backupFilename); err != nil {
            log.Printf("Warning: failed to create backup: %v", err)
        }
    }
    
    // Атомарная запись через временный файл
    tempFilename := filename + ".tmp"
    if err := os.WriteFile(tempFilename, encryptedData, fs.fileMode); err != nil {
        return fmt.Errorf("failed to write temp file: %w", err)
    }
    
    // Атомарное переименование
    if err := os.Rename(tempFilename, filename); err != nil {
        os.Remove(tempFilename) // Очистка при ошибке
        return fmt.Errorf("failed to rename temp file: %w", err)
    }
    
    // Логирование операции
    fs.logStorageOperation("store", userID, nil)
    
    return nil
}

func (fs *FileMFAStorage) GetMFAData(userID string) (*MFAUserData, error) {
    fs.mutex.RLock()
    defer fs.mutex.RUnlock()
    
    filename := fs.getUserFilename(userID)
    
    // Чтение зашифрованных данных
    encryptedData, err := os.ReadFile(filename)
    if err != nil {
        if os.IsNotExist(err) {
            return nil, &MFAError{
                Code:    MFAErrorNotFound,
                Message: "MFA data not found for user",
                UserID:  userID,
            }
        }
        return nil, fmt.Errorf("failed to read MFA data file: %w", err)
    }
    
    // Расшифровка данных
    jsonData, err := fs.encryptor.Decrypt(encryptedData)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt MFA data: %w", err)
    }
    
    // Десериализация из JSON
    var data MFAUserData
    if err := json.Unmarshal(jsonData, &data); err != nil {
        return nil, fmt.Errorf("failed to unmarshal MFA data: %w", err)
    }
    
    // Валидация загруженных данных
    if err := data.Validate(); err != nil {
        return nil, fmt.Errorf("invalid stored MFA data: %w", err)
    }
    
    return &data, nil
}

func (fs *FileMFAStorage) getUserFilename(userID string) string {
    // Безопасное имя файла (замена небезопасных символов)
    safeUserID := strings.ReplaceAll(userID, "/", "_")
    safeUserID = strings.ReplaceAll(safeUserID, "\\", "_")
    safeUserID = strings.ReplaceAll(safeUserID, "..", "_")
    
    return filepath.Join(fs.usersDir, safeUserID+".json")
}

func (fs *FileMFAStorage) startBackgroundTasks() {
    // Периодическое создание резервных копий
    go fs.periodicBackup()
    
    // Очистка старых файлов
    go fs.cleanup()
    
    // Проверка целостности данных
    go fs.integrityCheck()
}

func (fs *FileMFAStorage) periodicBackup() {
    ticker := time.NewTicker(24 * time.Hour) // Ежедневные бэкапы
    defer ticker.Stop()
    
    for range ticker.C {
        if err := fs.createBackup(); err != nil {
            log.Printf("Backup failed: %v", err)
        }
    }
}

func (fs *FileMFAStorage) createBackup() error {
    timestamp := time.Now().Format("20060102_150405")
    backupPath := filepath.Join(fs.backupDir, "daily", timestamp)
    
    if err := os.MkdirAll(backupPath, fs.dirMode); err != nil {
        return fmt.Errorf("failed to create backup directory: %w", err)
    }
    
    // Копирование всех пользовательских файлов
    return filepath.Walk(fs.usersDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        
        if info.IsDir() {
            return nil
        }
        
        relPath, err := filepath.Rel(fs.usersDir, path)
        if err != nil {
            return err
        }
        
        destPath := filepath.Join(backupPath, relPath)
        return fs.copyFile(path, destPath)
    })
}
```

## External Systems (Внешние системы)

### IAM Backend Integration
```plantuml
System_Ext(iam_backend, "IAM Backend", "LDAP/Vault/Database", "User identity provider")
```

**Реализация интеграции с IAM:**
```go
// integration/iam_backend.go - интеграция с внешним IAM
type IAMBackend interface {
    AuthenticateUser(username, password string) (*UserInfo, error)
    GetUserInfo(userID string) (*UserInfo, error)
    GetUserRoles(userID string) ([]string, error)
    IsUserActive(userID string) (bool, error)
    GetMFARequirements(userID string) (*MFARequirements, error)
}

// LDAP реализация
type LDAPBackend struct {
    conn     *ldap.Conn
    config   *LDAPConfig
    connPool *ConnectionPool
}

func (lb *LDAPBackend) GetMFARequirements(userID string) (*MFARequirements, error) {
    // Поиск пользователя в LDAP
    searchRequest := ldap.NewSearchRequest(
        lb.config.BaseDN,
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        0, 0, false,
        fmt.Sprintf("(uid=%s)", userID),
        []string{"memberOf", "mfaRequired", "mfaExempt"},
        nil,
    )
    
    sr, err := lb.conn.Search(searchRequest)
    if err != nil {
        return nil, fmt.Errorf("LDAP search failed: %w", err)
    }
    
    if len(sr.Entries) == 0 {
        return &MFARequirements{Required: false}, nil
    }
    
    entry := sr.Entries[0]
    
    // Проверка прямого требования MFA
    if mfaRequired := entry.GetAttributeValue("mfaRequired"); mfaRequired == "true" {
        return &MFARequirements{Required: true, Reason: "direct_requirement"}, nil
    }
    
    // Проверка исключения из MFA
    if mfaExempt := entry.GetAttributeValue("mfaExempt"); mfaExempt == "true" {
        return &MFARequirements{Required: false, Reason: "exempt"}, nil
    }
    
    // Проверка требования по группам
    groups := entry.GetAttributeValues("memberOf")
    for _, group := range groups {
        if lb.isGroupRequiresMFA(group) {
            return &MFARequirements{
                Required: true,
                Reason:   "group_requirement",
                Groups:   []string{group},
            }, nil
        }
    }
    
    return &MFARequirements{Required: false}, nil
}
```

Deployment Diagram Task 2 обеспечивает полное понимание физической архитектуры MFA Enhanced S3 Gateway системы и служит практическим руководством для развертывания в производственной среде, показывая как архитектурные компоненты размещаются на реальной инфраструктуре с учетом безопасности многофакторной аутентификации.