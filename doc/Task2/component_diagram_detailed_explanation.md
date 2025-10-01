# Подробное объяснение Component Diagram Task 2 - MFA Service Components

## Назначение диаграммы

Component Diagram для Task 2 показывает внутреннюю структуру MFA Service Container, детализируя компоненты, интерфейсы, модели данных и их взаимодействие. Эта диаграмма служит мостом между архитектурным дизайном контейнеров и фактической реализацией кода MFA системы.

## Структура PlantUML и связь с кодом

### Заголовок и внешние контейнеры
```plantuml
@startuml Task2_Component_Diagram
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Component.puml
title Component Diagram - MFA Service Components (Task 2)

Container(s3_api_server, "S3 API Server", "Go/Fiber", "Main API server")
Container(mfa_middleware, "MFA Middleware", "Go Middleware", "HTTP MFA validation")
```

**Архитектурное значение:**
- Показывает внешний контекст для понимания границ компонентов MFA
- Определяет точки интеграции с основной системой

## Service Interfaces (Интерфейсы сервисов)

### MFAService Interface
```plantuml
Component(mfa_service_interface, "MFAService", "Interface", "Core MFA operations contract")
```

**Связь с реализацией:**
```go
// interfaces/mfa_service.go - основной интерфейс MFA сервиса
type MFAService interface {
    // Управление секретами и настройкой
    GenerateSecret(userID string) (*MFASecret, error)
    EnableMFA(userID, token string) error
    DisableMFA(userID string) error
    
    // Валидация токенов
    ValidateTOTP(userID, token string) error
    ValidateBackupCode(userID, code string) error
    
    // Управление backup кодами
    GenerateBackupCodes(userID string) ([]string, error)
    GetBackupCodesCount(userID string) (int, error)
    
    // Статус и информация
    GetMFAStatus(userID string) (*MFAStatus, error)
    IsMFAEnabled(userID string) (bool, error)
    IsMFARequired(userID string) (bool, error)
    
    // Политики и конфигурация
    GetMFAPolicy() (*MFAPolicy, error)
    SetMFAPolicy(policy *MFAPolicy) error
    EvaluateMFARequirement(userID string, context map[string]interface{}) (bool, error)
    
    // Управление блокировками
    IsUserLocked(userID string) (bool, *time.Time, error)
    UnlockUser(userID string) error
    
    // Аудит и метрики
    GetMFAStatistics() (*MFAStatistics, error)
    GetUserMFAHistory(userID string, limit int) ([]*MFAEvent, error)
}

// Расширенный интерфейс для административных операций
type MFAAdminService interface {
    MFAService
    
    // Административные операции
    ForceDisableMFA(userID string, reason string) error
    ResetMFAForUser(userID string) error
    BulkEnableMFA(userIDs []string) error
    
    // Массовые операции
    GetAllMFAUsers() ([]*MFAUserSummary, error)
    ExportMFAData(format string) ([]byte, error)
    ImportMFAData(data []byte) error
    
    // Системные операции
    PerformMaintenance() error
    ValidateSystemIntegrity() error
}
```

### MFAStorage Interface
```plantuml
Component(mfa_storage_interface, "MFAStorage", "Interface", "Data persistence contract")
```

**Связь с реализацией:**
```go
// interfaces/mfa_storage.go - интерфейс хранения MFA данных
type MFAStorage interface {
    // Основные операции с данными пользователей
    StoreMFAData(userID string, data *MFAUserData) error
    GetMFAData(userID string) (*MFAUserData, error)
    DeleteMFAData(userID string) error
    
    // Массовые операции
    GetAllMFAUsers() ([]string, error)
    GetMFAUsersByStatus(enabled bool) ([]string, error)
    
    // Поиск и фильтрация
    FindMFAUsers(filter *MFAUserFilter) ([]*MFAUserData, error)
    CountMFAUsers(filter *MFAUserFilter) (int, error)
    
    // Политики и конфигурация
    StoreMFAPolicy(policy *MFAPolicy) error
    GetMFAPolicy() (*MFAPolicy, error)
    
    // Аудит и история
    StoreAuditEvent(event *MFAAuditEvent) error
    GetAuditEvents(userID string, limit int) ([]*MFAAuditEvent, error)
    
    // Системные операции
    Backup() error
    Restore(backupPath string) error
    Cleanup(olderThan time.Time) error
    
    // Транзакции и блокировки
    BeginTransaction() (MFATransaction, error)
    Lock(userID string) error
    Unlock(userID string) error
}

// Интерфейс для транзакционных операций
type MFATransaction interface {
    StoreMFAData(userID string, data *MFAUserData) error
    GetMFAData(userID string) (*MFAUserData, error)
    Commit() error
    Rollback() error
}

// Фильтр для поиска пользователей MFA
type MFAUserFilter struct {
    Enabled     *bool      `json:"enabled,omitempty"`
    LockedOnly  bool       `json:"locked_only,omitempty"`
    CreatedAfter *time.Time `json:"created_after,omitempty"`
    CreatedBefore *time.Time `json:"created_before,omitempty"`
    LastUsedAfter *time.Time `json:"last_used_after,omitempty"`
    LastUsedBefore *time.Time `json:"last_used_before,omitempty"`
}
```

## Core Service Implementations (Основные реализации сервисов)

### MFAServiceImpl
```plantuml
Component(mfa_service_impl, "MFAServiceImpl", "Service", "Main MFA service implementation")
```

**Связь с реализацией:**
```go
// service/mfa_service_impl.go - основная реализация MFA сервиса
type MFAServiceImpl struct {
    // Зависимости
    storage         MFAStorage
    totpGenerator   *TOTPGenerator
    qrGenerator     *QRCodeGenerator
    backupManager   *BackupCodeManager
    lockoutManager  *LockoutManager
    policyEvaluator *PolicyEvaluator
    
    // Конфигурация
    config *MFAConfig
    
    // Утилиты
    auditLogger AuditLogger
    metrics     *MFAMetrics
    
    // Синхронизация
    mutex sync.RWMutex
}

func NewMFAServiceImpl(storage MFAStorage, config *MFAConfig) *MFAServiceImpl {
    service := &MFAServiceImpl{
        storage:         storage,
        totpGenerator:   NewTOTPGenerator(config.TOTP),
        qrGenerator:     NewQRCodeGenerator(config.QR),
        backupManager:   NewBackupCodeManager(config.BackupCodes),
        lockoutManager:  NewLockoutManager(config.Lockout),
        policyEvaluator: NewPolicyEvaluator(config.Policy),
        config:          config,
        auditLogger:     NewAuditLogger(config.Audit),
        metrics:         NewMFAMetrics(),
    }
    
    // Запуск фоновых задач
    go service.startBackgroundTasks()
    
    return service
}

func (ms *MFAServiceImpl) EnableMFA(userID, token string) error {
    ms.mutex.Lock()
    defer ms.mutex.Unlock()
    
    // Получение временных данных MFA
    userData, err := ms.storage.GetMFAData(userID)
    if err != nil {
        return &MFAError{
            Code:    MFAErrorNotSetup,
            Message: "MFA not set up for user. Call GenerateSecret first.",
            UserID:  userID,
        }
    }
    
    if userData.Enabled {
        return &MFAError{
            Code:    MFAErrorAlreadyEnabled,
            Message: "MFA already enabled for user",
            UserID:  userID,
        }
    }
    
    // Валидация предоставленного токена
    if err := ms.totpGenerator.ValidateTOTP(userData.Secret, token, time.Now()); err != nil {
        ms.auditLogger.LogMFAEvent(context.Background(), "mfa_enable_failed", userID, map[string]interface{}{
            "reason": "invalid_token",
            "error":  err.Error(),
        })
        
        return &MFAError{
            Code:    MFAErrorInvalidToken,
            Message: "Invalid TOTP token provided",
            UserID:  userID,
        }
    }
    
    // Активация MFA
    userData.Enabled = true
    userData.EnabledAt = time.Now()
    userData.UpdatedAt = time.Now()
    
    // Сохранение активированных данных
    if err := ms.storage.StoreMFAData(userID, userData); err != nil {
        return fmt.Errorf("failed to enable MFA: %w", err)
    }
    
    // Логирование успешной активации
    ms.auditLogger.LogMFAEvent(context.Background(), "mfa_enabled", userID, map[string]interface{}{
        "enabled_at":           userData.EnabledAt,
        "backup_codes_count":   len(userData.BackupCodes),
    })
    
    ms.metrics.MFAEnabled.Inc()
    return nil
}

func (ms *MFAServiceImpl) IsMFARequired(userID string) (bool, error) {
    // Получение политики MFA
    policy, err := ms.storage.GetMFAPolicy()
    if err != nil {
        return false, fmt.Errorf("failed to get MFA policy: %w", err)
    }
    
    if !policy.Active {
        return false, nil // Политика MFA отключена
    }
    
    // Использование policy evaluator для определения требования
    context := map[string]interface{}{
        "user_id": userID,
        "time":    time.Now(),
    }
    
    return ms.policyEvaluator.EvaluateMFARequirement(userID, context)
}

func (ms *MFAServiceImpl) startBackgroundTasks() {
    // Очистка просроченных блокировок
    go ms.cleanupExpiredLockouts()
    
    // Периодическое обновление метрик
    go ms.updateMetrics()
    
    // Очистка старых аудит событий
    go ms.cleanupOldAuditEvents()
}

func (ms *MFAServiceImpl) cleanupExpiredLockouts() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        users, err := ms.storage.GetAllMFAUsers()
        if err != nil {
            continue
        }
        
        for _, userID := range users {
            userData, err := ms.storage.GetMFAData(userID)
            if err != nil {
                continue
            }
            
            if userData.LockedUntil != nil && time.Now().After(*userData.LockedUntil) {
                userData.LockedUntil = nil
                userData.UpdatedAt = time.Now()
                
                ms.storage.StoreMFAData(userID, userData)
                
                ms.auditLogger.LogMFAEvent(context.Background(), "mfa_lockout_expired", userID, map[string]interface{}{
                    "unlocked_at": time.Now(),
                })
            }
        }
    }
}
```

### TOTPGenerator
```plantuml
Component(totp_generator, "TOTPGenerator", "Component", "RFC 6238 TOTP implementation")
```

**Связь с реализацией:**
```go
// components/totp_generator.go - генератор и валидатор TOTP
type TOTPGenerator struct {
    config *TOTPConfig
}

type TOTPConfig struct {
    Issuer        string        `json:"issuer"`
    Period        time.Duration `json:"period"`        // 30 секунд
    Digits        int           `json:"digits"`        // 6 цифр
    Algorithm     string        `json:"algorithm"`     // SHA1, SHA256, SHA512
    Skew          int           `json:"skew"`          // Допустимое отклонение
    SecretLength  int           `json:"secret_length"` // Длина секрета в байтах
}

func NewTOTPGenerator(config *TOTPConfig) *TOTPGenerator {
    // Установка значений по умолчанию
    if config.Period == 0 {
        config.Period = 30 * time.Second
    }
    if config.Digits == 0 {
        config.Digits = 6
    }
    if config.Algorithm == "" {
        config.Algorithm = "SHA1"
    }
    if config.Skew == 0 {
        config.Skew = 1
    }
    if config.SecretLength == 0 {
        config.SecretLength = 20 // 160 бит
    }
    
    return &TOTPGenerator{config: config}
}

func (tg *TOTPGenerator) GenerateSecret() (string, error) {
    // Генерация криптографически стойкого случайного секрета
    secret := make([]byte, tg.config.SecretLength)
    if _, err := rand.Read(secret); err != nil {
        return "", fmt.Errorf("failed to generate random secret: %w", err)
    }
    
    // Кодирование в Base32 без padding для совместимости с TOTP приложениями
    encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
    
    return encoded, nil
}

func (tg *TOTPGenerator) GenerateTOTP(secret string, timestamp time.Time) (string, error) {
    // Декодирование секрета из Base32
    key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
    if err != nil {
        return "", fmt.Errorf("invalid secret format: %w", err)
    }
    
    // Вычисление временного счетчика согласно RFC 6238
    counter := uint64(timestamp.Unix()) / uint64(tg.config.Period.Seconds())
    
    // Выбор хэш-функции
    var hashFunc func() hash.Hash
    switch tg.config.Algorithm {
    case "SHA1":
        hashFunc = sha1.New
    case "SHA256":
        hashFunc = sha256.New
    case "SHA512":
        hashFunc = sha512.New
    default:
        return "", fmt.Errorf("unsupported algorithm: %s", tg.config.Algorithm)
    }
    
    // Генерация HMAC
    h := hmac.New(hashFunc, key)
    binary.Write(h, binary.BigEndian, counter)
    hash := h.Sum(nil)
    
    // Динамическое усечение согласно RFC 4226
    offset := hash[len(hash)-1] & 0x0F
    code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF
    
    // Получение нужного количества цифр
    code = code % uint32(math.Pow10(tg.config.Digits))
    
    return fmt.Sprintf("%0*d", tg.config.Digits, code), nil
}

func (tg *TOTPGenerator) ValidateTOTP(secret, token string, timestamp time.Time) error {
    // Проверка формата токена
    if len(token) != tg.config.Digits {
        return errors.New("invalid token length")
    }
    
    // Проверка что токен содержит только цифры
    if _, err := strconv.Atoi(token); err != nil {
        return errors.New("token must contain only digits")
    }
    
    // Проверка текущего временного окна
    currentToken, err := tg.GenerateTOTP(secret, timestamp)
    if err != nil {
        return fmt.Errorf("failed to generate current token: %w", err)
    }
    
    if subtle.ConstantTimeCompare([]byte(token), []byte(currentToken)) == 1 {
        return nil // Токен валиден для текущего окна
    }
    
    // Проверка предыдущих и следующих временных окон (clock skew tolerance)
    for i := 1; i <= tg.config.Skew; i++ {
        // Предыдущее временное окно
        prevTime := timestamp.Add(-time.Duration(i) * tg.config.Period)
        prevToken, err := tg.GenerateTOTP(secret, prevTime)
        if err == nil && subtle.ConstantTimeCompare([]byte(token), []byte(prevToken)) == 1 {
            return nil
        }
        
        // Следующее временное окно
        nextTime := timestamp.Add(time.Duration(i) * tg.config.Period)
        nextToken, err := tg.GenerateTOTP(secret, nextTime)
        if err == nil && subtle.ConstantTimeCompare([]byte(token), []byte(nextToken)) == 1 {
            return nil
        }
    }
    
    return errors.New("invalid TOTP token")
}

// Генерация URI для TOTP приложений
func (tg *TOTPGenerator) GenerateTOTPURI(secret, accountName string) string {
    params := url.Values{}
    params.Set("secret", secret)
    params.Set("issuer", tg.config.Issuer)
    params.Set("algorithm", tg.config.Algorithm)
    params.Set("digits", strconv.Itoa(tg.config.Digits))
    params.Set("period", strconv.Itoa(int(tg.config.Period.Seconds())))
    
    uri := fmt.Sprintf("otpauth://totp/%s:%s?%s",
        url.QueryEscape(tg.config.Issuer),
        url.QueryEscape(accountName),
        params.Encode(),
    )
    
    return uri
}
```

Component Diagram Task 2 обеспечивает детальное понимание внутренней структуры MFA Service компонентов и служит прямым руководством для реализации кода, показывая как архитектурные решения транслируются в конкретные Go структуры и интерфейсы.