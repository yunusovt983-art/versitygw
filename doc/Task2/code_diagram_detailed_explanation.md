# Подробное объяснение Code Diagram Task 2 - MFA Implementation Classes

## Назначение диаграммы

Code Diagram для Task 2 представляет самый детальный уровень архитектуры MFA Enhanced S3 Gateway системы, показывая конкретные Go структуры, интерфейсы, методы и их взаимосвязи. Эта диаграмма служит прямым мостом между архитектурным дизайном и фактической реализацией кода MFA системы.

## Структура PlantUML и реализация

### Заголовок и ключевые особенности
```plantuml
@startuml Task2_Code_Diagram
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Component.puml
title Code Diagram - MFA Implementation Classes and Interfaces (Task 2)
```

**Архитектурное значение:**
- Документирует конкретные Go структуры и интерфейсы
- Показывает методы и их сигнатуры
- Демонстрирует взаимосвязи на уровне кода

## Core Interfaces (Основные интерфейсы)

### MFAService Interface
```plantuml
Component(mfa_service_interface, "MFAService", "Interface", "GenerateSecret(), ValidateTOTP(), EnableMFA(), GetMFAStatus()")
```

**Полная реализация интерфейса:**
```go
// interfaces/mfa_service.go - основной интерфейс MFA сервиса
type MFAService interface {
    // Управление секретами и настройкой MFA
    GenerateSecret(userID string) (*MFASecret, error)
    EnableMFA(userID, token string) error
    DisableMFA(userID string) error
    
    // Валидация токенов
    ValidateTOTP(userID, token string) error
    ValidateBackupCode(userID, code string) error
    
    // Статус и информация
    GetMFAStatus(userID string) (*MFAStatus, error)
    IsMFAEnabled(userID string) (bool, error)
    IsMFARequired(userID string) (bool, error)
    
    // Управление backup кодами
    GenerateBackupCodes(userID string) ([]string, error)
    GetBackupCodesCount(userID string) (int, error)
    
    // Политики
    GetMFAPolicy() (*MFAPolicy, error)
    SetMFAPolicy(policy *MFAPolicy) error
    
    // Блокировки и безопасность
    IsUserLocked(userID string) (bool, *time.Time, error)
    UnlockUser(userID string) error
    
    // Статистика
    GetMFAStatistics() (*MFAStatistics, error)
}

// Расширенные методы для конкретной реализации
type MFAServiceExtended interface {
    MFAService
    
    // Внутренние методы для middleware
    ValidateMFAToken(userID, token string) (*MFAValidationResult, error)
    RecordMFAAttempt(userID string, success bool, method string) error
    
    // Административные операции
    ForceResetMFA(userID string, reason string) error
    BulkOperations(operation string, userIDs []string) error
    
    // Системные операции
    HealthCheck() error
    GetSystemMetrics() (*SystemMetrics, error)
}
```

### MFAStorage Interface
```plantuml
Component(mfa_storage_interface, "MFAStorage", "Interface", "StoreMFAData(), GetMFAData(), DeleteMFAData()")
```

**Полная реализация интерфейса:**
```go
// interfaces/mfa_storage.go - интерфейс хранения MFA данных
type MFAStorage interface {
    // Основные CRUD операции
    StoreMFAData(userID string, data *MFAUserData) error
    GetMFAData(userID string) (*MFAUserData, error)
    DeleteMFAData(userID string) error
    ExistsMFAData(userID string) (bool, error)
    
    // Массовые операции
    GetAllMFAUsers() ([]string, error)
    GetMFAUsersByStatus(enabled bool) ([]string, error)
    CountMFAUsers() (int, error)
    
    // Политики
    StoreMFAPolicy(policy *MFAPolicy) error
    GetMFAPolicy() (*MFAPolicy, error)
    
    // Аудит
    StoreAuditEvent(event *MFAAuditEvent) error
    GetAuditEvents(userID string, limit int) ([]*MFAAuditEvent, error)
    
    // Системные операции
    Backup(path string) error
    Restore(path string) error
    Cleanup(olderThan time.Time) error
    
    // Транзакции
    BeginTransaction() (MFATransaction, error)
}

// Интерфейс транзакций
type MFATransaction interface {
    StoreMFAData(userID string, data *MFAUserData) error
    GetMFAData(userID string) (*MFAUserData, error)
    Commit() error
    Rollback() error
}
```

## Data Models (Модели данных)

### MFASecret
```plantuml
Component(mfa_secret, "MFASecret", "Struct", "Secret, QRCode, BackupCodes, Issuer, AccountName")
```

**Полная реализация структуры:**
```go
// models/mfa_secret.go - структура секрета MFA для настройки
type MFASecret struct {
    Secret      string    `json:"secret"`       // Base32 encoded secret
    QRCode      string    `json:"qr_code"`      // Base64 encoded PNG QR code
    BackupCodes []string  `json:"backup_codes"` // Одноразовые backup коды
    Issuer      string    `json:"issuer"`       // Название организации
    AccountName string    `json:"account_name"` // Имя аккаунта для TOTP приложения
    GeneratedAt time.Time `json:"generated_at"` // Время генерации
    ExpiresAt   time.Time `json:"expires_at"`   // Время истечения (для временных секретов)
}

// Валидация MFA секрета
func (ms *MFASecret) Validate() error {
    if ms.Secret == "" {
        return errors.New("secret is required")
    }
    
    // Проверка формата Base32
    if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(ms.Secret); err != nil {
        return fmt.Errorf("invalid secret format: %w", err)
    }
    
    if ms.Issuer == "" {
        return errors.New("issuer is required")
    }
    
    if ms.AccountName == "" {
        return errors.New("account name is required")
    }
    
    if len(ms.BackupCodes) == 0 {
        return errors.New("backup codes are required")
    }
    
    return nil
}

// Проверка истечения срока действия
func (ms *MFASecret) IsExpired() bool {
    return !ms.ExpiresAt.IsZero() && time.Now().After(ms.ExpiresAt)
}

// Генерация TOTP URI для QR кода
func (ms *MFASecret) GenerateTOTPURI() string {
    params := url.Values{}
    params.Set("secret", ms.Secret)
    params.Set("issuer", ms.Issuer)
    
    return fmt.Sprintf("otpauth://totp/%s:%s?%s",
        url.QueryEscape(ms.Issuer),
        url.QueryEscape(ms.AccountName),
        params.Encode(),
    )
}
```

### MFAStatus
```plantuml
Component(mfa_status, "MFAStatus", "Struct", "Enabled, LastUsed, BackupCodesRemaining, FailedAttempts")
```

**Полная реализация структуры:**
```go
// models/mfa_status.go - статус MFA пользователя
type MFAStatus struct {
    UserID               string     `json:"user_id"`
    Enabled              bool       `json:"enabled"`
    Required             bool       `json:"required"`
    LastUsed             *time.Time `json:"last_used,omitempty"`
    BackupCodesRemaining int        `json:"backup_codes_remaining"`
    FailedAttempts       int        `json:"failed_attempts"`
    LockedUntil          *time.Time `json:"locked_until,omitempty"`
    EnabledAt            *time.Time `json:"enabled_at,omitempty"`
    CreatedAt            time.Time  `json:"created_at"`
    UpdatedAt            time.Time  `json:"updated_at"`
    
    // Дополнительная информация
    TotalValidations     int64      `json:"total_validations"`
    SuccessfulValidations int64     `json:"successful_validations"`
    LastValidationMethod string     `json:"last_validation_method,omitempty"` // "totp" или "backup_code"
    
    // Метаданные
    SetupMethod          string                 `json:"setup_method,omitempty"` // "qr_code", "manual"
    DeviceInfo           map[string]interface{} `json:"device_info,omitempty"`
}

// Проверка блокировки пользователя
func (ms *MFAStatus) IsLocked() bool {
    return ms.LockedUntil != nil && time.Now().Before(*ms.LockedUntil)
}

// Получение времени до разблокировки
func (ms *MFAStatus) TimeUntilUnlock() time.Duration {
    if !ms.IsLocked() {
        return 0
    }
    return ms.LockedUntil.Sub(time.Now())
}

// Проверка необходимости предупреждения о backup кодах
func (ms *MFAStatus) ShouldWarnAboutBackupCodes() bool {
    return ms.Enabled && ms.BackupCodesRemaining <= 2
}

// Вычисление коэффициента успешности
func (ms *MFAStatus) SuccessRate() float64 {
    if ms.TotalValidations == 0 {
        return 0.0
    }
    return float64(ms.SuccessfulValidations) / float64(ms.TotalValidations)
}
```

### MFAUserData
```plantuml
Component(mfa_user_data, "MFAUserData", "Struct", "UserID, Secret, BackupCodes, Enabled, LockedUntil")
```

**Полная реализация структуры:**
```go
// models/mfa_user_data.go - персистентные данные MFA пользователя
type MFAUserData struct {
    UserID      string    `json:"user_id"`
    Secret      string    `json:"secret"`       // Base32 encoded secret (зашифрован)
    BackupCodes []string  `json:"backup_codes"` // Хэшированные backup коды
    Enabled     bool      `json:"enabled"`
    
    // Временные метки
    CreatedAt   time.Time  `json:"created_at"`
    UpdatedAt   time.Time  `json:"updated_at"`
    EnabledAt   *time.Time `json:"enabled_at,omitempty"`
    LastUsed    *time.Time `json:"last_used,omitempty"`
    
    // Безопасность и блокировки
    FailedAttempts int        `json:"failed_attempts"`
    LockedUntil    *time.Time `json:"locked_until,omitempty"`
    
    // Статистика
    TotalValidations      int64  `json:"total_validations"`
    SuccessfulValidations int64  `json:"successful_validations"`
    LastValidationMethod  string `json:"last_validation_method,omitempty"`
    
    // Метаданные
    SetupMethod    string                 `json:"setup_method,omitempty"`
    DeviceInfo     map[string]interface{} `json:"device_info,omitempty"`
    IPAddresses    []string               `json:"ip_addresses,omitempty"` // История IP адресов
    UserAgents     []string               `json:"user_agents,omitempty"`  // История User-Agent'ов
    
    // Версионирование для миграций
    Version int `json:"version"`
}

// Валидация данных пользователя
func (mud *MFAUserData) Validate() error {
    if mud.UserID == "" {
        return errors.New("user ID is required")
    }
    
    if mud.Enabled && mud.Secret == "" {
        return errors.New("secret is required for enabled MFA")
    }
    
    if mud.Enabled && len(mud.BackupCodes) == 0 {
        return errors.New("backup codes are required for enabled MFA")
    }
    
    return nil
}

// Проверка блокировки
func (mud *MFAUserData) IsLocked() bool {
    return mud.LockedUntil != nil && time.Now().Before(*mud.LockedUntil)
}

// Сброс блокировки
func (mud *MFAUserData) Unlock() {
    mud.LockedUntil = nil
    mud.FailedAttempts = 0
    mud.UpdatedAt = time.Now()
}

// Увеличение счетчика неудачных попыток
func (mud *MFAUserData) IncrementFailedAttempts(maxAttempts int, lockoutDuration time.Duration) {
    mud.FailedAttempts++
    mud.UpdatedAt = time.Now()
    
    if mud.FailedAttempts >= maxAttempts {
        lockoutUntil := time.Now().Add(lockoutDuration)
        mud.LockedUntil = &lockoutUntil
        mud.FailedAttempts = 0 // Сброс после блокировки
    }
}

// Сброс счетчика неудачных попыток при успешной валидации
func (mud *MFAUserData) ResetFailedAttempts() {
    mud.FailedAttempts = 0
    mud.LockedUntil = nil
    mud.LastUsed = &time.Time{}
    *mud.LastUsed = time.Now()
    mud.SuccessfulValidations++
    mud.TotalValidations++
    mud.UpdatedAt = time.Now()
}

// Клонирование для безопасного использования
func (mud *MFAUserData) Clone() *MFAUserData {
    clone := *mud
    
    // Глубокое копирование слайсов
    clone.BackupCodes = make([]string, len(mud.BackupCodes))
    copy(clone.BackupCodes, mud.BackupCodes)
    
    clone.IPAddresses = make([]string, len(mud.IPAddresses))
    copy(clone.IPAddresses, mud.IPAddresses)
    
    clone.UserAgents = make([]string, len(mud.UserAgents))
    copy(clone.UserAgents, mud.UserAgents)
    
    // Глубокое копирование map
    if mud.DeviceInfo != nil {
        clone.DeviceInfo = make(map[string]interface{})
        for k, v := range mud.DeviceInfo {
            clone.DeviceInfo[k] = v
        }
    }
    
    return &clone
}
```

## Core Logic Classes (Основные классы логики)

### MFAServiceImpl
```plantuml
Component(mfa_service_impl, "MFAServiceImpl", "Class", "Main business logic: secret generation, validation, policy enforcement")
```

**Ключевые методы реализации:**
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
    encryptor   *DataEncryptor
    
    // Синхронизация
    mutex sync.RWMutex
}

// Генерация секрета MFA
func (ms *MFAServiceImpl) GenerateSecret(userID string) (*MFASecret, error) {
    ms.mutex.Lock()
    defer ms.mutex.Unlock()
    
    // Проверка существующего MFA
    if existing, err := ms.storage.GetMFAData(userID); err == nil && existing.Enabled {
        return nil, &MFAError{
            Code:    MFAErrorAlreadyEnabled,
            Message: "MFA already enabled for user",
            UserID:  userID,
        }
    }
    
    // Генерация нового секрета
    secret, err := ms.totpGenerator.GenerateSecret()
    if err != nil {
        return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
    }
    
    // Генерация backup кодов
    backupCodes, err := ms.backupManager.GenerateBackupCodes(ms.config.BackupCodes.Count)
    if err != nil {
        return nil, fmt.Errorf("failed to generate backup codes: %w", err)
    }
    
    // Создание имени аккаунта
    accountName := fmt.Sprintf("%s@%s", userID, ms.config.Issuer)
    
    // Генерация QR кода
    qrCode, err := ms.qrGenerator.GenerateQRCode(secret, accountName, ms.config.Issuer)
    if err != nil {
        return nil, fmt.Errorf("failed to generate QR code: %w", err)
    }
    
    // Шифрование секрета для хранения
    encryptedSecret, err := ms.encryptor.Encrypt(secret)
    if err != nil {
        return nil, fmt.Errorf("failed to encrypt secret: %w", err)
    }
    
    // Хэширование backup кодов
    hashedBackupCodes := ms.backupManager.HashBackupCodes(backupCodes)
    
    // Создание данных пользователя
    userData := &MFAUserData{
        UserID:      userID,
        Secret:      encryptedSecret,
        BackupCodes: hashedBackupCodes,
        Enabled:     false, // Будет активирован после подтверждения
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
        Version:     1,
    }
    
    // Сохранение данных
    if err := ms.storage.StoreMFAData(userID, userData); err != nil {
        return nil, fmt.Errorf("failed to store MFA data: %w", err)
    }
    
    // Создание MFA секрета для возврата
    mfaSecret := &MFASecret{
        Secret:      secret, // Возвращаем незашифрованный для настройки
        QRCode:      qrCode,
        BackupCodes: backupCodes, // Возвращаем незахэшированные для показа пользователю
        Issuer:      ms.config.Issuer,
        AccountName: accountName,
        GeneratedAt: time.Now(),
        ExpiresAt:   time.Now().Add(ms.config.SetupTimeout), // 15 минут на настройку
    }
    
    // Аудит событие
    ms.auditLogger.LogMFAEvent(context.Background(), "mfa_secret_generated", userID, map[string]interface{}{
        "account_name":       accountName,
        "backup_codes_count": len(backupCodes),
        "expires_at":         mfaSecret.ExpiresAt,
    })
    
    ms.metrics.MFASecretsGenerated.Inc()
    return mfaSecret, nil
}

// Валидация TOTP токена
func (ms *MFAServiceImpl) ValidateTOTP(userID, token string) error {
    startTime := time.Now()
    
    // Получение данных пользователя
    userData, err := ms.storage.GetMFAData(userID)
    if err != nil {
        ms.metrics.MFAValidationErrors.Inc()
        return &MFAError{
            Code:    MFAErrorNotEnabled,
            Message: "MFA not enabled for user",
            UserID:  userID,
        }
    }
    
    if !userData.Enabled {
        return &MFAError{
            Code:    MFAErrorNotEnabled,
            Message: "MFA not enabled for user",
            UserID:  userID,
        }
    }
    
    // Проверка блокировки
    if userData.IsLocked() {
        ms.metrics.MFALockedAttempts.Inc()
        return &MFAError{
            Code:    MFAErrorUserLocked,
            Message: "User temporarily locked",
            UserID:  userID,
            Details: map[string]interface{}{
                "locked_until": userData.LockedUntil,
                "retry_after":  userData.LockedUntil.Sub(time.Now()).Seconds(),
            },
        }
    }
    
    // Расшифровка секрета
    decryptedSecret, err := ms.encryptor.Decrypt(userData.Secret)
    if err != nil {
        return fmt.Errorf("failed to decrypt secret: %w", err)
    }
    
    // Попытка валидации как TOTP токен
    if err := ms.totpGenerator.ValidateTOTP(decryptedSecret, token, time.Now()); err == nil {
        return ms.handleSuccessfulValidation(userID, userData, "totp", startTime)
    }
    
    // Попытка валидации как backup код
    if ms.backupManager.ValidateBackupCode(token, userData.BackupCodes) {
        // Удаление использованного backup кода
        userData.BackupCodes = ms.backupManager.RemoveUsedBackupCode(token, userData.BackupCodes)
        
        // Сохранение обновленных данных
        if err := ms.storage.StoreMFAData(userID, userData); err != nil {
            return fmt.Errorf("failed to update backup codes: %w", err)
        }
        
        return ms.handleSuccessfulValidation(userID, userData, "backup_code", startTime)
    }
    
    // Обработка неудачной валидации
    return ms.handleFailedValidation(userID, userData, startTime)
}

// Обработка успешной валидации
func (ms *MFAServiceImpl) handleSuccessfulValidation(userID string, userData *MFAUserData, method string, startTime time.Time) error {
    userData.ResetFailedAttempts()
    userData.LastValidationMethod = method
    
    if err := ms.storage.StoreMFAData(userID, userData); err != nil {
        return fmt.Errorf("failed to update MFA data: %w", err)
    }
    
    // Аудит
    ms.auditLogger.LogMFAEvent(context.Background(), "mfa_validation_success", userID, map[string]interface{}{
        "method":                method,
        "validation_time_ms":    time.Since(startTime).Milliseconds(),
        "backup_codes_remaining": len(userData.BackupCodes),
    })
    
    ms.metrics.MFAValidationSuccess.Inc()
    ms.recordLatency("mfa_validation_success", time.Since(startTime))
    
    return nil
}

// Обработка неудачной валидации
func (ms *MFAServiceImpl) handleFailedValidation(userID string, userData *MFAUserData, startTime time.Time) error {
    userData.IncrementFailedAttempts(
        ms.config.Lockout.MaxFailedAttempts,
        time.Duration(ms.config.Lockout.LockoutDurationMinutes)*time.Minute,
    )
    
    if err := ms.storage.StoreMFAData(userID, userData); err != nil {
        return fmt.Errorf("failed to update failed attempts: %w", err)
    }
    
    // Аудит
    eventType := "mfa_validation_failure"
    if userData.IsLocked() {
        eventType = "mfa_user_locked"
        ms.metrics.MFAUserLockouts.Inc()
    }
    
    ms.auditLogger.LogMFAEvent(context.Background(), eventType, userID, map[string]interface{}{
        "failed_attempts":    userData.FailedAttempts,
        "validation_time_ms": time.Since(startTime).Milliseconds(),
        "locked":            userData.IsLocked(),
    })
    
    ms.metrics.MFAValidationFailure.Inc()
    
    if userData.IsLocked() {
        return &MFAError{
            Code:    MFAErrorUserLocked,
            Message: "User locked due to too many failed attempts",
            UserID:  userID,
            Details: map[string]interface{}{
                "locked_until": userData.LockedUntil,
                "retry_after":  userData.LockedUntil.Sub(time.Now()).Seconds(),
            },
        }
    }
    
    return &MFAError{
        Code:    MFAErrorInvalidToken,
        Message: "Invalid MFA token",
        UserID:  userID,
        Details: map[string]interface{}{
            "attempts_remaining": ms.config.Lockout.MaxFailedAttempts - userData.FailedAttempts,
        },
    }
}
```

Code Diagram Task 2 обеспечивает полное понимание реализации MFA Enhanced S3 Gateway системы на уровне кода и служит прямым руководством для разработчиков, показывая точное соответствие между архитектурными элементами и Go кодом многофакторной аутентификации.