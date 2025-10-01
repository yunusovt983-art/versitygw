# Подробное объяснение Container Diagram Task 2 - MFA Enhanced S3 Gateway

## Назначение диаграммы

Container Diagram для Task 2 детализирует внутреннюю архитектуру MFA Enhanced S3 Gateway системы, показывая основные контейнеры (приложения/сервисы), их технологии и взаимодействие. Эта диаграмма служит мостом между высокоуровневым контекстом и детальной реализацией MFA компонентов.

## Структура PlantUML и архитектурные решения

### Заголовок и участники
```plantuml
@startuml Task2_Container_Diagram
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Container.puml
title Container Diagram - MFA Enhanced S3 Gateway (Task 2)

Person(s3_user, "S3 API User", "User with MFA-enabled account")
Person(admin_user, "System Administrator", "Manages MFA configurations")
```

**Архитектурное значение:**
- Фокус на внутренней структуре MFA системы
- Показывает технологические границы между компонентами

## Основные контейнеры системы

### 1. S3 API Server
```plantuml
Container(s3_api_server, "S3 API Server", "Go/Fiber", "Main S3-compatible API server with MFA integration")
```

**Связь с реализацией:**
```go
// main.go - основной сервер S3 API с MFA интеграцией
type S3APIServer struct {
    app         *fiber.App
    mfaService  MFAService
    authService AuthService
    s3Backend   S3Backend
    config      *ServerConfig
    auditLogger AuditLogger
}

func NewS3APIServer(config *ServerConfig) (*S3APIServer, error) {
    app := fiber.New(fiber.Config{
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
        ErrorHandler: mfaErrorHandler,
    })
    
    // Инициализация MFA сервиса
    mfaStorage, err := NewFileMFAStorage(config.MFA.DataDir)
    if err != nil {
        return nil, fmt.Errorf("failed to create MFA storage: %w", err)
    }
    
    mfaService := NewMFAService(mfaStorage, config.MFA)
    
    server := &S3APIServer{
        app:         app,
        mfaService:  mfaService,
        authService: NewAuthService(config.Auth),
        s3Backend:   NewS3Backend(config.S3),
        config:      config,
        auditLogger: NewAuditLogger(config.Audit),
    }
    
    server.setupMiddleware()
    server.setupRoutes()
    return server, nil
}

func (s *S3APIServer) setupMiddleware() {
    // Базовые middleware
    s.app.Use(logger.New())
    s.app.Use(recover.New())
    s.app.Use(cors.New())
    
    // AWS Signature V4 аутентификация
    s.app.Use(NewAWSAuthMiddleware(s.authService))
    
    // MFA middleware (применяется после базовой аутентификации)
    s.app.Use(NewMFAMiddleware(s.mfaService, s.config.MFA))
    
    // Аудит middleware
    s.app.Use(NewAuditMiddleware(s.auditLogger))
}

func (s *S3APIServer) setupRoutes() {
    // MFA управление endpoints
    mfa := s.app.Group("/mfa")
    mfa.Post("/setup", s.handleMFASetup)
    mfa.Post("/enable", s.handleMFAEnable)
    mfa.Post("/disable", s.handleMFADisable)
    mfa.Get("/status", s.handleMFAStatus)
    mfa.Post("/backup-codes", s.handleGenerateBackupCodes)
    mfa.Post("/validate", s.handleValidateMFA)
    
    // S3 API endpoints (защищенные MFA)
    s.app.Get("/:bucket", s.handleListObjects)
    s.app.Get("/:bucket/:object", s.handleGetObject)
    s.app.Put("/:bucket/:object", s.handlePutObject)
    s.app.Delete("/:bucket/:object", s.handleDeleteObject)
    s.app.Head("/:bucket/:object", s.handleHeadObject)
    
    // Bucket operations
    s.app.Put("/:bucket", s.handleCreateBucket)
    s.app.Delete("/:bucket", s.handleDeleteBucket)
}
```

## Authentication Layer (Слой аутентификации)

### Enhanced Authentication
```plantuml
Container(enhanced_auth, "Enhanced Authentication", "Go Middleware", "V4 signature validation with MFA integration")
```

**Связь с реализацией:**
```go
// middleware/enhanced_auth.go - расширенная аутентификация
type EnhancedAuthMiddleware struct {
    authService AuthService
    mfaService  MFAService
    config      *AuthConfig
}

func NewEnhancedAuthMiddleware(authService AuthService, mfaService MFAService, config *AuthConfig) *EnhancedAuthMiddleware {
    return &EnhancedAuthMiddleware{
        authService: authService,
        mfaService:  mfaService,
        config:      config,
    }
}

func (eam *EnhancedAuthMiddleware) Handler() fiber.Handler {
    return func(c *fiber.Ctx) error {
        startTime := time.Now()
        
        // 1. Валидация AWS Signature V4
        account, err := eam.validateAWSSignature(c)
        if err != nil {
            eam.recordMetric("auth_signature_failed", time.Since(startTime))
            return c.Status(401).JSON(fiber.Map{
                "error": "Invalid AWS signature",
                "code":  "SIGNATURE_INVALID",
            })
        }
        
        // 2. Проверка активности пользователя
        active, err := eam.authService.IsUserActive(account.UserID)
        if err != nil || !active {
            eam.recordMetric("auth_user_inactive", time.Since(startTime))
            return c.Status(401).JSON(fiber.Map{
                "error": "User account inactive",
                "code":  "USER_INACTIVE",
            })
        }
        
        // 3. Сохранение информации о пользователе в контексте
        c.Locals("account", account)
        c.Locals("auth_time", startTime)
        
        eam.recordMetric("auth_signature_success", time.Since(startTime))
        return c.Next()
    }
}

func (eam *EnhancedAuthMiddleware) validateAWSSignature(c *fiber.Ctx) (*Account, error) {
    // Извлечение Authorization заголовка
    authHeader := c.Get("Authorization")
    if authHeader == "" {
        return nil, errors.New("missing Authorization header")
    }
    
    // Парсинг AWS Signature V4
    signature, err := parseAWSSignatureV4(authHeader)
    if err != nil {
        return nil, fmt.Errorf("invalid signature format: %w", err)
    }
    
    // Получение учетных данных пользователя
    credentials, err := eam.authService.GetCredentials(signature.AccessKeyID)
    if err != nil {
        return nil, fmt.Errorf("invalid access key: %w", err)
    }
    
    // Валидация подписи
    if err := eam.validateSignature(c, signature, credentials); err != nil {
        return nil, fmt.Errorf("signature validation failed: %w", err)
    }
    
    // Создание объекта Account
    account := &Account{
        UserID:      credentials.UserID,
        AccessKeyID: signature.AccessKeyID,
        DisplayName: credentials.DisplayName,
        Email:       credentials.Email,
    }
    
    return account, nil
}

func (eam *EnhancedAuthMiddleware) validateSignature(c *fiber.Ctx, signature *AWSSignatureV4, credentials *Credentials) error {
    // Построение строки для подписи
    stringToSign := eam.buildStringToSign(c, signature)
    
    // Вычисление ожидаемой подписи
    expectedSignature := eam.calculateSignature(stringToSign, credentials.SecretKey, signature)
    
    // Сравнение подписей (constant time для безопасности)
    if subtle.ConstantTimeCompare([]byte(signature.Signature), []byte(expectedSignature)) != 1 {
        return errors.New("signature mismatch")
    }
    
    return nil
}
```

### MFA Middleware
```plantuml
Container(mfa_middleware, "MFA Middleware", "Go Middleware", "MFA token validation and enforcement")
```

**Связь с реализацией:**
```go
// middleware/mfa.go - MFA middleware
type MFAMiddleware struct {
    mfaService MFAService
    config     *MFAConfig
    metrics    *MFAMetrics
}

func NewMFAMiddleware(mfaService MFAService, config *MFAConfig) *MFAMiddleware {
    return &MFAMiddleware{
        mfaService: mfaService,
        config:     config,
        metrics:    NewMFAMetrics(),
    }
}

func (mm *MFAMiddleware) Handler() fiber.Handler {
    return func(c *fiber.Ctx) error {
        startTime := time.Now()
        
        // Получение информации о пользователе из предыдущего middleware
        account := c.Locals("account").(*Account)
        
        // Проверка требования MFA для пользователя
        required, err := mm.mfaService.IsMFARequired(account.UserID)
        if err != nil {
            mm.metrics.MFACheckErrors.Inc()
            return c.Status(500).JSON(fiber.Map{
                "error": "MFA requirement check failed",
                "code":  "MFA_CHECK_ERROR",
            })
        }
        
        if !required {
            // MFA не требуется для этого пользователя
            c.Locals("mfa_verified", true)
            c.Locals("mfa_required", false)
            mm.metrics.MFANotRequired.Inc()
            return c.Next()
        }
        
        c.Locals("mfa_required", true)
        
        // Извлечение MFA токена из запроса
        mfaToken := mm.extractMFAToken(c)
        if mfaToken == "" {
            mm.metrics.MFATokenMissing.Inc()
            return c.Status(401).JSON(fiber.Map{
                "error": "MFA token required",
                "code":  "MFA_TOKEN_REQUIRED",
                "details": map[string]interface{}{
                    "header": "X-Amz-MFA",
                    "format": "TOTP token or backup code",
                },
            })
        }
        
        // Валидация MFA токена
        if err := mm.mfaService.ValidateTOTP(account.UserID, mfaToken); err != nil {
            mm.handleMFAValidationError(c, account.UserID, err)
            return nil // Ответ уже отправлен в handleMFAValidationError
        }
        
        // MFA успешно проверен
        c.Locals("mfa_verified", true)
        c.Locals("mfa_token_used", mfaToken)
        mm.metrics.MFAValidationSuccess.Inc()
        mm.recordLatency("mfa_validation_success", time.Since(startTime))
        
        return c.Next()
    }
}

func (mm *MFAMiddleware) extractMFAToken(c *fiber.Ctx) string {
    // Проверка заголовка X-Amz-MFA (основной способ)
    if token := c.Get("X-Amz-MFA"); token != "" {
        return token
    }
    
    // Проверка query параметра (альтернативный способ)
    if token := c.Query("mfa-token"); token != "" {
        return token
    }
    
    // Проверка в теле запроса для POST запросов
    if c.Method() == "POST" {
        if token := c.FormValue("mfa_token"); token != "" {
            return token
        }
    }
    
    return ""
}

func (mm *MFAMiddleware) handleMFAValidationError(c *fiber.Ctx, userID string, err error) {
    mm.metrics.MFAValidationFailure.Inc()
    
    // Определение типа ошибки
    var mfaErr *MFAError
    if errors.As(err, &mfaErr) {
        switch mfaErr.Code {
        case MFAErrorUserLocked:
            mm.metrics.MFAUserLocked.Inc()
            c.Status(429).JSON(fiber.Map{
                "error": "User temporarily locked due to failed MFA attempts",
                "code":  "USER_LOCKED",
                "details": map[string]interface{}{
                    "locked_until": mfaErr.Details["locked_until"],
                    "retry_after":  mfaErr.Details["retry_after"],
                },
            })
            
        case MFAErrorInvalidToken:
            mm.metrics.MFAInvalidToken.Inc()
            c.Status(401).JSON(fiber.Map{
                "error": "Invalid MFA token",
                "code":  "INVALID_MFA_TOKEN",
                "details": map[string]interface{}{
                    "attempts_remaining": mfaErr.Details["attempts_remaining"],
                },
            })
            
        case MFAErrorNotEnabled:
            mm.metrics.MFANotEnabled.Inc()
            c.Status(400).JSON(fiber.Map{
                "error": "MFA not enabled for user",
                "code":  "MFA_NOT_ENABLED",
                "details": map[string]interface{}{
                    "setup_url": "/mfa/setup",
                },
            })
            
        default:
            c.Status(500).JSON(fiber.Map{
                "error": "MFA validation error",
                "code":  "MFA_VALIDATION_ERROR",
            })
        }
    } else {
        c.Status(500).JSON(fiber.Map{
            "error": "Internal MFA error",
            "code":  "INTERNAL_MFA_ERROR",
        })
    }
}
```

## MFA Core Services (Основные MFA сервисы)

### MFA Service
```plantuml
Container(mfa_service, "MFA Service", "Go Service", "Core MFA business logic and operations")
```

**Связь с реализацией:**
```go
// service/mfa_service.go - основной MFA сервис
type MFAService interface {
    GenerateSecret(userID string) (*MFASecret, error)
    EnableMFA(userID, token string) error
    DisableMFA(userID string) error
    ValidateTOTP(userID, token string) error
    GetMFAStatus(userID string) (*MFAStatus, error)
    GenerateBackupCodes(userID string) ([]string, error)
    ValidateBackupCode(userID, code string) error
    IsMFARequired(userID string) (bool, error)
    GetMFAPolicy() (*MFAPolicy, error)
    SetMFAPolicy(policy *MFAPolicy) error
}

type MFAServiceImpl struct {
    storage         MFAStorage
    totpGenerator   *TOTPGenerator
    qrGenerator     *QRCodeGenerator
    backupManager   *BackupCodeManager
    lockoutManager  *LockoutManager
    policyEvaluator *PolicyEvaluator
    config          *MFAConfig
    auditLogger     AuditLogger
    metrics         *MFAMetrics
}

func NewMFAService(storage MFAStorage, config *MFAConfig) *MFAServiceImpl {
    return &MFAServiceImpl{
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
}

func (ms *MFAServiceImpl) GenerateSecret(userID string) (*MFASecret, error) {
    // Проверка существующего MFA
    existing, err := ms.storage.GetMFAData(userID)
    if err == nil && existing.Enabled {
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
    
    // Создание имени аккаунта для TOTP приложения
    accountName := fmt.Sprintf("%s@%s", userID, ms.config.Issuer)
    
    // Генерация QR кода
    qrCode, err := ms.qrGenerator.GenerateQRCode(secret, accountName, ms.config.Issuer)
    if err != nil {
        return nil, fmt.Errorf("failed to generate QR code: %w", err)
    }
    
    // Создание MFA секрета
    mfaSecret := &MFASecret{
        Secret:      secret,
        QRCode:      qrCode,
        BackupCodes: backupCodes,
        Issuer:      ms.config.Issuer,
        AccountName: accountName,
        GeneratedAt: time.Now(),
    }
    
    // Сохранение временных данных (не активированных)
    userData := &MFAUserData{
        UserID:      userID,
        Secret:      secret,
        BackupCodes: ms.backupManager.HashBackupCodes(backupCodes),
        Enabled:     false,
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
    }
    
    if err := ms.storage.StoreMFAData(userID, userData); err != nil {
        return nil, fmt.Errorf("failed to store MFA data: %w", err)
    }
    
    // Логирование события
    ms.auditLogger.LogMFAEvent(context.Background(), "mfa_secret_generated", userID, map[string]interface{}{
        "account_name": accountName,
        "backup_codes_count": len(backupCodes),
    })
    
    ms.metrics.MFASecretsGenerated.Inc()
    return mfaSecret, nil
}

func (ms *MFAServiceImpl) ValidateTOTP(userID, token string) error {
    startTime := time.Now()
    
    // Получение данных MFA пользователя
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
        ms.metrics.MFANotEnabledAttempts.Inc()
        return &MFAError{
            Code:    MFAErrorNotEnabled,
            Message: "MFA not enabled for user",
            UserID:  userID,
        }
    }
    
    // Проверка блокировки пользователя
    if userData.LockedUntil != nil && time.Now().Before(*userData.LockedUntil) {
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
    
    // Сначала попробовать валидацию как TOTP токен
    if err := ms.totpGenerator.ValidateTOTP(userData.Secret, token, time.Now()); err == nil {
        // TOTP токен валиден
        return ms.handleSuccessfulValidation(userID, userData, "totp", startTime)
    }
    
    // Если TOTP не прошел, попробовать как backup код
    if ms.backupManager.ValidateBackupCode(token, userData.BackupCodes) {
        // Backup код валиден - удалить его из списка
        userData.BackupCodes = ms.backupManager.RemoveUsedBackupCode(token, userData.BackupCodes)
        
        // Сохранить обновленные данные
        if err := ms.storage.StoreMFAData(userID, userData); err != nil {
            return fmt.Errorf("failed to update backup codes: %w", err)
        }
        
        return ms.handleSuccessfulValidation(userID, userData, "backup_code", startTime)
    }
    
    // Оба варианта не прошли - обработать неудачную попытку
    return ms.handleFailedValidation(userID, userData, startTime)
}

func (ms *MFAServiceImpl) handleSuccessfulValidation(userID string, userData *MFAUserData, method string, startTime time.Time) error {
    // Сброс счетчика неудачных попыток
    userData.FailedAttempts = 0
    userData.LockedUntil = nil
    userData.LastUsed = time.Now()
    userData.UpdatedAt = time.Now()
    
    // Сохранение обновленных данных
    if err := ms.storage.StoreMFAData(userID, userData); err != nil {
        return fmt.Errorf("failed to update MFA data: %w", err)
    }
    
    // Логирование успешной валидации
    ms.auditLogger.LogMFAEvent(context.Background(), "mfa_validation_success", userID, map[string]interface{}{
        "method":           method,
        "validation_time":  time.Since(startTime).Milliseconds(),
        "backup_codes_remaining": len(userData.BackupCodes),
    })
    
    ms.metrics.MFAValidationSuccess.Inc()
    ms.recordLatency("mfa_validation_success", time.Since(startTime))
    
    return nil
}

func (ms *MFAServiceImpl) handleFailedValidation(userID string, userData *MFAUserData, startTime time.Time) error {
    // Увеличение счетчика неудачных попыток
    userData.FailedAttempts++
    userData.UpdatedAt = time.Now()
    
    // Проверка необходимости блокировки
    if userData.FailedAttempts >= ms.config.Lockout.MaxFailedAttempts {
        lockoutDuration := time.Duration(ms.config.Lockout.LockoutDurationMinutes) * time.Minute
        lockoutUntil := time.Now().Add(lockoutDuration)
        userData.LockedUntil = &lockoutUntil
        userData.FailedAttempts = 0 // Сброс после блокировки
        
        // Логирование блокировки
        ms.auditLogger.LogMFAEvent(context.Background(), "mfa_user_locked", userID, map[string]interface{}{
            "lockout_duration_minutes": ms.config.Lockout.LockoutDurationMinutes,
            "locked_until":            lockoutUntil,
        })
        
        ms.metrics.MFAUserLockouts.Inc()
    }
    
    // Сохранение обновленных данных
    if err := ms.storage.StoreMFAData(userID, userData); err != nil {
        return fmt.Errorf("failed to update failed attempts: %w", err)
    }
    
    // Логирование неудачной попытки
    ms.auditLogger.LogMFAEvent(context.Background(), "mfa_validation_failure", userID, map[string]interface{}{
        "failed_attempts":     userData.FailedAttempts,
        "validation_time":     time.Since(startTime).Milliseconds(),
        "locked":             userData.LockedUntil != nil,
    })
    
    ms.metrics.MFAValidationFailure.Inc()
    
    // Возврат соответствующей ошибки
    if userData.LockedUntil != nil {
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

Container Diagram Task 2 обеспечивает детальное понимание архитектуры MFA Enhanced S3 Gateway системы на уровне контейнеров и служит основой для дальнейшей детализации компонентов, при этом каждый контейнер имеет прямое соответствие в реализации кода многофакторной аутентификации.