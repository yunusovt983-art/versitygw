# Подробное объяснение Context Diagram Task 2 - MFA Enhanced S3 Gateway

## Назначение диаграммы

Context Diagram для Task 2 показывает систему MFA Enhanced S3 Gateway в контексте пользователей и внешних систем. Эта диаграмма служит мостом между бизнес-требованиями многофакторной аутентификации и техническими решениями, определяя границы системы и ключевые взаимодействия для обеспечения безопасности S3 API.

## Структура PlantUML и связь с кодом

### Заголовок и настройки
```plantuml
@startuml Task2_Context_Diagram
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Context.puml
title System Context Diagram - MFA Enhanced S3 Gateway (Task 2)
```

**Связь с реализацией:**
- Заголовок отражает основную цель Task 2 - интеграцию MFA в S3 Gateway
- Использование C4_Context.puml обеспечивает стандартизированное представление

## Участники системы и их реализация

### 1. S3 API User (Пользователь S3 API)
```plantuml
Person(s3_user, "S3 API User", "Developer or application using S3 API with MFA authentication")
```

**Архитектурное значение:**
- Представляет разработчиков и приложения, использующие S3 API с MFA
- Инициирует запросы, требующие многофакторной аутентификации

**Связь с кодом:**
```go
// В auth/mfa.go - структура для представления пользователя с MFA
type MFAUser struct {
    UserID      string    `json:"user_id"`
    DisplayName string    `json:"display_name"`
    MFAEnabled  bool      `json:"mfa_enabled"`
    LastMFAUsed time.Time `json:"last_mfa_used"`
    FailedAttempts int    `json:"failed_attempts"`
    LockedUntil    *time.Time `json:"locked_until,omitempty"`
}

// Пример использования в middleware
func (mw *MFAMiddleware) VerifyMFA(c *fiber.Ctx) error {
    // Извлечение пользователя из контекста
    account := c.Locals("account").(Account)
    
    // Проверка требования MFA для пользователя
    required, err := mw.mfaService.IsMFARequired(account.UserID)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": "MFA check failed"})
    }
    
    if !required {
        return c.Next() // MFA не требуется
    }
    
    // Извлечение MFA токена из заголовка
    mfaToken := c.Get("X-Amz-MFA")
    if mfaToken == "" {
        return c.Status(401).JSON(fiber.Map{
            "error": "MFA token required",
            "code":  "MFA_TOKEN_REQUIRED",
        })
    }
    
    // Валидация MFA токена
    if err := mw.mfaService.ValidateTOTP(account.UserID, mfaToken); err != nil {
        return c.Status(401).JSON(fiber.Map{
            "error": "Invalid MFA token",
            "code":  "INVALID_MFA_TOKEN",
        })
    }
    
    // Установка флага успешной MFA проверки
    c.Locals("mfa_verified", true)
    return c.Next()
}
```

**Практическая реализация:**
- Пользователь аутентифицируется через AWS Signature V4 + MFA токен
- Каждый запрос может содержать TOTP токен в заголовке X-Amz-MFA
- Система проверяет политики MFA для определения требований

### 2. System Administrator (Администратор системы)
```plantuml
Person(admin_user, "System Administrator", "Manages MFA policies and user configurations")
```

**Архитектурное значение:**
- Управляет политиками MFA и конфигурациями пользователей
- Настраивает требования безопасности и мониторинг

**Связь с кодом:**
```go
// В admin/mfa_admin.go - интерфейс для администрирования MFA
type MFAAdminService interface {
    SetMFAPolicy(policy *MFAPolicy) error
    GetMFAPolicy() (*MFAPolicy, error)
    EnableMFAForUser(userID string) error
    DisableMFAForUser(userID string) error
    ResetMFAForUser(userID string) error
    GetMFAStatistics() (*MFAStatistics, error)
    GetUserMFAStatus(userID string) (*MFAStatus, error)
}

// Пример реализации Admin API
func (s *AdminAPIServer) setupMFARoutes() {
    mfa := s.app.Group("/admin/mfa")
    
    // Управление политиками MFA
    mfa.Get("/policy", s.getMFAPolicy)
    mfa.Put("/policy", s.updateMFAPolicy)
    
    // Управление пользователями
    mfa.Get("/users/:userId/status", s.getUserMFAStatus)
    mfa.Post("/users/:userId/enable", s.enableUserMFA)
    mfa.Post("/users/:userId/disable", s.disableUserMFA)
    mfa.Post("/users/:userId/reset", s.resetUserMFA)
    
    // Статистика и мониторинг
    mfa.Get("/statistics", s.getMFAStatistics)
    mfa.Get("/audit-log", s.getMFAAuditLog)
}

func (s *AdminAPIServer) updateMFAPolicy(c *fiber.Ctx) error {
    var policy MFAPolicy
    if err := c.BodyParser(&policy); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid policy data"})
    }
    
    // Валидация политики
    if err := policy.Validate(); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": err.Error()})
    }
    
    // Применение политики
    if err := s.mfaAdminService.SetMFAPolicy(&policy); err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }
    
    // Логирование изменения политики
    s.auditLogger.LogPolicyChange(c.Context(), "mfa_policy_updated", &policy)
    
    return c.JSON(fiber.Map{"message": "MFA policy updated successfully"})
}

// Структура политики MFA
type MFAPolicy struct {
    RequiredForRoles []string `json:"required_for_roles"`
    RequiredForUsers []string `json:"required_for_users"`
    ExemptUsers      []string `json:"exempt_users"`
    GracePeriodDays  int      `json:"grace_period_days"`
    MaxFailedAttempts int     `json:"max_failed_attempts"`
    LockoutDurationMinutes int `json:"lockout_duration_minutes"`
    BackupCodesCount int      `json:"backup_codes_count"`
    Active           bool     `json:"active"`
}
```

## Центральная система и её архитектура

### Versity S3 Gateway
```plantuml
System(s3_gateway, "Versity S3 Gateway", "S3-compatible API gateway with multi-factor authentication support")
```

**Архитектурное значение:**
- Центральная система, интегрирующая MFA в существующий S3 Gateway
- Обеспечивает совместимость с S3 API при добавлении MFA функциональности

**Связь с кодом:**
```go
// Основная структура S3 Gateway с MFA поддержкой
type EnhancedS3Gateway struct {
    app         *fiber.App
    mfaService  MFAService
    authService AuthService
    config      *GatewayConfig
    auditLogger AuditLogger
}

// Инициализация Gateway с MFA компонентами
func NewEnhancedS3Gateway(config *GatewayConfig) (*EnhancedS3Gateway, error) {
    // Создание MFA сервиса
    mfaStorage, err := NewFileMFAStorage(config.MFA.DataDir)
    if err != nil {
        return nil, fmt.Errorf("failed to create MFA storage: %w", err)
    }
    
    mfaService := NewMFAService(mfaStorage, config.MFA)
    
    // Создание Fiber приложения
    app := fiber.New(fiber.Config{
        ErrorHandler: customErrorHandler,
    })
    
    gateway := &EnhancedS3Gateway{
        app:         app,
        mfaService:  mfaService,
        authService: NewAuthService(config.Auth),
        config:      config,
        auditLogger: NewAuditLogger(config.Audit),
    }
    
    // Настройка middleware и маршрутов
    gateway.setupMiddleware()
    gateway.setupRoutes()
    
    return gateway, nil
}

// Настройка middleware с MFA интеграцией
func (gw *EnhancedS3Gateway) setupMiddleware() {
    // Базовые middleware
    gw.app.Use(logger.New())
    gw.app.Use(recover.New())
    
    // Аутентификация AWS Signature V4
    gw.app.Use(NewAWSAuthMiddleware(gw.authService))
    
    // MFA middleware (применяется после базовой аутентификации)
    gw.app.Use(NewMFAMiddleware(gw.mfaService, gw.config.MFA))
    
    // Аудит middleware
    gw.app.Use(NewAuditMiddleware(gw.auditLogger))
}

// Настройка S3 API маршрутов
func (gw *EnhancedS3Gateway) setupRoutes() {
    // MFA управление endpoints
    mfa := gw.app.Group("/mfa")
    mfa.Post("/setup", gw.handleMFASetup)
    mfa.Post("/enable", gw.handleMFAEnable)
    mfa.Post("/disable", gw.handleMFADisable)
    mfa.Get("/status", gw.handleMFAStatus)
    mfa.Post("/backup-codes", gw.handleGenerateBackupCodes)
    
    // S3 API endpoints (с MFA защитой)
    gw.app.Get("/:bucket", gw.handleListObjects)
    gw.app.Get("/:bucket/:object", gw.handleGetObject)
    gw.app.Put("/:bucket/:object", gw.handlePutObject)
    gw.app.Delete("/:bucket/:object", gw.handleDeleteObject)
    gw.app.Head("/:bucket/:object", gw.handleHeadObject)
}

// Обработчик настройки MFA
func (gw *EnhancedS3Gateway) handleMFASetup(c *fiber.Ctx) error {
    account := c.Locals("account").(Account)
    
    // Генерация секрета MFA
    secret, err := gw.mfaService.GenerateSecret(account.UserID)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": "Failed to generate MFA secret"})
    }
    
    // Логирование события настройки
    gw.auditLogger.LogMFAEvent(c.Context(), "mfa_setup_initiated", account.UserID, nil)
    
    return c.JSON(fiber.Map{
        "secret":       secret.Secret,
        "qr_code":      secret.QRCode,
        "backup_codes": secret.BackupCodes,
        "issuer":       secret.Issuer,
        "account_name": secret.AccountName,
    })
}
```

## Внешние системы и интеграции

### 1. TOTP Authenticator
```plantuml
System_Ext(totp_app, "TOTP Authenticator", "Mobile authenticator app (Google Authenticator, Authy, etc.)")
```

**Связь с кодом:**
```go
// auth/totp.go - генерация и валидация TOTP токенов
type TOTPGenerator struct {
    config *TOTPConfig
}

type TOTPConfig struct {
    Issuer     string        `json:"issuer"`
    Period     time.Duration `json:"period"`     // 30 секунд по умолчанию
    Digits     int           `json:"digits"`     // 6 цифр по умолчанию
    Algorithm  string        `json:"algorithm"`  // SHA1 по умолчанию
    Skew       int           `json:"skew"`       // Допустимое отклонение времени
}

func NewTOTPGenerator(config *TOTPConfig) *TOTPGenerator {
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
        config.Skew = 1 // Разрешить ±1 временное окно
    }
    
    return &TOTPGenerator{config: config}
}

// Генерация секрета для TOTP
func (tg *TOTPGenerator) GenerateSecret() (string, error) {
    // Генерация 20 байт случайных данных
    secret := make([]byte, 20)
    if _, err := rand.Read(secret); err != nil {
        return "", fmt.Errorf("failed to generate random secret: %w", err)
    }
    
    // Кодирование в Base32 для совместимости с TOTP приложениями
    return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// Генерация TOTP токена для текущего времени
func (tg *TOTPGenerator) GenerateTOTP(secret string, timestamp time.Time) (string, error) {
    // Декодирование секрета из Base32
    key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
    if err != nil {
        return "", fmt.Errorf("invalid secret format: %w", err)
    }
    
    // Вычисление временного счетчика (RFC 6238)
    counter := uint64(timestamp.Unix()) / uint64(tg.config.Period.Seconds())
    
    // Генерация HMAC
    h := hmac.New(sha1.New, key)
    binary.Write(h, binary.BigEndian, counter)
    hash := h.Sum(nil)
    
    // Динамическое усечение (RFC 4226)
    offset := hash[len(hash)-1] & 0x0F
    code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF
    
    // Получение нужного количества цифр
    code = code % uint32(math.Pow10(tg.config.Digits))
    
    return fmt.Sprintf("%0*d", tg.config.Digits, code), nil
}

// Валидация TOTP токена с учетом временного окна
func (tg *TOTPGenerator) ValidateTOTP(secret, token string, timestamp time.Time) error {
    // Проверка текущего временного окна
    currentToken, err := tg.GenerateTOTP(secret, timestamp)
    if err != nil {
        return err
    }
    
    if subtle.ConstantTimeCompare([]byte(token), []byte(currentToken)) == 1 {
        return nil // Токен валиден
    }
    
    // Проверка предыдущих и следующих временных окон (skew)
    for i := 1; i <= tg.config.Skew; i++ {
        // Предыдущее окно
        prevTime := timestamp.Add(-time.Duration(i) * tg.config.Period)
        prevToken, err := tg.GenerateTOTP(secret, prevTime)
        if err == nil && subtle.ConstantTimeCompare([]byte(token), []byte(prevToken)) == 1 {
            return nil
        }
        
        // Следующее окно
        nextTime := timestamp.Add(time.Duration(i) * tg.config.Period)
        nextToken, err := tg.GenerateTOTP(secret, nextTime)
        if err == nil && subtle.ConstantTimeCompare([]byte(token), []byte(nextToken)) == 1 {
            return nil
        }
    }
    
    return errors.New("invalid TOTP token")
}

// Генерация QR кода для настройки в TOTP приложении
func (tg *TOTPGenerator) GenerateQRCode(secret, accountName string) (string, error) {
    // Создание TOTP URI согласно стандарту
    uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
        url.QueryEscape(tg.config.Issuer),
        url.QueryEscape(accountName),
        secret,
        url.QueryEscape(tg.config.Issuer),
        tg.config.Algorithm,
        tg.config.Digits,
        int(tg.config.Period.Seconds()),
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

### 2. IAM Backend
```plantuml
System_Ext(iam_backend, "IAM Backend", "Identity and Access Management system (LDAP, Vault, Database)")
```

**Связь с кодом:**
```go
// integration/iam.go - интеграция с внешним IAM
type IAMBackend interface {
    AuthenticateUser(username, password string) (*UserInfo, error)
    GetUserInfo(userID string) (*UserInfo, error)
    GetUserRoles(userID string) ([]string, error)
    IsUserActive(userID string) (bool, error)
}

// LDAP реализация IAM Backend
type LDAPBackend struct {
    conn   *ldap.Conn
    config *LDAPConfig
}

func (lb *LDAPBackend) GetUserRoles(userID string) ([]string, error) {
    // Поиск пользователя в LDAP
    searchRequest := ldap.NewSearchRequest(
        lb.config.BaseDN,
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        0, 0, false,
        fmt.Sprintf("(uid=%s)", userID),
        []string{"memberOf"},
        nil,
    )
    
    sr, err := lb.conn.Search(searchRequest)
    if err != nil {
        return nil, fmt.Errorf("LDAP search failed: %w", err)
    }
    
    if len(sr.Entries) == 0 {
        return []string{}, nil
    }
    
    // Извлечение ролей из memberOf атрибутов
    roles := make([]string, 0)
    for _, memberOf := range sr.Entries[0].GetAttributeValues("memberOf") {
        // Парсинг DN для извлечения имени роли
        if role := extractRoleFromDN(memberOf); role != "" {
            roles = append(roles, role)
        }
    }
    
    return roles, nil
}

// Интеграция MFA с IAM для определения требований
func (ms *MFAService) IsMFARequired(userID string) (bool, error) {
    // Получение ролей пользователя из IAM
    roles, err := ms.iamBackend.GetUserRoles(userID)
    if err != nil {
        return false, fmt.Errorf("failed to get user roles: %w", err)
    }
    
    // Проверка политики MFA
    policy, err := ms.GetMFAPolicy()
    if err != nil {
        return false, err
    }
    
    // Проверка исключений
    for _, exemptUser := range policy.ExemptUsers {
        if exemptUser == userID {
            return false, nil
        }
    }
    
    // Проверка прямого требования для пользователя
    for _, requiredUser := range policy.RequiredForUsers {
        if requiredUser == userID {
            return true, nil
        }
    }
    
    // Проверка требования по ролям
    for _, userRole := range roles {
        for _, requiredRole := range policy.RequiredForRoles {
            if userRole == requiredRole {
                return true, nil
            }
        }
    }
    
    return false, nil
}
```

### 3. S3 Client Applications
```plantuml
System_Ext(s3_client, "S3 Client Applications", "AWS CLI, SDKs, or custom applications")
```

**Связь с кодом:**
```go
// Пример интеграции MFA в S3 клиент
type MFAEnabledS3Client struct {
    *s3.Client
    mfaTokenProvider MFATokenProvider
}

type MFATokenProvider interface {
    GetMFAToken() (string, error)
}

// Реализация провайдера TOTP токенов
type TOTPTokenProvider struct {
    secret string
    totp   *TOTPGenerator
}

func (ttp *TOTPTokenProvider) GetMFAToken() (string, error) {
    return ttp.totp.GenerateTOTP(ttp.secret, time.Now())
}

// Модификация S3 запросов для включения MFA токена
func (client *MFAEnabledS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
    // Получение MFA токена
    mfaToken, err := client.mfaTokenProvider.GetMFAToken()
    if err != nil {
        return nil, fmt.Errorf("failed to get MFA token: %w", err)
    }
    
    // Добавление MFA токена в заголовки запроса
    optFns = append(optFns, func(o *s3.Options) {
        o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
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
        })
    })
    
    return client.Client.GetObject(ctx, params, optFns...)
}
```

## Взаимосвязи и потоки данных

### 1. S3 User → S3 Gateway
```plantuml
Rel(s3_user, s3_gateway, "Makes S3 API requests with MFA tokens", "HTTPS")
```

**Реализация потока:**
```go
// HTTP handler для S3 API запросов с MFA
func (gw *EnhancedS3Gateway) handleGetObject(c *fiber.Ctx) error {
    // 1. Извлечение параметров запроса
    bucket := c.Params("bucket")
    object := c.Params("object")
    
    // 2. Проверка базовой аутентификации (уже выполнена в middleware)
    account := c.Locals("account").(Account)
    
    // 3. Проверка MFA (уже выполнена в MFA middleware)
    mfaVerified := c.Locals("mfa_verified").(bool)
    if !mfaVerified {
        return c.Status(401).JSON(fiber.Map{
            "error": "MFA verification required",
            "code":  "MFA_REQUIRED",
        })
    }
    
    // 4. Выполнение S3 операции
    object, err := gw.s3Backend.GetObject(c.Context(), bucket, object)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }
    
    // 5. Логирование успешного доступа
    gw.auditLogger.LogS3Access(c.Context(), "get_object", account.UserID, bucket, object)
    
    // 6. Возврат объекта
    c.Set("Content-Type", object.ContentType)
    c.Set("Content-Length", fmt.Sprintf("%d", object.Size))
    return c.Send(object.Data)
}
```

Context Diagram Task 2 обеспечивает четкое понимание границ MFA Enhanced S3 Gateway системы и служит основой для детализации архитектуры на следующих уровнях C4 модели, при этом каждый элемент диаграммы имеет прямое соответствие в реализации кода многофакторной аутентификации.