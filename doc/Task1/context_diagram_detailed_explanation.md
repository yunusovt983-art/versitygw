# Подробное объяснение Context Diagram Task 1 - Enhanced Cache System

## Назначение диаграммы

Context Diagram для Task 1 показывает систему Enhanced Cache System в контексте пользователей и внешних IAM сервисов. Эта диаграмма служит мостом между бизнес-требованиями улучшенного кэширования и техническими решениями, определяя границы системы и ключевые взаимодействия для оптимизации производительности аутентификации.

## Структура PlantUML и связь с кодом

### Заголовок и настройки
```plantuml
@startuml Task1_Enhanced_Cache_Architecture
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Context.puml
title Enhanced Cache System Architecture - Task1
```

**Связь с реализацией:**
- Заголовок отражает основную цель Task 1 - улучшение системы кэширования
- Использование C4_Context.puml обеспечивает стандартизированное представление

## Участники системы и их реализация

### 1. S3 Client (Пользователь S3 API)
```plantuml
Person(user, "S3 Client", "Applications using S3 API")
```

**Архитектурное значение:**
- Представляет приложения и клиентов, использующих S3 API
- Инициирует запросы, требующие аутентификации через кэшированные данные

**Связь с кодом:**
```go
// В client/s3_client.go - пример S3 клиента
type S3Client struct {
    endpoint    string
    accessKeyID string
    secretKey   string
    httpClient  *http.Client
}

func (c *S3Client) GetObject(bucket, key string) (*S3Object, error) {
    // Создание запроса с AWS Signature V4
    req, err := c.createSignedRequest("GET", bucket, key, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create signed request: %w", err)
    }
    
    // Отправка запроса (будет обработан Enhanced Cache System)
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == 401 {
        return nil, errors.New("authentication failed - check credentials")
    }
    
    if resp.StatusCode == 403 {
        return nil, errors.New("access denied - check permissions")
    }
    
    return parseS3Object(resp)
}

func (c *S3Client) createSignedRequest(method, bucket, key string, body io.Reader) (*http.Request, error) {
    url := fmt.Sprintf("%s/%s/%s", c.endpoint, bucket, key)
    req, err := http.NewRequest(method, url, body)
    if err != nil {
        return nil, err
    }
    
    // AWS Signature V4 подпись
    return c.signRequestV4(req)
}
```

**Практическая реализация:**
- Клиент аутентифицируется через AWS Signature V4
- Каждый запрос содержит Access Key ID для идентификации пользователя
- Enhanced Cache System ускоряет аутентификацию через кэширование

## Центральная система и её архитектура

### Versity S3 Gateway
```plantuml
System(gateway, "Versity S3 Gateway", "S3-compatible gateway with enhanced authentication caching")
```

**Архитектурное значение:**
- Центральная система, интегрирующая Enhanced Cache в существующий S3 Gateway
- Обеспечивает высокую производительность аутентификации через кэширование

**Связь с кодом:**
```go
// Основная структура S3 Gateway с Enhanced Cache
type EnhancedS3Gateway struct {
    app         *fiber.App
    iamCache    IAMService // Enhanced IAM Cache
    authService AuthService
    s3Backend   S3Backend
    config      *GatewayConfig
}

// Инициализация Gateway с Enhanced Cache
func NewEnhancedS3Gateway(config *GatewayConfig) (*EnhancedS3Gateway, error) {
    // Создание Enhanced IAM Cache
    cacheConfig := &EnhancedCacheConfig{
        MaxSize:         config.Cache.MaxSize,
        CleanupInterval: config.Cache.CleanupInterval,
        DefaultTTLs: map[CacheEntryType]time.Duration{
            UserCredentials: 15 * time.Minute,
            UserRoles:       30 * time.Minute,
            Permissions:     1 * time.Hour,
            MFASettings:     2 * time.Hour,
            SessionData:     10 * time.Minute,
        },
    }
    
    // Создание базового IAM сервиса
    var baseIAMService IAMService
    switch config.IAM.Type {
    case "ldap":
        baseIAMService = NewLDAPService(config.IAM.LDAP)
    case "vault":
        baseIAMService = NewVaultService(config.IAM.Vault)
    case "s3":
        baseIAMService = NewS3IAMService(config.IAM.S3)
    case "ipa":
        baseIAMService = NewIPAService(config.IAM.IPA)
    default:
        return nil, fmt.Errorf("unsupported IAM type: %s", config.IAM.Type)
    }
    
    // Создание Enhanced IAM Cache
    iamCache, err := NewEnhancedIAMCache(baseIAMService, cacheConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create enhanced IAM cache: %w", err)
    }
    
    gateway := &EnhancedS3Gateway{
        app:         fiber.New(),
        iamCache:    iamCache,
        authService: NewAuthService(config.Auth),
        s3Backend:   NewS3Backend(config.S3),
        config:      config,
    }
    
    gateway.setupMiddleware()
    gateway.setupRoutes()
    
    return gateway, nil
}

// Middleware для аутентификации с кэшированием
func (gw *EnhancedS3Gateway) setupMiddleware() {
    // Аутентификация с Enhanced Cache
    gw.app.Use(func(c *fiber.Ctx) error {
        // Извлечение Access Key из AWS Signature V4
        accessKey, err := extractAccessKeyFromRequest(c)
        if err != nil {
            return c.Status(401).JSON(fiber.Map{"error": "Invalid authentication"})
        }
        
        // Получение аккаунта через Enhanced Cache
        account, err := gw.iamCache.GetUserAccount(accessKey)
        if err != nil {
            return c.Status(401).JSON(fiber.Map{"error": "Authentication failed"})
        }
        
        // Сохранение в контексте для дальнейшего использования
        c.Locals("account", account)
        c.Locals("access_key", accessKey)
        
        return c.Next()
    })
}

// Обработчик S3 запросов с кэшированной аутентификацией
func (gw *EnhancedS3Gateway) handleGetObject(c *fiber.Ctx) error {
    // Аккаунт уже получен и проверен через Enhanced Cache в middleware
    account := c.Locals("account").(Account)
    
    bucket := c.Params("bucket")
    object := c.Params("object")
    
    // Проверка разрешений (также может использовать кэш)
    if !gw.hasPermission(account, bucket, object, "GET") {
        return c.Status(403).JSON(fiber.Map{"error": "Access denied"})
    }
    
    // Выполнение операции с объектом
    result, err := gw.s3Backend.GetObject(c.Context(), bucket, object)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }
    
    return c.JSON(result)
}
```

## Внешние системы и интеграции

### 1. External IAM Services
```plantuml
System_Ext(iam_services, "External IAM Services", "LDAP, Vault, S3, IPA services")
```

**Связь с кодом:**
```go
// interfaces/iam_service.go - общий интерфейс для всех IAM сервисов
type IAMService interface {
    CreateAccount(account Account) error
    GetUserAccount(accessKey string) (Account, error)
    UpdateUserAccount(accessKey string, props MutableProps) error
    DeleteUserAccount(accessKey string) error
    ListUserAccounts() ([]Account, error)
    Shutdown() error
}

// Реализация для LDAP
type LDAPService struct {
    conn     *ldap.Conn
    config   *LDAPConfig
    connPool *ConnectionPool
}

func (ls *LDAPService) GetUserAccount(accessKey string) (Account, error) {
    // Поиск пользователя по Access Key в LDAP
    searchRequest := ldap.NewSearchRequest(
        ls.config.BaseDN,
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        0, 0, false,
        fmt.Sprintf("(accessKeyId=%s)", accessKey),
        []string{"uid", "cn", "mail", "memberOf", "secretAccessKey"},
        nil,
    )
    
    sr, err := ls.conn.Search(searchRequest)
    if err != nil {
        return Account{}, fmt.Errorf("LDAP search failed: %w", err)
    }
    
    if len(sr.Entries) == 0 {
        return Account{}, errors.New("user not found")
    }
    
    entry := sr.Entries[0]
    account := Account{
        UserID:          entry.GetAttributeValue("uid"),
        DisplayName:     entry.GetAttributeValue("cn"),
        Email:           entry.GetAttributeValue("mail"),
        AccessKeyID:     accessKey,
        SecretAccessKey: entry.GetAttributeValue("secretAccessKey"),
        Groups:          entry.GetAttributeValues("memberOf"),
        CreatedAt:       time.Now(), // LDAP может не хранить эту информацию
        UpdatedAt:       time.Now(),
    }
    
    return account, nil
}

// Реализация для HashiCorp Vault
type VaultService struct {
    client *vault.Client
    config *VaultConfig
}

func (vs *VaultService) GetUserAccount(accessKey string) (Account, error) {
    // Получение данных пользователя из Vault
    secret, err := vs.client.Logical().Read(fmt.Sprintf("auth/aws/users/%s", accessKey))
    if err != nil {
        return Account{}, fmt.Errorf("vault read failed: %w", err)
    }
    
    if secret == nil || secret.Data == nil {
        return Account{}, errors.New("user not found in vault")
    }
    
    account := Account{
        UserID:          secret.Data["user_id"].(string),
        DisplayName:     secret.Data["display_name"].(string),
        Email:           secret.Data["email"].(string),
        AccessKeyID:     accessKey,
        SecretAccessKey: secret.Data["secret_access_key"].(string),
    }
    
    // Получение групп/ролей из Vault
    if groups, exists := secret.Data["groups"]; exists {
        if groupSlice, ok := groups.([]interface{}); ok {
            account.Groups = make([]string, len(groupSlice))
            for i, group := range groupSlice {
                account.Groups[i] = group.(string)
            }
        }
    }
    
    return account, nil
}

// Реализация для S3-based IAM
type S3IAMService struct {
    s3Client *s3.Client
    bucket   string
    prefix   string
}

func (s3iam *S3IAMService) GetUserAccount(accessKey string) (Account, error) {
    // Получение данных пользователя из S3 объекта
    key := fmt.Sprintf("%s/users/%s.json", s3iam.prefix, accessKey)
    
    result, err := s3iam.s3Client.GetObject(context.Background(), &s3.GetObjectInput{
        Bucket: aws.String(s3iam.bucket),
        Key:    aws.String(key),
    })
    if err != nil {
        var nsk *types.NoSuchKey
        if errors.As(err, &nsk) {
            return Account{}, errors.New("user not found")
        }
        return Account{}, fmt.Errorf("S3 get object failed: %w", err)
    }
    defer result.Body.Close()
    
    var account Account
    if err := json.NewDecoder(result.Body).Decode(&account); err != nil {
        return Account{}, fmt.Errorf("failed to decode user data: %w", err)
    }
    
    return account, nil
}
```

### 2. Object Storage
```plantuml
System_Ext(storage, "Object Storage", "Backend storage system")
```

**Связь с кодом:**
```go
// backend/storage.go - интерфейс для backend хранилища
type S3Backend interface {
    GetObject(ctx context.Context, bucket, key string) (*S3Object, error)
    PutObject(ctx context.Context, bucket, key string, data io.Reader) error
    DeleteObject(ctx context.Context, bucket, key string) error
    ListObjects(ctx context.Context, bucket, prefix string) (*ListObjectsResult, error)
    CreateBucket(ctx context.Context, bucket string) error
    DeleteBucket(ctx context.Context, bucket string) error
}

// Реализация для MinIO backend
type MinIOBackend struct {
    client *minio.Client
    config *MinIOConfig
}

func (mb *MinIOBackend) GetObject(ctx context.Context, bucket, key string) (*S3Object, error) {
    object, err := mb.client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
    if err != nil {
        return nil, fmt.Errorf("MinIO get object failed: %w", err)
    }
    defer object.Close()
    
    // Чтение данных объекта
    data, err := io.ReadAll(object)
    if err != nil {
        return nil, fmt.Errorf("failed to read object data: %w", err)
    }
    
    // Получение метаданных
    stat, err := object.Stat()
    if err != nil {
        return nil, fmt.Errorf("failed to get object stat: %w", err)
    }
    
    return &S3Object{
        Bucket:      bucket,
        Key:         key,
        Data:        data,
        Size:        stat.Size,
        ContentType: stat.ContentType,
        ETag:        stat.ETag,
        LastModified: stat.LastModified,
    }, nil
}
```

## Взаимосвязи и потоки данных

### 1. User → Gateway
```plantuml
Rel(user, gateway, "S3 API calls", "HTTPS")
```

**Реализация потока с кэшированием:**
```go
// HTTP handler для S3 API с Enhanced Cache
func (gw *EnhancedS3Gateway) handleS3Request(c *fiber.Ctx) error {
    startTime := time.Now()
    
    // 1. Извлечение Access Key из AWS Signature V4
    accessKey, err := extractAccessKeyFromRequest(c)
    if err != nil {
        return c.Status(401).JSON(fiber.Map{"error": "Invalid authentication"})
    }
    
    // 2. Получение аккаунта через Enhanced Cache (быстро!)
    account, err := gw.iamCache.GetUserAccount(accessKey)
    if err != nil {
        // Логирование cache miss или ошибки
        gw.logCacheEvent("cache_miss_or_error", accessKey, err)
        return c.Status(401).JSON(fiber.Map{"error": "Authentication failed"})
    }
    
    // 3. Логирование успешного cache hit
    gw.logCacheEvent("cache_hit", accessKey, nil)
    
    // 4. Сохранение в контексте
    c.Locals("account", account)
    c.Locals("auth_time", time.Since(startTime))
    
    return c.Next()
}

// Логирование событий кэша для мониторинга
func (gw *EnhancedS3Gateway) logCacheEvent(eventType, accessKey string, err error) {
    event := map[string]interface{}{
        "event_type":  eventType,
        "access_key":  accessKey,
        "timestamp":   time.Now(),
    }
    
    if err != nil {
        event["error"] = err.Error()
    }
    
    // Отправка в систему мониторинга
    gw.metricsCollector.RecordCacheEvent(event)
}
```

### 2. Gateway → IAM Services
```plantuml
Rel(gateway, iam_services, "Authentication requests", "Various protocols")
```

**Реализация интеграции с различными IAM сервисами:**
```go
// auth/enhanced_iam_cache.go - Enhanced IAM Cache с fallback
type EnhancedIAMCache struct {
    service       IAMService      // Базовый IAM сервис
    primaryCache  *EnhancedCache  // Основной кэш
    fallbackCache *EnhancedCache  // Fallback кэш
    config        *EnhancedIAMCacheConfig
    metrics       *CacheMetrics
    healthChecker *HealthChecker
    
    // Синхронизация
    mutex sync.RWMutex
}

func NewEnhancedIAMCache(service IAMService, config *EnhancedIAMCacheConfig) (*EnhancedIAMCache, error) {
    // Создание основного кэша
    primaryCache, err := NewEnhancedCache(config.CacheConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create primary cache: %w", err)
    }
    
    // Создание fallback кэша с расширенными TTL
    fallbackConfig := *config.CacheConfig
    fallbackConfig.MaxSize = config.CacheConfig.MaxSize / 2 // Меньший размер для fallback
    
    // Увеличение TTL для fallback кэша
    for entryType, ttl := range fallbackConfig.DefaultTTLs {
        fallbackConfig.DefaultTTLs[entryType] = ttl * 4 // 4x больше TTL
    }
    
    fallbackCache, err := NewEnhancedCache(&fallbackConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create fallback cache: %w", err)
    }
    
    cache := &EnhancedIAMCache{
        service:       service,
        primaryCache:  primaryCache,
        fallbackCache: fallbackCache,
        config:        config,
        metrics:       NewCacheMetrics(),
        healthChecker: NewHealthChecker(service, 30*time.Second),
    }
    
    // Запуск мониторинга здоровья
    go cache.healthChecker.Start()
    
    return cache, nil
}

func (eic *EnhancedIAMCache) GetUserAccount(accessKey string) (Account, error) {
    startTime := time.Now()
    userKey := eic.getUserKey(accessKey)
    
    // 1. Попытка получения из основного кэша
    if cached, found := eic.primaryCache.Get(userKey, UserCredentials); found {
        eic.metrics.PrimaryCacheHits.Inc()
        eic.recordLatency("primary_cache_hit", time.Since(startTime))
        return cached.(Account), nil
    }
    
    eic.metrics.PrimaryCacheMisses.Inc()
    
    // 2. Попытка получения из базового IAM сервиса
    if eic.healthChecker.IsHealthy() {
        account, err := eic.service.GetUserAccount(accessKey)
        if err == nil {
            // Успешно получили из IAM - обновляем оба кэша
            eic.primaryCache.Set(userKey, account, 0, UserCredentials) // Использует default TTL
            eic.fallbackCache.Set(userKey, account, 0, UserCredentials) // Расширенный TTL
            
            eic.metrics.IAMServiceHits.Inc()
            eic.recordLatency("iam_service_success", time.Since(startTime))
            return account, nil
        }
        
        eic.metrics.IAMServiceErrors.Inc()
        // Продолжаем к fallback кэшу
    }
    
    // 3. Попытка получения из fallback кэша
    if cached, found := eic.fallbackCache.Get(userKey, UserCredentials); found {
        eic.metrics.FallbackCacheHits.Inc()
        eic.primaryCache.SetFallbackMode(true) // Активируем fallback режим
        
        // Логирование использования fallback
        eic.logFallbackUsage(accessKey, "iam_service_unavailable")
        
        eic.recordLatency("fallback_cache_hit", time.Since(startTime))
        return cached.(Account), nil
    }
    
    eic.metrics.FallbackCacheMisses.Inc()
    eic.recordLatency("complete_cache_miss", time.Since(startTime))
    
    // 4. Полный промах - возвращаем ошибку
    return Account{}, errors.New("user not found and IAM service unavailable")
}

func (eic *EnhancedIAMCache) logFallbackUsage(accessKey, reason string) {
    event := map[string]interface{}{
        "event_type":  "fallback_cache_used",
        "access_key":  accessKey,
        "reason":      reason,
        "timestamp":   time.Now(),
        "cache_stats": eic.GetCacheStats(),
    }
    
    // Отправка в систему мониторинга
    eic.metrics.LogEvent(event)
}
```

### 3. Gateway → Storage
```plantuml
Rel(gateway, storage, "Object operations", "Backend protocol")
```

**Реализация интеграции с хранилищем:**
```go
// После успешной аутентификации через Enhanced Cache
func (gw *EnhancedS3Gateway) processS3Operation(c *fiber.Ctx) error {
    account := c.Locals("account").(Account)
    authTime := c.Locals("auth_time").(time.Duration)
    
    // Логирование производительности аутентификации
    gw.metrics.RecordAuthTime(authTime)
    
    bucket := c.Params("bucket")
    object := c.Params("object")
    method := c.Method()
    
    // Выполнение операции с backend хранилищем
    switch method {
    case "GET":
        return gw.handleGetObject(c, account, bucket, object)
    case "PUT":
        return gw.handlePutObject(c, account, bucket, object)
    case "DELETE":
        return gw.handleDeleteObject(c, account, bucket, object)
    default:
        return c.Status(405).JSON(fiber.Map{"error": "Method not allowed"})
    }
}
```

## Архитектурные принципы и их реализация

### 1. Принцип кэширования с fallback
```go
// Двухуровневая система кэширования
type DualCacheSystem struct {
    primary  *EnhancedCache // Быстрый кэш с коротким TTL
    fallback *EnhancedCache // Резервный кэш с длинным TTL
}

func (dcs *DualCacheSystem) Get(key string, entryType CacheEntryType) (interface{}, bool) {
    // Сначала проверяем основной кэш
    if value, found := dcs.primary.Get(key, entryType); found {
        return value, true
    }
    
    // Затем проверяем fallback кэш
    if value, found := dcs.fallback.Get(key, entryType); found {
        // Возвращаем из fallback, но помечаем как stale
        return value, true
    }
    
    return nil, false
}
```

### 2. Принцип LRU вытеснения
```go
// LRU реализация в Enhanced Cache
func (ec *EnhancedCache) evictLRU() {
    if len(ec.entries) < ec.maxSize {
        return // Нет необходимости в вытеснении
    }
    
    var oldestKey string
    var oldestTime time.Time
    
    // Поиск наименее недавно использованной записи
    for key, entry := range ec.entries {
        if oldestKey == "" || entry.accessTime.Before(oldestTime) {
            oldestKey = key
            oldestTime = entry.accessTime
        }
    }
    
    if oldestKey != "" {
        delete(ec.entries, oldestKey)
        ec.stats.Evictions++
    }
}
```

### 3. Принцип настраиваемых TTL
```go
// Настраиваемые TTL для различных типов данных
var DefaultTTLs = map[CacheEntryType]time.Duration{
    UserCredentials: 15 * time.Minute, // Короткий TTL для безопасности
    UserRoles:       30 * time.Minute, // Средний TTL для ролей
    Permissions:     1 * time.Hour,    // Длинный TTL для разрешений
    MFASettings:     2 * time.Hour,    // Очень длинный TTL для MFA
    SessionData:     10 * time.Minute, // Короткий TTL для сессий
}
```

## Соответствие требованиям Task 1

### 1.1 Политика вытеснения LRU
**Архитектурное решение:** EnhancedCache с LRU алгоритмом
**Реализация:**
```go
func (ec *EnhancedCache) Set(key string, value interface{}, ttl time.Duration, entryType CacheEntryType) {
    ec.mutex.Lock()
    defer ec.mutex.Unlock()
    
    // Проверка необходимости вытеснения
    if len(ec.entries) >= ec.maxSize {
        ec.evictLRU()
    }
    
    // Определение TTL
    if ttl == 0 {
        ttl = ec.defaultTTLs[entryType]
    }
    
    // Создание записи кэша
    entry := &CacheEntry{
        value:      value,
        expiry:     time.Now().Add(ttl),
        entryType:  entryType,
        accessTime: time.Now(),
        key:        key,
    }
    
    ec.entries[key] = entry
}
```

### 1.2 Механизмы инвалидации кэша
**Архитектурное решение:** Паттерн-based инвалидация
**Реализация:**
```go
func (eic *EnhancedIAMCache) InvalidateUser(userID string) error {
    pattern := fmt.Sprintf("^%s:", userID)
    
    // Инвалидация в обоих кэшах
    if err := eic.primaryCache.Invalidate(pattern); err != nil {
        return err
    }
    
    if err := eic.fallbackCache.Invalidate(pattern); err != nil {
        return err
    }
    
    eic.metrics.InvalidationsPerformed.Inc()
    return nil
}
```

### 1.3 Fallback механизм
**Архитектурное решение:** Двойной кэш с health checking
**Реализация:**
```go
func (eic *EnhancedIAMCache) GetUserAccount(accessKey string) (Account, error) {
    // Попытка основного кэша
    if account, found := eic.tryPrimaryCache(accessKey); found {
        return account, nil
    }
    
    // Попытка IAM сервиса
    if eic.healthChecker.IsHealthy() {
        if account, err := eic.tryIAMService(accessKey); err == nil {
            return account, nil
        }
    }
    
    // Fallback к резервному кэшу
    return eic.tryFallbackCache(accessKey)
}
```

Context Diagram Task 1 обеспечивает четкое понимание границ Enhanced Cache System и служит основой для детализации архитектуры кэширования на следующих уровнях C4 модели, при этом каждый элемент диаграммы имеет прямое соответствие в реализации кода системы кэширования.