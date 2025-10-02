# Подробное объяснение C4 Architecture Diagram Task 1 - Enhanced Cache System

## Назначение диаграммы

C4 Architecture Diagram для Task 1 представляет многоуровневую архитектуру Enhanced Cache System, показывая систему от контекста до деталей кода. Эта диаграмма служит мостом между высокоуровневыми требованиями кэширования и конкретной реализацией кода, обеспечивая понимание всех архитектурных слоев.

## Структура PlantUML и архитектурные уровни

### Заголовок и импорты
```plantuml
@startuml Task1_Enhanced_Cache_Architecture
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Context.puml
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Container.puml
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Component.puml
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Deployment.puml
```

**Архитектурное значение:**
- Использование всех уровней C4 модели для полного представления системы
- Обеспечение согласованности между различными уровнями абстракции

## LEVEL 1: System Context Diagram

### Участники системы
```plantuml
Person(user, "S3 Client", "Applications using S3 API")
System(gateway, "Versity S3 Gateway", "S3-compatible gateway with enhanced authentication caching")
System_Ext(iam_services, "External IAM Services", "LDAP, Vault, S3, IPA services")
System_Ext(storage, "Object Storage", "Backend storage system")
```

**Связь с реализацией:**
```go
// main.go - точка входа системы
type S3Gateway struct {
    server          *fiber.App
    enhancedCache   *EnhancedIAMCache
    iamServices     map[string]IAMService
    storageBackend  StorageBackend
    config          *GatewayConfig
}

func NewS3Gateway(config *GatewayConfig) (*S3Gateway, error) {
    // Создание Enhanced Cache системы
    cacheConfig := &EnhancedIAMCacheConfig{
        CacheConfig: &EnhancedCacheConfig{
            MaxSize:         config.Cache.MaxSize,
            CleanupInterval: config.Cache.CleanupInterval,
            DefaultTTLs: map[CacheEntryType]time.Duration{
                UserCredentials: 15 * time.Minute,
                UserRoles:      30 * time.Minute,
                Permissions:    1 * time.Hour,
                MFASettings:    2 * time.Hour,
                SessionData:    10 * time.Minute,
            },
        },
        FallbackCacheConfig: &EnhancedCacheConfig{
            MaxSize:         config.FallbackCache.MaxSize,
            CleanupInterval: config.FallbackCache.CleanupInterval,
            DefaultTTLs: map[CacheEntryType]time.Duration{
                UserCredentials: 1 * time.Hour,    // Расширенный TTL для fallback
                UserRoles:      2 * time.Hour,
                Permissions:    4 * time.Hour,
                MFASettings:    8 * time.Hour,
                SessionData:    30 * time.Minute,
            },
        },
        FallbackEnabled: config.FallbackEnabled,
    }
    
    // Создание базовых IAM сервисов
    iamServices := make(map[string]IAMService)
    
    if config.LDAP.Enabled {
        ldapService, err := NewLDAPService(config.LDAP)
        if err != nil {
            return nil, fmt.Errorf("failed to create LDAP service: %w", err)
        }
        iamServices["ldap"] = ldapService
    }
    
    if config.Vault.Enabled {
        vaultService, err := NewVaultService(config.Vault)
        if err != nil {
            return nil, fmt.Errorf("failed to create Vault service: %w", err)
        }
        iamServices["vault"] = vaultService
    }
    
    // Создание Enhanced IAM Cache с fallback
    primaryService := iamServices[config.PrimaryIAMService]
    enhancedCache, err := NewEnhancedIAMCache(primaryService, cacheConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create enhanced cache: %w", err)
    }
    
    return &S3Gateway{
        server:         fiber.New(),
        enhancedCache:  enhancedCache,
        iamServices:    iamServices,
        storageBackend: NewStorageBackend(config.Storage),
        config:         config,
    }, nil
}

// Основной обработчик S3 запросов
func (gw *S3Gateway) handleS3Request(c *fiber.Ctx) error {
    // Извлечение access key из запроса
    accessKey := extractAccessKeyFromRequest(c)
    if accessKey == "" {
        return c.Status(401).JSON(fiber.Map{"error": "Missing access key"})
    }
    
    // Получение аккаунта через Enhanced Cache
    account, err := gw.enhancedCache.GetUserAccount(accessKey)
    if err != nil {
        return c.Status(401).JSON(fiber.Map{"error": "Authentication failed"})
    }
    
    // Сохранение аккаунта в контексте для дальнейшего использования
    c.Locals("account", account)
    
    return c.Next()
}
```

### Взаимосвязи контекста
```plantuml
Rel(user, gateway, "S3 API calls", "HTTPS")
Rel(gateway, iam_services, "Authentication requests", "Various protocols")
Rel(gateway, storage, "Object operations", "Backend protocol")
```

**Практическая реализация:**
```go
// Интерфейс для взаимодействия с внешними IAM сервисами
type IAMService interface {
    CreateAccount(Account) error
    GetUserAccount(string) (Account, error)
    UpdateUserAccount(string, MutableProps) error
    DeleteUserAccount(string) error
    ListUserAccounts() ([]Account, error)
    Shutdown() error
}

// Структура аккаунта пользователя
type Account struct {
    UserID      string            `json:"user_id"`
    DisplayName string            `json:"display_name"`
    Email       string            `json:"email,omitempty"`
    Groups      []string          `json:"groups,omitempty"`
    Attributes  map[string]string `json:"attributes,omitempty"`
    CreatedAt   time.Time         `json:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at"`
    Active      bool              `json:"active"`
}
```

## LEVEL 2: Container Diagram

### Основные контейнеры
```plantuml
Container(s3_api, "S3 API Layer", "Go", "Handles S3 protocol requests")
Container(auth_system, "Enhanced Auth System", "Go", "Authentication with advanced caching")
Container(storage_layer, "Storage Layer", "Go", "Object storage operations")
```

**Связь с реализацией:**
```go
// s3api/server.go - S3 API Layer
type S3APIServer struct {
    app           *fiber.App
    authSystem    *EnhancedAuthSystem
    storageLayer  *StorageLayer
    middleware    []fiber.Handler
}

func (s *S3APIServer) setupRoutes() {
    // Middleware цепочка
    s.app.Use(s.loggingMiddleware())
    s.app.Use(s.authenticationMiddleware())
    s.app.Use(s.authorizationMiddleware())
    
    // S3 API endpoints
    s.app.Get("/:bucket", s.handleListObjects)
    s.app.Get("/:bucket/:object", s.handleGetObject)
    s.app.Put("/:bucket/:object", s.handlePutObject)
    s.app.Delete("/:bucket/:object", s.handleDeleteObject)
    s.app.Head("/:bucket/:object", s.handleHeadObject)
}

func (s *S3APIServer) authenticationMiddleware() fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Извлечение credentials из запроса
        accessKey := extractAccessKey(c)
        
        // Аутентификация через Enhanced Auth System
        account, err := s.authSystem.GetUserAccount(accessKey)
        if err != nil {
            return c.Status(401).JSON(fiber.Map{
                "error": "Authentication failed",
                "code":  "InvalidAccessKeyId",
            })
        }
        
        // Сохранение аккаунта в контексте
        c.Locals("account", account)
        return c.Next()
    }
}

// auth/enhanced_system.go - Enhanced Auth System
type EnhancedAuthSystem struct {
    iamCache      *EnhancedIAMCache
    auditLogger   AuditLogger
    metrics       *AuthMetrics
}

func (eas *EnhancedAuthSystem) GetUserAccount(accessKey string) (Account, error) {
    startTime := time.Now()
    
    // Получение аккаунта через кэш
    account, err := eas.iamCache.GetUserAccount(accessKey)
    if err != nil {
        eas.metrics.AuthFailures.Inc()
        eas.auditLogger.LogAuthFailure(accessKey, err.Error())
        return Account{}, err
    }
    
    // Успешная аутентификация
    eas.metrics.AuthSuccesses.Inc()
    eas.metrics.AuthLatency.Observe(time.Since(startTime).Seconds())
    eas.auditLogger.LogAuthSuccess(account.UserID, accessKey)
    
    return account, nil
}

// storage/layer.go - Storage Layer
type StorageLayer struct {
    backend       StorageBackend
    accessControl *AccessController
}

func (sl *StorageLayer) GetObject(ctx context.Context, bucket, key string, account Account) (*Object, error) {
    // Проверка прав доступа
    if !sl.accessControl.CanRead(account, bucket, key) {
        return nil, errors.New("access denied")
    }
    
    // Получение объекта из backend
    return sl.backend.GetObject(ctx, bucket, key)
}
```

### Внешние контейнеры
```plantuml
Container_Ext(iam_ldap, "LDAP Service", "LDAP", "User directory service")
Container_Ext(iam_vault, "Vault Service", "HashiCorp Vault", "Secret management")
Container_Ext(iam_s3, "S3 IAM Service", "AWS S3", "User data storage")
Container_Ext(iam_ipa, "IPA Service", "FreeIPA", "Identity management")
```

**Реализация интеграций:**
```go
// iam/ldap_service.go
type LDAPService struct {
    conn   *ldap.Conn
    config *LDAPConfig
}

func (ls *LDAPService) GetUserAccount(accessKey string) (Account, error) {
    // Поиск пользователя по access key
    searchRequest := ldap.NewSearchRequest(
        ls.config.BaseDN,
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        0, 0, false,
        fmt.Sprintf("(accessKey=%s)", accessKey),
        []string{"uid", "cn", "mail", "memberOf"},
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
    return Account{
        UserID:      entry.GetAttributeValue("uid"),
        DisplayName: entry.GetAttributeValue("cn"),
        Email:       entry.GetAttributeValue("mail"),
        Groups:      entry.GetAttributeValues("memberOf"),
        Active:      true,
    }, nil
}

// iam/vault_service.go
type VaultService struct {
    client *vault.Client
    config *VaultConfig
}

func (vs *VaultService) GetUserAccount(accessKey string) (Account, error) {
    // Получение секрета из Vault
    secret, err := vs.client.Logical().Read(fmt.Sprintf("secret/users/%s", accessKey))
    if err != nil {
        return Account{}, fmt.Errorf("vault read failed: %w", err)
    }
    
    if secret == nil {
        return Account{}, errors.New("user not found")
    }
    
    // Парсинг данных пользователя
    data := secret.Data
    return Account{
        UserID:      data["user_id"].(string),
        DisplayName: data["display_name"].(string),
        Email:       data["email"].(string),
        Active:      data["active"].(bool),
    }, nil
}
```

## LEVEL 3: Component Diagram

### Основные компоненты Enhanced Auth System
```plantuml
Component(iam_interface, "IAM Service Interface", "Go Interface", "Standard IAM operations contract")
Component(enhanced_iam_cache, "Enhanced IAM Cache", "Go Struct", "Main caching layer with fallback support")
Component(enhanced_cache, "Enhanced Cache Core", "Go Struct", "LRU cache with TTL and invalidation")
Component(fallback_cache, "Fallback Cache", "Go Struct", "Emergency cache for service outages")
Component(cache_stats, "Cache Statistics", "Go Struct", "Performance monitoring and metrics")
```

**Детальная реализация компонентов:**
```go
// cache/enhanced_iam_cache.go
type EnhancedIAMCache struct {
    service       IAMService
    cache         *EnhancedCache
    fallbackCache *EnhancedCache
    config        *EnhancedIAMCacheConfig
    mu            sync.RWMutex
}

func NewEnhancedIAMCache(service IAMService, config *EnhancedIAMCacheConfig) (*EnhancedIAMCache, error) {
    // Создание основного кэша
    primaryCache, err := NewEnhancedCache(config.CacheConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create primary cache: %w", err)
    }
    
    // Создание fallback кэша
    fallbackCache, err := NewEnhancedCache(config.FallbackCacheConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create fallback cache: %w", err)
    }
    
    return &EnhancedIAMCache{
        service:       service,
        cache:         primaryCache,
        fallbackCache: fallbackCache,
        config:        config,
    }, nil
}

func (eic *EnhancedIAMCache) GetUserAccount(accessKey string) (Account, error) {
    userKey := eic.getUserKey(accessKey)
    
    // Попытка получения из основного кэша
    if cached, found := eic.cache.Get(userKey, UserCredentials); found {
        return cached.(Account), nil
    }
    
    // Попытка получения из IAM сервиса
    account, err := eic.service.GetUserAccount(accessKey)
    if err != nil {
        // Если сервис недоступен, пробуем fallback кэш
        if cached, found := eic.fallbackCache.Get(userKey, UserCredentials); found {
            eic.cache.SetFallbackMode(true)
            return cached.(Account), nil
        }
        return Account{}, err
    }
    
    // Сохранение в оба кэша
    eic.cache.Set(userKey, account, 0, UserCredentials) // Использует default TTL
    eic.fallbackCache.Set(userKey, account, 0, UserCredentials)
    
    return account, nil
}

// cache/enhanced_cache.go
type EnhancedCache struct {
    entries      map[string]*CacheEntry
    maxSize      int
    fallbackMode bool
    stats        CacheStats
    defaultTTLs  map[CacheEntryType]time.Duration
    mu           sync.RWMutex
    cancel       context.CancelFunc
}

func NewEnhancedCache(config *EnhancedCacheConfig) (*EnhancedCache, error) {
    ctx, cancel := context.WithCancel(context.Background())
    
    cache := &EnhancedCache{
        entries:     make(map[string]*CacheEntry),
        maxSize:     config.MaxSize,
        defaultTTLs: config.DefaultTTLs,
        cancel:      cancel,
    }
    
    // Запуск фонового процесса очистки
    go cache.cleanupLoop(ctx, config.CleanupInterval)
    
    return cache, nil
}

func (ec *EnhancedCache) Get(key string, entryType CacheEntryType) (interface{}, bool) {
    ec.mu.RLock()
    defer ec.mu.RUnlock()
    
    entry, exists := ec.entries[key]
    if !exists {
        ec.stats.Misses++
        return nil, false
    }
    
    // Проверка типа и срока действия
    if entry.entryType != entryType || entry.isExpired() {
        ec.stats.Misses++
        return nil, false
    }
    
    // Обновление времени доступа для LRU
    entry.touch()
    ec.stats.Hits++
    
    return entry.value, true
}

func (ec *EnhancedCache) Set(key string, value interface{}, ttl time.Duration, entryType CacheEntryType) {
    ec.mu.Lock()
    defer ec.mu.Unlock()
    
    // Использование default TTL если не указан
    if ttl == 0 {
        ttl = ec.defaultTTLs[entryType]
    }
    
    // Проверка размера кэша
    if len(ec.entries) >= ec.maxSize {
        ec.evictLRU()
    }
    
    // Создание новой записи
    entry := &CacheEntry{
        value:      value,
        expiry:     time.Now().Add(ttl),
        entryType:  entryType,
        accessTime: time.Now(),
        key:        key,
    }
    
    ec.entries[key] = entry
}

func (ec *EnhancedCache) evictLRU() {
    var oldestKey string
    var oldestTime time.Time
    
    // Поиск самой старой записи
    for key, entry := range ec.entries {
        if oldestKey == "" || entry.accessTime.Before(oldestTime) {
            oldestKey = key
            oldestTime = entry.accessTime
        }
    }
    
    // Удаление самой старой записи
    if oldestKey != "" {
        delete(ec.entries, oldestKey)
        ec.stats.Evictions++
    }
}

// Структуры данных
type CacheEntry struct {
    value      interface{}
    expiry     time.Time
    entryType  CacheEntryType
    accessTime time.Time
    key        string
}

func (ce *CacheEntry) isExpired() bool {
    return time.Now().After(ce.expiry)
}

func (ce *CacheEntry) touch() {
    ce.accessTime = time.Now()
}

type CacheEntryType int

const (
    UserCredentials CacheEntryType = iota
    UserRoles
    Permissions
    MFASettings
    SessionData
)

type CacheStats struct {
    Hits           int64     `json:"hits"`
    Misses         int64     `json:"misses"`
    Evictions      int64     `json:"evictions"`
    Size           int       `json:"size"`
    MaxSize        int       `json:"max_size"`
    FallbackActive bool      `json:"fallback_active"`
    LastCleanup    time.Time `json:"last_cleanup"`
}

func (cs *CacheStats) HitRate() float64 {
    total := cs.Hits + cs.Misses
    if total == 0 {
        return 0
    }
    return float64(cs.Hits) / float64(total)
}
```

## LEVEL 4: Code Diagram

### Классы и интерфейсы
```plantuml
class EnhancedCache {
    +Get(key, entryType) (interface{}, bool)
    +Set(key, value, ttl, entryType)
    +Invalidate(pattern) error
    +InvalidateUser(userID) error
    +InvalidateType(entryType) error
    +SetFallbackMode(enabled bool)
    +GetStats() CacheStats
    +Shutdown() error
    -evictLRU()
    -cleanup()
    -cleanupLoop(ctx, interval)
}
```

**Полная реализация методов:**
```go
func (ec *EnhancedCache) Invalidate(pattern string) error {
    ec.mu.Lock()
    defer ec.mu.Unlock()
    
    // Компиляция регулярного выражения
    regex, err := regexp.Compile(pattern)
    if err != nil {
        return fmt.Errorf("invalid pattern: %w", err)
    }
    
    // Поиск и удаление соответствующих записей
    for key := range ec.entries {
        if regex.MatchString(key) {
            delete(ec.entries, key)
        }
    }
    
    return nil
}

func (ec *EnhancedCache) InvalidateUser(userID string) error {
    // Инвалидация всех записей пользователя
    pattern := fmt.Sprintf("^%s:", regexp.QuoteMeta(userID))
    return ec.Invalidate(pattern)
}

func (ec *EnhancedCache) InvalidateType(entryType CacheEntryType) error {
    ec.mu.Lock()
    defer ec.mu.Unlock()
    
    // Удаление всех записей указанного типа
    for key, entry := range ec.entries {
        if entry.entryType == entryType {
            delete(ec.entries, key)
        }
    }
    
    return nil
}

func (ec *EnhancedCache) cleanupLoop(ctx context.Context, interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            ec.cleanup()
        }
    }
}

func (ec *EnhancedCache) cleanup() {
    ec.mu.Lock()
    defer ec.mu.Unlock()
    
    now := time.Now()
    
    // Удаление истекших записей
    for key, entry := range ec.entries {
        if entry.isExpired() {
            delete(ec.entries, key)
        }
    }
    
    ec.stats.LastCleanup = now
}

func (ec *EnhancedCache) Shutdown() error {
    if ec.cancel != nil {
        ec.cancel()
    }
    
    ec.mu.Lock()
    defer ec.mu.Unlock()
    
    // Очистка всех записей
    ec.entries = make(map[string]*CacheEntry)
    
    return nil
}
```

## Deployment Diagram

### Развертывание системы
```plantuml
Deployment_Node(server, "Application Server", "Linux Server") {
    Deployment_Node(go_runtime, "Go Runtime", "Go 1.21+") {
        Container(gateway_app, "Versity S3 Gateway", "Go Application", "Main application with enhanced caching")
    }
    
    Deployment_Node(memory, "System Memory", "RAM") {
        ContainerDb(cache_memory, "Cache Storage", "In-Memory", "Primary and fallback cache data")
    }
}
```

**Конфигурация развертывания:**
```go
// config/deployment.go
type DeploymentConfig struct {
    Server struct {
        Host         string        `yaml:"host"`
        Port         int           `yaml:"port"`
        ReadTimeout  time.Duration `yaml:"read_timeout"`
        WriteTimeout time.Duration `yaml:"write_timeout"`
    } `yaml:"server"`
    
    Cache struct {
        MaxSize         int                                `yaml:"max_size"`
        CleanupInterval time.Duration                      `yaml:"cleanup_interval"`
        DefaultTTLs     map[string]time.Duration          `yaml:"default_ttls"`
    } `yaml:"cache"`
    
    FallbackCache struct {
        MaxSize         int                                `yaml:"max_size"`
        CleanupInterval time.Duration                      `yaml:"cleanup_interval"`
        DefaultTTLs     map[string]time.Duration          `yaml:"default_ttls"`
    } `yaml:"fallback_cache"`
    
    Memory struct {
        MaxHeapSize string `yaml:"max_heap_size"`
        GCPercent   int    `yaml:"gc_percent"`
    } `yaml:"memory"`
}

// Пример конфигурации
func DefaultDeploymentConfig() *DeploymentConfig {
    return &DeploymentConfig{
        Server: struct {
            Host         string        `yaml:"host"`
            Port         int           `yaml:"port"`
            ReadTimeout  time.Duration `yaml:"read_timeout"`
            WriteTimeout time.Duration `yaml:"write_timeout"`
        }{
            Host:         "0.0.0.0",
            Port:         8080,
            ReadTimeout:  30 * time.Second,
            WriteTimeout: 30 * time.Second,
        },
        Cache: struct {
            MaxSize         int                                `yaml:"max_size"`
            CleanupInterval time.Duration                      `yaml:"cleanup_interval"`
            DefaultTTLs     map[string]time.Duration          `yaml:"default_ttls"`
        }{
            MaxSize:         10000,
            CleanupInterval: 5 * time.Minute,
            DefaultTTLs: map[string]time.Duration{
                "UserCredentials": 15 * time.Minute,
                "UserRoles":      30 * time.Minute,
                "Permissions":    1 * time.Hour,
                "MFASettings":    2 * time.Hour,
                "SessionData":    10 * time.Minute,
            },
        },
        FallbackCache: struct {
            MaxSize         int                                `yaml:"max_size"`
            CleanupInterval time.Duration                      `yaml:"cleanup_interval"`
            DefaultTTLs     map[string]time.Duration          `yaml:"default_ttls"`
        }{
            MaxSize:         5000,
            CleanupInterval: 10 * time.Minute,
            DefaultTTLs: map[string]time.Duration{
                "UserCredentials": 1 * time.Hour,
                "UserRoles":      2 * time.Hour,
                "Permissions":    4 * time.Hour,
                "MFASettings":    8 * time.Hour,
                "SessionData":    30 * time.Minute,
            },
        },
    }
}
```

## Sequence Diagram: Cache Flow

### Нормальный поток с попаданием в кэш
```plantuml
client -> api: S3 Request with credentials
api -> cache: GetUserAccount(access_key)
cache -> primary: Get("user:access_key", UserCredentials)
primary -> cache: Return cached account
cache -> api: Return account
api -> client: S3 Response
```

**Реализация потока:**
```go
func (eic *EnhancedIAMCache) handleCacheHit(userKey string) (Account, error) {
    // Получение из основного кэша
    if cached, found := eic.cache.Get(userKey, UserCredentials); found {
        account := cached.(Account)
        
        // Логирование успешного попадания
        log.Printf("Cache hit for user key: %s", userKey)
        
        // Обновление метрик
        eic.cache.stats.Hits++
        
        return account, nil
    }
    
    return Account{}, errors.New("cache miss")
}
```

### Поток с промахом кэша и fallback
```plantuml
cache -> iam: GetUserAccount(access_key)
iam -> cache: Error: Service Unavailable
cache -> fallback: Get("user:access_key", UserCredentials)
fallback -> cache: Return stale account
cache -> cache: SetFallbackMode(true)
cache -> api: Return account (with fallback warning)
```

**Реализация fallback механизма:**
```go
func (eic *EnhancedIAMCache) handleServiceUnavailable(userKey string) (Account, error) {
    // Попытка получения из fallback кэша
    if cached, found := eic.fallbackCache.Get(userKey, UserCredentials); found {
        account := cached.(Account)
        
        // Активация fallback режима
        eic.cache.SetFallbackMode(true)
        eic.fallbackCache.SetFallbackMode(true)
        
        // Логирование использования fallback
        log.Printf("Using fallback cache for user key: %s", userKey)
        
        // Обновление метрик
        eic.fallbackCache.stats.Hits++
        eic.cache.stats.FallbackActive = true
        
        return account, nil
    }
    
    return Account{}, errors.New("service unavailable and no fallback data")
}
```

C4 Architecture Diagram Task 1 обеспечивает полное понимание Enhanced Cache System от высокоуровневого контекста до деталей реализации, служа мостом между архитектурными решениями и конкретным кодом системы кэширования аутентификации.