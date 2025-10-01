# Подробное объяснение Container Diagram Task 3 - Enhanced RBAC System

## Назначение диаграммы

Container Diagram для Task 3 детализирует внутреннюю архитектуру системы Enhanced RBAC, показывая основные контейнеры (приложения/сервисы), их технологии и взаимодействие. Эта диаграмма служит мостом между высокоуровневым контекстом и детальной реализацией компонентов.

## Структура PlantUML и архитектурные решения

### Заголовок и участники
```plantuml
@startuml Task3-Container-Diagram
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Container.puml
title Task 3: Enhanced Role-Based Access Control System - Container Diagram

Person(user, "User", "S3 API user")
Person(admin, "Administrator", "System administrator")
```

**Архитектурное значение:**
- Фокус на внутренней структуре системы RBAC
- Показывает технологические границы между компонентами

## Основные контейнеры системы

### 1. S3 API Gateway
```plantuml
Container(s3_api, "S3 API Gateway", "Go/Fiber", "Handles S3 API requests and responses")
```

**Связь с реализацией:**
```go
// main.go - основной сервер S3 API
type S3APIServer struct {
    app        *fiber.App
    authSystem *EnhancedAuthSystem
    backend    backend.Backend
    config     *Config
}

func NewS3APIServer(config *Config) *S3APIServer {
    app := fiber.New(fiber.Config{
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
    })
    
    server := &S3APIServer{
        app:     app,
        config:  config,
    }
    
    server.setupRoutes()
    return server
}

func (s *S3APIServer) setupRoutes() {
    // S3 API endpoints
    s.app.Get("/:bucket", s.handleListObjects)
    s.app.Get("/:bucket/:object", s.handleGetObject)
    s.app.Put("/:bucket/:object", s.handlePutObject)
    s.app.Delete("/:bucket/:object", s.handleDeleteObject)
    
    // Admin endpoints для управления ролями
    admin := s.app.Group("/admin")
    admin.Post("/roles", s.handleCreateRole)
    admin.Get("/roles/:id", s.handleGetRole)
}
```

**Ключевые особенности реализации:**
- Использование Fiber framework для высокой производительности
- Middleware для аутентификации и авторизации
- Поддержка стандартного S3 API протокола
### 
2. Authentication & Authorization Container Boundary

#### Access Control Engine
```plantuml
Container(access_control, "Access Control Engine", "Go", "Core access verification logic with enhanced role support")
```

**Связь с реализацией:**
```go
// auth/access.go - основная логика контроля доступа
type AccessControlEngine struct {
    roleManager     RoleManager
    permissionCache Cache
    auditLogger     AuditLogger
    fallbackChecker *TraditionalAccessChecker
}

func (ace *AccessControlEngine) VerifyAccess(ctx context.Context, opts *AccessOptions) error {
    // Проверка базовых условий
    if ace.isPublicBucket(opts.Bucket) {
        return nil
    }
    
    if ace.isRootUser(opts.Acc) {
        return nil
    }
    
    // Enhanced RBAC проверка
    if opts.RoleManager != nil {
        return ace.verifyEnhancedRoleAccess(ctx, opts)
    }
    
    // Fallback к традиционной проверке
    return ace.fallbackChecker.VerifyAccess(ctx, opts)
}

func (ace *AccessControlEngine) verifyEnhancedRoleAccess(ctx context.Context, opts *AccessOptions) error {
    // Получение эффективных разрешений пользователя
    permissions, err := opts.RoleManager.GetEffectivePermissions(opts.Acc.UserID)
    if err != nil {
        return fmt.Errorf("failed to get effective permissions: %w", err)
    }
    
    // Построение ARN ресурса
    resourceARN := buildResourceARN(opts.Bucket, opts.Object)
    
    // Проверка разрешения
    if permissions.HasPermission(resourceARN, string(opts.Action)) {
        ace.auditLogger.LogAccessGranted(ctx, opts)
        return nil
    }
    
    ace.auditLogger.LogAccessDenied(ctx, opts)
    return ErrAccessDenied
}
```

#### Role Manager
```plantuml
Container(role_manager, "Role Manager", "Go", "Manages enhanced roles, permissions, and hierarchies")
```

**Связь с реализацией:**
```go
// auth/rbac.go - управление ролями
type RoleManager interface {
    CreateRole(role *EnhancedRole) error
    GetRole(roleID string) (*EnhancedRole, error)
    GetUserRoles(userID string) ([]*EnhancedRole, error)
    GetEffectivePermissions(userID string) (*PermissionSet, error)
    AssignRole(userID, roleID, assignedBy string) error
    RevokeRole(userID, roleID string) error
    CheckPermission(userID, resource, action string) (bool, error)
}

// Конкретная реализация в памяти
type InMemoryRoleManager struct {
    roles       map[string]*EnhancedRole
    assignments map[string][]*RoleAssignment
    mutex       sync.RWMutex
    validator   *PermissionValidator
    cache       Cache
}

func (rm *InMemoryRoleManager) GetEffectivePermissions(userID string) (*PermissionSet, error) {
    // Проверка кэша
    if cached := rm.cache.GetPermissions(userID); cached != nil {
        return cached, nil
    }
    
    // Получение ролей пользователя
    roles, err := rm.GetUserRoles(userID)
    if err != nil {
        return nil, err
    }
    
    // Расширение иерархии ролей
    expandedRoles, err := rm.expandRoleHierarchy(roles)
    if err != nil {
        return nil, err
    }
    
    // Агрегация разрешений
    permissions := rm.aggregatePermissions(expandedRoles)
    
    // Кэширование результата
    rm.cache.SetPermissions(userID, permissions, 5*time.Minute)
    
    return permissions, nil
}

func (rm *InMemoryRoleManager) expandRoleHierarchy(roles []*EnhancedRole) ([]*EnhancedRole, error) {
    expanded := make(map[string]*EnhancedRole)
    
    var expandRole func(role *EnhancedRole) error
    expandRole = func(role *EnhancedRole) error {
        if _, exists := expanded[role.ID]; exists {
            return nil // Уже обработана
        }
        
        expanded[role.ID] = role
        
        // Рекурсивное расширение родительских ролей
        for _, parentID := range role.ParentRoles {
            parentRole, err := rm.GetRole(parentID)
            if err != nil {
                return fmt.Errorf("failed to get parent role %s: %w", parentID, err)
            }
            
            if err := expandRole(parentRole); err != nil {
                return err
            }
        }
        
        return nil
    }
    
    // Расширение всех ролей
    for _, role := range roles {
        if err := expandRole(role); err != nil {
            return nil, err
        }
    }
    
    // Преобразование в слайс
    result := make([]*EnhancedRole, 0, len(expanded))
    for _, role := range expanded {
        result = append(result, role)
    }
    
    return result, nil
}
```

#### Permission Engine
```plantuml
Container(permission_engine, "Permission Engine", "Go", "Evaluates permissions and handles aggregation")
```

**Связь с реализацией:**
```go
// auth/permissions.go - движок разрешений
type PermissionEngine struct {
    patternMatcher *ARNPatternMatcher
    aggregator     *PermissionAggregator
}

type PermissionSet struct {
    Permissions []DetailedPermission `json:"permissions"`
    ComputedAt  time.Time           `json:"computed_at"`
}

func (ps *PermissionSet) HasPermission(resource, action string) bool {
    for _, perm := range ps.Permissions {
        if perm.Matches(resource, action) {
            return perm.Effect == PermissionAllow
        }
    }
    return false // Deny by default
}

type DetailedPermission struct {
    Resource   string                 `json:"resource"`   // ARN pattern like "arn:aws:s3:::bucket/*"
    Action     string                 `json:"action"`     // S3 action like "s3:GetObject"
    Effect     PermissionEffect       `json:"effect"`     // Allow or Deny
    Conditions map[string]interface{} `json:"conditions"` // Additional conditions
}

func (dp *DetailedPermission) Matches(resource, action string) bool {
    // Проверка соответствия ресурса
    if !dp.matchesResource(resource) {
        return false
    }
    
    // Проверка соответствия действия
    if !dp.matchesAction(action) {
        return false
    }
    
    // Проверка дополнительных условий
    return dp.evaluateConditions()
}

func (dp *DetailedPermission) matchesResource(resource string) bool {
    // Поддержка AWS ARN patterns
    // arn:aws:s3:::* - все buckets
    // arn:aws:s3:::bucket/* - все объекты в bucket
    // arn:aws:s3:::bucket/prefix* - объекты с префиксом
    
    pattern := dp.Resource
    if strings.HasSuffix(pattern, "*") {
        prefix := strings.TrimSuffix(pattern, "*")
        return strings.HasPrefix(resource, prefix)
    }
    
    return pattern == resource
}

// Агрегатор разрешений с union семантикой
type PermissionAggregator struct{}

func (pa *PermissionAggregator) ComputeEffectivePermissions(roles []*EnhancedRole) *PermissionSet {
    allPermissions := make([]DetailedPermission, 0)
    
    // Сбор всех разрешений из ролей
    for _, role := range roles {
        allPermissions = append(allPermissions, role.Permissions...)
    }
    
    // Разрешение конфликтов (Deny wins principle)
    resolvedPermissions := pa.resolvePermissionConflicts(allPermissions)
    
    return &PermissionSet{
        Permissions: resolvedPermissions,
        ComputedAt:  time.Now(),
    }
}

func (pa *PermissionAggregator) resolvePermissionConflicts(permissions []DetailedPermission) []DetailedPermission {
    // Группировка по ресурсу и действию
    permissionMap := make(map[string]DetailedPermission)
    
    for _, perm := range permissions {
        key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
        
        existing, exists := permissionMap[key]
        if !exists {
            permissionMap[key] = perm
            continue
        }
        
        // Применение принципа "Deny wins"
        if perm.Effect == PermissionDeny || existing.Effect == PermissionDeny {
            perm.Effect = PermissionDeny
        }
        
        permissionMap[key] = perm
    }
    
    // Преобразование обратно в слайс
    result := make([]DetailedPermission, 0, len(permissionMap))
    for _, perm := range permissionMap {
        result = append(result, perm)
    }
    
    return result
}
```

#### Enhanced Cache
```plantuml
Container(cache_layer, "Enhanced Cache", "Go/In-Memory", "Caches roles, permissions, and access decisions")
```

**Связь с реализацией:**
```go
// auth/cache.go - система кэширования
type Cache interface {
    GetPermissions(userID string) *PermissionSet
    SetPermissions(userID string, permissions *PermissionSet, ttl time.Duration)
    GetRole(roleID string) *EnhancedRole
    SetRole(roleID string, role *EnhancedRole, ttl time.Duration)
    InvalidateUser(userID string)
    InvalidateRole(roleID string)
}

type LRUCache struct {
    permissions map[string]*CacheEntry
    roles       map[string]*CacheEntry
    mutex       sync.RWMutex
    maxSize     int
    ttlManager  *TTLManager
}

type CacheEntry struct {
    Value     interface{}
    ExpiresAt time.Time
    AccessedAt time.Time
}

func (c *LRUCache) GetPermissions(userID string) *PermissionSet {
    c.mutex.RLock()
    defer c.mutex.RUnlock()
    
    entry, exists := c.permissions[userID]
    if !exists || entry.ExpiresAt.Before(time.Now()) {
        return nil
    }
    
    // Обновление времени доступа для LRU
    entry.AccessedAt = time.Now()
    
    return entry.Value.(*PermissionSet)
}

func (c *LRUCache) SetPermissions(userID string, permissions *PermissionSet, ttl time.Duration) {
    c.mutex.Lock()
    defer c.mutex.Unlock()
    
    // Проверка размера кэша и вытеснение при необходимости
    if len(c.permissions) >= c.maxSize {
        c.evictLRU()
    }
    
    c.permissions[userID] = &CacheEntry{
        Value:      permissions,
        ExpiresAt:  time.Now().Add(ttl),
        AccessedAt: time.Now(),
    }
}

func (c *LRUCache) evictLRU() {
    var oldestKey string
    var oldestTime time.Time
    
    for key, entry := range c.permissions {
        if oldestKey == "" || entry.AccessedAt.Before(oldestTime) {
            oldestKey = key
            oldestTime = entry.AccessedAt
        }
    }
    
    if oldestKey != "" {
        delete(c.permissions, oldestKey)
    }
}

// TTL Manager для автоматической очистки
type TTLManager struct {
    cache     *LRUCache
    stopCh    chan struct{}
    cleanupInterval time.Duration
}

func (tm *TTLManager) Start() {
    ticker := time.NewTicker(tm.cleanupInterval)
    go func() {
        for {
            select {
            case <-ticker.C:
                tm.cleanup()
            case <-tm.stopCh:
                ticker.Stop()
                return
            }
        }
    }()
}

func (tm *TTLManager) cleanup() {
    now := time.Now()
    
    tm.cache.mutex.Lock()
    defer tm.cache.mutex.Unlock()
    
    // Очистка просроченных разрешений
    for key, entry := range tm.cache.permissions {
        if entry.ExpiresAt.Before(now) {
            delete(tm.cache.permissions, key)
        }
    }
    
    // Очистка просроченных ролей
    for key, entry := range tm.cache.roles {
        if entry.ExpiresAt.Before(now) {
            delete(tm.cache.roles, key)
        }
    }
}
```

### 3. Authentication Middleware
```plantuml
Container(middleware, "Authentication Middleware", "Go/Fiber", "Intercepts requests and enforces access control")
```

**Связь с реализацией:**
```go
// middleware/auth.go - middleware для аутентификации
type AuthMiddleware struct {
    accessControl *AccessControlEngine
    roleManager   RoleManager
}

func NewAuthMiddleware(accessControl *AccessControlEngine, roleManager RoleManager) *AuthMiddleware {
    return &AuthMiddleware{
        accessControl: accessControl,
        roleManager:   roleManager,
    }
}

func (am *AuthMiddleware) Handler() fiber.Handler {
    return func(c *fiber.Ctx) error {
        // Извлечение информации о пользователе из запроса
        account, err := am.extractAccountFromRequest(c)
        if err != nil {
            return c.Status(401).JSON(fiber.Map{"error": "Authentication required"})
        }
        
        // Создание AccessOptions
        opts := &AccessOptions{
            Acc:         account,
            Bucket:      c.Params("bucket"),
            Object:      c.Params("object", ""),
            Action:      Action(c.Method()),
            RoleManager: am.roleManager,
        }
        
        // Проверка доступа
        if err := am.accessControl.VerifyAccess(c.Context(), opts); err != nil {
            return c.Status(403).JSON(fiber.Map{"error": "Access denied"})
        }
        
        // Сохранение информации о пользователе в контексте
        c.Locals("account", account)
        c.Locals("accessOptions", opts)
        
        return c.Next()
    }
}

func (am *AuthMiddleware) extractAccountFromRequest(c *fiber.Ctx) (Account, error) {
    // Извлечение из AWS Signature V4
    authHeader := c.Get("Authorization")
    if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
        return am.parseAWSSignature(authHeader, c)
    }
    
    // Извлечение из Bearer token
    if strings.HasPrefix(authHeader, "Bearer ") {
        return am.parseBearerToken(authHeader)
    }
    
    return Account{}, errors.New("no valid authentication found")
}
```

### 4. Audit Logger
```plantuml
Container(audit_logger, "Audit Logger", "Go", "Logs security events and access attempts")
```

**Связь с реализацией:**
```go
// audit/logger.go - аудит логирование
type AuditLogger struct {
    writer     io.Writer
    formatter  LogFormatter
    buffer     chan *AuditEvent
    batchSize  int
    flushInterval time.Duration
}

type AuditEvent struct {
    Timestamp   time.Time `json:"timestamp"`
    EventType   string    `json:"event_type"`
    UserID      string    `json:"user_id"`
    Resource    string    `json:"resource"`
    Action      string    `json:"action"`
    Result      string    `json:"result"`
    IPAddress   string    `json:"ip_address"`
    UserAgent   string    `json:"user_agent"`
    RequestID   string    `json:"request_id"`
    Details     map[string]interface{} `json:"details,omitempty"`
}

func (al *AuditLogger) LogAccessGranted(ctx context.Context, opts *AccessOptions) {
    event := &AuditEvent{
        Timestamp: time.Now(),
        EventType: "access_granted",
        UserID:    opts.Acc.UserID,
        Resource:  buildResourceARN(opts.Bucket, opts.Object),
        Action:    string(opts.Action),
        Result:    "allowed",
        IPAddress: extractIPFromContext(ctx),
        UserAgent: extractUserAgentFromContext(ctx),
        RequestID: extractRequestIDFromContext(ctx),
    }
    
    al.logEvent(event)
}

func (al *AuditLogger) LogAccessDenied(ctx context.Context, opts *AccessOptions) {
    event := &AuditEvent{
        Timestamp: time.Now(),
        EventType: "access_denied",
        UserID:    opts.Acc.UserID,
        Resource:  buildResourceARN(opts.Bucket, opts.Object),
        Action:    string(opts.Action),
        Result:    "denied",
        IPAddress: extractIPFromContext(ctx),
        UserAgent: extractUserAgentFromContext(ctx),
        RequestID: extractRequestIDFromContext(ctx),
    }
    
    al.logEvent(event)
}

func (al *AuditLogger) logEvent(event *AuditEvent) {
    select {
    case al.buffer <- event:
        // Событие добавлено в буфер
    default:
        // Буфер полон, логируем синхронно
        al.writeEvent(event)
    }
}

// Асинхронная обработка событий
func (al *AuditLogger) Start() {
    go func() {
        batch := make([]*AuditEvent, 0, al.batchSize)
        ticker := time.NewTicker(al.flushInterval)
        
        for {
            select {
            case event := <-al.buffer:
                batch = append(batch, event)
                if len(batch) >= al.batchSize {
                    al.writeBatch(batch)
                    batch = batch[:0]
                }
                
            case <-ticker.C:
                if len(batch) > 0 {
                    al.writeBatch(batch)
                    batch = batch[:0]
                }
            }
        }
    }()
}
```

## Хранилища данных

### Role Storage
```plantuml
ContainerDb(role_storage, "Role Storage", "File System/Database", "Stores role definitions and assignments")
```

**Связь с реализацией:**
```go
// storage/file_storage.go - файловое хранилище ролей
type FileRoleStorage struct {
    dataDir     string
    rolesFile   string
    assignmentsFile string
    mutex       sync.RWMutex
}

func NewFileRoleStorage(dataDir string) *FileRoleStorage {
    return &FileRoleStorage{
        dataDir:         dataDir,
        rolesFile:       filepath.Join(dataDir, "roles.json"),
        assignmentsFile: filepath.Join(dataDir, "assignments.json"),
    }
}

func (frs *FileRoleStorage) SaveRole(role *EnhancedRole) error {
    frs.mutex.Lock()
    defer frs.mutex.Unlock()
    
    // Загрузка существующих ролей
    roles, err := frs.loadRoles()
    if err != nil {
        return err
    }
    
    // Обновление или добавление роли
    roles[role.ID] = role
    
    // Сохранение в файл
    return frs.saveRoles(roles)
}

func (frs *FileRoleStorage) loadRoles() (map[string]*EnhancedRole, error) {
    if _, err := os.Stat(frs.rolesFile); os.IsNotExist(err) {
        return make(map[string]*EnhancedRole), nil
    }
    
    data, err := os.ReadFile(frs.rolesFile)
    if err != nil {
        return nil, err
    }
    
    var roles map[string]*EnhancedRole
    if err := json.Unmarshal(data, &roles); err != nil {
        return nil, err
    }
    
    return roles, nil
}

func (frs *FileRoleStorage) saveRoles(roles map[string]*EnhancedRole) error {
    data, err := json.MarshalIndent(roles, "", "  ")
    if err != nil {
        return err
    }
    
    // Атомарная запись через временный файл
    tempFile := frs.rolesFile + ".tmp"
    if err := os.WriteFile(tempFile, data, 0644); err != nil {
        return err
    }
    
    return os.Rename(tempFile, frs.rolesFile)
}
```

## Взаимодействие между контейнерами

### Основные потоки данных
```plantuml
Rel(s3_api, middleware, "Request processing", "Go function calls")
Rel(middleware, access_control, "Verify access", "Go function calls")
Rel(access_control, role_manager, "Get user roles", "Go interface")
Rel(access_control, permission_engine, "Evaluate permissions", "Go function calls")
```

**Реализация потока запроса:**
```go
// Полный поток обработки S3 запроса
func (s *S3APIServer) handleGetObject(c *fiber.Ctx) error {
    // 1. Middleware извлекает и проверяет аутентификацию
    account := c.Locals("account").(Account)
    opts := c.Locals("accessOptions").(*AccessOptions)
    
    // 2. Доступ уже проверен в middleware, выполняем запрос
    object, err := s.backend.GetObject(c.Context(), opts.Bucket, opts.Object)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }
    
    // 3. Возвращаем объект клиенту
    c.Set("Content-Type", object.ContentType)
    c.Set("Content-Length", fmt.Sprintf("%d", object.Size))
    return c.Send(object.Data)
}

// Интеграция всех компонентов в main.go
func main() {
    // Инициализация компонентов
    cache := NewLRUCache(1000)
    roleStorage := NewFileRoleStorage("./data/roles")
    roleManager := NewFileBasedRoleManager(roleStorage, cache)
    permissionEngine := NewPermissionEngine()
    accessControl := NewAccessControlEngine(roleManager, permissionEngine, cache)
    auditLogger := NewAuditLogger(os.Stdout)
    
    // Создание middleware
    authMiddleware := NewAuthMiddleware(accessControl, roleManager)
    
    // Создание S3 API сервера
    s3Server := NewS3APIServer(&Config{
        Port: 8080,
    })
    
    // Подключение middleware
    s3Server.app.Use(authMiddleware.Handler())
    
    // Запуск сервера
    log.Fatal(s3Server.app.Listen(":8080"))
}
```

## Архитектурные паттерны и их реализация

### 1. Dependency Injection
```go
// Все зависимости инжектируются через конструкторы
type AccessControlEngine struct {
    roleManager     RoleManager     // Интерфейс, а не конкретная реализация
    permissionEngine *PermissionEngine
    cache          Cache           // Интерфейс для различных реализаций кэша
    auditLogger    AuditLogger
}

func NewAccessControlEngine(rm RoleManager, pe *PermissionEngine, c Cache, al AuditLogger) *AccessControlEngine {
    return &AccessControlEngine{
        roleManager:      rm,
        permissionEngine: pe,
        cache:           c,
        auditLogger:     al,
    }
}
```

### 2. Strategy Pattern
```go
// Различные стратегии для RoleManager
type RoleManager interface {
    // ... методы интерфейса
}

// Стратегия для работы с памятью
type InMemoryRoleManager struct { /* ... */ }

// Стратегия для работы с файлами
type FileBasedRoleManager struct { /* ... */ }

// Стратегия для работы с базой данных
type DatabaseRoleManager struct { /* ... */ }
```

### 3. Observer Pattern
```go
// Система событий для инвалидации кэша
type CacheInvalidationObserver interface {
    OnRoleChanged(roleID string)
    OnUserRoleChanged(userID string)
}

func (rm *InMemoryRoleManager) AssignRole(userID, roleID, assignedBy string) error {
    // ... логика назначения роли
    
    // Уведомление наблюдателей
    for _, observer := range rm.observers {
        observer.OnUserRoleChanged(userID)
    }
    
    return nil
}
```

## Соответствие требованиям Task 3

### 3.1 Расширение системы ролей с детальными разрешениями
**Контейнеры:** Role Manager + Permission Engine
**Реализация:** EnhancedRole с DetailedPermission, поддержка иерархии ролей

### 3.2 Динамическое назначение и обновление ролей
**Контейнеры:** Role Manager + Enhanced Cache
**Реализация:** Real-time обновления с инвалидацией кэша

### 3.3 Интеграция с проверкой контроля доступа
**Контейнеры:** Access Control Engine + Authentication Middleware
**Реализация:** Модифицированная функция VerifyAccess с поддержкой Enhanced RBAC

Container Diagram Task 3 обеспечивает детальное понимание архитектуры системы Enhanced RBAC на уровне контейнеров и служит основой для дальнейшей детализации компонентов, при этом каждый контейнер имеет прямое соответствие в реализации кода.