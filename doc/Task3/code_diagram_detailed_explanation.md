# Подробное объяснение Code Diagram Task 3 - Enhanced RBAC System

## Назначение диаграммы

Code Diagram для Task 3 представляет самый детальный уровень архитектуры Enhanced RBAC системы, показывая конкретные Go структуры, интерфейсы, методы и их взаимосвязи. Эта диаграмма служит прямым мостом между архитектурным дизайном и фактической реализацией кода, обеспечивая 1:1 соответствие между элементами диаграммы и кодом.

## Структура PlantUML и реализация

### Заголовок и ключевые детали реализации
```plantuml
@startuml Task3-Code-Diagram
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Component.puml
title Task 3: Enhanced Role-Based Access Control System - Code Level Diagram

note as N1
  <b>Key Implementation Details:</b>
  • VerifyAccess function modified for enhanced role integration
  • Permission aggregation with union semantics
  • Role hierarchy support with inheritance
  • AWS ARN pattern matching for S3 resources
  • Comprehensive test coverage with 9 test scenarios
end note
```

**Архитектурное значение:**
- Документирует ключевые особенности реализации
- Подчеркивает важные архитектурные решения
- Связывает диаграмму с тестовым покрытием

## Основные структуры данных и их реализация

### AccessOptions - Контекст запроса доступа
```plantuml
class "AccessOptions" {
    +Acl: ACL
    +AclPermission: Permission
    +IsRoot: bool
    +Acc: Account
    +Bucket: string
    +Object: string
    +Action: Action
    +RoleManager: RoleManager
}
```

**Полная реализация:**
```go
// auth/types.go - основная структура параметров доступа
type AccessOptions struct {
    // Традиционные поля ACL (для обратной совместимости)
    Acl           ACL        `json:"acl,omitempty"`
    AclPermission Permission `json:"acl_permission,omitempty"`
    
    // Информация о пользователе
    IsRoot bool    `json:"is_root"`
    Acc    Account `json:"account"`
    
    // Ресурс и действие
    Bucket string `json:"bucket"`
    Object string `json:"object,omitempty"`
    Action Action `json:"action"`
    
    // Enhanced RBAC компоненты
    RoleManager RoleManager `json:"-"` // Не сериализуется в JSON
    
    // Дополнительный контекст
    RequestTime   time.Time              `json:"request_time"`
    ClientIP      string                 `json:"client_ip,omitempty"`
    UserAgent     string                 `json:"user_agent,omitempty"`
    RequestID     string                 `json:"request_id,omitempty"`
    Context       map[string]interface{} `json:"context,omitempty"`
}

// Конструктор для создания AccessOptions
func NewAccessOptions(account Account, bucket, object string, action Action) *AccessOptions {
    return &AccessOptions{
        Acc:         account,
        Bucket:      bucket,
        Object:      object,
        Action:      action,
        RequestTime: time.Now(),
        Context:     make(map[string]interface{}),
    }
}

// Валидация параметров доступа
func (opts *AccessOptions) Validate() error {
    if opts.Acc.UserID == "" {
        return errors.New("user ID is required")
    }
    
    if opts.Bucket == "" {
        return errors.New("bucket name is required")
    }
    
    if opts.Action == "" {
        return errors.New("action is required")
    }
    
    // Валидация имени bucket (AWS S3 правила)
    if !isValidBucketName(opts.Bucket) {
        return fmt.Errorf("invalid bucket name: %s", opts.Bucket)
    }
    
    return nil
}

// Построение ARN ресурса
func (opts *AccessOptions) GetResourceARN() string {
    if opts.Object == "" {
        return fmt.Sprintf("arn:aws:s3:::%s", opts.Bucket)
    }
    return fmt.Sprintf("arn:aws:s3:::%s/%s", opts.Bucket, opts.Object)
}

// Добавление контекстной информации
func (opts *AccessOptions) WithContext(key string, value interface{}) *AccessOptions {
    if opts.Context == nil {
        opts.Context = make(map[string]interface{})
    }
    opts.Context[key] = value
    return opts
}

// Проверка является ли запрос от root пользователя
func (opts *AccessOptions) IsRootUser() bool {
    return opts.IsRoot || opts.Acc.UserID == "root" || opts.Acc.UserID == "admin"
}
```

### VerifyAccess - Главная функция проверки доступа
```plantuml
class "VerifyAccess" <<function>> {
    +VerifyAccess(ctx, backend, opts): error
    +verifyEnhancedRoleAccessWithAggregation(): (bool, error)
    +buildResourceARN(bucket, object): string
}
```

**Полная реализация:**
```go
// auth/access.go - главная функция проверки доступа
func VerifyAccess(ctx context.Context, backend backend.Backend, opts *AccessOptions) error {
    // Валидация входных параметров
    if err := opts.Validate(); err != nil {
        return fmt.Errorf("invalid access options: %w", err)
    }
    
    // Логирование запроса доступа
    logAccessAttempt(ctx, opts)
    
    // Проверка базовых условий (быстрые проверки)
    if result, handled := checkBasicConditions(opts); handled {
        return result
    }
    
    // Enhanced RBAC проверка (если доступен RoleManager)
    if opts.RoleManager != nil {
        return verifyEnhancedRoleAccessWithAggregation(ctx, opts)
    }
    
    // Fallback к традиционной проверке доступа
    return verifyTraditionalAccess(ctx, backend, opts)
}

// Проверка базовых условий
func checkBasicConditions(opts *AccessOptions) (error, bool) {
    // Публичные bucket'ы
    if isPublicBucket(opts.Bucket) {
        return nil, true
    }
    
    // Root пользователи
    if opts.IsRootUser() {
        return nil, true
    }
    
    // Административные роли (быстрая проверка)
    if hasAdminRole(opts.Acc) {
        return nil, true
    }
    
    return nil, false // Продолжить обычную проверку
}

// Основная функция Enhanced RBAC
func verifyEnhancedRoleAccessWithAggregation(ctx context.Context, opts *AccessOptions) error {
    startTime := time.Now()
    
    // Получение эффективных разрешений пользователя
    permissions, err := opts.RoleManager.GetEffectivePermissions(opts.Acc.UserID)
    if err != nil {
        recordMetric("rbac_permission_fetch_error", time.Since(startTime))
        return fmt.Errorf("failed to get effective permissions: %w", err)
    }
    
    // Построение ARN ресурса
    resourceARN := opts.GetResourceARN()
    
    // Проверка разрешения
    if permissions.HasPermission(resourceARN, string(opts.Action)) {
        recordMetric("rbac_access_granted", time.Since(startTime))
        logAccessGranted(ctx, opts, permissions)
        return nil
    }
    
    recordMetric("rbac_access_denied", time.Since(startTime))
    logAccessDenied(ctx, opts, permissions)
    return ErrAccessDenied
}

// Построение AWS ARN для ресурса
func buildResourceARN(bucket, object string) string {
    if object == "" {
        return fmt.Sprintf("arn:aws:s3:::%s", bucket)
    }
    return fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, object)
}

// Традиционная проверка доступа (fallback)
func verifyTraditionalAccess(ctx context.Context, backend backend.Backend, opts *AccessOptions) error {
    // Проверка bucket policy
    if err := verifyBucketPolicy(ctx, backend, opts); err != nil {
        return err
    }
    
    // Проверка ACL
    if err := verifyACL(ctx, backend, opts); err != nil {
        return err
    }
    
    return nil
}
```

### RoleManager Interface - Интерфейс управления ролями
```plantuml
interface "RoleManager" {
    +CreateRole(*EnhancedRole): error
    +GetRole(roleID): (*EnhancedRole, error)
    +GetUserRoles(userID): ([]*EnhancedRole, error)
    +GetEffectivePermissions(userID): (*PermissionSet, error)
    +CheckPermission(userID, resource, action): (bool, error)
    +AssignRole(userID, roleID, assignedBy): error
    +RevokeRole(userID, roleID): error
}
```

**Полная реализация интерфейса:**
```go
// auth/rbac.go - интерфейс управления ролями
type RoleManager interface {
    // Управление ролями
    CreateRole(role *EnhancedRole) error
    GetRole(roleID string) (*EnhancedRole, error)
    UpdateRole(role *EnhancedRole) error
    DeleteRole(roleID string) error
    ListRoles() ([]*EnhancedRole, error)
    
    // Управление назначениями ролей
    AssignRole(userID, roleID, assignedBy string) error
    RevokeRole(userID, roleID string) error
    GetUserRoles(userID string) ([]*EnhancedRole, error)
    GetRoleAssignments(roleID string) ([]*RoleAssignment, error)
    
    // Проверка разрешений
    GetEffectivePermissions(userID string) (*PermissionSet, error)
    CheckPermission(userID, resource, action string) (bool, error)
    
    // Валидация и утилиты
    ValidateRole(role *EnhancedRole) error
    ValidatePermission(permission *DetailedPermission) error
    
    // Управление иерархией
    GetRoleHierarchy(roleID string) ([]*EnhancedRole, error)
    CheckCircularDependency(role *EnhancedRole) error
    
    // Кэширование и производительность
    InvalidateCache(userID string)
    GetCacheStats() *CacheStats
}

// Статистика кэша
type CacheStats struct {
    HitRate        float64 `json:"hit_rate"`
    TotalRequests  int64   `json:"total_requests"`
    CacheHits      int64   `json:"cache_hits"`
    CacheMisses    int64   `json:"cache_misses"`
    EvictionCount  int64   `json:"eviction_count"`
    CurrentSize    int     `json:"current_size"`
    MaxSize        int     `json:"max_size"`
}
```

### InMemoryRoleManager - Реализация в памяти
```plantuml
class "InMemoryRoleManager" {
    -roles: map[string]*EnhancedRole
    -assignments: map[string][]*RoleAssignment
    -mutex: sync.RWMutex
    -validator: *PermissionValidator
    +NewInMemoryRoleManager(): *InMemoryRoleManager
    +expandRoleHierarchy([]*EnhancedRole): ([]*EnhancedRole, error)
}
```

**Полная реализация:**
```go
// auth/inmemory_role_manager.go - реализация в памяти
type InMemoryRoleManager struct {
    // Хранилище данных
    roles       map[string]*EnhancedRole
    assignments map[string][]*RoleAssignment
    
    // Синхронизация
    mutex sync.RWMutex
    
    // Компоненты
    validator *PermissionValidator
    cache     Cache
    metrics   *RoleManagerMetrics
    
    // Конфигурация
    config *RoleManagerConfig
}

type RoleManagerConfig struct {
    MaxRolesPerUser      int           `json:"max_roles_per_user"`
    MaxRoleHierarchyDepth int          `json:"max_role_hierarchy_depth"`
    CacheTTL             time.Duration `json:"cache_ttl"`
    EnableMetrics        bool          `json:"enable_metrics"`
}

func NewInMemoryRoleManager(config *RoleManagerConfig) *InMemoryRoleManager {
    if config == nil {
        config = &RoleManagerConfig{
            MaxRolesPerUser:       10,
            MaxRoleHierarchyDepth: 5,
            CacheTTL:             5 * time.Minute,
            EnableMetrics:        true,
        }
    }
    
    return &InMemoryRoleManager{
        roles:       make(map[string]*EnhancedRole),
        assignments: make(map[string][]*RoleAssignment),
        validator:   NewPermissionValidator(),
        cache:       NewLRUCache(1000),
        metrics:     NewRoleManagerMetrics(),
        config:      config,
    }
}

func (rm *InMemoryRoleManager) GetEffectivePermissions(userID string) (*PermissionSet, error) {
    // Проверка кэша
    if cached := rm.cache.GetPermissions(userID); cached != nil {
        rm.metrics.CacheHits.Inc()
        return cached, nil
    }
    rm.metrics.CacheMisses.Inc()
    
    // Получение ролей пользователя
    roles, err := rm.GetUserRoles(userID)
    if err != nil {
        return nil, fmt.Errorf("failed to get user roles: %w", err)
    }
    
    // Расширение иерархии ролей
    expandedRoles, err := rm.expandRoleHierarchy(roles)
    if err != nil {
        return nil, fmt.Errorf("failed to expand role hierarchy: %w", err)
    }
    
    // Агрегация разрешений
    permissions := rm.aggregatePermissions(expandedRoles)
    
    // Кэширование результата
    rm.cache.SetPermissions(userID, permissions, rm.config.CacheTTL)
    
    return permissions, nil
}

func (rm *InMemoryRoleManager) expandRoleHierarchy(roles []*EnhancedRole) ([]*EnhancedRole, error) {
    expanded := make(map[string]*EnhancedRole)
    visited := make(map[string]bool)
    depth := 0
    
    var expandRole func(role *EnhancedRole, currentDepth int) error
    expandRole = func(role *EnhancedRole, currentDepth int) error {
        // Проверка глубины иерархии
        if currentDepth > rm.config.MaxRoleHierarchyDepth {
            return fmt.Errorf("role hierarchy depth exceeded: %d", currentDepth)
        }
        
        // Проверка циклических зависимостей
        if visited[role.ID] {
            return fmt.Errorf("circular dependency detected: role %s", role.ID)
        }
        
        if _, exists := expanded[role.ID]; exists {
            return nil // Уже обработана
        }
        
        visited[role.ID] = true
        expanded[role.ID] = role
        
        // Рекурсивное расширение родительских ролей
        for _, parentID := range role.ParentRoles {
            parentRole, err := rm.GetRole(parentID)
            if err != nil {
                return fmt.Errorf("failed to get parent role %s: %w", parentID, err)
            }
            
            if err := expandRole(parentRole, currentDepth+1); err != nil {
                return err
            }
        }
        
        visited[role.ID] = false
        return nil
    }
    
    // Расширение всех ролей
    for _, role := range roles {
        if err := expandRole(role, 0); err != nil {
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

func (rm *InMemoryRoleManager) aggregatePermissions(roles []*EnhancedRole) *PermissionSet {
    allPermissions := make([]DetailedPermission, 0)
    
    // Сбор всех разрешений из ролей
    for _, role := range roles {
        allPermissions = append(allPermissions, role.Permissions...)
    }
    
    // Разрешение конфликтов (Deny wins principle)
    resolvedPermissions := rm.resolvePermissionConflicts(allPermissions)
    
    return &PermissionSet{
        Permissions: resolvedPermissions,
        ComputedAt:  time.Now(),
        UserID:      "", // Будет установлен вызывающим кодом
    }
}

func (rm *InMemoryRoleManager) resolvePermissionConflicts(permissions []DetailedPermission) []DetailedPermission {
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
        
        // Объединение условий
        if perm.Conditions != nil || existing.Conditions != nil {
            mergedConditions := make(map[string]interface{})
            
            // Копирование существующих условий
            for k, v := range existing.Conditions {
                mergedConditions[k] = v
            }
            
            // Добавление новых условий
            for k, v := range perm.Conditions {
                mergedConditions[k] = v
            }
            
            perm.Conditions = mergedConditions
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

Code Diagram Task 3 обеспечивает полное понимание реализации Enhanced RBAC системы на уровне кода и служит прямым руководством для разработчиков, показывая точное соответствие между архитектурными элементами и Go кодом.