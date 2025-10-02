# Подробное объяснение Context Diagram Task 3 - Enhanced RBAC System

## Назначение диаграммы

Context Diagram для Task 3 показывает систему Enhanced Role-Based Access Control (RBAC) в контексте пользователей и внешних систем. Эта диаграмма служит мостом между высокоуровневыми требованиями бизнеса и техническими решениями, определяя границы системы и ключевые взаимодействия.

## Структура PlantUML и связь с кодом

### Заголовок и настройки
```plantuml
@startuml Task3-Context-Diagram
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Context.puml
title Task 3: Enhanced Role-Based Access Control System - Context Diagram
```

**Связь с реализацией:**
- Заголовок отражает основную цель Task 3 - улучшенную систему RBAC
- Использование C4_Context.puml обеспечивает стандартизированное представление

## Участники системы и их реализация

### 1. User (Пользователь S3 API)
```plantuml
Person(user, "User", "S3 API user requesting access to resources")
```

**Архитектурное значение:**
- Представляет любого клиента, использующего S3 API
- Инициирует запросы доступа к ресурсам

**Связь с кодом:**
```go
// В auth/access.go - структура для представления пользователя
type AccessOptions struct {
    Acc    Account  // Информация о пользователе
    Bucket string   // Запрашиваемый bucket
    Object string   // Запрашиваемый объект
    Action Action   // Действие (GET, PUT, DELETE, etc.)
}

// Пример использования в VerifyAccess
func VerifyAccess(ctx context.Context, backend backend.Backend, opts *AccessOptions) error {
    // Проверка доступа пользователя к ресурсу
    if opts.RoleManager != nil {
        return verifyEnhancedRoleAccessWithAggregation(ctx, opts)
    }
    // Fallback к традиционной проверке доступа
    return verifyTraditionalAccess(ctx, backend, opts)
}
```

**Практическая реализация:**
- Пользователь аутентифицируется через AWS Signature V4 или другие методы
- Каждый запрос содержит информацию о пользователе, ресурсе и действии
- Система извлекает роли пользователя для проверки разрешений

### 2. Administrator (Администратор системы)
```plantuml
Person(admin, "Administrator", "System administrator managing roles and permissions")
```

**Архитектурное значение:**
- Управляет ролями, разрешениями и назначениями
- Настраивает политики безопасности

**Связь с кодом:**
```go
// В auth/rbac.go - интерфейс для управления ролями
type RoleManager interface {
    CreateRole(role *EnhancedRole) error
    GetRole(roleID string) (*EnhancedRole, error)
    GetUserRoles(userID string) ([]*EnhancedRole, error)
    AssignRole(userID, roleID, assignedBy string) error
    RevokeRole(userID, roleID string) error
    GetEffectivePermissions(userID string) (*PermissionSet, error)
}

// Пример создания роли администратором
func (rm *InMemoryRoleManager) CreateRole(role *EnhancedRole) error {
    if err := role.Validate(); err != nil {
        return fmt.Errorf("invalid role: %w", err)
    }
    
    rm.mutex.Lock()
    defer rm.mutex.Unlock()
    
    rm.roles[role.ID] = role
    return rm.saveRoleToDisk(role) // Персистентное сохранение
}
```

**Практическая реализация:**
- Admin API для управления ролями через REST endpoints
- CLI инструменты для массовых операций
- Web интерфейс для визуального управления ролями

## Центральная система и её архитектура

### Enhanced Authentication System
```plantuml
System_Boundary(versitygw, "VersityGW S3 Gateway") {
    System(auth_system, "Enhanced Authentication System", "Provides role-based access control with hierarchical permissions")
}
```

**Архитектурное значение:**
- Центральная система, реализующая улучшенный RBAC
- Интегрируется с существующим S3 Gateway

**Связь с кодом:**
```go
// Основная структура системы аутентификации
type EnhancedAuthSystem struct {
    roleManager     RoleManager
    permissionEngine *PermissionEngine
    cache          Cache
    auditLogger    AuditLogger
}

// Главная функция проверки доступа
func (eas *EnhancedAuthSystem) VerifyAccess(ctx context.Context, opts *AccessOptions) error {
    // 1. Получение ролей пользователя
    roles, err := eas.roleManager.GetUserRoles(opts.Acc.UserID)
    if err != nil {
        return fmt.Errorf("failed to get user roles: %w", err)
    }
    
    // 2. Вычисление эффективных разрешений
    permissions := eas.permissionEngine.ComputeEffectivePermissions(roles)
    
    // 3. Проверка разрешения на конкретное действие
    resourceARN := buildResourceARN(opts.Bucket, opts.Object)
    if permissions.HasPermission(resourceARN, string(opts.Action)) {
        eas.auditLogger.LogAccessGranted(opts)
        return nil
    }
    
    eas.auditLogger.LogAccessDenied(opts)
    return ErrAccessDenied
}
```

**Ключевые компоненты реализации:**

1. **Role Manager** - управление ролями и назначениями
2. **Permission Engine** - вычисление эффективных разрешений
3. **Cache Layer** - кэширование для производительности
4. **Audit Logger** - логирование событий доступа

## Внешние системы и интеграции

### 1. S3 Backend
```plantuml
System_Ext(s3_backend, "S3 Backend", "Storage backend (AWS S3, MinIO, etc.)")
```

**Связь с кодом:**
```go
// Интерфейс для работы с S3 backend
type Backend interface {
    GetBucketPolicy(bucket string) (*BucketPolicy, error)
    GetObjectACL(bucket, object string) (*ACL, error)
    // ... другие методы
}

// После успешной авторизации запрос передается в backend
func (s *S3APIServer) handleAuthorizedRequest(ctx context.Context, opts *AccessOptions) error {
    // Проверка доступа через Enhanced Auth System
    if err := s.authSystem.VerifyAccess(ctx, opts); err != nil {
        return err
    }
    
    // Передача запроса в backend
    return s.backend.ProcessRequest(ctx, opts)
}
```

### 2. IAM Service
```plantuml
System_Ext(iam_service, "IAM Service", "External identity and access management")
```

**Связь с кодом:**
```go
// Интеграция с внешним IAM для получения информации о пользователе
type IAMIntegration struct {
    endpoint string
    client   *http.Client
}

func (iam *IAMIntegration) GetUserInfo(userID string) (*UserInfo, error) {
    resp, err := iam.client.Get(fmt.Sprintf("%s/users/%s", iam.endpoint, userID))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var userInfo UserInfo
    if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
        return nil, err
    }
    
    return &userInfo, nil
}

// Использование в RoleManager для синхронизации ролей
func (rm *InMemoryRoleManager) syncWithIAM(userID string) error {
    userInfo, err := rm.iamIntegration.GetUserInfo(userID)
    if err != nil {
        return err
    }
    
    // Синхронизация ролей из внешнего IAM
    for _, externalRole := range userInfo.Roles {
        if err := rm.mapExternalRole(userID, externalRole); err != nil {
            log.Printf("Failed to map external role %s: %v", externalRole, err)
        }
    }
    
    return nil
}
```

### 3. Monitoring System
```plantuml
System_Ext(monitoring, "Monitoring System", "Logs and metrics collection")
```

**Связь с кодом:**
```go
// Метрики для мониторинга RBAC системы
type RBACMetrics struct {
    AccessChecks     prometheus.Counter
    AccessGranted    prometheus.Counter
    AccessDenied     prometheus.Counter
    RoleAssignments  prometheus.Gauge
    CacheHitRate     prometheus.Histogram
}

func NewRBACMetrics() *RBACMetrics {
    return &RBACMetrics{
        AccessChecks: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "rbac_access_checks_total",
            Help: "Total number of access checks performed",
        }),
        AccessGranted: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "rbac_access_granted_total",
            Help: "Total number of access grants",
        }),
        // ... другие метрики
    }
}

// Интеграция метрик в процесс проверки доступа
func (eas *EnhancedAuthSystem) VerifyAccessWithMetrics(ctx context.Context, opts *AccessOptions) error {
    eas.metrics.AccessChecks.Inc()
    
    err := eas.VerifyAccess(ctx, opts)
    if err != nil {
        eas.metrics.AccessDenied.Inc()
        return err
    }
    
    eas.metrics.AccessGranted.Inc()
    return nil
}
```

## Взаимосвязи и потоки данных

### 1. User → Auth System
```plantuml
Rel(user, auth_system, "Requests access to S3 resources", "HTTPS/S3 API")
```

**Реализация потока:**
```go
// HTTP handler для S3 API запросов
func (s *S3APIServer) handleS3Request(c *fiber.Ctx) error {
    // 1. Парсинг S3 запроса
    opts, err := parseS3Request(c)
    if err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
    }
    
    // 2. Проверка доступа через Enhanced Auth System
    if err := s.authSystem.VerifyAccess(c.Context(), opts); err != nil {
        return c.Status(403).JSON(fiber.Map{"error": "Access denied"})
    }
    
    // 3. Передача запроса в backend
    result, err := s.backend.ProcessRequest(c.Context(), opts)
    if err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }
    
    return c.JSON(result)
}

// Парсинг S3 запроса в AccessOptions
func parseS3Request(c *fiber.Ctx) (*AccessOptions, error) {
    return &AccessOptions{
        Acc:    extractAccountFromRequest(c),
        Bucket: c.Params("bucket"),
        Object: c.Params("object", ""),
        Action: Action(c.Method()),
    }, nil
}
```

### 2. Administrator → Auth System
```plantuml
Rel(admin, auth_system, "Manages roles and permissions", "Admin API")
```

**Реализация Admin API:**
```go
// REST API для управления ролями
func (s *AdminAPIServer) setupRoleRoutes() {
    api := s.app.Group("/api/v1")
    
    // Создание роли
    api.Post("/roles", s.createRole)
    // Получение роли
    api.Get("/roles/:id", s.getRole)
    // Назначение роли пользователю
    api.Post("/users/:userId/roles/:roleId", s.assignRole)
    // Отзыв роли
    api.Delete("/users/:userId/roles/:roleId", s.revokeRole)
}

func (s *AdminAPIServer) createRole(c *fiber.Ctx) error {
    var role EnhancedRole
    if err := c.BodyParser(&role); err != nil {
        return c.Status(400).JSON(fiber.Map{"error": "Invalid role data"})
    }
    
    if err := s.roleManager.CreateRole(&role); err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }
    
    return c.Status(201).JSON(role)
}

func (s *AdminAPIServer) assignRole(c *fiber.Ctx) error {
    userID := c.Params("userId")
    roleID := c.Params("roleId")
    assignedBy := extractAdminFromRequest(c)
    
    if err := s.roleManager.AssignRole(userID, roleID, assignedBy); err != nil {
        return c.Status(500).JSON(fiber.Map{"error": err.Error()})
    }
    
    return c.SendStatus(204)
}
```

## Архитектурные принципы и их реализация

### 1. Принцип единственной ответственности
Каждый компонент системы имеет четко определенную роль:
- **RoleManager** - управление ролями
- **PermissionEngine** - вычисление разрешений
- **Cache** - оптимизация производительности
- **AuditLogger** - логирование событий

### 2. Принцип открытости/закрытости
Система открыта для расширения через интерфейсы:
```go
// Интерфейс позволяет добавлять новые реализации RoleManager
type RoleManager interface {
    // ... методы интерфейса
}

// Можно легко добавить новую реализацию
type DatabaseRoleManager struct {
    db *sql.DB
}

func (drm *DatabaseRoleManager) CreateRole(role *EnhancedRole) error {
    // Реализация для базы данных
}
```

### 3. Принцип инверсии зависимостей
Высокоуровневые модули не зависят от низкоуровневых:
```go
// VerifyAccess зависит от абстракции RoleManager, а не от конкретной реализации
func VerifyAccess(ctx context.Context, backend backend.Backend, opts *AccessOptions) error {
    if opts.RoleManager != nil { // Dependency injection
        return verifyEnhancedRoleAccessWithAggregation(ctx, opts)
    }
    return verifyTraditionalAccess(ctx, backend, opts)
}
```

## Соответствие требованиям Task 3

### 3.1 Расширение системы ролей с детальными разрешениями
**Архитектурное решение:** Введение EnhancedRole с DetailedPermission
**Реализация:**
```go
type EnhancedRole struct {
    ID          string               `json:"id"`
    Name        string               `json:"name"`
    Permissions []DetailedPermission `json:"permissions"`
    ParentRoles []string             `json:"parent_roles"`
}

type DetailedPermission struct {
    Resource   string                 `json:"resource"`   // ARN pattern
    Action     string                 `json:"action"`     // S3 action
    Effect     PermissionEffect       `json:"effect"`     // Allow/Deny
    Conditions map[string]interface{} `json:"conditions"` // Дополнительные условия
}
```

### 3.2 Динамическое назначение и обновление ролей
**Архитектурное решение:** RoleManager с real-time обновлениями
**Реализация:**
```go
func (rm *InMemoryRoleManager) AssignRole(userID, roleID, assignedBy string) error {
    assignment := &RoleAssignment{
        UserID:     userID,
        RoleID:     roleID,
        AssignedAt: time.Now(),
        AssignedBy: assignedBy,
    }
    
    rm.mutex.Lock()
    rm.assignments[userID] = append(rm.assignments[userID], assignment)
    rm.mutex.Unlock()
    
    // Инвалидация кэша для немедленного применения изменений
    rm.cache.InvalidateUser(userID)
    
    return rm.saveAssignmentToDisk(assignment)
}
```

### 3.3 Интеграция с проверкой контроля доступа
**Архитектурное решение:** Модификация VerifyAccess для поддержки Enhanced RBAC
**Реализация:**
```go
func verifyEnhancedRoleAccessWithAggregation(ctx context.Context, opts *AccessOptions) error {
    // Получение эффективных разрешений пользователя
    permissions, err := opts.RoleManager.GetEffectivePermissions(opts.Acc.UserID)
    if err != nil {
        return err
    }
    
    // Построение ARN ресурса
    resourceARN := buildResourceARN(opts.Bucket, opts.Object)
    
    // Проверка разрешения
    if permissions.HasPermission(resourceARN, string(opts.Action)) {
        return nil // Доступ разрешен
    }
    
    return ErrAccessDenied
}
```

## Преимущества архитектурного подхода

### 1. Масштабируемость
- Модульная архитектура позволяет независимое масштабирование компонентов
- Кэширование снижает нагрузку на хранилище ролей
- Асинхронные операции для неблокирующей работы

### 2. Гибкость
- Поддержка различных реализаций RoleManager
- Расширяемая система разрешений через DetailedPermission
- Интеграция с внешними IAM системами

### 3. Безопасность
- Принцип "deny by default"
- Аудит всех операций доступа
- Валидация ролей и разрешений

### 4. Производительность
- Кэширование эффективных разрешений
- Оптимизированные алгоритмы агрегации разрешений
- Минимальные накладные расходы на проверку доступа

Context Diagram Task 3 обеспечивает четкое понимание границ системы Enhanced RBAC и служит основой для детализации архитектуры на следующих уровнях C4 модели, при этом каждый элемент диаграммы имеет прямое соответствие в реализации кода.