# Подробное объяснение Component Diagram Task 3 - Enhanced RBAC System

## Назначение диаграммы

Component Diagram для Task 3 показывает внутреннюю структуру контейнеров Access Control Engine, Role Manager, Permission Engine и Enhanced Cache. Эта диаграмма служит мостом между архитектурным дизайном контейнеров и фактической реализацией кода, детализируя компоненты и их взаимодействие.

## Структура PlantUML и связь с кодом

### Заголовок и внешние контейнеры
```plantuml
@startuml Task3-Component-Diagram
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Component.puml
title Task 3: Enhanced Role-Based Access Control System - Component Diagram

Container(s3_api, "S3 API Gateway", "Go/Fiber", "Handles S3 API requests")
```

**Архитектурное значение:**
- Показывает внешний контекст для понимания границ компонентов
- Определяет точки входа в систему RBAC

## Access Control Engine Components

### VerifyAccess Function
```plantuml
Component(verify_access, "VerifyAccess Function", "Go", "Main access verification entry point with enhanced role support")
```

**Связь с реализацией:**
```go
// auth/access.go - главная функция проверки доступа
func VerifyAccess(ctx context.Context, backend backend.Backend, opts *AccessOptions) error {
    // Проверка базовых условий
    if isPublicBucket(opts.Bucket) {
        return nil
    }
    
    if isRootUser(opts.Acc) {
        return nil
    }
    
    if hasAdminRole(opts.Acc) {
        return nil
    }
    
    // Enhanced RBAC проверка
    if opts.RoleManager != nil {
        return verifyEnhancedRoleAccessWithAggregation(ctx, opts)
    }
    
    // Fallback к традиционной проверке
    return verifyTraditionalAccess(ctx, backend, opts)
}

// Ключевая функция Enhanced RBAC
func verifyEnhancedRoleAccessWithAggregation(ctx context.Context, opts *AccessOptions) error {
    // Получение эффективных разрешений пользователя
    permissions, err := opts.RoleManager.GetEffectivePermissions(opts.Acc.UserID)
    if err != nil {
        return fmt.Errorf("failed to get effective permissions: %w", err)
    }
    
    // Построение ARN ресурса
    resourceARN := buildResourceARN(opts.Bucket, opts.Object)
    
    // Проверка разрешения
    if permissions.HasPermission(resourceARN, string(opts.Action)) {
        return nil // Доступ разрешен
    }
    
    return ErrAccessDenied
}

// Построение AWS ARN для ресурса
func buildResourceARN(bucket, object string) string {
    if object == "" {
        return fmt.Sprintf("arn:aws:s3:::%s", bucket)
    }
    return fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, object)
}
```

### EnhancedAccessChecker
```plantuml
Component(enhanced_checker, "EnhancedAccessChecker", "Go", "Comprehensive access checking with role integration")
```

**Связь с реализацией:**
```go
// auth/enhanced_checker.go - расширенная проверка доступа
type EnhancedAccessChecker struct {
    roleManager     RoleManager
    backend         backend.Backend
    patternMatcher  *ARNPatternMatcher
    auditLogger     AuditLogger
}

func NewEnhancedAccessChecker(rm RoleManager, backend backend.Backend) *EnhancedAccessChecker {
    return &EnhancedAccessChecker{
        roleManager:    rm,
        backend:       backend,
        patternMatcher: NewARNPatternMatcher(),
        auditLogger:   NewAuditLogger(),
    }
}

func (eac *EnhancedAccessChecker) CheckAccess(ctx context.Context, opts *AccessOptions) error {
    startTime := time.Now()
    
    // Получение ролей пользователя с кэшированием
    roles, err := eac.getUserRolesWithCache(opts.Acc.UserID)
    if err != nil {
        eac.auditLogger.LogError(ctx, "failed_to_get_roles", opts.Acc.UserID, err)
        return err
    }
    
    // Проверка каждой роли
    for _, role := range roles {
        if eac.checkRolePermission(role, opts) {
            eac.auditLogger.LogAccessGranted(ctx, opts.Acc.UserID, opts.Bucket, opts.Object, string(opts.Action))
            eac.recordMetrics("access_granted", time.Since(startTime))
            return nil
        }
    }
    
    eac.auditLogger.LogAccessDenied(ctx, opts.Acc.UserID, opts.Bucket, opts.Object, string(opts.Action))
    eac.recordMetrics("access_denied", time.Since(startTime))
    return ErrAccessDenied
}

func (eac *EnhancedAccessChecker) checkRolePermission(role *EnhancedRole, opts *AccessOptions) bool {
    resourceARN := buildResourceARN(opts.Bucket, opts.Object)
    
    for _, permission := range role.Permissions {
        if permission.Matches(resourceARN, string(opts.Action)) {
            return permission.Effect == PermissionAllow
        }
    }
    
    return false
}
```

### AccessOptions
```plantuml
Component(access_options, "AccessOptions", "Go Struct", "Contains access request context and parameters")
```

**Связь с реализацией:**
```go
// auth/types.go - структура параметров доступа
type AccessOptions struct {
    Acl           ACL         `json:"acl,omitempty"`
    AclPermission Permission  `json:"acl_permission,omitempty"`
    IsRoot        bool        `json:"is_root"`
    Acc           Account     `json:"account"`
    Bucket        string      `json:"bucket"`
    Object        string      `json:"object,omitempty"`
    Action        Action      `json:"action"`
    RoleManager   RoleManager `json:"-"` // Не сериализуется
    Context       map[string]interface{} `json:"context,omitempty"`
}

type Account struct {
    UserID      string            `json:"user_id"`
    DisplayName string            `json:"display_name"`
    Email       string            `json:"email,omitempty"`
    Groups      []string          `json:"groups,omitempty"`
    Attributes  map[string]string `json:"attributes,omitempty"`
}

type Action string

const (
    ActionGetObject    Action = "s3:GetObject"
    ActionPutObject    Action = "s3:PutObject"
    ActionDeleteObject Action = "s3:DeleteObject"
    ActionListBucket   Action = "s3:ListBucket"
    ActionGetBucketAcl Action = "s3:GetBucketAcl"
    ActionPutBucketAcl Action = "s3:PutBucketAcl"
)

// Валидация AccessOptions
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
    
    return nil
}
```### ARN
 Builder
```plantuml
Component(arn_builder, "ARN Builder", "Go", "Builds AWS ARN-style resource identifiers")
```

**Связь с реализацией:**
```go
// auth/arn_builder.go - построение AWS ARN
type ARNBuilder struct {
    region    string
    accountID string
}

func NewARNBuilder(region, accountID string) *ARNBuilder {
    return &ARNBuilder{
        region:    region,
        accountID: accountID,
    }
}

func (ab *ARNBuilder) BuildS3BucketARN(bucket string) string {
    return fmt.Sprintf("arn:aws:s3:::%s", bucket)
}

func (ab *ARNBuilder) BuildS3ObjectARN(bucket, object string) string {
    if object == "" {
        return ab.BuildS3BucketARN(bucket)
    }
    return fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, object)
}

func (ab *ARNBuilder) BuildS3PrefixARN(bucket, prefix string) string {
    return fmt.Sprintf("arn:aws:s3:::%s/%s*", bucket, prefix)
}

// Парсинг ARN обратно в компоненты
func (ab *ARNBuilder) ParseS3ARN(arn string) (*S3Resource, error) {
    // arn:aws:s3:::bucket/object
    parts := strings.Split(arn, ":")
    if len(parts) < 6 || parts[0] != "arn" || parts[1] != "aws" || parts[2] != "s3" {
        return nil, errors.New("invalid S3 ARN format")
    }
    
    resourcePart := parts[5]
    if resourcePart == "" {
        return nil, errors.New("empty resource in ARN")
    }
    
    // Разделение bucket и object
    slashIndex := strings.Index(resourcePart, "/")
    if slashIndex == -1 {
        return &S3Resource{
            Bucket: resourcePart,
            Object: "",
        }, nil
    }
    
    return &S3Resource{
        Bucket: resourcePart[:slashIndex],
        Object: resourcePart[slashIndex+1:],
    }, nil
}

type S3Resource struct {
    Bucket string `json:"bucket"`
    Object string `json:"object"`
}
```

## Role Manager Components

### RoleManager Interface
```plantuml
Component(role_interface, "RoleManager Interface", "Go Interface", "Defines role management operations")
```

**Связь с реализацией:**
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
}

// Базовая реализация с общей логикой
type BaseRoleManager struct {
    validator *PermissionValidator
    cache     Cache
    metrics   *RoleManagerMetrics
}

func (brm *BaseRoleManager) ValidateRole(role *EnhancedRole) error {
    if role.ID == "" {
        return errors.New("role ID is required")
    }
    
    if role.Name == "" {
        return errors.New("role name is required")
    }
    
    // Валидация разрешений
    for _, permission := range role.Permissions {
        if err := brm.ValidatePermission(&permission); err != nil {
            return fmt.Errorf("invalid permission: %w", err)
        }
    }
    
    // Проверка циклических зависимостей в иерархии
    if err := brm.checkCircularDependency(role); err != nil {
        return fmt.Errorf("circular dependency detected: %w", err)
    }
    
    return nil
}

func (brm *BaseRoleManager) checkCircularDependency(role *EnhancedRole) error {
    visited := make(map[string]bool)
    
    var checkRole func(roleID string) error
    checkRole = func(roleID string) error {
        if visited[roleID] {
            return fmt.Errorf("circular dependency: role %s", roleID)
        }
        
        visited[roleID] = true
        defer func() { visited[roleID] = false }()
        
        currentRole, err := brm.GetRole(roleID)
        if err != nil {
            return err
        }
        
        for _, parentID := range currentRole.ParentRoles {
            if err := checkRole(parentID); err != nil {
                return err
            }
        }
        
        return nil
    }
    
    return checkRole(role.ID)
}
```

### InMemoryRoleManager
```plantuml
Component(inmemory_manager, "InMemoryRoleManager", "Go", "In-memory role storage and management")
```

**Связь с реализацией:**
```go
// auth/inmemory_role_manager.go - реализация в памяти
type InMemoryRoleManager struct {
    BaseRoleManager
    roles       map[string]*EnhancedRole
    assignments map[string][]*RoleAssignment
    mutex       sync.RWMutex
}

func NewInMemoryRoleManager() *InMemoryRoleManager {
    return &InMemoryRoleManager{
        BaseRoleManager: BaseRoleManager{
            validator: NewPermissionValidator(),
            cache:     NewLRUCache(1000),
            metrics:   NewRoleManagerMetrics(),
        },
        roles:       make(map[string]*EnhancedRole),
        assignments: make(map[string][]*RoleAssignment),
    }
}

func (rm *InMemoryRoleManager) CreateRole(role *EnhancedRole) error {
    if err := rm.ValidateRole(role); err != nil {
        return err
    }
    
    rm.mutex.Lock()
    defer rm.mutex.Unlock()
    
    if _, exists := rm.roles[role.ID]; exists {
        return fmt.Errorf("role %s already exists", role.ID)
    }
    
    // Установка временных меток
    now := time.Now()
    role.CreatedAt = now
    role.UpdatedAt = now
    
    rm.roles[role.ID] = role
    rm.metrics.RolesCreated.Inc()
    
    return nil
}

func (rm *InMemoryRoleManager) GetUserRoles(userID string) ([]*EnhancedRole, error) {
    // Проверка кэша
    if cached := rm.cache.GetUserRoles(userID); cached != nil {
        return cached, nil
    }
    
    rm.mutex.RLock()
    assignments := rm.assignments[userID]
    rm.mutex.RUnlock()
    
    roles := make([]*EnhancedRole, 0, len(assignments))
    
    for _, assignment := range assignments {
        if assignment.IsExpired() {
            continue // Пропускаем просроченные назначения
        }
        
        role, err := rm.GetRole(assignment.RoleID)
        if err != nil {
            continue // Роль могла быть удалена
        }
        
        roles = append(roles, role)
    }
    
    // Расширение иерархии ролей
    expandedRoles, err := rm.expandRoleHierarchy(roles)
    if err != nil {
        return nil, err
    }
    
    // Кэширование результата
    rm.cache.SetUserRoles(userID, expandedRoles, 5*time.Minute)
    
    return expandedRoles, nil
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

### FileBasedRoleManager
```plantuml
Component(file_manager, "FileBasedRoleManager", "Go", "File-based persistent role storage")
```

**Связь с реализацией:**
```go
// auth/file_role_manager.go - файловая реализация
type FileBasedRoleManager struct {
    *InMemoryRoleManager
    dataDir     string
    rolesFile   string
    assignmentsFile string
    autoSave    bool
    saveInterval time.Duration
}

func NewFileBasedRoleManager(dataDir string) (*FileBasedRoleManager, error) {
    frm := &FileBasedRoleManager{
        InMemoryRoleManager: NewInMemoryRoleManager(),
        dataDir:            dataDir,
        rolesFile:          filepath.Join(dataDir, "roles.json"),
        assignmentsFile:    filepath.Join(dataDir, "assignments.json"),
        autoSave:          true,
        saveInterval:      30 * time.Second,
    }
    
    // Создание директории если не существует
    if err := os.MkdirAll(dataDir, 0755); err != nil {
        return nil, fmt.Errorf("failed to create data directory: %w", err)
    }
    
    // Загрузка существующих данных
    if err := frm.loadFromDisk(); err != nil {
        return nil, fmt.Errorf("failed to load data from disk: %w", err)
    }
    
    // Запуск автосохранения
    if frm.autoSave {
        go frm.startAutoSave()
    }
    
    return frm, nil
}

func (frm *FileBasedRoleManager) CreateRole(role *EnhancedRole) error {
    if err := frm.InMemoryRoleManager.CreateRole(role); err != nil {
        return err
    }
    
    return frm.saveRoleToDisk(role)
}

func (frm *FileBasedRoleManager) saveRoleToDisk(role *EnhancedRole) error {
    frm.mutex.Lock()
    defer frm.mutex.Unlock()
    
    // Загрузка всех ролей
    allRoles := make(map[string]*EnhancedRole)
    for id, r := range frm.roles {
        allRoles[id] = r
    }
    
    // Сериализация в JSON
    data, err := json.MarshalIndent(allRoles, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal roles: %w", err)
    }
    
    // Атомарная запись через временный файл
    tempFile := frm.rolesFile + ".tmp"
    if err := os.WriteFile(tempFile, data, 0644); err != nil {
        return fmt.Errorf("failed to write temp file: %w", err)
    }
    
    if err := os.Rename(tempFile, frm.rolesFile); err != nil {
        return fmt.Errorf("failed to rename temp file: %w", err)
    }
    
    return nil
}

func (frm *FileBasedRoleManager) loadFromDisk() error {
    // Загрузка ролей
    if err := frm.loadRolesFromDisk(); err != nil {
        return err
    }
    
    // Загрузка назначений
    if err := frm.loadAssignmentsFromDisk(); err != nil {
        return err
    }
    
    return nil
}

func (frm *FileBasedRoleManager) startAutoSave() {
    ticker := time.NewTicker(frm.saveInterval)
    defer ticker.Stop()
    
    for range ticker.C {
        if err := frm.saveToDisk(); err != nil {
            log.Printf("Auto-save failed: %v", err)
        }
    }
}
```

### PermissionValidator
```plantuml
Component(role_validator, "PermissionValidator", "Go", "Validates role and permission consistency")
```

**Связь с реализацией:**
```go
// auth/permission_validator.go - валидация разрешений
type PermissionValidator struct {
    allowedActions   map[string]bool
    allowedResources map[string]*regexp.Regexp
}

func NewPermissionValidator() *PermissionValidator {
    return &PermissionValidator{
        allowedActions: map[string]bool{
            "s3:GetObject":           true,
            "s3:PutObject":           true,
            "s3:DeleteObject":        true,
            "s3:ListBucket":          true,
            "s3:GetBucketAcl":        true,
            "s3:PutBucketAcl":        true,
            "s3:GetBucketPolicy":     true,
            "s3:PutBucketPolicy":     true,
            "s3:DeleteBucketPolicy":  true,
        },
        allowedResources: map[string]*regexp.Regexp{
            "bucket":     regexp.MustCompile(`^arn:aws:s3:::[\w\-\.]+$`),
            "object":     regexp.MustCompile(`^arn:aws:s3:::[\w\-\.]+/.*$`),
            "wildcard":   regexp.MustCompile(`^arn:aws:s3:::[\w\-\.\*]+(/.*)?$`),
        },
    }
}

func (pv *PermissionValidator) ValidatePermission(permission *DetailedPermission) error {
    // Валидация действия
    if !pv.allowedActions[permission.Action] {
        return fmt.Errorf("invalid action: %s", permission.Action)
    }
    
    // Валидация ресурса
    if err := pv.validateResource(permission.Resource); err != nil {
        return fmt.Errorf("invalid resource: %w", err)
    }
    
    // Валидация эффекта
    if permission.Effect != PermissionAllow && permission.Effect != PermissionDeny {
        return fmt.Errorf("invalid effect: %s", permission.Effect)
    }
    
    // Валидация условий
    if err := pv.validateConditions(permission.Conditions); err != nil {
        return fmt.Errorf("invalid conditions: %w", err)
    }
    
    return nil
}

func (pv *PermissionValidator) validateResource(resource string) error {
    for _, pattern := range pv.allowedResources {
        if pattern.MatchString(resource) {
            return nil
        }
    }
    
    return fmt.Errorf("resource does not match any allowed pattern: %s", resource)
}

func (pv *PermissionValidator) ValidatePermissionSet(permissions []DetailedPermission) error {
    // Поиск конфликтов разрешений
    conflicts := pv.findConflicts(permissions)
    if len(conflicts) > 0 {
        return fmt.Errorf("permission conflicts found: %v", conflicts)
    }
    
    return nil
}

func (pv *PermissionValidator) findConflicts(permissions []DetailedPermission) []string {
    conflicts := make([]string, 0)
    permissionMap := make(map[string][]DetailedPermission)
    
    // Группировка по ресурсу и действию
    for _, perm := range permissions {
        key := fmt.Sprintf("%s:%s", perm.Resource, perm.Action)
        permissionMap[key] = append(permissionMap[key], perm)
    }
    
    // Поиск конфликтов
    for key, perms := range permissionMap {
        if len(perms) > 1 {
            hasAllow := false
            hasDeny := false
            
            for _, perm := range perms {
                if perm.Effect == PermissionAllow {
                    hasAllow = true
                } else if perm.Effect == PermissionDeny {
                    hasDeny = true
                }
            }
            
            if hasAllow && hasDeny {
                conflicts = append(conflicts, key)
            }
        }
    }
    
    return conflicts
}
```

## Permission Engine Components

### EnhancedRole
```plantuml
Component(enhanced_role, "EnhancedRole", "Go Struct", "Role with detailed permissions and hierarchy")
```

**Связь с реализацией:**
```go
// auth/enhanced_role.go - расширенная роль
type EnhancedRole struct {
    ID          string               `json:"id"`
    Name        string               `json:"name"`
    Description string               `json:"description"`
    Permissions []DetailedPermission `json:"permissions"`
    ParentRoles []string             `json:"parent_roles"`
    CreatedAt   time.Time            `json:"created_at"`
    UpdatedAt   time.Time            `json:"updated_at"`
    Metadata    map[string]string    `json:"metadata"`
}

func (er *EnhancedRole) Validate() error {
    if er.ID == "" {
        return errors.New("role ID is required")
    }
    
    if er.Name == "" {
        return errors.New("role name is required")
    }
    
    // Валидация разрешений
    for i, permission := range er.Permissions {
        if err := permission.Validate(); err != nil {
            return fmt.Errorf("permission %d is invalid: %w", i, err)
        }
    }
    
    return nil
}

func (er *EnhancedRole) HasPermission(resource, action string) PermissionEffect {
    for _, permission := range er.Permissions {
        if permission.Matches(resource, action) {
            return permission.Effect
        }
    }
    
    return PermissionDeny // Deny by default
}

func (er *EnhancedRole) AddPermission(permission DetailedPermission) error {
    if err := permission.Validate(); err != nil {
        return err
    }
    
    er.Permissions = append(er.Permissions, permission)
    er.UpdatedAt = time.Now()
    
    return nil
}

func (er *EnhancedRole) RemovePermission(resource, action string) bool {
    for i, permission := range er.Permissions {
        if permission.Resource == resource && permission.Action == action {
            er.Permissions = append(er.Permissions[:i], er.Permissions[i+1:]...)
            er.UpdatedAt = time.Now()
            return true
        }
    }
    
    return false
}

// Клонирование роли для безопасного использования
func (er *EnhancedRole) Clone() *EnhancedRole {
    clone := &EnhancedRole{
        ID:          er.ID,
        Name:        er.Name,
        Description: er.Description,
        ParentRoles: make([]string, len(er.ParentRoles)),
        CreatedAt:   er.CreatedAt,
        UpdatedAt:   er.UpdatedAt,
        Metadata:    make(map[string]string),
        Permissions: make([]DetailedPermission, len(er.Permissions)),
    }
    
    copy(clone.ParentRoles, er.ParentRoles)
    copy(clone.Permissions, er.Permissions)
    
    for k, v := range er.Metadata {
        clone.Metadata[k] = v
    }
    
    return clone
}
```

Component Diagram Task 3 обеспечивает детальное понимание внутренней структуры компонентов Enhanced RBAC системы и служит прямым руководством для реализации кода, показывая как архитектурные решения транслируются в конкретные Go структуры и функции.