# Подробное объяснение Cache Detailed Architecture Task 1 - Enhanced Cache System

## Назначение диаграммы

Cache Detailed Architecture Diagram для Task 1 представляет детальную внутреннюю структуру Enhanced Cache System, фокусируясь на архитектуре кэширования, типах данных, конфигурации и взаимосвязях компонентов. Эта диаграмма служит мостом между архитектурным дизайном кэша и его конкретной реализацией в коде.

## Структура PlantUML и архитектурные компоненты

### Заголовок и тема
```plantuml
@startuml Task1_Cache_Detailed_Architecture
!theme plain
title Enhanced Cache System - Detailed Architecture (Task1)
```

**Архитектурное значение:**
- Фокус на детальной структуре кэширования
- Использование plain темы для четкости диаграммы

## Cache Entry Types - Типы кэшируемых данных

### Определение типов записей
```plantuml
enum CacheEntryType {
    UserCredentials (TTL: 15min)
    UserRoles (TTL: 30min)
    Permissions (TTL: 1hour)
    MFASettings (TTL: 2hours)
    SessionData (TTL: 10min)
}
```

**Связь с реализацией:**
```go
// cache/types.go - определение типов кэшируемых данных
type CacheEntryType int

const (
    UserCredentials CacheEntryType = iota
    UserRoles
    Permissions
    MFASettings
    SessionData
)

// Строковые представления для логирования и отладки
var CacheEntryTypeNames = map[CacheEntryType]string{
    UserCredentials: "UserCredentials",
    UserRoles:      "UserRoles", 
    Permissions:    "Permissions",
    MFASettings:    "MFASettings",
    SessionData:    "SessionData",
}

func (cet CacheEntryType) String() string {
    if name, exists := CacheEntryTypeNames[cet]; exists {
        return name
    }
    return fmt.Sprintf("Unknown(%d)", int(cet))
}

// Конфигурация TTL по умолчанию для каждого типа
var DefaultTTLs = map[CacheEntryType]time.Duration{
    UserCredentials: 15 * time.Minute,  // Частое обновление для безопасности
    UserRoles:      30 * time.Minute,   // Умеренное обновление ролей
    Permissions:    1 * time.Hour,      // Редкое изменение разрешений
    MFASettings:    2 * time.Hour,      // Стабильные настройки MFA
    SessionData:    10 * time.Minute,   // Короткий TTL для сессий
}

// Расширенные TTL для fallback кэша
var FallbackTTLs = map[CacheEntryType]time.Duration{
    UserCredentials: 1 * time.Hour,     // Расширенный для аварийных ситуаций
    UserRoles:      2 * time.Hour,
    Permissions:    4 * time.Hour,
    MFASettings:    8 * time.Hour,
    SessionData:    30 * time.Minute,
}

// Валидация типа записи
func (cet CacheEntryType) IsValid() bool {
    return cet >= UserCredentials && cet <= SessionData
}

// Получение TTL для типа записи
func (cet CacheEntryType) GetDefaultTTL() time.Duration {
    if ttl, exists := DefaultTTLs[cet]; exists {
        return ttl
    }
    return 15 * time.Minute // Безопасное значение по умолчанию
}

func (cet CacheEntryType) GetFallbackTTL() time.Duration {
    if ttl, exists := FallbackTTLs[cet]; exists {
        return ttl
    }
    return 1 * time.Hour // Безопасное значение для fallback
}
```

**Практическое использование типов:**
```go
// Примеры создания записей разных типов
func (eic *EnhancedIAMCache) cacheUserCredentials(userID string, account Account) {
    key := fmt.Sprintf("user:%s", userID)
    eic.cache.Set(key, account, 0, UserCredentials) // Использует default TTL
}

func (eic *EnhancedIAMCache) cacheUserRoles(userID string, roles []string) {
    key := fmt.Sprintf("roles:%s", userID)
    eic.cache.Set(key, roles, 0, UserRoles)
}

func (eic *EnhancedIAMCache) cacheUserPermissions(userID string, permissions []Permission) {
    key := fmt.Sprintf("permissions:%s", userID)
    eic.cache.Set(key, permissions, 0, Permissions)
}

func (eic *EnhancedIAMCache) cacheMFASettings(userID string, settings MFASettings) {
    key := fmt.Sprintf("mfa:%s", userID)
    eic.cache.Set(key, settings, 0, MFASettings)
}

func (eic *EnhancedIAMCache) cacheSessionData(sessionID string, session SessionData) {
    key := fmt.Sprintf("session:%s", sessionID)
    eic.cache.Set(key, session, 0, SessionData)
}
```

## Core Cache Structures - Основные структуры кэша

### CacheEntry - Запись кэша
```plantuml
class CacheEntry {
    -value: interface{}
    -expiry: time.Time
    -entryType: CacheEntryType
    -accessTime: time.Time
    -key: string
    +isExpired(): bool
    +touch(): void
}
```

**Детальная реализация:**
```go
// cache/entry.go - структура записи кэша
type CacheEntry struct {
    value      interface{}       // Кэшируемые данные
    expiry     time.Time        // Время истечения
    entryType  CacheEntryType   // Тип записи
    accessTime time.Time        // Время последнего доступа (для LRU)
    key        string           // Ключ записи
    createdAt  time.Time        // Время создания
    hitCount   int64            // Количество обращений
    mu         sync.RWMutex     // Мьютекс для безопасного доступа
}

// Создание новой записи кэша
func NewCacheEntry(key string, value interface{}, ttl time.Duration, entryType CacheEntryType) *CacheEntry {
    now := time.Now()
    return &CacheEntry{
        value:      value,
        expiry:     now.Add(ttl),
        entryType:  entryType,
        accessTime: now,
        key:        key,
        createdAt:  now,
        hitCount:   0,
    }
}

// Проверка истечения срока действия
func (ce *CacheEntry) isExpired() bool {
    ce.mu.RLock()
    defer ce.mu.RUnlock()
    return time.Now().After(ce.expiry)
}

// Обновление времени доступа (для LRU алгоритма)
func (ce *CacheEntry) touch() {
    ce.mu.Lock()
    defer ce.mu.Unlock()
    ce.accessTime = time.Now()
    ce.hitCount++
}

// Получение значения с проверкой типа
func (ce *CacheEntry) GetValue() interface{} {
    ce.mu.RLock()
    defer ce.mu.RUnlock()
    return ce.value
}

// Получение типизированного значения
func (ce *CacheEntry) GetTypedValue(expectedType CacheEntryType) (interface{}, error) {
    ce.mu.RLock()
    defer ce.mu.RUnlock()
    
    if ce.entryType != expectedType {
        return nil, fmt.Errorf("type mismatch: expected %s, got %s", 
            expectedType.String(), ce.entryType.String())
    }
    
    return ce.value, nil
}

// Обновление значения с сохранением метаданных
func (ce *CacheEntry) UpdateValue(value interface{}, ttl time.Duration) {
    ce.mu.Lock()
    defer ce.mu.Unlock()
    
    ce.value = value
    ce.expiry = time.Now().Add(ttl)
    ce.accessTime = time.Now()
}

// Получение статистики записи
func (ce *CacheEntry) GetStats() EntryStats {
    ce.mu.RLock()
    defer ce.mu.RUnlock()
    
    return EntryStats{
        Key:        ce.key,
        Type:       ce.entryType,
        CreatedAt:  ce.createdAt,
        AccessTime: ce.accessTime,
        Expiry:     ce.expiry,
        HitCount:   ce.hitCount,
        Age:        time.Since(ce.createdAt),
        TTL:        time.Until(ce.expiry),
    }
}

type EntryStats struct {
    Key        string            `json:"key"`
    Type       CacheEntryType    `json:"type"`
    CreatedAt  time.Time         `json:"created_at"`
    AccessTime time.Time         `json:"access_time"`
    Expiry     time.Time         `json:"expiry"`
    HitCount   int64             `json:"hit_count"`
    Age        time.Duration     `json:"age"`
    TTL        time.Duration     `json:"ttl"`
}
```

### CacheStats - Статистика кэша
```plantuml
class CacheStats {
    +Hits: int64
    +Misses: int64
    +Evictions: int64
    +Size: int
    +MaxSize: int
    +FallbackActive: bool
    +LastCleanup: time.Time
    +HitRate(): float64
}
```

**Реализация статистики:**
```go
// cache/stats.go - статистика кэша
type CacheStats struct {
    Hits           int64                    `json:"hits"`
    Misses         int64                    `json:"misses"`
    Evictions      int64                    `json:"evictions"`
    Size           int                      `json:"size"`
    MaxSize        int                      `json:"max_size"`
    FallbackActive bool                     `json:"fallback_active"`
    LastCleanup    time.Time               `json:"last_cleanup"`
    TypeStats      map[CacheEntryType]TypeStats `json:"type_stats"`
    StartTime      time.Time               `json:"start_time"`
    mu             sync.RWMutex            `json:"-"`
}

type TypeStats struct {
    Count     int   `json:"count"`
    Hits      int64 `json:"hits"`
    Misses    int64 `json:"misses"`
    Evictions int64 `json:"evictions"`
}

// Создание новой статистики
func NewCacheStats(maxSize int) *CacheStats {
    return &CacheStats{
        MaxSize:   maxSize,
        TypeStats: make(map[CacheEntryType]TypeStats),
        StartTime: time.Now(),
    }
}

// Вычисление коэффициента попаданий
func (cs *CacheStats) HitRate() float64 {
    cs.mu.RLock()
    defer cs.mu.RUnlock()
    
    total := cs.Hits + cs.Misses
    if total == 0 {
        return 0
    }
    return float64(cs.Hits) / float64(total)
}

// Обновление статистики попадания
func (cs *CacheStats) RecordHit(entryType CacheEntryType) {
    cs.mu.Lock()
    defer cs.mu.Unlock()
    
    cs.Hits++
    
    typeStats := cs.TypeStats[entryType]
    typeStats.Hits++
    cs.TypeStats[entryType] = typeStats
}

// Обновление статистики промаха
func (cs *CacheStats) RecordMiss(entryType CacheEntryType) {
    cs.mu.Lock()
    defer cs.mu.Unlock()
    
    cs.Misses++
    
    typeStats := cs.TypeStats[entryType]
    typeStats.Misses++
    cs.TypeStats[entryType] = typeStats
}

// Обновление статистики вытеснения
func (cs *CacheStats) RecordEviction(entryType CacheEntryType) {
    cs.mu.Lock()
    defer cs.mu.Unlock()
    
    cs.Evictions++
    
    typeStats := cs.TypeStats[entryType]
    typeStats.Evictions++
    typeStats.Count--
    cs.TypeStats[entryType] = typeStats
}

// Обновление размера кэша
func (cs *CacheStats) UpdateSize(newSize int) {
    cs.mu.Lock()
    defer cs.mu.Unlock()
    cs.Size = newSize
}

// Получение детальной статистики
func (cs *CacheStats) GetDetailedStats() DetailedStats {
    cs.mu.RLock()
    defer cs.mu.RUnlock()
    
    return DetailedStats{
        HitRate:        cs.HitRate(),
        Uptime:         time.Since(cs.StartTime),
        MemoryUsage:    cs.estimateMemoryUsage(),
        TypeBreakdown:  cs.getTypeBreakdown(),
        Performance:    cs.getPerformanceMetrics(),
    }
}

type DetailedStats struct {
    HitRate       float64                    `json:"hit_rate"`
    Uptime        time.Duration              `json:"uptime"`
    MemoryUsage   MemoryUsage               `json:"memory_usage"`
    TypeBreakdown map[CacheEntryType]float64 `json:"type_breakdown"`
    Performance   PerformanceMetrics         `json:"performance"`
}

type MemoryUsage struct {
    EstimatedBytes int64   `json:"estimated_bytes"`
    AveragePerEntry int64  `json:"average_per_entry"`
}

type PerformanceMetrics struct {
    RequestsPerSecond float64 `json:"requests_per_second"`
    AverageLatency    time.Duration `json:"average_latency"`
}
```

## Enhanced Cache Core - Ядро кэша

### EnhancedCache - Основной класс кэша
```plantuml
class EnhancedCache {
    -entries: map[string]*CacheEntry
    -maxSize: int
    -fallbackMode: bool
    -stats: CacheStats
    -defaultTTLs: map[CacheEntryType]time.Duration
    -mu: sync.RWMutex
    -cancel: context.CancelFunc
    
    +Get(key, entryType): (interface{}, bool)
    +Set(key, value, ttl, entryType): void
    +Invalidate(pattern): error
    +InvalidateUser(userID): error
    +InvalidateType(entryType): error
    +SetFallbackMode(enabled): void
    +GetStats(): CacheStats
    +Shutdown(): error
    -evictLRU(): void
    -cleanup(): void
    -cleanupLoop(ctx, interval): void
}
```

**Полная реализация EnhancedCache:**
```go
// cache/enhanced_cache.go - основной класс кэша
type EnhancedCache struct {
    entries      map[string]*CacheEntry           // Основное хранилище записей
    maxSize      int                              // Максимальный размер кэша
    fallbackMode bool                             // Режим fallback
    stats        *CacheStats                      // Статистика кэша
    defaultTTLs  map[CacheEntryType]time.Duration // TTL по умолчанию
    mu           sync.RWMutex                     // Мьютекс для безопасности
    cancel       context.CancelFunc               // Функция отмены фоновых процессов
    
    // Дополнительные поля для расширенной функциональности
    cleanupInterval time.Duration                 // Интервал очистки
    evictionPolicy  EvictionPolicy               // Политика вытеснения
    listeners       []CacheEventListener         // Слушатели событий кэша
}

type EvictionPolicy int

const (
    LRU EvictionPolicy = iota  // Least Recently Used
    LFU                        // Least Frequently Used
    FIFO                       // First In, First Out
)

type CacheEventListener interface {
    OnCacheHit(key string, entryType CacheEntryType)
    OnCacheMiss(key string, entryType CacheEntryType)
    OnCacheEviction(key string, entryType CacheEntryType)
    OnCacheSet(key string, entryType CacheEntryType)
}

// Создание нового Enhanced Cache
func NewEnhancedCache(config *EnhancedCacheConfig) (*EnhancedCache, error) {
    if config.MaxSize <= 0 {
        return nil, errors.New("max size must be positive")
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    
    cache := &EnhancedCache{
        entries:         make(map[string]*CacheEntry),
        maxSize:         config.MaxSize,
        defaultTTLs:     config.DefaultTTLs,
        stats:           NewCacheStats(config.MaxSize),
        cancel:          cancel,
        cleanupInterval: config.CleanupInterval,
        evictionPolicy:  config.EvictionPolicy,
        listeners:       make([]CacheEventListener, 0),
    }
    
    // Запуск фонового процесса очистки
    go cache.cleanupLoop(ctx, config.CleanupInterval)
    
    return cache, nil
}

// Получение значения из кэша
func (ec *EnhancedCache) Get(key string, entryType CacheEntryType) (interface{}, bool) {
    ec.mu.RLock()
    entry, exists := ec.entries[key]
    ec.mu.RUnlock()
    
    if !exists {
        ec.stats.RecordMiss(entryType)
        ec.notifyListeners(func(l CacheEventListener) { l.OnCacheMiss(key, entryType) })
        return nil, false
    }
    
    // Проверка типа и срока действия
    if entry.entryType != entryType || entry.isExpired() {
        // Удаление истекшей записи
        ec.mu.Lock()
        delete(ec.entries, key)
        ec.mu.Unlock()
        
        ec.stats.RecordMiss(entryType)
        ec.notifyListeners(func(l CacheEventListener) { l.OnCacheMiss(key, entryType) })
        return nil, false
    }
    
    // Обновление времени доступа для LRU
    entry.touch()
    ec.stats.RecordHit(entryType)
    ec.notifyListeners(func(l CacheEventListener) { l.OnCacheHit(key, entryType) })
    
    return entry.GetValue(), true
}

// Установка значения в кэш
func (ec *EnhancedCache) Set(key string, value interface{}, ttl time.Duration, entryType CacheEntryType) {
    // Использование default TTL если не указан
    if ttl == 0 {
        ttl = ec.defaultTTLs[entryType]
    }
    
    ec.mu.Lock()
    defer ec.mu.Unlock()
    
    // Проверка размера кэша и вытеснение при необходимости
    if len(ec.entries) >= ec.maxSize {
        ec.evictLRU()
    }
    
    // Создание новой записи
    entry := NewCacheEntry(key, value, ttl, entryType)
    ec.entries[key] = entry
    
    // Обновление статистики
    ec.stats.UpdateSize(len(ec.entries))
    ec.notifyListeners(func(l CacheEventListener) { l.OnCacheSet(key, entryType) })
}

// LRU вытеснение
func (ec *EnhancedCache) evictLRU() {
    var oldestKey string
    var oldestTime time.Time
    var oldestType CacheEntryType
    
    // Поиск самой старой записи
    for key, entry := range ec.entries {
        if oldestKey == "" || entry.accessTime.Before(oldestTime) {
            oldestKey = key
            oldestTime = entry.accessTime
            oldestType = entry.entryType
        }
    }
    
    // Удаление самой старой записи
    if oldestKey != "" {
        delete(ec.entries, oldestKey)
        ec.stats.RecordEviction(oldestType)
        ec.notifyListeners(func(l CacheEventListener) { l.OnCacheEviction(oldestKey, oldestType) })
    }
}

// Инвалидация по паттерну
func (ec *EnhancedCache) Invalidate(pattern string) error {
    regex, err := regexp.Compile(pattern)
    if err != nil {
        return fmt.Errorf("invalid pattern: %w", err)
    }
    
    ec.mu.Lock()
    defer ec.mu.Unlock()
    
    keysToDelete := make([]string, 0)
    
    // Поиск соответствующих ключей
    for key := range ec.entries {
        if regex.MatchString(key) {
            keysToDelete = append(keysToDelete, key)
        }
    }
    
    // Удаление найденных записей
    for _, key := range keysToDelete {
        if entry, exists := ec.entries[key]; exists {
            delete(ec.entries, key)
            ec.stats.RecordEviction(entry.entryType)
        }
    }
    
    ec.stats.UpdateSize(len(ec.entries))
    return nil
}

// Инвалидация пользователя
func (ec *EnhancedCache) InvalidateUser(userID string) error {
    pattern := fmt.Sprintf("^%s:", regexp.QuoteMeta(userID))
    return ec.Invalidate(pattern)
}

// Инвалидация по типу
func (ec *EnhancedCache) InvalidateType(entryType CacheEntryType) error {
    ec.mu.Lock()
    defer ec.mu.Unlock()
    
    keysToDelete := make([]string, 0)
    
    // Поиск записей указанного типа
    for key, entry := range ec.entries {
        if entry.entryType == entryType {
            keysToDelete = append(keysToDelete, key)
        }
    }
    
    // Удаление найденных записей
    for _, key := range keysToDelete {
        delete(ec.entries, key)
        ec.stats.RecordEviction(entryType)
    }
    
    ec.stats.UpdateSize(len(ec.entries))
    return nil
}

// Установка режима fallback
func (ec *EnhancedCache) SetFallbackMode(enabled bool) {
    ec.mu.Lock()
    defer ec.mu.Unlock()
    
    ec.fallbackMode = enabled
    ec.stats.FallbackActive = enabled
}

// Получение статистики
func (ec *EnhancedCache) GetStats() CacheStats {
    ec.mu.RLock()
    defer ec.mu.RUnlock()
    
    // Создание копии статистики
    statsCopy := *ec.stats
    statsCopy.Size = len(ec.entries)
    
    return statsCopy
}

// Фоновая очистка истекших записей
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
    keysToDelete := make([]string, 0)
    
    // Поиск истекших записей
    for key, entry := range ec.entries {
        if entry.isExpired() {
            keysToDelete = append(keysToDelete, key)
        }
    }
    
    // Удаление истекших записей
    for _, key := range keysToDelete {
        if entry, exists := ec.entries[key]; exists {
            delete(ec.entries, key)
            ec.stats.RecordEviction(entry.entryType)
        }
    }
    
    ec.stats.LastCleanup = now
    ec.stats.UpdateSize(len(ec.entries))
}

// Завершение работы кэша
func (ec *EnhancedCache) Shutdown() error {
    if ec.cancel != nil {
        ec.cancel()
    }
    
    ec.mu.Lock()
    defer ec.mu.Unlock()
    
    // Очистка всех записей
    ec.entries = make(map[string]*CacheEntry)
    ec.stats.UpdateSize(0)
    
    return nil
}

// Добавление слушателя событий
func (ec *EnhancedCache) AddListener(listener CacheEventListener) {
    ec.mu.Lock()
    defer ec.mu.Unlock()
    ec.listeners = append(ec.listeners, listener)
}

// Уведомление слушателей
func (ec *EnhancedCache) notifyListeners(notify func(CacheEventListener)) {
    for _, listener := range ec.listeners {
        go notify(listener) // Асинхронное уведомление
    }
}
```

## Configuration - Конфигурация

### EnhancedCacheConfig и EnhancedIAMCacheConfig
```plantuml
class EnhancedCacheConfig {
    +MaxSize: int
    +CleanupInterval: time.Duration
    +DefaultTTLs: map[CacheEntryType]time.Duration
}

class EnhancedIAMCacheConfig {
    +CacheConfig: *EnhancedCacheConfig
    +FallbackCacheConfig: *EnhancedCacheConfig
    +FallbackEnabled: bool
}
```

**Реализация конфигурации:**
```go
// config/cache_config.go - конфигурация кэша
type EnhancedCacheConfig struct {
    MaxSize         int                                `yaml:"max_size" json:"max_size"`
    CleanupInterval time.Duration                      `yaml:"cleanup_interval" json:"cleanup_interval"`
    DefaultTTLs     map[CacheEntryType]time.Duration  `yaml:"default_ttls" json:"default_ttls"`
    EvictionPolicy  EvictionPolicy                     `yaml:"eviction_policy" json:"eviction_policy"`
    EnableMetrics   bool                               `yaml:"enable_metrics" json:"enable_metrics"`
}

type EnhancedIAMCacheConfig struct {
    CacheConfig         *EnhancedCacheConfig `yaml:"cache" json:"cache"`
    FallbackCacheConfig *EnhancedCacheConfig `yaml:"fallback_cache" json:"fallback_cache"`
    FallbackEnabled     bool                 `yaml:"fallback_enabled" json:"fallback_enabled"`
    HealthCheckInterval time.Duration        `yaml:"health_check_interval" json:"health_check_interval"`
}

// Создание конфигурации по умолчанию
func DefaultEnhancedCacheConfig() *EnhancedCacheConfig {
    return &EnhancedCacheConfig{
        MaxSize:         10000,
        CleanupInterval: 5 * time.Minute,
        DefaultTTLs:     DefaultTTLs,
        EvictionPolicy:  LRU,
        EnableMetrics:   true,
    }
}

func DefaultEnhancedIAMCacheConfig() *EnhancedIAMCacheConfig {
    return &EnhancedIAMCacheConfig{
        CacheConfig:         DefaultEnhancedCacheConfig(),
        FallbackCacheConfig: DefaultFallbackCacheConfig(),
        FallbackEnabled:     true,
        HealthCheckInterval: 30 * time.Second,
    }
}

func DefaultFallbackCacheConfig() *EnhancedCacheConfig {
    config := DefaultEnhancedCacheConfig()
    config.MaxSize = 5000  // Меньший размер для fallback
    config.DefaultTTLs = FallbackTTLs  // Расширенные TTL
    config.CleanupInterval = 10 * time.Minute  // Реже очистка
    return config
}

// Валидация конфигурации
func (ecc *EnhancedCacheConfig) Validate() error {
    if ecc.MaxSize <= 0 {
        return errors.New("max_size must be positive")
    }
    
    if ecc.CleanupInterval <= 0 {
        return errors.New("cleanup_interval must be positive")
    }
    
    if len(ecc.DefaultTTLs) == 0 {
        return errors.New("default_ttls cannot be empty")
    }
    
    // Проверка TTL для каждого типа
    for entryType, ttl := range ecc.DefaultTTLs {
        if !entryType.IsValid() {
            return fmt.Errorf("invalid entry type: %d", int(entryType))
        }
        if ttl <= 0 {
            return fmt.Errorf("TTL for %s must be positive", entryType.String())
        }
    }
    
    return nil
}

func (eiac *EnhancedIAMCacheConfig) Validate() error {
    if eiac.CacheConfig == nil {
        return errors.New("cache config cannot be nil")
    }
    
    if err := eiac.CacheConfig.Validate(); err != nil {
        return fmt.Errorf("cache config validation failed: %w", err)
    }
    
    if eiac.FallbackEnabled {
        if eiac.FallbackCacheConfig == nil {
            return errors.New("fallback cache config cannot be nil when fallback is enabled")
        }
        
        if err := eiac.FallbackCacheConfig.Validate(); err != nil {
            return fmt.Errorf("fallback cache config validation failed: %w", err)
        }
    }
    
    if eiac.HealthCheckInterval <= 0 {
        return errors.New("health_check_interval must be positive")
    }
    
    return nil
}

// Загрузка конфигурации из файла
func LoadEnhancedIAMCacheConfig(configPath string) (*EnhancedIAMCacheConfig, error) {
    data, err := ioutil.ReadFile(configPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file: %w", err)
    }
    
    var config EnhancedIAMCacheConfig
    if err := yaml.Unmarshal(data, &config); err != nil {
        return nil, fmt.Errorf("failed to parse config: %w", err)
    }
    
    if err := config.Validate(); err != nil {
        return nil, fmt.Errorf("config validation failed: %w", err)
    }
    
    return &config, nil
}

// Пример YAML конфигурации
const ExampleConfigYAML = `
cache:
  max_size: 10000
  cleanup_interval: 5m
  eviction_policy: 0  # LRU
  enable_metrics: true
  default_ttls:
    0: 15m  # UserCredentials
    1: 30m  # UserRoles
    2: 1h   # Permissions
    3: 2h   # MFASettings
    4: 10m  # SessionData

fallback_cache:
  max_size: 5000
  cleanup_interval: 10m
  eviction_policy: 0  # LRU
  enable_metrics: true
  default_ttls:
    0: 1h   # UserCredentials
    1: 2h   # UserRoles
    2: 4h   # Permissions
    3: 8h   # MFASettings
    4: 30m  # SessionData

fallback_enabled: true
health_check_interval: 30s
`
```

Cache Detailed Architecture Diagram Task 1 обеспечивает глубокое понимание внутренней структуры Enhanced Cache System, показывая детальную реализацию каждого компонента и служа мостом между архитектурными решениями и конкретным кодом системы кэширования.