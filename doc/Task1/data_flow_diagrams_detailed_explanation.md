# Подробное объяснение Data Flow Diagrams Task 1 - Enhanced Cache System

## Назначение диаграммы

Data Flow Diagrams для Task 1 представляют различные сценарии работы Enhanced Cache System, показывая потоки данных в реальных ситуациях использования. Эти диаграммы служат мостом между архитектурным дизайном и практической реализацией, демонстрируя как система обрабатывает различные случаи использования кэша.

## Структура PlantUML и сценарии

### Заголовок и тема
```plantuml
@startuml Task1_Data_Flow_Diagrams
!theme plain
title Enhanced Cache System - Data Flow Scenarios (Task1)
```

**Архитектурное значение:**
- Фокус на практических сценариях использования
- Демонстрация различных путей выполнения в системе кэширования

## SCENARIO 1: Normal Cache Hit Flow

### Диаграмма потока
```plantuml
participant "S3 Client" as client
participant "S3 API Layer" as api
participant "Enhanced IAM Cache" as iam_cache
participant "Primary Cache" as primary
participant "Cache Statistics" as stats

client -> api: **S3 Request**\n(Access Key: "user123")
api -> iam_cache: **GetUserAccount("user123")**
iam_cache -> primary: **Get("user:user123", UserCredentials)**
primary -> primary: **Check expiry & type**
primary -> primary: **Update access time (LRU)**
primary -> stats: **Increment hits**
primary --> iam_cache: **Return Account{...}**
iam_cache --> api: **Return Account**
api --> client: **S3 Response (200 OK)**
```

**Реализация сценария Cache Hit:**
```go
// scenarios/cache_hit.go - реализация сценария попадания в кэш
func (eic *EnhancedIAMCache) handleCacheHitScenario(accessKey string) (Account, error) {
    startTime := time.Now()
    userKey := eic.getUserKey(accessKey)
    
    // Попытка получения из основного кэша
    if cached, found := eic.cache.Get(userKey, UserCredentials); found {
        account := cached.(Account)
        
        // Логирование успешного попадания
        log.Printf("Cache hit for access key: %s, user: %s", accessKey, account.UserID)
        
        // Обновление метрик производительности
        eic.metrics.CacheHitLatency.Observe(time.Since(startTime).Seconds())
        eic.metrics.TotalCacheHits.Inc()
        
        // Аудит успешного доступа
        eic.auditLogger.LogCacheAccess(account.UserID, "cache_hit", userKey)
        
        return account, nil
    }
    
    return Account{}, errors.New("cache miss")
}

// Детальная реализация Get метода с проверками
func (ec *EnhancedCache) Get(key string, entryType CacheEntryType) (interface{}, bool) {
    ec.mu.RLock()
    entry, exists := ec.entries[key]
    ec.mu.RUnlock()
    
    if !exists {
        ec.recordCacheMiss(key, entryType, "entry_not_found")
        return nil, false
    }
    
    // Проверка типа записи
    if entry.entryType != entryType {
        ec.recordCacheMiss(key, entryType, "type_mismatch")
        log.Printf("Cache type mismatch for key %s: expected %s, got %s", 
            key, entryType.String(), entry.entryType.String())
        return nil, false
    }
    
    // Проверка срока действия
    if entry.isExpired() {
        // Удаление истекшей записи
        ec.mu.Lock()
        delete(ec.entries, key)
        ec.mu.Unlock()
        
        ec.recordCacheMiss(key, entryType, "entry_expired")
        log.Printf("Cache entry expired for key %s", key)
        return nil, false
    }
    
    // Успешное попадание - обновление LRU и статистики
    entry.touch()
    ec.recordCacheHit(key, entryType)
    
    return entry.GetValue(), true
}
```

## SCENARIO 2: Cache Miss with Service Available

### Диаграмма потока
```plantuml
client -> api: **S3 Request**\n(Access Key: "newuser")
api -> iam_cache: **GetUserAccount("newuser")**
iam_cache -> primary: **Get("user:newuser", UserCredentials)**
primary -> stats: **Increment misses**
primary --> iam_cache: **Not found**
iam_cache -> base_iam: **GetUserAccount("newuser")**
base_iam --> iam_cache: **Return Account{...}**

par Store in Primary Cache
    iam_cache -> primary: **Set("user:newuser", account, 15min, UserCredentials)**
    primary -> primary: **Check cache size**
    alt Cache full
        primary -> primary: **evictLRU()**
        primary -> stats: **Increment evictions**
    end
    primary -> primary: **Store entry**
and Store in Fallback Cache
    iam_cache -> fallback: **Set("user:newuser", account, 60min, UserCredentials)**
    fallback -> fallback: **Store with extended TTL**
end
```

**Реализация сценария Cache Miss:**
```go
// scenarios/cache_miss.go - обработка промаха кэша
func (eic *EnhancedIAMCache) handleCacheMissScenario(accessKey string) (Account, error) {
    startTime := time.Now()
    userKey := eic.getUserKey(accessKey)
    
    // Попытка получения из IAM сервиса
    account, err := eic.fetchFromIAMService(accessKey)
    if err != nil {
        // Если основной сервис недоступен, пробуем fallback
        return eic.handleFallbackScenario(userKey)
    }
    
    // Успешное получение из IAM - сохранение в оба кэша
    eic.storeInBothCaches(userKey, account)
    
    // Метрики для cache miss с успешным восстановлением
    eic.metrics.CacheMissLatency.Observe(time.Since(startTime).Seconds())
    eic.metrics.TotalCacheMisses.Inc()
    eic.metrics.IAMServiceCalls.Inc()
    
    return account, nil
}
```

Data Flow Diagrams Task 1 обеспечивают полное понимание различных сценариев работы Enhanced Cache System, показывая как система обрабатывает различные ситуации и служа мостом между архитектурным дизайном и практической реализацией всех аспектов кэширования аутентификации.