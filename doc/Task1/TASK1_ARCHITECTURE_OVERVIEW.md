# Task1 Architecture Overview - Enhanced Cache System

## Архитектурные диаграммы

Данный документ содержит полную архитектуру системы улучшенного кэширования, реализованной в рамках Task1.

### Файлы диаграмм:

1. **`task1_c4_architecture.puml`** - Полная C4 архитектура (Context, Container, Component, Code)
2. **`task1_cache_detailed_architecture.puml`** - Детальная архитектура кэш-системы
3. **`task1_data_flow_diagrams.puml`** - Диаграммы потоков данных для различных сценариев

## C4 Architecture Levels

### Level 1: System Context
```
[S3 Client] ---> [Versity S3 Gateway] ---> [External IAM Services]
                        |
                        v
                [Object Storage]
```

### Level 2: Container Diagram
```
Versity S3 Gateway:
├── S3 API Layer
├── Enhanced Auth System ⭐ (Task1)
└── Storage Layer

External Services:
├── LDAP Service
├── Vault Service  
├── S3 IAM Service
└── IPA Service
```

### Level 3: Component Diagram
```
Enhanced Auth System:
├── IAM Service Interface
├── Enhanced IAM Cache ⭐
├── Enhanced Cache Core ⭐
├── Fallback Cache ⭐
├── Cache Statistics ⭐
└── Base IAM Services
```

### Level 4: Code Diagram
```
Key Classes:
├── EnhancedCache (LRU + TTL + Invalidation)
├── EnhancedIAMCache (IAM Integration + Fallback)
├── CacheEntry (Data Structure)
├── CacheStats (Monitoring)
└── CacheEntryType (Type System)
```

## Архитектурные принципы Task1

### 1. Layered Architecture (Слоистая архитектура)
```
┌─────────────────────────────────────┐
│           S3 API Layer              │
├─────────────────────────────────────┤
│        Enhanced IAM Cache           │ ⭐ Task1
├─────────────────────────────────────┤
│         Enhanced Cache Core         │ ⭐ Task1
├─────────────────────────────────────┤
│        Base IAM Services            │
└─────────────────────────────────────┘
```

### 2. Dual Cache Pattern (Двойной кэш)
```
Primary Cache ←→ Enhanced IAM Cache ←→ Fallback Cache
     ↓                    ↓                    ↓
  Fast TTL           Coordination         Extended TTL
  (15 min)           & Health             (60 min)
                     Monitoring
```

### 3. Strategy Pattern (Стратегия инвалидации)
```
Cache Invalidation:
├── Pattern-based (Regex)
├── User-based (All user data)
├── Type-based (Specific data types)
└── Direct key (Single entry)
```

## Ключевые архитектурные решения

### 1. LRU Eviction Policy
- **Проблема**: Неконтролируемый рост памяти
- **Решение**: Least Recently Used алгоритм
- **Реализация**: Отслеживание времени доступа + автоматическое вытеснение

### 2. Configurable TTL per Type
- **Проблема**: Разные типы данных имеют разную частоту изменений
- **Решение**: Индивидуальные TTL для каждого типа
- **Типы**:
  - UserCredentials: 15 мин
  - UserRoles: 30 мин  
  - Permissions: 1 час
  - MFASettings: 2 часа
  - SessionData: 10 мин

### 3. Fallback Mechanism
- **Проблема**: Недоступность IAM сервисов
- **Решение**: Отдельный кэш с расширенным TTL
- **Преимущества**: Непрерывность сервиса, graceful degradation

### 4. Advanced Invalidation
- **Проблема**: Устаревшие данные после изменений
- **Решение**: Множественные стратегии инвалидации
- **Методы**: Pattern, User, Type, Direct

## Data Flow Scenarios

### Scenario 1: Cache Hit (Попадание в кэш)
```
Client → API → IAM Cache → Primary Cache → Return Data
                                ↓
                         Update LRU + Stats
```

### Scenario 2: Cache Miss - Service Available
```
Client → API → IAM Cache → Primary Cache (miss)
                    ↓
              Base IAM Service
                    ↓
         Store in Primary + Fallback
                    ↓
              Return Data
```

### Scenario 3: Fallback Scenario
```
Client → API → IAM Cache → Primary Cache (miss)
                    ↓
              Base IAM Service (error)
                    ↓
              Fallback Cache (hit)
                    ↓
         Return Stale Data + Warning
```

### Scenario 4: Cache Invalidation
```
Admin → Update Request → IAM Cache
                           ↓
                    Update IAM Service
                           ↓
              Invalidate Primary + Fallback
                           ↓
                    Refresh with New Data
```

### Scenario 5: LRU Eviction
```
New Entry → Cache Full → Find LRU Entry → Evict → Add New Entry
                              ↓
                        Update Statistics
```

### Scenario 6: Health Monitoring
```
Health Monitor → Check IAM Service → Update Fallback Mode
                        ↓
                 Update Statistics
```

## Performance Characteristics

### Memory Usage
- **Controlled Growth**: Максимальный размер кэша
- **LRU Eviction**: Автоматическое управление памятью
- **Dual Cache**: Оптимизация между скоростью и надежностью

### Response Time
- **Cache Hit**: ~1ms (memory access)
- **Cache Miss**: ~50-200ms (IAM service call)
- **Fallback**: ~1ms (stale data acceptable)

### Throughput
- **Concurrent Access**: Thread-safe операции
- **Read Optimization**: RWMutex для параллельного чтения
- **Write Batching**: Эффективная запись в оба кэша

## Monitoring & Observability

### Cache Statistics
```go
type CacheStats struct {
    Hits           int64    // Количество попаданий
    Misses         int64    // Количество промахов  
    Evictions      int64    // Количество вытеснений
    Size           int      // Текущий размер
    MaxSize        int      // Максимальный размер
    FallbackActive bool     // Статус fallback режима
    LastCleanup    time.Time // Последняя очистка
}
```

### Health Metrics
- **Hit Rate**: Процент попаданий в кэш
- **Eviction Rate**: Частота вытеснений
- **Fallback Usage**: Использование резервного кэша
- **Service Health**: Доступность IAM сервисов

## Security Considerations

### Data Protection
- **In-Memory Only**: Нет персистентного хранения
- **TTL Enforcement**: Автоматическое истечение данных
- **Secure Cleanup**: Полная очистка при shutdown

### Access Control
- **Interface Segregation**: Четкое разделение интерфейсов
- **Type Safety**: Строгая типизация кэш-записей
- **Pattern Validation**: Безопасная инвалидация по шаблонам

## Deployment Architecture

### Single Node Deployment
```
Application Server:
├── Go Runtime
│   └── Versity S3 Gateway
│       └── Enhanced Cache System ⭐
└── System Memory
    ├── Primary Cache Storage
    └── Fallback Cache Storage
```

### High Availability Considerations
- **Stateless Design**: Кэш не влияет на консистентность
- **Fast Recovery**: Быстрое восстановление после рестарта
- **Service Independence**: Работа при недоступности IAM

## Future Enhancements

### Potential Improvements
1. **Distributed Caching**: Redis/Memcached integration
2. **Cache Warming**: Proactive cache population
3. **Advanced Metrics**: Prometheus integration
4. **Cache Partitioning**: Sharding for large datasets
5. **Compression**: Memory optimization for large entries

### Scalability Considerations
- **Horizontal Scaling**: Multiple gateway instances
- **Cache Coordination**: Distributed invalidation
- **Load Balancing**: IAM service distribution
- **Resource Monitoring**: Memory and CPU optimization

## Conclusion

Архитектура Task1 представляет собой комплексное решение для улучшения производительности и надежности системы аутентификации через:

1. **Эффективное управление памятью** (LRU)
2. **Гибкую конфигурацию TTL** (по типам данных)
3. **Надежный fallback механизм** (непрерывность сервиса)
4. **Продвинутую инвалидацию** (множественные стратегии)
5. **Комплексный мониторинг** (производительность и здоровье)

Система спроектирована с учетом принципов SOLID, обеспечивает высокую производительность и готова к продакшн использованию.