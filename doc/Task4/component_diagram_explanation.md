# Объяснение Component Diagram (c4_architecture_component.puml)

## Назначение диаграммы

Component Diagram показывает внутреннюю структуру контейнера Security Audit Logger, детализируя его компоненты, их взаимодействие и ответственности. Это третий уровень модели C4, который раскрывает архитектуру на уровне компонентов внутри выбранного контейнера.

## Структура PlantUML файла

### Заголовок и импорты
```plantuml
@startuml Task4_Security_System_Component
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Component.puml

title Component Diagram - Security Audit Logger Container (Task 4)
```

**Объяснение:**
- Использование C4_Component.puml для элементов уровня компонентов
- Фокус на детализации Security Audit Logger контейнера

### Внешние контейнеры
```plantuml
Container(activity_detector, "Suspicious Activity Detector", "Go")
Container(alert_system, "Security Alert System", "Go")
Container(reporting_system, "Security Reporting System", "Go")
```

**Контекст взаимодействия:**
- Показаны внешние контейнеры для понимания границ и взаимодействий
- Упрощенное представление без детального описания

## Основные компоненты Security Audit Logger

### Security Event Manager
```plantuml
Component(event_manager, "Security Event Manager", "Go Struct", "Manages security event lifecycle and validation")
```

**Детальное описание:**
- **Тип:** Go Struct - основная структура данных с методами
- **Роль:** Центральный координатор всех операций с событиями безопасности
- **Ключевые ответственности:**
  - **Валидация событий** - проверка корректности и полноты данных
  - **Маршрутизация событий** - направление событий соответствующим обработчикам
  - **Управление жизненным циклом** - от создания до архивации событий
  - **Координация компонентов** - синхронизация работы всех частей системы

**Архитектурные особенности:**
- Единая точка входа для всех событий безопасности
- Реализация паттерна Facade для упрощения интерфейса
- Асинхронная обработка для высокой производительности
- Встроенная обработка ошибок и восстановление

### Pattern Analyzer
```plantuml
Component(pattern_analyzer, "Pattern Analyzer", "Go Interface", "Analyzes security event patterns for threats")
```

**Детальное описание:**
- **Тип:** Go Interface - абстракция для различных алгоритмов анализа
- **Роль:** Анализ паттернов событий для выявления угроз безопасности
- **Алгоритмы анализа:**
  - **Статистический анализ** - выявление аномалий в статистических данных
  - **Временной анализ** - обнаружение подозрительных временных паттернов
  - **Поведенческий анализ** - анализ изменений в поведении пользователей
  - **Корреляционный анализ** - связывание разрозненных событий

**Технические особенности:**
- Интерфейсная архитектура для подключения различных алгоритмов
- Поддержка машинного обучения и статистических методов
- Настраиваемые пороги чувствительности
- Адаптивное обучение на исторических данных

### Event Store Manager
```plantuml
Component(event_store_mgr, "Event Store Manager", "Go Struct", "Manages in-memory and persistent event storage")
```

**Детальное описание:**
- **Тип:** Go Struct - конкретная реализация управления хранилищем
- **Роль:** Управление двухуровневым хранилищем событий
- **Архитектура хранения:**
  - **In-Memory Cache** - быстрый доступ к недавним событиям
  - **Persistent Storage** - долгосрочное хранение на диске
  - **LRU Eviction** - политика вытеснения для управления памятью
  - **Compression** - сжатие данных для экономии места

**Функциональность:**
- Автоматическое управление жизненным циклом данных
- Оптимизация запросов через индексирование
- Резервное копирование критических данных
- Мониторинг использования ресурсов

### Severity Calculator
```plantuml
Component(severity_calculator, "Severity Calculator", "Go Function", "Calculates risk scores and severity levels")
```

**Детальное описание:**
- **Тип:** Go Function - функциональный компонент для расчетов
- **Роль:** Расчет оценок риска и определение уровней серьезности
- **Алгоритмы расчета:**
  - **Базовая оценка** - начальная оценка на основе типа события
  - **Контекстные факторы** - учет времени, местоположения, истории
  - **Весовые коэффициенты** - настраиваемые веса для различных факторов
  - **Нормализация** - приведение к стандартной шкале 0-100

**Факторы риска:**
- Тип события (аутентификация, доступ, изменения)
- Частота событий от пользователя/IP
- Географическое расположение
- Время события (рабочие/нерабочие часы)
- Исторические данные пользователя

## Специализированные обработчики событий

### Authentication Event Handler
```plantuml
Component(auth_event_handler, "Authentication Event Handler", "Go Struct", "Handles authentication-specific events")
```

**Специализация:**
- **Типы событий:** LOGIN, LOGOUT, AUTH_FAILURE, PASSWORD_CHANGE
- **Анализ паттернов:** Брутфорс атаки, credential stuffing
- **Метрики:** Время между попытками, географическое распределение
- **Интеграция:** MFA системы, password policies

**Ключевые функции:**
- Валидация учетных данных
- Отслеживание неудачных попыток
- Анализ паттернов входа
- Интеграция с системами блокировки

### MFA Event Handler
```plantuml
Component(mfa_event_handler, "MFA Event Handler", "Go Struct", "Handles multi-factor authentication events")
```

**Специализация:**
- **Типы событий:** MFA_CHALLENGE, MFA_SUCCESS, MFA_FAILURE, MFA_BYPASS
- **Анализ:** Попытки обхода MFA, аномальные паттерны использования
- **Метрики:** Частота использования MFA, типы факторов
- **Безопасность:** Обнаружение компрометации второго фактора

**Ключевые функции:**
- Валидация TOTP токенов
- Отслеживание backup кодов
- Анализ попыток обхода
- Интеграция с MFA провайдерами

### Session Event Handler
```plantuml
Component(session_event_handler, "Session Event Handler", "Go Struct", "Handles session lifecycle events")
```

**Специализация:**
- **Типы событий:** SESSION_START, SESSION_END, SESSION_TIMEOUT, SESSION_HIJACK
- **Анализ:** Аномальные сессии, session hijacking, concurrent sessions
- **Метрики:** Продолжительность сессий, количество активных сессий
- **Безопасность:** Обнаружение подозрительной активности в сессиях

**Ключевые функции:**
- Управление жизненным циклом сессий
- Отслеживание активности в сессиях
- Обнаружение аномальных паттернов
- Принудительное завершение сессий

### Permission Event Handler
```plantuml
Component(permission_event_handler, "Permission Event Handler", "Go Struct", "Handles authorization and permission events")
```

**Специализация:**
- **Типы событий:** ACCESS_GRANTED, ACCESS_DENIED, PRIVILEGE_ESCALATION
- **Анализ:** Попытки эскалации привилегий, нарушения политик доступа
- **Метрики:** Частота отказов в доступе, паттерны доступа к ресурсам
- **Безопасность:** Обнаружение insider threats, нарушений RBAC

**Ключевые функции:**
- Валидация разрешений
- Отслеживание изменений ролей
- Анализ паттернов доступа
- Обнаружение нарушений политик

## Хранилища данных компонентов

### In-Memory Event Store
```plantuml
ComponentDb(memory_store, "In-Memory Event Store", "sync.Map", "Fast access to recent security events")
```

**Технические характеристики:**
- **Тип:** sync.Map - потокобезопасная карта Go
- **Назначение:** Быстрый доступ к недавним событиям безопасности
- **Особенности:**
  - Concurrent-safe операции
  - O(1) доступ по ключу
  - Автоматическое управление памятью
  - LRU eviction policy

**Структура данных:**
```go
type MemoryEventStore struct {
    events    sync.Map // map[string]*SecurityEvent
    index     sync.Map // map[string][]string (индексы)
    maxSize   int
    eviction  *LRUEviction
}
```

### Persistent Event Store
```plantuml
ComponentDb(persistent_store, "Persistent Event Store", "File/JSON", "Long-term storage of security events")
```

**Технические характеристики:**
- **Формат:** JSON файлы для структурированного хранения
- **Организация:** Партиционирование по дате и типу событий
- **Особенности:**
  - Сжатие данных (gzip)
  - Ротация файлов по размеру/времени
  - Индексирование для быстрого поиска
  - Резервное копирование

**Структура файлов:**
```
/var/log/security/
├── 2024/01/15/
│   ├── auth_events.json.gz
│   ├── mfa_events.json.gz
│   └── session_events.json.gz
└── indexes/
    ├── user_index.json
    └── ip_index.json
```

## Взаимодействие компонентов

### Внутренние взаимодействия
```plantuml
Rel(event_manager, auth_event_handler, "Route auth events", "Function call")
Rel(event_manager, mfa_event_handler, "Route MFA events", "Function call")
Rel(event_manager, session_event_handler, "Route session events", "Function call")
Rel(event_manager, permission_event_handler, "Route permission events", "Function call")
```

**Паттерн маршрутизации:**
1. **Event Manager** получает событие
2. Определяет тип события по SecurityEventType
3. Маршрутизирует к соответствующему обработчику
4. Обработчик выполняет специализированную логику

### Анализ и расчеты
```plantuml
Rel(auth_event_handler, severity_calculator, "Calculate risk", "Function call")
Rel(mfa_event_handler, severity_calculator, "Calculate risk", "Function call")
Rel(session_event_handler, pattern_analyzer, "Analyze patterns", "Interface call")
Rel(permission_event_handler, pattern_analyzer, "Analyze patterns", "Interface call")
```

**Поток анализа:**
1. Обработчик события вызывает Severity Calculator
2. Рассчитывается базовая оценка риска
3. Pattern Analyzer анализирует контекст и паттерны
4. Итоговая оценка передается в Event Manager

### Управление хранилищем
```plantuml
Rel(event_manager, event_store_mgr, "Store events", "Method call")
Rel(pattern_analyzer, event_store_mgr, "Query events", "Method call")
```

**Операции с данными:**
- **Store events** - сохранение новых событий
- **Query events** - запросы для анализа паттернов
- **Update indexes** - обновление индексов для быстрого поиска
- **Cleanup old data** - очистка устаревших данных

### Взаимодействие с хранилищами
```plantuml
Rel(event_store_mgr, memory_store, "Cache events", "Read/Write")
Rel(event_store_mgr, persistent_store, "Persist events", "Read/Write")
```

**Стратегия хранения:**
1. Новые события сначала попадают в memory_store
2. Асинхронно записываются в persistent_store
3. Старые события вытесняются из памяти
4. Запросы сначала проверяют memory_store, затем persistent_store

## Внешние взаимодействия

### Интеграция с другими контейнерами
```plantuml
Rel(event_manager, activity_detector, "Send events", "Channel/API")
Rel(pattern_analyzer, alert_system, "Threat patterns", "Event notification")
Rel(event_store_mgr, reporting_system, "Event data", "Query API")
```

**Внешние интерфейсы:**
1. **Channel/API** - асинхронная передача событий
2. **Event notification** - уведомления о найденных угрозах
3. **Query API** - предоставление данных для отчетности

## Архитектурные паттерны

### 1. Strategy Pattern
- **Pattern Analyzer** как интерфейс для различных алгоритмов
- Возможность подключения новых алгоритмов анализа
- Настройка алгоритмов через конфигурацию

### 2. Chain of Responsibility
- Последовательная обработка событий через обработчики
- Каждый обработчик решает, обрабатывать ли событие
- Возможность добавления новых обработчиков

### 3. Observer Pattern
- Уведомления о событиях между компонентами
- Слабая связанность через события
- Возможность подписки на определенные типы событий

### 4. Repository Pattern
- **Event Store Manager** как абстракция над хранилищем
- Единый интерфейс для различных типов хранения
- Инкапсуляция логики доступа к данным

## Преимущества архитектуры компонентов

### 1. Разделение ответственности
- Каждый компонент имеет четко определенную роль
- Специализированные обработчики для разных типов событий
- Упрощенное тестирование и отладка

### 2. Расширяемость
- Легкое добавление новых типов событий
- Подключение новых алгоритмов анализа
- Модульная архитектура для независимого развития

### 3. Производительность
- Двухуровневое хранилище для оптимизации доступа
- Асинхронная обработка событий
- Эффективные алгоритмы индексирования

### 4. Надежность
- Изоляция ошибок в отдельных компонентах
- Graceful degradation при сбоях
- Резервирование критических данных

## Соответствие требованиям Task 4

### 4.1 Улучшение аудит логирования
- **Security Event Manager** - централизованное управление событиями
- **Специализированные обработчики** - детальная обработка различных типов событий
- **Event Store Manager** - эффективное хранение и индексирование

### 4.2 Система оповещений и блокировки
- **Pattern Analyzer** - обнаружение подозрительных паттернов
- **Severity Calculator** - оценка серьезности угроз
- **Интеграция с Alert System** - передача данных для оповещений

### 4.3 Система отчетности и аудиторского следа
- **Persistent Event Store** - долгосрочное хранение для аудита
- **Query API** - предоставление данных для отчетности
- **Структурированные данные** - удобство анализа и экспорта

Диаграмма компонентов обеспечивает детальное понимание внутренней архитектуры Security Audit Logger и служит основой для реализации на уровне кода.