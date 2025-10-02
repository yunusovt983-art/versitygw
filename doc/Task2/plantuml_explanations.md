# Подробные объяснения PlantUML диаграмм Task 2

Данный документ содержит детальные объяснения всех PlantUML диаграмм, созданных для архитектуры системы MFA в рамках Task 2.

## 📋 Список диаграмм

1. [C4 Context Diagram](#1-c4-context-diagram) - Контекстная диаграмма
2. [C4 Container Diagram](#2-c4-container-diagram) - Диаграмма контейнеров  
3. [C4 Component Diagram](#3-c4-component-diagram) - Диаграмма компонентов
4. [C4 Code Diagram](#4-c4-code-diagram) - Диаграмма кода
5. [MFA Sequence Diagram](#5-mfa-sequence-diagram) - Диаграмма последовательности
6. [MFA Deployment Diagram](#6-mfa-deployment-diagram) - Диаграмма развертывания
7. [MFA Integration Diagram](#7-mfa-integration-diagram) - Диаграмма интеграции
8. [MFA Security Architecture](#8-mfa-security-architecture) - Архитектура безопасности

---

## 1. C4 Context Diagram

**Файл:** `c4_context_diagram.puml`

### 🎯 Назначение
Показывает систему Versity S3 Gateway с MFA на самом высоком уровне абстракции, демонстрируя взаимодействие с внешними пользователями и системами.

### 🏗️ Основные элементы

#### Участники (Persons):
- **S3 API User** - Разработчик или приложение, использующее S3 API с MFA
- **System Administrator** - Администратор, управляющий MFA политиками

#### Центральная система:
- **Versity S3 Gateway** - S3-совместимый API gateway с поддержкой MFA

#### Внешние системы:
- **TOTP Authenticator** - Мобильные приложения (Google Authenticator, Authy)
- **IAM Backend** - Система управления идентификацией (LDAP, Vault, Database)
- **S3 Client Applications** - AWS CLI, SDK или пользовательские приложения
- **Monitoring System** - Система логирования и метрик (Prometheus, ELK)

### 🔄 Ключевые взаимодействия
- Пользователи отправляют S3 запросы с MFA токенами через HTTPS
- Gateway взаимодействует с IAM для аутентификации пользователей
- Система предоставляет QR коды для настройки TOTP приложений
- Отправляет аудит логи и метрики в систему мониторинга

### 📝 Особенности
- RFC 6238 TOTP валидация
- Поддержка backup кодов
- Политики принуждения MFA
- Защита от блокировки пользователей
- Комплексное аудирование

---

## 2. C4 Container Diagram

**Файл:** `c4_container_diagram.puml`

### 🎯 Назначение
Детализирует внутреннюю структуру S3 Gateway системы, показывая основные контейнеры и их взаимодействие.

### 🏗️ Архитектурные слои

#### 1. Основной сервер:
- **S3 API Server** (Go/Fiber) - Главный API сервер с MFA интеграцией

#### 2. Слой аутентификации:
- **Enhanced Authentication** - V4 signature валидация с MFA
- **MFA Middleware** - Валидация и принуждение MFA токенов

#### 3. MFA сервисы:
- **MFA Service** - Основная бизнес-логика MFA
- **TOTP Generator** - RFC 6238 генерация и валидация
- **QR Code Generator** - Генерация QR кодов для настройки

#### 4. Слой хранения:
- **MFA Storage** - Пользовательские MFA данные (JSON)
- **Configuration Storage** - MFA политики и настройки

#### 5. Утилиты:
- **Audit Logger** - Логирование MFA событий
- **Metrics Collector** - Сбор MFA метрик

### 🔄 Взаимодействия
- API Server → Enhanced Auth → MFA Middleware → MFA Service
- MFA Service использует TOTP Generator, QR Generator и MFA Storage
- Middleware интегрируется с Audit Logger и Metrics Collector

### 📝 Ключевые особенности
- Файловая персистентность с шифрованием секретов
- Хешированные backup коды
- Изоляция пользователей
- Атомарные операции

---

## 3. C4 Component Diagram

**Файл:** `c4_component_diagram.puml`

### 🎯 Назначение
Показывает детальную внутреннюю структуру MFA Service Container, включая все компоненты и их взаимодействия.

### 🏗️ Компонентная архитектура

#### 1. Интерфейсы сервисов:
- **MFAService** - Контракт основных MFA операций
- **MFAStorage** - Контракт персистентности данных

#### 2. Основные реализации:
- **MFAServiceImpl** - Главная реализация MFA сервиса
- **TOTPGenerator** - RFC 6238 TOTP реализация
- **QRCodeGenerator** - Генерация QR кодов
- **MFATokenValidator** - Валидация токенов

#### 3. Реализации хранения:
- **FileMFAStorage** - Файловое хранение MFA данных
- **MemoryMFAStorage** - In-memory хранение для тестов

#### 4. Модели данных:
- **MFASecret** - Структура данных настройки MFA
- **MFAStatus** - Информация о статусе пользователя
- **MFAConfig** - Конфигурация системы MFA
- **MFAUserData** - Персистентные данные пользователя
- **MFAPolicy** - Политики принуждения MFA

#### 5. Движок политик:
- **PolicyEvaluator** - Логика оценки MFA политик
- **RoleChecker** - Требования на основе ролей

#### 6. Компоненты безопасности:
- **LockoutManager** - Блокировка и ограничение скорости
- **BackupCodeManager** - Генерация и валидация backup кодов
- **SecretGenerator** - Криптографически безопасная генерация

#### 7. Обработка ошибок:
- **MFAErrorHandler** - Обработка MFA ошибок
- **MFAErrorCodes** - Определения кодов ошибок

### 🔄 Ключевые зависимости
- MFAServiceImpl реализует MFAService интерфейс
- Использует все основные компоненты (TOTP, QR, Policy, Lockout, Backup)
- FileMFAStorage и MemoryMFAStorage реализуют MFAStorage
- Интеграция с внешней IAM системой через RoleChecker

### 📝 Архитектурные принципы
- Dependency Injection через интерфейсы
- Single Responsibility для каждого компонента
- Testability с отдельными реализациями для тестов
- Security by Design с выделенными компонентами безопасности

---

## 4. C4 Code Diagram

**Файл:** `c4_code_diagram.puml`

### 🎯 Назначение
Представляет самый детальный уровень архитектуры с конкретными классами, интерфейсами и их методами.

### 🏗️ Структура кода

#### 1. Основные интерфейсы:
- **MFAService** - `GenerateSecret()`, `ValidateTOTP()`, `EnableMFA()`, `GetMFAStatus()`
- **MFAStorage** - `StoreMFAData()`, `GetMFAData()`, `DeleteMFAData()`

#### 2. Модели данных:
- **MFASecret** - `Secret`, `QRCode`, `BackupCodes`, `Issuer`, `AccountName`
- **MFAStatus** - `Enabled`, `LastUsed`, `BackupCodesRemaining`, `FailedAttempts`
- **MFAConfig** - `Required`, `TOTPWindow`, `BackupCodes`, `GracePeriod`, `MaxFailedAttempts`
- **MFAUserData** - `UserID`, `Secret`, `BackupCodes`, `Enabled`, `LockedUntil`
- **MFAPolicy** - `RequiredForRoles`, `RequiredForUsers`, `ExemptUsers`, `Active`

#### 3. Основная логика:
- **MFAServiceImpl** - Основная бизнес-логика
- **TOTPGenerator** - RFC 6238 реализация с методами генерации и валидации
- **QRCodeGenerator** - Генерация QR кодов для настройки

#### 4. Реализации хранения:
- **FileMFAStorage** - JSON файловое хранение с атомарными записями и правами 0600
- **MemoryMFAStorage** - In-memory хранение для разработки и тестов

#### 5. Middleware классы:
- **MFAMiddleware** - `VerifyMFA()`, `RequireMFA()`, `extractMFAToken()`
- **EnhancedAuthMiddleware** - Интеграция V4 signature + MFA валидация
- **MFATokenValidator** - Утилиты валидации токенов

#### 6. Компоненты безопасности:
- **BackupCodeManager** - Генерация, хеширование и валидация backup кодов
- **LockoutManager** - Логика блокировки пользователей
- **SecretGenerator** - Криптографически безопасная генерация секретов

#### 7. Обработка ошибок:
- **MFAError** - `Code`, `Message`, `UserID`
- **MFAErrorCode** - `InvalidToken`, `UserLocked`, `NotEnabled`

#### 8. Утилиты:
- **ContextKeys** - `MFAVerified`, `Account`, `IsRoot`
- **AuditLogger** - Логирование MFA событий
- **MetricsCollector** - Сбор метрик успеха/неудачи

### 🔄 Детальные взаимодействия
- Реализация интерфейсов с конкретными методами
- Зависимости между компонентами с описанием использования
- Интеграция с утилитами для логирования и метрик

### 📝 Технические детали
- **RFC 6238 Features:** 30-секундные окна, HMAC-SHA1, 6-значные токены, Base32 кодирование
- **Security Features:** Атомарные файловые операции, права доступа 0600, JSON сериализация
- **Key Methods:** Полный список методов для каждого основного класса

---

## 5. MFA Sequence Diagram

**Файл:** `mfa_sequence_diagram.puml`

### 🎯 Назначение
Показывает полный жизненный цикл MFA системы через временные последовательности взаимодействий.

### 🏗️ Участники диаграммы
- **S3 User** - Пользователь S3 API
- **S3 Client** - Клиентское приложение
- **S3 Gateway** - Основной шлюз
- **Enhanced Auth** - Расширенная аутентификация
- **MFA Middleware** - MFA middleware
- **MFA Service** - MFA сервис
- **TOTP Generator** - TOTP генератор
- **MFA Storage** - MFA хранилище
- **TOTP App** - TOTP приложение
- **Audit Logger** - Аудит логгер

### 🔄 Основные сценарии

#### 1. MFA Setup Phase (Настройка MFA):
1. Пользователь запрашивает настройку MFA
2. Gateway аутентифицирует пользователя через V4 подпись
3. MFA Service генерирует секрет и backup коды
4. Возвращается QR код и backup коды
5. Пользователь сканирует QR код в TOTP приложении
6. Подтверждение настройки с TOTP токеном
7. Активация MFA для пользователя

#### 2. MFA Authentication Phase (Аутентификация MFA):
1. Пользователь генерирует TOTP токен в приложении
2. Отправляет S3 запрос с MFA токеном в заголовке
3. Gateway валидирует V4 подпись и проверяет требования MFA
4. MFA Middleware извлекает и валидирует MFA токен
5. При успехе - обработка запроса, при неудаче - ошибка

#### 3. Backup Code Usage (Использование backup кодов):
1. Пользователь отправляет запрос с backup кодом
2. TOTP валидация не проходит
3. Система пробует валидацию backup кода
4. При успехе - код удаляется из списка доступных
5. Обработка запроса с предупреждением об использовании backup кода

#### 4. Error Handling (Обработка ошибок):
1. Пользователь отправляет невалидный/просроченный токен
2. Система инкрементирует счетчик неудачных попыток
3. При превышении лимита - блокировка пользователя
4. Логирование всех событий безопасности
5. Возврат соответствующей ошибки клиенту

### 📝 Особенности безопасности
- Временная валидация токенов (30-секундные окна)
- Отслеживание неудачных попыток и блокировка пользователей
- Backup коды для экстренного доступа
- Комплексное аудирование
- Ограничение скорости и предотвращение злоупотреблений

---

## 6. MFA Deployment Diagram

**Файл:** `mfa_deployment_diagram.puml`

### 🎯 Назначение
Описывает физическую архитектуру системы MFA, показывая развертывание компонентов на различных узлах инфраструктуры.

### 🏗️ Узлы развертывания

#### 1. Клиентская среда:
**Мобильные устройства (iOS/Android):**
- **TOTP Authenticator** - Google Authenticator, Authy и др.

**Клиентские рабочие станции:**
- **S3 Client** - AWS CLI/SDK с поддержкой MFA токенов

#### 2. Сервер S3 Gateway:
**Go Runtime (Go 1.21+):**
- **Versity S3 Gateway** - Основное приложение с MFA
- **MFA Components** - MFA Service, Middleware, TOTP Generator, QR Generator

**Файловая система:**
- **MFA Data Store** - JSON файлы с правами доступа 0600
- **Configuration** - YAML/JSON конфигурации

#### 3. Внешние системы:
- **IAM Backend** - LDAP/Vault/Database для идентификации
- **Logging System** - Syslog/ELK для аудита
- **Metrics System** - Prometheus/Grafana для мониторинга

### 🔄 Сетевые взаимодействия
- **Клиенты → Gateway:** HTTPS запросы с MFA токенами (порт 443/8080)
- **TOTP App → QR Generator:** Сканирование QR кодов
- **Gateway → IAM:** Аутентификация пользователей
- **Gateway → Monitoring:** Логи и метрики

### 🔒 Границы безопасности
- **DMZ:** Публичный доступ через HTTPS
- **Internal Network:** Безопасные внутренние соединения

### 📝 Особенности безопасности
- Файлы с правами доступа 0600
- Шифрование секретов в покое
- Хешированные backup коды
- Изоляция пользовательских данных

---

## 7. MFA Integration Diagram

**Файл:** `mfa_integration_diagram.puml`

### 🎯 Назначение
Показывает интеграцию новой MFA системы с существующим S3 Gateway, обеспечивая обратную совместимость.

### 🏗️ Архитектурные слои

#### 1. Существующая система:
- **S3 API Server** - Существующий S3-совместимый API
- **V4 Authentication** - AWS V4 signature валидация
- **IAM Service** - Управление пользователями и ролями
- **S3 Controllers** - Обработчики S3 операций
- **Storage Backend** - Хранилище объектов

#### 2. Новая MFA система:
- **MFA Service** - Основная MFA функциональность
- **MFA Middleware** - Слой валидации MFA
- **Enhanced Authentication** - Интеграция V4 + MFA
- **MFA Storage** - Пользовательские MFA данные
- **MFA Admin API** - Конечные точки управления MFA

#### 3. Слой интеграции:
- **Context Manager** - Общие ключи контекста
- **Policy Engine** - Оценка требований MFA
- **Audit Integration** - Унифицированное логирование
- **Metrics Integration** - Объединенные метрики

### 🔄 Интеграционные взаимодействия
- **Enhanced Auth** заменяет V4 auth middleware
- **Enhanced Auth** делегирует стандартную V4 валидацию
- **Enhanced Auth** интегрируется с MFA Middleware
- **Policy Engine** запрашивает роли пользователей из IAM Service
- Унифицированное логирование и метрики

### 📝 Ключевые точки интеграции
- Обертывание существующей V4 аутентификации
- Добавление слоя MFA валидации
- Сохранение обратной совместимости
- Расширение потока аутентификации

### 🔒 Зоны совместимости
- **Backward Compatibility Zone:** V4 Auth, IAM Service, S3 Controllers
- **Enhanced Security Zone:** Enhanced Auth, MFA Middleware, MFA Service
- **Shared Infrastructure:** Context Manager, Audit Integration, Metrics

---

## 8. MFA Security Architecture

**Файл:** `mfa_security_architecture.puml`

### 🎯 Назначение
Детализирует все уровни безопасности MFA системы, показывая защитные механизмы и соответствие стандартам.

### 🏗️ Слои безопасности

#### 1. Слой аутентификации:
- **V4 Signature Validation** - Валидация V4 подписей
- **MFA Token Validation** - Валидация MFA токенов
- **Enhanced Authentication** - Расширенная аутентификация

#### 2. Основная безопасность MFA:
- **TOTP Generator** - TOTP генератор
- **Secret Generator** - Генератор секретов
- **Backup Code Manager** - Менеджер backup кодов
- **Lockout Manager** - Менеджер блокировок

#### 3. Безопасность данных:
- **Encrypted Storage** - Зашифрованное хранилище
- **Hashed Backup Codes** - Хешированные backup коды
- **File Permissions** - Права доступа к файлам (0600)
- **Atomic Operations** - Атомарные операции

#### 4. Принуждение политик:
- **Role-based MFA** - MFA на основе ролей
- **Operation-based MFA** - MFA на основе операций
- **User Exemptions** - Исключения пользователей
- **Grace Periods** - Льготные периоды

#### 5. Предотвращение атак:
- **Rate Limiting** - Ограничение скорости
- **User Lockout** - Блокировка пользователей
- **Time Window Validation** - Валидация временных окон
- **Replay Attack Prevention** - Предотвращение replay атак

#### 6. Аудит и мониторинг:
- **Security Logging** - Логирование безопасности
- **Failed Attempt Tracking** - Отслеживание неудачных попыток
- **Success Metrics** - Метрики успеха
- **Alert Generation** - Генерация оповещений

### 🌐 Внешняя безопасность:
- **TOTP Apps** - TOTP приложения (RFC 6238)
- **QR Code Security** - Безопасность QR кодов
- **Network Security** - Сетевая безопасность (HTTPS only)
- **IAM Integration** - Интеграция IAM

### 📋 Соответствие стандартам:
- **RFC 6238 TOTP** - Time-Based One-Time Password Algorithm
- **RFC 4226 HOTP** - HMAC-Based One-Time Password Algorithm
- **Crypto Standards** - crypto/rand для случайности
- **Security Best Practices** - Лучшие практики безопасного хранения

### 📝 Детальные заметки безопасности

#### V4 Signature Security:
- HMAC-SHA256 подписывание
- Валидация целостности запроса
- Проверка временных меток
- Валидация учетных данных

#### TOTP Security Features:
- Соответствие RFC 6238
- 30-секундные временные окна
- HMAC-SHA1 алгоритм
- Base32 кодирование секретов
- Допуск временного сдвига (±1 окно)

#### Cryptographic Security:
- crypto/rand для случайности
- 160-битные (20-байтные) секреты
- Base32 кодирование
- Безопасная деривация ключей

#### Data Protection:
- Права доступа к файлам 0600
- JSON сериализация
- Атомарные операции записи
- Изоляция пользовательских данных
- Хеширование backup кодов (SHA256)

#### Abuse Prevention:
- Отслеживание неудачных попыток
- Прогрессивные периоды блокировки
- Пользовательские ограничения скорости
- Автоматическая разблокировка по таймауту
- Возможности переопределения администратором

#### Audit Trail:
- Логирование всех MFA событий
- Отслеживание успехов/неудач
- Идентификация пользователей
- Запись временных меток
- Обнаружение инцидентов безопасности

### 🔒 Границы доверия
- **Trust Boundary:** Enhanced Auth, MFA Auth, Storage
- **External Trust:** TOTP Apps, IAM

---

## 🎯 Заключение

Все PlantUML диаграммы Task 2 представляют комплексную архитектурную документацию системы MFA, охватывающую:

### 📊 Уровни абстракции:
1. **Контекст** - Высокоуровневое представление
2. **Контейнеры** - Основные компоненты
3. **Компоненты** - Детальная структура
4. **Код** - Конкретные классы и интерфейсы

### 🔄 Поведенческие аспекты:
5. **Последовательность** - Жизненный цикл процессов
6. **Развертывание** - Физическая архитектура
7. **Интеграция** - Взаимодействие с существующей системой
8. **Безопасность** - Комплексная архитектура безопасности

### 🔧 Ключевые технологии:
- **Стандарты:** RFC 6238, RFC 4226
- **Технологии:** Go, Fiber, JSON, YAML
- **Безопасность:** crypto/rand, HMAC-SHA1, SHA256
- **Хранение:** Файловая система с правами 0600
- **Интеграция:** V4 signature + MFA validation

Данная документация обеспечивает полное понимание архитектуры MFA системы и служит основой для разработки, тестирования, развертывания и поддержки.