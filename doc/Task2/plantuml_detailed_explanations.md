# Подробные объяснения PlantUML диаграмм Task 2

Данный документ содержит детальные объяснения всех PlantUML диаграмм MFA системы Task 2.

## 📋 Список диаграмм

1. [C4 Context Diagram](#1-c4-context-diagram)
2. [C4 Container Diagram](#2-c4-container-diagram)  
3. [C4 Component Diagram](#3-c4-component-diagram)
4. [C4 Code Diagram](#4-c4-code-diagram)
5. [MFA Sequence Diagram](#5-mfa-sequence-diagram)
6. [MFA Deployment Diagram](#6-mfa-deployment-diagram)
7. [MFA Integration Diagram](#7-mfa-integration-diagram)
8. [MFA Security Architecture](#8-mfa-security-architecture)

---

## 1. C4 Context Diagram

**Файл:** `c4_context_diagram.puml`

### 🎯 Назначение
Контекстная диаграмма показывает систему Versity S3 Gateway с MFA на самом высоком уровне абстракции.

### 🏗️ Основные элементы

#### Участники (Persons):
- **S3 API User** - Разработчик или приложение, использующее S3 API с MFA
- **System Administrator** - Администратор, управляющий MFA политиками

#### Центральная система:
- **Versity S3 Gateway** - S3-совместимый API gateway с поддержкой MFA

#### Внешние системы:
- **TOTP Authenticator** - Мобильные приложения аутентификации
- **IAM Backend** - Система управления идентификацией
- **S3 Client Applications** - AWS CLI, SDK или пользовательские приложения
- **Monitoring System** - Система логирования и метрик

### 🔄 Ключевые взаимодействия
- Пользователи отправляют S3 запросы с MFA токенами через HTTPS
- Gateway взаимодействует с IAM для аутентификации пользователей
- Система предоставляет QR коды для настройки TOTP приложений

---

## 2. C4 Container Diagram

**Файл:** `c4_container_diagram.puml`

### 🎯 Назначение
Детализирует внутреннюю структуру S3 Gateway системы, показывая основные контейнеры.

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

---

Продолжение следует в следующих частях файла...##
 3. C4 Component Diagram

**Файл:** `c4_component_diagram.puml`

### 🎯 Назначение
Показывает детальную внутреннюю структуру MFA Service Container.

### 🏗️ Компонентная архитектура

#### 1. Интерфейсы сервисов:
- **MFAService** - Контракт основных MFA операций
- **MFAStorage** - Контракт персистентности данных

#### 2. Основные реализации:
- **MFAServiceImpl** - Главная реализация MFA сервиса
- **TOTPGenerator** - RFC 6238 TOTP реализация
- **QRCodeGenerator** - Генерация QR кодов

#### 3. Компоненты безопасности:
- **LockoutManager** - Блокировка и ограничение скорости
- **BackupCodeManager** - Генерация и валидация backup кодов
- **SecretGenerator** - Криптографически безопасная генерация

---

## 4. C4 Code Diagram

**Файл:** `c4_code_diagram.puml`

### 🎯 Назначение
Представляет самый детальный уровень архитектуры с конкретными классами.

### 🏗️ Структура кода

#### 1. Основные интерфейсы:
- **MFAService** - `GenerateSecret()`, `ValidateTOTP()`, `EnableMFA()`
- **MFAStorage** - `StoreMFAData()`, `GetMFAData()`, `DeleteMFAData()`

#### 2. Модели данных:
- **MFASecret** - `Secret`, `QRCode`, `BackupCodes`, `Issuer`
- **MFAStatus** - `Enabled`, `LastUsed`, `BackupCodesRemaining`
- **MFAConfig** - `Required`, `TOTPWindow`, `BackupCodes`

#### 3. Middleware классы:
- **MFAMiddleware** - `VerifyMFA()`, `RequireMFA()`, `extractMFAToken()`
- **EnhancedAuthMiddleware** - Интеграция V4 signature + MFA

---

## 5. MFA Sequence Diagram

**Файл:** `mfa_sequence_diagram.puml`

### 🎯 Назначение
Показывает полный жизненный цикл MFA системы через временные последовательности.

### 🔄 Основные сценарии

#### 1. MFA Setup Phase:
1. Пользователь запрашивает настройку MFA
2. Gateway аутентифицирует пользователя через V4 подпись
3. MFA Service генерирует секрет и backup коды
4. Возвращается QR код и backup коды
5. Пользователь сканирует QR код в TOTP приложении

#### 2. MFA Authentication Phase:
1. Пользователь генерирует TOTP токен в приложении
2. Отправляет S3 запрос с MFA токеном в заголовке
3. Gateway валидирует V4 подпись и проверяет требования MFA
4. MFA Middleware извлекает и валидирует MFA токен

#### 3. Backup Code Usage:
1. Пользователь отправляет запрос с backup кодом
2. TOTP валидация не проходит
3. Система пробует валидацию backup кода
4. При успехе - код удаляется из списка доступных

---

## 6. MFA Deployment Diagram

**Файл:** `mfa_deployment_diagram.puml`

### 🎯 Назначение
Описывает физическую архитектуру системы MFA на различных узлах инфраструктуры.

### 🏗️ Узлы развертывания

#### 1. Клиентская среда:
- **Мобильные устройства:** TOTP Authenticator приложения
- **Рабочие станции:** S3 Client с поддержкой MFA токенов

#### 2. Сервер S3 Gateway:
- **Go Runtime:** Versity S3 Gateway с MFA компонентами
- **Файловая система:** MFA Data Store с правами доступа 0600

#### 3. Внешние системы:
- **IAM Backend:** LDAP/Vault/Database для идентификации
- **Logging System:** Syslog/ELK для аудита
- **Metrics System:** Prometheus/Grafana для мониторинга

---

## 7. MFA Integration Diagram

**Файл:** `mfa_integration_diagram.puml`

### 🎯 Назначение
Показывает интеграцию новой MFA системы с существующим S3 Gateway.

### 🏗️ Архитектурные слои

#### 1. Существующая система:
- **S3 API Server** - Существующий S3-совместимый API
- **V4 Authentication** - AWS V4 signature валидация
- **IAM Service** - Управление пользователями и ролями

#### 2. Новая MFA система:
- **MFA Service** - Основная MFA функциональность
- **MFA Middleware** - Слой валидации MFA
- **Enhanced Authentication** - Интеграция V4 + MFA

#### 3. Слой интеграции:
- **Context Manager** - Общие ключи контекста
- **Policy Engine** - Оценка требований MFA
- **Audit Integration** - Унифицированное логирование

---

## 8. MFA Security Architecture

**Файл:** `mfa_security_architecture.puml`

### 🎯 Назначение
Детализирует все уровни безопасности MFA системы.

### 🏗️ Слои безопасности

#### 1. Слой аутентификации:
- **V4 Signature Validation** - Валидация V4 подписей
- **MFA Token Validation** - Валидация MFA токенов
- **Enhanced Authentication** - Расширенная аутентификация

#### 2. Основная безопасность MFA:
- **TOTP Generator** - TOTP генератор
- **Secret Generator** - Генератор секретов
- **Backup Code Manager** - Менеджер backup кодов

#### 3. Предотвращение атак:
- **Rate Limiting** - Ограничение скорости
- **User Lockout** - Блокировка пользователей
- **Time Window Validation** - Валидация временных окон
- **Replay Attack Prevention** - Предотвращение replay атак

### 📋 Соответствие стандартам:
- **RFC 6238 TOTP** - Time-Based One-Time Password Algorithm
- **RFC 4226 HOTP** - HMAC-Based One-Time Password Algorithm
- **Crypto Standards** - crypto/rand для случайности

---

## 🎯 Заключение

Все PlantUML диаграммы Task 2 представляют комплексную архитектурную документацию системы MFA, охватывающую все уровни от высокоуровневого контекста до деталей реализации и обеспечения безопасности.