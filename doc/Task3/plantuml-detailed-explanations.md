# Подробные объяснения PlantUML диаграмм Task 3

Данный документ содержит детальные объяснения всех PlantUML диаграмм Enhanced RBAC системы Task 3.

## 📋 Список диаграмм

1. **[c4-context-diagram.puml](#1-context-diagram)** - Контекстная диаграмма
2. **[c4-container-diagram.puml](#2-container-diagram)** - Диаграмма контейнеров
3. **[c4-component-diagram.puml](#3-component-diagram)** - Диаграмма компонентов
4. **[c4-code-diagram.puml](#4-code-diagram)** - Диаграмма кода
5. **[sequence-diagram.puml](#5-sequence-diagram)** - Диаграмма последовательности
6. **[rbac-integration-diagram.puml](#6-integration-diagram)** - Диаграмма интеграции
7. **[rbac-deployment-diagram.puml](#7-deployment-diagram)** - Диаграмма развертывания
8. **[rbac-security-architecture.puml](#8-security-architecture)** - Архитектура безопасности

---

## 1. Context Diagram
**Файл:** `c4-context-diagram.puml`

### 🎯 Назначение
Показывает систему Enhanced RBAC на самом высоком уровне абстракции в контексте внешних пользователей и систем.

### 🏗️ Архитектурные элементы

#### Пользователи (Actors)
- **User**: Пользователь S3 API, запрашивающий доступ к ресурсам
- **Administrator**: Системный администратор, управляющий ролями и разрешениями

#### Основная система
- **VersityGW S3 Gateway**: Центральная система с Enhanced Authentication System
  - Обеспечивает role-based access control
  - Поддерживает иерархические разрешения

#### Внешние системы
- **S3 Backend**: Хранилище данных (AWS S3, MinIO, etc.)
- **IAM Service**: Внешняя система управления идентификацией
- **Monitoring System**: Система сбора логов и метрик

### 🔄 Взаимодействия
1. **User → Auth System**: HTTPS/S3 API запросы на доступ к ресурсам
2. **Admin → Auth System**: Admin API для управления ролями
3. **Auth System → S3 Backend**: Доступ к хранилищу после авторизации
4. **Auth System → IAM Service**: Валидация учетных данных пользователей
5. **Auth System → Monitoring**: Отправка аудит логов и метрик

### 💡 Ключевые особенности
- Четкое разделение ролей пользователей и администраторов
- Централизованная система аутентификации и авторизации
- Интеграция с внешними системами для полноценного функционирования
--
-

## 2. Container Diagram
**Файл:** `c4-container-diagram.puml`

### 🎯 Назначение
Детализирует внутреннюю структуру VersityGW S3 Gateway, показывая основные контейнеры и их взаимодействие в рамках Enhanced RBAC системы.

### 🏗️ Архитектурные элементы

#### Основные контейнеры
- **S3 API Gateway**: Go/Fiber сервер для обработки S3 API запросов
- **Authentication Middleware**: Go/Fiber middleware для перехвата и обработки запросов
- **Audit Logger**: Go компонент для логирования событий безопасности

#### Authentication & Authorization группа
- **Access Control Engine**: Основная логика проверки доступа с Enhanced RBAC
- **Role Manager**: Управление ролями, разрешениями и иерархиями
- **Permission Engine**: Оценка разрешений и агрегация
- **Enhanced Cache**: In-memory кэширование ролей и решений о доступе

#### Хранилище данных
- **Role Storage**: File System/Database для хранения определений ролей

### 🔄 Потоки данных
1. **User → S3 API**: HTTPS запросы
2. **Admin → Role Manager**: Admin API для управления ролями
3. **S3 API → Middleware**: Обработка запросов
4. **Middleware → Access Control**: Проверка доступа
5. **Access Control → Role Manager**: Получение ролей пользователя
6. **Access Control → Permission Engine**: Оценка разрешений
7. **Role Manager ↔ Cache**: Кэширование данных ролей
8. **Role Manager ↔ Storage**: Персистентное хранение

### 💡 Ключевые особенности
- Четкое разделение ответственности между контейнерами
- Централизованное кэширование для производительности
- Отдельный компонент для аудита безопасности
- Модульная архитектура для легкого расширения

---

## 3. Component Diagram
**Файл:** `c4-component-diagram.puml`

### 🎯 Назначение
Показывает детальную структуру компонентов внутри каждого контейнера Enhanced RBAC системы.

### 🏗️ Архитектурные элементы

#### Access Control Engine компоненты
- **VerifyAccess Function**: Главная точка входа для проверки доступа
- **EnhancedAccessChecker**: Комплексная проверка доступа с интеграцией ролей
- **AccessOptions**: Структура данных с контекстом запроса
- **ARN Builder**: Построение AWS ARN-идентификаторов ресурсов

#### Role Manager компоненты
- **RoleManager Interface**: Определяет операции управления ролями
- **InMemoryRoleManager**: In-memory реализация управления ролями
- **FileBasedRoleManager**: Файловая персистентная реализация
- **PermissionValidator**: Валидация консистентности ролей и разрешений

#### Permission Engine компоненты
- **EnhancedRole**: Роль с детальными разрешениями и иерархией
- **DetailedPermission**: Гранулярное разрешение с условиями
- **PermissionSet**: Агрегированные разрешения от множественных ролей
- **RoleAssignment**: Назначение роли пользователю с метаданными
- **ARN Pattern Matcher**: Сопоставление AWS ARN паттернов
- **Permission Aggregator**: Агрегация разрешений с union семантикой

#### Enhanced Cache компоненты
- **Cache Interface**: Определяет операции кэширования
- **LRU Cache**: Реализация Least Recently Used кэша
- **TTL Manager**: Управление временем жизни записей кэша
- **Invalidation Engine**: Обработка паттернов инвалидации кэша

### 🔄 Взаимодействия компонентов
1. **S3 API → VerifyAccess**: Проверка доступа пользователя
2. **VerifyAccess → EnhancedAccessChecker**: Использование расширенной проверки
3. **EnhancedAccessChecker → RoleManager**: Получение ролей пользователя
4. **RoleManager → InMemory/FileBased**: Реализация операций
5. **Permission Aggregator → PermissionSet**: Создание агрегированных разрешений
6. **Pattern Matcher → DetailedPermission**: Сопоставление ресурсов
7. **Cache Interface → LRU Cache**: Хранение в кэше

### 💡 Ключевые особенности
- Интерфейсы для гибкости реализации
- Модульная структура для тестирования
- Специализированные компоненты для каждой задачи
- Эффективное кэширование с различными стратегиями---


## 4. Code Diagram
**Файл:** `c4-code-diagram.puml`

### 🎯 Назначение
Представляет структуру классов, интерфейсов и их взаимосвязи на уровне кода Enhanced RBAC системы.

### 🏗️ Архитектурные элементы

#### Основные структуры данных
- **AccessOptions**: Контекст запроса с параметрами доступа
  - Содержит ACL, разрешения, информацию о пользователе
  - Включает RoleManager для Enhanced RBAC

- **EnhancedRole**: Роль с детальными разрешениями
  - ID, Name, Description для идентификации
  - Permissions массив для детальных разрешений
  - ParentRoles для поддержки иерархии
  - Методы Validate() и HasPermission()

- **DetailedPermission**: Гранулярное разрешение
  - Resource, Action, Effect для определения доступа
  - Conditions для контекстных ограничений
  - Методы сопоставления ресурсов и действий

#### Интерфейсы и реализации
- **RoleManager Interface**: Определяет все операции с ролями
  - CRUD операции для ролей
  - Назначение/отзыв ролей пользователям
  - Вычисление эффективных разрешений

- **InMemoryRoleManager**: In-memory реализация
  - Использует maps для хранения ролей и назначений
  - RWMutex для thread-safety
  - PermissionValidator для валидации

- **FileBasedRoleManager**: Файловая реализация
  - Расширяет InMemoryRoleManager
  - Добавляет персистентность через файловую систему

#### Утилитарные компоненты
- **EnhancedAccessChecker**: Удобный интерфейс для проверки доступа
- **PermissionValidator**: Валидация наборов разрешений
- **PatternMatcher**: Сопоставление AWS ARN паттернов
- **PermissionAggregator**: Агрегация разрешений с union семантикой

### 🔄 Отношения между классами
1. **VerifyAccess → AccessOptions**: Использует для контекста
2. **AccessOptions → RoleManager**: Содержит ссылку на менеджер ролей
3. **RoleManager ← InMemory/FileBased**: Реализации интерфейса
4. **EnhancedRole → DetailedPermission**: Композиция разрешений
5. **DetailedPermission → PermissionEffect**: Использует enum
6. **PermissionAggregator → PermissionSet**: Создает агрегированные разрешения

### 💡 Ключевые особенности
- Четкое разделение интерфейсов и реализаций
- Композиция для гибкости структур данных
- Утилитарные классы для специализированных операций
- Thread-safe реализации с использованием мьютексов

---

## 5. Sequence Diagram
**Файл:** `sequence-diagram.puml`

### 🎯 Назначение
Показывает временную последовательность взаимодействий при проверке доступа с Enhanced RBAC системой.

### 🏗️ Участники последовательности
- **User**: Пользователь, отправляющий S3 запрос
- **S3 API**: API сервер для обработки запросов
- **Auth Middleware**: Middleware для аутентификации
- **VerifyAccess**: Функция проверки доступа
- **RoleManager**: Менеджер ролей
- **PermissionEngine**: Движок разрешений
- **Cache**: Система кэширования
- **S3 Backend**: Хранилище данных

### 🔄 Поток выполнения

#### Фаза 1: Инициация запроса
1. **User → S3 API**: GET /bucket/object запрос
2. **S3 API → Middleware**: Обработка запроса
3. **Middleware → VerifyAccess**: Вызов проверки доступа

#### Фаза 2: Базовые проверки
4. **VerifyAccess**: Проверка публичного bucket
5. **VerifyAccess**: Проверка root пользователя
6. **VerifyAccess**: Проверка admin роли

#### Фаза 3: Enhanced RBAC (при необходимости)
7. **VerifyAccess → RoleManager**: GetEffectivePermissions(userID)
8. **RoleManager → Cache**: Попытка получить из кэша
9. **Cache → RoleManager**: Cache miss
10. **RoleManager**: GetUserRoles(userID)
11. **RoleManager**: expandRoleHierarchy(roles)
12. **RoleManager → PermissionEngine**: ComputeEffectivePermissions
13. **PermissionEngine**: Сбор всех разрешений
14. **PermissionEngine**: resolvePermissionConflicts()
15. **PermissionEngine → RoleManager**: PermissionSet
16. **RoleManager → Cache**: Сохранение в кэш с TTL

#### Фаза 4: Проверка разрешений
17. **VerifyAccess**: buildResourceARN(bucket, object)
18. **VerifyAccess → PermissionEngine**: HasPermission(resource, action)
19. **PermissionEngine**: matchesARNPattern(pattern, resource)
20. **PermissionEngine → VerifyAccess**: allowed/denied

#### Фаза 5: Fallback (при необходимости)
21. **VerifyAccess → Backend**: GetBucketPolicy(bucket)
22. **VerifyAccess**: VerifyBucketPolicy()
23. **VerifyAccess**: verifyACL()

#### Фаза 6: Выполнение запроса
24. **Middleware → Backend**: Forward Request (если разрешено)
25. **Backend → User**: HTTP Response

### 💡 Ключевые особенности
- Многоуровневая проверка доступа
- Кэширование для оптимизации производительности
- Fallback к традиционным методам
- Поддержка иерархии ролей и агрегации разрешений-
--

## 6. Integration Diagram
**Файл:** `rbac-integration-diagram.puml`

### 🎯 Назначение
Показывает интеграцию Enhanced RBAC системы с существующими компонентами S3 Gateway.

### 🏗️ Архитектурные границы

#### Existing S3 Gateway System
- **S3 API Server**: Существующие S3 API endpoints
- **Authentication Middleware**: V4 signature аутентификация
- **IAM Service**: Существующее управление идентификацией
- **Bucket Policy Engine**: Традиционные bucket-level политики
- **ACL Engine**: Традиционные object-level ACL

#### Enhanced RBAC System (Task 3)
- **Enhanced Role Manager**: Управление ролями с детальными разрешениями
- **Enhanced Access Control**: Проверка доступа с агрегацией ролей
- **Permission Engine**: Оценка детальных разрешений
- **RBAC Cache**: Кэширование разрешений ролей

#### Integration Layer
- **Enhanced VerifyAccess**: Модифицированная проверка доступа с RBAC
- **Context Manager**: Управление контекстом запроса с информацией о ролях
- **Policy Resolver**: Разрешение конфликтов между RBAC и традиционными политиками
- **Enhanced Audit Logger**: Логирование решений RBAC о доступе

#### Backward Compatibility
- **Fallback Handler**: Откат к традиционному контролю доступа
- **Migration Service**: Миграция традиционных политик в RBAC
- **Compatibility Layer**: Обеспечение работы существующих API

#### Extended Security Features
- **Deny Override Engine**: Приоритет запрещающих разрешений
- **Role Hierarchy Resolver**: Разрешение наследования ролей
- **Permission Aggregator**: Объединение разрешений от множественных ролей

### 🔄 Интеграционные потоки
1. **Клиенты → S3 API**: Существующие S3 API запросы
2. **Администраторы → Role Manager**: Управление ролями
3. **Auth Middleware → Enhanced VerifyAccess**: Расширенная проверка доступа
4. **Enhanced VerifyAccess → Role Manager**: Получение ролей пользователя
5. **Access Control → Permission Engine**: Оценка разрешений
6. **Enhanced VerifyAccess → Fallback Handler**: Откат при ошибках
7. **Fallback Handler → Bucket Policy/ACL**: Традиционные методы

### 💡 Ключевые особенности интеграции
- **Бесшовная интеграция**: Минимальные изменения в существующем коде
- **Обратная совместимость**: Поддержка существующих API и политик
- **Graceful degradation**: Откат к традиционным методам при ошибках
- **Миграционная поддержка**: Инструменты для перехода на RBAC

---

## 7. Deployment Diagram
**Файл:** `rbac-deployment-diagram.puml`

### 🎯 Назначение
Описывает физическое развертывание Enhanced RBAC системы в производственной среде.

### 🏗️ Deployment узлы

#### Client Environment
- **Developer Workstation**: Linux/macOS/Windows
  - AWS S3 SDK для различных языков программирования
  - RBAC Admin CLI для управления ролями
- **Mobile Device**: iOS/Android
  - Mobile S3 приложения

#### S3 Gateway Cluster
- **Gateway Node 1 & 2**: Linux контейнеры
  - S3 API Server (Go/Fiber)
  - RBAC Engine для Enhanced role-based access control
  - Role Cache для in-memory кэширования разрешений
- **Load Balancer**: NGINX/HAProxy
  - Распределение запросов между узлами gateway

#### Storage Tier
- **Role Storage**: File System/Database
  - Role Database (JSON Files/SQLite)
  - Audit Logs для RBAC решений о доступе
- **Object Storage**: Backend Storage
  - S3 Backend (MinIO/AWS S3/GCS)

#### External Systems
- **IAM Provider**: LDAP/AD/OAuth для аутентификации
- **Monitoring System**: Prometheus/Grafana для RBAC метрик
- **Alerting System**: Alert manager для security events

#### DMZ (Demilitarized Zone)
- **Reverse Proxy**: NGINX/Cloudflare
  - SSL Termination и HTTPS безопасность

### 🔄 Сетевые соединения
1. **Клиенты → SSL Termination**: HTTPS S3 API вызовы (TLS 1.3)
2. **SSL Termination → Load Balancer**: HTTP (внутренний)
3. **Load Balancer → Gateway Nodes**: HTTP распределение
4. **Gateway Nodes → RBAC Engine**: Локальные вызовы (in-process)
5. **RBAC Engine → Role Storage**: File I/O для персистентности
6. **RBAC Engine → External Systems**: Аутентификация и мониторинг
7. **Role Cache 1 ↔ Role Cache 2**: Синхронизация кэша

### 💡 Ключевые особенности развертывания
- **Высокая доступность**: Множественные gateway узлы
- **Балансировка нагрузки**: Распределение запросов
- **Персистентное хранение**: Роли, разрешения, аудит логи
- **Безопасность периметра**: SSL/TLS, DDoS защита, WAF
- **Внешняя интеграция**: IAM, мониторинг, алертинг

---

## 8. Security Architecture
**Файл:** `rbac-security-architecture.puml`

### 🎯 Назначение
Детализирует многоуровневую архитектуру безопасности Enhanced RBAC системы.

### 🏗️ Слои безопасности

#### Authentication Layer
- **V4 Signature Validation**: Проверка AWS подписей
- **IAM Integration**: Интеграция с системами идентификации
- **MFA Validation**: Проверка многофакторной аутентификации
- **Session Management**: Управление пользовательскими сессиями

#### Enhanced RBAC Core Security
- **Role Validation**: Валидация ролей и их структуры
- **Permission Evaluation**: Оценка разрешений с контекстом
- **Hierarchy Resolution**: Разрешение иерархии ролей
- **Deny Override Engine**: Приоритет запрещающих разрешений
- **Permission Aggregation**: Агрегация разрешений с union семантикой

#### Data Security
- **Role Data Encryption**: Шифрование данных ролей
- **Permission Hashing**: Хеширование чувствительных данных
- **Secure Storage**: Безопасное хранение с правами доступа
- **Access Control Lists**: Файловые разрешения (0600)

#### Attack Prevention
- **Rate Limiting**: Ограничение частоты запросов
- **Input Validation**: Валидация всех входных данных
- **SQL Injection Prevention**: Защита от SQL инъекций
- **Path Traversal Protection**: Защита от path traversal атак
- **Privilege Escalation Prevention**: Предотвращение эскалации привилегий

#### Audit and Monitoring
- **Security Event Logging**: Логирование событий безопасности
- **Access Decision Audit**: Аудит решений о доступе
- **Role Change Tracking**: Отслеживание изменений ролей
- **Anomaly Detection**: Обнаружение аномальной активности
- **Compliance Reporting**: Отчеты для соответствия стандартам

#### Standards Compliance
- **RBAC Standard (NIST)**: Соответствие NIST RBAC модели
- **AWS IAM Compatibility**: Совместимость с AWS IAM
- **GDPR Compliance**: Соответствие требованиям защиты данных
- **SOC 2 Controls**: Контроли безопасности SOC 2

### 🛡️ Политики безопасности

#### Access Control Policies
- **Deny by Default**: Запрет по умолчанию
- **Explicit Allow Required**: Требование явных разрешений
- **Deny Override Allow**: Приоритет запрещающих разрешений
- **Least Privilege Principle**: Принцип минимальных привилегий

#### Role Management Policies
- **Role Separation**: Разделение ролей
- **Hierarchy Validation**: Валидация структуры иерархии
- **Circular Reference Prevention**: Предотвращение циклических ссылок
- **Role Assignment Approval**: Утверждение назначения ролей

#### Data Protection Policies
- **Encryption at Rest**: Шифрование данных в покое
- **Encryption in Transit**: Шифрование данных в передаче
- **Key Management**: Управление ключами шифрования
- **Data Retention**: Политики хранения данных

### 🚨 Защита от угроз

#### Common Attacks
- **Privilege Escalation**: Эскалация привилегий
- **Role Mining**: Исследование ролей
- **Permission Enumeration**: Перечисление разрешений
- **Session Hijacking**: Перехват сессий
- **Insider Threats**: Внутренние угрозы

#### Mitigation Strategies
- **Multi-Factor Authentication**: Многофакторная аутентификация
- **Regular Access Reviews**: Регулярные проверки доступа
- **Automated Deprovisioning**: Автоматическое отзыв доступа
- **Behavioral Analytics**: Поведенческая аналитика
- **Zero Trust Model**: Модель нулевого доверия

### 💡 Ключевые принципы безопасности
- **Defense in Depth**: Многоуровневая защита
- **Fail-Secure Design**: Безопасное поведение при сбоях
- **Comprehensive Monitoring**: Всеобъемлющий мониторинг
- **Standards Compliance**: Соответствие стандартам безопасности

---

## 🎯 Заключение

Все PlantUML диаграммы Task 3 представляют комплексную архитектурную документацию системы Enhanced RBAC, охватывающую:

### 📊 Уровни абстракции:
- **Context**: Система в контексте пользователей и внешних систем
- **Container**: Внутренняя структура с основными компонентами
- **Component**: Детальная структура компонентов и их взаимодействие
- **Code**: Классы, интерфейсы и структуры данных

### 🔄 Поведенческие аспекты:
- **Sequence**: Временные последовательности взаимодействий
- **Integration**: Интеграция с существующими системами

### 🚀 Операционные аспекты:
- **Deployment**: Физическое развертывание в производственной среде
- **Security**: Многоуровневая архитектура безопасности

Каждая диаграмма дополняет другие, создавая полную картину архитектуры Enhanced RBAC системы Task 3.