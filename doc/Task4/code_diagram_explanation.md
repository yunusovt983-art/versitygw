# Объяснение Code Diagram (c4_architecture_code.puml)

## Назначение диаграммы

Code Diagram представляет четвертый и самый детальный уровень модели C4, показывающий конкретные структуры данных, интерфейсы, классы и их взаимосвязи в реализации Security Event Manager. Эта диаграмма служит мостом между архитектурным дизайном и фактической реализацией кода.

## Структура PlantUML файла

### Заголовок и импорты
```plantuml
@startuml Task4_Security_System_Code
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Component.puml

title Code Diagram - Security Event Manager Implementation (Task 4)
```

**Объяснение:**
- Использование C4_Component.puml для представления элементов кода
- Фокус на детальной реализации Security Event Manager

## Основные структуры данных

### SecurityEvent - Ядро системы событий
```plantuml
Component(security_event, "SecurityEvent", "Go Struct", "Core security event data structure")
```

**Детальная структура:**
```go
type SecurityEvent struct {
    ID          string                 `json:"id"`
    Type        SecurityEventType      `json:"type"`
    Severity    SecuritySeverity       `json:"severity"`
    Timestamp   time.Time              `json:"timestamp"`
    UserID      string                 `json:"user_id,omitempty"`
    IPAddress   string                 `json:"ip_address,omitempty"`
    UserAgent   string                 `json:"user_agent,omitempty"`
    Success     bool                   `json:"success"`
    Message     string                 `json:"message"`
    Details     map[string]interface{} `json:"details,omitempty"`
    RequestID   string                 `json:"request_id,omitempty"`
    SessionID   string                 `json:"session_id,omitempty"`
    MFAUsed     bool                   `json:"mfa_used,omitempty"`
    Provider    string                 `json:"provider,omitempty"`
    Resource    string                 `json:"resource,omitempty"`
    Action      string                 `json:"action,omitempty"`
}
```

**Архитектурные особенности:**
- **Универсальность** - подходит для всех типов событий безопасности
- **Расширяемость** - поле Details для дополнительных данных
- **JSON сериализация** - для хранения и передачи данных
- **Опциональные поля** - гибкость для различных сценариев

**Валидация данных:**
```go
func (e *SecurityEvent) Validate() error {
    if e.ID == "" {
        return errors.New("event ID is required")
    }
    if e.Type == "" {
        return errors.New("event type is required")
    }
    if e.Timestamp.IsZero() {
        e.Timestamp = time.Now()
    }
    return nil
}
```

### SecurityEventType - Типизированные константы
```plantuml
Component(event_type, "SecurityEventType", "Go Const", "Enumeration of security event types")
```

**Полное определение:**
```go
type SecurityEventType string

const (
    // Authentication events
    EventTypeAuthAttempt     SecurityEventType = "auth_attempt"
    EventTypeAuthSuccess     SecurityEventType = "auth_success"
    EventTypeAuthFailure     SecurityEventType = "auth_failure"
    
    // MFA events
    EventTypeMFAAttempt      SecurityEventType = "mfa_attempt"
    EventTypeMFASuccess      SecurityEventType = "mfa_success"
    EventTypeMFAFailure      SecurityEventType = "mfa_failure"
    
    // User management events
    EventTypeUserLocked      SecurityEventType = "user_locked"
    EventTypeUserUnlocked    SecurityEventType = "user_unlocked"
    
    // Security events
    EventTypeSuspiciousActivity SecurityEventType = "suspicious_activity"
    EventTypeSessionCreated  SecurityEventType = "session_created"
    EventTypeSessionExpired  SecurityEventType = "session_expired"
    EventTypePermissionDenied SecurityEventType = "permission_denied"
)
```

**Преимущества типизации:**
- **Типобезопасность** - предотвращение ошибок времени выполнения
- **Автодополнение** - поддержка IDE
- **Рефакторинг** - безопасное переименование
- **Документирование** - самодокументируемый код

### SecuritySeverity - Уровни серьезности
```plantuml
Component(severity_level, "SecuritySeverity", "Go Const", "Security severity levels")
```

**Определение уровней:**
```go
type SecuritySeverity string

const (
    SeverityLow      SecuritySeverity = "low"      // Информационные события
    SeverityMedium   SecuritySeverity = "medium"   // Подозрительная активность
    SeverityHigh     SecuritySeverity = "high"     // Вероятные атаки
    SeverityCritical SecuritySeverity = "critical" // Активные атаки
)
```

**Использование в системе:**
```go
func (s SecuritySeverity) Priority() int {
    switch s {
    case SeverityLow:
        return 1
    case SeverityMedium:
        return 2
    case SeverityHigh:
        return 3
    case SeverityCritical:
        return 4
    default:
        return 0
    }
}
```

## Основные интерфейсы и реализации

### SecurityAuditLogger - Главный интерфейс
```plantuml
Component(audit_logger_impl, "SecurityAuditLogger", "Go Struct", "Main audit logger implementation")
```

**Интерфейс:**
```go
type SecurityAuditLogger interface {
    LogSecurityEvent(event *SecurityEvent) error
    LogAuthenticationAttempt(userID, ipAddress, userAgent string, success bool, details *AuthenticationDetails) error
    LogMFAAttempt(userID, ipAddress string, success bool, details map[string]interface{}) error
    LogSuspiciousActivity(pattern *SuspiciousPattern) error
    LogUserLockout(userID, reason string, duration time.Duration) error
    LogPermissionDenied(userID, resource, action, reason string) error
    GetSecurityEvents(filter *SecurityEventFilter) ([]*SecurityEvent, error)
    Close() error
}
```

**Конкретная реализация:**
```go
type SecurityAuditLoggerImpl struct {
    mu       sync.RWMutex
    events   []*SecurityEvent
    detector *SuspiciousActivityDetector
    config   *SecurityAuditConfig
}

func (s *SecurityAuditLoggerImpl) LogSecurityEvent(event *SecurityEvent) error {
    if err := event.Validate(); err != nil {
        return fmt.Errorf("invalid event: %w", err)
    }
    
    s.mu.Lock()
    defer s.mu.Unlock()
    
    // Generate ID if not provided
    if event.ID == "" {
        event.ID = generateEventID()
    }
    
    // Set timestamp if not provided
    if event.Timestamp.IsZero() {
        event.Timestamp = time.Now()
    }
    
    // Add event to storage
    s.events = append(s.events, event)
    
    // Cleanup old events if needed
    s.cleanupOldEvents()
    
    // Trigger pattern detection if enabled
    if s.detector != nil {
        go s.detector.AnalyzeEvent(event)
    }
    
    return nil
}
```

### EventValidator - Интерфейс валидации
```plantuml
Component(event_validator, "EventValidator", "Go Interface", "Validates security event data")
```

**Интерфейс валидации:**
```go
type EventValidator interface {
    ValidateEvent(event *SecurityEvent) error
    ValidateEventType(eventType SecurityEventType) bool
    ValidateUserID(userID string) bool
    ValidateSeverity(severity SecuritySeverity) bool
}
```

**Реализация валидатора:**
```go
type DefaultEventValidator struct {
    allowedEventTypes map[SecurityEventType]bool
    userIDPattern     *regexp.Regexp
}

func (v *DefaultEventValidator) ValidateEvent(event *SecurityEvent) error {
    if event == nil {
        return errors.New("event cannot be nil")
    }
    
    if !v.ValidateEventType(event.Type) {
        return fmt.Errorf("invalid event type: %s", event.Type)
    }
    
    if event.UserID != "" && !v.ValidateUserID(event.UserID) {
        return fmt.Errorf("invalid user ID format: %s", event.UserID)
    }
    
    if !v.ValidateSeverity(event.Severity) {
        return fmt.Errorf("invalid severity level: %s", event.Severity)
    }
    
    return nil
}
```

### PatternDetector - Интерфейс обнаружения паттернов
```plantuml
Component(pattern_detector, "PatternDetector", "Go Interface", "Detects suspicious patterns")
```

**Интерфейс детектора:**
```go
type PatternDetector interface {
    AnalyzeEvent(event *SecurityEvent) (*ThreatPattern, error)
    DetectAnomalies(events []*SecurityEvent) ([]*Anomaly, error)
    UpdatePatterns(patterns []*ThreatPattern) error
    GetDetectionStats() *DetectionStats
}
```

**Структуры для анализа:**
```go
type ThreatPattern struct {
    ID          string                 `json:"id"`
    Type        string                 `json:"type"`
    Description string                 `json:"description"`
    Severity    SecuritySeverity       `json:"severity"`
    Confidence  float64                `json:"confidence"`
    Events      []*SecurityEvent       `json:"events"`
    Metadata    map[string]interface{} `json:"metadata"`
}

type Anomaly struct {
    ID          string           `json:"id"`
    Type        string           `json:"type"`
    Score       float64          `json:"score"`
    Description string           `json:"description"`
    Event       *SecurityEvent   `json:"event"`
    Context     *AnomalyContext  `json:"context"`
}
```

## Слой хранения данных

### EventStorage - Абстрактный интерфейс хранения
```plantuml
Component(event_storage, "EventStorage", "Go Interface", "Abstract event storage interface")
```

**Интерфейс хранения:**
```go
type EventStorage interface {
    Store(event *SecurityEvent) error
    Get(id string) (*SecurityEvent, error)
    Query(filter *EventFilter) ([]*SecurityEvent, error)
    Delete(id string) error
    Count() (int64, error)
    Close() error
}
```

### MemoryEventStorage - Хранение в памяти
```plantuml
Component(memory_storage, "MemoryEventStorage", "Go Struct", "In-memory event storage implementation")
```

**Реализация в памяти:**
```go
type MemoryEventStorage struct {
    mu       sync.RWMutex
    events   map[string]*SecurityEvent
    indexes  map[string]*Index
    maxSize  int
    eviction *LRUEviction
}

func (m *MemoryEventStorage) Store(event *SecurityEvent) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    // Check capacity
    if len(m.events) >= m.maxSize {
        if err := m.eviction.Evict(); err != nil {
            return fmt.Errorf("failed to evict old events: %w", err)
        }
    }
    
    // Store event
    m.events[event.ID] = event
    
    // Update indexes
    m.updateIndexes(event)
    
    return nil
}

func (m *MemoryEventStorage) Query(filter *EventFilter) ([]*SecurityEvent, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    var results []*SecurityEvent
    
    for _, event := range m.events {
        if m.matchesFilter(event, filter) {
            results = append(results, event)
        }
    }
    
    return results, nil
}
```

### FileEventStorage - Файловое хранение
```plantuml
Component(file_storage, "FileEventStorage", "Go Struct", "File-based event storage implementation")
```

**Реализация файлового хранения:**
```go
type FileEventStorage struct {
    mu          sync.RWMutex
    basePath    string
    compression bool
    rotation    *FileRotation
    indexes     *FileIndexes
}

func (f *FileEventStorage) Store(event *SecurityEvent) error {
    f.mu.Lock()
    defer f.mu.Unlock()
    
    // Determine file path based on event timestamp
    filePath := f.getFilePath(event.Timestamp, event.Type)
    
    // Ensure directory exists
    if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
        return fmt.Errorf("failed to create directory: %w", err)
    }
    
    // Open file for appending
    file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        return fmt.Errorf("failed to open file: %w", err)
    }
    defer file.Close()
    
    // Serialize event to JSON
    data, err := json.Marshal(event)
    if err != nil {
        return fmt.Errorf("failed to marshal event: %w", err)
    }
    
    // Write to file
    if _, err := file.Write(append(data, '\n')); err != nil {
        return fmt.Errorf("failed to write event: %w", err)
    }
    
    // Update indexes
    f.indexes.Update(event)
    
    // Check for rotation
    f.rotation.CheckRotation(filePath)
    
    return nil
}
```

## Слой анализа данных

### RiskCalculator - Расчет рисков
```plantuml
Component(risk_calculator, "RiskCalculator", "Go Struct", "Calculates security risk scores")
```

**Реализация калькулятора рисков:**
```go
type RiskCalculator struct {
    config     *RiskConfig
    weights    map[string]float64
    baselines  map[string]float64
    history    *RiskHistory
}

func (r *RiskCalculator) CalculateRisk(event *SecurityEvent) (int, error) {
    score := 0.0
    
    // Base score by event type
    if baseScore, exists := r.baselines[string(event.Type)]; exists {
        score += baseScore
    }
    
    // Time-based factors
    score += r.calculateTimeRisk(event.Timestamp)
    
    // Frequency-based factors
    score += r.calculateFrequencyRisk(event.UserID, event.IPAddress)
    
    // Geographic factors
    if event.IPAddress != "" {
        score += r.calculateGeoRisk(event.IPAddress)
    }
    
    // User behavior factors
    score += r.calculateBehaviorRisk(event.UserID, event)
    
    // Normalize to 0-100 scale
    normalizedScore := int(math.Min(100, math.Max(0, score)))
    
    return normalizedScore, nil
}

func (r *RiskCalculator) calculateTimeRisk(timestamp time.Time) float64 {
    hour := timestamp.Hour()
    
    // Higher risk for off-hours access
    if hour < 6 || hour > 22 {
        return r.weights["off_hours"] * 20.0
    }
    
    // Weekend access
    if timestamp.Weekday() == time.Saturday || timestamp.Weekday() == time.Sunday {
        return r.weights["weekend"] * 10.0
    }
    
    return 0.0
}
```

### ThreatAnalyzer - Анализ угроз
```plantuml
Component(threat_analyzer, "ThreatAnalyzer", "Go Struct", "Analyzes threats and attack patterns")
```

**Реализация анализатора угроз:**
```go
type ThreatAnalyzer struct {
    patterns    map[string]*ThreatSignature
    ml          *MachineLearningEngine
    statistics  *StatisticalAnalyzer
    correlation *CorrelationEngine
}

func (t *ThreatAnalyzer) AnalyzeThreats(events []*SecurityEvent) ([]*ThreatPattern, error) {
    var threats []*ThreatPattern
    
    // Statistical analysis
    anomalies, err := t.statistics.DetectAnomalies(events)
    if err != nil {
        return nil, fmt.Errorf("statistical analysis failed: %w", err)
    }
    
    // Pattern matching
    for _, signature := range t.patterns {
        if matches := signature.Match(events); len(matches) > 0 {
            threat := &ThreatPattern{
                ID:          generateThreatID(),
                Type:        signature.Type,
                Description: signature.Description,
                Severity:    signature.Severity,
                Confidence:  signature.CalculateConfidence(matches),
                Events:      matches,
            }
            threats = append(threats, threat)
        }
    }
    
    // Machine learning analysis
    if t.ml != nil {
        mlThreats, err := t.ml.PredictThreats(events)
        if err == nil {
            threats = append(threats, mlThreats...)
        }
    }
    
    // Correlation analysis
    correlatedThreats := t.correlation.CorrelateThreats(threats)
    
    return correlatedThreats, nil
}
```

### ComplianceChecker - Проверка соответствия
```plantuml
Component(compliance_checker, "ComplianceChecker", "Go Struct", "Checks compliance requirements")
```

**Реализация проверки соответствия:**
```go
type ComplianceChecker struct {
    frameworks map[string]*ComplianceFramework
    rules      []*ComplianceRule
    auditor    *ComplianceAuditor
}

func (c *ComplianceChecker) CheckCompliance(event *SecurityEvent) (*ComplianceResult, error) {
    result := &ComplianceResult{
        EventID:     event.ID,
        Timestamp:   time.Now(),
        Violations:  make([]*ComplianceViolation, 0),
        Passed:      make([]*ComplianceCheck, 0),
    }
    
    // Check against all rules
    for _, rule := range c.rules {
        if rule.Applies(event) {
            check := rule.Check(event)
            if check.Passed {
                result.Passed = append(result.Passed, check)
            } else {
                violation := &ComplianceViolation{
                    RuleID:      rule.ID,
                    Description: check.Description,
                    Severity:    rule.Severity,
                    Event:       event,
                }
                result.Violations = append(result.Violations, violation)
            }
        }
    }
    
    // Calculate overall compliance score
    result.Score = c.calculateComplianceScore(result)
    
    return result, nil
}
```

## Взаимосвязи между компонентами

### Основные потоки данных
```plantuml
Rel(audit_logger_impl, security_event, "Creates", "struct instantiation")
Rel(audit_logger_impl, event_validator, "Validates events", "interface call")
Rel(audit_logger_impl, pattern_detector, "Detects patterns", "interface call")
Rel(audit_logger_impl, event_storage, "Stores events", "interface call")
```

**Поток обработки событий:**
1. **SecurityAuditLogger** создает экземпляр **SecurityEvent**
2. Валидирует событие через **EventValidator**
3. Сохраняет событие через **EventStorage**
4. Запускает анализ паттернов через **PatternDetector**

### Анализ и обработка
```plantuml
Rel(pattern_detector, risk_calculator, "Uses", "composition")
Rel(pattern_detector, threat_analyzer, "Uses", "composition")
Rel(pattern_detector, compliance_checker, "Uses", "composition")
```

**Интеграция анализаторов:**
- **PatternDetector** использует **RiskCalculator** для оценки рисков
- **ThreatAnalyzer** анализирует паттерны атак
- **ComplianceChecker** проверяет соответствие требованиям

### Работа с данными
```plantuml
Rel(risk_calculator, security_event, "Calculates risk for", "data analysis")
Rel(threat_analyzer, security_event, "Analyzes threats in", "pattern analysis")
Rel(compliance_checker, security_event, "Checks compliance of", "rule validation")
```

## Внешние зависимости

### Интеграция с внешними компонентами
```plantuml
Component_Ext(suspicious_detector, "SuspiciousActivityDetector", "External component")
Component_Ext(alert_system_ext, "SecurityAlertSystem", "External component")

Rel(audit_logger_impl, suspicious_detector, "Sends events to", "method call")
Rel(pattern_detector, alert_system_ext, "Triggers alerts via", "event notification")
```

**Внешние интерфейсы:**
- Отправка событий в **SuspiciousActivityDetector**
- Триггер алертов через **SecurityAlertSystem**

## Архитектурные паттерны на уровне кода

### 1. Factory Pattern
```go
type EventFactory struct {
    validators map[SecurityEventType]EventValidator
}

func (f *EventFactory) CreateEvent(eventType SecurityEventType, data map[string]interface{}) (*SecurityEvent, error) {
    validator, exists := f.validators[eventType]
    if !exists {
        return nil, fmt.Errorf("unsupported event type: %s", eventType)
    }
    
    event := &SecurityEvent{
        ID:        generateEventID(),
        Type:      eventType,
        Timestamp: time.Now(),
    }
    
    if err := f.populateFromData(event, data); err != nil {
        return nil, err
    }
    
    if err := validator.ValidateEvent(event); err != nil {
        return nil, err
    }
    
    return event, nil
}
```

### 2. Builder Pattern
```go
type SecurityEventBuilder struct {
    event *SecurityEvent
}

func NewSecurityEventBuilder() *SecurityEventBuilder {
    return &SecurityEventBuilder{
        event: &SecurityEvent{
            ID:        generateEventID(),
            Timestamp: time.Now(),
            Details:   make(map[string]interface{}),
        },
    }
}

func (b *SecurityEventBuilder) WithType(eventType SecurityEventType) *SecurityEventBuilder {
    b.event.Type = eventType
    return b
}

func (b *SecurityEventBuilder) WithUser(userID string) *SecurityEventBuilder {
    b.event.UserID = userID
    return b
}

func (b *SecurityEventBuilder) WithSeverity(severity SecuritySeverity) *SecurityEventBuilder {
    b.event.Severity = severity
    return b
}

func (b *SecurityEventBuilder) Build() (*SecurityEvent, error) {
    if err := b.event.Validate(); err != nil {
        return nil, err
    }
    return b.event, nil
}
```

### 3. Decorator Pattern
```go
type EventDecorator interface {
    Decorate(event *SecurityEvent) error
}

type GeoLocationDecorator struct {
    geoService GeoLocationService
}

func (d *GeoLocationDecorator) Decorate(event *SecurityEvent) error {
    if event.IPAddress != "" {
        location, err := d.geoService.GetLocation(event.IPAddress)
        if err == nil {
            event.Details["geo_location"] = location
        }
    }
    return nil
}

type RiskScoreDecorator struct {
    calculator *RiskCalculator
}

func (d *RiskScoreDecorator) Decorate(event *SecurityEvent) error {
    score, err := d.calculator.CalculateRisk(event)
    if err == nil {
        event.Details["risk_score"] = score
    }
    return nil
}
```

## Преимущества архитектуры кода

### 1. Типобезопасность
- Использование типизированных констант
- Строгая типизация интерфейсов
- Compile-time проверки

### 2. Расширяемость
- Интерфейсы для подключения новых реализаций
- Паттерны проектирования для гибкости
- Модульная архитектура

### 3. Производительность
- Эффективные структуры данных
- Оптимизированные алгоритмы
- Минимальные аллокации памяти

### 4. Тестируемость
- Четкие интерфейсы для мокирования
- Изолированные компоненты
- Dependency injection

## Соответствие требованиям Task 4

### 4.1 Улучшение аудит логирования
- **SecurityEvent** - структурированные данные событий
- **EventValidator** - валидация целостности данных
- **EventStorage** - эффективное хранение и индексирование

### 4.2 Система оповещений и блокировки
- **PatternDetector** - обнаружение подозрительных паттернов
- **ThreatAnalyzer** - анализ угроз и атак
- **RiskCalculator** - оценка серьезности событий

### 4.3 Система отчетности и аудиторского следа
- **ComplianceChecker** - проверка соответствия требованиям
- **FileEventStorage** - долгосрочное хранение для аудита
- **Структурированные данные** - удобство анализа и экспорта

Code Diagram обеспечивает детальное понимание реализации на уровне кода и служит руководством для разработчиков при имплементации системы безопасности.