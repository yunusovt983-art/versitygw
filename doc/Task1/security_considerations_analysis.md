# Анализ соображений безопасности Task 1 - Enhanced Cache System

## Обзор безопасности

Enhanced Cache System Task 1 включает множественные уровни защиты для обеспечения безопасности кэшированных данных аутентификации, предотвращения утечек информации и защиты от различных типов атак.

## 1. Защита данных в памяти

### Шифрование чувствительных данных
```go
type SecureCacheEntry struct {
    encryptedValue []byte        // Зашифрованные данные
    expiry         time.Time     // Время истечения
    entryType      CacheEntryType
    accessTime     time.Time
    key            string
    salt           []byte        // Соль для шифрования
    checksum       []byte        // Контрольная сумма для целостности
}

type CacheEncryption struct {
    key    []byte
    cipher cipher.AEAD
}

func NewCacheEncryption(masterKey []byte) (*CacheEncryption, error) {
    block, err := aes.NewCipher(masterKey)
    if err != nil {
        return nil, err
    }
    
    aead, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    return &CacheEncryption{
        key:    masterKey,
        cipher: aead,
    }, nil
}

func (ce *CacheEncryption) Encrypt(data []byte, salt []byte) ([]byte, error) {
    nonce := make([]byte, ce.cipher.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    
    // Добавление соли к данным
    saltedData := append(salt, data...)
    
    ciphertext := ce.cipher.Seal(nonce, nonce, saltedData, nil)
    return ciphertext, nil
}

func (ce *CacheEncryption) Decrypt(ciphertext []byte, expectedSalt []byte) ([]byte, error) {
    if len(ciphertext) < ce.cipher.NonceSize() {
        return nil, errors.New("ciphertext too short")
    }
    
    nonce := ciphertext[:ce.cipher.NonceSize()]
    encrypted := ciphertext[ce.cipher.NonceSize():]
    
    saltedData, err := ce.cipher.Open(nil, nonce, encrypted, nil)
    if err != nil {
        return nil, err
    }
    
    // Проверка соли
    if len(saltedData) < len(expectedSalt) {
        return nil, errors.New("invalid decrypted data")
    }
    
    if !bytes.Equal(saltedData[:len(expectedSalt)], expectedSalt) {
        return nil, errors.New("salt mismatch")
    }
    
    return saltedData[len(expectedSalt):], nil
}

// Безопасное создание записи кэша
func NewSecureCacheEntry(key string, value interface{}, ttl time.Duration, entryType CacheEntryType, encryption *CacheEncryption) (*SecureCacheEntry, error) {
    // Сериализация значения
    valueBytes, err := json.Marshal(value)
    if err != nil {
        return nil, err
    }
    
    // Генерация соли
    salt := make([]byte, 16)
    if _, err := rand.Read(salt); err != nil {
        return nil, err
    }
    
    // Шифрование данных
    encryptedValue, err := encryption.Encrypt(valueBytes, salt)
    if err != nil {
        return nil, err
    }
    
    // Вычисление контрольной суммы
    hasher := sha256.New()
    hasher.Write(encryptedValue)
    hasher.Write(salt)
    checksum := hasher.Sum(nil)
    
    return &SecureCacheEntry{
        encryptedValue: encryptedValue,
        expiry:         time.Now().Add(ttl),
        entryType:      entryType,
        accessTime:     time.Now(),
        key:            key,
        salt:           salt,
        checksum:       checksum,
    }, nil
}
```

### Безопасная очистка памяти
```go
// Безопасная очистка чувствительных данных из памяти
func (sce *SecureCacheEntry) SecureDestroy() {
    // Перезапись зашифрованных данных
    if sce.encryptedValue != nil {
        for i := range sce.encryptedValue {
            sce.encryptedValue[i] = 0
        }
        sce.encryptedValue = nil
    }
    
    // Перезапись соли
    if sce.salt != nil {
        for i := range sce.salt {
            sce.salt[i] = 0
        }
        sce.salt = nil
    }
    
    // Перезапись контрольной суммы
    if sce.checksum != nil {
        for i := range sce.checksum {
            sce.checksum[i] = 0
        }
        sce.checksum = nil
    }
    
    // Очистка ключа
    sce.key = ""
    
    // Принудительная сборка мусора
    runtime.GC()
}

// Безопасное завершение работы кэша
func (ec *EnhancedCache) SecureShutdown() error {
    ec.mu.Lock()
    defer ec.mu.Unlock()
    
    // Безопасное удаление всех записей
    for key, entry := range ec.entries {
        if secureEntry, ok := entry.(*SecureCacheEntry); ok {
            secureEntry.SecureDestroy()
        }
        delete(ec.entries, key)
    }
    
    // Отмена фоновых процессов
    if ec.cancel != nil {
        ec.cancel()
    }
    
    return nil
}
```

## 2. Контроль доступа и авторизация

### Многоуровневая авторизация
```go
type AccessControlPolicy struct {
    UserPermissions  map[string][]Permission
    RolePermissions  map[string][]Permission
    ResourcePolicies map[string]ResourcePolicy
}

type Permission struct {
    Resource string
    Action   string
    Effect   PermissionEffect
}

type PermissionEffect int

const (
    Allow PermissionEffect = iota
    Deny
)

type ResourcePolicy struct {
    AllowedUsers  []string
    AllowedRoles  []string
    DeniedUsers   []string
    DeniedRoles   []string
    RequiredMFA   bool
    TimeRestrictions []TimeRestriction
}

type TimeRestriction struct {
    StartTime time.Time
    EndTime   time.Time
    DaysOfWeek []time.Weekday
}

// Проверка прав доступа к кэшу
func (acp *AccessControlPolicy) CheckCacheAccess(userID string, userRoles []string, resource string, action string) (bool, error) {
    // Проверка временных ограничений
    if !acp.checkTimeRestrictions(resource) {
        return false, errors.New("access denied: outside allowed time window")
    }
    
    // Проверка явных запретов (имеют приоритет)
    if acp.isExplicitlyDenied(userID, userRoles, resource, action) {
        return false, errors.New("access explicitly denied")
    }
    
    // Проверка разрешений пользователя
    if acp.isUserAllowed(userID, resource, action) {
        return true, nil
    }
    
    // Проверка разрешений ролей
    if acp.isRoleAllowed(userRoles, resource, action) {
        return true, nil
    }
    
    return false, errors.New("access denied: insufficient permissions")
}

func (acp *AccessControlPolicy) isExplicitlyDenied(userID string, userRoles []string, resource string, action string) bool {
    // Проверка запретов пользователя
    if permissions, exists := acp.UserPermissions[userID]; exists {
        for _, perm := range permissions {
            if perm.Resource == resource && perm.Action == action && perm.Effect == Deny {
                return true
            }
        }
    }
    
    // Проверка запретов ролей
    for _, role := range userRoles {
        if permissions, exists := acp.RolePermissions[role]; exists {
            for _, perm := range permissions {
                if perm.Resource == resource && perm.Action == action && perm.Effect == Deny {
                    return true
                }
            }
        }
    }
    
    return false
}
```

## 3. Аудит и мониторинг безопасности

### Комплексная система аудита
```go
type SecurityAuditLogger struct {
    logger        *log.Logger
    encryptor     *AuditEncryption
    signer        *AuditSigner
    alertManager  *SecurityAlertManager
}

type AuditEvent struct {
    Timestamp    time.Time              `json:"timestamp"`
    EventType    string                 `json:"event_type"`
    UserID       string                 `json:"user_id"`
    SessionID    string                 `json:"session_id"`
    IPAddress    string                 `json:"ip_address"`
    UserAgent    string                 `json:"user_agent"`
    Resource     string                 `json:"resource"`
    Action       string                 `json:"action"`
    Result       string                 `json:"result"`
    Details      map[string]interface{} `json:"details"`
    RiskScore    int                    `json:"risk_score"`
    Signature    string                 `json:"signature"`
}

func (sal *SecurityAuditLogger) LogCacheAccess(userID, sessionID, ipAddress, resource, action, result string, details map[string]interface{}) {
    event := &AuditEvent{
        Timestamp: time.Now(),
        EventType: "cache_access",
        UserID:    userID,
        SessionID: sessionID,
        IPAddress: ipAddress,
        Resource:  resource,
        Action:    action,
        Result:    result,
        Details:   details,
        RiskScore: sal.calculateRiskScore(userID, ipAddress, action, result),
    }
    
    // Подпись события для обеспечения целостности
    signature, err := sal.signer.SignEvent(event)
    if err != nil {
        log.Printf("Failed to sign audit event: %v", err)
    } else {
        event.Signature = signature
    }
    
    // Шифрование чувствительных данных
    encryptedEvent, err := sal.encryptor.EncryptEvent(event)
    if err != nil {
        log.Printf("Failed to encrypt audit event: %v", err)
        return
    }
    
    // Запись в лог
    sal.logger.Printf("AUDIT: %s", encryptedEvent)
    
    // Проверка на подозрительную активность
    if event.RiskScore > 7 {
        sal.alertManager.SendSecurityAlert(event)
    }
}

func (sal *SecurityAuditLogger) calculateRiskScore(userID, ipAddress, action, result string) int {
    score := 0
    
    // Базовый риск по типу действия
    switch action {
    case "cache_access":
        score += 1
    case "cache_invalidation":
        score += 3
    case "admin_operation":
        score += 5
    }
    
    // Увеличение риска при неудачах
    if result == "failure" || result == "denied" {
        score += 3
    }
    
    // Проверка IP адреса
    if sal.isUnknownIP(ipAddress) {
        score += 2
    }
    
    // Проверка частоты запросов
    if sal.isHighFrequencyUser(userID) {
        score += 2
    }
    
    return score
}
```## 4.
 Защита от атак

### Защита от атак типа Timing Attack
```go
// Константное время для операций сравнения
func constantTimeCompare(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    
    var result byte
    for i := 0; i < len(a); i++ {
        result |= a[i] ^ b[i]
    }
    
    return result == 0
}

// Безопасная проверка ключей кэша
func (ec *EnhancedCache) secureKeyLookup(key string) (*CacheEntry, bool) {
    ec.mu.RLock()
    defer ec.mu.RUnlock()
    
    // Добавление случайной задержки для предотвращения timing attacks
    randomDelay := time.Duration(rand.Intn(100)) * time.Microsecond
    time.Sleep(randomDelay)
    
    entry, exists := ec.entries[key]
    return entry, exists
}
```

### Rate Limiting и защита от DoS
```go
type RateLimiter struct {
    requests map[string]*UserRateLimit
    mu       sync.RWMutex
    config   *RateLimitConfig
}

type UserRateLimit struct {
    count      int64
    resetTime  time.Time
    blocked    bool
    blockUntil time.Time
}

type RateLimitConfig struct {
    RequestsPerMinute int
    BurstSize         int
    BlockDuration     time.Duration
    WhitelistedIPs    []string
}

func (rl *RateLimiter) CheckRateLimit(userID, ipAddress string) error {
    // Проверка белого списка IP
    if rl.isWhitelisted(ipAddress) {
        return nil
    }
    
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    key := fmt.Sprintf("%s:%s", userID, ipAddress)
    limit, exists := rl.requests[key]
    
    now := time.Now()
    
    if !exists {
        rl.requests[key] = &UserRateLimit{
            count:     1,
            resetTime: now.Add(time.Minute),
        }
        return nil
    }
    
    // Проверка блокировки
    if limit.blocked && now.Before(limit.blockUntil) {
        return fmt.Errorf("rate limit exceeded, blocked until %v", limit.blockUntil)
    }
    
    // Сброс счетчика если прошла минута
    if now.After(limit.resetTime) {
        limit.count = 1
        limit.resetTime = now.Add(time.Minute)
        limit.blocked = false
        return nil
    }
    
    limit.count++
    
    // Проверка превышения лимита
    if limit.count > int64(rl.config.RequestsPerMinute) {
        limit.blocked = true
        limit.blockUntil = now.Add(rl.config.BlockDuration)
        
        // Логирование подозрительной активности
        log.Printf("Rate limit exceeded for user %s from IP %s", userID, ipAddress)
        
        return fmt.Errorf("rate limit exceeded: %d requests per minute", rl.config.RequestsPerMinute)
    }
    
    return nil
}

// Интеграция с кэшем
func (eic *EnhancedIAMCache) GetUserAccountWithRateLimit(accessKey, userID, ipAddress string) (Account, error) {
    // Проверка rate limit
    if err := eic.rateLimiter.CheckRateLimit(userID, ipAddress); err != nil {
        eic.auditLogger.LogSecurityEvent("rate_limit_exceeded", userID, ipAddress, err.Error())
        return Account{}, err
    }
    
    return eic.GetUserAccount(accessKey)
}
```

### Защита от Cache Poisoning
```go
type CacheIntegrityChecker struct {
    trustedSources map[string]bool
    checksumCache  map[string]string
    mu             sync.RWMutex
}

func (cic *CacheIntegrityChecker) ValidateEntry(key string, value interface{}, source string) error {
    // Проверка доверенного источника
    if !cic.isTrustedSource(source) {
        return fmt.Errorf("untrusted source: %s", source)
    }
    
    // Вычисление контрольной суммы
    checksum, err := cic.calculateChecksum(value)
    if err != nil {
        return fmt.Errorf("failed to calculate checksum: %w", err)
    }
    
    cic.mu.Lock()
    defer cic.mu.Unlock()
    
    // Проверка на изменение данных
    if existingChecksum, exists := cic.checksumCache[key]; exists {
        if existingChecksum != checksum {
            // Потенциальная атака cache poisoning
            log.Printf("WARNING: Cache poisoning detected for key %s", key)
            return errors.New("cache integrity violation detected")
        }
    }
    
    cic.checksumCache[key] = checksum
    return nil
}

func (cic *CacheIntegrityChecker) calculateChecksum(value interface{}) (string, error) {
    data, err := json.Marshal(value)
    if err != nil {
        return "", err
    }
    
    hasher := sha256.New()
    hasher.Write(data)
    return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (cic *CacheIntegrityChecker) isTrustedSource(source string) bool {
    cic.mu.RLock()
    defer cic.mu.RUnlock()
    return cic.trustedSources[source]
}
```

## 5. Безопасная конфигурация

### Защищенное управление ключами
```go
type KeyManager struct {
    masterKey    []byte
    derivedKeys  map[string][]byte
    keyRotation  *KeyRotationScheduler
    hsm          HSMInterface // Hardware Security Module
}

type KeyRotationScheduler struct {
    rotationInterval time.Duration
    lastRotation     time.Time
    stopChan         chan struct{}
}

func NewKeyManager(masterKey []byte, hsmConfig *HSMConfig) (*KeyManager, error) {
    km := &KeyManager{
        masterKey:   masterKey,
        derivedKeys: make(map[string][]byte),
    }
    
    // Инициализация HSM если доступен
    if hsmConfig != nil {
        hsm, err := NewHSM(hsmConfig)
        if err != nil {
            return nil, fmt.Errorf("failed to initialize HSM: %w", err)
        }
        km.hsm = hsm
    }
    
    // Запуск ротации ключей
    km.keyRotation = &KeyRotationScheduler{
        rotationInterval: 24 * time.Hour,
        lastRotation:     time.Now(),
        stopChan:         make(chan struct{}),
    }
    
    go km.keyRotationLoop()
    
    return km, nil
}

func (km *KeyManager) DeriveKey(purpose string, salt []byte) ([]byte, error) {
    // Использование HKDF для вывода ключей
    hkdf := hkdf.New(sha256.New, km.masterKey, salt, []byte(purpose))
    
    key := make([]byte, 32) // 256-bit key
    if _, err := io.ReadFull(hkdf, key); err != nil {
        return nil, fmt.Errorf("failed to derive key: %w", err)
    }
    
    km.derivedKeys[purpose] = key
    return key, nil
}

func (km *KeyManager) keyRotationLoop() {
    ticker := time.NewTicker(km.keyRotation.rotationInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            if err := km.rotateKeys(); err != nil {
                log.Printf("Key rotation failed: %v", err)
            }
        case <-km.keyRotation.stopChan:
            return
        }
    }
}

func (km *KeyManager) rotateKeys() error {
    log.Printf("Starting key rotation...")
    
    // Генерация нового мастер-ключа
    newMasterKey := make([]byte, 32)
    if _, err := rand.Read(newMasterKey); err != nil {
        return fmt.Errorf("failed to generate new master key: %w", err)
    }
    
    // Сохранение старого ключа для расшифровки существующих данных
    oldMasterKey := km.masterKey
    
    // Обновление мастер-ключа
    km.masterKey = newMasterKey
    
    // Перевывод всех производных ключей
    for purpose := range km.derivedKeys {
        salt := make([]byte, 16)
        rand.Read(salt)
        
        if _, err := km.DeriveKey(purpose, salt); err != nil {
            // Откат в случае ошибки
            km.masterKey = oldMasterKey
            return fmt.Errorf("failed to re-derive key for %s: %w", purpose, err)
        }
    }
    
    km.keyRotation.lastRotation = time.Now()
    log.Printf("Key rotation completed successfully")
    
    return nil
}
```

### Безопасная конфигурация кэша
```go
type SecureCacheConfig struct {
    EncryptionEnabled    bool          `yaml:"encryption_enabled"`
    KeyRotationInterval  time.Duration `yaml:"key_rotation_interval"`
    AuditLevel          string        `yaml:"audit_level"` // "minimal", "standard", "verbose"
    RateLimitConfig     *RateLimitConfig `yaml:"rate_limit"`
    AccessControlPolicy *AccessControlPolicy `yaml:"access_control"`
    SecurityHeaders     map[string]string `yaml:"security_headers"`
    TLSConfig          *TLSConfig `yaml:"tls"`
}

func (scc *SecureCacheConfig) Validate() error {
    if scc.EncryptionEnabled && scc.KeyRotationInterval <= 0 {
        return errors.New("key rotation interval must be positive when encryption is enabled")
    }
    
    if scc.RateLimitConfig != nil {
        if scc.RateLimitConfig.RequestsPerMinute <= 0 {
            return errors.New("requests per minute must be positive")
        }
    }
    
    validAuditLevels := map[string]bool{
        "minimal":  true,
        "standard": true,
        "verbose":  true,
    }
    
    if !validAuditLevels[scc.AuditLevel] {
        return fmt.Errorf("invalid audit level: %s", scc.AuditLevel)
    }
    
    return nil
}

// Применение безопасной конфигурации
func (eic *EnhancedIAMCache) ApplySecurityConfig(config *SecureCacheConfig) error {
    if err := config.Validate(); err != nil {
        return fmt.Errorf("invalid security config: %w", err)
    }
    
    // Настройка шифрования
    if config.EncryptionEnabled {
        encryption, err := NewCacheEncryption(eic.keyManager.masterKey)
        if err != nil {
            return fmt.Errorf("failed to setup encryption: %w", err)
        }
        eic.encryption = encryption
    }
    
    // Настройка rate limiting
    if config.RateLimitConfig != nil {
        eic.rateLimiter = NewRateLimiter(config.RateLimitConfig)
    }
    
    // Настройка контроля доступа
    if config.AccessControlPolicy != nil {
        eic.accessControl = config.AccessControlPolicy
    }
    
    // Настройка аудита
    eic.auditLogger.SetLevel(config.AuditLevel)
    
    return nil
}
```

Эти меры безопасности обеспечивают комплексную защиту Enhanced Cache System, включая шифрование данных, контроль доступа, аудит, защиту от атак и безопасное управление ключами.