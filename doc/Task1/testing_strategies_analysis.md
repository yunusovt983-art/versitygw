# Анализ стратегий тестирования Task 1 - Enhanced Cache System

## Обзор стратегий тестирования

Enhanced Cache System Task 1 требует комплексного подхода к тестированию, включающего unit тесты, интеграционные тесты, нагрузочные тесты и тесты безопасности для обеспечения надежности и производительности системы кэширования.

## 1. Unit тестирование

### Тестирование основных операций кэша
```go
package cache

import (
    "testing"
    "time"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestEnhancedCache_BasicOperations(t *testing.T) {
    config := &EnhancedCacheConfig{
        MaxSize:         100,
        CleanupInterval: 1 * time.Minute,
        DefaultTTLs: map[CacheEntryType]time.Duration{
            UserCredentials: 15 * time.Minute,
        },
    }
    
    cache, err := NewEnhancedCache(config)
    require.NoError(t, err)
    defer cache.Shutdown()
    
    t.Run("Set and Get", func(t *testing.T) {
        key := "test:user123"
        value := Account{UserID: "user123", DisplayName: "Test User"}
        
        // Set value
        cache.Set(key, value, 0, UserCredentials)
        
        // Get value
        retrieved, found := cache.Get(key, UserCredentials)
        assert.True(t, found)
        assert.Equal(t, value, retrieved.(Account))
    })
    
    t.Run("TTL Expiration", func(t *testing.T) {
        key := "test:expiring"
        value := Account{UserID: "expiring", DisplayName: "Expiring User"}
        
        // Set with short TTL
        cache.Set(key, value, 100*time.Millisecond, UserCredentials)
        
        // Should be available immediately
        _, found := cache.Get(key, UserCredentials)
        assert.True(t, found)
        
        // Wait for expiration
        time.Sleep(150 * time.Millisecond)
        
        // Should be expired
        _, found = cache.Get(key, UserCredentials)
        assert.False(t, found)
    })
    
    t.Run("Type Mismatch", func(t *testing.T) {
        key := "test:type"
        value := Account{UserID: "type", DisplayName: "Type User"}
        
        // Set as UserCredentials
        cache.Set(key, value, 0, UserCredentials)
        
        // Try to get as different type
        _, found := cache.Get(key, UserRoles)
        assert.False(t, found)
    })
}

func TestEnhancedCache_LRUEviction(t *testing.T) {
    config := &EnhancedCacheConfig{
        MaxSize:         3, // Small cache for testing eviction
        CleanupInterval: 1 * time.Minute,
        DefaultTTLs: map[CacheEntryType]time.Duration{
            UserCredentials: 15 * time.Minute,
        },
    }
    
    cache, err := NewEnhancedCache(config)
    require.NoError(t, err)
    defer cache.Shutdown()
    
    // Fill cache to capacity
    cache.Set("key1", "value1", 0, UserCredentials)
    time.Sleep(1 * time.Millisecond) // Ensure different access times
    cache.Set("key2", "value2", 0, UserCredentials)
    time.Sleep(1 * time.Millisecond)
    cache.Set("key3", "value3", 0, UserCredentials)
    
    // Access key1 to make it more recently used
    cache.Get("key1", UserCredentials)
    
    // Add another item, should evict key2 (least recently used)
    cache.Set("key4", "value4", 0, UserCredentials)
    
    // key2 should be evicted
    _, found := cache.Get("key2", UserCredentials)
    assert.False(t, found)
    
    // Others should still exist
    _, found = cache.Get("key1", UserCredentials)
    assert.True(t, found)
    _, found = cache.Get("key3", UserCredentials)
    assert.True(t, found)
    _, found = cache.Get("key4", UserCredentials)
    assert.True(t, found)
}

func TestEnhancedCache_Invalidation(t *testing.T) {
    cache, err := NewEnhancedCache(&EnhancedCacheConfig{
        MaxSize: 100,
        DefaultTTLs: map[CacheEntryType]time.Duration{
            UserCredentials: 15 * time.Minute,
            UserRoles:      30 * time.Minute,
        },
    })
    require.NoError(t, err)
    defer cache.Shutdown()
    
    // Set up test data
    cache.Set("user:alice:creds", "alice_creds", 0, UserCredentials)
    cache.Set("user:alice:roles", "alice_roles", 0, UserRoles)
    cache.Set("user:bob:creds", "bob_creds", 0, UserCredentials)
    cache.Set("user:bob:roles", "bob_roles", 0, UserRoles)
    
    t.Run("Pattern Invalidation", func(t *testing.T) {
        // Invalidate all alice entries
        err := cache.Invalidate("^user:alice:")
        assert.NoError(t, err)
        
        // Alice entries should be gone
        _, found := cache.Get("user:alice:creds", UserCredentials)
        assert.False(t, found)
        _, found = cache.Get("user:alice:roles", UserRoles)
        assert.False(t, found)
        
        // Bob entries should remain
        _, found = cache.Get("user:bob:creds", UserCredentials)
        assert.True(t, found)
        _, found = cache.Get("user:bob:roles", UserRoles)
        assert.True(t, found)
    })
    
    t.Run("Type Invalidation", func(t *testing.T) {
        // Invalidate all UserCredentials
        err := cache.InvalidateType(UserCredentials)
        assert.NoError(t, err)
        
        // Credentials should be gone
        _, found := cache.Get("user:bob:creds", UserCredentials)
        assert.False(t, found)
        
        // Roles should remain
        _, found = cache.Get("user:bob:roles", UserRoles)
        assert.True(t, found)
    })
}
```

### Тестирование Enhanced IAM Cache
```go
func TestEnhancedIAMCache_Integration(t *testing.T) {
    // Mock IAM service
    mockService := &MockIAMService{
        users: map[string]Account{
            "access123": {UserID: "user123", DisplayName: "Test User"},
            "access456": {UserID: "user456", DisplayName: "Another User"},
        },
    }
    
    config := &EnhancedIAMCacheConfig{
        CacheConfig: &EnhancedCacheConfig{
            MaxSize: 100,
            DefaultTTLs: map[CacheEntryType]time.Duration{
                UserCredentials: 15 * time.Minute,
            },
        },
        FallbackCacheConfig: &EnhancedCacheConfig{
            MaxSize: 50,
            DefaultTTLs: map[CacheEntryType]time.Duration{
                UserCredentials: 1 * time.Hour,
            },
        },
        FallbackEnabled: true,
    }
    
    cache, err := NewEnhancedIAMCache(mockService, config)
    require.NoError(t, err)
    defer cache.Shutdown()
    
    t.Run("Cache Hit Flow", func(t *testing.T) {
        // First call should hit IAM service
        account1, err := cache.GetUserAccount("access123")
        assert.NoError(t, err)
        assert.Equal(t, "user123", account1.UserID)
        assert.Equal(t, 1, mockService.callCount)
        
        // Second call should hit cache
        account2, err := cache.GetUserAccount("access123")
        assert.NoError(t, err)
        assert.Equal(t, account1, account2)
        assert.Equal(t, 1, mockService.callCount) // No additional call
    })
    
    t.Run("Fallback Mechanism", func(t *testing.T) {
        // First, populate cache
        account, err := cache.GetUserAccount("access456")
        assert.NoError(t, err)
        assert.Equal(t, "user456", account.UserID)
        
        // Simulate IAM service failure
        mockService.simulateFailure = true
        
        // Clear primary cache but keep fallback
        cache.cache.InvalidateType(UserCredentials)
        
        // Should get from fallback cache
        fallbackAccount, err := cache.GetUserAccount("access456")
        assert.NoError(t, err)
        assert.Equal(t, "user456", fallbackAccount.UserID)
        
        // Should be in fallback mode
        assert.True(t, cache.fallbackMode)
    })
}

type MockIAMService struct {
    users           map[string]Account
    callCount       int
    simulateFailure bool
}

func (m *MockIAMService) GetUserAccount(accessKey string) (Account, error) {
    m.callCount++
    
    if m.simulateFailure {
        return Account{}, errors.New("simulated IAM service failure")
    }
    
    if account, exists := m.users[accessKey]; exists {
        return account, nil
    }
    
    return Account{}, errors.New("user not found")
}

func (m *MockIAMService) CreateAccount(Account) error { return nil }
func (m *MockIAMService) UpdateUserAccount(string, MutableProps) error { return nil }
func (m *MockIAMService) DeleteUserAccount(string) error { return nil }
func (m *MockIAMService) ListUserAccounts() ([]Account, error) { return nil, nil }
func (m *MockIAMService) Shutdown() error { return nil }
```

## 2. Интеграционное тестирование

### Тестирование с реальными IAM сервисами
```go
func TestEnhancedIAMCache_LDAPIntegration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping LDAP integration test in short mode")
    }
    
    // Setup test LDAP server
    ldapConfig := &LDAPConfig{
        Host:     "localhost",
        Port:     389,
        BaseDN:   "dc=test,dc=com",
        Username: "cn=admin,dc=test,dc=com",
        Password: "admin",
    }
    
    ldapService, err := NewLDAPService(ldapConfig)
    if err != nil {
        t.Skipf("LDAP server not available: %v", err)
    }
    
    cacheConfig := &EnhancedIAMCacheConfig{
        CacheConfig: &EnhancedCacheConfig{
            MaxSize: 100,
            DefaultTTLs: map[CacheEntryType]time.Duration{
                UserCredentials: 5 * time.Minute,
            },
        },
        FallbackEnabled: true,
    }
    
    cache, err := NewEnhancedIAMCache(ldapService, cacheConfig)
    require.NoError(t, err)
    defer cache.Shutdown()
    
    t.Run("Real LDAP Lookup", func(t *testing.T) {
        // This test requires a real LDAP server with test data
        account, err := cache.GetUserAccount("testuser")
        if err != nil {
            t.Skipf("Test user not found in LDAP: %v", err)
        }
        
        assert.NotEmpty(t, account.UserID)
        assert.NotEmpty(t, account.DisplayName)
        
        // Verify caching
        stats := cache.GetCacheStats()
        assert.Greater(t, stats.Size, 0)
    })
}
```##
 3. Нагрузочное тестирование

### Тестирование производительности кэша
```go
func BenchmarkEnhancedCache_Get(b *testing.B) {
    cache, _ := NewEnhancedCache(&EnhancedCacheConfig{
        MaxSize: 10000,
        DefaultTTLs: map[CacheEntryType]time.Duration{
            UserCredentials: 15 * time.Minute,
        },
    })
    defer cache.Shutdown()
    
    // Pre-populate cache
    for i := 0; i < 1000; i++ {
        key := fmt.Sprintf("user:%d", i)
        value := Account{UserID: fmt.Sprintf("user%d", i)}
        cache.Set(key, value, 0, UserCredentials)
    }
    
    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            key := fmt.Sprintf("user:%d", rand.Intn(1000))
            cache.Get(key, UserCredentials)
        }
    })
}

func BenchmarkEnhancedCache_Set(b *testing.B) {
    cache, _ := NewEnhancedCache(&EnhancedCacheConfig{
        MaxSize: 10000,
        DefaultTTLs: map[CacheEntryType]time.Duration{
            UserCredentials: 15 * time.Minute,
        },
    })
    defer cache.Shutdown()
    
    b.ResetTimer()
    b.RunParallel(func(pb *testing.PB) {
        i := 0
        for pb.Next() {
            key := fmt.Sprintf("user:%d", i)
            value := Account{UserID: fmt.Sprintf("user%d", i)}
            cache.Set(key, value, 0, UserCredentials)
            i++
        }
    })
}

// Стресс-тест с высокой конкурентностью
func TestEnhancedCache_ConcurrentStress(t *testing.T) {
    cache, err := NewEnhancedCache(&EnhancedCacheConfig{
        MaxSize: 1000,
        DefaultTTLs: map[CacheEntryType]time.Duration{
            UserCredentials: 15 * time.Minute,
        },
    })
    require.NoError(t, err)
    defer cache.Shutdown()
    
    const (
        numGoroutines = 100
        operationsPerGoroutine = 1000
    )
    
    var wg sync.WaitGroup
    errors := make(chan error, numGoroutines)
    
    // Запуск множественных горутин для операций с кэшем
    for i := 0; i < numGoroutines; i++ {
        wg.Add(1)
        go func(goroutineID int) {
            defer wg.Done()
            
            for j := 0; j < operationsPerGoroutine; j++ {
                key := fmt.Sprintf("goroutine:%d:op:%d", goroutineID, j)
                value := Account{
                    UserID: fmt.Sprintf("user_%d_%d", goroutineID, j),
                    DisplayName: fmt.Sprintf("User %d %d", goroutineID, j),
                }
                
                // Случайная операция
                switch rand.Intn(3) {
                case 0: // Set
                    cache.Set(key, value, 0, UserCredentials)
                case 1: // Get
                    cache.Get(key, UserCredentials)
                case 2: // Invalidate
                    if rand.Float32() < 0.1 { // 10% chance
                        pattern := fmt.Sprintf("^goroutine:%d:", goroutineID)
                        if err := cache.Invalidate(pattern); err != nil {
                            errors <- err
                            return
                        }
                    }
                }
            }
        }(i)
    }
    
    wg.Wait()
    close(errors)
    
    // Проверка на ошибки
    for err := range errors {
        t.Errorf("Concurrent operation failed: %v", err)
    }
    
    // Проверка целостности кэша
    stats := cache.GetStats()
    t.Logf("Final cache stats: Size=%d, Hits=%d, Misses=%d, HitRate=%.2f%%", 
        stats.Size, stats.Hits, stats.Misses, stats.HitRate()*100)
    
    assert.LessOrEqual(t, stats.Size, 1000, "Cache size should not exceed maximum")
}
```

### Тестирование производительности с реальной нагрузкой
```go
func TestEnhancedIAMCache_LoadTest(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping load test in short mode")
    }
    
    // Создание mock сервиса с задержкой
    mockService := &MockIAMServiceWithLatency{
        users: generateTestUsers(10000),
        latency: 50 * time.Millisecond, // Симуляция сетевой задержки
    }
    
    cache, err := NewEnhancedIAMCache(mockService, &EnhancedIAMCacheConfig{
        CacheConfig: &EnhancedCacheConfig{
            MaxSize: 5000,
            DefaultTTLs: map[CacheEntryType]time.Duration{
                UserCredentials: 10 * time.Minute,
            },
        },
        FallbackEnabled: true,
    })
    require.NoError(t, err)
    defer cache.Shutdown()
    
    const (
        testDuration = 30 * time.Second
        numClients = 50
    )
    
    var (
        totalRequests int64
        successfulRequests int64
        totalLatency time.Duration
        mu sync.Mutex
    )
    
    ctx, cancel := context.WithTimeout(context.Background(), testDuration)
    defer cancel()
    
    var wg sync.WaitGroup
    
    // Запуск клиентов
    for i := 0; i < numClients; i++ {
        wg.Add(1)
        go func(clientID int) {
            defer wg.Done()
            
            for {
                select {
                case <-ctx.Done():
                    return
                default:
                    // Случайный пользователь
                    userID := rand.Intn(10000)
                    accessKey := fmt.Sprintf("access_%d", userID)
                    
                    start := time.Now()
                    _, err := cache.GetUserAccount(accessKey)
                    latency := time.Since(start)
                    
                    mu.Lock()
                    totalRequests++
                    if err == nil {
                        successfulRequests++
                        totalLatency += latency
                    }
                    mu.Unlock()
                    
                    // Небольшая пауза между запросами
                    time.Sleep(10 * time.Millisecond)
                }
            }
        }(i)
    }
    
    wg.Wait()
    
    // Анализ результатов
    successRate := float64(successfulRequests) / float64(totalRequests) * 100
    avgLatency := totalLatency / time.Duration(successfulRequests)
    requestsPerSecond := float64(totalRequests) / testDuration.Seconds()
    
    stats := cache.GetCacheStats()
    
    t.Logf("Load test results:")
    t.Logf("  Duration: %v", testDuration)
    t.Logf("  Total requests: %d", totalRequests)
    t.Logf("  Successful requests: %d", successfulRequests)
    t.Logf("  Success rate: %.2f%%", successRate)
    t.Logf("  Average latency: %v", avgLatency)
    t.Logf("  Requests per second: %.2f", requestsPerSecond)
    t.Logf("  Cache hit rate: %.2f%%", stats.HitRate()*100)
    t.Logf("  Cache size: %d", stats.Size)
    
    // Проверка производительности
    assert.Greater(t, successRate, 95.0, "Success rate should be > 95%")
    assert.Less(t, avgLatency, 10*time.Millisecond, "Average latency should be < 10ms")
    assert.Greater(t, stats.HitRate(), 0.8, "Cache hit rate should be > 80%")
}

type MockIAMServiceWithLatency struct {
    users   map[string]Account
    latency time.Duration
    mu      sync.RWMutex
}

func (m *MockIAMServiceWithLatency) GetUserAccount(accessKey string) (Account, error) {
    // Симуляция сетевой задержки
    time.Sleep(m.latency)
    
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    if account, exists := m.users[accessKey]; exists {
        return account, nil
    }
    
    return Account{}, errors.New("user not found")
}

func generateTestUsers(count int) map[string]Account {
    users := make(map[string]Account, count)
    
    for i := 0; i < count; i++ {
        accessKey := fmt.Sprintf("access_%d", i)
        users[accessKey] = Account{
            UserID:      fmt.Sprintf("user_%d", i),
            DisplayName: fmt.Sprintf("Test User %d", i),
            Email:       fmt.Sprintf("user%d@example.com", i),
            Groups:      []string{"users", fmt.Sprintf("group_%d", i%10)},
            Active:      true,
            CreatedAt:   time.Now().Add(-time.Duration(rand.Intn(365)) * 24 * time.Hour),
        }
    }
    
    return users
}
```

## 4. Тестирование безопасности

### Тестирование защиты от атак
```go
func TestEnhancedCache_SecurityTests(t *testing.T) {
    cache, err := NewEnhancedCache(&EnhancedCacheConfig{
        MaxSize: 1000,
        DefaultTTLs: map[CacheEntryType]time.Duration{
            UserCredentials: 15 * time.Minute,
        },
    })
    require.NoError(t, err)
    defer cache.Shutdown()
    
    t.Run("Cache Poisoning Protection", func(t *testing.T) {
        // Попытка установить вредоносные данные
        maliciousData := map[string]interface{}{
            "script": "<script>alert('xss')</script>",
            "sql":    "'; DROP TABLE users; --",
        }
        
        cache.Set("malicious:key", maliciousData, 0, UserCredentials)
        
        // Данные должны быть сохранены как есть (без выполнения)
        retrieved, found := cache.Get("malicious:key", UserCredentials)
        assert.True(t, found)
        
        retrievedMap := retrieved.(map[string]interface{})
        assert.Equal(t, maliciousData["script"], retrievedMap["script"])
        assert.Equal(t, maliciousData["sql"], retrievedMap["sql"])
    })
    
    t.Run("Memory Exhaustion Protection", func(t *testing.T) {
        // Попытка переполнения кэша
        initialSize := cache.GetStats().Size
        
        for i := 0; i < 2000; i++ { // Больше чем maxSize
            key := fmt.Sprintf("overflow:%d", i)
            value := strings.Repeat("A", 1024) // 1KB per entry
            cache.Set(key, value, 0, UserCredentials)
        }
        
        stats := cache.GetStats()
        assert.LessOrEqual(t, stats.Size, 1000, "Cache should not exceed max size")
        assert.Greater(t, stats.Evictions, int64(0), "Should have evictions")
    })
    
    t.Run("Invalid Key Handling", func(t *testing.T) {
        invalidKeys := []string{
            "",                    // Empty key
            strings.Repeat("A", 10000), // Very long key
            "key\x00with\x00nulls", // Key with null bytes
            "key\nwith\nnewlines", // Key with newlines
        }
        
        for _, key := range invalidKeys {
            // Should not panic or cause issues
            cache.Set(key, "value", 0, UserCredentials)
            cache.Get(key, UserCredentials)
        }
    })
}

func TestEnhancedIAMCache_RateLimitingTests(t *testing.T) {
    rateLimitConfig := &RateLimitConfig{
        RequestsPerMinute: 10,
        BurstSize:         5,
        BlockDuration:     1 * time.Minute,
    }
    
    mockService := &MockIAMService{
        users: map[string]Account{
            "test": {UserID: "test", DisplayName: "Test User"},
        },
    }
    
    cache, err := NewEnhancedIAMCache(mockService, &EnhancedIAMCacheConfig{
        CacheConfig: &EnhancedCacheConfig{MaxSize: 100},
    })
    require.NoError(t, err)
    defer cache.Shutdown()
    
    // Установка rate limiter
    cache.rateLimiter = NewRateLimiter(rateLimitConfig)
    
    t.Run("Rate Limit Enforcement", func(t *testing.T) {
        userID := "testuser"
        ipAddress := "192.168.1.100"
        
        // Первые 10 запросов должны пройти
        for i := 0; i < 10; i++ {
            err := cache.rateLimiter.CheckRateLimit(userID, ipAddress)
            assert.NoError(t, err, "Request %d should be allowed", i+1)
        }
        
        // 11-й запрос должен быть заблокирован
        err := cache.rateLimiter.CheckRateLimit(userID, ipAddress)
        assert.Error(t, err, "Request should be rate limited")
        assert.Contains(t, err.Error(), "rate limit exceeded")
    })
}
```

## 5. Тестирование отказоустойчивости

### Тестирование fallback механизма
```go
func TestEnhancedIAMCache_FailoverTests(t *testing.T) {
    mockService := &MockIAMServiceWithFailures{
        users: map[string]Account{
            "test": {UserID: "test", DisplayName: "Test User"},
        },
    }
    
    cache, err := NewEnhancedIAMCache(mockService, &EnhancedIAMCacheConfig{
        CacheConfig: &EnhancedCacheConfig{
            MaxSize: 100,
            DefaultTTLs: map[CacheEntryType]time.Duration{
                UserCredentials: 5 * time.Minute,
            },
        },
        FallbackCacheConfig: &EnhancedCacheConfig{
            MaxSize: 50,
            DefaultTTLs: map[CacheEntryType]time.Duration{
                UserCredentials: 30 * time.Minute,
            },
        },
        FallbackEnabled: true,
    })
    require.NoError(t, err)
    defer cache.Shutdown()
    
    t.Run("Service Recovery", func(t *testing.T) {
        // Первоначальная загрузка в кэш
        account, err := cache.GetUserAccount("test")
        assert.NoError(t, err)
        assert.Equal(t, "test", account.UserID)
        
        // Симуляция отказа сервиса
        mockService.SetFailureMode(true)
        
        // Очистка основного кэша
        cache.cache.InvalidateType(UserCredentials)
        
        // Должен использовать fallback
        fallbackAccount, err := cache.GetUserAccount("test")
        assert.NoError(t, err)
        assert.Equal(t, "test", fallbackAccount.UserID)
        assert.True(t, cache.fallbackMode)
        
        // Восстановление сервиса
        mockService.SetFailureMode(false)
        
        // Проверка восстановления
        time.Sleep(100 * time.Millisecond) // Дать время на обнаружение восстановления
        
        // Новый запрос должен обновить кэш
        recoveredAccount, err := cache.GetUserAccount("test")
        assert.NoError(t, err)
        assert.Equal(t, "test", recoveredAccount.UserID)
    })
    
    t.Run("Partial Service Degradation", func(t *testing.T) {
        // Симуляция частичных отказов (50% запросов падают)
        mockService.SetPartialFailureRate(0.5)
        
        successCount := 0
        totalRequests := 100
        
        for i := 0; i < totalRequests; i++ {
            _, err := cache.GetUserAccount("test")
            if err == nil {
                successCount++
            }
        }
        
        // Должно быть больше 50% успешных запросов благодаря кэшу
        successRate := float64(successCount) / float64(totalRequests)
        assert.Greater(t, successRate, 0.7, "Success rate should be > 70% with caching")
    })
}

type MockIAMServiceWithFailures struct {
    users              map[string]Account
    failureMode        bool
    partialFailureRate float64
    mu                 sync.RWMutex
}

func (m *MockIAMServiceWithFailures) SetFailureMode(enabled bool) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.failureMode = enabled
}

func (m *MockIAMServiceWithFailures) SetPartialFailureRate(rate float64) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.partialFailureRate = rate
}

func (m *MockIAMServiceWithFailures) GetUserAccount(accessKey string) (Account, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    if m.failureMode {
        return Account{}, errors.New("service unavailable")
    }
    
    if m.partialFailureRate > 0 && rand.Float64() < m.partialFailureRate {
        return Account{}, errors.New("temporary service error")
    }
    
    if account, exists := m.users[accessKey]; exists {
        return account, nil
    }
    
    return Account{}, errors.New("user not found")
}
```

Эти стратегии тестирования обеспечивают комплексную проверку Enhanced Cache System, включая функциональность, производительность, безопасность и отказоустойчивость системы кэширования аутентификации.