// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package ipfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// EncryptionManager handles client-side encryption for IPFS objects
type EncryptionManager struct {
	config       *EncryptionConfig
	keyManager   *KeyManager
	cipherSuites map[string]CipherSuite
	mu           sync.RWMutex
}

// EncryptionConfig contains encryption configuration
type EncryptionConfig struct {
	DefaultAlgorithm    string            `json:"default_algorithm"`
	KeyRotationInterval time.Duration     `json:"key_rotation_interval"`
	KeyDerivationRounds int               `json:"key_derivation_rounds"`
	EnableCompression   bool              `json:"enable_compression"`
	ChunkSize          int               `json:"chunk_size"`
	Algorithms         map[string]string `json:"algorithms"`
}

// DefaultEncryptionConfig returns default encryption configuration
func DefaultEncryptionConfig() *EncryptionConfig {
	return &EncryptionConfig{
		DefaultAlgorithm:    "AES-256-GCM",
		KeyRotationInterval: 24 * time.Hour,
		KeyDerivationRounds: 100000,
		EnableCompression:   true,
		ChunkSize:          64 * 1024, // 64KB chunks
		Algorithms: map[string]string{
			"AES-256-GCM": "aes-256-gcm",
			"AES-256-CBC": "aes-256-cbc",
			"ChaCha20":    "chacha20-poly1305",
		},
	}
}

// KeyManager manages encryption keys
type KeyManager struct {
	masterKey    []byte
	derivedKeys  map[string]*DerivedKey
	keyRotation  time.Duration
	mu           sync.RWMutex
}

// DerivedKey represents a derived encryption key
type DerivedKey struct {
	Key       []byte    `json:"key"`
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Version   int       `json:"version"`
}

// CipherSuite interface for different encryption algorithms
type CipherSuite interface {
	Encrypt(data []byte, key []byte) (*EncryptedData, error)
	Decrypt(encData *EncryptedData, key []byte) ([]byte, error)
	KeySize() int
	Name() string
}

// EncryptedData contains encrypted data and metadata
type EncryptedData struct {
	Algorithm    string            `json:"algorithm"`
	KeyVersion   int               `json:"key_version"`
	Nonce        []byte            `json:"nonce"`
	Ciphertext   []byte            `json:"ciphertext"`
	AuthTag      []byte            `json:"auth_tag,omitempty"`
	Metadata     map[string]string `json:"metadata"`
	Compressed   bool              `json:"compressed"`
	OriginalSize int64             `json:"original_size"`
}

// NewEncryptionManager creates a new encryption manager
func NewEncryptionManager(config *EncryptionConfig, masterKey []byte) (*EncryptionManager, error) {
	if config == nil {
		config = DefaultEncryptionConfig()
	}

	keyManager := &KeyManager{
		masterKey:   masterKey,
		derivedKeys: make(map[string]*DerivedKey),
		keyRotation: config.KeyRotationInterval,
	}

	em := &EncryptionManager{
		config:       config,
		keyManager:   keyManager,
		cipherSuites: make(map[string]CipherSuite),
	}

	// Register cipher suites
	em.registerCipherSuites()

	// Initialize default key
	if err := em.rotateKey(config.DefaultAlgorithm); err != nil {
		return nil, fmt.Errorf("failed to initialize default key: %w", err)
	}

	// Start key rotation routine
	go em.keyRotationRoutine()

	return em, nil
}

// EncryptObject encrypts an object with metadata
func (em *EncryptionManager) EncryptObject(data []byte, metadata map[string]string, algorithm string) (*EncryptedData, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	if algorithm == "" {
		algorithm = em.config.DefaultAlgorithm
	}

	// Get cipher suite
	cipherSuite, exists := em.cipherSuites[algorithm]
	if !exists {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}

	// Get encryption key
	key, err := em.keyManager.GetKey(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Compress data if enabled
	originalSize := int64(len(data))
	compressed := false
	if em.config.EnableCompression && len(data) > 1024 {
		compressedData, err := compressData(data)
		if err == nil && len(compressedData) < len(data) {
			data = compressedData
			compressed = true
		}
	}

	// Encrypt data
	encryptedData, err := cipherSuite.Encrypt(data, key.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Set encryption metadata
	encryptedData.Algorithm = algorithm
	encryptedData.KeyVersion = key.Version
	encryptedData.Compressed = compressed
	encryptedData.OriginalSize = originalSize
	encryptedData.Metadata = metadata

	return encryptedData, nil
}

// DecryptObject decrypts an encrypted object
func (em *EncryptionManager) DecryptObject(encData *EncryptedData) ([]byte, map[string]string, error) {
	em.mu.RLock()
	defer em.mu.RUnlock()

	// Get cipher suite
	cipherSuite, exists := em.cipherSuites[encData.Algorithm]
	if !exists {
		return nil, nil, fmt.Errorf("unsupported encryption algorithm: %s", encData.Algorithm)
	}

	// Get decryption key
	key, err := em.keyManager.GetKeyByVersion(encData.Algorithm, encData.KeyVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get decryption key: %w", err)
	}

	// Decrypt data
	data, err := cipherSuite.Decrypt(encData, key.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	// Decompress if needed
	if encData.Compressed {
		decompressedData, err := decompressData(data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decompress data: %w", err)
		}
		data = decompressedData
	}

	return data, encData.Metadata, nil
}

// EncryptStream encrypts data in streaming fashion for large objects
func (em *EncryptionManager) EncryptStream(reader io.Reader, metadata map[string]string, algorithm string) (*EncryptedStream, error) {
	if algorithm == "" {
		algorithm = em.config.DefaultAlgorithm
	}

	// Get cipher suite
	cipherSuite, exists := em.cipherSuites[algorithm]
	if !exists {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}

	// Get encryption key
	key, err := em.keyManager.GetKey(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %w", err)
	}

	return NewEncryptedStream(reader, cipherSuite, key, em.config.ChunkSize, metadata)
}

// DecryptStream decrypts data in streaming fashion
func (em *EncryptionManager) DecryptStream(encStream *EncryptedStream) (io.Reader, error) {
	// Get cipher suite
	cipherSuite, exists := em.cipherSuites[encStream.Algorithm]
	if !exists {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", encStream.Algorithm)
	}

	// Get decryption key
	key, err := em.keyManager.GetKeyByVersion(encStream.Algorithm, encStream.KeyVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get decryption key: %w", err)
	}

	return NewDecryptedStream(encStream, cipherSuite, key)
}

// Key management methods

func (km *KeyManager) GetKey(algorithm string) (*DerivedKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	key, exists := km.derivedKeys[algorithm]
	if !exists {
		return nil, fmt.Errorf("no key available for algorithm: %s", algorithm)
	}

	// Check if key is expired
	if time.Now().After(key.ExpiresAt) {
		return nil, fmt.Errorf("key expired for algorithm: %s", algorithm)
	}

	return key, nil
}

func (km *KeyManager) GetKeyByVersion(algorithm string, version int) (*DerivedKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	// For now, we only keep the current key
	// In a full implementation, you'd maintain a history of keys
	key, exists := km.derivedKeys[algorithm]
	if !exists {
		return nil, fmt.Errorf("no key available for algorithm: %s", algorithm)
	}

	if key.Version != version {
		return nil, fmt.Errorf("key version %d not found for algorithm: %s", version, algorithm)
	}

	return key, nil
}

func (km *KeyManager) DeriveKey(algorithm string, keySize int) (*DerivedKey, error) {
	// Use PBKDF2 to derive key from master key
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Simple key derivation (in production, use proper PBKDF2)
	hash := sha256.New()
	hash.Write(km.masterKey)
	hash.Write(salt)
	hash.Write([]byte(algorithm))
	derivedKey := hash.Sum(nil)

	// Truncate or extend to required key size
	if len(derivedKey) > keySize {
		derivedKey = derivedKey[:keySize]
	} else if len(derivedKey) < keySize {
		// Extend key by repeating hash
		for len(derivedKey) < keySize {
			hash.Reset()
			hash.Write(derivedKey)
			derivedKey = append(derivedKey, hash.Sum(nil)...)
		}
		derivedKey = derivedKey[:keySize]
	}

	now := time.Now()
	return &DerivedKey{
		Key:       derivedKey,
		Algorithm: algorithm,
		CreatedAt: now,
		ExpiresAt: now.Add(km.keyRotation),
		Version:   int(now.Unix()), // Simple versioning
	}, nil
}

// Cipher suite implementations

// AESGCMCipherSuite implements AES-256-GCM encryption
type AESGCMCipherSuite struct{}

func (acs *AESGCMCipherSuite) Encrypt(data []byte, key []byte) (*EncryptedData, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	return &EncryptedData{
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

func (acs *AESGCMCipherSuite) Decrypt(encData *EncryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, encData.Nonce, encData.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

func (acs *AESGCMCipherSuite) KeySize() int {
	return 32 // 256 bits
}

func (acs *AESGCMCipherSuite) Name() string {
	return "AES-256-GCM"
}

// Helper methods

func (em *EncryptionManager) registerCipherSuites() {
	em.cipherSuites["AES-256-GCM"] = &AESGCMCipherSuite{}
	// Add more cipher suites as needed
}

func (em *EncryptionManager) rotateKey(algorithm string) error {
	cipherSuite, exists := em.cipherSuites[algorithm]
	if !exists {
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	key, err := em.keyManager.DeriveKey(algorithm, cipherSuite.KeySize())
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	em.keyManager.mu.Lock()
	em.keyManager.derivedKeys[algorithm] = key
	em.keyManager.mu.Unlock()

	return nil
}

func (em *EncryptionManager) keyRotationRoutine() {
	ticker := time.NewTicker(em.config.KeyRotationInterval)
	defer ticker.Stop()

	for range ticker.C {
		for algorithm := range em.cipherSuites {
			if err := em.rotateKey(algorithm); err != nil {
				// Log error but continue
				fmt.Printf("Failed to rotate key for %s: %v\n", algorithm, err)
			}
		}
	}
}

// EncryptionMetadata contains metadata about encrypted objects
type EncryptionMetadata struct {
	IsEncrypted      bool              `json:"is_encrypted"`
	Algorithm        string            `json:"algorithm"`
	KeyVersion       int               `json:"key_version"`
	EncryptedSize    int64             `json:"encrypted_size"`
	OriginalSize     int64             `json:"original_size"`
	Compressed       bool              `json:"compressed"`
	EncryptionTime   time.Time         `json:"encryption_time"`
	AdditionalData   map[string]string `json:"additional_data"`
}

// ToHeaders converts encryption metadata to HTTP headers
func (em *EncryptionMetadata) ToHeaders() map[string]string {
	headers := make(map[string]string)
	
	if em.IsEncrypted {
		headers["X-IPFS-Encryption"] = "true"
		headers["X-IPFS-Encryption-Algorithm"] = em.Algorithm
		headers["X-IPFS-Encryption-Key-Version"] = fmt.Sprintf("%d", em.KeyVersion)
		headers["X-IPFS-Original-Size"] = fmt.Sprintf("%d", em.OriginalSize)
		
		if em.Compressed {
			headers["X-IPFS-Compressed"] = "true"
		}
		
		// Add additional metadata
		for key, value := range em.AdditionalData {
			headers[fmt.Sprintf("X-IPFS-Meta-%s", key)] = value
		}
	}
	
	return headers
}

// FromHeaders creates encryption metadata from HTTP headers
func EncryptionMetadataFromHeaders(headers map[string]string) *EncryptionMetadata {
	em := &EncryptionMetadata{
		AdditionalData: make(map[string]string),
	}
	
	if headers["X-IPFS-Encryption"] == "true" {
		em.IsEncrypted = true
		em.Algorithm = headers["X-IPFS-Encryption-Algorithm"]
		
		if keyVersion := headers["X-IPFS-Encryption-Key-Version"]; keyVersion != "" {
			fmt.Sscanf(keyVersion, "%d", &em.KeyVersion)
		}
		
		if originalSize := headers["X-IPFS-Original-Size"]; originalSize != "" {
			fmt.Sscanf(originalSize, "%d", &em.OriginalSize)
		}
		
		em.Compressed = headers["X-IPFS-Compressed"] == "true"
		
		// Extract additional metadata
		for key, value := range headers {
			if len(key) > 12 && key[:12] == "X-IPFS-Meta-" {
				metaKey := key[12:]
				em.AdditionalData[metaKey] = value
			}
		}
	}
	
	return em
}

// Utility functions for compression (placeholder implementations)
func compressData(data []byte) ([]byte, error) {
	// Placeholder - implement actual compression (gzip, lz4, etc.)
	return data, nil
}

func decompressData(data []byte) ([]byte, error) {
	// Placeholder - implement actual decompression
	return data, nil
}

// SerializeEncryptedData serializes encrypted data to bytes
func SerializeEncryptedData(encData *EncryptedData) ([]byte, error) {
	return json.Marshal(encData)
}

// DeserializeEncryptedData deserializes encrypted data from bytes
func DeserializeEncryptedData(data []byte) (*EncryptedData, error) {
	var encData EncryptedData
	if err := json.Unmarshal(data, &encData); err != nil {
		return nil, fmt.Errorf("failed to deserialize encrypted data: %w", err)
	}
	return &encData, nil
}

// GetEncryptionKeyHash returns a hash of the encryption key for verification
func (em *EncryptionManager) GetEncryptionKeyHash(algorithm string) (string, error) {
	key, err := em.keyManager.GetKey(algorithm)
	if err != nil {
		return "", err
	}
	
	hash := sha256.Sum256(key.Key)
	return base64.StdEncoding.EncodeToString(hash[:8]), nil
}