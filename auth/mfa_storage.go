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

package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MFAStorage defines the interface for MFA data persistence
type MFAStorage interface {
	// StoreMFAData stores MFA data for a user
	StoreMFAData(userID string, data *MFAUserData) error
	
	// GetMFAData retrieves MFA data for a user
	GetMFAData(userID string) (*MFAUserData, error)
	
	// DeleteMFAData removes MFA data for a user
	DeleteMFAData(userID string) error
	
	// ListMFAUsers returns a list of users with MFA enabled
	ListMFAUsers() ([]string, error)
	
	// UpdateLastUsed updates the last used timestamp for a user
	UpdateLastUsed(userID string, timestamp time.Time) error
	
	// UpdateFailedAttempts updates the failed attempts count and lockout status
	UpdateFailedAttempts(userID string, attempts int, lockedUntil *time.Time) error
	
	// Close closes the storage connection
	Close() error
}

// FileMFAStorage implements MFA storage using the filesystem
type FileMFAStorage struct {
	baseDir string
	mutex   sync.RWMutex
}

// NewFileMFAStorage creates a new file-based MFA storage
func NewFileMFAStorage(baseDir string) (*FileMFAStorage, error) {
	if baseDir == "" {
		return nil, errors.New("base directory cannot be empty")
	}
	
	// Create directory if it doesn't exist
	mfaDir := filepath.Join(baseDir, "mfa")
	if err := os.MkdirAll(mfaDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create MFA directory: %w", err)
	}
	
	return &FileMFAStorage{
		baseDir: mfaDir,
	}, nil
}

// StoreMFAData stores MFA data for a user
func (f *FileMFAStorage) StoreMFAData(userID string, data *MFAUserData) error {
	if userID == "" {
		return errors.New("userID cannot be empty")
	}
	
	if data == nil {
		return errors.New("MFA data cannot be nil")
	}
	
	f.mutex.Lock()
	defer f.mutex.Unlock()
	
	// Update timestamps
	now := time.Now()
	if data.CreatedAt.IsZero() {
		data.CreatedAt = now
	}
	data.UpdatedAt = now
	
	// Serialize data
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal MFA data: %w", err)
	}
	
	// Write to file
	filename := f.getUserFilename(userID)
	if err := os.WriteFile(filename, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write MFA data file: %w", err)
	}
	
	return nil
}

// GetMFAData retrieves MFA data for a user
func (f *FileMFAStorage) GetMFAData(userID string) (*MFAUserData, error) {
	if userID == "" {
		return nil, errors.New("userID cannot be empty")
	}
	
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	
	filename := f.getUserFilename(userID)
	
	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, ErrMFANotEnabled
	}
	
	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read MFA data file: %w", err)
	}
	
	// Deserialize data
	var mfaData MFAUserData
	if err := json.Unmarshal(data, &mfaData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MFA data: %w", err)
	}
	
	return &mfaData, nil
}

// DeleteMFAData removes MFA data for a user
func (f *FileMFAStorage) DeleteMFAData(userID string) error {
	if userID == "" {
		return errors.New("userID cannot be empty")
	}
	
	f.mutex.Lock()
	defer f.mutex.Unlock()
	
	filename := f.getUserFilename(userID)
	
	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return ErrMFANotEnabled
	}
	
	// Remove file
	if err := os.Remove(filename); err != nil {
		return fmt.Errorf("failed to delete MFA data file: %w", err)
	}
	
	return nil
}

// ListMFAUsers returns a list of users with MFA enabled
func (f *FileMFAStorage) ListMFAUsers() ([]string, error) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	
	entries, err := os.ReadDir(f.baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read MFA directory: %w", err)
	}
	
	var users []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		
		name := entry.Name()
		if filepath.Ext(name) == ".json" {
			// Extract user ID from filename (remove .json extension)
			userID := name[:len(name)-5]
			users = append(users, userID)
		}
	}
	
	return users, nil
}

// UpdateLastUsed updates the last used timestamp for a user
func (f *FileMFAStorage) UpdateLastUsed(userID string, timestamp time.Time) error {
	data, err := f.GetMFAData(userID)
	if err != nil {
		return err
	}
	
	data.LastUsed = timestamp
	data.FailedAttempts = 0 // Reset failed attempts on successful use
	data.LockedUntil = nil  // Clear lockout
	
	return f.StoreMFAData(userID, data)
}

// UpdateFailedAttempts updates the failed attempts count and lockout status
func (f *FileMFAStorage) UpdateFailedAttempts(userID string, attempts int, lockedUntil *time.Time) error {
	data, err := f.GetMFAData(userID)
	if err != nil {
		return err
	}
	
	data.FailedAttempts = attempts
	data.LockedUntil = lockedUntil
	
	return f.StoreMFAData(userID, data)
}

// Close closes the storage connection (no-op for file storage)
func (f *FileMFAStorage) Close() error {
	return nil
}

// getUserFilename returns the filename for a user's MFA data
func (f *FileMFAStorage) getUserFilename(userID string) string {
	// Hash the user ID to avoid filesystem issues with special characters
	hash := sha256.Sum256([]byte(userID))
	hashedID := hex.EncodeToString(hash[:])
	return filepath.Join(f.baseDir, hashedID+".json")
}

// MemoryMFAStorage implements MFA storage using in-memory storage (for testing)
type MemoryMFAStorage struct {
	data  map[string]*MFAUserData
	mutex sync.RWMutex
}

// NewMemoryMFAStorage creates a new in-memory MFA storage
func NewMemoryMFAStorage() *MemoryMFAStorage {
	return &MemoryMFAStorage{
		data: make(map[string]*MFAUserData),
	}
}

// StoreMFAData stores MFA data for a user
func (m *MemoryMFAStorage) StoreMFAData(userID string, data *MFAUserData) error {
	if userID == "" {
		return errors.New("userID cannot be empty")
	}
	
	if data == nil {
		return errors.New("MFA data cannot be nil")
	}
	
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Update timestamps
	now := time.Now()
	if data.CreatedAt.IsZero() {
		data.CreatedAt = now
	}
	data.UpdatedAt = now
	
	// Create a copy to avoid external modifications
	dataCopy := *data
	m.data[userID] = &dataCopy
	
	return nil
}

// GetMFAData retrieves MFA data for a user
func (m *MemoryMFAStorage) GetMFAData(userID string) (*MFAUserData, error) {
	if userID == "" {
		return nil, errors.New("userID cannot be empty")
	}
	
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	data, exists := m.data[userID]
	if !exists {
		return nil, ErrMFANotEnabled
	}
	
	// Return a copy to avoid external modifications
	dataCopy := *data
	return &dataCopy, nil
}

// DeleteMFAData removes MFA data for a user
func (m *MemoryMFAStorage) DeleteMFAData(userID string) error {
	if userID == "" {
		return errors.New("userID cannot be empty")
	}
	
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if _, exists := m.data[userID]; !exists {
		return ErrMFANotEnabled
	}
	
	delete(m.data, userID)
	return nil
}

// ListMFAUsers returns a list of users with MFA enabled
func (m *MemoryMFAStorage) ListMFAUsers() ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	users := make([]string, 0, len(m.data))
	for userID := range m.data {
		users = append(users, userID)
	}
	
	return users, nil
}

// UpdateLastUsed updates the last used timestamp for a user
func (m *MemoryMFAStorage) UpdateLastUsed(userID string, timestamp time.Time) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	data, exists := m.data[userID]
	if !exists {
		return ErrMFANotEnabled
	}
	
	data.LastUsed = timestamp
	data.FailedAttempts = 0 // Reset failed attempts on successful use
	data.LockedUntil = nil  // Clear lockout
	data.UpdatedAt = time.Now()
	
	return nil
}

// UpdateFailedAttempts updates the failed attempts count and lockout status
func (m *MemoryMFAStorage) UpdateFailedAttempts(userID string, attempts int, lockedUntil *time.Time) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	data, exists := m.data[userID]
	if !exists {
		return ErrMFANotEnabled
	}
	
	data.FailedAttempts = attempts
	data.LockedUntil = lockedUntil
	data.UpdatedAt = time.Now()
	
	return nil
}

// Close closes the storage connection (no-op for memory storage)
func (m *MemoryMFAStorage) Close() error {
	return nil
}