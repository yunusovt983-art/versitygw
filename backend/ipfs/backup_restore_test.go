package ipfs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewBackupRestoreManager(t *testing.T) {
	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()

	brm := NewBackupRestoreManager(mockMetadata, nil, logger)

	assert.NotNil(t, brm)
	assert.Equal(t, mockMetadata, brm.metadataStore)
	assert.NotNil(t, brm.config)
	assert.Equal(t, "/var/lib/versitygw/backups", brm.config.BackupDirectory)
	assert.Equal(t, 24*time.Hour, brm.config.BackupInterval)
	assert.True(t, brm.config.CompressionEnabled)
}

func TestBackupRestoreManager_CreateFullBackup(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "backup_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()

	config := &BackupConfig{
		BackupDirectory:    tempDir,
		CompressionEnabled: false, // Disable compression for easier testing
		VerifyBackup:       false, // Disable verification for this test
	}

	brm := NewBackupRestoreManager(mockMetadata, config, logger)

	// Mock data
	testMappings := []*ObjectMapping{
		{
			S3Key:       "test-key-1",
			Bucket:      "test-bucket",
			CID:         "QmTest123",
			Size:        1024,
			ContentType: "text/plain",
			CreatedAt:   time.Now(),
		},
		{
			S3Key:       "test-key-2",
			Bucket:      "test-bucket",
			CID:         "QmTest456",
			Size:        2048,
			ContentType: "application/json",
			CreatedAt:   time.Now(),
		},
	}

	mockMetadata.On("GetAllMappings", mock.Anything).Return(testMappings, nil)

	ctx := context.Background()
	err = brm.CreateBackup(ctx, BackupTypeFull)
	assert.NoError(t, err)

	// Verify backup file was created
	files, err := filepath.Glob(filepath.Join(tempDir, "metadata_backup_*.json"))
	require.NoError(t, err)
	require.Len(t, files, 1)

	// Verify backup content
	backupFile := files[0]
	file, err := os.Open(backupFile)
	require.NoError(t, err)
	defer file.Close()

	decoder := json.NewDecoder(file)

	// Read backup metadata
	var backupMetadata BackupMetadata
	err = decoder.Decode(&backupMetadata)
	require.NoError(t, err)

	assert.Equal(t, "1.0", backupMetadata.Version)
	assert.Equal(t, BackupTypeFull, backupMetadata.BackupType)
	assert.Equal(t, int64(2), backupMetadata.RecordCount)

	// Read mappings
	mappingsRead := 0
	for {
		var mapping ObjectMapping
		if err := decoder.Decode(&mapping); err != nil {
			break
		}
		mappingsRead++
		
		// Verify mapping data
		found := false
		for _, testMapping := range testMappings {
			if mapping.S3Key == testMapping.S3Key && mapping.CID == testMapping.CID {
				found = true
				assert.Equal(t, testMapping.Bucket, mapping.Bucket)
				assert.Equal(t, testMapping.Size, mapping.Size)
				assert.Equal(t, testMapping.ContentType, mapping.ContentType)
				break
			}
		}
		assert.True(t, found, "Mapping not found in test data")
	}

	assert.Equal(t, len(testMappings), mappingsRead)

	// Verify statistics
	stats := brm.GetBackupStatistics()
	assert.Equal(t, int64(1), stats.TotalBackups)
	assert.Equal(t, int64(1), stats.SuccessfulBackups)
	assert.Equal(t, int64(0), stats.FailedBackups)

	mockMetadata.AssertExpectations(t)
}

func TestBackupRestoreManager_CreateIncrementalBackup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "backup_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()

	config := &BackupConfig{
		BackupDirectory:    tempDir,
		CompressionEnabled: false,
		VerifyBackup:       false,
	}

	brm := NewBackupRestoreManager(mockMetadata, config, logger)

	// Set last backup time
	lastBackupTime := time.Now().Add(-1 * time.Hour)
	brm.mu.Lock()
	brm.lastBackupTime = lastBackupTime
	brm.mu.Unlock()

	// Mock incremental data
	incrementalMappings := []*ObjectMapping{
		{
			S3Key:     "new-key",
			Bucket:    "test-bucket",
			CID:       "QmNew123",
			Size:      512,
			CreatedAt: time.Now(),
		},
	}

	mockMetadata.On("GetMappingsModifiedSince", mock.Anything, lastBackupTime).Return(incrementalMappings, nil)

	ctx := context.Background()
	err = brm.CreateBackup(ctx, BackupTypeIncremental)
	assert.NoError(t, err)

	// Verify backup file
	files, err := filepath.Glob(filepath.Join(tempDir, "metadata_backup_*_1.json"))
	require.NoError(t, err)
	require.Len(t, files, 1)

	// Verify content
	file, err := os.Open(files[0])
	require.NoError(t, err)
	defer file.Close()

	decoder := json.NewDecoder(file)

	var backupMetadata BackupMetadata
	err = decoder.Decode(&backupMetadata)
	require.NoError(t, err)

	assert.Equal(t, BackupTypeIncremental, backupMetadata.BackupType)
	assert.Equal(t, int64(1), backupMetadata.RecordCount)

	mockMetadata.AssertExpectations(t)
}

func TestBackupRestoreManager_RestoreBackup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "restore_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()

	// Create test backup file
	backupFile := filepath.Join(tempDir, "test_backup.json")
	file, err := os.Create(backupFile)
	require.NoError(t, err)

	encoder := json.NewEncoder(file)

	// Write backup metadata
	backupMetadata := BackupMetadata{
		Version:     "1.0",
		Timestamp:   time.Now(),
		BackupType:  BackupTypeFull,
		RecordCount: 2,
	}
	err = encoder.Encode(backupMetadata)
	require.NoError(t, err)

	// Write test mappings
	testMappings := []ObjectMapping{
		{
			S3Key:       "restore-key-1",
			Bucket:      "restore-bucket",
			CID:         "QmRestore123",
			Size:        1024,
			ContentType: "text/plain",
		},
		{
			S3Key:       "restore-key-2",
			Bucket:      "restore-bucket",
			CID:         "QmRestore456",
			Size:        2048,
			ContentType: "application/json",
		},
	}

	for _, mapping := range testMappings {
		err = encoder.Encode(mapping)
		require.NoError(t, err)
	}

	file.Close()

	// Mock metadata store calls
	mockMetadata.On("GetMapping", "restore-key-1", "restore-bucket").Return(nil, assert.AnError) // Not exists
	mockMetadata.On("GetMapping", "restore-key-2", "restore-bucket").Return(nil, assert.AnError) // Not exists
	mockMetadata.On("StoreMapping", mock.MatchedBy(func(mapping *ObjectMapping) bool {
		return mapping.S3Key == "restore-key-1" || mapping.S3Key == "restore-key-2"
	})).Return(nil).Times(2)

	brm := NewBackupRestoreManager(mockMetadata, nil, logger)

	options := &RestoreOptions{
		BackupPath:        backupFile,
		VerifyIntegrity:   false,
		DryRun:            false,
		OverwriteExisting: false,
	}

	ctx := context.Background()
	err = brm.RestoreBackup(ctx, options)
	assert.NoError(t, err)

	mockMetadata.AssertExpectations(t)
}

func TestBackupRestoreManager_RestoreWithFilter(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "restore_filter_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()

	// Create test backup file
	backupFile := filepath.Join(tempDir, "test_backup.json")
	file, err := os.Create(backupFile)
	require.NoError(t, err)

	encoder := json.NewEncoder(file)

	// Write backup metadata
	backupMetadata := BackupMetadata{
		Version:     "1.0",
		Timestamp:   time.Now(),
		BackupType:  BackupTypeFull,
		RecordCount: 3,
	}
	err = encoder.Encode(backupMetadata)
	require.NoError(t, err)

	// Write test mappings
	testMappings := []ObjectMapping{
		{
			S3Key:     "bucket1/key1",
			Bucket:    "bucket1",
			CID:       "QmTest1",
			CreatedAt: time.Now().Add(-2 * time.Hour),
		},
		{
			S3Key:     "bucket2/key2",
			Bucket:    "bucket2",
			CID:       "QmTest2",
			CreatedAt: time.Now().Add(-1 * time.Hour),
		},
		{
			S3Key:     "bucket1/key3",
			Bucket:    "bucket1",
			CID:       "QmTest3",
			CreatedAt: time.Now(),
		},
	}

	for _, mapping := range testMappings {
		err = encoder.Encode(mapping)
		require.NoError(t, err)
	}

	file.Close()

	// Mock only bucket1 mappings should be restored
	mockMetadata.On("GetMapping", "bucket1/key1", "bucket1").Return(nil, assert.AnError)
	mockMetadata.On("GetMapping", "bucket1/key3", "bucket1").Return(nil, assert.AnError)
	mockMetadata.On("StoreMapping", mock.MatchedBy(func(mapping *ObjectMapping) bool {
		return mapping.Bucket == "bucket1"
	})).Return(nil).Times(2)

	brm := NewBackupRestoreManager(mockMetadata, nil, logger)

	options := &RestoreOptions{
		BackupPath:      backupFile,
		VerifyIntegrity: false,
		DryRun:          false,
		RestoreFilter: &RestoreFilter{
			Buckets: []string{"bucket1"},
		},
	}

	ctx := context.Background()
	err = brm.RestoreBackup(ctx, options)
	assert.NoError(t, err)

	mockMetadata.AssertExpectations(t)
}

func TestBackupRestoreManager_DryRunRestore(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dry_run_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()

	// Create test backup file
	backupFile := filepath.Join(tempDir, "test_backup.json")
	file, err := os.Create(backupFile)
	require.NoError(t, err)

	encoder := json.NewEncoder(file)

	backupMetadata := BackupMetadata{
		Version:     "1.0",
		Timestamp:   time.Now(),
		BackupType:  BackupTypeFull,
		RecordCount: 1,
	}
	err = encoder.Encode(backupMetadata)
	require.NoError(t, err)

	testMapping := ObjectMapping{
		S3Key:  "dry-run-key",
		Bucket: "dry-run-bucket",
		CID:    "QmDryRun123",
	}
	err = encoder.Encode(testMapping)
	require.NoError(t, err)

	file.Close()

	// No metadata store calls should be made for dry run
	brm := NewBackupRestoreManager(mockMetadata, nil, logger)

	options := &RestoreOptions{
		BackupPath:      backupFile,
		VerifyIntegrity: false,
		DryRun:          true,
	}

	ctx := context.Background()
	err = brm.RestoreBackup(ctx, options)
	assert.NoError(t, err)

	// Verify no calls were made to metadata store
	mockMetadata.AssertNotCalled(t, "StoreMapping")
}

func TestBackupRestoreManager_CompressedBackup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "compressed_backup_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()

	config := &BackupConfig{
		BackupDirectory:    tempDir,
		CompressionEnabled: true,
		VerifyBackup:       false,
	}

	brm := NewBackupRestoreManager(mockMetadata, config, logger)

	testMappings := []*ObjectMapping{
		{
			S3Key:  "compressed-key",
			Bucket: "compressed-bucket",
			CID:    "QmCompressed123",
			Size:   1024,
		},
	}

	mockMetadata.On("GetAllMappings", mock.Anything).Return(testMappings, nil)

	ctx := context.Background()
	err = brm.CreateBackup(ctx, BackupTypeFull)
	assert.NoError(t, err)

	// Verify compressed backup file was created
	files, err := filepath.Glob(filepath.Join(tempDir, "metadata_backup_*.json.gz"))
	require.NoError(t, err)
	require.Len(t, files, 1)

	// Verify we can restore from compressed backup
	mockMetadata.On("GetMapping", "compressed-key", "compressed-bucket").Return(nil, assert.AnError)
	mockMetadata.On("StoreMapping", mock.MatchedBy(func(mapping *ObjectMapping) bool {
		return mapping.S3Key == "compressed-key"
	})).Return(nil)

	options := &RestoreOptions{
		BackupPath:      files[0],
		VerifyIntegrity: false,
		DryRun:          false,
	}

	err = brm.RestoreBackup(ctx, options)
	assert.NoError(t, err)

	mockMetadata.AssertExpectations(t)
}

func TestBackupRestoreManager_BackupVerification(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "verification_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()

	config := &BackupConfig{
		BackupDirectory:    tempDir,
		CompressionEnabled: false,
		VerifyBackup:       true,
	}

	brm := NewBackupRestoreManager(mockMetadata, config, logger)

	testMappings := []*ObjectMapping{
		{
			S3Key:  "verify-key",
			Bucket: "verify-bucket",
			CID:    "QmVerify123",
		},
	}

	mockMetadata.On("GetAllMappings", mock.Anything).Return(testMappings, nil)

	ctx := context.Background()
	err = brm.CreateBackup(ctx, BackupTypeFull)
	assert.NoError(t, err)

	// Backup should succeed with verification
	stats := brm.GetBackupStatistics()
	assert.Equal(t, int64(1), stats.SuccessfulBackups)
	assert.Equal(t, int64(0), stats.FailedBackups)

	mockMetadata.AssertExpectations(t)
}

func TestBackupRestoreManager_ListBackups(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "list_backups_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()

	config := &BackupConfig{
		BackupDirectory:    tempDir,
		CompressionEnabled: false,
		VerifyBackup:       false,
	}

	brm := NewBackupRestoreManager(mockMetadata, config, logger)

	// Create multiple backups
	testMappings := []*ObjectMapping{
		{S3Key: "key1", Bucket: "bucket1", CID: "QmTest1"},
		{S3Key: "key2", Bucket: "bucket1", CID: "QmTest2"},
	}

	mockMetadata.On("GetAllMappings", mock.Anything).Return(testMappings, nil).Times(2)

	ctx := context.Background()
	
	// Create full backup
	err = brm.CreateBackup(ctx, BackupTypeFull)
	assert.NoError(t, err)

	time.Sleep(10 * time.Millisecond) // Ensure different timestamps

	// Create incremental backup
	brm.mu.Lock()
	brm.lastBackupTime = time.Now().Add(-1 * time.Hour)
	brm.mu.Unlock()

	mockMetadata.On("GetMappingsModifiedSince", mock.Anything, mock.Anything).Return(testMappings[:1], nil)
	err = brm.CreateBackup(ctx, BackupTypeIncremental)
	assert.NoError(t, err)

	// List backups
	backups, err := brm.ListBackups()
	assert.NoError(t, err)
	assert.Len(t, backups, 2)

	// Verify backup info
	fullBackupFound := false
	incrementalBackupFound := false

	for _, backup := range backups {
		assert.True(t, strings.Contains(backup.Path, "metadata_backup_"))
		assert.Greater(t, backup.Size, int64(0))
		assert.False(t, backup.Timestamp.IsZero())

		if backup.Type == BackupTypeFull {
			fullBackupFound = true
			assert.Equal(t, int64(2), backup.RecordCount)
		} else if backup.Type == BackupTypeIncremental {
			incrementalBackupFound = true
			assert.Equal(t, int64(1), backup.RecordCount)
		}
	}

	assert.True(t, fullBackupFound, "Full backup not found in list")
	assert.True(t, incrementalBackupFound, "Incremental backup not found in list")

	mockMetadata.AssertExpectations(t)
}

func TestBackupRestoreManager_CleanupOldBackups(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cleanup_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()

	config := &BackupConfig{
		BackupDirectory: tempDir,
		RetentionPeriod: 1 * time.Hour, // Short retention for testing
	}

	brm := NewBackupRestoreManager(mockMetadata, config, logger)

	// Create old backup file
	oldBackupFile := filepath.Join(tempDir, "metadata_backup_old_0.json")
	file, err := os.Create(oldBackupFile)
	require.NoError(t, err)
	file.Close()

	// Set file modification time to be older than retention period
	oldTime := time.Now().Add(-2 * time.Hour)
	err = os.Chtimes(oldBackupFile, oldTime, oldTime)
	require.NoError(t, err)

	// Create recent backup file
	recentBackupFile := filepath.Join(tempDir, "metadata_backup_recent_0.json")
	file, err = os.Create(recentBackupFile)
	require.NoError(t, err)
	file.Close()

	// Run cleanup
	err = brm.cleanupOldBackups()
	assert.NoError(t, err)

	// Verify old backup was deleted
	_, err = os.Stat(oldBackupFile)
	assert.True(t, os.IsNotExist(err))

	// Verify recent backup still exists
	_, err = os.Stat(recentBackupFile)
	assert.NoError(t, err)
}

// Benchmark tests

func BenchmarkBackupRestoreManager_CreateBackup(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "benchmark_backup")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	mockMetadata := &MockMetadataStore{}
	logger := logrus.New()

	config := &BackupConfig{
		BackupDirectory:    tempDir,
		CompressionEnabled: false,
		VerifyBackup:       false,
	}

	brm := NewBackupRestoreManager(mockMetadata, config, logger)

	// Create test data
	testMappings := make([]*ObjectMapping, 1000)
	for i := 0; i < 1000; i++ {
		testMappings[i] = &ObjectMapping{
			S3Key:  fmt.Sprintf("key-%d", i),
			Bucket: "benchmark-bucket",
			CID:    fmt.Sprintf("QmBenchmark%d", i),
			Size:   int64(i * 1024),
		}
	}

	mockMetadata.On("GetAllMappings", mock.Anything).Return(testMappings, nil)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := brm.CreateBackup(ctx, BackupTypeFull)
		if err != nil {
			b.Fatal(err)
		}
		
		// Clean up backup file
		files, _ := filepath.Glob(filepath.Join(tempDir, "metadata_backup_*.json"))
		for _, file := range files {
			os.Remove(file)
		}
	}
}