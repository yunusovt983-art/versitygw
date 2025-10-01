package ipfs

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// BackupRestoreManager handles backup and restore operations for metadata
type BackupRestoreManager struct {
	metadataStore MetadataStore
	config        *BackupConfig
	logger        *logrus.Logger
	
	// State management
	mu              sync.RWMutex
	isBackupRunning bool
	lastBackupTime  time.Time
	backupStats     BackupStatistics
}

type BackupConfig struct {
	BackupDirectory     string        `json:"backup_directory"`
	BackupInterval      time.Duration `json:"backup_interval"`
	RetentionPeriod     time.Duration `json:"retention_period"`
	CompressionEnabled  bool          `json:"compression_enabled"`
	IncrementalBackup   bool          `json:"incremental_backup"`
	MaxBackupSize       int64         `json:"max_backup_size"`
	BackupBatchSize     int           `json:"backup_batch_size"`
	VerifyBackup        bool          `json:"verify_backup"`
	EncryptionEnabled   bool          `json:"encryption_enabled"`
	EncryptionKey       string        `json:"encryption_key"`
}

type BackupStatistics struct {
	TotalBackups        int64     `json:"total_backups"`
	SuccessfulBackups   int64     `json:"successful_backups"`
	FailedBackups       int64     `json:"failed_backups"`
	LastBackupTime      time.Time `json:"last_backup_time"`
	LastBackupDuration  time.Duration `json:"last_backup_duration"`
	LastBackupSize      int64     `json:"last_backup_size"`
	TotalBackupSize     int64     `json:"total_backup_size"`
}

type BackupMetadata struct {
	Version       string            `json:"version"`
	Timestamp     time.Time         `json:"timestamp"`
	BackupType    BackupType        `json:"backup_type"`
	RecordCount   int64             `json:"record_count"`
	Checksum      string            `json:"checksum"`
	Compressed    bool              `json:"compressed"`
	Encrypted     bool              `json:"encrypted"`
	Dependencies  []string          `json:"dependencies"`
	Metadata      map[string]string `json:"metadata"`
}

type BackupType int

const (
	BackupTypeFull BackupType = iota
	BackupTypeIncremental
	BackupTypeDifferential
)

type RestoreOptions struct {
	BackupPath        string    `json:"backup_path"`
	RestorePoint      time.Time `json:"restore_point"`
	VerifyIntegrity   bool      `json:"verify_integrity"`
	DryRun            bool      `json:"dry_run"`
	OverwriteExisting bool      `json:"overwrite_existing"`
	RestoreFilter     *RestoreFilter `json:"restore_filter"`
}

type RestoreFilter struct {
	Buckets    []string `json:"buckets"`
	KeyPrefix  string   `json:"key_prefix"`
	DateRange  *DateRange `json:"date_range"`
}

type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// NewBackupRestoreManager creates a new backup/restore manager
func NewBackupRestoreManager(
	metadataStore MetadataStore,
	config *BackupConfig,
	logger *logrus.Logger,
) *BackupRestoreManager {
	if config == nil {
		config = &BackupConfig{
			BackupDirectory:    "/var/lib/versitygw/backups",
			BackupInterval:     24 * time.Hour,
			RetentionPeriod:    30 * 24 * time.Hour,
			CompressionEnabled: true,
			IncrementalBackup:  true,
			MaxBackupSize:      10 * 1024 * 1024 * 1024, // 10GB
			BackupBatchSize:    10000,
			VerifyBackup:       true,
		}
	}

	return &BackupRestoreManager{
		metadataStore: metadataStore,
		config:        config,
		logger:        logger,
	}
}

// Start begins the backup scheduler
func (brm *BackupRestoreManager) Start(ctx context.Context) error {
	brm.logger.Info("Starting backup/restore manager")

	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(brm.config.BackupDirectory, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Start periodic backup scheduler
	go brm.runBackupScheduler(ctx)

	// Start cleanup scheduler
	go brm.runCleanupScheduler(ctx)

	return nil
}

// Stop gracefully shuts down the backup/restore manager
func (brm *BackupRestoreManager) Stop(ctx context.Context) error {
	brm.logger.Info("Stopping backup/restore manager")

	// Wait for any running backup to complete
	brm.mu.RLock()
	isRunning := brm.isBackupRunning
	brm.mu.RUnlock()

	if isRunning {
		brm.logger.Info("Waiting for backup to complete")
		// Wait with timeout
		timeout := time.NewTimer(5 * time.Minute)
		ticker := time.NewTicker(1 * time.Second)
		defer timeout.Stop()
		defer ticker.Stop()

		for {
			select {
			case <-timeout.C:
				brm.logger.Warn("Backup did not complete within timeout")
				return nil
			case <-ticker.C:
				brm.mu.RLock()
				if !brm.isBackupRunning {
					brm.mu.RUnlock()
					return nil
				}
				brm.mu.RUnlock()
			}
		}
	}

	return nil
}

// CreateBackup creates a backup of the metadata
func (brm *BackupRestoreManager) CreateBackup(ctx context.Context, backupType BackupType) error {
	brm.mu.Lock()
	if brm.isBackupRunning {
		brm.mu.Unlock()
		return fmt.Errorf("backup is already running")
	}
	brm.isBackupRunning = true
	brm.mu.Unlock()

	defer func() {
		brm.mu.Lock()
		brm.isBackupRunning = false
		brm.mu.Unlock()
	}()

	startTime := time.Now()
	brm.logger.WithField("backup_type", backupType).Info("Starting backup")

	// Generate backup filename
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("metadata_backup_%s_%d.json", timestamp, backupType)
	if brm.config.CompressionEnabled {
		filename += ".gz"
	}
	backupPath := filepath.Join(brm.config.BackupDirectory, filename)

	// Create backup file
	file, err := os.Create(backupPath)
	if err != nil {
		brm.backupStats.FailedBackups++
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer file.Close()

	var writer io.Writer = file
	var gzipWriter *gzip.Writer

	// Add compression if enabled
	if brm.config.CompressionEnabled {
		gzipWriter = gzip.NewWriter(file)
		writer = gzipWriter
		defer gzipWriter.Close()
	}

	// Create backup metadata
	backupMetadata := &BackupMetadata{
		Version:    "1.0",
		Timestamp:  time.Now(),
		BackupType: backupType,
		Compressed: brm.config.CompressionEnabled,
		Encrypted:  brm.config.EncryptionEnabled,
	}

	// Write backup metadata header
	encoder := json.NewEncoder(writer)
	if err := encoder.Encode(backupMetadata); err != nil {
		brm.backupStats.FailedBackups++
		return fmt.Errorf("failed to write backup metadata: %w", err)
	}

	// Backup data based on type
	var recordCount int64
	switch backupType {
	case BackupTypeFull:
		recordCount, err = brm.createFullBackup(ctx, encoder)
	case BackupTypeIncremental:
		recordCount, err = brm.createIncrementalBackup(ctx, encoder)
	case BackupTypeDifferential:
		recordCount, err = brm.createDifferentialBackup(ctx, encoder)
	default:
		err = fmt.Errorf("unknown backup type: %d", backupType)
	}

	if err != nil {
		brm.backupStats.FailedBackups++
		return fmt.Errorf("backup failed: %w", err)
	}

	// Close gzip writer if used
	if gzipWriter != nil {
		if err := gzipWriter.Close(); err != nil {
			brm.backupStats.FailedBackups++
			return fmt.Errorf("failed to close gzip writer: %w", err)
		}
	}

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		brm.logger.WithError(err).Warn("Failed to get backup file size")
	}

	// Verify backup if enabled
	if brm.config.VerifyBackup {
		if err := brm.verifyBackup(backupPath); err != nil {
			brm.backupStats.FailedBackups++
			return fmt.Errorf("backup verification failed: %w", err)
		}
	}

	// Update statistics
	duration := time.Since(startTime)
	brm.mu.Lock()
	brm.backupStats.TotalBackups++
	brm.backupStats.SuccessfulBackups++
	brm.backupStats.LastBackupTime = startTime
	brm.backupStats.LastBackupDuration = duration
	if fileInfo != nil {
		brm.backupStats.LastBackupSize = fileInfo.Size()
		brm.backupStats.TotalBackupSize += fileInfo.Size()
	}
	brm.lastBackupTime = startTime
	brm.mu.Unlock()

	brm.logger.WithFields(logrus.Fields{
		"backup_path":   backupPath,
		"record_count":  recordCount,
		"duration":      duration,
		"size":          fileInfo.Size(),
	}).Info("Backup completed successfully")

	return nil
}

// RestoreBackup restores metadata from a backup
func (brm *BackupRestoreManager) RestoreBackup(ctx context.Context, options *RestoreOptions) error {
	brm.logger.WithField("backup_path", options.BackupPath).Info("Starting restore")

	if options.DryRun {
		brm.logger.Info("Performing dry run restore")
	}

	// Open backup file
	file, err := os.Open(options.BackupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file

	// Check if file is compressed
	if filepath.Ext(options.BackupPath) == ".gz" {
		gzipReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	decoder := json.NewDecoder(reader)

	// Read backup metadata
	var backupMetadata BackupMetadata
	if err := decoder.Decode(&backupMetadata); err != nil {
		return fmt.Errorf("failed to read backup metadata: %w", err)
	}

	brm.logger.WithFields(logrus.Fields{
		"version":      backupMetadata.Version,
		"timestamp":    backupMetadata.Timestamp,
		"backup_type":  backupMetadata.BackupType,
		"record_count": backupMetadata.RecordCount,
	}).Info("Backup metadata loaded")

	// Verify backup integrity if requested
	if options.VerifyIntegrity {
		if err := brm.verifyBackupIntegrity(&backupMetadata, decoder); err != nil {
			return fmt.Errorf("backup integrity verification failed: %w", err)
		}
	}

	// Restore data
	recordsRestored := int64(0)
	for {
		var mapping ObjectMapping
		if err := decoder.Decode(&mapping); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to decode mapping: %w", err)
		}

		// Apply restore filter
		if options.RestoreFilter != nil && !brm.shouldRestoreMapping(&mapping, options.RestoreFilter) {
			continue
		}

		// Restore mapping
		if !options.DryRun {
			if options.OverwriteExisting {
				if err := brm.metadataStore.StoreMapping(ctx, &mapping); err != nil {
					brm.logger.WithError(err).WithFields(logrus.Fields{
						"s3_key": mapping.S3Key,
						"bucket": mapping.Bucket,
					}).Warn("Failed to restore mapping")
					continue
				}
			} else {
				// Check if mapping already exists
				existing, err := brm.metadataStore.GetMapping(ctx, mapping.S3Key, mapping.Bucket)
				if err == nil && existing != nil {
					brm.logger.WithFields(logrus.Fields{
						"s3_key": mapping.S3Key,
						"bucket": mapping.Bucket,
					}).Debug("Skipping existing mapping")
					continue
				}

				if err := brm.metadataStore.StoreMapping(ctx, &mapping); err != nil {
					brm.logger.WithError(err).WithFields(logrus.Fields{
						"s3_key": mapping.S3Key,
						"bucket": mapping.Bucket,
					}).Warn("Failed to restore mapping")
					continue
				}
			}
		}

		recordsRestored++
	}

	brm.logger.WithField("records_restored", recordsRestored).Info("Restore completed successfully")
	return nil
}

// createFullBackup creates a full backup of all metadata
func (brm *BackupRestoreManager) createFullBackup(ctx context.Context, encoder *json.Encoder) (int64, error) {
	brm.logger.Info("Creating full backup")

	// Get all mappings from metadata store
	mappings, err := brm.metadataStore.GetAllMappings(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get all mappings: %w", err)
	}

	recordCount := int64(0)
	for _, mapping := range mappings {
		if err := encoder.Encode(mapping); err != nil {
			return recordCount, fmt.Errorf("failed to encode mapping: %w", err)
		}
		recordCount++

		// Check context cancellation
		select {
		case <-ctx.Done():
			return recordCount, ctx.Err()
		default:
		}
	}

	return recordCount, nil
}

// createIncrementalBackup creates an incremental backup since last backup
func (brm *BackupRestoreManager) createIncrementalBackup(ctx context.Context, encoder *json.Encoder) (int64, error) {
	brm.logger.Info("Creating incremental backup")

	brm.mu.RLock()
	lastBackupTime := brm.lastBackupTime
	brm.mu.RUnlock()

	if lastBackupTime.IsZero() {
		brm.logger.Info("No previous backup found, creating full backup")
		return brm.createFullBackup(ctx, encoder)
	}

	// Get mappings modified since last backup
	mappings, err := brm.metadataStore.GetMappingsModifiedSince(ctx, lastBackupTime)
	if err != nil {
		return 0, fmt.Errorf("failed to get modified mappings: %w", err)
	}

	recordCount := int64(0)
	for _, mapping := range mappings {
		if err := encoder.Encode(mapping); err != nil {
			return recordCount, fmt.Errorf("failed to encode mapping: %w", err)
		}
		recordCount++

		select {
		case <-ctx.Done():
			return recordCount, ctx.Err()
		default:
		}
	}

	return recordCount, nil
}

// createDifferentialBackup creates a differential backup
func (brm *BackupRestoreManager) createDifferentialBackup(ctx context.Context, encoder *json.Encoder) (int64, error) {
	brm.logger.Info("Creating differential backup")

	// Find the last full backup
	lastFullBackupTime, err := brm.findLastFullBackupTime()
	if err != nil {
		brm.logger.WithError(err).Info("No full backup found, creating full backup")
		return brm.createFullBackup(ctx, encoder)
	}

	// Get mappings modified since last full backup
	mappings, err := brm.metadataStore.GetMappingsModifiedSince(ctx, lastFullBackupTime)
	if err != nil {
		return 0, fmt.Errorf("failed to get modified mappings: %w", err)
	}

	recordCount := int64(0)
	for _, mapping := range mappings {
		if err := encoder.Encode(mapping); err != nil {
			return recordCount, fmt.Errorf("failed to encode mapping: %w", err)
		}
		recordCount++

		select {
		case <-ctx.Done():
			return recordCount, ctx.Err()
		default:
		}
	}

	return recordCount, nil
}

// runBackupScheduler runs the periodic backup scheduler
func (brm *BackupRestoreManager) runBackupScheduler(ctx context.Context) {
	ticker := time.NewTicker(brm.config.BackupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			backupType := BackupTypeFull
			if brm.config.IncrementalBackup {
				backupType = BackupTypeIncremental
			}

			if err := brm.CreateBackup(ctx, backupType); err != nil {
				brm.logger.WithError(err).Error("Scheduled backup failed")
			}
		}
	}
}

// runCleanupScheduler runs the backup cleanup scheduler
func (brm *BackupRestoreManager) runCleanupScheduler(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour) // Run cleanup daily
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := brm.cleanupOldBackups(); err != nil {
				brm.logger.WithError(err).Error("Backup cleanup failed")
			}
		}
	}
}

// cleanupOldBackups removes old backup files based on retention policy
func (brm *BackupRestoreManager) cleanupOldBackups() error {
	brm.logger.Info("Starting backup cleanup")

	files, err := filepath.Glob(filepath.Join(brm.config.BackupDirectory, "metadata_backup_*.json*"))
	if err != nil {
		return fmt.Errorf("failed to list backup files: %w", err)
	}

	cutoffTime := time.Now().Add(-brm.config.RetentionPeriod)
	deletedCount := 0

	for _, file := range files {
		fileInfo, err := os.Stat(file)
		if err != nil {
			brm.logger.WithError(err).WithField("file", file).Warn("Failed to stat backup file")
			continue
		}

		if fileInfo.ModTime().Before(cutoffTime) {
			if err := os.Remove(file); err != nil {
				brm.logger.WithError(err).WithField("file", file).Warn("Failed to delete old backup file")
			} else {
				brm.logger.WithField("file", file).Info("Deleted old backup file")
				deletedCount++
			}
		}
	}

	brm.logger.WithField("deleted_count", deletedCount).Info("Backup cleanup completed")
	return nil
}

// verifyBackup verifies the integrity of a backup file
func (brm *BackupRestoreManager) verifyBackup(backupPath string) error {
	brm.logger.WithField("backup_path", backupPath).Debug("Verifying backup")

	file, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file for verification: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file

	if filepath.Ext(backupPath) == ".gz" {
		gzipReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader for verification: %w", err)
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	decoder := json.NewDecoder(reader)

	// Read and verify metadata
	var backupMetadata BackupMetadata
	if err := decoder.Decode(&backupMetadata); err != nil {
		return fmt.Errorf("failed to read backup metadata during verification: %w", err)
	}

	// Count records
	recordCount := int64(0)
	for {
		var mapping ObjectMapping
		if err := decoder.Decode(&mapping); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to decode mapping during verification: %w", err)
		}
		recordCount++
	}

	if recordCount != backupMetadata.RecordCount {
		return fmt.Errorf("record count mismatch: expected %d, got %d", backupMetadata.RecordCount, recordCount)
	}

	brm.logger.WithFields(logrus.Fields{
		"backup_path":  backupPath,
		"record_count": recordCount,
	}).Debug("Backup verification completed")

	return nil
}

// verifyBackupIntegrity verifies the integrity of backup data
func (brm *BackupRestoreManager) verifyBackupIntegrity(metadata *BackupMetadata, decoder *json.Decoder) error {
	brm.logger.Info("Verifying backup integrity")

	// This would implement checksum verification, signature validation, etc.
	// For now, we'll just validate that we can read all records
	recordCount := int64(0)
	for {
		var mapping ObjectMapping
		if err := decoder.Decode(&mapping); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("integrity check failed: %w", err)
		}
		recordCount++
	}

	if recordCount != metadata.RecordCount {
		return fmt.Errorf("integrity check failed: record count mismatch")
	}

	return nil
}

// shouldRestoreMapping checks if a mapping should be restored based on filter
func (brm *BackupRestoreManager) shouldRestoreMapping(mapping *ObjectMapping, filter *RestoreFilter) bool {
	// Check bucket filter
	if len(filter.Buckets) > 0 {
		found := false
		for _, bucket := range filter.Buckets {
			if mapping.Bucket == bucket {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check key prefix filter
	if filter.KeyPrefix != "" {
		if !strings.HasPrefix(mapping.S3Key, filter.KeyPrefix) {
			return false
		}
	}

	// Check date range filter
	if filter.DateRange != nil {
		if mapping.CreatedAt.Before(filter.DateRange.Start) || mapping.CreatedAt.After(filter.DateRange.End) {
			return false
		}
	}

	return true
}

// findLastFullBackupTime finds the timestamp of the last full backup
func (brm *BackupRestoreManager) findLastFullBackupTime() (time.Time, error) {
	files, err := filepath.Glob(filepath.Join(brm.config.BackupDirectory, "metadata_backup_*_0.json*"))
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to list full backup files: %w", err)
	}

	if len(files) == 0 {
		return time.Time{}, fmt.Errorf("no full backup files found")
	}

	// Find the most recent full backup
	var latestTime time.Time
	for _, file := range files {
		fileInfo, err := os.Stat(file)
		if err != nil {
			continue
		}

		if fileInfo.ModTime().After(latestTime) {
			latestTime = fileInfo.ModTime()
		}
	}

	return latestTime, nil
}

// GetBackupStatistics returns backup statistics
func (brm *BackupRestoreManager) GetBackupStatistics() BackupStatistics {
	brm.mu.RLock()
	defer brm.mu.RUnlock()
	return brm.backupStats
}

// ListBackups returns a list of available backups
func (brm *BackupRestoreManager) ListBackups() ([]BackupInfo, error) {
	files, err := filepath.Glob(filepath.Join(brm.config.BackupDirectory, "metadata_backup_*.json*"))
	if err != nil {
		return nil, fmt.Errorf("failed to list backup files: %w", err)
	}

	backups := make([]BackupInfo, 0, len(files))
	for _, file := range files {
		fileInfo, err := os.Stat(file)
		if err != nil {
			continue
		}

		backup := BackupInfo{
			Path:      file,
			Size:      fileInfo.Size(),
			Timestamp: fileInfo.ModTime(),
		}

		// Try to read backup metadata
		if metadata, err := brm.readBackupMetadata(file); err == nil {
			backup.Type = metadata.BackupType
			backup.RecordCount = metadata.RecordCount
			backup.Compressed = metadata.Compressed
			backup.Encrypted = metadata.Encrypted
		}

		backups = append(backups, backup)
	}

	return backups, nil
}

// readBackupMetadata reads metadata from a backup file
func (brm *BackupRestoreManager) readBackupMetadata(backupPath string) (*BackupMetadata, error) {
	file, err := os.Open(backupPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var reader io.Reader = file

	if filepath.Ext(backupPath) == ".gz" {
		gzipReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	decoder := json.NewDecoder(reader)
	var metadata BackupMetadata
	if err := decoder.Decode(&metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

// BackupInfo represents information about a backup file
type BackupInfo struct {
	Path        string     `json:"path"`
	Size        int64      `json:"size"`
	Timestamp   time.Time  `json:"timestamp"`
	Type        BackupType `json:"type"`
	RecordCount int64      `json:"record_count"`
	Compressed  bool       `json:"compressed"`
	Encrypted   bool       `json:"encrypted"`
}