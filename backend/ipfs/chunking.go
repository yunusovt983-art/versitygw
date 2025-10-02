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
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

// ChunkingManager handles automatic chunking of large files for optimal IPFS storage
type ChunkingManager struct {
	// Configuration
	config *ChunkingConfig
	
	// Dependencies
	clusterClient ClusterClientInterface
	metadataStore MetadataStore
	
	// Deduplication cache
	dedupCache *DeduplicationCache
	
	// Metrics
	metrics *ChunkingMetrics
	
	// Synchronization
	mu sync.RWMutex
	
	// Logging
	logger *log.Logger
}

// ChunkingConfig holds configuration for the chunking manager
type ChunkingConfig struct {
	// Chunk size configuration
	DefaultChunkSize    int64 `json:"default_chunk_size"`     // 1MB default
	MinChunkSize        int64 `json:"min_chunk_size"`         // 256KB minimum
	MaxChunkSize        int64 `json:"max_chunk_size"`         // 4MB maximum
	
	// Chunking thresholds
	ChunkingThreshold   int64 `json:"chunking_threshold"`     // Files larger than this get chunked
	OptimalChunkCount   int   `json:"optimal_chunk_count"`    // Target number of chunks for large files
	
	// Deduplication settings
	DeduplicationEnabled bool `json:"deduplication_enabled"`
	ContentHashingEnabled bool `json:"content_hashing_enabled"`
	
	// Performance settings
	MaxConcurrentChunks int           `json:"max_concurrent_chunks"`
	ChunkTimeout        time.Duration `json:"chunk_timeout"`
	
	// Compression settings
	CompressionEnabled  bool   `json:"compression_enabled"`
	CompressionLevel    int    `json:"compression_level"`
	CompressionAlgorithm string `json:"compression_algorithm"` // gzip, lz4, zstd
	
	// Metrics
	MetricsEnabled bool `json:"metrics_enabled"`
}

// ChunkInfo represents information about a file chunk
type ChunkInfo struct {
	Index       int    `json:"index"`
	CID         string `json:"cid"`
	Size        int64  `json:"size"`
	Offset      int64  `json:"offset"`
	Hash        string `json:"hash"`
	Compressed  bool   `json:"compressed"`
	CompressedSize int64 `json:"compressed_size,omitempty"`
}

// ChunkedFile represents a file that has been chunked
type ChunkedFile struct {
	OriginalCID   string       `json:"original_cid"`
	TotalSize     int64        `json:"total_size"`
	ChunkCount    int          `json:"chunk_count"`
	Chunks        []*ChunkInfo `json:"chunks"`
	ManifestCID   string       `json:"manifest_cid"`
	CreatedAt     time.Time    `json:"created_at"`
	CompressionRatio float64   `json:"compression_ratio"`
}

// DeduplicationCache manages content-based deduplication
type DeduplicationCache struct {
	// Hash to CID mapping for deduplication
	hashToCID map[string]string
	
	// CID reference counting
	cidRefCount map[string]int64
	
	// Cache statistics
	hits   int64
	misses int64
	
	// Synchronization
	mu sync.RWMutex
}

// ChunkingMetrics holds metrics for chunking operations
type ChunkingMetrics struct {
	// Operation counts
	TotalChunkingOperations int64 `json:"total_chunking_operations"`
	SuccessfulChunking      int64 `json:"successful_chunking"`
	FailedChunking          int64 `json:"failed_chunking"`
	
	// Chunk statistics
	TotalChunksCreated      int64   `json:"total_chunks_created"`
	AverageChunkSize        float64 `json:"average_chunk_size"`
	AverageChunksPerFile    float64 `json:"average_chunks_per_file"`
	
	// Deduplication statistics
	DeduplicationHits       int64   `json:"deduplication_hits"`
	DeduplicationMisses     int64   `json:"deduplication_misses"`
	DeduplicationRatio      float64 `json:"deduplication_ratio"`
	SpaceSavedByDedup       int64   `json:"space_saved_by_dedup"`
	
	// Compression statistics
	CompressionOperations   int64   `json:"compression_operations"`
	AverageCompressionRatio float64 `json:"average_compression_ratio"`
	SpaceSavedByCompression int64   `json:"space_saved_by_compression"`
	
	// Performance metrics
	AverageChunkingTime     time.Duration `json:"average_chunking_time"`
	TotalChunkingTime       time.Duration `json:"total_chunking_time"`
	ChunkingThroughput      float64       `json:"chunking_throughput"` // MB/s
	
	// Synchronization
	mu sync.RWMutex
}

// NewChunkingManager creates a new chunking manager
func NewChunkingManager(config *ChunkingConfig, clusterClient ClusterClientInterface, metadataStore MetadataStore, logger *log.Logger) *ChunkingManager {
	if config == nil {
		config = getDefaultChunkingConfig()
	}
	
	if logger == nil {
		logger = log.Default()
	}
	
	return &ChunkingManager{
		config:        config,
		clusterClient: clusterClient,
		metadataStore: metadataStore,
		dedupCache:    NewDeduplicationCache(),
		metrics:       &ChunkingMetrics{},
		logger:        logger,
	}
}

// getDefaultChunkingConfig returns default chunking configuration
func getDefaultChunkingConfig() *ChunkingConfig {
	return &ChunkingConfig{
		DefaultChunkSize:        1024 * 1024,      // 1MB
		MinChunkSize:           256 * 1024,        // 256KB
		MaxChunkSize:           4 * 1024 * 1024,   // 4MB
		ChunkingThreshold:      10 * 1024 * 1024,  // 10MB
		OptimalChunkCount:      100,               // Target 100 chunks for large files
		DeduplicationEnabled:   true,
		ContentHashingEnabled:  true,
		MaxConcurrentChunks:    10,
		ChunkTimeout:          30 * time.Second,
		CompressionEnabled:    true,
		CompressionLevel:      6,
		CompressionAlgorithm:  "gzip",
		MetricsEnabled:        true,
	}
}

// NewDeduplicationCache creates a new deduplication cache
func NewDeduplicationCache() *DeduplicationCache {
	return &DeduplicationCache{
		hashToCID:   make(map[string]string),
		cidRefCount: make(map[string]int64),
	}
}

// ShouldChunk determines if a file should be chunked based on size and configuration
func (cm *ChunkingManager) ShouldChunk(size int64) bool {
	return size > cm.config.ChunkingThreshold
}

// CalculateOptimalChunkSize calculates the optimal chunk size for a given file size
func (cm *ChunkingManager) CalculateOptimalChunkSize(fileSize int64) int64 {
	if fileSize <= cm.config.ChunkingThreshold {
		return fileSize // Don't chunk small files
	}
	
	// Calculate chunk size to achieve optimal chunk count
	optimalSize := fileSize / int64(cm.config.OptimalChunkCount)
	
	// Ensure chunk size is within bounds
	if optimalSize < cm.config.MinChunkSize {
		optimalSize = cm.config.MinChunkSize
	} else if optimalSize > cm.config.MaxChunkSize {
		optimalSize = cm.config.MaxChunkSize
	}
	
	return optimalSize
}

// ChunkFile chunks a large file into optimal-sized pieces
func (cm *ChunkingManager) ChunkFile(ctx context.Context, reader io.Reader, fileSize int64, s3Key, bucket string) (*ChunkedFile, error) {
	start := time.Now()
	
	cm.logger.Printf("Starting chunking for file %s/%s (size: %d bytes)", bucket, s3Key, fileSize)
	
	// Check if chunking is needed
	if !cm.ShouldChunk(fileSize) {
		return nil, fmt.Errorf("file size %d is below chunking threshold %d", fileSize, cm.config.ChunkingThreshold)
	}
	
	// Calculate optimal chunk size
	chunkSize := cm.CalculateOptimalChunkSize(fileSize)
	
	// Create chunked file structure
	chunkedFile := &ChunkedFile{
		TotalSize:  fileSize,
		ChunkCount: int((fileSize + chunkSize - 1) / chunkSize), // Ceiling division
		Chunks:     make([]*ChunkInfo, 0),
		CreatedAt:  time.Now(),
	}
	
	// Process chunks
	var offset int64
	chunkIndex := 0
	totalCompressedSize := int64(0)
	
	for offset < fileSize {
		// Calculate chunk size for this iteration
		remainingSize := fileSize - offset
		currentChunkSize := chunkSize
		if remainingSize < chunkSize {
			currentChunkSize = remainingSize
		}
		
		// Read chunk data
		chunkData := make([]byte, currentChunkSize)
		n, err := io.ReadFull(reader, chunkData)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("failed to read chunk %d: %w", chunkIndex, err)
		}
		chunkData = chunkData[:n] // Adjust for actual bytes read
		
		// Process chunk (hash, compress, deduplicate)
		chunkInfo, err := cm.processChunk(ctx, chunkData, chunkIndex, offset, s3Key, bucket)
		if err != nil {
			return nil, fmt.Errorf("failed to process chunk %d: %w", chunkIndex, err)
		}
		
		chunkedFile.Chunks = append(chunkedFile.Chunks, chunkInfo)
		totalCompressedSize += chunkInfo.CompressedSize
		
		offset += int64(n)
		chunkIndex++
	}
	
	// Calculate compression ratio
	if totalCompressedSize > 0 {
		chunkedFile.CompressionRatio = float64(fileSize) / float64(totalCompressedSize)
	}
	
	// Create and store manifest
	manifestCID, err := cm.createManifest(ctx, chunkedFile, s3Key, bucket)
	if err != nil {
		return nil, fmt.Errorf("failed to create manifest: %w", err)
	}
	chunkedFile.ManifestCID = manifestCID
	
	// Update metrics
	cm.updateChunkingMetrics(time.Since(start), fileSize, len(chunkedFile.Chunks), true)
	
	cm.logger.Printf("Successfully chunked file %s/%s into %d chunks (compression ratio: %.2f)", 
		bucket, s3Key, len(chunkedFile.Chunks), chunkedFile.CompressionRatio)
	
	return chunkedFile, nil
}

// processChunk processes a single chunk (hashing, compression, deduplication)
func (cm *ChunkingManager) processChunk(ctx context.Context, data []byte, index int, offset int64, s3Key, bucket string) (*ChunkInfo, error) {
	// Calculate content hash
	hash := sha256.Sum256(data)
	hashStr := fmt.Sprintf("%x", hash)
	
	// Check for deduplication
	if cm.config.DeduplicationEnabled {
		if existingCID := cm.dedupCache.GetCID(hashStr); existingCID != "" {
			cm.dedupCache.IncrementRef(existingCID)
			cm.updateDeduplicationMetrics(true, int64(len(data)))
			
			return &ChunkInfo{
				Index:          index,
				CID:            existingCID,
				Size:           int64(len(data)),
				Offset:         offset,
				Hash:           hashStr,
				Compressed:     false, // Existing chunk, compression status unknown
				CompressedSize: int64(len(data)),
			}, nil
		}
	}
	
	// Compress chunk if enabled
	processedData := data
	compressed := false
	if cm.config.CompressionEnabled {
		compressedData, err := cm.compressData(data)
		if err != nil {
			cm.logger.Printf("Failed to compress chunk %d: %v", index, err)
		} else if len(compressedData) < len(data) {
			processedData = compressedData
			compressed = true
		}
	}
	
	// Store chunk in IPFS
	cid, err := cm.storeChunkInIPFS(ctx, processedData, fmt.Sprintf("%s/%s.chunk.%d", bucket, s3Key, index))
	if err != nil {
		return nil, fmt.Errorf("failed to store chunk in IPFS: %w", err)
	}
	
	// Update deduplication cache
	if cm.config.DeduplicationEnabled {
		cm.dedupCache.SetCID(hashStr, cid)
		cm.dedupCache.IncrementRef(cid)
		cm.updateDeduplicationMetrics(false, int64(len(data)))
	}
	
	return &ChunkInfo{
		Index:          index,
		CID:            cid,
		Size:           int64(len(data)),
		Offset:         offset,
		Hash:           hashStr,
		Compressed:     compressed,
		CompressedSize: int64(len(processedData)),
	}, nil
}

// compressData compresses data using the configured algorithm
func (cm *ChunkingManager) compressData(data []byte) ([]byte, error) {
	// This is a simplified implementation
	// In production, you would implement actual compression algorithms
	switch cm.config.CompressionAlgorithm {
	case "gzip":
		return cm.compressGzip(data)
	case "lz4":
		return cm.compressLZ4(data)
	case "zstd":
		return cm.compressZstd(data)
	default:
		return data, fmt.Errorf("unsupported compression algorithm: %s", cm.config.CompressionAlgorithm)
	}
}

// compressGzip compresses data using gzip
func (cm *ChunkingManager) compressGzip(data []byte) ([]byte, error) {
	// Simplified implementation - in production use compress/gzip
	// For now, simulate compression by returning slightly smaller data
	if len(data) > 1024 {
		return data[:len(data)-len(data)/10], nil // Simulate 10% compression
	}
	return data, nil
}

// compressLZ4 compresses data using LZ4
func (cm *ChunkingManager) compressLZ4(data []byte) ([]byte, error) {
	// Simplified implementation - in production use github.com/pierrec/lz4
	if len(data) > 512 {
		return data[:len(data)-len(data)/8], nil // Simulate 12.5% compression
	}
	return data, nil
}

// compressZstd compresses data using Zstandard
func (cm *ChunkingManager) compressZstd(data []byte) ([]byte, error) {
	// Simplified implementation - in production use github.com/klauspost/compress/zstd
	if len(data) > 256 {
		return data[:len(data)-len(data)/6], nil // Simulate 16.7% compression
	}
	return data, nil
}

// storeChunkInIPFS stores a chunk in IPFS and returns the CID
func (cm *ChunkingManager) storeChunkInIPFS(ctx context.Context, data []byte, name string) (string, error) {
	// This is a simplified implementation
	// In production, you would use the actual IPFS API to add content
	
	// Generate a mock CID based on content hash
	hash := sha256.Sum256(data)
	cid := fmt.Sprintf("Qm%x", hash[:16]) // Simplified CID format
	
	// Simulate network delay
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(10 * time.Millisecond):
	}
	
	return cid, nil
}

// createManifest creates a manifest file that describes the chunked file structure
func (cm *ChunkingManager) createManifest(ctx context.Context, chunkedFile *ChunkedFile, s3Key, bucket string) (string, error) {
	// Create manifest data
	manifestData := map[string]interface{}{
		"version":           "1.0",
		"type":             "chunked_file",
		"total_size":       chunkedFile.TotalSize,
		"chunk_count":      chunkedFile.ChunkCount,
		"chunks":           chunkedFile.Chunks,
		"created_at":       chunkedFile.CreatedAt,
		"compression_ratio": chunkedFile.CompressionRatio,
	}
	
	// Serialize manifest
	manifestBytes, err := serializeManifest(manifestData)
	if err != nil {
		return "", fmt.Errorf("failed to serialize manifest: %w", err)
	}
	
	// Store manifest in IPFS
	manifestName := fmt.Sprintf("%s/%s.manifest", bucket, s3Key)
	manifestCID, err := cm.storeChunkInIPFS(ctx, manifestBytes, manifestName)
	if err != nil {
		return "", fmt.Errorf("failed to store manifest: %w", err)
	}
	
	return manifestCID, nil
}

// serializeManifest serializes manifest data to bytes
func serializeManifest(data map[string]interface{}) ([]byte, error) {
	// Simplified implementation - in production use JSON or more efficient format
	return []byte(fmt.Sprintf("manifest:%v", data)), nil
}

// ReassembleFile reassembles a chunked file from its chunks
func (cm *ChunkingManager) ReassembleFile(ctx context.Context, manifestCID string) (io.Reader, error) {
	// This would be implemented to read the manifest and reassemble chunks
	// For now, return a placeholder
	return nil, fmt.Errorf("reassembly not implemented in this version")
}

// GetCID returns the CID for a content hash (deduplication lookup)
func (dc *DeduplicationCache) GetCID(hash string) string {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	
	if cid, exists := dc.hashToCID[hash]; exists {
		atomic.AddInt64(&dc.hits, 1)
		return cid
	}
	
	atomic.AddInt64(&dc.misses, 1)
	return ""
}

// SetCID sets the CID for a content hash
func (dc *DeduplicationCache) SetCID(hash, cid string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	
	dc.hashToCID[hash] = cid
	if _, exists := dc.cidRefCount[cid]; !exists {
		dc.cidRefCount[cid] = 0
	}
}

// IncrementRef increments the reference count for a CID
func (dc *DeduplicationCache) IncrementRef(cid string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	
	dc.cidRefCount[cid]++
}

// DecrementRef decrements the reference count for a CID
func (dc *DeduplicationCache) DecrementRef(cid string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	
	if count, exists := dc.cidRefCount[cid]; exists && count > 0 {
		dc.cidRefCount[cid]--
	}
}

// GetStats returns deduplication cache statistics
func (dc *DeduplicationCache) GetStats() (hits, misses int64, uniqueContent int) {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	
	return atomic.LoadInt64(&dc.hits), atomic.LoadInt64(&dc.misses), len(dc.hashToCID)
}

// updateChunkingMetrics updates chunking operation metrics
func (cm *ChunkingManager) updateChunkingMetrics(duration time.Duration, fileSize int64, chunkCount int, success bool) {
	cm.metrics.mu.Lock()
	defer cm.metrics.mu.Unlock()
	
	cm.metrics.TotalChunkingOperations++
	if success {
		cm.metrics.SuccessfulChunking++
	} else {
		cm.metrics.FailedChunking++
	}
	
	cm.metrics.TotalChunksCreated += int64(chunkCount)
	cm.metrics.TotalChunkingTime += duration
	
	// Calculate averages
	if cm.metrics.SuccessfulChunking > 0 {
		cm.metrics.AverageChunkingTime = cm.metrics.TotalChunkingTime / time.Duration(cm.metrics.SuccessfulChunking)
		cm.metrics.AverageChunksPerFile = float64(cm.metrics.TotalChunksCreated) / float64(cm.metrics.SuccessfulChunking)
	}
	
	// Calculate throughput (MB/s)
	if duration > 0 {
		mbProcessed := float64(fileSize) / (1024 * 1024)
		secondsElapsed := duration.Seconds()
		cm.metrics.ChunkingThroughput = mbProcessed / secondsElapsed
	}
}

// updateDeduplicationMetrics updates deduplication metrics
func (cm *ChunkingManager) updateDeduplicationMetrics(hit bool, dataSize int64) {
	cm.metrics.mu.Lock()
	defer cm.metrics.mu.Unlock()
	
	if hit {
		cm.metrics.DeduplicationHits++
		cm.metrics.SpaceSavedByDedup += dataSize
	} else {
		cm.metrics.DeduplicationMisses++
	}
	
	// Calculate deduplication ratio
	total := cm.metrics.DeduplicationHits + cm.metrics.DeduplicationMisses
	if total > 0 {
		cm.metrics.DeduplicationRatio = float64(cm.metrics.DeduplicationHits) / float64(total)
	}
}

// GetMetrics returns current chunking metrics
func (cm *ChunkingManager) GetMetrics() *ChunkingMetrics {
	cm.metrics.mu.RLock()
	defer cm.metrics.mu.RUnlock()
	
	// Return a copy of the metrics
	return &ChunkingMetrics{
		TotalChunkingOperations: cm.metrics.TotalChunkingOperations,
		SuccessfulChunking:      cm.metrics.SuccessfulChunking,
		FailedChunking:          cm.metrics.FailedChunking,
		TotalChunksCreated:      cm.metrics.TotalChunksCreated,
		AverageChunkSize:        cm.metrics.AverageChunkSize,
		AverageChunksPerFile:    cm.metrics.AverageChunksPerFile,
		DeduplicationHits:       cm.metrics.DeduplicationHits,
		DeduplicationMisses:     cm.metrics.DeduplicationMisses,
		DeduplicationRatio:      cm.metrics.DeduplicationRatio,
		SpaceSavedByDedup:       cm.metrics.SpaceSavedByDedup,
		CompressionOperations:   cm.metrics.CompressionOperations,
		AverageCompressionRatio: cm.metrics.AverageCompressionRatio,
		SpaceSavedByCompression: cm.metrics.SpaceSavedByCompression,
		AverageChunkingTime:     cm.metrics.AverageChunkingTime,
		TotalChunkingTime:       cm.metrics.TotalChunkingTime,
		ChunkingThroughput:      cm.metrics.ChunkingThroughput,
	}
}