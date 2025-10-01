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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// MultipartUpload represents an ongoing multipart upload
type MultipartUpload struct {
	// Upload identification
	UploadID string `json:"upload_id"`
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	
	// Upload metadata
	ContentType     string            `json:"content_type,omitempty"`
	ContentEncoding string            `json:"content_encoding,omitempty"`
	ContentLanguage string            `json:"content_language,omitempty"`
	CacheControl    string            `json:"cache_control,omitempty"`
	UserMetadata    map[string]string `json:"user_metadata,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
	ACL             string            `json:"acl,omitempty"`
	
	// Upload state
	Parts       map[int32]*MultipartPart `json:"parts"`
	Initiated   time.Time                `json:"initiated"`
	LastUpdated time.Time                `json:"last_updated"`
	Owner       string                   `json:"owner"`
	
	// IPFS specific data
	TempPins    []string `json:"temp_pins"`    // Temporary pins for parts
	TotalSize   int64    `json:"total_size"`   // Total size of all parts
	PartCount   int32    `json:"part_count"`   // Number of uploaded parts
	
	// Synchronization
	mu sync.RWMutex `json:"-"`
}

// MultipartPart represents a single part of a multipart upload
type MultipartPart struct {
	PartNumber   int32     `json:"part_number"`
	CID          string    `json:"cid"`
	Size         int64     `json:"size"`
	ETag         string    `json:"etag"`
	LastModified time.Time `json:"last_modified"`
	Checksum     string    `json:"checksum,omitempty"`
	
	// Pin information
	PinStatus PinStatus `json:"pin_status"`
	PinNodes  []string  `json:"pin_nodes,omitempty"`
}

// MultipartStore defines the interface for storing multipart upload metadata
type MultipartStore interface {
	// Multipart upload operations
	CreateMultipartUpload(ctx context.Context, upload *MultipartUpload) error
	GetMultipartUpload(ctx context.Context, uploadID string) (*MultipartUpload, error)
	DeleteMultipartUpload(ctx context.Context, uploadID string) error
	ListMultipartUploads(ctx context.Context, bucket string, keyMarker string, uploadIDMarker string, maxUploads int32) ([]*MultipartUpload, error)
	
	// Part operations
	StorePart(ctx context.Context, uploadID string, part *MultipartPart) error
	GetPart(ctx context.Context, uploadID string, partNumber int32) (*MultipartPart, error)
	ListParts(ctx context.Context, uploadID string, partNumberMarker int32, maxParts int32) ([]*MultipartPart, error)
	DeletePart(ctx context.Context, uploadID string, partNumber int32) error
	
	// Cleanup operations
	CleanupExpiredUploads(ctx context.Context, maxAge time.Duration) (int, error)
	GetUploadStats(ctx context.Context) (*MultipartStats, error)
}

// MultipartStats represents statistics about multipart uploads
type MultipartStats struct {
	ActiveUploads     int64 `json:"active_uploads"`
	TotalParts        int64 `json:"total_parts"`
	TotalSize         int64 `json:"total_size"`
	AveragePartSize   int64 `json:"average_part_size"`
	OldestUpload      time.Time `json:"oldest_upload"`
	ExpiredUploads    int64 `json:"expired_uploads"`
	CompletedUploads  int64 `json:"completed_uploads"`
	AbortedUploads    int64 `json:"aborted_uploads"`
}

// NewMultipartUpload creates a new multipart upload
func NewMultipartUpload(bucket, key, owner string) *MultipartUpload {
	uploadID := generateUploadID()
	now := time.Now()
	
	return &MultipartUpload{
		UploadID:     uploadID,
		Bucket:       bucket,
		Key:          key,
		Owner:        owner,
		Parts:        make(map[int32]*MultipartPart),
		Initiated:    now,
		LastUpdated:  now,
		UserMetadata: make(map[string]string),
		Tags:         make(map[string]string),
		TempPins:     make([]string, 0),
		ACL:          "private", // Default ACL
	}
}

// generateUploadID generates a unique upload ID
func generateUploadID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// AddPart adds a part to the multipart upload
func (mu *MultipartUpload) AddPart(part *MultipartPart) {
	mu.mu.Lock()
	defer mu.mu.Unlock()
	
	// Remove existing part if it exists
	if existingPart, exists := mu.Parts[part.PartNumber]; exists {
		mu.TotalSize -= existingPart.Size
	} else {
		mu.PartCount++
	}
	
	mu.Parts[part.PartNumber] = part
	mu.TotalSize += part.Size
	mu.LastUpdated = time.Now()
}

// GetPart retrieves a part by part number
func (mu *MultipartUpload) GetPart(partNumber int32) (*MultipartPart, bool) {
	mu.mu.RLock()
	defer mu.mu.RUnlock()
	
	part, exists := mu.Parts[partNumber]
	return part, exists
}

// GetSortedParts returns all parts sorted by part number
func (mu *MultipartUpload) GetSortedParts() []*MultipartPart {
	mu.mu.RLock()
	defer mu.mu.RUnlock()
	
	parts := make([]*MultipartPart, 0, len(mu.Parts))
	for _, part := range mu.Parts {
		parts = append(parts, part)
	}
	
	sort.Slice(parts, func(i, j int) bool {
		return parts[i].PartNumber < parts[j].PartNumber
	})
	
	return parts
}

// RemovePart removes a part from the multipart upload
func (mu *MultipartUpload) RemovePart(partNumber int32) bool {
	mu.mu.Lock()
	defer mu.mu.Unlock()
	
	if part, exists := mu.Parts[partNumber]; exists {
		delete(mu.Parts, partNumber)
		mu.TotalSize -= part.Size
		mu.PartCount--
		mu.LastUpdated = time.Now()
		return true
	}
	return false
}

// AddTempPin adds a temporary pin CID
func (mu *MultipartUpload) AddTempPin(cid string) {
	mu.mu.Lock()
	defer mu.mu.Unlock()
	
	mu.TempPins = append(mu.TempPins, cid)
	mu.LastUpdated = time.Now()
}

// GetTempPins returns all temporary pin CIDs
func (mu *MultipartUpload) GetTempPins() []string {
	mu.mu.RLock()
	defer mu.mu.RUnlock()
	
	pins := make([]string, len(mu.TempPins))
	copy(pins, mu.TempPins)
	return pins
}

// ClearTempPins clears all temporary pins
func (mu *MultipartUpload) ClearTempPins() {
	mu.mu.Lock()
	defer mu.mu.Unlock()
	
	mu.TempPins = mu.TempPins[:0]
	mu.LastUpdated = time.Now()
}

// ValidateCompleteParts validates that all parts are present and in order for completion
func (mu *MultipartUpload) ValidateCompleteParts(completedParts []types.CompletedPart) error {
	mu.mu.RLock()
	defer mu.mu.RUnlock()
	
	if len(completedParts) == 0 {
		return fmt.Errorf("no parts specified for completion")
	}
	
	// Check that all specified parts exist
	for _, completedPart := range completedParts {
		partNumber := *completedPart.PartNumber
		part, exists := mu.Parts[partNumber]
		if !exists {
			return fmt.Errorf("part %d not found", partNumber)
		}
		
		// Validate ETag if provided
		if completedPart.ETag != nil && *completedPart.ETag != part.ETag {
			return fmt.Errorf("ETag mismatch for part %d: expected %s, got %s", 
				partNumber, part.ETag, *completedPart.ETag)
		}
	}
	
	// Validate part numbers are consecutive starting from 1
	partNumbers := make([]int32, len(completedParts))
	for i, part := range completedParts {
		partNumbers[i] = *part.PartNumber
	}
	sort.Slice(partNumbers, func(i, j int) bool {
		return partNumbers[i] < partNumbers[j]
	})
	
	for i, partNumber := range partNumbers {
		if partNumber != int32(i+1) {
			return fmt.Errorf("parts must be consecutive starting from 1, missing part %d", i+1)
		}
	}
	
	return nil
}

// GetStats returns statistics about the multipart upload
func (mu *MultipartUpload) GetStats() map[string]interface{} {
	mu.mu.RLock()
	defer mu.mu.RUnlock()
	
	stats := map[string]interface{}{
		"upload_id":     mu.UploadID,
		"bucket":        mu.Bucket,
		"key":           mu.Key,
		"part_count":    mu.PartCount,
		"total_size":    mu.TotalSize,
		"temp_pins":     len(mu.TempPins),
		"initiated":     mu.Initiated,
		"last_updated":  mu.LastUpdated,
		"age_minutes":   time.Since(mu.Initiated).Minutes(),
	}
	
	if mu.PartCount > 0 {
		stats["average_part_size"] = mu.TotalSize / int64(mu.PartCount)
	}
	
	return stats
}

// IsExpired checks if the multipart upload has expired
func (mu *MultipartUpload) IsExpired(maxAge time.Duration) bool {
	mu.mu.RLock()
	defer mu.mu.RUnlock()
	
	return time.Since(mu.Initiated) > maxAge
}

// Clone creates a deep copy of the multipart upload
func (mu *MultipartUpload) Clone() *MultipartUpload {
	mu.mu.RLock()
	defer mu.mu.RUnlock()
	
	clone := &MultipartUpload{
		UploadID:        mu.UploadID,
		Bucket:          mu.Bucket,
		Key:             mu.Key,
		ContentType:     mu.ContentType,
		ContentEncoding: mu.ContentEncoding,
		ContentLanguage: mu.ContentLanguage,
		CacheControl:    mu.CacheControl,
		ACL:             mu.ACL,
		Initiated:       mu.Initiated,
		LastUpdated:     mu.LastUpdated,
		Owner:           mu.Owner,
		TotalSize:       mu.TotalSize,
		PartCount:       mu.PartCount,
		Parts:           make(map[int32]*MultipartPart),
		UserMetadata:    make(map[string]string),
		Tags:            make(map[string]string),
		TempPins:        make([]string, len(mu.TempPins)),
	}
	
	// Deep copy parts
	for partNum, part := range mu.Parts {
		clone.Parts[partNum] = &MultipartPart{
			PartNumber:   part.PartNumber,
			CID:          part.CID,
			Size:         part.Size,
			ETag:         part.ETag,
			LastModified: part.LastModified,
			Checksum:     part.Checksum,
			PinStatus:    part.PinStatus,
			PinNodes:     make([]string, len(part.PinNodes)),
		}
		copy(clone.Parts[partNum].PinNodes, part.PinNodes)
	}
	
	// Deep copy metadata
	for k, v := range mu.UserMetadata {
		clone.UserMetadata[k] = v
	}
	for k, v := range mu.Tags {
		clone.Tags[k] = v
	}
	
	// Deep copy temp pins
	copy(clone.TempPins, mu.TempPins)
	
	return clone
}