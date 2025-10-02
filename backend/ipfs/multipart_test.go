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
	"bytes"
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3response"
)

func TestMultipartUpload_NewMultipartUpload(t *testing.T) {
	upload := NewMultipartUpload("test-bucket", "test-key", "test-owner")
	
	if upload.Bucket != "test-bucket" {
		t.Errorf("Expected bucket 'test-bucket', got '%s'", upload.Bucket)
	}
	if upload.Key != "test-key" {
		t.Errorf("Expected key 'test-key', got '%s'", upload.Key)
	}
	if upload.Owner != "test-owner" {
		t.Errorf("Expected owner 'test-owner', got '%s'", upload.Owner)
	}
	if upload.UploadID == "" {
		t.Error("Expected non-empty upload ID")
	}
	if len(upload.Parts) != 0 {
		t.Errorf("Expected empty parts map, got %d parts", len(upload.Parts))
	}
	if upload.PartCount != 0 {
		t.Errorf("Expected part count 0, got %d", upload.PartCount)
	}
	if upload.TotalSize != 0 {
		t.Errorf("Expected total size 0, got %d", upload.TotalSize)
	}
}

func TestMultipartUpload_AddPart(t *testing.T) {
	upload := NewMultipartUpload("test-bucket", "test-key", "test-owner")
	
	part1 := &MultipartPart{
		PartNumber:   1,
		CID:          "test-cid-1",
		Size:         1024,
		ETag:         "test-etag-1",
		LastModified: time.Now(),
		PinStatus:    PinStatusPending,
	}
	
	upload.AddPart(part1)
	
	if upload.PartCount != 1 {
		t.Errorf("Expected part count 1, got %d", upload.PartCount)
	}
	if upload.TotalSize != 1024 {
		t.Errorf("Expected total size 1024, got %d", upload.TotalSize)
	}
	
	retrievedPart, exists := upload.GetPart(1)
	if !exists {
		t.Error("Expected part 1 to exist")
	}
	if retrievedPart.CID != "test-cid-1" {
		t.Errorf("Expected CID 'test-cid-1', got '%s'", retrievedPart.CID)
	}
	
	// Test replacing existing part
	part1Updated := &MultipartPart{
		PartNumber:   1,
		CID:          "test-cid-1-updated",
		Size:         2048,
		ETag:         "test-etag-1-updated",
		LastModified: time.Now(),
		PinStatus:    PinStatusPinned,
	}
	
	upload.AddPart(part1Updated)
	
	if upload.PartCount != 1 {
		t.Errorf("Expected part count 1 after update, got %d", upload.PartCount)
	}
	if upload.TotalSize != 2048 {
		t.Errorf("Expected total size 2048 after update, got %d", upload.TotalSize)
	}
	
	retrievedPart, exists = upload.GetPart(1)
	if !exists {
		t.Error("Expected part 1 to exist after update")
	}
	if retrievedPart.CID != "test-cid-1-updated" {
		t.Errorf("Expected updated CID 'test-cid-1-updated', got '%s'", retrievedPart.CID)
	}
}

func TestMultipartUpload_GetSortedParts(t *testing.T) {
	upload := NewMultipartUpload("test-bucket", "test-key", "test-owner")
	
	// Add parts in non-sequential order
	parts := []*MultipartPart{
		{PartNumber: 3, CID: "cid-3", Size: 1024, ETag: "etag-3", LastModified: time.Now()},
		{PartNumber: 1, CID: "cid-1", Size: 1024, ETag: "etag-1", LastModified: time.Now()},
		{PartNumber: 2, CID: "cid-2", Size: 1024, ETag: "etag-2", LastModified: time.Now()},
	}
	
	for _, part := range parts {
		upload.AddPart(part)
	}
	
	sortedParts := upload.GetSortedParts()
	
	if len(sortedParts) != 3 {
		t.Errorf("Expected 3 sorted parts, got %d", len(sortedParts))
	}
	
	for i, part := range sortedParts {
		expectedPartNumber := int32(i + 1)
		if part.PartNumber != expectedPartNumber {
			t.Errorf("Expected part number %d at index %d, got %d", expectedPartNumber, i, part.PartNumber)
		}
	}
}

func TestMultipartUpload_ValidateCompleteParts(t *testing.T) {
	upload := NewMultipartUpload("test-bucket", "test-key", "test-owner")
	
	// Add parts
	parts := []*MultipartPart{
		{PartNumber: 1, CID: "cid-1", Size: 1024, ETag: "etag-1", LastModified: time.Now()},
		{PartNumber: 2, CID: "cid-2", Size: 1024, ETag: "etag-2", LastModified: time.Now()},
		{PartNumber: 3, CID: "cid-3", Size: 1024, ETag: "etag-3", LastModified: time.Now()},
	}
	
	for _, part := range parts {
		upload.AddPart(part)
	}
	
	// Test valid completion
	completedParts := []types.CompletedPart{
		{PartNumber: int32Ptr(1), ETag: stringPtr("etag-1")},
		{PartNumber: int32Ptr(2), ETag: stringPtr("etag-2")},
		{PartNumber: int32Ptr(3), ETag: stringPtr("etag-3")},
	}
	
	err := upload.ValidateCompleteParts(completedParts)
	if err != nil {
		t.Errorf("Expected valid completion, got error: %v", err)
	}
	
	// Test missing part
	incompleteParts := []types.CompletedPart{
		{PartNumber: int32Ptr(1), ETag: stringPtr("etag-1")},
		{PartNumber: int32Ptr(3), ETag: stringPtr("etag-3")},
	}
	
	err = upload.ValidateCompleteParts(incompleteParts)
	if err == nil {
		t.Error("Expected error for missing part 2, got nil")
	}
	
	// Test ETag mismatch
	mismatchParts := []types.CompletedPart{
		{PartNumber: int32Ptr(1), ETag: stringPtr("wrong-etag")},
		{PartNumber: int32Ptr(2), ETag: stringPtr("etag-2")},
		{PartNumber: int32Ptr(3), ETag: stringPtr("etag-3")},
	}
	
	err = upload.ValidateCompleteParts(mismatchParts)
	if err == nil {
		t.Error("Expected error for ETag mismatch, got nil")
	}
	
	// Test non-existent part
	nonExistentParts := []types.CompletedPart{
		{PartNumber: int32Ptr(1), ETag: stringPtr("etag-1")},
		{PartNumber: int32Ptr(2), ETag: stringPtr("etag-2")},
		{PartNumber: int32Ptr(4), ETag: stringPtr("etag-4")},
	}
	
	err = upload.ValidateCompleteParts(nonExistentParts)
	if err == nil {
		t.Error("Expected error for non-existent part 4, got nil")
	}
}

func TestIPFSBackend_CreateMultipartUpload(t *testing.T) {
	backend := setupTestIPFSBackend(t)
	defer backend.Shutdown()
	
	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	contentType := "application/octet-stream"
	
	input := s3response.CreateMultipartUploadInput{
		Bucket:      &bucket,
		Key:         &key,
		ContentType: &contentType,
		Metadata:    map[string]string{"custom": "metadata"},
	}
	
	result, err := backend.CreateMultipartUpload(ctx, input)
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}
	
	if result.Bucket != bucket {
		t.Errorf("Expected bucket '%s', got '%s'", bucket, result.Bucket)
	}
	if result.Key != key {
		t.Errorf("Expected key '%s', got '%s'", key, result.Key)
	}
	if result.UploadId == "" {
		t.Error("Expected non-empty upload ID")
	}
	
	// Verify upload was stored
	upload, err := backend.getMultipartUpload(ctx, result.UploadId)
	if err != nil {
		t.Fatalf("Failed to retrieve stored upload: %v", err)
	}
	
	if upload.ContentType != contentType {
		t.Errorf("Expected content type '%s', got '%s'", contentType, upload.ContentType)
	}
	if upload.UserMetadata["custom"] != "metadata" {
		t.Errorf("Expected custom metadata 'metadata', got '%s'", upload.UserMetadata["custom"])
	}
}

func TestIPFSBackend_UploadPart(t *testing.T) {
	backend := setupTestIPFSBackend(t)
	defer backend.Shutdown()
	
	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	
	// Create multipart upload first
	createInput := s3response.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &key,
	}
	
	createResult, err := backend.CreateMultipartUpload(ctx, createInput)
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}
	
	uploadID := createResult.UploadId
	partNumber := int32(1)
	partData := []byte("test part data")
	
	uploadInput := &s3.UploadPartInput{
		Bucket:     &bucket,
		Key:        &key,
		UploadId:   &uploadID,
		PartNumber: &partNumber,
		Body:       bytes.NewReader(partData),
	}
	
	uploadResult, err := backend.UploadPart(ctx, uploadInput)
	if err != nil {
		t.Fatalf("UploadPart failed: %v", err)
	}
	
	if uploadResult.ETag == nil || *uploadResult.ETag == "" {
		t.Error("Expected non-empty ETag")
	}
	
	// Verify part was stored
	upload, err := backend.getMultipartUpload(ctx, uploadID)
	if err != nil {
		t.Fatalf("Failed to retrieve upload after part upload: %v", err)
	}
	
	part, exists := upload.GetPart(partNumber)
	if !exists {
		t.Error("Expected part to exist after upload")
	}
	if part.Size != int64(len(partData)) {
		t.Errorf("Expected part size %d, got %d", len(partData), part.Size)
	}
	if upload.PartCount != 1 {
		t.Errorf("Expected part count 1, got %d", upload.PartCount)
	}
	if upload.TotalSize != int64(len(partData)) {
		t.Errorf("Expected total size %d, got %d", len(partData), upload.TotalSize)
	}
}

func TestIPFSBackend_ListParts(t *testing.T) {
	backend := setupTestIPFSBackend(t)
	defer backend.Shutdown()
	
	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	
	// Create multipart upload
	createInput := s3response.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &key,
	}
	
	createResult, err := backend.CreateMultipartUpload(ctx, createInput)
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}
	
	uploadID := createResult.UploadId
	
	// Upload multiple parts
	partData := [][]byte{
		[]byte("part 1 data"),
		[]byte("part 2 data"),
		[]byte("part 3 data"),
	}
	
	for i, data := range partData {
		partNumber := int32(i + 1)
		uploadInput := &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &key,
			UploadId:   &uploadID,
			PartNumber: &partNumber,
			Body:       bytes.NewReader(data),
		}
		
		_, err := backend.UploadPart(ctx, uploadInput)
		if err != nil {
			t.Fatalf("UploadPart %d failed: %v", partNumber, err)
		}
	}
	
	// List parts
	listInput := &s3.ListPartsInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &uploadID,
	}
	
	listResult, err := backend.ListParts(ctx, listInput)
	if err != nil {
		t.Fatalf("ListParts failed: %v", err)
	}
	
	if len(listResult.Parts) != 3 {
		t.Errorf("Expected 3 parts, got %d", len(listResult.Parts))
	}
	
	// Verify parts are sorted by part number
	for i, part := range listResult.Parts {
		expectedPartNumber := int32(i + 1)
		if part.PartNumber != int(expectedPartNumber) {
			t.Errorf("Expected part number %d at index %d, got %d", expectedPartNumber, i, part.PartNumber)
		}
		if part.ETag == "" {
			t.Errorf("Expected non-empty ETag for part %d", expectedPartNumber)
		}
		if part.Size != int64(len(partData[i])) {
			t.Errorf("Expected size %d for part %d, got %d", len(partData[i]), expectedPartNumber, part.Size)
		}
	}
}

func TestIPFSBackend_CompleteMultipartUpload(t *testing.T) {
	backend := setupTestIPFSBackend(t)
	defer backend.Shutdown()
	
	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	
	// Create multipart upload
	createInput := s3response.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &key,
	}
	
	createResult, err := backend.CreateMultipartUpload(ctx, createInput)
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}
	
	uploadID := createResult.UploadId
	
	// Upload parts
	partData := [][]byte{
		[]byte("part 1 data"),
		[]byte("part 2 data"),
		[]byte("part 3 data"),
	}
	
	var completedParts []types.CompletedPart
	
	for i, data := range partData {
		partNumber := int32(i + 1)
		uploadInput := &s3.UploadPartInput{
			Bucket:     &bucket,
			Key:        &key,
			UploadId:   &uploadID,
			PartNumber: &partNumber,
			Body:       bytes.NewReader(data),
		}
		
		uploadResult, err := backend.UploadPart(ctx, uploadInput)
		if err != nil {
			t.Fatalf("UploadPart %d failed: %v", partNumber, err)
		}
		
		completedParts = append(completedParts, types.CompletedPart{
			PartNumber: &partNumber,
			ETag:       uploadResult.ETag,
		})
	}
	
	// Complete multipart upload
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	}
	
	completeResult, versionID, err := backend.CompleteMultipartUpload(ctx, completeInput)
	if err != nil {
		t.Fatalf("CompleteMultipartUpload failed: %v", err)
	}
	
	if completeResult.Bucket == nil || *completeResult.Bucket != bucket {
		t.Errorf("Expected bucket '%s', got '%v'", bucket, completeResult.Bucket)
	}
	if completeResult.Key == nil || *completeResult.Key != key {
		t.Errorf("Expected key '%s', got '%v'", key, completeResult.Key)
	}
	if completeResult.ETag == nil || *completeResult.ETag == "" {
		t.Error("Expected non-empty ETag")
	}
	if versionID != "" {
		t.Errorf("Expected empty version ID, got '%s'", versionID)
	}
	
	// Verify object mapping was created
	mapping, err := backend.GetObjectMapping(ctx, key, bucket)
	if err != nil {
		t.Fatalf("Failed to get object mapping after completion: %v", err)
	}
	
	expectedTotalSize := int64(0)
	for _, data := range partData {
		expectedTotalSize += int64(len(data))
	}
	
	if mapping.Size != expectedTotalSize {
		t.Errorf("Expected total size %d, got %d", expectedTotalSize, mapping.Size)
	}
}

func TestIPFSBackend_AbortMultipartUpload(t *testing.T) {
	backend := setupTestIPFSBackend(t)
	defer backend.Shutdown()
	
	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-key"
	
	// Create multipart upload
	createInput := s3response.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &key,
	}
	
	createResult, err := backend.CreateMultipartUpload(ctx, createInput)
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}
	
	uploadID := createResult.UploadId
	
	// Upload a part
	partNumber := int32(1)
	partData := []byte("test part data")
	uploadInput := &s3.UploadPartInput{
		Bucket:     &bucket,
		Key:        &key,
		UploadId:   &uploadID,
		PartNumber: &partNumber,
		Body:       bytes.NewReader(partData),
	}
	
	_, err = backend.UploadPart(ctx, uploadInput)
	if err != nil {
		t.Fatalf("UploadPart failed: %v", err)
	}
	
	// Abort multipart upload
	abortInput := &s3.AbortMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &uploadID,
	}
	
	err = backend.AbortMultipartUpload(ctx, abortInput)
	if err != nil {
		t.Fatalf("AbortMultipartUpload failed: %v", err)
	}
	
	// Verify upload was cleaned up (give some time for async cleanup)
	time.Sleep(100 * time.Millisecond)
	
	_, err = backend.getMultipartUpload(ctx, uploadID)
	if err == nil {
		t.Error("Expected upload to be cleaned up after abort")
	}
}

func TestIPFSBackend_ListMultipartUploads(t *testing.T) {
	backend := setupTestIPFSBackend(t)
	defer backend.Shutdown()
	
	ctx := context.Background()
	bucket := "test-bucket"
	
	// Create multiple multipart uploads
	uploads := []string{"key1", "key2", "key3"}
	var uploadIDs []string
	
	for _, key := range uploads {
		createInput := s3response.CreateMultipartUploadInput{
			Bucket: &bucket,
			Key:    &key,
		}
		
		createResult, err := backend.CreateMultipartUpload(ctx, createInput)
		if err != nil {
			t.Fatalf("CreateMultipartUpload for key '%s' failed: %v", key, err)
		}
		
		uploadIDs = append(uploadIDs, createResult.UploadId)
	}
	
	// List multipart uploads
	listInput := &s3.ListMultipartUploadsInput{
		Bucket: &bucket,
	}
	
	listResult, err := backend.ListMultipartUploads(ctx, listInput)
	if err != nil {
		t.Fatalf("ListMultipartUploads failed: %v", err)
	}
	
	if len(listResult.Uploads) != 3 {
		t.Errorf("Expected 3 uploads, got %d", len(listResult.Uploads))
	}
	
	// Verify uploads are sorted by key
	for i, upload := range listResult.Uploads {
		expectedKey := uploads[i]
		if upload.Key != expectedKey {
			t.Errorf("Expected key '%s' at index %d, got '%s'", expectedKey, i, upload.Key)
		}
		if upload.UploadID == "" {
			t.Errorf("Expected non-empty upload ID for key '%s'", expectedKey)
		}
	}
}

// Helper function to set up a test IPFS backend
func setupTestIPFSBackend(t *testing.T) *IPFSBackend {
	config := &IPFSConfig{
		ClusterEndpoints:    []string{"http://localhost:9094"},
		ConnectTimeout:      10 * time.Second,
		RequestTimeout:      30 * time.Second,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
		MaxConcurrentPins:   10,
		PinTimeout:          60 * time.Second,
		ChunkSize:           1024 * 1024,
		ReplicationMin:      1,
		ReplicationMax:      3,
		CompressionEnabled:  false,
		MetadataDBType:      "memory",
		MetadataDBEndpoints: []string{},
		CacheEndpoints:      []string{},
		CacheEnabled:        false,
		MetricsEnabled:      false,
		LogLevel:            "info",
	}
	
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	
	opts := IPFSOptions{
		Logger:  logger,
		Context: context.Background(),
	}
	
	backend, err := New(config, opts)
	if err != nil {
		t.Fatalf("Failed to create IPFS backend: %v", err)
	}
	
	return backend
}

// Test helper functions
func TestParseTaggingString(t *testing.T) {
	tests := []struct {
		input    string
		expected map[string]string
	}{
		{
			input:    "",
			expected: map[string]string{},
		},
		{
			input:    "key1=value1",
			expected: map[string]string{"key1": "value1"},
		},
		{
			input:    "key1=value1&key2=value2",
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			input:    "key1=value1&key2=value2&key3=value3",
			expected: map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"},
		},
		{
			input:    "invalid",
			expected: map[string]string{},
		},
		{
			input:    "key1=value1&invalid&key2=value2",
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
	}
	
	for _, test := range tests {
		result := parseTaggingString(test.input)
		
		if len(result) != len(test.expected) {
			t.Errorf("For input '%s', expected %d tags, got %d", test.input, len(test.expected), len(result))
			continue
		}
		
		for key, expectedValue := range test.expected {
			if actualValue, exists := result[key]; !exists {
				t.Errorf("For input '%s', expected key '%s' to exist", test.input, key)
			} else if actualValue != expectedValue {
				t.Errorf("For input '%s', expected value '%s' for key '%s', got '%s'", 
					test.input, expectedValue, key, actualValue)
			}
		}
	}
}

func TestGenerateUploadID(t *testing.T) {
	// Generate multiple upload IDs and verify they are unique
	ids := make(map[string]bool)
	
	for i := 0; i < 100; i++ {
		id := generateUploadID()
		
		if id == "" {
			t.Error("Generated upload ID should not be empty")
		}
		
		if len(id) != 32 { // 16 bytes * 2 hex chars per byte
			t.Errorf("Expected upload ID length 32, got %d", len(id))
		}
		
		if ids[id] {
			t.Errorf("Duplicate upload ID generated: %s", id)
		}
		
		ids[id] = true
	}
}

func TestIPFSBackend_UploadPartCopy(t *testing.T) {
	backend := setupTestIPFSBackend(t)
	defer backend.Shutdown()
	
	ctx := context.Background()
	sourceBucket := "source-bucket"
	sourceKey := "source-key"
	destBucket := "dest-bucket"
	destKey := "dest-key"
	
	// First, create a source object
	sourceData := []byte("source object data for copying")
	putInput := s3response.PutObjectInput{
		Bucket: &sourceBucket,
		Key:    &sourceKey,
		Body:   bytes.NewReader(sourceData),
	}
	
	_, err := backend.PutObject(ctx, putInput)
	if err != nil {
		t.Fatalf("Failed to create source object: %v", err)
	}
	
	// Create multipart upload for destination
	createInput := s3response.CreateMultipartUploadInput{
		Bucket: &destBucket,
		Key:    &destKey,
	}
	
	createResult, err := backend.CreateMultipartUpload(ctx, createInput)
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}
	
	uploadID := createResult.UploadId
	partNumber := int32(1)
	copySource := sourceBucket + "/" + sourceKey
	
	// Test UploadPartCopy
	copyInput := &s3.UploadPartCopyInput{
		Bucket:     &destBucket,
		Key:        &destKey,
		UploadId:   &uploadID,
		PartNumber: &partNumber,
		CopySource: &copySource,
	}
	
	copyResult, err := backend.UploadPartCopy(ctx, copyInput)
	if err != nil {
		t.Fatalf("UploadPartCopy failed: %v", err)
	}
	
	if copyResult.ETag == nil || *copyResult.ETag == "" {
		t.Error("Expected non-empty ETag from UploadPartCopy")
	}
	
	// Verify the part was stored
	upload, err := backend.getMultipartUpload(ctx, uploadID)
	if err != nil {
		t.Fatalf("Failed to retrieve upload after part copy: %v", err)
	}
	
	part, exists := upload.GetPart(partNumber)
	if !exists {
		t.Error("Expected part to exist after copy")
	}
	// Note: The part size might be different due to IPFS encoding/metadata
	// Just verify it's reasonable (not zero and not too large)
	if part.Size <= 0 || part.Size > int64(len(sourceData)*3) {
		t.Errorf("Expected reasonable part size, got %d (source was %d bytes)", part.Size, len(sourceData))
	}
}

func TestMultipartUpload_Clone(t *testing.T) {
	original := NewMultipartUpload("test-bucket", "test-key", "test-owner")
	original.ContentType = "application/json"
	original.UserMetadata["custom"] = "value"
	original.Tags["env"] = "test"
	
	part := &MultipartPart{
		PartNumber:   1,
		CID:          "test-cid",
		Size:         1024,
		ETag:         "test-etag",
		LastModified: time.Now(),
		PinStatus:    PinStatusPinned,
		PinNodes:     []string{"node1", "node2"},
	}
	original.AddPart(part)
	original.AddTempPin("temp-cid-1")
	
	clone := original.Clone()
	
	// Verify clone has same values
	if clone.UploadID != original.UploadID {
		t.Errorf("Expected upload ID '%s', got '%s'", original.UploadID, clone.UploadID)
	}
	if clone.ContentType != original.ContentType {
		t.Errorf("Expected content type '%s', got '%s'", original.ContentType, clone.ContentType)
	}
	if clone.UserMetadata["custom"] != original.UserMetadata["custom"] {
		t.Error("User metadata not cloned correctly")
	}
	if clone.Tags["env"] != original.Tags["env"] {
		t.Error("Tags not cloned correctly")
	}
	
	// Verify parts are cloned
	clonedPart, exists := clone.GetPart(1)
	if !exists {
		t.Error("Part not cloned")
	}
	if clonedPart.CID != part.CID {
		t.Error("Part CID not cloned correctly")
	}
	
	// Verify temp pins are cloned
	clonedTempPins := clone.GetTempPins()
	if len(clonedTempPins) != 1 || clonedTempPins[0] != "temp-cid-1" {
		t.Error("Temp pins not cloned correctly")
	}
	
	// Verify independence (modifying clone doesn't affect original)
	clone.UserMetadata["custom"] = "modified"
	if original.UserMetadata["custom"] == "modified" {
		t.Error("Clone is not independent - modifying clone affected original")
	}
	
	clonedPart.CID = "modified-cid"
	originalPart, _ := original.GetPart(1)
	if originalPart.CID == "modified-cid" {
		t.Error("Clone is not independent - modifying cloned part affected original")
	}
}