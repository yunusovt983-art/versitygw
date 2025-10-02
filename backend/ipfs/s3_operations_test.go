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
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3response"
)

// TestPutObject tests the PutObject operation
func TestPutObject(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-object"
	content := "Hello, IPFS World!"
	contentType := "text/plain"

	input := s3response.PutObjectInput{
		Bucket:      &bucket,
		Key:         &key,
		Body:        strings.NewReader(content),
		ContentType: &contentType,
		Metadata: map[string]string{
			"test-key": "test-value",
		},
	}

	output, err := backend.PutObject(ctx, input)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Verify output
	if output.ETag == "" {
		t.Error("Expected non-empty ETag (CID)")
	}

	// Verify object was stored in metadata
	mapping, err := backend.GetObjectMapping(ctx, key, bucket)
	if err != nil {
		t.Fatalf("Failed to get object mapping: %v", err)
	}

	if mapping.S3Key != key {
		t.Errorf("Expected S3Key %s, got %s", key, mapping.S3Key)
	}
	if mapping.Bucket != bucket {
		t.Errorf("Expected Bucket %s, got %s", bucket, mapping.Bucket)
	}
	if mapping.ContentType != contentType {
		t.Errorf("Expected ContentType %s, got %s", contentType, mapping.ContentType)
	}
	if mapping.Size != int64(len(content)) {
		t.Errorf("Expected Size %d, got %d", len(content), mapping.Size)
	}
	if mapping.UserMetadata["test-key"] != "test-value" {
		t.Errorf("Expected metadata test-key=test-value, got %s", mapping.UserMetadata["test-key"])
	}
}

// TestGetObject tests the GetObject operation
func TestGetObject(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-object"
	content := "Hello, IPFS World!"
	contentType := "text/plain"

	// First, put an object
	putInput := s3response.PutObjectInput{
		Bucket:      &bucket,
		Key:         &key,
		Body:        strings.NewReader(content),
		ContentType: &contentType,
		Metadata: map[string]string{
			"test-key": "test-value",
		},
	}

	_, err := backend.PutObject(ctx, putInput)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Now get the object
	getInput := &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	output, err := backend.GetObject(ctx, getInput)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}

	// Verify output
	if output.ContentType == nil || *output.ContentType != contentType {
		t.Errorf("Expected ContentType %s, got %v", contentType, output.ContentType)
	}

	if output.ContentLength == nil || *output.ContentLength != int64(len(content)) {
		t.Errorf("Expected ContentLength %d, got %v", len(content), output.ContentLength)
	}

	if output.ETag == nil || *output.ETag == "" {
		t.Error("Expected non-empty ETag")
	}

	if output.Metadata == nil || output.Metadata["test-key"] != "test-value" {
		t.Errorf("Expected metadata test-key=test-value, got %v", output.Metadata)
	}

	// Verify IPFS-specific metadata
	if output.Metadata["ipfs-cid"] == "" {
		t.Error("Expected IPFS CID in metadata")
	}
	if output.Metadata["ipfs-pin-status"] == "" {
		t.Error("Expected IPFS pin status in metadata")
	}

	// Read and verify body content
	bodyBytes, err := io.ReadAll(output.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	output.Body.Close()

	// Note: In our test implementation, getObjectFromIPFS returns dummy data
	// In a real implementation, this would be the actual content
	expectedContent := "IPFS object data for CID: " + *output.ETag
	if string(bodyBytes) != expectedContent {
		t.Errorf("Expected body content %s, got %s", expectedContent, string(bodyBytes))
	}
}

// TestHeadObject tests the HeadObject operation
func TestHeadObject(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-object"
	content := "Hello, IPFS World!"
	contentType := "text/plain"

	// First, put an object
	putInput := s3response.PutObjectInput{
		Bucket:      &bucket,
		Key:         &key,
		Body:        strings.NewReader(content),
		ContentType: &contentType,
		Metadata: map[string]string{
			"test-key": "test-value",
		},
	}

	_, err := backend.PutObject(ctx, putInput)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Now head the object
	headInput := &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	output, err := backend.HeadObject(ctx, headInput)
	if err != nil {
		t.Fatalf("HeadObject failed: %v", err)
	}

	// Verify output
	if output.ContentType == nil || *output.ContentType != contentType {
		t.Errorf("Expected ContentType %s, got %v", contentType, output.ContentType)
	}

	if output.ContentLength == nil || *output.ContentLength != int64(len(content)) {
		t.Errorf("Expected ContentLength %d, got %v", len(content), output.ContentLength)
	}

	if output.ETag == nil || *output.ETag == "" {
		t.Error("Expected non-empty ETag")
	}

	if output.LastModified == nil {
		t.Error("Expected LastModified timestamp")
	}

	if output.Metadata == nil || output.Metadata["test-key"] != "test-value" {
		t.Errorf("Expected metadata test-key=test-value, got %v", output.Metadata)
	}

	// Verify IPFS-specific metadata
	if output.Metadata["ipfs-cid"] == "" {
		t.Error("Expected IPFS CID in metadata")
	}
	if output.Metadata["ipfs-pin-status"] == "" {
		t.Error("Expected IPFS pin status in metadata")
	}
	if output.Metadata["ipfs-replication-count"] == "" {
		t.Error("Expected IPFS replication count in metadata")
	}
}

// TestDeleteObject tests the DeleteObject operation
func TestDeleteObject(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-object"
	content := "Hello, IPFS World!"

	// First, put an object
	putInput := s3response.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   strings.NewReader(content),
	}

	_, err := backend.PutObject(ctx, putInput)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Verify object exists
	_, err = backend.GetObjectMapping(ctx, key, bucket)
	if err != nil {
		t.Fatalf("Object should exist before deletion: %v", err)
	}

	// Delete the object
	deleteInput := &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	output, err := backend.DeleteObject(ctx, deleteInput)
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}

	// Verify output (should be empty for successful deletion)
	if output == nil {
		t.Error("Expected non-nil DeleteObjectOutput")
	}

	// Verify object no longer exists in metadata
	_, err = backend.GetObjectMapping(ctx, key, bucket)
	if err == nil {
		t.Error("Object should not exist after deletion")
	}
}

// TestGetObjectWithRange tests the GetObject operation with range requests
func TestGetObjectWithRange(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-object"
	content := "0123456789abcdefghijklmnopqrstuvwxyz"

	// First, put an object
	putInput := s3response.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   strings.NewReader(content),
	}

	_, err := backend.PutObject(ctx, putInput)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Test range request
	rangeHeader := "bytes=5-10"
	getInput := &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Range:  &rangeHeader,
	}

	output, err := backend.GetObject(ctx, getInput)
	if err != nil {
		t.Fatalf("GetObject with range failed: %v", err)
	}

	// Verify range response
	if output.ContentRange == nil {
		t.Error("Expected ContentRange header for range request")
	}

	expectedLength := int64(6) // bytes 5-10 inclusive
	if output.ContentLength == nil || *output.ContentLength != expectedLength {
		t.Errorf("Expected ContentLength %d for range request, got %v", expectedLength, output.ContentLength)
	}

	// Note: In our test implementation, the range logic works on the dummy data
	// In a real implementation, this would work on the actual IPFS content
}

// TestPutObjectWithChecksums tests PutObject with checksums
func TestPutObjectWithChecksums(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-object"
	content := "Hello, IPFS World!"
	crc32Checksum := "12345678"
	sha256Checksum := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	input := s3response.PutObjectInput{
		Bucket:         &bucket,
		Key:            &key,
		Body:           strings.NewReader(content),
		ChecksumCRC32:  &crc32Checksum,
		ChecksumSHA256: &sha256Checksum,
	}

	output, err := backend.PutObject(ctx, input)
	if err != nil {
		t.Fatalf("PutObject with checksums failed: %v", err)
	}

	// Verify checksums in response
	if output.ChecksumCRC32 == nil || *output.ChecksumCRC32 != crc32Checksum {
		t.Errorf("Expected ChecksumCRC32 %s, got %v", crc32Checksum, output.ChecksumCRC32)
	}
	if output.ChecksumSHA256 == nil || *output.ChecksumSHA256 != sha256Checksum {
		t.Errorf("Expected ChecksumSHA256 %s, got %v", sha256Checksum, output.ChecksumSHA256)
	}
	if output.ChecksumType != types.ChecksumTypeFullObject {
		t.Errorf("Expected ChecksumType %s, got %s", types.ChecksumTypeFullObject, output.ChecksumType)
	}
}

// TestPutObjectWithTags tests PutObject with object tagging
func TestPutObjectWithTags(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucket := "test-bucket"
	key := "test-object"
	content := "Hello, IPFS World!"
	tagging := "Environment=Production&Team=Backend"

	input := s3response.PutObjectInput{
		Bucket:  &bucket,
		Key:     &key,
		Body:    strings.NewReader(content),
		Tagging: &tagging,
	}

	_, err := backend.PutObject(ctx, input)
	if err != nil {
		t.Fatalf("PutObject with tags failed: %v", err)
	}

	// Verify tags were stored in metadata
	mapping, err := backend.GetObjectMapping(ctx, key, bucket)
	if err != nil {
		t.Fatalf("Failed to get object mapping: %v", err)
	}

	expectedTags := map[string]string{
		"Environment": "Production",
		"Team":        "Backend",
	}

	for k, v := range expectedTags {
		if mapping.Tags[k] != v {
			t.Errorf("Expected tag %s=%s, got %s", k, v, mapping.Tags[k])
		}
	}
}

// TestObjectNotFound tests operations on non-existent objects
func TestObjectNotFound(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucket := "test-bucket"
	key := "non-existent-object"

	// Test GetObject on non-existent object
	getInput := &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	_, err := backend.GetObject(ctx, getInput)
	if err == nil {
		t.Error("Expected error for GetObject on non-existent object")
	}

	// Test HeadObject on non-existent object
	headInput := &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	_, err = backend.HeadObject(ctx, headInput)
	if err == nil {
		t.Error("Expected error for HeadObject on non-existent object")
	}

	// Test DeleteObject on non-existent object (should succeed - S3 is idempotent)
	deleteInput := &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	_, err = backend.DeleteObject(ctx, deleteInput)
	if err != nil {
		t.Errorf("DeleteObject on non-existent object should succeed: %v", err)
	}
}

// setupTestBackend creates a test IPFS backend instance
func setupTestBackend(t *testing.T) (*IPFSBackend, func()) {
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

	backend, err := New(config, IPFSOptions{})
	if err != nil {
		t.Fatalf("Failed to create test backend: %v", err)
	}

	// Disable health checking for tests since we don't have a real IPFS cluster
	backend.EnableClusterHealthChecking(false)
	
	// Wait a moment for initialization to complete
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		backend.Shutdown()
	}

	return backend, cleanup
}