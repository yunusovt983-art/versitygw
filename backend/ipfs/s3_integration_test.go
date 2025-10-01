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
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3response"
)

// TestS3OperationsIntegration tests the complete S3 operations workflow
func TestS3OperationsIntegration(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucket := "integration-test-bucket"
	key := "integration-test-object"
	content := "This is a test object for IPFS integration"
	contentType := "text/plain"

	// Step 1: Put an object
	t.Log("Step 1: PutObject")
	putInput := s3response.PutObjectInput{
		Bucket:      &bucket,
		Key:         &key,
		Body:        strings.NewReader(content),
		ContentType: &contentType,
		Metadata: map[string]string{
			"test-environment": "integration",
			"test-purpose":     "s3-operations",
		},
	}

	putOutput, err := backend.PutObject(ctx, putInput)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	if putOutput.ETag == "" {
		t.Error("Expected non-empty ETag from PutObject")
	}
	t.Logf("PutObject successful, ETag: %s", putOutput.ETag)

	// Step 2: Head the object to verify metadata
	t.Log("Step 2: HeadObject")
	headInput := &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	headOutput, err := backend.HeadObject(ctx, headInput)
	if err != nil {
		t.Fatalf("HeadObject failed: %v", err)
	}

	// Verify metadata
	if headOutput.ContentType == nil || *headOutput.ContentType != contentType {
		t.Errorf("Expected ContentType %s, got %v", contentType, headOutput.ContentType)
	}
	if headOutput.ContentLength == nil || *headOutput.ContentLength != int64(len(content)) {
		t.Errorf("Expected ContentLength %d, got %v", len(content), headOutput.ContentLength)
	}
	if headOutput.ETag == nil || *headOutput.ETag != putOutput.ETag {
		t.Errorf("Expected ETag %s, got %v", putOutput.ETag, headOutput.ETag)
	}

	// Verify user metadata
	if headOutput.Metadata["test-environment"] != "integration" {
		t.Errorf("Expected metadata test-environment=integration, got %s", headOutput.Metadata["test-environment"])
	}

	// Verify IPFS-specific metadata
	if headOutput.Metadata["ipfs-cid"] == "" {
		t.Error("Expected IPFS CID in metadata")
	}
	if headOutput.Metadata["ipfs-pin-status"] == "" {
		t.Error("Expected IPFS pin status in metadata")
	}

	t.Logf("HeadObject successful, CID: %s, Pin Status: %s", 
		headOutput.Metadata["ipfs-cid"], headOutput.Metadata["ipfs-pin-status"])

	// Step 3: Get the object and verify content
	t.Log("Step 3: GetObject")
	getInput := &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	getOutput, err := backend.GetObject(ctx, getInput)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}

	// Verify response metadata matches HeadObject
	if getOutput.ContentType == nil || *getOutput.ContentType != *headOutput.ContentType {
		t.Error("GetObject ContentType doesn't match HeadObject")
	}
	if getOutput.ContentLength == nil || *getOutput.ContentLength != *headOutput.ContentLength {
		t.Error("GetObject ContentLength doesn't match HeadObject")
	}
	if getOutput.ETag == nil || *getOutput.ETag != *headOutput.ETag {
		t.Error("GetObject ETag doesn't match HeadObject")
	}

	// Verify IPFS metadata is present
	if getOutput.Metadata["ipfs-cid"] != headOutput.Metadata["ipfs-cid"] {
		t.Error("GetObject IPFS CID doesn't match HeadObject")
	}

	getOutput.Body.Close()
	t.Log("GetObject successful")

	// Step 4: Delete the object
	t.Log("Step 4: DeleteObject")
	deleteInput := &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	deleteOutput, err := backend.DeleteObject(ctx, deleteInput)
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}

	if deleteOutput == nil {
		t.Error("Expected non-nil DeleteObjectOutput")
	}
	t.Log("DeleteObject successful")

	// Step 5: Verify object is deleted
	t.Log("Step 5: Verify deletion")
	_, err = backend.HeadObject(ctx, headInput)
	if err == nil {
		t.Error("Expected error when accessing deleted object")
	}

	_, err = backend.GetObject(ctx, getInput)
	if err == nil {
		t.Error("Expected error when getting deleted object")
	}

	t.Log("Object deletion verified")

	// Step 6: Verify idempotent delete
	t.Log("Step 6: Test idempotent delete")
	_, err = backend.DeleteObject(ctx, deleteInput)
	if err != nil {
		t.Errorf("DeleteObject should be idempotent, but got error: %v", err)
	}

	t.Log("Integration test completed successfully!")
}

// TestS3OperationsWithLargeObject tests operations with larger objects
func TestS3OperationsWithLargeObject(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucket := "large-object-test-bucket"
	key := "large-test-object"
	
	// Create a larger content (1MB)
	content := strings.Repeat("This is a large test object for IPFS integration. ", 20000)
	contentType := "text/plain"

	t.Logf("Testing with large object: %d bytes", len(content))

	// Put the large object
	putInput := s3response.PutObjectInput{
		Bucket:      &bucket,
		Key:         &key,
		Body:        strings.NewReader(content),
		ContentType: &contentType,
	}

	putOutput, err := backend.PutObject(ctx, putInput)
	if err != nil {
		t.Fatalf("PutObject failed for large object: %v", err)
	}

	t.Logf("Large object stored with CID: %s", putOutput.ETag)

	// Head the object
	headInput := &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	headOutput, err := backend.HeadObject(ctx, headInput)
	if err != nil {
		t.Fatalf("HeadObject failed for large object: %v", err)
	}

	if headOutput.ContentLength == nil || *headOutput.ContentLength != int64(len(content)) {
		t.Errorf("Expected ContentLength %d, got %v", len(content), headOutput.ContentLength)
	}

	t.Log("Large object operations completed successfully")

	// Clean up
	deleteInput := &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	_, err = backend.DeleteObject(ctx, deleteInput)
	if err != nil {
		t.Errorf("Failed to delete large object: %v", err)
	}
}

// TestS3OperationsWithSpecialCharacters tests operations with special characters in keys
func TestS3OperationsWithSpecialCharacters(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucket := "special-chars-test-bucket"
	
	// Test various special characters in object keys
	testCases := []struct {
		name string
		key  string
	}{
		{"spaces", "object with spaces.txt"},
		{"unicode", "объект-тест-файл.txt"},
		{"special-chars", "object!@#$%^&*()_+-=[]{}|;':\",./<>?.txt"},
		{"path-like", "folder/subfolder/object.txt"},
		{"dots", "object.with.many.dots.txt"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			content := "Test content for " + tc.name
			
			// Put object
			putInput := s3response.PutObjectInput{
				Bucket: &bucket,
				Key:    &tc.key,
				Body:   strings.NewReader(content),
			}

			putOutput, err := backend.PutObject(ctx, putInput)
			if err != nil {
				t.Fatalf("PutObject failed for key %s: %v", tc.key, err)
			}

			// Head object
			headInput := &s3.HeadObjectInput{
				Bucket: &bucket,
				Key:    &tc.key,
			}

			_, err = backend.HeadObject(ctx, headInput)
			if err != nil {
				t.Fatalf("HeadObject failed for key %s: %v", tc.key, err)
			}

			// Delete object
			deleteInput := &s3.DeleteObjectInput{
				Bucket: &bucket,
				Key:    &tc.key,
			}

			_, err = backend.DeleteObject(ctx, deleteInput)
			if err != nil {
				t.Fatalf("DeleteObject failed for key %s: %v", tc.key, err)
			}

			t.Logf("Successfully tested key: %s (CID: %s)", tc.key, putOutput.ETag)
		})
	}
}