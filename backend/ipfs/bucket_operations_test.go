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
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestIPFSBackend_CreateBucket(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name        string
		input       *s3.CreateBucketInput
		defaultACL  []byte
		expectError bool
		errorCode   string
	}{
		{
			name: "valid bucket creation",
			input: &s3.CreateBucketInput{
				Bucket: stringPtr("test-bucket"),
			},
			defaultACL:  []byte("private"),
			expectError: false,
		},
		{
			name: "bucket with region",
			input: &s3.CreateBucketInput{
				Bucket: stringPtr("test-bucket-region"),
				CreateBucketConfiguration: &types.CreateBucketConfiguration{
					LocationConstraint: types.BucketLocationConstraint("us-west-2"),
				},
			},
			defaultACL:  []byte("private"),
			expectError: false,
		},
		{
			name: "bucket with object lock",
			input: &s3.CreateBucketInput{
				Bucket:                     stringPtr("test-bucket-lock"),
				ObjectLockEnabledForBucket: boolPtr(true),
			},
			defaultACL:  []byte("private"),
			expectError: false,
		},
		{
			name:        "nil input",
			input:       nil,
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
		{
			name: "nil bucket name",
			input: &s3.CreateBucketInput{
				Bucket: nil,
			},
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
		{
			name: "invalid bucket name - too short",
			input: &s3.CreateBucketInput{
				Bucket: stringPtr("ab"),
			},
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
		{
			name: "invalid bucket name - too long",
			input: &s3.CreateBucketInput{
				Bucket: stringPtr("this-bucket-name-is-way-too-long-and-exceeds-the-maximum-allowed-length-of-sixty-three-characters"),
			},
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
		{
			name: "invalid bucket name - uppercase",
			input: &s3.CreateBucketInput{
				Bucket: stringPtr("Test-Bucket"),
			},
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
		{
			name: "invalid bucket name - starts with hyphen",
			input: &s3.CreateBucketInput{
				Bucket: stringPtr("-test-bucket"),
			},
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
		{
			name: "invalid bucket name - ends with hyphen",
			input: &s3.CreateBucketInput{
				Bucket: stringPtr("test-bucket-"),
			},
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
		{
			name: "invalid bucket name - consecutive periods",
			input: &s3.CreateBucketInput{
				Bucket: stringPtr("test..bucket"),
			},
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
		{
			name: "invalid bucket name - IP address format",
			input: &s3.CreateBucketInput{
				Bucket: stringPtr("192.168.1.1"),
			},
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := backend.CreateBucket(ctx, tt.input, tt.defaultACL)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if apiErr, ok := err.(s3err.APIError); ok {
					if apiErr.Code != tt.errorCode {
						t.Errorf("expected error code %s, got %s", tt.errorCode, apiErr.Code)
					}
				} else {
					t.Errorf("expected APIError, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}

				// Verify bucket was created
				bucketName := *tt.input.Bucket
				metadata, err := backend.GetCachedBucketMetadata(ctx, bucketName)
				if err != nil {
					t.Errorf("failed to get created bucket metadata: %v", err)
					return
				}

				if metadata.Name != bucketName {
					t.Errorf("expected bucket name %s, got %s", bucketName, metadata.Name)
				}

				if tt.input.CreateBucketConfiguration != nil && tt.input.CreateBucketConfiguration.LocationConstraint != "" {
					expectedRegion := string(tt.input.CreateBucketConfiguration.LocationConstraint)
					if metadata.Region != expectedRegion {
						t.Errorf("expected region %s, got %s", expectedRegion, metadata.Region)
					}
				}

				if tt.input.ObjectLockEnabledForBucket != nil && *tt.input.ObjectLockEnabledForBucket {
					if metadata.Tags["ObjectLockEnabled"] != "true" {
						t.Errorf("expected ObjectLockEnabled tag to be true")
					}
				}
			}
		})
	}
}

func TestIPFSBackend_CreateBucket_AlreadyExists(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucketName := "existing-bucket"

	// Create bucket first time
	input := &s3.CreateBucketInput{
		Bucket: stringPtr(bucketName),
	}
	err := backend.CreateBucket(ctx, input, []byte("private"))
	if err != nil {
		t.Fatalf("failed to create bucket first time: %v", err)
	}

	// Try to create same bucket again
	err = backend.CreateBucket(ctx, input, []byte("private"))
	if err == nil {
		t.Errorf("expected error when creating existing bucket")
		return
	}

	if apiErr, ok := err.(s3err.APIError); ok {
		if apiErr.Code != "BucketAlreadyExists" {
			t.Errorf("expected BucketAlreadyExists error, got %s", apiErr.Code)
		}
	} else {
		t.Errorf("expected APIError, got %T", err)
	}
}

func TestIPFSBackend_ListBuckets(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	owner := "test-owner"

	// Create test buckets
	buckets := []string{"bucket1", "bucket2", "bucket3"}
	for _, bucketName := range buckets {
		input := &s3.CreateBucketInput{
			Bucket: stringPtr(bucketName),
		}
		err := backend.CreateBucket(ctx, input, []byte("private"))
		if err != nil {
			t.Fatalf("failed to create bucket %s: %v", bucketName, err)
		}
	}

	tests := []struct {
		name           string
		input          s3response.ListBucketsInput
		expectedCount  int
		expectError    bool
	}{
		{
			name: "list all buckets as admin",
			input: s3response.ListBucketsInput{
				Owner:   owner,
				IsAdmin: true,
			},
			expectedCount: 3,
			expectError:   false,
		},
		{
			name: "list buckets as owner",
			input: s3response.ListBucketsInput{
				Owner:   "default-owner", // This is the default owner set in NewBucketMetadata
				IsAdmin: false,
			},
			expectedCount: 3,
			expectError:   false,
		},
		{
			name: "list buckets as different owner",
			input: s3response.ListBucketsInput{
				Owner:   "different-owner",
				IsAdmin: false,
			},
			expectedCount: 0,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := backend.ListBuckets(ctx, tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}

				if len(result.Buckets.Bucket) != tt.expectedCount {
					t.Errorf("expected %d buckets, got %d", tt.expectedCount, len(result.Buckets.Bucket))
				}

				// Verify owner information
				if result.Owner.ID != tt.input.Owner {
					t.Errorf("expected owner ID %s, got %s", tt.input.Owner, result.Owner.ID)
				}

				// Verify bucket names if we expect any
				if tt.expectedCount > 0 {
					foundBuckets := make(map[string]bool)
					for _, bucket := range result.Buckets.Bucket {
						foundBuckets[bucket.Name] = true
					}

					if tt.input.IsAdmin || tt.input.Owner == "default-owner" {
						for _, expectedBucket := range buckets {
							if !foundBuckets[expectedBucket] {
								t.Errorf("expected bucket %s not found in results", expectedBucket)
							}
						}
					}
				}
			}
		})
	}
}

func TestIPFSBackend_HeadBucket(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucketName := "test-head-bucket"

	// Create a test bucket
	createInput := &s3.CreateBucketInput{
		Bucket: stringPtr(bucketName),
		CreateBucketConfiguration: &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint("us-west-2"),
		},
	}
	err := backend.CreateBucket(ctx, createInput, []byte("private"))
	if err != nil {
		t.Fatalf("failed to create test bucket: %v", err)
	}

	tests := []struct {
		name        string
		input       *s3.HeadBucketInput
		expectError bool
		errorCode   string
	}{
		{
			name: "existing bucket",
			input: &s3.HeadBucketInput{
				Bucket: stringPtr(bucketName),
			},
			expectError: false,
		},
		{
			name: "non-existing bucket",
			input: &s3.HeadBucketInput{
				Bucket: stringPtr("non-existing-bucket"),
			},
			expectError: true,
			errorCode:   "NoSuchBucket",
		},
		{
			name:        "nil input",
			input:       nil,
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
		{
			name: "nil bucket name",
			input: &s3.HeadBucketInput{
				Bucket: nil,
			},
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := backend.HeadBucket(ctx, tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if apiErr, ok := err.(s3err.APIError); ok {
					if apiErr.Code != tt.errorCode {
						t.Errorf("expected error code %s, got %s", tt.errorCode, apiErr.Code)
					}
				} else {
					t.Errorf("expected APIError, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}

				if output == nil {
					t.Errorf("expected output but got nil")
					return
				}

				if output.BucketRegion == nil {
					t.Errorf("expected bucket region but got nil")
				} else if *output.BucketRegion != "us-west-2" {
					t.Errorf("expected region us-west-2, got %s", *output.BucketRegion)
				}
			}
		})
	}
}

func TestIPFSBackend_DeleteBucket(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name        string
		bucketName  string
		setupFunc   func(string) error
		expectError bool
		errorCode   string
	}{
		{
			name:       "delete empty bucket",
			bucketName: "empty-bucket",
			setupFunc: func(bucket string) error {
				input := &s3.CreateBucketInput{
					Bucket: stringPtr(bucket),
				}
				return backend.CreateBucket(ctx, input, []byte("private"))
			},
			expectError: false,
		},
		{
			name:       "delete non-existing bucket",
			bucketName: "non-existing-bucket",
			setupFunc:  func(bucket string) error { return nil },
			expectError: true,
			errorCode:   "NoSuchBucket",
		},
		{
			name:       "invalid bucket name",
			bucketName: "Invalid-Bucket-Name",
			setupFunc:  func(bucket string) error { return nil },
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			if err := tt.setupFunc(tt.bucketName); err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			// Test delete
			err := backend.DeleteBucket(ctx, tt.bucketName)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if apiErr, ok := err.(s3err.APIError); ok {
					if apiErr.Code != tt.errorCode {
						t.Errorf("expected error code %s, got %s", tt.errorCode, apiErr.Code)
					}
				} else {
					t.Errorf("expected APIError, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}

				// Verify bucket was deleted
				_, err := backend.GetCachedBucketMetadata(ctx, tt.bucketName)
				if err == nil {
					t.Errorf("bucket still exists after deletion")
				}
			}
		})
	}
}

// Helper functions are now in ipfs.go

func TestValidateBucketName(t *testing.T) {
	tests := []struct {
		name        string
		bucketName  string
		expectError bool
	}{
		{"valid name", "test-bucket", false},
		{"valid with numbers", "test-bucket-123", false},
		{"valid with periods", "test.bucket.name", false},
		{"minimum length", "abc", false},
		{"maximum length", "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxy", false},
		{"too short", "ab", true},
		{"too long", "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234", true},
		{"uppercase letters", "Test-Bucket", true},
		{"starts with hyphen", "-test-bucket", true},
		{"ends with hyphen", "test-bucket-", true},
		{"starts with period", ".test-bucket", true},
		{"ends with period", "test-bucket.", true},
		{"consecutive periods", "test..bucket", true},
		{"IP address format", "192.168.1.1", true},
		{"invalid characters", "test_bucket", true},
		{"spaces", "test bucket", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBucketName(tt.bucketName)
			if tt.expectError && err == nil {
				t.Errorf("expected error for bucket name %s", tt.bucketName)
			} else if !tt.expectError && err != nil {
				t.Errorf("unexpected error for bucket name %s: %v", tt.bucketName, err)
			}
		})
	}
}