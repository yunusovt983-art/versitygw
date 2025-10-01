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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/s3err"
	"github.com/versity/versitygw/s3response"
)

func TestIPFSBackend_ListObjects(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucketName := "test-list-bucket"

	// Create test bucket
	createInput := &s3.CreateBucketInput{
		Bucket: stringPtr(bucketName),
	}
	err := backend.CreateBucket(ctx, createInput, []byte("private"))
	if err != nil {
		t.Fatalf("failed to create test bucket: %v", err)
	}

	// Create test objects
	testObjects := []struct {
		key  string
		data string
	}{
		{"file1.txt", "content1"},
		{"file2.txt", "content2"},
		{"dir1/file3.txt", "content3"},
		{"dir1/file4.txt", "content4"},
		{"dir2/file5.txt", "content5"},
	}

	for _, obj := range testObjects {
		putInput := s3response.PutObjectInput{
			Bucket: &bucketName,
			Key:    &obj.key,
			Body:   stringReader(obj.data),
		}
		_, err := backend.PutObject(ctx, putInput)
		if err != nil {
			t.Fatalf("failed to put object %s: %v", obj.key, err)
		}
	}

	tests := []struct {
		name           string
		input          *s3.ListObjectsInput
		expectedCount  int
		expectedKeys   []string
		expectError    bool
		errorCode      string
	}{
		{
			name: "list all objects",
			input: &s3.ListObjectsInput{
				Bucket: stringPtr(bucketName),
			},
			expectedCount: 5,
			expectedKeys:  []string{"dir1/file3.txt", "dir1/file4.txt", "dir2/file5.txt", "file1.txt", "file2.txt"},
			expectError:   false,
		},
		{
			name: "list with prefix",
			input: &s3.ListObjectsInput{
				Bucket: stringPtr(bucketName),
				Prefix: stringPtr("dir1/"),
			},
			expectedCount: 2,
			expectedKeys:  []string{"dir1/file3.txt", "dir1/file4.txt"},
			expectError:   false,
		},
		{
			name: "list with delimiter",
			input: &s3.ListObjectsInput{
				Bucket:    stringPtr(bucketName),
				Delimiter: stringPtr("/"),
			},
			expectedCount: 2, // file1.txt, file2.txt (dir1/ and dir2/ should be common prefixes)
			expectedKeys:  []string{"file1.txt", "file2.txt"},
			expectError:   false,
		},
		{
			name: "list with max keys",
			input: &s3.ListObjectsInput{
				Bucket:  stringPtr(bucketName),
				MaxKeys: int32Ptr(2),
			},
			expectedCount: 2,
			expectError:   false,
		},
		{
			name: "list with max keys 0",
			input: &s3.ListObjectsInput{
				Bucket:  stringPtr(bucketName),
				MaxKeys: int32Ptr(0),
			},
			expectedCount: 0,
			expectError:   false,
		},
		{
			name: "list non-existing bucket",
			input: &s3.ListObjectsInput{
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
			input: &s3.ListObjectsInput{
				Bucket: nil,
			},
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
		{
			name: "invalid max keys",
			input: &s3.ListObjectsInput{
				Bucket:  stringPtr(bucketName),
				MaxKeys: int32Ptr(-1),
			},
			expectError: true,
			errorCode:   "InvalidArgument",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := backend.ListObjects(ctx, tt.input)

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

				if len(result.Contents) != tt.expectedCount {
					t.Errorf("expected %d objects, got %d", tt.expectedCount, len(result.Contents))
				}

				// Check specific keys if provided
				if tt.expectedKeys != nil {
					foundKeys := make([]string, len(result.Contents))
					for i, obj := range result.Contents {
						if obj.Key != nil {
							foundKeys[i] = *obj.Key
						}
					}

					for _, expectedKey := range tt.expectedKeys {
						found := false
						for _, foundKey := range foundKeys {
							if foundKey == expectedKey {
								found = true
								break
							}
						}
						if !found {
							t.Errorf("expected key %s not found in results", expectedKey)
						}
					}
				}

				// Verify response structure
				if result.Name == nil || *result.Name != bucketName {
					t.Errorf("expected bucket name %s, got %v", bucketName, result.Name)
				}

				if result.IsTruncated == nil {
					t.Errorf("IsTruncated should not be nil")
				}

				if result.MaxKeys == nil {
					t.Errorf("MaxKeys should not be nil")
				}
			}
		})
	}
}

func TestIPFSBackend_ListObjectsV2(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucketName := "test-listv2-bucket"

	// Create test bucket
	createInput := &s3.CreateBucketInput{
		Bucket: stringPtr(bucketName),
	}
	err := backend.CreateBucket(ctx, createInput, []byte("private"))
	if err != nil {
		t.Fatalf("failed to create test bucket: %v", err)
	}

	// Create test objects
	testObjects := []struct {
		key  string
		data string
	}{
		{"a-file.txt", "content1"},
		{"b-file.txt", "content2"},
		{"c-file.txt", "content3"},
		{"d-file.txt", "content4"},
		{"e-file.txt", "content5"},
	}

	for _, obj := range testObjects {
		putInput := s3response.PutObjectInput{
			Bucket: &bucketName,
			Key:    &obj.key,
			Body:   stringReader(obj.data),
		}
		_, err := backend.PutObject(ctx, putInput)
		if err != nil {
			t.Fatalf("failed to put object %s: %v", obj.key, err)
		}
	}

	tests := []struct {
		name           string
		input          *s3.ListObjectsV2Input
		expectedCount  int
		expectedKeys   []string
		expectError    bool
		errorCode      string
	}{
		{
			name: "list all objects",
			input: &s3.ListObjectsV2Input{
				Bucket: stringPtr(bucketName),
			},
			expectedCount: 5,
			expectedKeys:  []string{"a-file.txt", "b-file.txt", "c-file.txt", "d-file.txt", "e-file.txt"},
			expectError:   false,
		},
		{
			name: "list with start after",
			input: &s3.ListObjectsV2Input{
				Bucket:     stringPtr(bucketName),
				StartAfter: stringPtr("b-file.txt"),
			},
			expectedCount: 3,
			expectedKeys:  []string{"c-file.txt", "d-file.txt", "e-file.txt"},
			expectError:   false,
		},
		{
			name: "list with max keys",
			input: &s3.ListObjectsV2Input{
				Bucket:  stringPtr(bucketName),
				MaxKeys: int32Ptr(3),
			},
			expectedCount: 3,
			expectError:   false,
		},
		{
			name: "list with max keys 0",
			input: &s3.ListObjectsV2Input{
				Bucket:  stringPtr(bucketName),
				MaxKeys: int32Ptr(0),
			},
			expectedCount: 0,
			expectError:   false,
		},
		{
			name: "list non-existing bucket",
			input: &s3.ListObjectsV2Input{
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
			input: &s3.ListObjectsV2Input{
				Bucket: nil,
			},
			expectError: true,
			errorCode:   "InvalidBucketName",
		},
		{
			name: "invalid max keys",
			input: &s3.ListObjectsV2Input{
				Bucket:  stringPtr(bucketName),
				MaxKeys: int32Ptr(-1),
			},
			expectError: true,
			errorCode:   "InvalidArgument",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := backend.ListObjectsV2(ctx, tt.input)

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

				if len(result.Contents) != tt.expectedCount {
					t.Errorf("expected %d objects, got %d", tt.expectedCount, len(result.Contents))
				}

				// Check specific keys if provided
				if tt.expectedKeys != nil {
					foundKeys := make([]string, len(result.Contents))
					for i, obj := range result.Contents {
						if obj.Key != nil {
							foundKeys[i] = *obj.Key
						}
					}

					for _, expectedKey := range tt.expectedKeys {
						found := false
						for _, foundKey := range foundKeys {
							if foundKey == expectedKey {
								found = true
								break
							}
						}
						if !found {
							t.Errorf("expected key %s not found in results", expectedKey)
						}
					}
				}

				// Verify response structure
				if result.Name == nil || *result.Name != bucketName {
					t.Errorf("expected bucket name %s, got %v", bucketName, result.Name)
				}

				if result.IsTruncated == nil {
					t.Errorf("IsTruncated should not be nil")
				}

				if result.MaxKeys == nil {
					t.Errorf("MaxKeys should not be nil")
				}

				if result.KeyCount == nil {
					t.Errorf("KeyCount should not be nil")
				} else if *result.KeyCount != int32(len(result.Contents)) {
					t.Errorf("KeyCount %d does not match actual count %d", *result.KeyCount, len(result.Contents))
				}
			}
		})
	}
}

func TestIPFSBackend_ListObjects_Pagination(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucketName := "test-pagination-bucket"

	// Create test bucket
	createInput := &s3.CreateBucketInput{
		Bucket: stringPtr(bucketName),
	}
	err := backend.CreateBucket(ctx, createInput, []byte("private"))
	if err != nil {
		t.Fatalf("failed to create test bucket: %v", err)
	}

	// Create many test objects for pagination testing
	objectCount := 25
	for i := 0; i < objectCount; i++ {
		key := fmt.Sprintf("object-%03d.txt", i)
		putInput := s3response.PutObjectInput{
			Bucket: &bucketName,
			Key:    &key,
			Body:   stringReader(fmt.Sprintf("content-%d", i)),
		}
		_, err := backend.PutObject(ctx, putInput)
		if err != nil {
			t.Fatalf("failed to put object %s: %v", key, err)
		}
	}

	// Test pagination with ListObjects
	t.Run("ListObjects pagination", func(t *testing.T) {
		var allObjects []string
		marker := ""
		maxKeys := int32(10)

		for {
			input := &s3.ListObjectsInput{
				Bucket:  stringPtr(bucketName),
				MaxKeys: &maxKeys,
			}
			if marker != "" {
				input.Marker = &marker
			}

			result, err := backend.ListObjects(ctx, input)
			if err != nil {
				t.Fatalf("ListObjects failed: %v", err)
			}

			for _, obj := range result.Contents {
				if obj.Key != nil {
					allObjects = append(allObjects, *obj.Key)
				}
			}

			if result.IsTruncated == nil || !*result.IsTruncated {
				break
			}

			if result.NextMarker != nil {
				marker = *result.NextMarker
			} else if len(result.Contents) > 0 && result.Contents[len(result.Contents)-1].Key != nil {
				marker = *result.Contents[len(result.Contents)-1].Key
			} else {
				break
			}
		}

		if len(allObjects) != objectCount {
			t.Errorf("expected %d objects, got %d", objectCount, len(allObjects))
		}
	})

	// Test pagination with ListObjectsV2
	t.Run("ListObjectsV2 pagination", func(t *testing.T) {
		var allObjects []string
		continuationToken := ""
		maxKeys := int32(10)

		for {
			input := &s3.ListObjectsV2Input{
				Bucket:  stringPtr(bucketName),
				MaxKeys: &maxKeys,
			}
			if continuationToken != "" {
				input.ContinuationToken = &continuationToken
			}

			result, err := backend.ListObjectsV2(ctx, input)
			if err != nil {
				t.Fatalf("ListObjectsV2 failed: %v", err)
			}

			for _, obj := range result.Contents {
				if obj.Key != nil {
					allObjects = append(allObjects, *obj.Key)
				}
			}

			if result.IsTruncated == nil || !*result.IsTruncated {
				break
			}

			if result.NextContinuationToken != nil {
				continuationToken = *result.NextContinuationToken
			} else {
				break
			}
		}

		if len(allObjects) != objectCount {
			t.Errorf("expected %d objects, got %d", objectCount, len(allObjects))
		}
	})
}

func TestIPFSBackend_ListObjects_Cache(t *testing.T) {
	backend, cleanup := setupTestBackend(t)
	defer cleanup()

	ctx := context.Background()
	bucketName := "test-cache-bucket"

	// Create test bucket
	createInput := &s3.CreateBucketInput{
		Bucket: stringPtr(bucketName),
	}
	err := backend.CreateBucket(ctx, createInput, []byte("private"))
	if err != nil {
		t.Fatalf("failed to create test bucket: %v", err)
	}

	// Create test object
	putInput := s3response.PutObjectInput{
		Bucket: &bucketName,
		Key:    stringPtr("test-object.txt"),
		Body:   stringReader("test content"),
	}
	_, err = backend.PutObject(ctx, putInput)
	if err != nil {
		t.Fatalf("failed to put object: %v", err)
	}

	// First call - should populate cache
	input := &s3.ListObjectsInput{
		Bucket: stringPtr(bucketName),
	}
	
	start := time.Now()
	result1, err := backend.ListObjects(ctx, input)
	duration1 := time.Since(start)
	if err != nil {
		t.Fatalf("first ListObjects failed: %v", err)
	}

	// Second call - should use cache (should be faster)
	start = time.Now()
	result2, err := backend.ListObjects(ctx, input)
	duration2 := time.Since(start)
	if err != nil {
		t.Fatalf("second ListObjects failed: %v", err)
	}

	// Verify results are the same
	if len(result1.Contents) != len(result2.Contents) {
		t.Errorf("cached result has different object count: %d vs %d", len(result1.Contents), len(result2.Contents))
	}

	// Cache should make the second call faster (though this is not guaranteed in tests)
	t.Logf("First call: %v, Second call: %v", duration1, duration2)
}

// Helper functions
func stringReader(s string) *strings.Reader {
	return strings.NewReader(s)
}