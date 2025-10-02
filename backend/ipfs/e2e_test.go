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
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/versity/versitygw/s3response"
)

// E2ETestSuite represents the end-to-end test suite for IPFS backend
type E2ETestSuite struct {
	backend    *IPFSBackend
	ctx        context.Context
	logger     *log.Logger
	testBucket string
}

// NewE2ETestSuite creates a new end-to-end test suite
func NewE2ETestSuite(t *testing.T) *E2ETestSuite {
	logger := log.New(os.Stdout, "[E2E] ", log.LstdFlags)
	
	// Create test configuration
	config := &IPFSConfig{
		ClusterEndpoints:    []string{"http://localhost:9094"}, // Default IPFS-Cluster endpoint
		ConnectTimeout:      30 * time.Second,
		RequestTimeout:      60 * time.Second,
		MaxRetries:          3,
		RetryDelay:          1 * time.Second,
		MaxConcurrentPins:   10,
		PinTimeout:          5 * time.Minute,
		ChunkSize:           1024 * 1024, // 1MB
		ReplicationMin:      1,
		ReplicationMax:      3,
		CompressionEnabled:  false,
		MetadataDBType:      "memory",
		MetadataDBEndpoints: []string{},
		CacheEndpoints:      []string{},
		CacheEnabled:        false,
		MetricsEnabled:      false,
		LogLevel:           "info",
		ReplicaManagerEnabled: false,
	}
	
	opts := IPFSOptions{
		Logger:  logger,
		Context: context.Background(),
	}
	
	// Create IPFS backend
	backend, err := New(config, opts)
	require.NoError(t, err, "Failed to create IPFS backend")
	
	return &E2ETestSuite{
		backend:    backend,
		ctx:        context.Background(),
		logger:     logger,
		testBucket: "e2e-test-bucket",
	}
}

// Cleanup cleans up test resources
func (suite *E2ETestSuite) Cleanup() {
	if suite.backend != nil {
		suite.backend.Shutdown()
	}
}

// TestFullWorkflow tests the complete IPFS backend workflow
func TestFullWorkflow(t *testing.T) {
	suite := NewE2ETestSuite(t)
	defer suite.Cleanup()
	
	t.Run("CreateBucket", suite.testCreateBucket)
	t.Run("PutObject", suite.testPutObject)
	t.Run("GetObject", suite.testGetObject)
	t.Run("HeadObject", suite.testHeadObject)
	t.Run("ListObjects", suite.testListObjects)
	t.Run("MultipartUpload", suite.testMultipartUpload)
	t.Run("DeleteObject", suite.testDeleteObject)
	t.Run("DeleteBucket", suite.testDeleteBucket)
}

// testCreateBucket tests bucket creation
func (suite *E2ETestSuite) testCreateBucket(t *testing.T) {
	suite.logger.Printf("Testing bucket creation: %s", suite.testBucket)
	
	input := &s3.CreateBucketInput{
		Bucket: &suite.testBucket,
	}
	
	err := suite.backend.CreateBucket(suite.ctx, input, nil)
	assert.NoError(t, err, "Failed to create bucket")
	
	// Verify bucket exists
	headInput := &s3.HeadBucketInput{
		Bucket: &suite.testBucket,
	}
	
	_, err = suite.backend.HeadBucket(suite.ctx, headInput)
	assert.NoError(t, err, "Bucket should exist after creation")
	
	suite.logger.Printf("✓ Bucket creation successful")
}

// testPutObject tests object upload
func (suite *E2ETestSuite) testPutObject(t *testing.T) {
	suite.logger.Printf("Testing object upload")
	
	testKey := "test-object.txt"
	testData := []byte("Hello, IPFS World! This is a test object.")
	
	input := s3response.PutObjectInput{
		Bucket: suite.testBucket,
		Key:    testKey,
		Body:   bytes.NewReader(testData),
		Metadata: map[string]string{
			"test-key": "test-value",
		},
	}
	
	output, err := suite.backend.PutObject(suite.ctx, input)
	assert.NoError(t, err, "Failed to put object")
	assert.NotEmpty(t, output.ETag, "ETag should not be empty")
	
	suite.logger.Printf("✓ Object upload successful, ETag: %s", output.ETag)
}

// testGetObject tests object download
func (suite *E2ETestSuite) testGetObject(t *testing.T) {
	suite.logger.Printf("Testing object download")
	
	testKey := "test-object.txt"
	expectedData := []byte("Hello, IPFS World! This is a test object.")
	
	input := &s3.GetObjectInput{
		Bucket: &suite.testBucket,
		Key:    &testKey,
	}
	
	output, err := suite.backend.GetObject(suite.ctx, input)
	assert.NoError(t, err, "Failed to get object")
	assert.NotNil(t, output.Body, "Object body should not be nil")
	
	// Read and verify data
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(output.Body)
	assert.NoError(t, err, "Failed to read object body")
	
	actualData := buf.Bytes()
	assert.Equal(t, expectedData, actualData, "Object data should match")
	
	// Verify metadata
	assert.NotNil(t, output.Metadata, "Metadata should not be nil")
	assert.Equal(t, "test-value", output.Metadata["test-key"], "Metadata should match")
	
	suite.logger.Printf("✓ Object download successful, size: %d bytes", len(actualData))
}

// testHeadObject tests object metadata retrieval
func (suite *E2ETestSuite) testHeadObject(t *testing.T) {
	suite.logger.Printf("Testing object head operation")
	
	testKey := "test-object.txt"
	
	input := &s3.HeadObjectInput{
		Bucket: &suite.testBucket,
		Key:    &testKey,
	}
	
	output, err := suite.backend.HeadObject(suite.ctx, input)
	assert.NoError(t, err, "Failed to head object")
	assert.NotNil(t, output.ContentLength, "Content length should not be nil")
	assert.Equal(t, int64(42), *output.ContentLength, "Content length should match")
	
	suite.logger.Printf("✓ Object head operation successful, size: %d", *output.ContentLength)
}

// testListObjects tests object listing
func (suite *E2ETestSuite) testListObjects(t *testing.T) {
	suite.logger.Printf("Testing object listing")
	
	// Upload additional test objects
	for i := 1; i <= 3; i++ {
		testKey := fmt.Sprintf("list-test-%d.txt", i)
		testData := []byte(fmt.Sprintf("Test data for object %d", i))
		
		input := s3response.PutObjectInput{
			Bucket: suite.testBucket,
			Key:    testKey,
			Body:   bytes.NewReader(testData),
		}
		
		_, err := suite.backend.PutObject(suite.ctx, input)
		assert.NoError(t, err, "Failed to put test object %d", i)
	}
	
	// List objects
	input := &s3.ListObjectsV2Input{
		Bucket: &suite.testBucket,
	}
	
	output, err := suite.backend.ListObjectsV2(suite.ctx, input)
	assert.NoError(t, err, "Failed to list objects")
	assert.NotNil(t, output.Contents, "Contents should not be nil")
	assert.GreaterOrEqual(t, len(output.Contents), 4, "Should have at least 4 objects")
	
	suite.logger.Printf("✓ Object listing successful, found %d objects", len(output.Contents))
}

// testMultipartUpload tests multipart upload functionality
func (suite *E2ETestSuite) testMultipartUpload(t *testing.T) {
	suite.logger.Printf("Testing multipart upload")
	
	testKey := "multipart-test.txt"
	
	// Create multipart upload
	createInput := &s3.CreateMultipartUploadInput{
		Bucket: &suite.testBucket,
		Key:    &testKey,
	}
	
	createOutput, err := suite.backend.CreateMultipartUpload(suite.ctx, createInput)
	assert.NoError(t, err, "Failed to create multipart upload")
	assert.NotEmpty(t, *createOutput.UploadId, "Upload ID should not be empty")
	
	uploadId := *createOutput.UploadId
	
	// Upload parts
	parts := []types.CompletedPart{}
	for i := 1; i <= 3; i++ {
		partData := []byte(fmt.Sprintf("Part %d data for multipart upload test", i))
		
		uploadInput := &s3.UploadPartInput{
			Bucket:     &suite.testBucket,
			Key:        &testKey,
			PartNumber: int32(i),
			UploadId:   &uploadId,
			Body:       bytes.NewReader(partData),
		}
		
		uploadOutput, err := suite.backend.UploadPart(suite.ctx, uploadInput)
		assert.NoError(t, err, "Failed to upload part %d", i)
		assert.NotEmpty(t, *uploadOutput.ETag, "Part ETag should not be empty")
		
		parts = append(parts, types.CompletedPart{
			ETag:       uploadOutput.ETag,
			PartNumber: int32(i),
		})
	}
	
	// Complete multipart upload
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   &suite.testBucket,
		Key:      &testKey,
		UploadId: &uploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: parts,
		},
	}
	
	completeOutput, err := suite.backend.CompleteMultipartUpload(suite.ctx, completeInput)
	assert.NoError(t, err, "Failed to complete multipart upload")
	assert.NotEmpty(t, *completeOutput.ETag, "Final ETag should not be empty")
	
	suite.logger.Printf("✓ Multipart upload successful, ETag: %s", *completeOutput.ETag)
}

// testDeleteObject tests object deletion
func (suite *E2ETestSuite) testDeleteObject(t *testing.T) {
	suite.logger.Printf("Testing object deletion")
	
	testKey := "test-object.txt"
	
	input := &s3.DeleteObjectInput{
		Bucket: &suite.testBucket,
		Key:    &testKey,
	}
	
	_, err := suite.backend.DeleteObject(suite.ctx, input)
	assert.NoError(t, err, "Failed to delete object")
	
	// Verify object is deleted
	getInput := &s3.GetObjectInput{
		Bucket: &suite.testBucket,
		Key:    &testKey,
	}
	
	_, err = suite.backend.GetObject(suite.ctx, getInput)
	assert.Error(t, err, "Object should not exist after deletion")
	
	suite.logger.Printf("✓ Object deletion successful")
}

// testDeleteBucket tests bucket deletion
func (suite *E2ETestSuite) testDeleteBucket(t *testing.T) {
	suite.logger.Printf("Testing bucket deletion")
	
	// Clean up remaining objects first
	listInput := &s3.ListObjectsV2Input{
		Bucket: &suite.testBucket,
	}
	
	listOutput, err := suite.backend.ListObjectsV2(suite.ctx, listInput)
	if err == nil && listOutput.Contents != nil {
		for _, obj := range listOutput.Contents {
			deleteInput := &s3.DeleteObjectInput{
				Bucket: &suite.testBucket,
				Key:    obj.Key,
			}
			suite.backend.DeleteObject(suite.ctx, deleteInput)
		}
	}
	
	// Delete bucket
	err = suite.backend.DeleteBucket(suite.ctx, suite.testBucket)
	assert.NoError(t, err, "Failed to delete bucket")
	
	// Verify bucket is deleted
	headInput := &s3.HeadBucketInput{
		Bucket: &suite.testBucket,
	}
	
	_, err = suite.backend.HeadBucket(suite.ctx, headInput)
	assert.Error(t, err, "Bucket should not exist after deletion")
	
	suite.logger.Printf("✓ Bucket deletion successful")
}

// TestPerformanceScenario tests performance with multiple concurrent operations
func TestPerformanceScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}
	
	suite := NewE2ETestSuite(t)
	defer suite.Cleanup()
	
	suite.logger.Printf("Starting performance test scenario")
	
	// Create test bucket
	input := &s3.CreateBucketInput{
		Bucket: &suite.testBucket,
	}
	err := suite.backend.CreateBucket(suite.ctx, input, nil)
	require.NoError(t, err)
	
	// Test concurrent uploads
	numObjects := 100
	objectSize := 1024 * 10 // 10KB
	
	start := time.Now()
	
	for i := 0; i < numObjects; i++ {
		testKey := fmt.Sprintf("perf-test-%d.txt", i)
		testData := make([]byte, objectSize)
		for j := range testData {
			testData[j] = byte(i % 256)
		}
		
		putInput := s3response.PutObjectInput{
			Bucket: suite.testBucket,
			Key:    testKey,
			Body:   bytes.NewReader(testData),
		}
		
		_, err := suite.backend.PutObject(suite.ctx, putInput)
		assert.NoError(t, err, "Failed to put performance test object %d", i)
	}
	
	uploadDuration := time.Since(start)
	uploadRate := float64(numObjects) / uploadDuration.Seconds()
	
	suite.logger.Printf("✓ Performance test completed: %d objects in %v (%.2f objects/sec)",
		numObjects, uploadDuration, uploadRate)
	
	// Cleanup
	suite.backend.DeleteBucket(suite.ctx, suite.testBucket)
}

// TestFailureRecovery tests failure recovery scenarios
func TestFailureRecovery(t *testing.T) {
	suite := NewE2ETestSuite(t)
	defer suite.Cleanup()
	
	suite.logger.Printf("Testing failure recovery scenarios")
	
	// Test handling of non-existent bucket
	nonExistentBucket := "non-existent-bucket"
	getInput := &s3.GetObjectInput{
		Bucket: &nonExistentBucket,
		Key:    awsString("test.txt"),
	}
	
	_, err := suite.backend.GetObject(suite.ctx, getInput)
	assert.Error(t, err, "Should fail for non-existent bucket")
	
	// Test handling of non-existent object
	createInput := &s3.CreateBucketInput{
		Bucket: &suite.testBucket,
	}
	err = suite.backend.CreateBucket(suite.ctx, createInput, nil)
	require.NoError(t, err)
	
	getInput = &s3.GetObjectInput{
		Bucket: &suite.testBucket,
		Key:    awsString("non-existent-object.txt"),
	}
	
	_, err = suite.backend.GetObject(suite.ctx, getInput)
	assert.Error(t, err, "Should fail for non-existent object")
	
	suite.logger.Printf("✓ Failure recovery tests completed")
	
	// Cleanup
	suite.backend.DeleteBucket(suite.ctx, suite.testBucket)
}

// Helper function to create string pointer
func awsString(s string) *string {
	return &s
}