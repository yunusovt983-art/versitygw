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
	"errors"
	"strings"
	"testing"
)

func TestErrorCode_String(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		expected string
	}{
		{ErrIPFSNodeUnavailable, "IPFS_NODE_UNAVAILABLE"},
		{ErrClusterUnavailable, "CLUSTER_UNAVAILABLE"},
		{ErrPinTimeout, "PIN_TIMEOUT"},
		{ErrCIDNotFound, "CID_NOT_FOUND"},
		{ErrInvalidConfig, "INVALID_CONFIG"},
		{ErrorCode(999), "UNKNOWN_ERROR"}, // Test unknown error code
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.code.String()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestNewIPFSError(t *testing.T) {
	code := ErrPinTimeout
	message := "pin operation timed out"
	
	err := NewIPFSError(code, message)
	
	if err.Code != code {
		t.Errorf("expected code %v, got %v", code, err.Code)
	}
	
	if err.Message != message {
		t.Errorf("expected message %s, got %s", message, err.Message)
	}
	
	if err.Timestamp.IsZero() {
		t.Errorf("expected timestamp to be set")
	}
	
	if !err.Retryable {
		t.Errorf("expected pin timeout to be retryable")
	}
}

func TestNewIPFSErrorWithCause(t *testing.T) {
	code := ErrConnectionTimeout
	message := "connection timed out"
	cause := errors.New("network timeout")
	
	err := NewIPFSErrorWithCause(code, message, cause)
	
	if err.Code != code {
		t.Errorf("expected code %v, got %v", code, err.Code)
	}
	
	if err.Message != message {
		t.Errorf("expected message %s, got %s", message, err.Message)
	}
	
	if err.Cause != cause {
		t.Errorf("expected cause %v, got %v", cause, err.Cause)
	}
	
	if !err.Retryable {
		t.Errorf("expected connection timeout to be retryable")
	}
}

func TestNewIPFSErrorWithContext(t *testing.T) {
	code := ErrCIDNotFound
	message := "CID not found in cluster"
	cid := "QmTest123"
	bucket := "test-bucket"
	s3Key := "test/object.txt"
	cause := errors.New("not found")
	
	err := NewIPFSErrorWithContext(code, message, cid, bucket, s3Key, cause)
	
	if err.Code != code {
		t.Errorf("expected code %v, got %v", code, err.Code)
	}
	
	if err.Message != message {
		t.Errorf("expected message %s, got %s", message, err.Message)
	}
	
	if err.CID != cid {
		t.Errorf("expected CID %s, got %s", cid, err.CID)
	}
	
	if err.Bucket != bucket {
		t.Errorf("expected bucket %s, got %s", bucket, err.Bucket)
	}
	
	if err.S3Key != s3Key {
		t.Errorf("expected S3Key %s, got %s", s3Key, err.S3Key)
	}
	
	if err.Cause != cause {
		t.Errorf("expected cause %v, got %v", cause, err.Cause)
	}
}

func TestIPFSError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *IPFSError
		contains []string
	}{
		{
			name: "error with CID and S3Key",
			err: &IPFSError{
				Code:    ErrPinTimeout,
				Message: "pin operation timed out",
				CID:     "QmTest123",
				Bucket:  "test-bucket",
				S3Key:   "test/object.txt",
			},
			contains: []string{"PIN_TIMEOUT", "pin operation timed out", "QmTest123", "test-bucket", "test/object.txt"},
		},
		{
			name: "error with CID only",
			err: &IPFSError{
				Code:    ErrCIDNotFound,
				Message: "CID not found",
				CID:     "QmTest456",
			},
			contains: []string{"CID_NOT_FOUND", "CID not found", "QmTest456"},
		},
		{
			name: "error with S3Key only",
			err: &IPFSError{
				Code:    ErrMetadataNotFound,
				Message: "metadata not found",
				Bucket:  "my-bucket",
				S3Key:   "my/object.txt",
			},
			contains: []string{"METADATA_NOT_FOUND", "metadata not found", "my-bucket", "my/object.txt"},
		},
		{
			name: "basic error",
			err: &IPFSError{
				Code:    ErrInvalidConfig,
				Message: "invalid configuration",
			},
			contains: []string{"INVALID_CONFIG", "invalid configuration"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errorStr := tt.err.Error()
			
			for _, expected := range tt.contains {
				if !strings.Contains(errorStr, expected) {
					t.Errorf("expected error string to contain '%s', got: %s", expected, errorStr)
				}
			}
		})
	}
}

func TestIPFSError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := NewIPFSErrorWithCause(ErrPinFailed, "pin failed", cause)
	
	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("expected unwrapped error to be %v, got %v", cause, unwrapped)
	}
}

func TestIPFSError_IsRetryable(t *testing.T) {
	retryableErr := NewIPFSError(ErrConnectionTimeout, "timeout")
	if !retryableErr.IsRetryable() {
		t.Errorf("expected connection timeout to be retryable")
	}
	
	nonRetryableErr := NewIPFSError(ErrInvalidConfig, "invalid config")
	if nonRetryableErr.IsRetryable() {
		t.Errorf("expected invalid config to not be retryable")
	}
}

func TestIsRetryableError(t *testing.T) {
	retryableCodes := []ErrorCode{
		ErrIPFSNodeUnavailable,
		ErrClusterUnavailable,
		ErrConnectionTimeout,
		ErrPinTimeout,
		ErrNodeSyncFailed,
		ErrConsensusTimeout,
		ErrTooManyRequests,
	}
	
	nonRetryableCodes := []ErrorCode{
		ErrAuthenticationFailed,
		ErrCIDInvalid,
		ErrInvalidConfig,
		ErrMissingEndpoints,
		ErrInvalidReplication,
		ErrDataCorruption,
		ErrChecksumMismatch,
	}
	
	for _, code := range retryableCodes {
		if !isRetryableError(code) {
			t.Errorf("expected %s to be retryable", code.String())
		}
	}
	
	for _, code := range nonRetryableCodes {
		if isRetryableError(code) {
			t.Errorf("expected %s to not be retryable", code.String())
		}
	}
}

func TestWrapError(t *testing.T) {
	originalErr := errors.New("original error")
	code := ErrPinFailed
	message := "pin operation failed"
	
	wrappedErr := WrapError(code, message, originalErr)
	
	if wrappedErr.Code != code {
		t.Errorf("expected code %v, got %v", code, wrappedErr.Code)
	}
	
	if wrappedErr.Message != message {
		t.Errorf("expected message %s, got %s", message, wrappedErr.Message)
	}
	
	if wrappedErr.Cause != originalErr {
		t.Errorf("expected cause %v, got %v", originalErr, wrappedErr.Cause)
	}
}

func TestIsIPFSError(t *testing.T) {
	ipfsErr := NewIPFSError(ErrPinTimeout, "timeout")
	genericErr := errors.New("generic error")
	
	if !IsIPFSError(ipfsErr) {
		t.Errorf("expected IsIPFSError to return true for IPFS error")
	}
	
	if IsIPFSError(genericErr) {
		t.Errorf("expected IsIPFSError to return false for generic error")
	}
}

func TestGetIPFSError(t *testing.T) {
	ipfsErr := NewIPFSError(ErrPinTimeout, "timeout")
	genericErr := errors.New("generic error")
	
	extracted, ok := GetIPFSError(ipfsErr)
	if !ok {
		t.Errorf("expected GetIPFSError to return true for IPFS error")
	}
	if extracted != ipfsErr {
		t.Errorf("expected extracted error to be the same as original")
	}
	
	_, ok = GetIPFSError(genericErr)
	if ok {
		t.Errorf("expected GetIPFSError to return false for generic error")
	}
}