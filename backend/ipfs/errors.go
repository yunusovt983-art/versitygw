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
	"fmt"
	"time"
)

// ErrorCode represents different types of IPFS-related errors
type ErrorCode int

const (
	// Connection errors
	ErrIPFSNodeUnavailable ErrorCode = iota
	ErrClusterUnavailable
	ErrConnectionTimeout
	ErrAuthenticationFailed
	
	// Pin operation errors
	ErrPinTimeout
	ErrPinFailed
	ErrUnpinFailed
	ErrInsufficientReplicas
	ErrPinNotFound
	
	// Data integrity errors
	ErrCIDNotFound
	ErrCIDInvalid
	ErrDataCorruption
	ErrChecksumMismatch
	
	// Metadata errors
	ErrMetadataCorruption
	ErrMetadataNotFound
	ErrMetadataStoreFailed
	
	// Cluster errors
	ErrClusterSplit
	ErrNodeSyncFailed
	ErrConsensusTimeout
	
	// Resource errors
	ErrStorageQuotaExceeded
	ErrMemoryExhausted
	ErrTooManyRequests
	
	// Configuration errors
	ErrInvalidConfig
	ErrMissingEndpoints
	ErrInvalidReplication
)

// IPFSError represents an error that occurred in the IPFS backend
type IPFSError struct {
	Code      ErrorCode
	Message   string
	CID       string
	S3Key     string
	Bucket    string
	Cause     error
	Timestamp time.Time
	Retryable bool
}

// Error implements the error interface
func (e *IPFSError) Error() string {
	if e.CID != "" && e.S3Key != "" {
		return fmt.Sprintf("IPFS error [%s]: %s (CID: %s, S3Key: %s/%s)", 
			e.Code.String(), e.Message, e.CID, e.Bucket, e.S3Key)
	} else if e.CID != "" {
		return fmt.Sprintf("IPFS error [%s]: %s (CID: %s)", 
			e.Code.String(), e.Message, e.CID)
	} else if e.S3Key != "" {
		return fmt.Sprintf("IPFS error [%s]: %s (S3Key: %s/%s)", 
			e.Code.String(), e.Message, e.Bucket, e.S3Key)
	}
	return fmt.Sprintf("IPFS error [%s]: %s", e.Code.String(), e.Message)
}

// Unwrap returns the underlying cause error
func (e *IPFSError) Unwrap() error {
	return e.Cause
}

// IsRetryable returns true if the error is retryable
func (e *IPFSError) IsRetryable() bool {
	return e.Retryable
}

// String returns a string representation of the error code
func (code ErrorCode) String() string {
	switch code {
	case ErrIPFSNodeUnavailable:
		return "IPFS_NODE_UNAVAILABLE"
	case ErrClusterUnavailable:
		return "CLUSTER_UNAVAILABLE"
	case ErrConnectionTimeout:
		return "CONNECTION_TIMEOUT"
	case ErrAuthenticationFailed:
		return "AUTHENTICATION_FAILED"
	case ErrPinTimeout:
		return "PIN_TIMEOUT"
	case ErrPinFailed:
		return "PIN_FAILED"
	case ErrUnpinFailed:
		return "UNPIN_FAILED"
	case ErrInsufficientReplicas:
		return "INSUFFICIENT_REPLICAS"
	case ErrPinNotFound:
		return "PIN_NOT_FOUND"
	case ErrCIDNotFound:
		return "CID_NOT_FOUND"
	case ErrCIDInvalid:
		return "CID_INVALID"
	case ErrDataCorruption:
		return "DATA_CORRUPTION"
	case ErrChecksumMismatch:
		return "CHECKSUM_MISMATCH"
	case ErrMetadataCorruption:
		return "METADATA_CORRUPTION"
	case ErrMetadataNotFound:
		return "METADATA_NOT_FOUND"
	case ErrMetadataStoreFailed:
		return "METADATA_STORE_FAILED"
	case ErrClusterSplit:
		return "CLUSTER_SPLIT"
	case ErrNodeSyncFailed:
		return "NODE_SYNC_FAILED"
	case ErrConsensusTimeout:
		return "CONSENSUS_TIMEOUT"
	case ErrStorageQuotaExceeded:
		return "STORAGE_QUOTA_EXCEEDED"
	case ErrMemoryExhausted:
		return "MEMORY_EXHAUSTED"
	case ErrTooManyRequests:
		return "TOO_MANY_REQUESTS"
	case ErrInvalidConfig:
		return "INVALID_CONFIG"
	case ErrMissingEndpoints:
		return "MISSING_ENDPOINTS"
	case ErrInvalidReplication:
		return "INVALID_REPLICATION"
	default:
		return "UNKNOWN_ERROR"
	}
}

// NewIPFSError creates a new IPFS error
func NewIPFSError(code ErrorCode, message string) *IPFSError {
	return &IPFSError{
		Code:      code,
		Message:   message,
		Timestamp: time.Now(),
		Retryable: isRetryableError(code),
	}
}

// NewIPFSErrorWithCause creates a new IPFS error with an underlying cause
func NewIPFSErrorWithCause(code ErrorCode, message string, cause error) *IPFSError {
	return &IPFSError{
		Code:      code,
		Message:   message,
		Cause:     cause,
		Timestamp: time.Now(),
		Retryable: isRetryableError(code),
	}
}

// NewIPFSErrorWithContext creates a new IPFS error with context information
func NewIPFSErrorWithContext(code ErrorCode, message, cid, bucket, s3Key string, cause error) *IPFSError {
	return &IPFSError{
		Code:      code,
		Message:   message,
		CID:       cid,
		S3Key:     s3Key,
		Bucket:    bucket,
		Cause:     cause,
		Timestamp: time.Now(),
		Retryable: isRetryableError(code),
	}
}

// isRetryableError determines if an error code represents a retryable error
func isRetryableError(code ErrorCode) bool {
	switch code {
	case ErrIPFSNodeUnavailable,
		ErrClusterUnavailable,
		ErrConnectionTimeout,
		ErrPinTimeout,
		ErrNodeSyncFailed,
		ErrConsensusTimeout,
		ErrTooManyRequests:
		return true
	case ErrAuthenticationFailed,
		ErrCIDInvalid,
		ErrInvalidConfig,
		ErrMissingEndpoints,
		ErrInvalidReplication,
		ErrDataCorruption,
		ErrChecksumMismatch:
		return false
	default:
		// Conservative approach: assume non-retryable unless explicitly marked
		return false
	}
}

// WrapError wraps a generic error into an IPFS error
func WrapError(code ErrorCode, message string, err error) *IPFSError {
	return NewIPFSErrorWithCause(code, message, err)
}

// IsIPFSError checks if an error is an IPFS error
func IsIPFSError(err error) bool {
	_, ok := err.(*IPFSError)
	return ok
}

// GetIPFSError extracts an IPFS error from a generic error
func GetIPFSError(err error) (*IPFSError, bool) {
	ipfsErr, ok := err.(*IPFSError)
	return ipfsErr, ok
}