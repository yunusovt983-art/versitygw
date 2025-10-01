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
	"log"
	"os"
	"strings"
)

// LogLevel represents different logging levels
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelFatal
)

// String returns string representation of log level
func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	case LogLevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// ParseLogLevel parses a string into a LogLevel
func ParseLogLevel(level string) LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return LogLevelDebug
	case "INFO":
		return LogLevelInfo
	case "WARN", "WARNING":
		return LogLevelWarn
	case "ERROR":
		return LogLevelError
	case "FATAL":
		return LogLevelFatal
	default:
		return LogLevelInfo
	}
}

// Logger wraps the standard logger with level-based logging
type Logger struct {
	*log.Logger
	level LogLevel
}

// NewLogger creates a new logger with the specified level
func NewLogger(level LogLevel) *Logger {
	return &Logger{
		Logger: log.New(os.Stdout, "[IPFS] ", log.LstdFlags|log.Lshortfile),
		level:  level,
	}
}

// NewLoggerFromConfig creates a logger from configuration
func NewLoggerFromConfig(config *IPFSConfig) *Logger {
	level := ParseLogLevel(config.LogLevel)
	return NewLogger(level)
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// GetLevel returns the current logging level
func (l *Logger) GetLevel() LogLevel {
	return l.level
}

// shouldLog checks if a message should be logged based on level
func (l *Logger) shouldLog(level LogLevel) bool {
	return level >= l.level
}

// Debug logs a debug message
func (l *Logger) Debug(v ...interface{}) {
	if l.shouldLog(LogLevelDebug) {
		l.Logger.Printf("[DEBUG] %s", fmt.Sprint(v...))
	}
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, v ...interface{}) {
	if l.shouldLog(LogLevelDebug) {
		l.Logger.Printf("[DEBUG] "+format, v...)
	}
}

// Info logs an info message
func (l *Logger) Info(v ...interface{}) {
	if l.shouldLog(LogLevelInfo) {
		l.Logger.Printf("[INFO] %s", fmt.Sprint(v...))
	}
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, v ...interface{}) {
	if l.shouldLog(LogLevelInfo) {
		l.Logger.Printf("[INFO] "+format, v...)
	}
}

// Warn logs a warning message
func (l *Logger) Warn(v ...interface{}) {
	if l.shouldLog(LogLevelWarn) {
		l.Logger.Printf("[WARN] %s", fmt.Sprint(v...))
	}
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, v ...interface{}) {
	if l.shouldLog(LogLevelWarn) {
		l.Logger.Printf("[WARN] "+format, v...)
	}
}

// Error logs an error message
func (l *Logger) Error(v ...interface{}) {
	if l.shouldLog(LogLevelError) {
		l.Logger.Printf("[ERROR] %s", fmt.Sprint(v...))
	}
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, v ...interface{}) {
	if l.shouldLog(LogLevelError) {
		l.Logger.Printf("[ERROR] "+format, v...)
	}
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(v ...interface{}) {
	if l.shouldLog(LogLevelFatal) {
		l.Logger.Printf("[FATAL] %s", fmt.Sprint(v...))
		os.Exit(1)
	}
}

// Fatalf logs a formatted fatal message and exits
func (l *Logger) Fatalf(format string, v ...interface{}) {
	if l.shouldLog(LogLevelFatal) {
		l.Logger.Printf("[FATAL] "+format, v...)
		os.Exit(1)
	}
}

// LogError logs an IPFS error with appropriate level
func (l *Logger) LogError(err *IPFSError) {
	if err == nil {
		return
	}

	// Determine log level based on error severity
	var level LogLevel
	switch err.Code {
	case ErrInvalidConfig, ErrMissingEndpoints, ErrInvalidReplication:
		level = LogLevelFatal
	case ErrDataCorruption, ErrMetadataCorruption, ErrClusterSplit:
		level = LogLevelError
	case ErrPinTimeout, ErrConnectionTimeout, ErrNodeSyncFailed:
		level = LogLevelWarn
	default:
		level = LogLevelError
	}

	// Log with context
	message := fmt.Sprintf("IPFS Error [%s]: %s", err.Code.String(), err.Message)
	if err.CID != "" {
		message += fmt.Sprintf(" (CID: %s)", err.CID)
	}
	if err.S3Key != "" {
		message += fmt.Sprintf(" (S3Key: %s/%s)", err.Bucket, err.S3Key)
	}
	if err.Cause != nil {
		message += fmt.Sprintf(" (Cause: %v)", err.Cause)
	}

	switch level {
	case LogLevelDebug:
		l.Debug(message)
	case LogLevelInfo:
		l.Info(message)
	case LogLevelWarn:
		l.Warn(message)
	case LogLevelError:
		l.Error(message)
	case LogLevelFatal:
		l.Fatal(message)
	}
}

// LogOperation logs an operation with timing information
func (l *Logger) LogOperation(operation, cid, bucket, s3Key string, duration int64, err error) {
	if err != nil {
		if ipfsErr, ok := GetIPFSError(err); ok {
			l.LogError(ipfsErr)
		} else {
			l.Errorf("Operation %s failed: %v (Duration: %dms, CID: %s, S3Key: %s/%s)", 
				operation, err, duration, cid, bucket, s3Key)
		}
	} else {
		l.Infof("Operation %s completed successfully (Duration: %dms, CID: %s, S3Key: %s/%s)", 
			operation, duration, cid, bucket, s3Key)
	}
}