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
	"errors"
	"log"
	"strings"
	"testing"
)

func TestLogLevel_String(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{LogLevelDebug, "DEBUG"},
		{LogLevelInfo, "INFO"},
		{LogLevelWarn, "WARN"},
		{LogLevelError, "ERROR"},
		{LogLevelFatal, "FATAL"},
		{LogLevel(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected LogLevel
	}{
		{"DEBUG", LogLevelDebug},
		{"debug", LogLevelDebug},
		{"INFO", LogLevelInfo},
		{"info", LogLevelInfo},
		{"WARN", LogLevelWarn},
		{"warn", LogLevelWarn},
		{"WARNING", LogLevelWarn},
		{"ERROR", LogLevelError},
		{"error", LogLevelError},
		{"FATAL", LogLevelFatal},
		{"fatal", LogLevelFatal},
		{"unknown", LogLevelInfo}, // Default to INFO
		{"", LogLevelInfo},         // Default to INFO
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseLogLevel(tt.input)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestNewLogger(t *testing.T) {
	logger := NewLogger(LogLevelDebug)
	
	if logger == nil {
		t.Fatalf("expected logger to be created")
	}
	
	if logger.GetLevel() != LogLevelDebug {
		t.Errorf("expected level to be DEBUG, got %v", logger.GetLevel())
	}
}

func TestNewLoggerFromConfig(t *testing.T) {
	config := &IPFSConfig{
		LogLevel: "warn",
	}
	
	logger := NewLoggerFromConfig(config)
	
	if logger == nil {
		t.Fatalf("expected logger to be created")
	}
	
	if logger.GetLevel() != LogLevelWarn {
		t.Errorf("expected level to be WARN, got %v", logger.GetLevel())
	}
}

func TestLogger_SetLevel(t *testing.T) {
	logger := NewLogger(LogLevelInfo)
	
	logger.SetLevel(LogLevelError)
	
	if logger.GetLevel() != LogLevelError {
		t.Errorf("expected level to be ERROR, got %v", logger.GetLevel())
	}
}

func TestLogger_ShouldLog(t *testing.T) {
	logger := NewLogger(LogLevelWarn)
	
	// Should log WARN and above
	if !logger.shouldLog(LogLevelWarn) {
		t.Errorf("expected to log WARN level")
	}
	
	if !logger.shouldLog(LogLevelError) {
		t.Errorf("expected to log ERROR level")
	}
	
	if !logger.shouldLog(LogLevelFatal) {
		t.Errorf("expected to log FATAL level")
	}
	
	// Should not log below WARN
	if logger.shouldLog(LogLevelDebug) {
		t.Errorf("expected not to log DEBUG level")
	}
	
	if logger.shouldLog(LogLevelInfo) {
		t.Errorf("expected not to log INFO level")
	}
}

func TestLogger_LoggingMethods(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		Logger: log.New(&buf, "[TEST] ", 0),
		level:  LogLevelDebug,
	}
	
	// Test Debug
	logger.Debug("debug message")
	if !strings.Contains(buf.String(), "[DEBUG] debug message") {
		t.Errorf("expected debug message in output, got: %s", buf.String())
	}
	
	buf.Reset()
	
	// Test Debugf
	logger.Debugf("debug %s %d", "formatted", 123)
	if !strings.Contains(buf.String(), "[DEBUG] debug formatted 123") {
		t.Errorf("expected formatted debug message in output, got: %s", buf.String())
	}
	
	buf.Reset()
	
	// Test Info
	logger.Info("info message")
	if !strings.Contains(buf.String(), "[INFO] info message") {
		t.Errorf("expected info message in output, got: %s", buf.String())
	}
	
	buf.Reset()
	
	// Test Warn
	logger.Warn("warn message")
	if !strings.Contains(buf.String(), "[WARN] warn message") {
		t.Errorf("expected warn message in output, got: %s", buf.String())
	}
	
	buf.Reset()
	
	// Test Error
	logger.Error("error message")
	if !strings.Contains(buf.String(), "[ERROR] error message") {
		t.Errorf("expected error message in output, got: %s", buf.String())
	}
}

func TestLogger_LoggingWithLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		Logger: log.New(&buf, "[TEST] ", 0),
		level:  LogLevelWarn, // Only WARN and above
	}
	
	// Should not log DEBUG
	logger.Debug("debug message")
	if strings.Contains(buf.String(), "debug message") {
		t.Errorf("expected debug message to be filtered out, got: %s", buf.String())
	}
	
	// Should not log INFO
	logger.Info("info message")
	if strings.Contains(buf.String(), "info message") {
		t.Errorf("expected info message to be filtered out, got: %s", buf.String())
	}
	
	// Should log WARN
	logger.Warn("warn message")
	if !strings.Contains(buf.String(), "warn message") {
		t.Errorf("expected warn message in output, got: %s", buf.String())
	}
}

func TestLogger_LogError(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		Logger: log.New(&buf, "[TEST] ", 0),
		level:  LogLevelDebug,
	}
	
	// Test logging nil error
	logger.LogError(nil)
	if buf.Len() > 0 {
		t.Errorf("expected no output for nil error, got: %s", buf.String())
	}
	
	// Test logging IPFS error with context
	ipfsErr := NewIPFSErrorWithContext(
		ErrPinTimeout,
		"pin operation timed out",
		"QmTest123",
		"test-bucket",
		"test/object.txt",
		errors.New("network timeout"),
	)
	
	logger.LogError(ipfsErr)
	output := buf.String()
	
	expectedStrings := []string{
		"PIN_TIMEOUT",
		"pin operation timed out",
		"QmTest123",
		"test-bucket",
		"test/object.txt",
		"network timeout",
	}
	
	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain '%s', got: %s", expected, output)
		}
	}
}

func TestLogger_LogOperation(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		Logger: log.New(&buf, "[TEST] ", 0),
		level:  LogLevelDebug,
	}
	
	// Test successful operation
	logger.LogOperation("PutObject", "QmTest123", "test-bucket", "test/object.txt", 150, nil)
	output := buf.String()
	
	expectedStrings := []string{
		"PutObject",
		"completed successfully",
		"150ms",
		"QmTest123",
		"test-bucket",
		"test/object.txt",
	}
	
	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain '%s', got: %s", expected, output)
		}
	}
	
	buf.Reset()
	
	// Test failed operation with IPFS error
	ipfsErr := NewIPFSError(ErrPinTimeout, "pin timed out")
	logger.LogOperation("PinObject", "QmTest456", "test-bucket", "test/object2.txt", 5000, ipfsErr)
	output = buf.String()
	
	expectedStrings = []string{
		"PIN_TIMEOUT",
		"pin timed out",
	}
	
	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain '%s', got: %s", expected, output)
		}
	}
	
	buf.Reset()
	
	// Test failed operation with generic error
	genericErr := errors.New("generic error")
	logger.LogOperation("GetObject", "QmTest789", "test-bucket", "test/object3.txt", 200, genericErr)
	output = buf.String()
	
	expectedStrings = []string{
		"GetObject failed",
		"generic error",
		"200ms",
		"QmTest789",
		"test-bucket",
		"test/object3.txt",
	}
	
	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain '%s', got: %s", expected, output)
		}
	}
}