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

package auth

import (
	"net/url"
	"strings"
	"testing"
)

func TestQRCodeGenerator_GenerateQRCodeURL(t *testing.T) {
	config := DefaultMFAConfig()
	generator := NewQRCodeGenerator(config)

	secret := "JBSWY3DPEHPK3PXP"
	accountName := "test@example.com"

	qrURL, err := generator.GenerateQRCodeURL(secret, accountName)
	if err != nil {
		t.Fatalf("GenerateQRCodeURL() error = %v", err)
	}

	// Parse the URL to validate its structure
	parsedURL, err := url.Parse(qrURL)
	if err != nil {
		t.Fatalf("Generated URL is not valid: %v", err)
	}

	// Check scheme
	if parsedURL.Scheme != "otpauth" {
		t.Errorf("URL scheme = %s, want otpauth", parsedURL.Scheme)
	}

	// Check host (should be "totp")
	if parsedURL.Host != "totp" {
		t.Errorf("URL host = %s, want totp", parsedURL.Host)
	}

	// Check that path contains issuer and account name
	if !strings.Contains(parsedURL.Path, url.QueryEscape(config.Issuer)) {
		t.Errorf("URL path should contain issuer")
	}

	// Check query parameters
	params := parsedURL.Query()
	
	if params.Get("secret") != secret {
		t.Errorf("Secret parameter = %s, want %s", params.Get("secret"), secret)
	}

	if params.Get("issuer") != config.Issuer {
		t.Errorf("Issuer parameter = %s, want %s", params.Get("issuer"), config.Issuer)
	}
}

func TestQRCodeGenerator_GenerateQRCodeURL_EmptyInputs(t *testing.T) {
	config := DefaultMFAConfig()
	generator := NewQRCodeGenerator(config)

	tests := []struct {
		name        string
		secret      string
		accountName string
		wantErr     bool
	}{
		{
			name:        "empty secret",
			secret:      "",
			accountName: "test@example.com",
			wantErr:     true,
		},
		{
			name:        "empty account name",
			secret:      "JBSWY3DPEHPK3PXP",
			accountName: "",
			wantErr:     true,
		},
		{
			name:        "valid inputs",
			secret:      "JBSWY3DPEHPK3PXP",
			accountName: "test@example.com",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := generator.GenerateQRCodeURL(tt.secret, tt.accountName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateQRCodeURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestQRCodeGenerator_GenerateQRCodeData(t *testing.T) {
	config := DefaultMFAConfig()
	generator := NewQRCodeGenerator(config)

	secret := "JBSWY3DPEHPK3PXP"
	accountName := "test@example.com"

	options := &QRCodeOptions{
		Digits:    6,
		Period:    30,
		Algorithm: "SHA1",
	}

	qrData, err := generator.GenerateQRCodeData(secret, accountName, options)
	if err != nil {
		t.Fatalf("GenerateQRCodeData() error = %v", err)
	}

	if qrData.Secret != secret {
		t.Errorf("QRCodeData.Secret = %s, want %s", qrData.Secret, secret)
	}

	if qrData.AccountName != accountName {
		t.Errorf("QRCodeData.AccountName = %s, want %s", qrData.AccountName, accountName)
	}

	if qrData.Issuer != config.Issuer {
		t.Errorf("QRCodeData.Issuer = %s, want %s", qrData.Issuer, config.Issuer)
	}

	if qrData.Digits != options.Digits {
		t.Errorf("QRCodeData.Digits = %d, want %d", qrData.Digits, options.Digits)
	}

	if qrData.Period != options.Period {
		t.Errorf("QRCodeData.Period = %d, want %d", qrData.Period, options.Period)
	}

	if qrData.URL == "" {
		t.Error("QRCodeData.URL should not be empty")
	}
}

func TestQRCodeOptions_Validate(t *testing.T) {
	tests := []struct {
		name    string
		options *QRCodeOptions
		wantErr bool
	}{
		{
			name: "valid options",
			options: &QRCodeOptions{
				Digits:    6,
				Period:    30,
				Algorithm: "SHA1",
			},
			wantErr: false,
		},
		{
			name: "invalid digits - too small",
			options: &QRCodeOptions{
				Digits:    5,
				Period:    30,
				Algorithm: "SHA1",
			},
			wantErr: true,
		},
		{
			name: "invalid digits - too large",
			options: &QRCodeOptions{
				Digits:    9,
				Period:    30,
				Algorithm: "SHA1",
			},
			wantErr: true,
		},
		{
			name: "invalid period - too small",
			options: &QRCodeOptions{
				Digits:    6,
				Period:    10,
				Algorithm: "SHA1",
			},
			wantErr: true,
		},
		{
			name: "invalid period - too large",
			options: &QRCodeOptions{
				Digits:    6,
				Period:    400,
				Algorithm: "SHA1",
			},
			wantErr: true,
		},
		{
			name: "invalid algorithm",
			options: &QRCodeOptions{
				Digits:    6,
				Period:    30,
				Algorithm: "MD5",
			},
			wantErr: true,
		},
		{
			name: "empty algorithm (should be valid)",
			options: &QRCodeOptions{
				Digits:    6,
				Period:    30,
				Algorithm: "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.options.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("QRCodeOptions.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestQRCodeData_GetManualEntryKey(t *testing.T) {
	qrData := &QRCodeData{
		Secret: "JBSWY3DPEHPK3PXP",
	}

	manualKey := qrData.GetManualEntryKey()
	expected := "JBSW Y3DP EHPK 3PXP"

	if manualKey != expected {
		t.Errorf("GetManualEntryKey() = %s, want %s", manualKey, expected)
	}
}

func TestQRCodeData_GetSetupInstructions(t *testing.T) {
	qrData := &QRCodeData{
		URL:         "otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test",
		Secret:      "JBSWY3DPEHPK3PXP",
		AccountName: "user@example.com",
		Issuer:      "Test Service",
		Digits:      6,
		Period:      30,
		Algorithm:   "SHA1",
	}

	instructions := qrData.GetSetupInstructions()

	if instructions.QRCodeURL != qrData.URL {
		t.Errorf("Instructions.QRCodeURL = %s, want %s", instructions.QRCodeURL, qrData.URL)
	}

	if instructions.AccountName != qrData.AccountName {
		t.Errorf("Instructions.AccountName = %s, want %s", instructions.AccountName, qrData.AccountName)
	}

	if instructions.Issuer != qrData.Issuer {
		t.Errorf("Instructions.Issuer = %s, want %s", instructions.Issuer, qrData.Issuer)
	}

	if len(instructions.Instructions) == 0 {
		t.Error("Instructions should not be empty")
	}

	// Check that manual key is formatted
	expectedManualKey := "JBSW Y3DP EHPK 3PXP"
	if instructions.ManualKey != expectedManualKey {
		t.Errorf("Instructions.ManualKey = %s, want %s", instructions.ManualKey, expectedManualKey)
	}
}

func TestQRCodeGenerator_WithSpecialCharacters(t *testing.T) {
	config := DefaultMFAConfig()
	generator := NewQRCodeGenerator(config)

	secret := "JBSWY3DPEHPK3PXP"
	accountName := "test user@example.com" // Contains space and special chars

	qrURL, err := generator.GenerateQRCodeURL(secret, accountName)
	if err != nil {
		t.Fatalf("GenerateQRCodeURL() error = %v", err)
	}

	// Parse the URL to ensure it's valid
	parsedURL, err := url.Parse(qrURL)
	if err != nil {
		t.Fatalf("Generated URL with special characters is not valid: %v", err)
	}

	// Ensure the URL contains properly encoded components
	if parsedURL.Scheme != "otpauth" {
		t.Errorf("URL scheme = %s, want otpauth", parsedURL.Scheme)
	}

	// Check that secret parameter is present and correct
	params := parsedURL.Query()
	if params.Get("secret") != secret {
		t.Errorf("Secret parameter = %s, want %s", params.Get("secret"), secret)
	}
}