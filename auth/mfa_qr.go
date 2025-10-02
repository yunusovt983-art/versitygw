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
	"fmt"
	"net/url"
	"strings"
)

// QRCodeGenerator provides functionality to generate QR code data for TOTP setup
type QRCodeGenerator struct {
	config *MFAConfig
}

// NewQRCodeGenerator creates a new QR code generator
func NewQRCodeGenerator(config *MFAConfig) *QRCodeGenerator {
	if config == nil {
		config = DefaultMFAConfig()
	}
	return &QRCodeGenerator{config: config}
}

// GenerateQRCodeURL generates a TOTP URL that can be encoded as a QR code
func (q *QRCodeGenerator) GenerateQRCodeURL(secret, accountName string) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("secret cannot be empty")
	}
	
	if accountName == "" {
		return "", fmt.Errorf("account name cannot be empty")
	}
	
	// Clean up the account name and issuer for URL encoding
	cleanAccountName := strings.TrimSpace(accountName)
	cleanIssuer := strings.TrimSpace(q.config.Issuer)
	
	// Build the TOTP URL according to the Google Authenticator format
	// otpauth://totp/Issuer:AccountName?secret=SECRET&issuer=Issuer
	
	// URL encode the components
	encodedAccountName := url.QueryEscape(cleanAccountName)
	encodedIssuer := url.QueryEscape(cleanIssuer)
	encodedSecret := url.QueryEscape(secret)
	
	// Construct the label (Issuer:AccountName)
	label := fmt.Sprintf("%s:%s", encodedIssuer, encodedAccountName)
	
	// Build the URL
	totpURL := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s",
		label, encodedSecret, encodedIssuer)
	
	return totpURL, nil
}

// GenerateQRCodeData generates QR code data with additional parameters
func (q *QRCodeGenerator) GenerateQRCodeData(secret, accountName string, options *QRCodeOptions) (*QRCodeData, error) {
	if options == nil {
		options = &QRCodeOptions{
			Digits: 6,
			Period: 30,
		}
	}
	
	// Validate options
	if err := options.Validate(); err != nil {
		return nil, fmt.Errorf("invalid QR code options: %w", err)
	}
	
	// Generate base URL
	baseURL, err := q.GenerateQRCodeURL(secret, accountName)
	if err != nil {
		return nil, err
	}
	
	// Add additional parameters if they differ from defaults
	params := url.Values{}
	
	if options.Digits != 6 {
		params.Add("digits", fmt.Sprintf("%d", options.Digits))
	}
	
	if options.Period != 30 {
		params.Add("period", fmt.Sprintf("%d", options.Period))
	}
	
	if options.Algorithm != "" && options.Algorithm != "SHA1" {
		params.Add("algorithm", options.Algorithm)
	}
	
	// Append additional parameters if any
	finalURL := baseURL
	if len(params) > 0 {
		finalURL += "&" + params.Encode()
	}
	
	return &QRCodeData{
		URL:         finalURL,
		Secret:      secret,
		AccountName: accountName,
		Issuer:      q.config.Issuer,
		Digits:      options.Digits,
		Period:      options.Period,
		Algorithm:   options.Algorithm,
	}, nil
}

// QRCodeOptions contains options for QR code generation
type QRCodeOptions struct {
	// Digits is the number of digits in the TOTP code (default: 6)
	Digits int `json:"digits"`
	
	// Period is the time period in seconds for TOTP (default: 30)
	Period int `json:"period"`
	
	// Algorithm is the hash algorithm (default: SHA1)
	Algorithm string `json:"algorithm"`
}

// Validate validates the QR code options
func (o *QRCodeOptions) Validate() error {
	if o.Digits < 6 || o.Digits > 8 {
		return fmt.Errorf("digits must be between 6 and 8")
	}
	
	if o.Period < 15 || o.Period > 300 {
		return fmt.Errorf("period must be between 15 and 300 seconds")
	}
	
	if o.Algorithm != "" {
		validAlgorithms := []string{"SHA1", "SHA256", "SHA512"}
		valid := false
		for _, alg := range validAlgorithms {
			if o.Algorithm == alg {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("algorithm must be one of: %v", validAlgorithms)
		}
	}
	
	return nil
}

// QRCodeData contains all the data needed for QR code generation
type QRCodeData struct {
	// URL is the complete TOTP URL for QR code generation
	URL string `json:"url"`
	
	// Secret is the base32-encoded secret
	Secret string `json:"secret"`
	
	// AccountName is the account identifier
	AccountName string `json:"account_name"`
	
	// Issuer is the service name
	Issuer string `json:"issuer"`
	
	// Digits is the number of digits in TOTP codes
	Digits int `json:"digits"`
	
	// Period is the time period for TOTP
	Period int `json:"period"`
	
	// Algorithm is the hash algorithm used
	Algorithm string `json:"algorithm"`
}

// GetManualEntryKey returns a formatted secret for manual entry
func (q *QRCodeData) GetManualEntryKey() string {
	// Format the secret in groups of 4 characters for easier manual entry
	secret := strings.ToUpper(q.Secret)
	var formatted strings.Builder
	
	for i, char := range secret {
		if i > 0 && i%4 == 0 {
			formatted.WriteString(" ")
		}
		formatted.WriteRune(char)
	}
	
	return formatted.String()
}

// GetSetupInstructions returns user-friendly setup instructions
func (q *QRCodeData) GetSetupInstructions() *SetupInstructions {
	return &SetupInstructions{
		QRCodeURL:    q.URL,
		ManualKey:    q.GetManualEntryKey(),
		AccountName:  q.AccountName,
		Issuer:       q.Issuer,
		Instructions: q.generateInstructions(),
	}
}

// generateInstructions generates step-by-step setup instructions
func (q *QRCodeData) generateInstructions() []string {
	return []string{
		"1. Install a TOTP authenticator app on your mobile device (Google Authenticator, Authy, etc.)",
		"2. Open the authenticator app and choose to add a new account",
		"3. Either scan the QR code below or manually enter the provided key",
		fmt.Sprintf("4. Enter the account name: %s", q.AccountName),
		fmt.Sprintf("5. Enter the issuer: %s", q.Issuer),
		"6. Save the account in your authenticator app",
		"7. Enter the 6-digit code from your authenticator app to complete setup",
	}
}

// SetupInstructions contains user-friendly MFA setup instructions
type SetupInstructions struct {
	// QRCodeURL is the URL for QR code generation
	QRCodeURL string `json:"qr_code_url"`
	
	// ManualKey is the formatted secret for manual entry
	ManualKey string `json:"manual_key"`
	
	// AccountName is the account identifier
	AccountName string `json:"account_name"`
	
	// Issuer is the service name
	Issuer string `json:"issuer"`
	
	// Instructions are step-by-step setup instructions
	Instructions []string `json:"instructions"`
}