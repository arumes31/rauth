package core

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestEncryption(t *testing.T) {
	key := "12345678901234567890123456789012" // 32 bytes
	plaintext := "secret token message"

	encrypted, err := EncryptToken(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := DecryptToken(encrypted, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted text mismatch. Got %s, want %s", decrypted, plaintext)
	}
}

func TestValidatePassword(t *testing.T) {
	cfg := &Config{
		MinPasswordLength: 8,
		RequirePasswordUpper: true,
		RequirePasswordLower: true,
		RequirePasswordNumber: true,
		RequirePasswordSpecial: true,
	}

	tests := []struct {
		password string
		valid    bool
	}{
		{"SecurePass123!", true},
		{"short", false},
		{"noupper123!", false},
		{"NOLOWER123!", false},
		{"NoNumber!", false},
		{"NoSpecial123", false},
	}

	for _, tt := range tests {
		err := ValidatePassword(tt.password, cfg)
		if tt.valid {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
		}
	}
}

func TestValidateRedirectURL(t *testing.T) {
	cfg := &Config{
		AllowedHosts: []string{"example.com", "trust.com"},
	}

	tests := []struct {
		url      string
		expected string
	}{
		{"/profile", "/profile"},
		{"https://example.com/callback", "https://example.com/callback"},
		{"https://evil.com", "/"},
		{"//evil.com", "/"},
		{"javascript:alert(1)", "/"},
		{"", "/"},
	}

	for _, tt := range tests {
		res := ValidateRedirectURL(tt.url, "/", "user", cfg)
		assert.Equal(t, tt.expected, res)
	}
}

func TestIsUserAgentCompatible(t *testing.T) {
	tests := []struct {
		name     string
		oldUA    string
		newUA    string
		expected bool
	}{
		{
			name:     "Same UA",
			oldUA:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			newUA:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			expected: true,
		},
		{
			name:     "Same Browser Different OS",
			oldUA:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			newUA:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			expected: false,
		},
		{
			name:     "Different Browser Same OS",
			oldUA:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			newUA:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
			expected: false,
		},
		{
			name:     "Linux and Android Compatible",
			oldUA:    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			newUA:    "Mozilla/5.0 (Android 13; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
			expected: false, // Different browsers
		},
		{
			name:     "Linux and Android Compatible Same Browser",
			oldUA:    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			newUA:    "Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			expected: true,
		},
		{
			name:     "Unknown Compatibility",
			oldUA:    "MyCustomApp/1.0",
			newUA:    "MyCustomApp/1.1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := IsUserAgentCompatible(tt.oldUA, tt.newUA)
			assert.Equal(t, tt.expected, res)
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected bool
		msg      string
	}{
		{"test@example.com", true, ""},
		{"user.name+tag@gmail.com", true, ""},
		{"", false, "Email is required"},
		{"invalid-email", false, "Invalid email format"},
		{"@example.com", false, "Invalid email format"},
		{"test@", false, "Invalid email format"},
		{"test@.com", false, "Invalid email format"},
		{"test@example", false, "Invalid email format"},
	}

	for _, tt := range tests {
		err := ValidateEmail(tt.email)
		if tt.expected {
			assert.NoError(t, err, "Email: %s", tt.email)
		} else {
			assert.Error(t, err, "Email: %s", tt.email)
			assert.Equal(t, tt.msg, err.Error())
		}
	}
}
