package core

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsCommonPassword(t *testing.T) {
	// Ensure common passwords check is enabled
	InitCommonPasswords(true)

	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{"Common password", "123456", true},
		{"Common password 'password'", "password", true},
		{"Common password case-insensitive", "PASSWORD", true},
		{"Common password mixed case", "QwErTy", true},
		{"Common password with whitespace", "  123456  ", true},
		{"Common password 'qwerty' with whitespace", "  qwerty  ", true},
		{"Non-common password", "ThisIsAUniquePassword123!", false},
		{"Empty password", "", false},
		{"Whitespace only", "   ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCommonPassword(tt.password)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestValidatePasswordCommonCheck(t *testing.T) {
	// ValidatePassword surfaces the common-password rejection when enabled.
	InitCommonPasswords(true)
	cfg := &Config{
		MinPasswordLength:    4,
		CheckCommonPasswords: true,
	}
	require.Error(t, ValidatePassword("password", cfg))

	// Should not error if CheckCommonPasswords is false
	cfg.CheckCommonPasswords = false
	require.NoError(t, ValidatePassword("password", cfg))
}

func TestInitCommonPasswords(t *testing.T) {
	// Test disabling
	InitCommonPasswords(false)
	require.False(t, isCommonPassword("123456"), "Should return false for common password when disabled")

	// Test re-enabling
	InitCommonPasswords(true)
	require.True(t, isCommonPassword("123456"), "Should return true for common password when enabled")
}

func TestParseCommonPasswordsEdgeCases(t *testing.T) {
	// Backup original raw string and restore it after test
	originalRaw := commonPasswordsRaw
	defer func() {
		commonPasswordsRaw = originalRaw
		// Reset the once mechanism and parse again to restore state
		commonPasswordsOnce = sync.Once{}
		commonPasswordsOn = true
		InitCommonPasswords(true)
	}()

	// Provide a test raw string with comments, empty lines, and spaces
	commonPasswordsRaw = `
# This is a comment
123456
  password
# Another comment

qwerty
`
	// Reset the once mechanism so it parses the new string
	commonPasswordsOnce = sync.Once{}

	// Call parse directly via InitCommonPasswords to populate commonPasswords map
	InitCommonPasswords(true)

	require.NotNil(t, commonPasswords)

	// Should contain the passwords, trimmed and lowercased
	_, has123456 := commonPasswords["123456"]
	require.True(t, has123456, "Should contain 123456")

	_, hasPassword := commonPasswords["password"]
	require.True(t, hasPassword, "Should contain password, ignoring surrounding spaces")

	_, hasQwerty := commonPasswords["qwerty"]
	require.True(t, hasQwerty, "Should contain qwerty")

	// Should not contain comments or empty strings
	require.Len(t, commonPasswords, 3, "Should only have 3 valid passwords")
}
