package core

import (
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
		{"Substring prefix", "prefix_password", false},
		{"Substring suffix", "123456_suffix", false},
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

func TestInitCommonPasswords_MultipleCalls(t *testing.T) {
	// Test that it is safe to call multiple times
	InitCommonPasswords(true)
	InitCommonPasswords(true)
	InitCommonPasswords(false)
	require.False(t, isCommonPassword("123456"))
	InitCommonPasswords(true)
	require.True(t, isCommonPassword("123456"))
}
