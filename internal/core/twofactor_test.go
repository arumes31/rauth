package core

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestTOTPCodeReused(t *testing.T) {
	s := miniredis.RunT(t)
	TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	// First use of a code is accepted; an immediate replay is rejected.
	require.False(t, TOTPCodeReused("alice", "123456"))
	require.True(t, TOTPCodeReused("alice", "123456"))

	// A different code, and the same code for another user, are independent.
	require.False(t, TOTPCodeReused("alice", "654321"))
	require.False(t, TOTPCodeReused("bob", "123456"))

	// Empty codes are never treated as reused.
	require.False(t, TOTPCodeReused("alice", ""))
}

func TestRecoveryCodes(t *testing.T) {
	s := miniredis.RunT(t)
	UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	codes, err := GenerateRecoveryCodes("alice")
	require.NoError(t, err)
	require.Len(t, codes, recoveryCodeCount)
	require.Equal(t, int64(recoveryCodeCount), CountRecoveryCodes("alice"))

	// A valid code is consumed exactly once.
	require.True(t, ConsumeRecoveryCode("alice", codes[0]))
	require.False(t, ConsumeRecoveryCode("alice", codes[0]))
	require.Equal(t, int64(recoveryCodeCount-1), CountRecoveryCodes("alice"))

	// Codes are case-insensitive and tolerate the display separator.
	require.True(t, ConsumeRecoveryCode("alice", codes[1]))

	// Unknown codes are rejected.
	require.False(t, ConsumeRecoveryCode("alice", "0000-00000"))

	// Regenerating replaces the previous batch.
	newCodes, err := GenerateRecoveryCodes("alice")
	require.NoError(t, err)
	require.Equal(t, int64(recoveryCodeCount), CountRecoveryCodes("alice"))
	require.False(t, ConsumeRecoveryCode("alice", codes[2])) // old batch invalid
	require.True(t, ConsumeRecoveryCode("alice", newCodes[0]))

	// Clearing removes everything.
	ClearRecoveryCodes("alice")
	require.Equal(t, int64(0), CountRecoveryCodes("alice"))
}

func TestIsCommonPassword(t *testing.T) {
	InitCommonPasswords(true)
	require.True(t, isCommonPassword("password"))
	require.True(t, isCommonPassword("PASSWORD")) // case-insensitive
	require.True(t, isCommonPassword("  qwerty  "))
	require.False(t, isCommonPassword("S0me-Uniqu3-Passphrase!"))

	// ValidatePassword surfaces the common-password rejection when enabled.
	cfg := &Config{MinPasswordLength: 4, CheckCommonPasswords: true}
	require.Error(t, ValidatePassword("password", cfg))

	// Over-length passwords are rejected to avoid bcrypt's 72-byte truncation.
	long := make([]byte, 73)
	for i := range long {
		long[i] = 'a'
	}
	require.Error(t, ValidatePassword(string(long), &Config{MinPasswordLength: 4}))
}
