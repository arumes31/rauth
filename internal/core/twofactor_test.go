package core

import (
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
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

	// totp.Validate accepts whitespace-padded codes, so padding must not mint
	// a fresh replay record for an already used code.
	require.False(t, TOTPCodeReused("carol", "111111"))
	require.True(t, TOTPCodeReused("carol", " 111111"))
	require.True(t, TOTPCodeReused("carol", "111111\t\n"))
}

func TestRecoveryCodes(t *testing.T) {
	setupPG(t)
	require.NoError(t, PutUser(User{Username: "alice"}))

	codes, err := GenerateRecoveryCodes("alice")
	require.NoError(t, err)
	require.Len(t, codes, recoveryCodeCount)
	require.Equal(t, int64(recoveryCodeCount), CountRecoveryCodes("alice"))

	// A valid code is consumed exactly once.
	require.True(t, ConsumeRecoveryCode("alice", codes[0]))
	require.False(t, ConsumeRecoveryCode("alice", codes[0]))
	require.Equal(t, int64(recoveryCodeCount-1), CountRecoveryCodes("alice"))

	// Codes are case-insensitive and tolerate the display separator.
	transformedCode := strings.ToLower(codes[1][:4]) + "-" + strings.ToLower(codes[1][4:])
	require.True(t, ConsumeRecoveryCode("alice", transformedCode))

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

	// Empty or whitespace-only codes are rejected.
	require.False(t, ConsumeRecoveryCode("alice", ""))
	require.False(t, ConsumeRecoveryCode("alice", "   "))

}

func TestConsumeRecoveryCode_DatabaseError(t *testing.T) {
	// A database error returns false: point PG at a closed pool.
	setupPG(t)
	oldPG := PG
	closed, err := pgxpool.New(Ctx, "postgres://localhost:1/none")
	require.NoError(t, err)
	closed.Close()
	PG = closed
	defer func() { PG = oldPG }()

	require.False(t, ConsumeRecoveryCode("alice", "valid-code"))
}
