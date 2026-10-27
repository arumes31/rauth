package core

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression tests for the 2026-10-27 security audit findings.

func newRegressionRedis(t *testing.T) {
	t.Helper()
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})
	UserDB, TokenDB, RateLimitDB, AuditDB, InviteDB = client, client, client, client, client
	ServerSecret = "32byte-secret-key-for-testing-!!"
}

// Finding 12: IPv6 clients are bucketed per /64.
func TestRegression_RateLimitIP(t *testing.T) {
	assert.Equal(t, "203.0.113.7", RateLimitIP("203.0.113.7"))
	assert.Equal(t, "2001:db8:1:2::/64", RateLimitIP("2001:db8:1:2:aaaa:bbbb:cccc:dddd"))
	assert.Equal(t, RateLimitIP("2001:db8:1:2::1"), RateLimitIP("2001:db8:1:2::ffff"))
	assert.NotEqual(t, RateLimitIP("2001:db8:1:2::1"), RateLimitIP("2001:db8:1:3::1"))
	assert.Equal(t, "not-an-ip", RateLimitIP("not-an-ip"))
}

// Finding 13: a credential write-back for a deleted account must not
// re-create its passkey hash, and a recreated account starts clean.
func TestRegression_CredentialNotRematerializedAfterDelete(t *testing.T) {
	newRegressionRedis(t)
	require.NoError(t, CreateUser("erin", "Password123", "", false, ""))
	require.NoError(t, SaveWebAuthnCredential("erin", &webauthn.Credential{ID: []byte("k1")}))
	require.NoError(t, DeleteUser("erin"))

	err := UpdateWebAuthnSignCount("erin", []byte("k1"), 7)
	assert.Error(t, err)
	exists, _ := UserDB.Exists(Ctx, "user:erin:webauthn_creds_v2").Result()
	assert.Equal(t, int64(0), exists)

	// Leftover satellite state from any path is cleared on recreation.
	UserDB.HSet(Ctx, "user:erin:webauthn_creds_v2", "6b31", "{}")
	UserDB.SAdd(Ctx, "user:erin:recovery_codes", "x")
	require.NoError(t, CreateUser("erin", "Password123", "", false, ""))
	assert.Empty(t, GetWebAuthnCredentials("erin"))
	assert.Equal(t, int64(0), CountRecoveryCodes("erin"))
}

// Findings 2/10: delete and recreate bumps the generation past old tokens.
func TestRegression_AuthGenerationAcrossRecreate(t *testing.T) {
	newRegressionRedis(t)
	require.NoError(t, CreateUser("frank", "Password123", "", false, ""))
	value, err := PendingTokenValue("frank")
	require.NoError(t, err)
	_, ok := ResolvePendingToken(value)
	assert.True(t, ok)

	require.NoError(t, DeleteUser("frank"))
	require.NoError(t, CreateUser("frank", "Password123", "", false, ""))
	_, ok = ResolvePendingToken(value)
	assert.False(t, ok, "a pending token from the deleted account must not resolve")

	// Legacy (pre-generation) values stay valid only while the generation is 0.
	_, ok = ResolvePendingToken("legacy")
	assert.True(t, ok)
}

// Concurrent creation of the same name cannot overwrite an existing account.
func TestRegression_CreateUserIsAtomic(t *testing.T) {
	newRegressionRedis(t)
	require.NoError(t, CreateUser("gina", "Password123", "", false, ""))
	assert.Error(t, CreateUser("gina", "Other12345", "", true, ""))
	u, err := GetUser("gina")
	require.NoError(t, err)
	assert.Equal(t, "0", u.IsAdmin)
}

// Hardening: recovery codes are keyed hashes; legacy unkeyed codes still work.
func TestRegression_RecoveryCodesKeyedAndBackwardCompatible(t *testing.T) {
	newRegressionRedis(t)
	codes, err := GenerateRecoveryCodes("hank")
	require.NoError(t, err)
	require.Len(t, codes, recoveryCodeCount)
	assert.Len(t, normalizeRecoveryCode(codes[0]), 2*recoveryCodeBytes)
	stored, _ := UserDB.SMembers(Ctx, recoveryCodesKey("hank")).Result()
	assert.NotContains(t, stored, legacyHashRecoveryCode(codes[0]), "new codes must use the keyed hash")
	assert.True(t, ConsumeRecoveryCode("hank", codes[0]))
	assert.False(t, ConsumeRecoveryCode("hank", codes[0]))

	UserDB.SAdd(Ctx, recoveryCodesKey("hank"), legacyHashRecoveryCode("abcde-12345"))
	assert.True(t, ConsumeRecoveryCode("hank", "abcde-12345"))
}

// Finding 9: reconciliation only prunes tokens that are really gone.
func TestRegression_ReconcileKeepsLiveSessions(t *testing.T) {
	newRegressionRedis(t)
	TokenDB.HSet(Ctx, "X-rauth-authtoken=live", "status", "valid")
	TokenDB.SAdd(Ctx, "user_sessions:ivan", "live", "gone")
	assert.Equal(t, int64(1), reconcileIndexSets("user_sessions:*"))
	members, _ := TokenDB.SMembers(Ctx, "user_sessions:ivan").Result()
	assert.Equal(t, []string{"live"}, members)
}

// The second-factor write refuses to overwrite or to create a stub hash.
func TestRegression_SetSecondFactorIfUnset(t *testing.T) {
	newRegressionRedis(t)
	ok, err := SetSecondFactorIfUnset("ghost", "enc:x")
	require.NoError(t, err)
	assert.False(t, ok)
	exists, _ := UserDB.Exists(Ctx, "user:ghost").Result()
	assert.Equal(t, int64(0), exists)

	require.NoError(t, CreateUser("judy", "Password123", "", false, ""))
	ok, _ = SetSecondFactorIfUnset("judy", "enc:first")
	assert.True(t, ok)
	ok, _ = SetSecondFactorIfUnset("judy", "enc:second")
	assert.False(t, ok)
}
