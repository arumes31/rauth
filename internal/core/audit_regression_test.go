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
	TokenDB, RateLimitDB, InviteDB = client, client, client
	setupPG(t)
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
	var n int
	require.NoError(t, PG.QueryRow(Ctx, "SELECT count(*) FROM webauthn_credentials WHERE username = 'erin'").Scan(&n))
	assert.Equal(t, 0, n)

	// Satellite rows cannot outlive the account (foreign keys), so a
	// recreated account starts clean.
	assert.Error(t, SaveWebAuthnCredential("erin", &webauthn.Credential{ID: []byte("k2")}))
	_, err = GenerateRecoveryCodes("erin")
	assert.Error(t, err)
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
	require.NoError(t, CreateUser("hank", "Password123", "", false, ""))
	codes, err := GenerateRecoveryCodes("hank")
	require.NoError(t, err)
	require.Len(t, codes, recoveryCodeCount)
	assert.Len(t, normalizeRecoveryCode(codes[0]), 2*recoveryCodeBytes)
	var stored []string
	require.NoError(t, PG.QueryRow(Ctx, "SELECT array_agg(code_hash) FROM recovery_codes WHERE username = 'hank'").Scan(&stored))
	assert.NotContains(t, stored, legacyHashRecoveryCode(codes[0]), "new codes must use the keyed hash")
	assert.True(t, ConsumeRecoveryCode("hank", codes[0]))
	assert.False(t, ConsumeRecoveryCode("hank", codes[0]))

	_, err = PG.Exec(Ctx, "INSERT INTO recovery_codes (username, code_hash) VALUES ('hank', $1)", legacyHashRecoveryCode("abcde-12345"))
	require.NoError(t, err)
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

// The second-factor write refuses to overwrite or to create an account.
func TestRegression_SetSecondFactorIfUnset(t *testing.T) {
	newRegressionRedis(t)
	ok, err := SetSecondFactorIfUnset("ghost", "enc:x")
	require.NoError(t, err)
	assert.False(t, ok)
	exists, _ := UserExists("ghost")
	assert.False(t, exists)

	require.NoError(t, CreateUser("judy", "Password123", "", false, ""))
	ok, _ = SetSecondFactorIfUnset("judy", "enc:first")
	assert.True(t, ok)
	ok, _ = SetSecondFactorIfUnset("judy", "enc:second")
	assert.False(t, ok)
}

// Restamping a session that no longer exists must not create a TTL-less hash.
func TestRegression_RestampOnlyExistingSession(t *testing.T) {
	newRegressionRedis(t)
	RestampSession("gone", "5")
	exists, _ := TokenDB.Exists(Ctx, "X-rauth-authtoken=gone").Result()
	assert.Equal(t, int64(0), exists)

	TokenDB.HSet(Ctx, "X-rauth-authtoken=live", "status", "valid")
	RestampSession("live", "5")
	assert.Equal(t, "5", TokenDB.HGet(Ctx, "X-rauth-authtoken=live", "auth_gen").Val())
}
