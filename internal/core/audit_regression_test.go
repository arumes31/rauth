package core

import (
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
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
	require.NoError(t, SaveWebAuthnCredential("erin", &webauthn.Credential{ID: []byte("k1")}, currentGen(t, "erin")))
	require.NoError(t, DeleteUser("erin"))

	err := UpdateWebAuthnSignCount("erin", []byte("k1"), 7)
	assert.Error(t, err)
	var n int
	require.NoError(t, PG.QueryRow(Ctx, "SELECT count(*) FROM webauthn_credentials WHERE username = 'erin'").Scan(&n))
	assert.Equal(t, 0, n)

	// Satellite rows cannot outlive the account (foreign keys), so a
	// recreated account starts clean.
	assert.Error(t, SaveWebAuthnCredential("erin", &webauthn.Credential{ID: []byte("k2")}, currentGen(t, "erin")))
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
	gen := currentGen(t, "frank")
	value := PendingTokenValue("frank", gen)
	name, resolvedGen, ok := ResolvePendingToken(value)
	assert.True(t, ok)
	assert.Equal(t, "frank", name)
	assert.Equal(t, gen, resolvedGen, "the session issued at the end must carry the login's generation")

	require.NoError(t, DeleteUser("frank"))
	require.NoError(t, CreateUser("frank", "Password123", "", false, ""))
	_, _, ok = ResolvePendingToken(value)
	assert.False(t, ok, "a pending token from the deleted account must not resolve")

	// Legacy (pre-generation) values stay valid only while the generation is 0.
	_, _, ok = ResolvePendingToken("legacy")
	assert.True(t, ok)
}

// A credential reset commits the generation bump with the change itself, so
// a login that read the generation before the old credentials can only ever
// carry the old generation.
func TestRegression_RevokeAuthIsAtomic(t *testing.T) {
	newRegressionRedis(t)
	require.NoError(t, CreateUser("rita", "Password123", "", false, ""))
	before := currentGen(t, "rita")
	oldHash := func() string { u, _ := GetUser("rita"); return u.Password }()

	// A change that fails rolls the bump back: nothing was revoked.
	_, err := RevokeAuth("rita", func(tx pgx.Tx) error {
		_, _ = tx.Exec(Ctx, "UPDATE users SET password = 'x' WHERE username = 'rita'")
		return errors.New("boom")
	})
	require.Error(t, err)
	assert.Equal(t, before, currentGen(t, "rita"))
	u, _ := GetUser("rita")
	assert.Equal(t, oldHash, u.Password)

	gen, err := SetPassword("rita", "newhash")
	require.NoError(t, err)
	assert.NotEqual(t, before, gen)
	assert.Equal(t, gen, currentGen(t, "rita"))
	_, err = SetPassword("nobody", "h")
	assert.ErrorIs(t, err, ErrUserNotFound)
}

// Enrollment writes authorized under an old generation are rejected, and a
// reset that deletes factors also removes ones written just before it.
func TestRegression_FactorWritesNeedCurrentGeneration(t *testing.T) {
	newRegressionRedis(t)
	require.NoError(t, CreateUser("sam", "Password123", "", false, ""))
	stale := currentGen(t, "sam")
	_, err := SetPassword("sam", "newhash")
	require.NoError(t, err)

	ok, err := SetSecondFactorIfUnset("sam", "enc:attacker", stale)
	require.NoError(t, err)
	assert.False(t, ok, "an enrollment authorized before the reset must not land")
	assert.ErrorIs(t, SaveWebAuthnCredential("sam", &webauthn.Credential{ID: []byte("evil")}, stale), ErrStaleGeneration)
	assert.Empty(t, GetWebAuthnCredentials("sam"))

	// Current generation: the writes go through, and a reset removes them all.
	ok, err = SetSecondFactorIfUnset("sam", "enc:mine", currentGen(t, "sam"))
	require.NoError(t, err)
	assert.True(t, ok)
	require.NoError(t, SaveWebAuthnCredential("sam", &webauthn.Credential{ID: []byte("mine")}, currentGen(t, "sam")))
	_, err = GenerateRecoveryCodes("sam")
	require.NoError(t, err)
	_, err = ResetSecondFactors("sam")
	require.NoError(t, err)
	u, _ := GetUser("sam")
	assert.Empty(t, u.TwoFactor)
	assert.Empty(t, GetWebAuthnCredentials("sam"))
	assert.Equal(t, int64(0), CountRecoveryCodes("sam"))
}

// A factor write holding the generation lock makes a concurrent reset wait,
// so the reset runs after it and removes what it wrote.
func TestRegression_ResetWaitsForInFlightFactorWrite(t *testing.T) {
	newRegressionRedis(t)
	require.NoError(t, CreateUser("tess", "Password123", "", false, ""))
	gen := currentGen(t, "tess")

	tx, err := PG.Begin(Ctx)
	require.NoError(t, err)
	current, err := lockAuthGeneration(tx, "tess", gen)
	require.NoError(t, err)
	require.True(t, current)
	_, err = tx.Exec(Ctx, `INSERT INTO webauthn_credentials (username, cred_id, data) VALUES ('tess', 'aa', '{}')`)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { _, err := ResetSecondFactors("tess"); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("reset finished while a factor write held the generation lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	require.NoError(t, tx.Commit(Ctx))
	require.NoError(t, <-done)

	var n int
	require.NoError(t, PG.QueryRow(Ctx, "SELECT count(*) FROM webauthn_credentials WHERE username = 'tess'").Scan(&n))
	assert.Equal(t, 0, n, "the reset must remove the passkey written just before it")
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
	ok, err := SetSecondFactorIfUnset("ghost", "enc:x", "0")
	require.NoError(t, err)
	assert.False(t, ok)
	exists, _ := UserExists("ghost")
	assert.False(t, exists)

	require.NoError(t, CreateUser("judy", "Password123", "", false, ""))
	ok, _ = SetSecondFactorIfUnset("judy", "enc:first", currentGen(t, "judy"))
	assert.True(t, ok)
	ok, _ = SetSecondFactorIfUnset("judy", "enc:second", currentGen(t, "judy"))
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
