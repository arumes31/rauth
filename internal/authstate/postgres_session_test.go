package authstate_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"rauth/internal/authstate"
	"rauth/internal/core"
	"rauth/internal/pgtest"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const indexSecret = "test-only-stable-index-key-32-bytes-long"
const encryptionSecret = "test-only-payload-key-one-32-bytes-long"

func keyring(t *testing.T, active string, keys map[string]string) *authstate.Keyring {
	t.Helper()
	k, err := authstate.NewKeyring(indexSecret, active, keys)
	require.NoError(t, err)
	return k
}
func fixture(t *testing.T) (*pgxpool.Pool, *authstate.PostgresSessions, *authstate.PostgresSessions) {
	t.Helper()
	p := pgtest.Open(t, core.Migrate)
	pgtest.Reset(t, p)
	core.PG = p
	_, err := p.Exec(context.Background(), "INSERT INTO users(username) VALUES('alice')")
	require.NoError(t, err)
	k := keyring(t, "v1", map[string]string{"v1": encryptionSecret})
	a, err := authstate.NewPostgresSessions(context.Background(), p, k)
	require.NoError(t, err)
	other, err := pgxpool.NewWithConfig(context.Background(), p.Config())
	require.NoError(t, err)
	t.Cleanup(other.Close)
	b, err := authstate.NewPostgresSessions(context.Background(), other, k)
	require.NoError(t, err)
	return p, a, b
}
func token(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
func params() authstate.IssueSession {
	return authstate.IssueSession{Username: "alice", Generation: 0, IP: "203.0.113.42", Fields: map[string]string{"agent": "private-test-agent"}, IdleTTL: 10 * time.Minute, AbsoluteTTL: time.Hour}
}

func TestPostgresSessionsCrossNodeLifecycle(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	old, next, replaced := token("old"), token("next"), token("replacement")
	require.NoError(t, a.Issue(ctx, old, params()))
	initial, err := b.Get(ctx, old)
	require.NoError(t, err)
	assert.Equal(t, "alice", initial.Username)
	assert.Equal(t, "203.0.113.42", initial.IP)
	assert.Equal(t, "private-test-agent", initial.Fields["agent"])
	var hash, payload []byte
	require.NoError(t, p.QueryRow(ctx, "SELECT token_hash,payload FROM auth_sessions").Scan(&hash, &payload))
	assert.Len(t, hash, 32)
	assert.NotContains(t, string(payload), old)
	assert.NotContains(t, string(payload), "private-test-agent")
	require.ErrorIs(t, b.Issue(ctx, old, params()), authstate.ErrConflict)
	changed, err := b.Rotate(ctx, old, next, 10*time.Minute, 30*time.Second)
	require.NoError(t, err)
	require.True(t, changed)
	retired, err := a.Get(ctx, old)
	require.NoError(t, err)
	assert.Equal(t, next, retired.Successor)
	successor, err := a.Get(ctx, next)
	require.NoError(t, err)
	assert.Equal(t, initial.FamilyID, successor.FamilyID)
	assert.True(t, initial.AbsoluteExpiresAt.Equal(successor.AbsoluteExpiresAt))
	changed, err = a.Rotate(ctx, old, token("fork"), 10*time.Minute, 30*time.Second)
	require.NoError(t, err)
	assert.False(t, changed)
	changed, err = a.Refresh(ctx, old, time.Hour)
	require.NoError(t, err)
	assert.False(t, changed)
	retiredAfter, err := b.Get(ctx, old)
	require.NoError(t, err)
	assert.True(t, retired.IdleExpiresAt.Equal(retiredAfter.IdleExpiresAt))
	changed, err = a.Replace(ctx, next, replaced)
	require.NoError(t, err)
	require.True(t, changed)
	_, err = b.Get(ctx, next)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	replacement, err := b.Get(ctx, replaced)
	require.NoError(t, err)
	assert.True(t, successor.IdleExpiresAt.Equal(replacement.IdleExpiresAt))
	assert.Equal(t, initial.FamilyID, replacement.FamilyID)
	require.NoError(t, b.Revoke(ctx, old))
	for _, tok := range []string{old, next, replaced} {
		_, err = a.Get(ctx, tok)
		assert.ErrorIs(t, err, authstate.ErrNotFound)
	}
	changed, err = a.Refresh(ctx, replaced, time.Hour)
	require.NoError(t, err)
	assert.False(t, changed)
	changed, err = a.Rotate(ctx, replaced, token("resurrection"), time.Hour, 30*time.Second)
	require.NoError(t, err)
	assert.False(t, changed)
}
func TestPostgresSessionsExpiryAndRefreshBound(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	tok := token("expiry")
	require.NoError(t, a.Issue(ctx, tok, params()))
	changed, err := b.Refresh(ctx, tok, time.Hour)
	require.NoError(t, err)
	assert.False(t, changed, "hot requests do not write sliding expiry each time")
	_, err = p.Exec(ctx, "UPDATE auth_session_families SET absolute_expires_at=clock_timestamp()+interval '1 minute'; UPDATE auth_sessions SET last_refreshed_at=clock_timestamp()-interval '2 minutes'")
	require.NoError(t, err)
	changed, err = b.Refresh(ctx, tok, time.Hour)
	require.NoError(t, err)
	require.True(t, changed)
	session, err := a.Get(ctx, tok)
	require.NoError(t, err)
	assert.True(t, session.IdleExpiresAt.Equal(session.AbsoluteExpiresAt))
	changed, err = a.Rotate(ctx, tok, token("capped"), time.Hour, 30*time.Second)
	require.NoError(t, err)
	require.True(t, changed)
	session, err = b.Get(ctx, token("capped"))
	require.NoError(t, err)
	assert.True(t, session.IdleExpiresAt.Equal(session.AbsoluteExpiresAt))
	_, err = p.Exec(ctx, "UPDATE auth_session_families SET absolute_expires_at=clock_timestamp()-interval '1 second'")
	require.NoError(t, err)
	_, err = b.Get(ctx, token("capped"))
	require.ErrorIs(t, err, authstate.ErrNotFound)
	changed, err = b.Refresh(ctx, token("capped"), time.Hour)
	require.NoError(t, err)
	assert.False(t, changed)
	require.NoError(t, a.Cleanup(ctx))
	var count int
	require.NoError(t, p.QueryRow(ctx, "SELECT count(*) FROM auth_sessions").Scan(&count))
	assert.Zero(t, count)
}
func TestPostgresSessionsConcurrentRotationAndLogout(t *testing.T) {
	_, a, b := fixture(t)
	ctx := context.Background()
	old := token("concurrent")
	require.NoError(t, a.Issue(ctx, old, params()))
	start := make(chan struct{})
	var wg sync.WaitGroup
	var wins atomic.Int32
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			store := a
			if i%2 == 0 {
				store = b
			}
			ok, err := store.Rotate(ctx, old, token(string(rune('a'+i))), time.Hour, 30*time.Second)
			if err != nil {
				assert.ErrorIs(t, err, authstate.ErrBusy)
			}
			if ok {
				wins.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	require.Equal(t, int32(1), wins.Load())
	session, err := b.Get(ctx, old)
	require.NoError(t, err)
	require.NotEmpty(t, session.Successor)
	require.NoError(t, a.Revoke(ctx, old))
	_, err = b.Get(ctx, session.Successor)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	// The winner is irrelevant when logout races a new rotation: every possible
	// successor belongs to the revoked family.
	for i := 0; i < 4; i++ {
		old, next := token("race"+string(rune('a'+i))), token("successor"+string(rune('a'+i)))
		require.NoError(t, a.Issue(ctx, old, params()))
		gate := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-gate
			_, err := a.Rotate(ctx, old, next, time.Hour, 30*time.Second)
			if err != nil {
				assert.ErrorIs(t, err, authstate.ErrBusy)
			}
		}()
		go func() { defer wg.Done(); <-gate; assert.NoError(t, b.Revoke(ctx, old)) }()
		close(gate)
		wg.Wait()
		for _, tok := range []string{old, next} {
			_, err := b.Get(ctx, tok)
			assert.ErrorIs(t, err, authstate.ErrNotFound)
		}
	}
}
func TestPostgresSessionsGenerationAndRestamp(t *testing.T) {
	_, a, b := fixture(t)
	ctx := context.Background()
	old := token("generation")
	require.NoError(t, a.Issue(ctx, old, params()))
	gen, err := core.RevokeAuth("alice", nil)
	require.NoError(t, err)
	require.Equal(t, "1", gen)
	_, err = b.Get(ctx, old)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	require.ErrorIs(t, b.Issue(ctx, token("stale-proof"), params()), authstate.ErrStaleGeneration)
	ok, err := a.Restamp(ctx, old, 0, 1)
	require.NoError(t, err)
	require.True(t, ok)
	session, err := b.Get(ctx, old)
	require.NoError(t, err)
	assert.Equal(t, int64(1), session.Generation)
	require.NoError(t, b.RevokeUser(ctx, "alice"))
	_, err = a.Get(ctx, old)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	ok, err = a.Restamp(ctx, old, 1, 2)
	require.NoError(t, err)
	assert.False(t, ok, "global logout cannot be undone by restamping")
	p := params()
	p.Generation = 1
	require.ErrorIs(t, a.Issue(ctx, token("pre-logout-proof"), p), authstate.ErrStaleGeneration)
	p.Generation = 2
	require.NoError(t, b.Issue(ctx, token("fresh-proof"), p))
}
func TestPostgresSessionsKeyRotationAndTamper(t *testing.T) {
	p, a, _ := fixture(t)
	ctx := context.Background()
	old := token("old-key")
	require.NoError(t, a.Issue(ctx, old, params()))
	_, err := authstate.NewPostgresSessions(ctx, p, keyring(t, "v2", map[string]string{"v2": strings.Repeat("b", 32)}))
	require.ErrorContains(t, err, "encryption key is missing")
	both := keyring(t, "v2", map[string]string{"v1": encryptionSecret, "v2": strings.Repeat("b", 32)})
	rotated, err := authstate.NewPostgresSessions(ctx, p, both)
	require.NoError(t, err)
	_, err = rotated.Get(ctx, old)
	require.NoError(t, err)
	ok, err := rotated.Rotate(ctx, old, token("new-key"), time.Hour, 30*time.Second)
	require.NoError(t, err)
	require.True(t, ok)
	newOnly, err := authstate.NewPostgresSessions(ctx, p, keyring(t, "v2", map[string]string{"v2": strings.Repeat("b", 32)}))
	require.NoError(t, err)
	_, err = newOnly.Get(ctx, token("new-key"))
	require.NoError(t, err)
	wrongIndex, err := authstate.NewKeyring(strings.Repeat("x", 32), "v2", map[string]string{"v2": strings.Repeat("b", 32)})
	require.NoError(t, err)
	_, err = authstate.NewPostgresSessions(ctx, p, wrongIndex)
	require.ErrorIs(t, err, authstate.ErrKeyMismatch)
	_, err = authstate.NewPostgresSessions(ctx, p, keyring(t, "v2", map[string]string{"v2": strings.Repeat("c", 32)}))
	require.ErrorIs(t, err, authstate.ErrKeyMismatch)
	_, err = p.Exec(ctx, "UPDATE auth_sessions SET payload=substring(payload FROM 2)")
	require.NoError(t, err)
	_, err = newOnly.Get(ctx, token("new-key"))
	require.ErrorContains(t, err, "could not be decrypted")
}
func TestPostgresSessionsCredentialRevocationRacesIssue(t *testing.T) {
	_, a, b := fixture(t)
	ctx := context.Background()
	gate := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-gate
		err := a.Issue(ctx, token("raced-proof"), params())
		if err != nil {
			assert.ErrorIs(t, err, authstate.ErrStaleGeneration)
		}
	}()
	go func() { defer wg.Done(); <-gate; _, err := core.RevokeAuth("alice", nil); assert.NoError(t, err) }()
	close(gate)
	wg.Wait()
	_, err := b.Get(ctx, token("raced-proof"))
	require.ErrorIs(t, err, authstate.ErrNotFound)
}

func TestPostgresSessionsPayloadIsBoundToItsToken(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	require.NoError(t, a.Issue(ctx, token("first-row"), params()))
	var hash, body []byte
	require.NoError(t, p.QueryRow(ctx, "SELECT token_hash,payload FROM auth_sessions").Scan(&hash, &body))
	require.NoError(t, b.Issue(ctx, token("second-row"), params()))
	_, err := p.Exec(ctx, "UPDATE auth_sessions SET payload=$2 WHERE token_hash<>$1", hash, body)
	require.NoError(t, err)
	_, err = a.Get(ctx, token("second-row"))
	require.ErrorContains(t, err, "could not be decrypted")
	_, err = b.Get(ctx, token("first-row"))
	require.NoError(t, err)
}
func TestAuthStateRejectsInvalidKeyrings(t *testing.T) {
	cases := []struct {
		index, active string
		keys          map[string]string
	}{
		{"short", "v1", map[string]string{"v1": encryptionSecret}},
		{indexSecret, "missing", map[string]string{"v1": encryptionSecret}},
		{indexSecret, "../key", map[string]string{"../key": encryptionSecret}},
		{indexSecret, "v1", map[string]string{"v1": "short"}},
		{indexSecret, "v1", map[string]string{"v1": encryptionSecret, "v2": encryptionSecret, "v3": encryptionSecret, "v4": encryptionSecret}},
	}
	for _, c := range cases {
		_, err := authstate.NewKeyring(c.index, c.active, c.keys)
		require.Error(t, err)
	}
}

func TestPostgresSessionsBusyDoesNotMeanExpired(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	old, next := token("old-busy"), token("live-busy")
	require.NoError(t, a.Issue(ctx, old, params()))
	changed, err := a.Rotate(ctx, old, next, time.Hour, 30*time.Second)
	require.NoError(t, err)
	require.True(t, changed)
	session, err := b.Get(ctx, next)
	require.NoError(t, err)
	tx, err := p.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "SELECT id FROM auth_session_families WHERE id=$1 FOR UPDATE", session.FamilyID)
	require.NoError(t, err)
	// Retired tokens return without trying to acquire the held family lock.
	changed, err = b.Rotate(ctx, old, token("retired-no-fork"), time.Hour, 30*time.Second)
	require.NoError(t, err)
	assert.False(t, changed)
	changed, err = b.Rotate(ctx, next, token("busy-next"), time.Hour, 30*time.Second)
	require.ErrorIs(t, err, authstate.ErrBusy)
	assert.False(t, changed)
	changed, err = b.Replace(ctx, next, token("busy-replacement"))
	require.ErrorIs(t, err, authstate.ErrBusy)
	assert.False(t, changed)
	_, err = b.Get(ctx, next)
	require.NoError(t, err, "a busy mutation must not invalidate an active token")
	require.NoError(t, tx.Rollback(ctx))
	changed, err = b.Rotate(ctx, next, token("retry-next"), time.Hour, 30*time.Second)
	require.NoError(t, err)
	assert.True(t, changed)
}
func TestPostgresSessionsCleanupDrainsBacklogInBatches(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	live := token("keep-live")
	require.NoError(t, a.Issue(ctx, live, params()))
	var expired, active string
	require.NoError(t, p.QueryRow(ctx, "INSERT INTO auth_session_families(id,username,auth_gen,absolute_expires_at) VALUES(gen_random_uuid(),'alice',0,clock_timestamp()-interval '1 hour') RETURNING id::text").Scan(&expired))
	require.NoError(t, p.QueryRow(ctx, "INSERT INTO auth_session_families(id,username,auth_gen,absolute_expires_at) VALUES(gen_random_uuid(),'alice',0,clock_timestamp()+interval '1 hour') RETURNING id::text").Scan(&active))
	// More than one batch in each category; absolute-expired families may still
	// have children whose idle deadline is in the future (e.g. an older writer).
	_, err := p.Exec(ctx, `INSERT INTO auth_sessions(token_hash,family_id,key_id,payload,issued_at,idle_expires_at,last_refreshed_at)
 SELECT decode(lpad(to_hex(n),64,'0'),'hex'),$1,'v1',decode('00','hex'),clock_timestamp()-interval '2 hours',clock_timestamp()+interval '1 hour',clock_timestamp()-interval '2 hours'
 FROM generate_series(1,1205) n`, expired)
	require.NoError(t, err)
	_, err = p.Exec(ctx, `INSERT INTO auth_sessions(token_hash,family_id,key_id,payload,issued_at,idle_expires_at,last_refreshed_at)
 SELECT decode(lpad(to_hex(n),64,'0'),'hex'),$1,'v1',decode('00','hex'),clock_timestamp()-interval '2 hours',clock_timestamp()-interval '1 hour',clock_timestamp()-interval '2 hours'
 FROM generate_series(2001,3305) n`, active)
	require.NoError(t, err)
	require.NoError(t, a.Cleanup(ctx))
	var count int
	require.NoError(t, p.QueryRow(ctx, "SELECT count(*) FROM auth_sessions").Scan(&count))
	assert.Equal(t, 1, count)
	require.NoError(t, p.QueryRow(ctx, "SELECT count(*) FROM auth_session_families WHERE id=$1", expired).Scan(&count))
	assert.Zero(t, count)
	_, err = b.Get(ctx, live)
	require.NoError(t, err)
	require.NoError(t, a.Cleanup(ctx), "cleanup is idempotent")
}
