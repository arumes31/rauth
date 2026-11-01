package authstate_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"rauth/internal/authstate"
	"rauth/internal/core"
)

func TestSessionManagementQueriesAndOwnership(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	_, err := p.Exec(ctx, "INSERT INTO users(username) VALUES('bob')")
	require.NoError(t, err)
	for _, name := range []string{"alice-0", "alice-1", "alice-2", "bob"} {
		value := params()
		value.Fields["token"] = "must-not-be-exposed"
		value.Fields["rotated_to"] = "also-private"
		if name == "bob" {
			value.Username = "bob"
			value.IP = "203.0.113.99"
		}
		require.NoError(t, a.Issue(ctx, token(name), value))
	}
	first, err := b.List(ctx, "alice", "", 2)
	require.NoError(t, err)
	require.Len(t, first.Sessions, 2)
	require.NotEmpty(t, first.Next)
	second, err := a.List(ctx, "alice", first.Next, 2)
	require.NoError(t, err)
	require.Len(t, second.Sessions, 1)
	assert.Empty(t, second.Next)
	seen := map[string]bool{}
	for _, entry := range append(first.Sessions, second.Sessions...) {
		assert.Equal(t, "alice", entry.Username)
		assert.NotEmpty(t, entry.Handle)
		assert.False(t, seen[entry.Handle])
		seen[entry.Handle] = true
		assert.NotContains(t, entry.Fields, "token")
		assert.NotContains(t, entry.Fields, "rotated_to")
	}
	count, err := a.ActiveCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(4), count)
	active, err := b.HasActiveForIP(ctx, "::ffff:203.0.113.42")
	require.NoError(t, err)
	assert.True(t, active)
	all, err := a.List(ctx, "", "", 200)
	require.NoError(t, err)
	require.Len(t, all.Sessions, 4)
	bob, err := a.Get(ctx, token("bob"))
	require.NoError(t, err)
	changed, err := a.RevokeFamily(ctx, bob.FamilyID, "alice")
	require.NoError(t, err)
	assert.False(t, changed)
	_, err = a.Get(ctx, token("bob"))
	require.NoError(t, err, "another account cannot revoke this family")
	require.ErrorIs(t, b.RevokeOthers(ctx, "alice", token("bob")), authstate.ErrNotFound)
	require.NoError(t, b.RevokeOthers(ctx, "alice", token("alice-0")))
	mine, err := a.Get(ctx, token("alice-0"))
	require.NoError(t, err)
	for _, name := range []string{"alice-1", "alice-2"} {
		_, err = a.Get(ctx, token(name))
		require.ErrorIs(t, err, authstate.ErrNotFound)
	}
	count, err = a.ActiveCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
	changed, err = b.RevokeFamily(ctx, mine.FamilyID, "alice")
	require.NoError(t, err)
	assert.True(t, changed)
	active, err = a.HasActiveForIP(ctx, params().IP)
	require.NoError(t, err)
	assert.False(t, active)
	_, err = core.RevokeAuth("bob", nil)
	require.NoError(t, err)
	active, err = b.HasActiveForIP(ctx, "203.0.113.99")
	require.NoError(t, err)
	assert.False(t, active, "generation revocation invalidates IP shortcuts too")
	all, err = a.List(ctx, "", "", 200)
	require.NoError(t, err)
	assert.Empty(t, all.Sessions)
	_, err = a.List(ctx, "alice", "invalid-cursor", 2)
	require.Error(t, err)
}

func TestSessionCountryUpdatePreservesExpiryAndCannotRevive(t *testing.T) {
	_, a, b := fixture(t)
	ctx := context.Background()
	old, next := token("country-old"), token("country-next")
	require.NoError(t, a.Issue(ctx, old, params()))
	before, err := a.Get(ctx, old)
	require.NoError(t, err)
	changed, err := b.UpdateCountry(ctx, old, "AT")
	require.NoError(t, err)
	require.True(t, changed)
	after, err := a.Get(ctx, old)
	require.NoError(t, err)
	assert.Equal(t, "AT", after.Fields["country"])
	assert.True(t, before.IdleExpiresAt.Equal(after.IdleExpiresAt))
	changed, err = b.Rotate(ctx, old, next, time.Minute, 30*time.Second)
	require.NoError(t, err)
	require.True(t, changed)
	changed, err = a.UpdateCountry(ctx, old, "DE")
	require.NoError(t, err)
	assert.False(t, changed)
	require.NoError(t, a.Revoke(ctx, old))
	changed, err = b.UpdateCountry(ctx, next, "DE")
	require.NoError(t, err)
	assert.False(t, changed)
	_, err = a.Get(ctx, next)
	require.ErrorIs(t, err, authstate.ErrNotFound)
}

func TestStepUpGrantAtomicReplacementAndRotation(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	_, err := p.Exec(ctx, "UPDATE users SET is_admin=true WHERE username='alice'")
	require.NoError(t, err)
	old, next, rotated := token("step-old"), token("step-next"), token("step-rotated")
	value := params()
	value.IdleTTL = time.Minute
	value.AbsoluteTTL = 90 * time.Second
	require.NoError(t, a.Issue(ctx, old, value))
	grant := authstate.PublicAccessGrant{Username: "alice", Generation: 0, TTL: 15 * time.Minute}
	bad := grant
	bad.Generation = 1
	changed, err := b.ReplaceWithGrant(ctx, old, next, bad)
	require.ErrorIs(t, err, authstate.ErrStaleGeneration)
	assert.False(t, changed)
	_, err = a.Get(ctx, old)
	require.NoError(t, err)
	changed, err = b.ReplaceWithGrant(ctx, old, next, grant)
	require.NoError(t, err)
	require.True(t, changed)
	_, err = a.Get(ctx, old)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	remaining, err := a.GrantRemaining(ctx, next, "alice")
	require.NoError(t, err)
	assert.Positive(t, remaining)
	assert.LessOrEqual(t, remaining, time.Minute)
	oldRemaining, err := b.GrantRemaining(ctx, old, "alice")
	require.NoError(t, err)
	assert.Zero(t, oldRemaining)
	other, err := b.GrantRemaining(ctx, next, "bob")
	require.NoError(t, err)
	assert.Zero(t, other)
	var deadline time.Time
	require.NoError(t, p.QueryRow(ctx, "SELECT expires_at FROM auth_step_up_grants").Scan(&deadline))
	changed, err = a.Rotate(ctx, next, rotated, time.Minute, 30*time.Second)
	require.NoError(t, err)
	require.True(t, changed)
	oldRemaining, err = b.GrantRemaining(ctx, next, "alice")
	require.NoError(t, err)
	assert.Zero(t, oldRemaining, "retired token cannot authorize admin mutations")
	remaining, err = b.GrantRemaining(ctx, rotated, "alice")
	require.NoError(t, err)
	assert.Positive(t, remaining)
	var sameDeadline bool
	require.NoError(t, p.QueryRow(ctx, "SELECT bool_and(expires_at=$1) FROM auth_step_up_grants", deadline).Scan(&sameDeadline))
	assert.True(t, sameDeadline, "rotation must not extend the step-up window")
	// The token deleted by step-up still reaches the family for a racing logout.
	require.NoError(t, b.Revoke(ctx, old))
	_, err = a.Get(ctx, rotated)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	remaining, err = a.GrantRemaining(ctx, rotated, "alice")
	require.NoError(t, err)
	assert.Zero(t, remaining)
}

func TestStepUpGrantFailureRollbackLockAndGeneration(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	old, next := token("grant-fail-old"), token("grant-fail-next")
	require.NoError(t, a.Issue(ctx, old, params()))
	grant := authstate.PublicAccessGrant{Username: "alice", TTL: time.Minute}
	changed, err := b.ReplaceWithGrant(ctx, old, next, grant)
	require.Error(t, err, "non-admin cannot obtain this grant")
	assert.False(t, changed)
	_, err = a.Get(ctx, old)
	require.NoError(t, err, "failed grant must roll back replacement")
	_, err = a.Get(ctx, next)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	_, err = p.Exec(ctx, "UPDATE users SET is_admin=true WHERE username='alice'")
	require.NoError(t, err)
	require.NoError(t, b.Issue(ctx, next, params()))
	changed, err = a.ReplaceWithGrant(ctx, old, next, grant)
	require.ErrorIs(t, err, authstate.ErrConflict)
	assert.False(t, changed)
	_, err = b.Get(ctx, old)
	require.NoError(t, err)
	final := token("grant-fail-final")
	changed, err = a.ReplaceWithGrant(ctx, old, final, grant)
	require.NoError(t, err)
	require.True(t, changed)
	require.NoError(t, b.LockGrant(ctx, final))
	remaining, err := a.GrantRemaining(ctx, final, "alice")
	require.NoError(t, err)
	assert.Zero(t, remaining)
	fresh := token("grant-new-final")
	changed, err = b.ReplaceWithGrant(ctx, final, fresh, grant)
	require.NoError(t, err)
	require.True(t, changed)
	_, err = core.RevokeAuth("alice", nil)
	require.NoError(t, err)
	remaining, err = a.GrantRemaining(ctx, fresh, "alice")
	require.NoError(t, err)
	assert.Zero(t, remaining, "credential reset revokes a grant without waiting for expiry")
}

func TestSessionRevocationSurvivesGraceCleanupAndReplacementRace(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	old, next := token("alias-old"), token("alias-next")
	require.NoError(t, a.Issue(ctx, old, params()))
	changed, err := b.Rotate(ctx, old, next, time.Minute, time.Second)
	require.NoError(t, err)
	require.True(t, changed)
	_, err = p.Exec(ctx, "UPDATE auth_sessions SET idle_expires_at=clock_timestamp()-interval '1 second' WHERE retired")
	require.NoError(t, err)
	require.NoError(t, a.Cleanup(ctx))
	require.NoError(t, b.Revoke(ctx, old))
	_, err = a.Get(ctx, next)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	for i := 0; i < 3; i++ {
		previous := token("race-old" + string(rune('a'+i)))
		successor := token("race-new" + string(rune('a'+i)))
		require.NoError(t, a.Issue(ctx, previous, params()))
		gate := make(chan struct{})
		results := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-gate
			_, err := a.Replace(ctx, previous, successor)
			if errors.Is(err, authstate.ErrBusy) {
				err = nil
			}
			results <- err
		}()
		go func() { defer wg.Done(); <-gate; results <- b.Revoke(ctx, previous) }()
		close(gate)
		wg.Wait()
		close(results)
		for err := range results {
			require.NoError(t, err)
		}
		_, err = a.Get(ctx, successor)
		require.ErrorIs(t, err, authstate.ErrNotFound, "logout must win regardless of replacement ordering")
	}
}

func TestSessionIPIndexDoesNotStrandUnparseableMetadata(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	for i, ip := range []string{"", "unknown", "192.0.2.1:4444", "[2001:db8::1]", "fe80::1%eth0"} {
		value := params()
		value.IP = ip
		old, next, final := token("unknown-ip-old"+string(rune('a'+i))), token("unknown-ip-next"+string(rune('a'+i))), token("unknown-ip-final"+string(rune('a'+i)))
		require.NoError(t, a.Issue(ctx, old, value))
		changed, err := b.Rotate(ctx, old, next, time.Minute, 30*time.Second)
		require.NoError(t, err)
		require.True(t, changed)
		changed, err = a.Replace(ctx, next, final)
		require.NoError(t, err)
		require.True(t, changed)
		session, err := b.Get(ctx, final)
		require.NoError(t, err)
		assert.Equal(t, ip, session.IP)
		active, err := b.HasActiveForIP(ctx, ip)
		require.Error(t, err)
		assert.False(t, active, "unparseable addresses must never gain a shared IP shortcut")
	}
	var indexed int
	require.NoError(t, p.QueryRow(ctx, "SELECT count(*) FROM auth_sessions WHERE ip_hash IS NOT NULL").Scan(&indexed))
	assert.Zero(t, indexed)
}
