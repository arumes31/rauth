package authstate_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"rauth/internal/authstate"
	"rauth/internal/core"
)

func TestPostgresValidationBatchRefreshBoundsAndCounterScope(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	raw := token("validation-batch-live")
	require.NoError(t, a.Issue(ctx, raw, params()))
	original, err := b.Get(ctx, raw)
	require.NoError(t, err)
	_, err = p.Exec(ctx, "UPDATE auth_sessions SET last_refreshed_at=clock_timestamp()-interval '40 seconds',idle_expires_at=clock_timestamp()+interval '1 minute'")
	require.NoError(t, err)
	const key = "rate_limit:validate:203.0.113.42"
	_, err = a.Counters().Increment(ctx, key, time.Minute)
	require.NoError(t, err)
	changed, err := a.RefreshValidation(ctx, a.Counters(), raw, 2*time.Hour, key)
	require.NoError(t, err)
	require.True(t, changed)
	count, err := b.Counters().Count(ctx, key)
	require.NoError(t, err)
	require.Zero(t, count)
	next, err := b.Get(ctx, raw)
	require.NoError(t, err)
	require.True(t, next.AbsoluteExpiresAt.Equal(original.AbsoluteExpiresAt))
	require.True(t, next.IdleExpiresAt.Equal(next.AbsoluteExpiresAt), "refresh cannot extend absolute lifetime")
	var refreshed, after time.Time
	require.NoError(t, p.QueryRow(ctx, "SELECT last_refreshed_at FROM auth_sessions").Scan(&refreshed))
	changed, err = a.RefreshValidation(ctx, a.Counters(), raw, 2*time.Hour, key)
	require.NoError(t, err)
	require.False(t, changed)
	require.NoError(t, p.QueryRow(ctx, "SELECT last_refreshed_at FROM auth_sessions").Scan(&after))
	require.True(t, refreshed.Equal(after), "the same refresh write bound applies to the batch")

	const login = "rate_limit:login:alice"
	_, err = a.Counters().Increment(ctx, login, time.Minute)
	require.NoError(t, err)
	changed, err = a.RefreshValidation(ctx, a.Counters(), raw, time.Minute, login)
	require.Error(t, err)
	require.False(t, changed)
	count, err = b.Counters().Count(ctx, login)
	require.NoError(t, err)
	require.Equal(t, int64(1), count, "bookkeeping cannot clear login or 2FA throttles")
	_, err = a.Counters().Increment(ctx, key, time.Minute)
	require.NoError(t, err)
	for _, call := range []func() (bool, error){
		func() (bool, error) { return a.RefreshValidation(ctx, b.Counters(), raw, time.Minute, key) },
		func() (bool, error) { return a.RefreshValidation(ctx, nil, raw, time.Minute, key) },
		func() (bool, error) { return a.RefreshValidation(ctx, a.Counters(), raw, 0, key) },
		func() (bool, error) { return a.RefreshValidation(ctx, a.Counters(), "short", time.Minute, key) },
	} {
		changed, err = call()
		require.Error(t, err)
		require.False(t, changed)
		count, err = b.Counters().Count(ctx, key)
		require.NoError(t, err)
		require.Equal(t, int64(1), count, "invalid calls must not partly clear a counter")
	}
}

func TestPostgresValidationBatchCannotReviveInvalidSessions(t *testing.T) {
	for _, kind := range []string{"revoked", "generation", "expired", "retired", "deleted-user"} {
		t.Run(kind, func(t *testing.T) {
			p, a, b := fixture(t)
			ctx := context.Background()
			raw := token("validation-batch-" + kind)
			require.NoError(t, a.Issue(ctx, raw, params()))
			var retiredExpiry time.Time
			switch kind {
			case "revoked":
				require.NoError(t, b.Revoke(ctx, raw))
			case "generation":
				_, err := core.BumpAuthGeneration("alice")
				require.NoError(t, err)
			case "expired":
				_, err := p.Exec(ctx, "UPDATE auth_sessions SET idle_expires_at=clock_timestamp()-interval '1 second'")
				require.NoError(t, err)
			case "deleted-user":
				_, err := p.Exec(ctx, "DELETE FROM users WHERE username='alice'")
				require.NoError(t, err)
			case "retired":
				changed, err := b.Rotate(ctx, raw, token("validation-successor"), time.Minute, 30*time.Second)
				require.NoError(t, err)
				require.True(t, changed)
				value, err := b.Get(ctx, raw)
				require.NoError(t, err)
				retiredExpiry = value.IdleExpiresAt
			}
			changed, err := a.RefreshValidation(ctx, a.Counters(), raw, time.Hour, "rate_limit:validate:203.0.113.42")
			require.NoError(t, err)
			require.False(t, changed)
			value, err := b.Get(ctx, raw)
			if kind == "retired" {
				require.NoError(t, err)
				require.NotEmpty(t, value.Successor)
				require.True(t, retiredExpiry.Equal(value.IdleExpiresAt))
			} else {
				require.ErrorIs(t, err, authstate.ErrNotFound)
			}
		})
	}
}

func TestPostgresValidationBatchReportsDeferredCommitFailureAndRollsBack(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	raw := token("validation-batch-deferred-error")
	require.NoError(t, a.Issue(ctx, raw, params()))
	_, err := p.Exec(ctx, "UPDATE auth_sessions SET last_refreshed_at=clock_timestamp()-interval '40 seconds'")
	require.NoError(t, err)
	var before, after time.Time
	require.NoError(t, p.QueryRow(ctx, "SELECT last_refreshed_at FROM auth_sessions").Scan(&before))
	const key = "rate_limit:validate:203.0.113.42"
	_, err = a.Counters().Increment(ctx, key, time.Minute)
	require.NoError(t, err)
	_, err = p.Exec(ctx, `CREATE FUNCTION reject_validation_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic deferred validation rejection'; RETURN NEW; END $$;
CREATE CONSTRAINT TRIGGER reject_validation_refresh AFTER UPDATE ON auth_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_validation_refresh()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := p.Exec(ctx, "DROP FUNCTION reject_validation_refresh() CASCADE")
		require.NoError(t, err)
	})
	changed, err := a.RefreshValidation(ctx, a.Counters(), raw, time.Hour, key)
	require.Error(t, err, "a late implicit-transaction commit error must be observed while closing the batch")
	require.False(t, changed)
	count, err := b.Counters().Count(ctx, key)
	require.NoError(t, err)
	require.Equal(t, int64(1), count, "counter deletion must roll back with failed refresh")
	require.NoError(t, p.QueryRow(ctx, "SELECT last_refreshed_at FROM auth_sessions").Scan(&after))
	require.True(t, before.Equal(after))
	_, err = b.Get(ctx, raw)
	require.NoError(t, err, "batch failure must leave the original live session usable")
}
