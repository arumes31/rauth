package authstate_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"rauth/internal/authstate"
	"rauth/internal/core"
)

func TestArtifactsCrossNodeSingleUseAndRevocation(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	id := token("pending-shared")
	require.NoError(t, a.Artifacts().Put(ctx, authstate.Pending2FA, id, authstate.Artifact{Data: []byte("alice:0"), Username: "alice"}, 5*time.Minute))
	got, err := b.Artifacts().Get(ctx, authstate.Pending2FA, id)
	require.NoError(t, err)
	assert.Equal(t, "alice:0", string(got.Data))
	_, err = b.Artifacts().Get(ctx, authstate.PasskeyLogin, id)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	var body []byte
	require.NoError(t, p.QueryRow(ctx, "SELECT payload FROM auth_artifacts").Scan(&body))
	assert.NotContains(t, string(body), "alice:0")
	gate := make(chan struct{})
	var wg sync.WaitGroup
	var wins atomic.Int32
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-gate
			s := a.Artifacts()
			if i%2 == 0 {
				s = b.Artifacts()
			}
			_, err := s.Take(ctx, authstate.Pending2FA, id)
			if err == nil {
				wins.Add(1)
			} else {
				assert.ErrorIs(t, err, authstate.ErrNotFound)
			}
		}(i)
	}
	close(gate)
	wg.Wait()
	assert.Equal(t, int32(1), wins.Load())
	require.ErrorIs(t, a.Artifacts().Put(ctx, authstate.Pending2FA, id, authstate.Artifact{Data: []byte("alice:0"), Username: "alice"}, time.Minute), authstate.ErrConflict, "a consumed proof cannot be restored")
	stale := token("stale-proof")
	require.NoError(t, a.Artifacts().Put(ctx, authstate.Pending2FA, stale, authstate.Artifact{Data: []byte("alice:0"), Username: "alice"}, time.Minute))
	_, err = core.RevokeAuth("alice", nil)
	require.NoError(t, err)
	_, err = b.Artifacts().Get(ctx, authstate.Pending2FA, stale)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	_, err = b.Artifacts().Take(ctx, authstate.Pending2FA, stale)
	require.ErrorIs(t, err, authstate.ErrStaleGeneration)
}
func TestArtifactsConsumeCallbackIsAtomic(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	id := token("invite-callback")
	require.NoError(t, a.Artifacts().Put(ctx, authstate.Invitation, id, authstate.Artifact{Data: []byte("new@example.com")}, 24*time.Hour))
	aborted := errors.New("callback aborted")
	_, err := b.Artifacts().Consume(ctx, authstate.Invitation, id, func(ctx context.Context, tx pgx.Tx, value authstate.Artifact) error {
		_, err := tx.Exec(ctx, "INSERT INTO users(username,email) VALUES('new-account',$1)", string(value.Data))
		if err != nil {
			return err
		}
		return aborted
	})
	require.ErrorIs(t, err, aborted)
	var count int
	require.NoError(t, p.QueryRow(ctx, "SELECT count(*) FROM users WHERE username='new-account'").Scan(&count))
	assert.Zero(t, count)
	_, err = a.Artifacts().Get(ctx, authstate.Invitation, id)
	require.NoError(t, err)
	_, err = b.Artifacts().Consume(ctx, authstate.Invitation, id, func(ctx context.Context, tx pgx.Tx, value authstate.Artifact) error {
		_, err := tx.Exec(ctx, "INSERT INTO users(username,email) VALUES('new-account',$1)", string(value.Data))
		return err
	})
	require.NoError(t, err)
	_, err = a.Artifacts().Take(ctx, authstate.Invitation, id)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	require.NoError(t, p.QueryRow(ctx, "SELECT count(*) FROM users WHERE username='new-account'").Scan(&count))
	assert.Equal(t, 1, count)
}
func TestArtifactsSecretExpiryAndEncryptionKeyRetention(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	id := token("stable-enrollment")
	value := authstate.Artifact{Data: []byte("original-secret"), Username: "alice"}
	require.NoError(t, a.Artifacts().Put(ctx, authstate.EnrollmentSecret, id, value, time.Minute))
	value.Data = []byte("different-secret")
	require.ErrorIs(t, b.Artifacts().Put(ctx, authstate.EnrollmentSecret, id, value, time.Minute), authstate.ErrConflict)
	got, err := b.Artifacts().Get(ctx, authstate.EnrollmentSecret, id)
	require.NoError(t, err)
	assert.Equal(t, "original-secret", string(got.Data))
	_, err = p.Exec(ctx, "UPDATE auth_artifacts SET expires_at=clock_timestamp()-interval '1 second'")
	require.NoError(t, err)
	_, err = a.Artifacts().Get(ctx, authstate.EnrollmentSecret, id)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	require.NoError(t, b.Artifacts().Put(ctx, authstate.EnrollmentSecret, id, value, time.Minute))
	got, err = a.Artifacts().Get(ctx, authstate.EnrollmentSecret, id)
	require.NoError(t, err)
	assert.Equal(t, "different-secret", string(got.Data))
	_, err = authstate.NewPostgresSessions(ctx, p, keyring(t, "v2", map[string]string{"v2": strings.Repeat("b", 32)}))
	require.ErrorContains(t, err, "encryption key is missing", "live challenge keys cannot be retired just because no sessions exist")
	require.NoError(t, a.Artifacts().Put(ctx, authstate.PasskeyLogin, id, authstate.Artifact{Data: []byte("login-json")}, time.Minute))
	_, err = p.Exec(ctx, "UPDATE auth_artifacts SET payload=(SELECT payload FROM auth_artifacts WHERE kind='pending_setup_secret') WHERE kind='webauthn_login_session'")
	require.NoError(t, err)
	_, err = b.Artifacts().Get(ctx, authstate.PasskeyLogin, id)
	require.Error(t, err, "ciphertext cannot move between challenge purposes")
}
func TestSQLCountersAreGlobalFixedWindowAndReplaySafe(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	first, err := a.Counters().Increment(ctx, "login:user", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(1), first)
	var before time.Time
	require.NoError(t, p.QueryRow(ctx, "SELECT expires_at FROM auth_security_counters").Scan(&before))
	n, err := b.Counters().Increment(ctx, "login:user", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)
	var after time.Time
	require.NoError(t, p.QueryRow(ctx, "SELECT expires_at FROM auth_security_counters").Scan(&after))
	assert.True(t, before.Equal(after), "attempts do not slide the original window")
	_, err = p.Exec(ctx, "UPDATE auth_security_counters SET expires_at=clock_timestamp()-interval '1 second'")
	require.NoError(t, err)
	n, err = a.Counters().Increment(ctx, "login:user", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-gate
			s := a.Counters()
			if i%2 == 0 {
				s = b.Counters()
			}
			_, err := s.Increment(ctx, "parallel", time.Minute)
			assert.NoError(t, err)
		}(i)
	}
	close(gate)
	wg.Wait()
	n, err = b.Counters().Count(ctx, "parallel")
	require.NoError(t, err)
	assert.Equal(t, int64(6), n)
	used, err := a.Counters().MarkTOTP(ctx, "alice", " 123456 ", 90*time.Second)
	require.NoError(t, err)
	assert.True(t, used)
	used, err = b.Counters().MarkTOTP(ctx, "alice", "123456", 90*time.Second)
	require.NoError(t, err)
	assert.False(t, used)
	_, err = p.Exec(ctx, "UPDATE auth_replay_markers SET expires_at=clock_timestamp()-interval '1 second'")
	require.NoError(t, err)
	used, err = b.Counters().MarkTOTP(ctx, "alice", "123456", 90*time.Second)
	require.NoError(t, err)
	assert.True(t, used)
	require.NoError(t, a.Counters().Reset(ctx, "parallel"))
	n, err = b.Counters().Count(ctx, "parallel")
	require.NoError(t, err)
	assert.Zero(t, n)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = a.Counters().MarkTOTP(canceled, "alice", "654321", time.Minute)
	require.Error(t, err)
}

func TestArtifactsConsumeCallbackCancellationRollsBack(t *testing.T) {
	_, a, b := fixture(t)
	parent := context.Background()
	id := token("callback-cancellation")
	require.NoError(t, a.Artifacts().Put(parent, authstate.Invitation, id, authstate.Artifact{Data: []byte("invite@example.com")}, time.Hour))
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	start := time.Now()
	_, err := b.Artifacts().Consume(ctx, authstate.Invitation, id, func(ctx context.Context, tx pgx.Tx, _ authstate.Artifact) error {
		deadline, ok := ctx.Deadline()
		require.True(t, ok, "all callback statements must share the transaction deadline")
		require.LessOrEqual(t, time.Until(deadline), 10*time.Second)
		timer := time.AfterFunc(100*time.Millisecond, cancel)
		defer timer.Stop()
		_, err := tx.Exec(ctx, "SELECT pg_sleep(30)")
		return err
	})
	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 5*time.Second, "cancelled callback must release its locks promptly")
	_, err = a.Artifacts().Take(parent, authstate.Invitation, id)
	require.NoError(t, err, "cancelled callback must roll back the one-use claim")
}
