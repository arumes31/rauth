package eventstore

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"rauth/internal/requestevent"
	"sync"
	"testing"
	"time"
)

func TestCollectorOrphanLockExpiresAndFencesStaleWriter(t *testing.T) {
	pool := setup(t)
	o := options()
	old := open(t, pool, o)
	pid := old.lock.Conn().PgConn().PID()
	node := uuid.NewString()
	prior := decision(node)
	_, err := old.Ingest(background, node, []requestevent.Event{prior})
	require.NoError(t, err)
	// Do not touch the reserved session: emulate an abandoned network hop while
	// the server-side connection remains alive. Other SQL sessions remain usable.
	require.Eventually(t, func() bool {
		var exists bool
		err := pool.QueryRow(background, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)", pid).Scan(&exists)
		return err == nil && !exists
	}, 35*time.Second, 250*time.Millisecond, "server must release an orphaned collector lock without a client reconnect or operator termination")
	next := open(t, pool, o)
	require.Equal(t, old.Epoch(), next.Epoch())
	_, err = old.Status(background)
	require.ErrorIs(t, err, ErrUnavailable)
	stale := decision(node)
	ack, err := old.Ingest(background, node, []requestevent.Event{stale})
	require.ErrorIs(t, err, ErrUnavailable)
	require.Nil(t, ack, "a stale owner must never acknowledge a new event")
	ack, err = next.Ingest(background, node, []requestevent.Event{prior})
	require.NoError(t, err)
	require.Equal(t, []string{prior.EventID}, ack)
	live := decision(node)
	_, err = next.Ingest(background, node, []requestevent.Event{live})
	require.NoError(t, err)
	batch, err := next.After(background, 0, "")
	require.NoError(t, err)
	require.Len(t, batch.Events, 2, "takeover must preserve committed data and deduplicate replay")
}

func TestCollectorStatusHeartbeatsKeepLockAlive(t *testing.T) {
	pool := setup(t)
	o := options()
	s := open(t, pool, o)
	pid := s.lock.Conn().PgConn().PID()
	// Observe beyond the production lease, not a shortened test-only timeout.
	deadline := time.Now().Add(32 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(background, 3*time.Second)
		_, err := s.Status(ctx)
		cancel()
		require.NoError(t, err)
		time.Sleep(2 * time.Second)
	}
	require.Equal(t, pid, s.lock.Conn().PgConn().PID())
	ctx, cancel := context.WithTimeout(background, 3*time.Second)
	defer cancel()
	other, err := Open(ctx, pool, o)
	if other != nil {
		_ = other.Close()
	}
	require.ErrorIs(t, err, ErrUnavailable, "heartbeat must retain exclusive ownership beyond its idle lease")
	_, err = s.Status(background)
	require.NoError(t, err)
}

func TestCollectorCloseDiscardsReservedLockSession(t *testing.T) {
	pool := setup(t)
	o := options()
	for i := 0; i < 4; i++ {
		s := open(t, pool, o)
		pid := s.lock.Conn().PgConn().PID()
		require.NoError(t, s.Close())
		require.Eventually(t, func() bool {
			var exists bool
			err := pool.QueryRow(background, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)", pid).Scan(&exists)
			return err == nil && !exists
		}, 2*time.Second, 10*time.Millisecond, "reserved lock sessions must be destroyed rather than returned to the shared pool")
		_, err := s.Status(background)
		require.ErrorIs(t, err, ErrUnavailable)
	}
}

func TestCollectorStatusAndCloseSerializeReservedConnection(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			ctx, cancel := context.WithTimeout(background, 3*time.Second)
			defer cancel()
			_, err := s.Status(ctx)
			if err != nil {
				assert.ErrorIs(t, err, ErrUnavailable)
			}
		}()
	}
	require.NoError(t, s.Close())
	group.Wait()
}

func TestCollectorLockQueryHasServerDeadline(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	pid := s.lock.Conn().PgConn().PID()
	// Leave the client deadline longer: cancellation must come from PostgreSQL,
	// even when a disconnected caller could not deliver its own cancel request.
	ctx, cancel := context.WithTimeout(background, 9*time.Second)
	defer cancel()
	_, err := s.lock.Exec(ctx, "SELECT pg_sleep(20)")
	var server *pgconn.PgError
	require.ErrorAs(t, err, &server, "the server must bound active work on its lock session")
	require.Equal(t, "57014", server.Code)
	require.NoError(t, ctx.Err(), "the server must cancel before the client deadline")
	require.Equal(t, pid, s.lock.Conn().PgConn().PID())
	_, err = s.Status(background)
	require.NoError(t, err, "a timed-out statement must not destroy healthy ownership")
}
