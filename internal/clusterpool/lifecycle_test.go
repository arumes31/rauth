package clusterpool

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"net"
	"net/url"
	"rauth/internal/core"
	"rauth/internal/pgtest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type lifecycleWANConn struct {
	net.Conn
	enabled *atomic.Bool
}

func (c *lifecycleWANConn) Write(p []byte) (int, error) {
	if c.enabled.Load() {
		time.Sleep(400 * time.Millisecond)
	}
	return c.Conn.Write(p)
}
func lifecycleConfig(t *testing.T, enabled *atomic.Bool) *pgxpool.Config {
	t.Helper()
	fixture := pgtest.Open(t, core.Migrate)
	cfg := fixture.Config()
	u, err := url.Parse(cfg.ConnConfig.ConnString())
	require.NoError(t, err)
	q := u.Query()
	q.Set("target_session_attrs", "read-write")
	u.RawQuery = q.Encode()
	selected, err := pgxpool.ParseConfig(u.String())
	require.NoError(t, err)
	cfg.ConnConfig.ValidateConnect = selected.ConnConfig.ValidateConnect
	dial := cfg.ConnConfig.DialFunc
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &lifecycleWANConn{c, enabled}, nil
	}
	return cfg
}
func TestFirstUseRetainsSameSocketThroughQueuedLateAndCanceledCallers(t *testing.T) {
	enabled := &atomic.Bool{}
	defer enabled.Store(false)
	cfg := lifecycleConfig(t, enabled)
	made := make(chan *pgx.Conn, 1)
	cfg.AfterConnect = func(_ context.Context, c *pgx.Conn) error { made <- c; return nil }
	entered, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	var checks atomic.Int32
	cfg.PrepareConn = func(context.Context, *pgx.Conn) (bool, error) {
		checks.Add(1)
		first.Do(func() { close(entered); <-release })
		return true, nil
	}
	require.NoError(t, Configure(cfg, 1, true))
	parent, cancel := context.WithCancel(t.Context())
	pool, err := pgxpool.NewWithConfig(parent, cfg)
	require.NoError(t, err)
	defer func() { cancel(); pool.Close() }()
	var original *pgx.Conn
	select {
	case original = <-made:
	case <-time.After(10 * time.Second):
		t.Fatal("socket constructor did not finish")
	}
	pid := original.PgConn().PID()
	require.Eventually(t, func() bool { return pool.Stat().IdleConns() == 1 }, time.Second, time.Millisecond)
	var callers sync.WaitGroup
	results := make(chan error, 5)
	call := func(started chan<- struct{}) {
		defer callers.Done()
		ctx, done := context.WithTimeout(t.Context(), 2*time.Second)
		defer done()
		if started != nil {
			started <- struct{}{}
		}
		conn, err := pool.Acquire(ctx)
		if conn != nil {
			conn.Release()
		}
		results <- err
	}
	callers.Add(1)
	go call(nil)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("first acquisition did not reach PrepareConn")
	}
	queued := make(chan struct{}, 4)
	for range 4 {
		callers.Add(1)
		go call(queued)
	}
	for range 4 {
		<-queued
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	callers.Wait()
	close(results)
	for err := range results {
		require.ErrorIs(t, err, ErrWarming)
	}
	require.EqualValues(t, 5, checks.Load())
	require.Equal(t, true, original.PgConn().CustomData()[freshConnectionKey])
	canceled, stop := context.WithCancel(t.Context())
	stop()
	conn, err := pool.Acquire(canceled)
	require.Nil(t, conn)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, true, original.PgConn().CustomData()[freshConnectionKey])
	require.EqualValues(t, 1, pool.Stat().NewConnsCount())
	require.EqualValues(t, 1, pool.Stat().IdleConns())
	// Idle Ping precedes PrepareConn; an original3s caller still has enough
	// measured work budget after a400ms Ping. Same backend survives all rejects.
	enabled.Store(true)
	time.Sleep(1200 * time.Millisecond)
	fresh, done := context.WithTimeout(t.Context(), 3*time.Second)
	defer done()
	conn, err = pool.Acquire(fresh)
	require.NoError(t, err)
	defer conn.Release()
	require.Equal(t, pid, conn.Conn().PgConn().PID())
	require.NotContains(t, original.PgConn().CustomData(), freshConnectionKey)
	var primary bool
	require.NoError(t, conn.QueryRow(fresh, "SELECT NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off'").Scan(&primary))
	require.True(t, primary)
	require.EqualValues(t, 1, pool.Stat().NewConnsCount())
}
func TestFirstUseGuardRetainsYoungFreshSocketInsteadOfIdlePing(t *testing.T) {
	enabled := &atomic.Bool{}
	defer enabled.Store(false)
	cfg := lifecycleConfig(t, enabled)
	made := make(chan *pgx.Conn, 2)
	cfg.AfterConnect = func(_ context.Context, c *pgx.Conn) error { made <- c; return nil }
	var checks atomic.Int32
	cfg.PrepareConn = func(context.Context, *pgx.Conn) (bool, error) { checks.Add(1); return true, nil }
	require.NoError(t, Configure(cfg, 1, true))
	parent, cancel := context.WithCancel(t.Context())
	pool, err := pgxpool.NewWithConfig(parent, cfg)
	require.NoError(t, err)
	defer func() { cancel(); pool.Close() }()
	var first *pgx.Conn
	select {
	case first = <-made:
	case <-time.After(10 * time.Second):
		t.Fatal("socket constructor did not finish")
	}
	require.Eventually(t, func() bool { return pool.Stat().IdleConns() == 1 }, time.Second, time.Millisecond)
	enabled.Store(true)
	// Idle longer than pgx's default 1s ping threshold, as after a slow WAN constructor.
	time.Sleep(1200 * time.Millisecond)
	short, stop := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer stop()
	conn, err := pool.Acquire(short)
	if conn != nil {
		conn.Release()
	}
	require.ErrorIs(t, err, ErrWarming, "the young fresh socket reaches the first-use guard without an idle Ping")
	require.EqualValues(t, 1, checks.Load())
	require.Equal(t, 1, int(pool.Stat().IdleConns()), "the socket is retained for the next fresh call")
	enabled.Store(false)
	fresh, done := context.WithTimeout(t.Context(), 3*time.Second)
	defer done()
	conn, err = pool.Acquire(fresh)
	require.NoError(t, err)
	require.Same(t, first.PgConn(), conn.Conn().PgConn())
	conn.Release()
	require.EqualValues(t, 1, pool.Stat().NewConnsCount())
}
