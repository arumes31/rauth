package clusterregistry_test

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"net"
	"net/url"
	"rauth/internal/clusterpool"
	"rauth/internal/clusterregistry"
	"rauth/internal/clustertransport"
	"sync/atomic"
	"testing"
	"time"
)

type authorityWANConn struct {
	net.Conn
	delay   time.Duration
	enabled *atomic.Bool
}

func (c *authorityWANConn) Write(p []byte) (int, error) {
	if c.enabled.Load() {
		time.Sleep(c.delay)
	}
	return c.Conn.Write(p)
}

func authorityWANConfig(t *testing.T, base *pgxpool.Config, maximum int32, critical bool, delay time.Duration, enabled *atomic.Bool, name string) *pgxpool.Config {
	t.Helper()
	cfg := base.Copy()
	uri, err := url.Parse(cfg.ConnConfig.ConnString())
	require.NoError(t, err)
	q := uri.Query()
	q.Set("target_session_attrs", "read-write")
	uri.RawQuery = q.Encode()
	selected, err := pgxpool.ParseConfig(uri.String())
	require.NoError(t, err)
	cfg.ConnConfig.ValidateConnect = selected.ConnConfig.ValidateConnect
	require.NoError(t, clusterpool.Configure(cfg, maximum, critical))
	cfg.ConnConfig.RuntimeParams["application_name"] = name
	dial := cfg.ConnConfig.DialFunc
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &authorityWANConn{conn, delay, enabled}, nil
	}
	return cfg
}
func newAuthorityWANPool(t *testing.T, cfg *pgxpool.Config) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(p.Close)
	return p
}
func TestAuthorityPoolsWarmEveryColdSlotBeforeEnrollment(t *testing.T) {
	for _, delay := range []time.Duration{225 * time.Millisecond, 400 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			write, read, _, writer := fixture(t)
			e := entry()
			_, err := writer.Put(ctx, 0, e)
			require.NoError(t, err)
			enabled := &atomic.Bool{}
			enabled.Store(true)
			defer enabled.Store(false)
			prefix := "authority-cold-" + uuid.NewString()
			var pools []*pgxpool.Pool
			for i, n := range []int32{1, 2, 1} {
				pools = append(pools, newAuthorityWANPool(t, authorityWANConfig(t, read.Config(), n, true, delay, enabled, fmt.Sprintf("%s-%d", prefix, i))))
			}
			started := time.Now()
			require.NoError(t, clusterpool.Warm(t.Context(), pools...))
			t.Logf("cold=%s all4slots_warm=%s", delay, time.Since(started))
			for i, p := range pools {
				require.Equal(t, []int32{1, 2, 1}[i], p.Stat().TotalConns())
				require.Zero(t, p.Stat().AcquiredConns())
			}
			reader, err := clusterregistry.NewReader(pools[1], cluster)
			require.NoError(t, err)
			_, err = reader.Lookup(t.Context(), e.NodeID)
			require.NoError(t, err)
			require.NoError(t, reader.Authorize(t.Context(), peer(e), clustertransport.PolicyRead))
			e.Enabled = false
			_, err = writer.Put(ctx, 1, e)
			require.NoError(t, err)
			require.ErrorIs(t, reader.Authorize(t.Context(), peer(e), clustertransport.PolicyRead), clustertransport.ErrDenied, "warm sockets must not cache committed grants")
			var count int
			require.NoError(t, write.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE application_name LIKE $1", prefix+"%").Scan(&count))
			require.Equal(t, 4, count)
		})
	}
}
func authorityContinuousCalls(t *testing.T, r *clusterregistry.Reader, e clusterregistry.Entry, expectColdFailure bool) {
	t.Helper()
	deadline := time.Now().Add(35 * time.Second)
	successes, unavailable := 0, 0
	for successes < 3 && time.Now().Before(deadline) {
		err := r.Authorize(t.Context(), peer(e), clustertransport.PolicyRead)
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, clustertransport.ErrUnavailable)
			unavailable++
		}
		// Intentionally no quiet period, Ping, reset, pool recreation or retry cache.
	}
	require.Equal(t, 3, successes)
	if expectColdFailure {
		require.Positive(t, unavailable)
	}
	t.Logf("continuous successes=%d unavailable=%d", successes, unavailable)
}
func TestAuthorityCriticalPoolRecoversColdDuringContinuousCalls(t *testing.T) {
	_, read, _, writer := fixture(t)
	e := entry()
	_, err := writer.Put(ctx, 0, e)
	require.NoError(t, err)
	enabled := &atomic.Bool{}
	enabled.Store(true)
	defer enabled.Store(false)
	pool := newAuthorityWANPool(t, authorityWANConfig(t, read.Config(), 2, true, 400*time.Millisecond, enabled, "authority-cold-critical-"+uuid.NewString()))
	reader, err := clusterregistry.NewReader(pool, cluster)
	require.NoError(t, err)
	authorityContinuousCalls(t, reader, e, true)
	require.GreaterOrEqual(t, pool.Stat().NewConnsCount(), int64(2))
	require.LessOrEqual(t, pool.Stat().TotalConns(), int32(2))
}
func TestAuthorityPoolRefillsKilledSlotsDuringContinuousCalls(t *testing.T) {
	write, read, _, writer := fixture(t)
	e := entry()
	_, err := writer.Put(ctx, 0, e)
	require.NoError(t, err)
	enabled := &atomic.Bool{}
	enabled.Store(true)
	defer enabled.Store(false)
	name := "authority-kill-" + uuid.NewString()
	pool := newAuthorityWANPool(t, authorityWANConfig(t, read.Config(), 2, true, 400*time.Millisecond, enabled, name))
	require.NoError(t, clusterpool.Warm(t.Context(), pool))
	reader, err := clusterregistry.NewReader(pool, cluster)
	require.NoError(t, err)
	rows, err := write.Query(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name=$1", name)
	require.NoError(t, err)
	killed := 0
	for rows.Next() {
		var ok bool
		require.NoError(t, rows.Scan(&ok))
		require.True(t, ok)
		killed++
	}
	rows.Close()
	require.NoError(t, rows.Err())
	require.Equal(t, 2, killed)
	authorityContinuousCalls(t, reader, e, false)
	require.GreaterOrEqual(t, pool.Stat().NewConnsCount(), int64(4))
}
func TestAuthorityPoolRecoversAfterIdleAndLifetimeEviction(t *testing.T) {
	for _, kind := range []string{"idle", "lifetime"} {
		t.Run(kind, func(t *testing.T) {
			_, read, _, writer := fixture(t)
			e := entry()
			_, err := writer.Put(ctx, 0, e)
			require.NoError(t, err)
			enabled := &atomic.Bool{}
			enabled.Store(true)
			defer enabled.Store(false)
			cfg := authorityWANConfig(t, read.Config(), 2, true, 225*time.Millisecond, enabled, "authority-expire-"+uuid.NewString())
			if kind == "idle" {
				cfg.ConnConfig.RuntimeParams["idle_session_timeout"] = "2s"
			} else {
				cfg.MaxConnLifetime = 4 * time.Second
			}
			pool := newAuthorityWANPool(t, cfg)
			require.NoError(t, clusterpool.Warm(t.Context(), pool))
			reader, err := clusterregistry.NewReader(pool, cluster)
			require.NoError(t, err)
			time.Sleep(5 * time.Second) // Deliberate idle/lifetime trigger, not a recovery quiet period.
			authorityContinuousCalls(t, reader, e, false)
			require.GreaterOrEqual(t, pool.Stat().NewConnsCount(), int64(4))
		})
	}
}
func TestAuthorityWarmupRejectsInvalidTLS(t *testing.T) {
	_, read, _, _ := fixture(t)
	enabled := &atomic.Bool{}
	cfg := authorityWANConfig(t, read.Config(), 1, true, 0, enabled, "authority-invalid-tls")
	cfg.ConnConfig.TLSConfig = cfg.ConnConfig.TLSConfig.Clone()
	cfg.ConnConfig.TLSConfig.ServerName = "wrong-authority.invalid"
	// Do not allow a valid fallback to mask the deliberately invalid hostname.
	cfg.ConnConfig.Fallbacks = nil
	pool := newAuthorityWANPool(t, cfg)
	require.Error(t, clusterpool.Warm(t.Context(), pool))
	require.Zero(t, pool.Stat().AcquiredConns())
}
func TestAuthorityFleetWarmFloorFitsExisting47SlotBudget(t *testing.T) {
	write, read, _, _ := fixture(t)
	enabled := &atomic.Bool{}
	prefix := "authority-budget-" + uuid.NewString()
	var pools []*pgxpool.Pool
	var maximum int32
	add := func(n int32, critical bool) {
		cfg := authorityWANConfig(t, read.Config(), n, critical, 0, enabled, fmt.Sprintf("%s-%d", prefix, len(pools)))
		pools = append(pools, newAuthorityWANPool(t, cfg))
		maximum += n
	}
	for range 4 {
		add(4, false)
		add(1, true)
		add(2, false)
		add(2, true)
	}
	add(1, true)
	add(1, false)
	add(1, false)
	add(1, false)
	add(3, false)
	add(2, false)
	add(2, false)
	require.EqualValues(t, 47, maximum)
	require.NoError(t, clusterpool.Warm(t.Context(), pools...))
	var count int
	require.NoError(t, write.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE application_name LIKE $1", prefix+"%").Scan(&count))
	require.Equal(t, 13, count)
	for _, p := range pools {
		require.Zero(t, p.Stat().AcquiredConns())
	}
}

func TestAuthorityWarmupCancellationAndShutdownAreBounded(t *testing.T) {
	_, read, _, _ := fixture(t)
	enabled := &atomic.Bool{}
	enabled.Store(true)
	defer enabled.Store(false)
	parent, cancel := context.WithCancel(t.Context())
	cfg := authorityWANConfig(t, read.Config(), 2, true, 400*time.Millisecond, enabled, "authority-close-"+uuid.NewString())
	pool, err := pgxpool.NewWithConfig(parent, cfg)
	require.NoError(t, err)
	warm, stopWarm := context.WithTimeout(parent, 150*time.Millisecond)
	require.ErrorIs(t, clusterpool.Warm(warm, pool), context.DeadlineExceeded)
	stopWarm()
	require.Zero(t, pool.Stat().AcquiredConns())
	cancel() // Runtime Close cancels its parent before closing authority pools.
	started := time.Now()
	pool.Close()
	require.Less(t, time.Since(started), 3*time.Second)
}

func TestAuthorityConstructorFinishesAfterAcquireCancellation(t *testing.T) {
	_, read, _, _ := fixture(t)
	enabled := &atomic.Bool{}
	enabled.Store(true)
	defer enabled.Store(false)
	pool := newAuthorityWANPool(t, authorityWANConfig(t, read.Config(), 1, false, 400*time.Millisecond, enabled, "authority-acquire-"+uuid.NewString()))
	short, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	conn, err := pool.Acquire(short)
	cancel()
	require.Nil(t, conn)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.EqualValues(t, 1, pool.Stat().ConstructingConns())
	require.Positive(t, pool.Stat().CanceledAcquireCount())
	// No quiet period: a second acquisition waits for the SAME pending resource.
	// This tests construction, not a late-acquired authorization transaction.
	next, cancelNext := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancelNext()
	conn, err = pool.Acquire(next)
	require.NoError(t, err)
	require.Positive(t, conn.Conn().PgConn().PID())
	conn.Release()
	require.EqualValues(t, 1, pool.Stat().NewConnsCount())
	require.EqualValues(t, 1, pool.Stat().TotalConns())
	require.Zero(t, pool.Stat().AcquiredConns())
}
