package core

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

type authPoolWANConn struct {
	net.Conn
	enabled *atomic.Bool
}

func (c *authPoolWANConn) Write(p []byte) (int, error) {
	if c.enabled.Load() {
		time.Sleep(400 * time.Millisecond)
	}
	return c.Conn.Write(p)
}
func TestAuthenticationPoolRecoversKilledAllSocketsDuringContinuousHealthWAN(t *testing.T) {
	cfg := runtimeAuthStateFixture(t)
	fixture := PG
	marker := authStateAuthorityRecord{Mode: "postgres-v1", ServerKeyCheck: serverKeyCheck(cfg.ServerSecret), CutoverAt: time.Now().Add(-10 * time.Minute), ReadyAfter: time.Now().Add(-8 * time.Minute), LegacyExpired: true}
	raw, err := json.Marshal(marker)
	require.NoError(t, err)
	_, err = fixture.Exec(t.Context(), "INSERT INTO app_meta(key,value)VALUES('redis_import','synthetic'),('auth_state_authority',$1)", string(raw))
	require.NoError(t, err)
	require.NoError(t, InitAuthenticationState(cfg))
	pc := fixture.Config()
	pc.MaxConns = 4
	pc.MinConns = 0
	pc.MinIdleConns = 0
	pc.ConnConfig.ConnectTimeout = 5 * time.Second
	require.NoError(t, configureAuthStateDatabase(cfg, pc))
	u, err := url.Parse(pc.ConnConfig.ConnString())
	require.NoError(t, err)
	q := u.Query()
	q.Set("target_session_attrs", "read-write")
	u.RawQuery = q.Encode()
	selected, err := pgxpool.ParseConfig(u.String())
	require.NoError(t, err)
	pc.ConnConfig.ValidateConnect = selected.ConnConfig.ValidateConnect
	name := "auth-health-recovery-" + uuid.NewString()
	pc.ConnConfig.RuntimeParams["application_name"] = name
	enabled := &atomic.Bool{}
	dial := pc.ConnConfig.DialFunc
	pc.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &authPoolWANConn{c, enabled}, nil
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), pc)
	require.NoError(t, err)
	var held []*pgxpool.Conn
	defer func() {
		enabled.Store(false)
		for _, c := range held {
			c.Release()
		}
		PG = fixture
		pool.Close()
	}()
	PG = pool
	for range 4 {
		c, err := pool.Acquire(t.Context())
		require.NoError(t, err)
		held = append(held, c)
	}
	for _, c := range held {
		c.Release()
	}
	held = nil
	rows, err := fixture.Query(t.Context(), "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name=$1", name)
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
	require.Equal(t, 4, killed)
	enabled.Store(true)
	deadline := time.Now().Add(35 * time.Second)
	successes, unavailable := 0, 0
	for successes < 3 && time.Now().Before(deadline) {
		call, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		started := time.Now()
		err = CheckAuthenticationAuthority(call)
		cancel()
		if err == nil {
			successes++
		} else {
			unavailable++
		}
		t.Logf("auth400 continuous elapsed=%s error_type=%T ready=%t conns=%d constructing=%d acquired=%d", time.Since(started), err, err == nil, pool.Stat().TotalConns(), pool.Stat().ConstructingConns(), pool.Stat().AcquiredConns())
	}
	t.Logf("auth400 killed=%d successes=%d unavailable=%d new_connections=%d", killed, successes, unavailable, pool.Stat().NewConnsCount())
	require.Equal(t, 3, successes, "same auth pool must recover without quiet period/reset/restart or cached authority")
	require.LessOrEqual(t, pool.Stat().TotalConns(), int32(4))
}
