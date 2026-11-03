package clusterstate_test

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"net"
	"net/url"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clusterpool"
	"rauth/internal/clusterstate"
	"sync/atomic"
	"testing"
	"time"
)

type headWANConn struct {
	net.Conn
	enabled *atomic.Bool
}

func (c *headWANConn) Write(p []byte) (int, error) {
	if c.enabled.Load() {
		time.Sleep(400 * time.Millisecond)
	}
	return c.Conn.Write(p)
}
func TestAuthoritativeHeadWarmupAndConnectionReplacementWAN(t *testing.T) {
	write, publisher, _ := fixture(t)
	expected := publish(t, publisher, clusterpolicy.Identity{}, 1, `{"rules":[]}`, []byte("feed"))
	enabled := &atomic.Bool{}
	enabled.Store(true)
	defer enabled.Store(false)
	cfg := write.Config()
	require.NoError(t, clusterpool.Configure(cfg, 1, true))
	u, err := url.Parse(cfg.ConnConfig.ConnString())
	require.NoError(t, err)
	q := u.Query()
	q.Set("target_session_attrs", "read-write")
	u.RawQuery = q.Encode()
	selected, err := pgxpool.ParseConfig(u.String())
	require.NoError(t, err)
	cfg.ConnConfig.ValidateConnect = selected.ConnConfig.ValidateConnect
	name := "authority-head-" + uuid.NewString()
	cfg.ConnConfig.RuntimeParams["application_name"] = name
	dial := cfg.ConnConfig.DialFunc
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &headWANConn{c, enabled}, nil
	}
	heads, err := pgxpool.NewWithConfig(t.Context(), cfg)
	require.NoError(t, err)
	defer heads.Close()
	// Payloads retain their own budget and can be occupied without head starvation.
	bc := write.Config()
	require.NoError(t, clusterpool.Configure(bc, 2, false))
	blobs, err := pgxpool.NewWithConfig(t.Context(), bc)
	require.NoError(t, err)
	defer blobs.Close()
	held1, err := blobs.Acquire(t.Context())
	require.NoError(t, err)
	defer held1.Release()
	held2, err := blobs.Acquire(t.Context())
	require.NoError(t, err)
	defer held2.Release()
	reader, err := clusterstate.NewReader(heads, blobs, verifier(t, cluster))
	require.NoError(t, err)
	require.NoError(t, clusterpool.Warm(t.Context(), heads))
	current, err := reader.Current(t.Context())
	require.NoError(t, err)
	require.Equal(t, expected.Verified.Identity(), current.Verified.Identity())
	var killed bool
	require.NoError(t, write.QueryRow(t.Context(), "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name=$1", name).Scan(&killed))
	require.True(t, killed)
	recovered := false
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		current, err = reader.Current(t.Context())
		if err == nil {
			require.Equal(t, expected.Verified.Identity(), current.Verified.Identity())
			recovered = true
			break
		}
	}
	require.True(t, recovered, "head pool must recover without manual warm/reset or a quiet period")
	require.GreaterOrEqual(t, heads.Stat().NewConnsCount(), int64(2))
	require.EqualValues(t, 2, blobs.Stat().AcquiredConns())
}
