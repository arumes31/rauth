package clusterregistry_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"rauth/internal/clusterregistry"
	"rauth/internal/clustertransport"
)

type countingConn struct {
	net.Conn
	writes *atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

// Each authorization queries the writable authority, but it must cost a single
// network round trip on a warm connection so WAN latency cannot exhaust the
// fixed authorization deadline.
func TestAuthorizeUsesOneRoundTripOnWarmConnection(t *testing.T) {
	_, read, _, writer := fixture(t)
	e := entry()
	_, err := writer.Put(ctx, 0, e)
	require.NoError(t, err)
	writes := &atomic.Int64{}
	cfg := read.Config().Copy()
	cfg.MaxConns = 1
	dial := cfg.ConnConfig.DialFunc
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &countingConn{conn, writes}, nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	r, err := clusterregistry.NewReader(pool, cluster)
	require.NoError(t, err)
	require.NoError(t, r.Authorize(ctx, peer(e), clustertransport.PolicyRead))
	before := writes.Load()
	started := time.Now()
	require.NoError(t, r.Authorize(ctx, peer(e), clustertransport.PolicyRead))
	require.Equal(t, int64(1), writes.Load()-before, "warm authorization must be one round trip (took %s)", time.Since(started))
	require.ErrorIs(t, r.Authorize(ctx, peer(e), clustertransport.StatusRead), clustertransport.ErrDenied)
}
