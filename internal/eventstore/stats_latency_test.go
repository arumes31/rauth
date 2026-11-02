package eventstore

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"rauth/internal/requestevent"
)

type delayedStatsConn struct {
	net.Conn
	enabled *atomic.Bool
}

func (c *delayedStatsConn) Write(p []byte) (int, error) {
	if c.enabled.Load() {
		time.Sleep(225 * time.Millisecond)
	}
	return c.Conn.Write(p)
}

func TestStatisticsRemotePrimaryReadBudget(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	node := uuid.NewString()
	event := decision(node)
	_, err := s.Ingest(background, node, []requestevent.Event{event})
	require.NoError(t, err)
	cfg := s.stats.Config()
	originalDial := cfg.ConnConfig.DialFunc
	var enabled atomic.Bool
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := originalDial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &delayedStatsConn{Conn: conn, enabled: &enabled}, nil
	}
	delayed, err := pgxpool.NewWithConfig(background, cfg)
	require.NoError(t, err)
	s.stats.Close()
	s.stats = delayed
	// Warm the connection and statements before measuring SQL round trips.
	_, err = s.Statistics(background, StatsQuery{Range: "5m"})
	require.NoError(t, err)
	enabled.Store(true)
	view, err := s.Statistics(background, StatsQuery{Range: "5m"})
	enabled.Store(false)
	require.NoError(t, err, "remote reads must fit the unchanged two-second budget")
	require.EqualValues(t, 1, view.Total)
	require.EqualValues(t, 1, view.Top["urls"][0].Count)
	require.False(t, view.TopUnavailable)
}
