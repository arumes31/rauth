package eventstore

import (
	"context"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"rauth/internal/requestevent"
)

type coldReaderConn struct {
	net.Conn
	delay   time.Duration
	enabled *atomic.Bool
}

func (c *coldReaderConn) Write(p []byte) (int, error) {
	if c.enabled.Load() {
		time.Sleep(c.delay)
	}
	return c.Conn.Write(p)
}

func coldReaderStore(t *testing.T, delay time.Duration) (*Store, *atomic.Bool, requestevent.Event, requestevent.Event) {
	t.Helper()
	pool := setup(t)
	cfg := pool.Config()
	uri, err := url.Parse(cfg.ConnConfig.ConnString())
	require.NoError(t, err)
	query := uri.Query()
	query.Set("target_session_attrs", "read-write")
	uri.RawQuery = query.Encode()
	selected, err := pgxpool.ParseConfig(uri.String())
	require.NoError(t, err)
	cfg.ConnConfig.ValidateConnect = selected.ConnConfig.ValidateConnect
	cfg.ConnConfig.ConnectTimeout = 2 * time.Second
	cfg.MaxConns = 3
	cfg.MinConns = 0
	original := cfg.ConnConfig.DialFunc
	enabled := &atomic.Bool{}
	cfg.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := original(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &coldReaderConn{Conn: conn, delay: delay, enabled: enabled}, nil
	}
	main, err := pgxpool.NewWithConfig(background, cfg)
	require.NoError(t, err)
	t.Cleanup(main.Close)
	s := open(t, main, options())
	node := uuid.NewString()
	event := decision(node)
	event.ProcessingMicros = 1234
	diagnostic := metricEvent(node, 1)
	diagnostic.Metrics.Diagnostics = true
	diagnostic.Metrics.CaptureID = uuid.NewString()
	diagnostic.Metrics.Parts = 1
	_, err = s.Ingest(background, node, []requestevent.Event{event, diagnostic})
	require.NoError(t, err)
	// No reader connection or query has been warmed. Delay includes TLS/SCRAM,
	// writable-leader validation, read-only setup and statement preparation.
	enabled.Store(true)
	t.Cleanup(func() { enabled.Store(false) })
	return s, enabled, event, diagnostic
}

func TestColdReadersAcrossWAN(t *testing.T) {
	for _, delay := range []time.Duration{225 * time.Millisecond, 250 * time.Millisecond, 400 * time.Millisecond} {
		for _, kind := range []string{"statistics", "history", "diagnostics", "feed", "tail"} {
			t.Run(delay.String()+"/"+kind, func(t *testing.T) {
				s, _, event, diagnostic := coldReaderStore(t, delay)
				started := time.Now()
				switch kind {
				case "statistics":
					view, err := s.Statistics(background, StatsQuery{Range: "5m"})
					require.NoError(t, err)
					require.EqualValues(t, 1, view.Total)
				case "history":
					events, err := s.Decisions(background, StatsQuery{Range: "5m"})
					require.NoError(t, err)
					require.Len(t, events, 1)
					require.Equal(t, event.EventID, events[0].EventID)
				case "diagnostics":
					view, err := s.Diagnostics(background, event.NodeID)
					require.NoError(t, err)
					require.True(t, view.Complete)
					require.Len(t, view.Parts, 1)
					require.Equal(t, diagnostic.Metrics.CaptureID, view.Parts[0].CaptureID)
				case "tail":
					cursor, err := s.FeedStart(background, event.NodeID, 100)
					require.NoError(t, err)
					require.Zero(t, cursor)
				case "feed":
					ctx, cancel := context.WithTimeout(background, ReadTimeout)
					defer cancel()
					batch, err := s.After(ctx, 0, event.NodeID)
					require.NoError(t, err)
					require.Len(t, batch.Events, 1)
					require.Equal(t, event.EventID, batch.Events[0].EventID)
					cursor, err := s.FeedStart(ctx, event.NodeID, 100)
					require.NoError(t, err)
					require.Zero(t, cursor)
				}
				require.Less(t, time.Since(started), ReadTimeout+time.Second, "cold read and its bounded feed lookup must finish")
			})
		}
	}
}

func TestColdReaderHonorsParentCancellation(t *testing.T) {
	s, _, _, _ := coldReaderStore(t, 250*time.Millisecond)
	ctx, cancel := context.WithTimeout(background, 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := s.Statistics(ctx, StatsQuery{Range: "5m"})
	require.ErrorIs(t, err, ErrUnavailable)
	require.Less(t, time.Since(started), time.Second)
}

func TestReaderServerDeadlineRemainsShorterThanReadBudget(t *testing.T) {
	pool := setup(t)
	s := open(t, pool, options())
	for _, reader := range []*pgxpool.Pool{s.history, s.stats} {
		ctx, cancel := context.WithTimeout(background, 5*time.Second)
		started := time.Now()
		_, err := reader.Exec(ctx, "SELECT pg_sleep(4)")
		var server *pgconn.PgError
		require.ErrorAs(t, err, &server)
		require.Equal(t, "57014", server.Code)
		require.NoError(t, ctx.Err(), "server must cancel work before the larger caller budget")
		require.Less(t, time.Since(started), 3500*time.Millisecond)
		cancel()
		var mode string
		require.NoError(t, reader.QueryRow(background, "SHOW transaction_read_only").Scan(&mode))
		require.Equal(t, "on", mode)
		_, err = reader.Exec(background, "UPDATE event_ledgers SET epoch=epoch")
		require.ErrorAs(t, err, &server)
		require.Equal(t, "25006", server.Code)
	}
}

// The collector needs two cold sessions: one reserved advisory-lock connection
// and one transaction connection. Its event-only startup budget covers both.
func TestColdCollectorOpenAcrossWAN(t *testing.T) {
	for _, delay := range []time.Duration{225 * time.Millisecond, 250 * time.Millisecond, 400 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			pool := setup(t)
			o := options()
			var role string
			require.NoError(t, pool.QueryRow(background, "SELECT current_user").Scan(&role))
			require.NoError(t, Provision(background, pool, o, role))
			cfg := pool.Config()
			uri, err := url.Parse(cfg.ConnConfig.ConnString())
			require.NoError(t, err)
			q := uri.Query()
			q.Set("target_session_attrs", "read-write")
			uri.RawQuery = q.Encode()
			selected, err := pgxpool.ParseConfig(uri.String())
			require.NoError(t, err)
			cfg.ConnConfig.ValidateConnect = selected.ConnConfig.ValidateConnect
			cfg.ConnConfig.ConnectTimeout = 5 * time.Second
			cfg.MaxConns = 3
			cfg.MinConns = 0
			original := cfg.ConnConfig.DialFunc
			enabled := &atomic.Bool{}
			enabled.Store(true)
			cfg.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := original(ctx, network, address)
				if err != nil {
					return nil, err
				}
				return &coldReaderConn{Conn: conn, delay: delay, enabled: enabled}, nil
			}
			delayed, err := pgxpool.NewWithConfig(background, cfg)
			require.NoError(t, err)
			t.Cleanup(delayed.Close)
			ctx, cancel := context.WithTimeout(background, 10*time.Second)
			started := time.Now()
			s, err := Open(ctx, delayed, o)
			cancel()
			enabled.Store(false)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, s.Close()) })
			require.Less(t, time.Since(started), 10*time.Second)
			node := uuid.NewString()
			_, err = s.Ingest(background, node, []requestevent.Event{decision(node)})
			require.NoError(t, err)
			_, err = s.Status(background)
			require.NoError(t, err)
		})
	}
}
