package clusterpool

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestFreshConnectionRetainsMarkerAcrossRejectedCallers(t *testing.T) {
	data := map[string]any{freshConnectionKey: true, "unrelated": "kept"}
	for range 4 {
		late, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		ok, err := prepareFresh(late, data)
		cancel()
		require.True(t, ok)
		require.ErrorIs(t, err, ErrWarming)
		require.Equal(t, true, data[freshConnectionKey])
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	ok, err := prepareFresh(canceled, data)
	require.True(t, ok)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, true, data[freshConnectionKey])
	fresh, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ok, err = prepareFresh(fresh, data)
	require.True(t, ok)
	require.NoError(t, err)
	require.NotContains(t, data, freshConnectionKey)
	require.Equal(t, "kept", data["unrelated"])
	short, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	ok, err = prepareFresh(short, data)
	require.True(t, ok)
	require.NoError(t, err, "already-warm connections have no additional budget floor")
}
func TestFreshConnectionPreservesPriorHookPrecedence(t *testing.T) {
	denied := errors.New("synthetic prior check refused")
	for _, test := range []struct {
		name    string
		prepare bool
		before  bool
		ok      bool
		err     error
	}{
		{"prepare-denies", true, true, false, denied}, {"prepare-releases-error", true, true, true, denied}, {"legacy-denies", false, true, false, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := pgxpool.ParseConfig("postgres://synthetic@localhost/db?sslmode=verify-full")
			require.NoError(t, err)
			beforeCalls, prepareCalls := 0, 0
			if test.prepare {
				cfg.PrepareConn = func(context.Context, *pgx.Conn) (bool, error) { prepareCalls++; return test.ok, test.err }
			}
			if test.before {
				//nolint:staticcheck // Explicit compatibility contract.
				cfg.BeforeAcquire = func(context.Context, *pgx.Conn) bool { beforeCalls++; return false }
			}
			require.NoError(t, Configure(cfg, 1, true))
			ok, err := cfg.PrepareConn(context.Background(), nil)
			require.Equal(t, test.ok, ok)
			require.ErrorIs(t, err, test.err)
			if test.prepare {
				require.Equal(t, 1, prepareCalls)
				require.Zero(t, beforeCalls)
			} else {
				require.Equal(t, 1, beforeCalls)
			}
		})
	}
}
func TestFreshConnectionPreservesAfterConnectFailureAndContext(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://synthetic@localhost/db?sslmode=verify-full")
	require.NoError(t, err)
	denied := errors.New("synthetic connection check failed")
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cfg.AfterConnect = func(ctx context.Context, _ *pgx.Conn) error { require.Same(t, parent, ctx); return denied }
	require.NoError(t, Configure(cfg, 1, true))
	require.ErrorIs(t, cfg.AfterConnect(parent, nil), denied)
}
