package clusterpool_test

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"net"
	"rauth/internal/clusterpool"
	"testing"
	"time"
)

func TestConfigurePreservesBudgetsAndConnectionSecurity(t *testing.T) {
	for _, critical := range []bool{false, true} {
		cfg, err := pgxpool.ParseConfig("postgres://synthetic@localhost/db?sslmode=verify-full&target_session_attrs=read-write")
		require.NoError(t, err)
		tls, validate := cfg.ConnConfig.TLSConfig, cfg.ConnConfig.ValidateConnect
		require.NoError(t, clusterpool.Configure(cfg, 2, critical))
		require.Same(t, tls, cfg.ConnConfig.TLSConfig)
		require.NotNil(t, validate)
		require.NotNil(t, cfg.ConnConfig.ValidateConnect)
		require.False(t, cfg.ConnConfig.TLSConfig.InsecureSkipVerify)
		require.EqualValues(t, 2, cfg.MaxConns)
		require.Zero(t, cfg.MinIdleConns)
		require.Equal(t, 5*time.Second, cfg.ConnConfig.ConnectTimeout)
		if critical {
			require.EqualValues(t, 2, cfg.MinConns)
			require.Equal(t, 2*time.Second, cfg.HealthCheckPeriod)
		} else {
			require.Zero(t, cfg.MinConns)
		}
	}
	require.ErrorIs(t, clusterpool.Configure(nil, 1, true), clusterpool.ErrInvalid)
	require.ErrorIs(t, clusterpool.Configure(&pgxpool.Config{}, 1, true), clusterpool.ErrInvalid)
	cfg, err := pgxpool.ParseConfig("")
	require.NoError(t, err)
	require.ErrorIs(t, clusterpool.Configure(cfg, 0, true), clusterpool.ErrInvalid)
}
func TestWarmRefusesNilAndHonorsCanceledStartup(t *testing.T) {
	require.ErrorIs(t, clusterpool.Warm(nil), clusterpool.ErrInvalid) //nolint:staticcheck // Deliberately test refusal of invalid input.
	require.ErrorIs(t, clusterpool.Warm(context.Background(), nil), clusterpool.ErrInvalid)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg, err := pgxpool.ParseConfig("postgres://synthetic@localhost/db?sslmode=disable")
	require.NoError(t, err)
	require.NoError(t, clusterpool.Configure(cfg, 1, true))
	cfg.ConnConfig.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	require.ErrorIs(t, clusterpool.Warm(ctx, pool), context.Canceled)
	require.Zero(t, pool.Stat().AcquiredConns())
}
