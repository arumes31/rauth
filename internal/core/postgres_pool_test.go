package core

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"rauth/internal/pgtest"
)

func TestPostgresFleetRespectsConfiguredPoolBudget(t *testing.T) {
	fixture := pgtest.Open(t, Migrate)
	ctx := context.Background()
	var schema string
	require.NoError(t, fixture.QueryRow(ctx, "SELECT current_schema()").Scan(&schema))
	u, err := url.Parse(os.Getenv(pgtest.EnvURL))
	require.NoError(t, err)
	name := "pool-budget-" + uuid.NewString()
	q := u.Query()
	q.Set("search_path", schema)
	q.Set("application_name", name)
	q.Set("pool_max_conns", "4")
	q.Set("pool_min_conns", "0")
	u.RawQuery = q.Encode()
	cfg := &Config{AuthStateMode: "postgres", PostgresURL: u.String()}
	old := PG
	var pools []*pgxpool.Pool
	var held []*pgxpool.Conn
	defer func() {
		for _, conn := range held {
			conn.Release()
		}
		for _, pool := range pools {
			pool.Close()
		}
		PG = old
	}()
	for i := 0; i < 5; i++ {
		if i == 0 {
			err = InitPostgres(cfg)
		} else {
			err = InitPostgresWorker(cfg)
		}
		require.NoError(t, err)
		pools = append(pools, PG)
		require.Equal(t, int32(4), PG.Config().MaxConns, "each process must honor its explicit limit")
	}
	for i, pool := range pools {
		for j := 0; j < 4; j++ {
			acquire, cancel := context.WithTimeout(ctx, 3*time.Second)
			conn, err := pool.Acquire(acquire)
			cancel()
			require.NoError(t, err)
			held = append(held, conn)
			var ready bool
			require.NoError(t, conn.QueryRow(ctx, "SELECT NOT pg_is_in_recovery()").Scan(&ready))
			require.True(t, ready)
		}
		acquire, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		extra, err := pool.Acquire(acquire)
		cancel()
		if extra != nil {
			extra.Release()
		}
		require.ErrorIs(t, err, context.DeadlineExceeded, fmt.Sprintf("node %d must apply backpressure", i))
	}
	var actual int
	require.NoError(t, fixture.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE application_name=$1", name).Scan(&actual))
	require.Equal(t, 20, actual, "five nodes together may use only the configured fleet budget")
}

func TestPostgresPoolOptionsRetainDefaultsAndDriverValidation(t *testing.T) {
	for _, connection := range []string{
		"postgres://synthetic:password@localhost/db?sslmode=disable",
		"host=localhost user=synthetic password='private pool_max_conns=4' dbname=db sslmode=disable",
	} {
		config, err := postgresPoolConfig(connection)
		require.NoError(t, err)
		require.Equal(t, int32(20), config.MaxConns, "text inside a password is not an option")
	}
	for _, connection := range []string{
		"postgres://synthetic:password@localhost/db?sslmode=disable&pool_max_conns=4",
		"host=localhost user=synthetic dbname=db sslmode=disable pool_max_conns=4",
	} {
		config, err := postgresPoolConfig(connection)
		require.NoError(t, err)
		require.Equal(t, int32(4), config.MaxConns)
		require.NotContains(t, config.ConnConfig.RuntimeParams, "pool_max_conns")
	}
	for _, maximum := range []string{"0", "-1", "invalid"} {
		_, err := postgresPoolConfig("postgres://localhost/db?sslmode=disable&pool_max_conns=" + maximum)
		require.Error(t, err)
	}
}
