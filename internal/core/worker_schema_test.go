package core

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"net/url"
	"os"
	"rauth/internal/pgtest"
	"testing"
)

func TestWorkerSchemaRequiresExactExistingVersionsAndPrimary(t *testing.T) {
	pool := pgtest.Open(t, Migrate)
	ctx := context.Background()
	require.NoError(t, VerifyWorkerSchema(ctx, pool))
	cfg := pool.Config()
	cfg.MaxConns = 1
	other, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer other.Close()
	_, err = other.Exec(ctx, "SET default_transaction_read_only=on")
	require.NoError(t, err)
	require.ErrorIs(t, VerifyWorkerSchema(ctx, other), ErrWorkerSchema)
	_, err = pool.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES(99999)")
	require.NoError(t, err)
	require.ErrorIs(t, VerifyWorkerSchema(ctx, pool), ErrWorkerSchema)
	_, err = pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version=99999")
	require.NoError(t, err)
	var highest int
	require.NoError(t, pool.QueryRow(ctx, "SELECT max(version) FROM schema_migrations").Scan(&highest))
	_, err = pool.Exec(ctx, "DELETE FROM schema_migrations WHERE version=$1", highest)
	require.NoError(t, err)
	require.ErrorIs(t, VerifyWorkerSchema(ctx, pool), ErrWorkerSchema)
	_, err = pool.Exec(ctx, "INSERT INTO schema_migrations(version)VALUES($1)", highest)
	require.NoError(t, err)
	require.NoError(t, VerifyWorkerSchema(ctx, pool))
}
func TestWorkerStartupUsesSelectOnlySchemaGrantWithoutDDL(t *testing.T) {
	pool := pgtest.Open(t, Migrate)
	ctx := context.Background()
	role := "rauth_worker_" + fmt.Sprintf("%x", sha256.Sum256([]byte(uuid.NewString())))[:16]
	ident := pgx.Identifier{role}.Sanitize()
	_, err := pool.Exec(ctx, "CREATE ROLE "+ident+" LOGIN PASSWORD 'synthetic-worker-test-only'")
	require.NoError(t, err)
	defer func() { _, _ = pool.Exec(ctx, "DROP OWNED BY "+ident); _, _ = pool.Exec(ctx, "DROP ROLE "+ident) }()
	var schema string
	require.NoError(t, pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema))
	_, err = pool.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO "+ident)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "GRANT SELECT ON schema_migrations TO "+ident)
	require.NoError(t, err)
	u, err := url.Parse(os.Getenv(pgtest.EnvURL))
	require.NoError(t, err)
	u.User = url.UserPassword(role, "synthetic-worker-test-only")
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	cfg := &Config{AuthStateMode: "postgres", PostgresURL: u.String()}
	old := PG
	defer func() {
		if PG != old && PG != nil {
			PG.Close()
		}
		PG = old
	}()
	require.NoError(t, InitPostgresWorker(cfg))
	_, err = PG.Exec(ctx, "CREATE TABLE worker_must_not_create(id int)")
	require.Error(t, err, "worker startup succeeded without gaining schema CREATE")
	require.NoError(t, VerifyWorkerSchema(ctx, PG))
}
func TestWorkerStartupRejectsLegacyAuthority(t *testing.T) {
	require.Error(t, InitPostgresWorker(&Config{AuthStateMode: "redis"}))
	require.Error(t, InitPostgresWorker(nil))
}

func TestWorkerStartupRefusesEmptySchemaWhileControllerStillMigrates(t *testing.T) {
	pool := pgtest.Open(t, Migrate)
	ctx := context.Background()
	schema := "rauth_startup_" + fmt.Sprintf("%x", sha256.Sum256([]byte(uuid.NewString())))[:16]
	ident := pgx.Identifier{schema}.Sanitize()
	_, err := pool.Exec(ctx, "CREATE SCHEMA "+ident)
	require.NoError(t, err)
	defer func() { _, _ = pool.Exec(ctx, "DROP SCHEMA "+ident+" CASCADE") }()
	u, err := url.Parse(os.Getenv(pgtest.EnvURL))
	require.NoError(t, err)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	cfg := &Config{AuthStateMode: "postgres", PostgresURL: u.String()}
	old := PG
	defer func() {
		if PG != old && PG != nil {
			PG.Close()
		}
		PG = old
	}()
	require.ErrorIs(t, InitPostgresWorker(cfg), ErrWorkerSchema)
	require.Same(t, old, PG, "failed worker startup must not publish its database pool")
	var objects int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM pg_tables WHERE schemaname=$1", schema).Scan(&objects))
	require.Zero(t, objects, "worker must not create bookkeeping or schema tables")
	require.NoError(t, InitPostgres(cfg), "legacy/controller initialization must retain migrations")
	require.NoError(t, VerifyWorkerSchema(ctx, PG))
}
