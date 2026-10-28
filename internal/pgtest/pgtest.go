// Package pgtest gives tests a Postgres pool on a private schema.
//
// Tests need RAUTH_TEST_DATABASE_URL pointing at a server where the user may
// create schemas, e.g.
//
//	docker run -d --name rauth-test-pg -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:18-alpine
//	RAUTH_TEST_DATABASE_URL=postgres://postgres:test@localhost:55432/postgres?sslmode=disable go test ./...
//
// Without it, tests that need the database are skipped locally and fail in CI.
package pgtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnvURL names the variable holding the test server's connection string.
const EnvURL = "RAUTH_TEST_DATABASE_URL"

var (
	once    sync.Once
	pool    *pgxpool.Pool
	openErr error
)

var nonIdent = regexp.MustCompile(`[^a-z0-9_]+`)

// schemaName derives a schema from the test binary, so packages tested in
// parallel by "go test ./..." never share tables.
func schemaName() string {
	base := strings.ToLower(filepath.Base(os.Args[0]))
	base = strings.TrimSuffix(strings.TrimSuffix(base, ".exe"), ".test")
	return "rauth_test_" + nonIdent.ReplaceAllString(base, "_")
}

// Open returns a pool whose search_path is a schema recreated empty on the
// first call in this process. migrate is run once to create the tables.
func Open(t testing.TB, migrate func(context.Context, *pgxpool.Pool) error) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv(EnvURL)
	if url == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s must be set in CI", EnvURL)
		}
		t.Skipf("%s not set; skipping test that needs Postgres", EnvURL)
	}
	once.Do(func() {
		ctx := context.Background()
		schema := schemaName()
		admin, err := pgx.Connect(ctx, url)
		if err != nil {
			openErr = err
			return
		}
		ident := pgx.Identifier{schema}.Sanitize()
		_, err = admin.Exec(ctx, fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE; CREATE SCHEMA %s", ident, ident))
		_ = admin.Close(ctx)
		if err != nil {
			openErr = err
			return
		}
		cfg, err := pgxpool.ParseConfig(url)
		if err != nil {
			openErr = err
			return
		}
		cfg.ConnConfig.RuntimeParams["search_path"] = schema
		cfg.MaxConns = 8
		pool, err = pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			openErr = err
			return
		}
		openErr = migrate(ctx, pool)
	})
	if openErr != nil {
		t.Fatalf("test Postgres: %v", openErr)
	}
	return pool
}

// Reset empties every table except the migration bookkeeping.
func Reset(t testing.TB, p *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	rows, err := p.Query(ctx, `SELECT tablename FROM pg_tables
		WHERE schemaname = current_schema() AND tablename <> 'schema_migrations'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			tables = append(tables, pgx.Identifier{name}.Sanitize())
		}
	}
	rows.Close()
	if len(tables) == 0 {
		return
	}
	if _, err := p.Exec(ctx, "TRUNCATE "+strings.Join(tables, ", ")+" RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}
