package core

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PG is the durable store: accounts, their credentials, auth generations,
// bypass rules and the audit log. Redis keeps only ephemeral state (sessions,
// rate limits, invites, in-flight ceremonies).
var PG *pgxpool.Pool

//go:embed migrations/*.sql
var migrationFS embed.FS

// postgresConnectTimeout bounds how long startup waits for the database, so a
// container started alongside Postgres survives its initialization.
const postgresConnectTimeout = 60 * time.Second

func InitPostgres(cfg *Config) error {
	poolCfg, err := pgxpool.ParseConfig(cfg.PostgresURL)
	if err != nil {
		return fmt.Errorf("invalid Postgres connection settings: %w", err)
	}
	poolCfg.MaxConns = redisPoolSize
	poolCfg.ConnConfig.ConnectTimeout = 5 * time.Second

	pool, err := pgxpool.NewWithConfig(Ctx, poolCfg)
	if err != nil {
		return err
	}

	deadline := time.Now().Add(postgresConnectTimeout)
	for {
		err = pool.Ping(Ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			pool.Close()
			return fmt.Errorf("failed to connect to Postgres: %w", err)
		}
		slog.Warn("Postgres not reachable yet, retrying", "error", err)
		time.Sleep(2 * time.Second)
	}

	if err := Migrate(Ctx, pool); err != nil {
		pool.Close()
		return fmt.Errorf("failed to migrate Postgres schema: %w", err)
	}
	PG = pool
	return nil
}

// migrationLockID serializes schema migrations across instances starting at once.
const migrationLockID = 0x72617574 // "raut"

// Migrate applies every embedded migration not yet recorded in
// schema_migrations, each in its own transaction.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return err
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockID) }()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    integer PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}

	files, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)

	for _, file := range files {
		name := strings.TrimPrefix(file, "migrations/")
		version, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %s: name must start with a version number", name)
		}
		var applied bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := migrationFS.ReadFile(file)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version)
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
		slog.Info("Applied database migration", "migration", name)
	}
	return nil
}

// isNoRows reports whether err means the queried row does not exist.
func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
