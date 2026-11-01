package core

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"
)

var ErrWorkerSchema = errors.New("worker requires the matching migrated PostgreSQL schema")

// VerifyWorkerSchema is a bounded SELECT-only startup check. The controller or
// offline operator owns migrations. Refuse missing, incomplete or unknown newer
// schema versions rather than attempting DDL under worker credentials.
func VerifyWorkerSchema(parent context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return ErrWorkerSchema
	}
	files, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil || len(files) == 0 {
		return ErrWorkerSchema
	}
	required := make([]int, 0, len(files))
	for _, file := range files {
		version, e := strconv.Atoi(strings.SplitN(strings.TrimPrefix(file, "migrations/"), "_", 2)[0])
		if e != nil || version <= 0 {
			return ErrWorkerSchema
		}
		required = append(required, version)
	}
	slices.Sort(required)
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return ErrWorkerSchema
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	var primary bool
	if tx.QueryRow(ctx, `SELECT NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off'`).Scan(&primary) != nil || !primary {
		return ErrWorkerSchema
	}
	rows, err := tx.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version LIMIT $1`, len(required)+1)
	if err != nil {
		return ErrWorkerSchema
	}
	defer rows.Close()
	actual := make([]int, 0, len(required)+1)
	for rows.Next() {
		var version int
		if rows.Scan(&version) != nil {
			return ErrWorkerSchema
		}
		actual = append(actual, version)
	}
	if rows.Err() != nil || !slices.Equal(actual, required) {
		return ErrWorkerSchema
	}
	return nil
}
