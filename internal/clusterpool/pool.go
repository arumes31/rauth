// Package clusterpool warms existing authority transports, never grants or leases.
package clusterpool

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const ConnectTimeout = 5 * time.Second
const WarmTimeout = 15 * time.Second
const HealthCheckPeriod = 2 * time.Second

var ErrInvalid = errors.New("invalid cluster authority pool")
var ErrWarming = errors.New("cluster authority connection became ready too late for this call")

// Measured cold head work after acquisition is 2.412s at 400ms injected writes.
// This does not extend the caller's 3s. A late FIRST acquisition returns an
// operational error while retaining the new socket for the next fresh call.
const coldQueryBudget = 2500 * time.Millisecond
const freshConnectionKey = "rauth.clusterpool.first_use"

func prepareFresh(ctx context.Context, data map[string]any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return true, err
	}
	fresh, _ := data[freshConnectionKey].(bool)
	if !fresh {
		return true, nil
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < coldQueryBudget {
		return true, ErrWarming
	}
	delete(data, freshConnectionKey)
	return true, nil
}

func preserveFirstUse(cfg *pgxpool.Config) {
	after, prepare, before := cfg.AfterConnect, cfg.PrepareConn, cfg.BeforeAcquire //nolint:staticcheck // Retain the legacy security callback with pgx precedence.
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if after != nil {
			if err := after(ctx, conn); err != nil {
				return err
			}
		}
		conn.PgConn().CustomData()[freshConnectionKey] = true
		return nil
	}
	cfg.PrepareConn = func(ctx context.Context, conn *pgx.Conn) (bool, error) {
		// Preserve pgx's existing PrepareConn precedence and any security callback.
		if prepare != nil {
			if ok, err := prepare(ctx, conn); !ok || err != nil {
				return ok, err
			}
		} else if before != nil && !before(ctx, conn) {
			return false, nil
		}
		// Ordinary pgx Acquire releases a resource on true+error. Its PUBLIC
		// AcquireAllIdle instead destroys on any error and is not used by the
		// application critical pools (nor by pgx's internal puddle maintenance).
		// Metadata describes socket lifecycle, never a grant.
		// Driver idle Ping runs BEFORE this callback. A deadline expiring
		// during that Ping can still destroy a socket; this guard only protects
		// first handoff once PrepareConn is reached.
		return prepareFresh(ctx, conn.PgConn().CustomData())
	}
}

// Configure preserves the caller's fixed connection budget and TLS/leader
// selection. Constructors can finish after a 3s request acquisition expires.
func Configure(cfg *pgxpool.Config, maximum int32, critical bool) error {
	if cfg == nil || cfg.ConnConfig == nil || maximum < 1 {
		return ErrInvalid
	}
	cfg.MaxConns = maximum
	cfg.MinConns = 0
	cfg.MinIdleConns = 0
	cfg.ConnConfig.ConnectTimeout = ConnectTimeout
	if critical {
		cfg.MinConns = maximum
		cfg.HealthCheckPeriod = HealthCheckPeriod
		preserveFirstUse(cfg)
	}
	return nil
}

// Warm verifies all configured minimum slots before bootstrap authorization.
// Holding them together prevents successive acquisitions warming one socket
// repeatedly. Pings are transport checks; they cannot renew policy freshness.
func Warm(parent context.Context, pools ...*pgxpool.Pool) error {
	if parent == nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, WarmTimeout)
	defer cancel()
	var held []*pgxpool.Conn
	defer func() {
		for _, conn := range held {
			conn.Release()
		}
	}()
	for _, pool := range pools {
		if pool == nil {
			return ErrInvalid
		}
		cfg := pool.Config()
		if cfg.MinConns < 0 || cfg.MinConns > cfg.MaxConns {
			return ErrInvalid
		}
		for range cfg.MinConns {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				return err
			}
			held = append(held, conn)
			if err := conn.Ping(ctx); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
