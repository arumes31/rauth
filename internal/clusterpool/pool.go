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
const freshSinceKey = "rauth.clusterpool.authenticated_at"

// A socket that was just authenticated and validated has proven liveness. With
// TLS+SCRAM at 400ms per write, construction alone takes ~2.85s, so pgx's
// default idle ping (idle measured from creation) would push the first handoff
// past the caller's 3s and destroy the new socket on every attempt. Only young,
// never-handed-out sockets skip the ping; older warm sockets are still checked.
// Age is measured from authentication, because a rejected first use releases
// the socket and resets pgx's idle clock.
const freshPingGrace = 30 * time.Second

func skipFreshPing(data map[string]any, now time.Time) bool {
	fresh, _ := data[freshConnectionKey].(bool)
	since, ok := data[freshSinceKey].(time.Time)
	return fresh && ok && now.Sub(since) < freshPingGrace
}

func shouldPingFresh(next func(context.Context, pgxpool.ShouldPingParams) bool) func(context.Context, pgxpool.ShouldPingParams) bool {
	return func(ctx context.Context, p pgxpool.ShouldPingParams) bool {
		if p.Conn != nil && skipFreshPing(p.Conn.PgConn().CustomData(), time.Now()) {
			return false
		}
		if next != nil {
			return next(ctx, p)
		}
		return p.IdleDuration > time.Second
	}
}

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
		conn.PgConn().CustomData()[freshSinceKey] = time.Now()
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
		// Driver idle Ping runs BEFORE this callback; shouldPingFresh keeps
		// it from consuming a fresh socket's remaining budget.
		return prepareFresh(ctx, conn.PgConn().CustomData())
	}
	cfg.ShouldPing = shouldPingFresh(cfg.ShouldPing)
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

// CloseTimeout bounds how long shutdown waits for authority pools to close.
const CloseTimeout = 2 * time.Second

// CloseBounded closes pools in parallel and returns once all have closed or
// timeout elapses, reporting whether every pool finished. pgx waits for
// connections that are still being established when a pool closes, and over a
// slow WAN that can take seconds; shutdown must not depend on it. Pools that
// are still closing finish in the background.
func CloseBounded(timeout time.Duration, pools ...*pgxpool.Pool) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		finished := make(chan struct{}, len(pools))
		for _, pool := range pools {
			go func() {
				if pool != nil {
					pool.Close()
				}
				finished <- struct{}{}
			}()
		}
		for range pools {
			<-finished
		}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}
