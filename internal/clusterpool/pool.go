// Package clusterpool warms existing authority transports, never grants or leases.
package clusterpool

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const ConnectTimeout = 5 * time.Second
const WarmTimeout = 15 * time.Second
const HealthCheckPeriod = 2 * time.Second

var ErrInvalid = errors.New("invalid cluster authority pool")

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
