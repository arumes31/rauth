package authstate

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

type CounterStore interface {
	Increment(context.Context, string, time.Duration) (int64, error)
	Count(context.Context, string) (int64, error)
	Reset(context.Context, string) error
	MarkTOTP(context.Context, string, string, time.Duration) (bool, error)
}
type PostgresCounters struct{ s *PostgresSessions }

func (s *PostgresSessions) Counters() *PostgresCounters { return &PostgresCounters{s: s} }

var _ CounterStore = (*PostgresCounters)(nil)

func (c *PostgresCounters) hash(key string) ([]byte, error) {
	if key == "" || len(key) > 1024 {
		return nil, errors.New("invalid security counter key")
	}
	return c.s.keys.stateHash("security-counter", key), nil
}

// Increment adds one to the counter. Concurrent increments of the same counter
// in this process are coalesced into one SQL statement: a burst from one client
// (a page load, polling tabs) otherwise serializes on the row lock, one
// synchronous-replication commit after another, and exhausts the pool. Each
// caller still receives a distinct count, exactly as if the increments had run
// one by one, so rate-limit decisions are unchanged. Errors fail closed for
// every joined caller.
func (c *PostgresCounters) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	h, err := c.hash(key)
	if err != nil {
		return 0, err
	}
	if ttl < time.Second || ttl > 7*24*time.Hour {
		return 0, errors.New("invalid security counter duration")
	}
	return c.s.counters.increment(ctx, h, ttl, c.add)
}

// add applies n increments in one statement and returns the resulting count.
func (c *PostgresCounters) add(ctx context.Context, h []byte, ttl time.Duration, n int64) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	var count int64
	err := c.s.pool.QueryRow(ctx, `INSERT INTO auth_security_counters(key_hash,count,expires_at) VALUES($1,$3,clock_timestamp()+make_interval(secs=>$2))
  ON CONFLICT(key_hash) DO UPDATE SET count=CASE WHEN auth_security_counters.expires_at<=clock_timestamp() THEN $3 ELSE LEAST(auth_security_counters.count+$3,$4) END,
  expires_at=CASE WHEN auth_security_counters.expires_at<=clock_timestamp() THEN EXCLUDED.expires_at ELSE auth_security_counters.expires_at END RETURNING count`, h, ttl.Seconds(), n, int64(counterCap)).Scan(&count)
	return count, err
}

// counterCap is where stored counts saturate.
const counterCap = 1_000_000_000

type counterAdd func(context.Context, []byte, time.Duration, int64) (int64, error)

// counterBatch collects increments that arrive while an earlier statement for
// the same counter is in flight.
type counterBatch struct {
	n     int64
	done  chan struct{}
	count int64
	err   error
}

// counterCoalescer is usable as a zero value. At most one statement per
// counter (key hash and duration) is in flight; later arrivals join one open
// batch that is flushed as soon as the previous statement completes.
type counterCoalescer struct {
	mu   sync.Mutex
	open map[string]*counterBatch
	busy map[string]bool
	// wait bounds how long a caller waits for its batch, including time spent
	// queued behind an earlier statement (zero means mutationTimeout).
	wait time.Duration
}

func (co *counterCoalescer) increment(ctx context.Context, h []byte, ttl time.Duration, add counterAdd) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	k := string(h) + "\x00" + ttl.String()
	co.mu.Lock()
	if co.open == nil {
		co.open, co.busy = map[string]*counterBatch{}, map[string]bool{}
	}
	b := co.open[k]
	if b == nil {
		b = &counterBatch{done: make(chan struct{})}
		co.open[k] = b
		if !co.busy[k] {
			co.busy[k] = true
			// Detached from cancellation (not from values): one canceled request
			// must not fail the others joined to the same batch.
			go co.flush(context.WithoutCancel(ctx), k, h, ttl, add)
		}
	}
	b.n++
	position := b.n
	wait := co.wait
	co.mu.Unlock()
	if wait <= 0 {
		wait = mutationTimeout
	}
	// A caller that joins while an earlier statement is stalled must not wait
	// for that statement's timeout and then its own: one budget, fail closed.
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-b.done:
		if b.err != nil {
			return 0, b.err
		}
		if b.count >= counterCap {
			// Saturated: count-n would invent values below the stored count.
			return b.count, nil
		}
		// The batch moved the counter from count-n to count; this caller is
		// the position-th of those n increments.
		return b.count - b.n + position, nil
	case <-ctx.Done():
		// The increment may still be applied; counting an abandoned attempt
		// only makes the limiter stricter.
		return 0, ctx.Err()
	case <-timer.C:
		return 0, context.DeadlineExceeded
	}
}

// flush applies batches until none is open; each statement has its own
// mutation timeout.
func (co *counterCoalescer) flush(ctx context.Context, k string, h []byte, ttl time.Duration, add counterAdd) {
	for {
		co.mu.Lock()
		b := co.open[k]
		if b == nil {
			delete(co.busy, k)
			co.mu.Unlock()
			return
		}
		delete(co.open, k)
		co.mu.Unlock()
		b.count, b.err = add(ctx, h, ttl, b.n)
		close(b.done)
	}
}
func (c *PostgresCounters) Count(ctx context.Context, key string) (int64, error) {
	h, err := c.hash(key)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var count int64
	err = c.s.pool.QueryRow(ctx, "SELECT COALESCE((SELECT count FROM auth_security_counters WHERE key_hash=$1 AND expires_at>clock_timestamp()),0)", h).Scan(&count)
	return count, err
}
func (c *PostgresCounters) Reset(ctx context.Context, key string) error {
	h, err := c.hash(key)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	_, err = c.s.pool.Exec(ctx, "DELETE FROM auth_security_counters WHERE key_hash=$1", h)
	return err
}

// MarkTOTP returns true only for the first reservation of this normalized
// user/code pair. The marker is global, fixed-window, and never stores the code.
func (c *PostgresCounters) MarkTOTP(ctx context.Context, user, code string, ttl time.Duration) (bool, error) {
	code = strings.TrimSpace(code)
	if user == "" || len(user) > 256 || code == "" || len(code) > 128 || ttl < time.Second || ttl > 5*time.Minute {
		return false, errors.New("invalid replay marker")
	}
	h := c.s.keys.stateHash("totp-replay", user+"\x00"+code)
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	tag, err := c.s.pool.Exec(ctx, `INSERT INTO auth_replay_markers(key_hash,expires_at) VALUES($1,clock_timestamp()+make_interval(secs=>$2))
  ON CONFLICT(key_hash) DO UPDATE SET expires_at=EXCLUDED.expires_at WHERE auth_replay_markers.expires_at<=clock_timestamp()`, h, ttl.Seconds())
	return tag.RowsAffected() == 1, err
}
