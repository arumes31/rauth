package authstate

import (
	"context"
	"errors"
	"strings"
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
func (c *PostgresCounters) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	h, err := c.hash(key)
	if err != nil {
		return 0, err
	}
	if ttl < time.Second || ttl > 7*24*time.Hour {
		return 0, errors.New("invalid security counter duration")
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	var count int64
	err = c.s.pool.QueryRow(ctx, `INSERT INTO auth_security_counters(key_hash,count,expires_at) VALUES($1,1,clock_timestamp()+make_interval(secs=>$2))
  ON CONFLICT(key_hash) DO UPDATE SET count=CASE WHEN auth_security_counters.expires_at<=clock_timestamp() THEN 1 ELSE LEAST(auth_security_counters.count+1,1000000000) END,
  expires_at=CASE WHEN auth_security_counters.expires_at<=clock_timestamp() THEN EXCLUDED.expires_at ELSE auth_security_counters.expires_at END RETURNING count`, h, ttl.Seconds()).Scan(&count)
	return count, err
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
