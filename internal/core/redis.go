package core

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"log/slog"
	"time"
)

var (
	Ctx          = context.Background()
	UserDB       *redis.Client
	TokenDB      *redis.Client
	RateLimitDB  *redis.Client
	AuditDB      *redis.Client
	InviteDB     *redis.Client
	ServerSecret string
	StartTime    = time.Now()
)

// redisPoolSize is the per-database connection pool size.
const redisPoolSize = 20

func InitRedis(cfg *Config) error {
	ServerSecret = cfg.ServerSecret
	opts := &redis.Options{
		Addr:         fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort),
		Password:     cfg.RedisPassword,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     redisPoolSize,
		PoolTimeout:  30 * time.Second,
	}

	UserDB = redis.NewClient(copyOptions(opts, 0))
	TokenDB = redis.NewClient(copyOptions(opts, 1))
	RateLimitDB = redis.NewClient(copyOptions(opts, 2))
	AuditDB = redis.NewClient(copyOptions(opts, 3))
	InviteDB = redis.NewClient(copyOptions(opts, 4))

	// Ping all
	for i, client := range []*redis.Client{UserDB, TokenDB, RateLimitDB, AuditDB, InviteDB} {
		if err := client.Ping(Ctx).Err(); err != nil {
			return fmt.Errorf("failed to connect to Redis DB %d: %w", i, err)
		}
	}

	return nil
}

func InvalidateUserSessions(username string) {
	indexKey := "user_sessions:" + username
	tokens, err := TokenDB.SMembers(Ctx, indexKey).Result()
	if err != nil {
		return
	}

	if len(tokens) == 0 {
		return
	}

	// ⚡ Bolt optimization: Batch variadic string keys to delete in one pipeline round trip.
	var toDel []string
	for _, token := range tokens {
		toDel = append(toDel, "X-rauth-authtoken="+token)
	}
	toDel = append(toDel, indexKey)

	pipe := TokenDB.Pipeline()
	pipe.Del(Ctx, toDel...)
	if _, err := pipe.Exec(Ctx); err != nil {
		slog.Error("Failed to execute InvalidateUserSessions pipeline", "error", err)
	}
}

func InvalidateOtherUserSessions(username, currentToken string) {
	indexKey := "user_sessions:" + username
	tokens, err := TokenDB.SMembers(Ctx, indexKey).Result()
	if err != nil {
		return
	}

	// ⚡ Bolt optimization: Accumulate keys and batch delete/remove with variadic commands.
	var toDel []string
	var toRem []interface{}
	for _, token := range tokens {
		if token == currentToken {
			continue
		}
		toDel = append(toDel, "X-rauth-authtoken="+token)
		toRem = append(toRem, token)
	}

	if len(toDel) > 0 {
		pipe := TokenDB.Pipeline()
		pipe.Del(Ctx, toDel...)
		pipe.SRem(Ctx, indexKey, toRem...)
		if _, err := pipe.Exec(Ctx); err != nil {
			slog.Error("Failed to execute InvalidateOtherUserSessions pipeline", "error", err)
		}
	}
}

// HasActiveSessions reports whether the given IP currently has a valid session.
// It consults the per-IP index (maintained at session issue time) rather than
// scanning the entire token keyspace, and prunes stale members it encounters.
func HasActiveSessions(ip string) bool {
	indexKey := "ip_sessions:" + ip
	tokens, err := TokenDB.SMembers(Ctx, indexKey).Result()
	if err != nil {
		return false
	}

	if len(tokens) == 0 {
		return false
	}

	// ⚡ Bolt optimization: Batch HGet requests to avoid N+1 queries.
	pipe := TokenDB.Pipeline()
	cmds := make(map[string]*redis.StringCmd, len(tokens))
	for _, token := range tokens {
		cmds[token] = pipe.HGet(Ctx, "X-rauth-authtoken="+token, "status")
	}
	_, err = pipe.Exec(Ctx)
	if err != nil && err != redis.Nil {
		// A non-nil error from Exec means the pipeline completely failed.
		// We shouldn't erroneously prune all tokens or return an incorrect result.
		return false
	}

	var stale []interface{}
	hasActive := false
	for _, token := range tokens {
		status, err := cmds[token].Result()
		if err == nil && status == "valid" {
			hasActive = true
		} else {
			stale = append(stale, token)
		}
	}

	if len(stale) > 0 {
		TokenDB.SRem(Ctx, indexKey, stale...)
	}
	return hasActive
}

func AddSessionIndex(username, token string) {
	TokenDB.SAdd(Ctx, "user_sessions:"+username, token)
}

func RemoveSessionIndex(username, token string) {
	TokenDB.SRem(Ctx, "user_sessions:"+username, token)
}

// AddIPSessionIndex records a session token under its origin IP so brute-force
// checks can look up active sessions for an IP without a full keyspace scan.
func AddIPSessionIndex(ip, token string) {
	TokenDB.SAdd(Ctx, "ip_sessions:"+ip, token)
}

// RemoveIPSessionIndex removes a token from its per-IP session index.
func RemoveIPSessionIndex(ip, token string) {
	TokenDB.SRem(Ctx, "ip_sessions:"+ip, token)
}

// SyncSessionIndexes reconciles the session index sets with live token state:
// it walks the bounded set of index keys (one per user / per IP) rather than
// the entire token keyspace, prunes entries whose tokens have expired or been
// invalidated, and returns the number of live sessions for the gauge.
func SyncSessionIndexes() int64 {
	var count int64
	count += reconcileIndexSets("user_sessions:*")
	reconcileIndexSets("ip_sessions:*")
	return count
}

// reconcileIndexSets prunes dead token members from every index set matching
// pattern and returns the number of live members across those sets.
func reconcileIndexSets(pattern string) int64 {
	if TokenDB == nil {
		return 0
	}
	var live int64
	var cursor uint64

	for {
		keys, nextCursor, err := TokenDB.Scan(Ctx, cursor, pattern, 100).Result()
		if err != nil {
			slog.Error("SyncSessionIndexes: Scan failed", "pattern", pattern, "error", err)
			break
		}

		if len(keys) == 0 {
			cursor = nextCursor
			if cursor == 0 {
				break
			}
			continue
		}

		// Phase 1: Batch SMembers requests across all keys to gather tokens
		pipe1 := TokenDB.Pipeline()
		smembersCmds := make(map[string]*redis.StringSliceCmd, len(keys))
		for _, indexKey := range keys {
			smembersCmds[indexKey] = pipe1.SMembers(Ctx, indexKey)
		}
		_, _ = pipe1.Exec(Ctx)

		// Phase 2: Batch HGet requests for status across all unique tokens
		pipe2 := TokenDB.Pipeline()
		hgetCmds := make(map[string]*redis.StringCmd)
		for _, indexKey := range keys {
			tokens, err := smembersCmds[indexKey].Result()
			if err != nil || len(tokens) == 0 {
				continue
			}
			for _, token := range tokens {
				if _, exists := hgetCmds[token]; !exists {
					hgetCmds[token] = pipe2.HGet(Ctx, "X-rauth-authtoken="+token, "status")
				}
			}
		}

		if len(hgetCmds) > 0 {
			_, _ = pipe2.Exec(Ctx)
		}

		// Phase 3: Evaluate liveness and batch removals per index key
		pipe3 := TokenDB.Pipeline()
		hasRemovals := false

		for _, indexKey := range keys {
			tokens, _ := smembersCmds[indexKey].Result()
			var stale []interface{}
			for _, token := range tokens {
				cmd := hgetCmds[token]
				if cmd != nil {
					status, err := cmd.Result()
					if err == nil && status == "valid" {
						live++
						continue
					}
				}
				stale = append(stale, token)
			}
			if len(stale) > 0 {
				pipe3.SRem(Ctx, indexKey, stale...)
				hasRemovals = true
			}
		}

		if hasRemovals {
			_, _ = pipe3.Exec(Ctx)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return live
}

func copyOptions(base *redis.Options, db int) *redis.Options {
	clone := *base
	clone.DB = db
	return &clone
}
