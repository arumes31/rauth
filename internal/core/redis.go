package core

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
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

	pipe := TokenDB.Pipeline()
	for _, token := range tokens {
		pipe.Del(Ctx, "X-rauth-authtoken="+token)
	}
	pipe.Del(Ctx, indexKey)
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

	pipe := TokenDB.Pipeline()
	for _, token := range tokens {
		if token == currentToken {
			continue
		}
		pipe.Del(Ctx, "X-rauth-authtoken="+token)
		pipe.SRem(Ctx, indexKey, token)
	}
	if _, err := pipe.Exec(Ctx); err != nil {
		slog.Error("Failed to execute InvalidateOtherUserSessions pipeline", "error", err)
	}
}

// HasActiveSessions reports whether the given IP currently has a valid session.
// It consults the per-IP index (maintained at session issue time) rather than
// scanning the entire token keyspace, and prunes stale members it encounters.
func HasActiveSessions(ip string) bool {
	indexKey := "ip_sessions:" + ip
	tokens, err := TokenDB.SMembers(Ctx, indexKey).Result()
	if err != nil || len(tokens) == 0 {
		return false
	}

	pipe := TokenDB.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, len(tokens))
	for i, token := range tokens {
		cmds[i] = pipe.HGetAll(Ctx, "X-rauth-authtoken="+token)
	}

	_, _ = pipe.Exec(Ctx)

	var hasActive bool
	var toPrune []any
	for i, cmd := range cmds {
		data, err := cmd.Result()
		if err == nil && len(data) > 0 && data["status"] == "valid" {
			hasActive = true
		} else {
			toPrune = append(toPrune, tokens[i])
		}
	}

	if len(toPrune) > 0 {
		TokenDB.SRem(Ctx, indexKey, toPrune...)
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
	var live int64
	var cursor uint64

	for {
		keys, nextCursor, err := TokenDB.Scan(Ctx, cursor, pattern, 100).Result()
		if err != nil {
			slog.Error("SyncSessionIndexes: Scan failed", "pattern", pattern, "error", err)
			break
		}

		for _, indexKey := range keys {
			tokens, err := TokenDB.SMembers(Ctx, indexKey).Result()
			if err != nil || len(tokens) == 0 {
				continue
			}

			pipe := TokenDB.Pipeline()
			cmds := make([]*redis.MapStringStringCmd, len(tokens))
			for i, token := range tokens {
				cmds[i] = pipe.HGetAll(Ctx, "X-rauth-authtoken="+token)
			}

			_, _ = pipe.Exec(Ctx)

			var toPrune []any
			for i, cmd := range cmds {
				data, err := cmd.Result()
				if err == nil && len(data) > 0 && data["status"] == "valid" {
					live++
				} else {
					toPrune = append(toPrune, tokens[i])
				}
			}

			if len(toPrune) > 0 {
				TokenDB.SRem(Ctx, indexKey, toPrune...)
			}
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
