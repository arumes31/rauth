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
	if err != nil {
		return false
	}

	if len(tokens) == 0 {
		return false
	}

	pipe := TokenDB.Pipeline()
	cmds := make(map[string]*redis.MapStringStringCmd, len(tokens))
	for _, token := range tokens {
		cmds[token] = pipe.HGetAll(Ctx, "X-rauth-authtoken="+token)
	}

	if _, err := pipe.Exec(Ctx); err != nil && err != redis.Nil {
		slog.Error("HasActiveSessions: Pipeline failed", "ip", ip, "error", err)
	}

	var hasActive bool
	prunePipe := TokenDB.Pipeline()
	hasPrunes := false
	for _, token := range tokens {
		data, err := cmds[token].Result()
		if err == nil && len(data) > 0 && data["status"] == "valid" {
			hasActive = true
			continue
		}
		// Token expired or was invalidated: drop the dangling index entry.
		prunePipe.SRem(Ctx, indexKey, token)
		hasPrunes = true
	}

	if hasPrunes {
		if _, err := prunePipe.Exec(Ctx); err != nil {
			slog.Error("HasActiveSessions: Prune pipeline failed", "ip", ip, "error", err)
		}
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

		if len(keys) > 0 {
			// Phase 1: Batch fetch SMembers for all keys in this Scan batch
			pipe := TokenDB.Pipeline()
			smemberCmds := make([]*redis.StringSliceCmd, len(keys))
			for i, key := range keys {
				smemberCmds[i] = pipe.SMembers(Ctx, key)
			}
			if _, err := pipe.Exec(Ctx); err != nil && err != redis.Nil {
				slog.Error("SyncSessionIndexes: SMembers pipeline failed", "error", err)
			}

			// Collect all unique tokens and map them back to their origin index keys
			tokenToIndexKeys := make(map[string][]string)
			for i, cmd := range smemberCmds {
				tokens, err := cmd.Result()
				if err != nil {
					continue
				}
				for _, token := range tokens {
					tokenToIndexKeys[token] = append(tokenToIndexKeys[token], keys[i])
				}
			}

			if len(tokenToIndexKeys) > 0 {
				// Phase 2: Batch fetch HGetAll for all found tokens
				pipe = TokenDB.Pipeline()
				hgetCmds := make(map[string]*redis.MapStringStringCmd)
				for token := range tokenToIndexKeys {
					hgetCmds[token] = pipe.HGetAll(Ctx, "X-rauth-authtoken="+token)
				}
				if _, err := pipe.Exec(Ctx); err != nil && err != redis.Nil {
					slog.Error("SyncSessionIndexes: HGetAll pipeline failed", "error", err)
				}

				// Phase 3: Prune dead tokens and count live ones
				prunePipe := TokenDB.Pipeline()
				hasPrunes := false
				for token, cmd := range hgetCmds {
					data, err := cmd.Result()
					if err == nil && len(data) > 0 && data["status"] == "valid" {
						// This token is valid; increment live count for EACH index set it belongs to
						// (since live count is aggregated across user_sessions:*).
						live += int64(len(tokenToIndexKeys[token]))
						continue
					}

					// Dead/expired token: drop it from all index sets that reference it
					for _, indexKey := range tokenToIndexKeys[token] {
						prunePipe.SRem(Ctx, indexKey, token)
						hasPrunes = true
					}
				}
				if hasPrunes {
					if _, err := prunePipe.Exec(Ctx); err != nil {
						slog.Error("SyncSessionIndexes: Prune pipeline failed", "error", err)
					}
				}
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
