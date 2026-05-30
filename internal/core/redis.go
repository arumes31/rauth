package core

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"log/slog"
	"strings"
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

func InitRedis(cfg *Config) error {
	ServerSecret = cfg.ServerSecret
	opts := &redis.Options{
		Addr:         fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort),
		Password:     cfg.RedisPassword,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     20,
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
	keysToDel := make([]string, 0, len(tokens)+1)
	for _, token := range tokens {
		keysToDel = append(keysToDel, "X-rauth-authtoken="+token)
	}
	keysToDel = append(keysToDel, indexKey)

	pipe.Del(Ctx, keysToDel...)
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

	if len(tokens) == 0 {
		return
	}

	keysToDel := make([]string, 0, len(tokens))
	tokensToRemove := make([]interface{}, 0, len(tokens))

	for _, token := range tokens {
		if token == currentToken {
			continue
		}
		keysToDel = append(keysToDel, "X-rauth-authtoken="+token)
		tokensToRemove = append(tokensToRemove, token)
	}

	if len(keysToDel) == 0 {
		return
	}

	pipe := TokenDB.Pipeline()
	pipe.Del(Ctx, keysToDel...)
	pipe.SRem(Ctx, indexKey, tokensToRemove...)
	if _, err := pipe.Exec(Ctx); err != nil {
		slog.Error("Failed to execute InvalidateOtherUserSessions pipeline", "error", err)
	}
}

func HasActiveSessions(ip string) bool {
	var cursor uint64
	for {
		keys, nextCursor, err := TokenDB.Scan(Ctx, cursor, "X-rauth-authtoken=*", 100).Result()
		if err != nil {
			return false
		}

		if len(keys) > 0 {
			pipe := TokenDB.Pipeline()
			cmds := make([]*redis.MapStringStringCmd, len(keys))
			for i, k := range keys {
				cmds[i] = pipe.HGetAll(Ctx, k)
			}
			_, _ = pipe.Exec(Ctx)

			for _, cmd := range cmds {
				data, err := cmd.Result()
				if err == nil && data["ip"] == ip && data["status"] == "valid" {
					return true
				}
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return false
}

func AddSessionIndex(username, token string) {
	TokenDB.SAdd(Ctx, "user_sessions:"+username, token)
}

func RemoveSessionIndex(username, token string) {
	TokenDB.SRem(Ctx, "user_sessions:"+username, token)
}

func SyncSessionIndexes() int64 {
	var count int64
	var cursor uint64
	const prefix = "X-rauth-authtoken="

	for {
		keys, nextCursor, err := TokenDB.Scan(Ctx, cursor, prefix+"*", 100).Result()
		if err != nil {
			slog.Error("SyncSessionIndexes: Scan failed", "error", err)
			break
		}

		if len(keys) > 0 {
			pipe := TokenDB.Pipeline()
			cmds := make([]*redis.MapStringStringCmd, len(keys))
			for i, key := range keys {
				cmds[i] = pipe.HGetAll(Ctx, key)
			}
			_, _ = pipe.Exec(Ctx)

			saddPipe := TokenDB.Pipeline()
			addedAny := false
			for i, key := range keys {
				data, err := cmds[i].Result()
				if err != nil || len(data) == 0 {
					continue
				}

				username := data["username"]
				if username != "" && data["status"] == "valid" {
					token := strings.TrimPrefix(key, prefix)
					if token != key {
						saddPipe.SAdd(Ctx, "user_sessions:"+username, token)
						count++
						addedAny = true
					} else {
						slog.Warn("SyncSessionIndexes: token key missing expected prefix", "key", key)
					}
				}
			}
			if addedAny {
				if _, err := saddPipe.Exec(Ctx); err != nil {
					slog.Error("SyncSessionIndexes: SAdd pipeline failed", "error", err)
				}
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return count
}

func copyOptions(base *redis.Options, db int) *redis.Options {
	clone := *base
	clone.DB = db
	return &clone
}
