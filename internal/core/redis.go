package core

import (
	"log/slog"
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
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

func HasActiveSessions(ip string) bool {
	var cursor uint64
	for {
		keys, nextCursor, err := TokenDB.Scan(Ctx, cursor, "X-rauth-authtoken=*", 100).Result()
		if err != nil {
			return false
		}

		for _, k := range keys {
			data, err := TokenDB.HGetAll(Ctx, k).Result()
			if err == nil && data["ip"] == ip && data["status"] == "valid" {
				return true
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

func copyOptions(base *redis.Options, db int) *redis.Options {
	clone := *base
	clone.DB = db
	return &clone
}
