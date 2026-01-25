package core

import (
	"context"
	"fmt"
	"time"
	"github.com/redis/go-redis/v9"
)

var (
	Ctx          = context.Background()
	UserDB       *redis.Client
	TokenDB      *redis.Client
	RateLimitDB  *redis.Client
	AuditDB      *redis.Client
	ServerSecret string
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

	// Ping all
	for i, client := range []*redis.Client{UserDB, TokenDB, RateLimitDB, AuditDB} {
		if err := client.Ping(Ctx).Err(); err != nil {
			return fmt.Errorf("failed to connect to Redis DB %d: %w", i, err)
		}
	}

	return nil
}

func InvalidateUserSessions(username string) {
	keys, err := TokenDB.Keys(Ctx, "X-rauth-authtoken=*").Result()
	if err != nil {
		return
	}

	for _, k := range keys {
		data, err := TokenDB.HGetAll(Ctx, k).Result()
		if err == nil && data["username"] == username {
			TokenDB.Del(Ctx, k)
		}
	}
}

func copyOptions(base *redis.Options, db int) *redis.Options {
	clone := *base
	clone.DB = db
	return &clone
}
