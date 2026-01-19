package core

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
)

var (
	Ctx          = context.Background()
	UserDB       *redis.Client
	TokenDB      *redis.Client
	RateLimitDB  *redis.Client
	AuditDB      *redis.Client
)

func InitRedis(cfg *Config) error {
	UserDB = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort),
		Password: cfg.RedisPassword,
		DB:       0,
	})

	TokenDB = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort),
		Password: cfg.RedisPassword,
		DB:       1,
	})

	RateLimitDB = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort),
		Password: cfg.RedisPassword,
		DB:       2,
	})

	AuditDB = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.RedisHost, cfg.RedisPort),
		Password: cfg.RedisPassword,
		DB:       3,
	})

	return UserDB.Ping(Ctx).Err()
}
