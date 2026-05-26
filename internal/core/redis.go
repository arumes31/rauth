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
	keys, err := TokenDB.SMembers(Ctx, "user_sessions:"+username).Result()
	if err != nil {
		return
	}

	pipe := TokenDB.Pipeline()
	for _, k := range keys {
		pipe.Del(Ctx, k)
	}
	pipe.Del(Ctx, "user_sessions:"+username)
	pipe.Exec(Ctx)
}

func InvalidateOtherUserSessions(username, currentToken string) {
	keys, err := TokenDB.SMembers(Ctx, "user_sessions:"+username).Result()
	if err != nil {
		return
	}

	pipe := TokenDB.Pipeline()
	for _, k := range keys {
		if k == "X-rauth-authtoken="+currentToken {
			continue
		}
		pipe.Del(Ctx, k)
		pipe.SRem(Ctx, "user_sessions:"+username, k)
	}
	pipe.Exec(Ctx)
}

func HasActiveSessions(ip string) bool {
	iter := TokenDB.Scan(Ctx, 0, "X-rauth-authtoken=*", 0).Iterator()
	for iter.Next(Ctx) {
		k := iter.Val()
		data, err := TokenDB.HGetAll(Ctx, k).Result()
		if err == nil && data["ip"] == ip && data["status"] == "valid" {
			return true
		}
	}
	return false
}

func AddSessionToIndex(username, key string) {
	TokenDB.SAdd(Ctx, "user_sessions:"+username, key)
}

func RemoveSessionFromIndex(username, key string) {
	TokenDB.SRem(Ctx, "user_sessions:"+username, key)
}

func DeleteSession(key string) {
	data, err := TokenDB.HGetAll(Ctx, key).Result()
	if err == nil && data["username"] != "" {
		RemoveSessionFromIndex(data["username"], key)
	}
	TokenDB.Del(Ctx, key)
}

func copyOptions(base *redis.Options, db int) *redis.Options {
	clone := *base
	clone.DB = db
	return &clone
}
