package core

import "github.com/redis/go-redis/v9"

func init() {
	// Initialize global Redis clients to prevent nil pointer dereferences
	// in background goroutines (like SyncSessionIndexes) during tests.
	UserDB = redis.NewClient(&redis.Options{})
	TokenDB = redis.NewClient(&redis.Options{})
	RateLimitDB = redis.NewClient(&redis.Options{})
	AuditDB = redis.NewClient(&redis.Options{})
	InviteDB = redis.NewClient(&redis.Options{})
}
