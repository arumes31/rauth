package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func BenchmarkEnsureUserUIDsBackfill(b *testing.B) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	UserDB = client
	Ctx = context.Background()
	AuditDB = client

	// Setup 1000 users missing UIDs
	for i := 0; i < 1000; i++ {
		username := fmt.Sprintf("user%d", i)
		UserDB.SAdd(Ctx, "users", username)
		UserDB.HSet(Ctx, "user:"+username, "username", username)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Inside the benchmark loop we must reset the users to state without UIDs
		b.StopTimer()
		// Flush all UIDs to ensure backfill happens each time
		keys, _ := UserDB.Keys(Ctx, "uid:*").Result()
		if len(keys) > 0 {
			UserDB.Del(Ctx, keys...)
		}
		keysBin, _ := UserDB.Keys(Ctx, "uid_bin:*").Result()
		if len(keysBin) > 0 {
			UserDB.Del(Ctx, keysBin...)
		}
		for j := 0; j < 1000; j++ {
			UserDB.HDel(Ctx, fmt.Sprintf("user:user%d", j), "uid")
		}
		b.StartTimer()

		EnsureUserUIDs()
	}
}
