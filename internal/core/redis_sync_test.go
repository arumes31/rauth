package core

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestSyncSessionIndexes(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	TokenDB = client
	Ctx = context.Background()

	// user1: token1 (valid), token2 (stale - missing)
	AddSessionIndex("user1", "token1")
	AddSessionIndex("user1", "token2")
	TokenDB.HSet(Ctx, "X-rauth-authtoken=token1", map[string]string{
		"status": "valid",
	})

	// user2: token3 (valid)
	AddSessionIndex("user2", "token3")
	TokenDB.HSet(Ctx, "X-rauth-authtoken=token3", map[string]string{
		"status": "valid",
	})

	// ip1: token4 (invalid status)
	AddIPSessionIndex("1.2.3.4", "token4")
	TokenDB.HSet(Ctx, "X-rauth-authtoken=token4", map[string]string{
		"status": "expired",
	})

	count := SyncSessionIndexes()
	require.Equal(t, int64(2), count)

	// Verify pruning
	m1, _ := TokenDB.SMembers(Ctx, "user_sessions:user1").Result()
	require.Contains(t, m1, "token1")
	require.NotContains(t, m1, "token2")
	require.Len(t, m1, 1)

	m2, _ := TokenDB.SMembers(Ctx, "user_sessions:user2").Result()
	require.Contains(t, m2, "token3")
	require.Len(t, m2, 1)

	m3, _ := TokenDB.SMembers(Ctx, "ip_sessions:1.2.3.4").Result()
	require.Empty(t, m3)
}
