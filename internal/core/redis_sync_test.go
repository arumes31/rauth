package core

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncSessionIndexes(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	// Save and restore global state
	oldTokenDB := TokenDB
	oldCtx := Ctx
	defer func() { TokenDB = oldTokenDB; Ctx = oldCtx }()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	TokenDB = client
	Ctx = context.Background()

	// Setup valid sessions
	TokenDB.HSet(Ctx, "X-rauth-authtoken=valid1", "status", "valid")
	TokenDB.HSet(Ctx, "X-rauth-authtoken=valid2", "status", "valid")

	// Setup invalid/stale sessions
	TokenDB.HSet(Ctx, "X-rauth-authtoken=invalid1", "status", "invalid")
	// missing1 has no hash

	// Add to user indexes
	TokenDB.SAdd(Ctx, "user_sessions:user1", "valid1", "invalid1", "missing1")
	TokenDB.SAdd(Ctx, "user_sessions:user2", "valid2")

	// Add to IP indexes
	TokenDB.SAdd(Ctx, "ip_sessions:127.0.0.1", "valid1", "invalid1")
	TokenDB.SAdd(Ctx, "ip_sessions:192.168.1.1", "missing1", "valid2")

	// Call SyncSessionIndexes
	liveCount := SyncSessionIndexes()

	// Verify live count: only valid1 and valid2 should be counted. Since user_sessions are counted and ip_sessions are not (count += reconcileIndexSets("user_sessions:*"); reconcileIndexSets("ip_sessions:*")), the return value should be 2.
	assert.Equal(t, int64(2), liveCount)

	// Verify user1 index is pruned
	user1Members, err := TokenDB.SMembers(Ctx, "user_sessions:user1").Result()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"valid1"}, user1Members)

	// Verify user2 index is untouched (all valid)
	user2Members, err := TokenDB.SMembers(Ctx, "user_sessions:user2").Result()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"valid2"}, user2Members)

	// Verify IP indexes are pruned
	ip1Members, err := TokenDB.SMembers(Ctx, "ip_sessions:127.0.0.1").Result()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"valid1"}, ip1Members)

	ip2Members, err := TokenDB.SMembers(Ctx, "ip_sessions:192.168.1.1").Result()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"valid2"}, ip2Members)
}

func TestSyncSessionIndexes_NilTokenDB(t *testing.T) {
	// Temporarily set TokenDB to nil
	oldTokenDB := TokenDB
	TokenDB = nil
	defer func() { TokenDB = oldTokenDB }()

	liveCount := SyncSessionIndexes()
	assert.Equal(t, int64(0), liveCount)
}
