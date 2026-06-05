package core

import (
	"context"
	"testing"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReconcileIndexSets(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	TokenDB = redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = TokenDB.Close() }()
	Ctx = context.Background()

	// Set up mock data
	// Valid token
	TokenDB.SAdd(Ctx, "user_sessions:user1", "token1")
	TokenDB.HSet(Ctx, "X-rauth-authtoken=token1", "status", "valid")

	// Invalid token (missing status)
	TokenDB.SAdd(Ctx, "user_sessions:user1", "token2")
	TokenDB.HSet(Ctx, "X-rauth-authtoken=token2", "other", "data")

	// Stale token (no key)
	TokenDB.SAdd(Ctx, "user_sessions:user1", "token3")

	// Valid token for another user
	TokenDB.SAdd(Ctx, "user_sessions:user2", "token4")
	TokenDB.HSet(Ctx, "X-rauth-authtoken=token4", "status", "valid")

	// Empty set
	TokenDB.SAdd(Ctx, "user_sessions:user3", "token5")
	TokenDB.SRem(Ctx, "user_sessions:user3", "token5")

	// Run function under test
	live := reconcileIndexSets("user_sessions:*")

	// Verify
	assert.Equal(t, int64(2), live, "Should return 2 live sessions")

	tokens1, _ := TokenDB.SMembers(Ctx, "user_sessions:user1").Result()
	assert.ElementsMatch(t, []string{"token1"}, tokens1, "Only token1 should remain for user1")

	tokens2, _ := TokenDB.SMembers(Ctx, "user_sessions:user2").Result()
	assert.ElementsMatch(t, []string{"token4"}, tokens2, "Token4 should remain for user2")
}
