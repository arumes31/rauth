package core

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestInitRedis(t *testing.T) {
	s := miniredis.RunT(t)

	cfg := &Config{
		RedisHost: "127.0.0.1",
		RedisPort: s.Port(),
	}

	err := InitRedis(cfg)
	assert.NoError(t, err)

	assert.NotNil(t, UserDB)
	assert.NotNil(t, TokenDB)
	assert.NotNil(t, RateLimitDB)
	assert.NotNil(t, AuditDB)

	// Verify they point to different DBs
	assert.Equal(t, 0, UserDB.Options().DB)
	assert.Equal(t, 1, TokenDB.Options().DB)
	assert.Equal(t, 2, RateLimitDB.Options().DB)
	assert.Equal(t, 3, AuditDB.Options().DB)
}

func TestSessionManagement(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	TokenDB = client
	Ctx = context.Background()

	t.Run("AddSessionIndex", func(t *testing.T) {
		AddSessionIndex("testuser", "token123")

		members, err := TokenDB.SMembers(Ctx, "user_sessions:testuser").Result()
		require.NoError(t, err)
		require.Contains(t, members, "token123")
	})

	t.Run("RemoveSessionIndex", func(t *testing.T) {
		RemoveSessionIndex("testuser", "token123")

		members, err := TokenDB.SMembers(Ctx, "user_sessions:testuser").Result()
		require.NoError(t, err)
		require.NotContains(t, members, "token123")
	})

	t.Run("InvalidateUserSessions", func(t *testing.T) {
		AddSessionIndex("testuser2", "token456")
		AddSessionIndex("testuser2", "token789")
		TokenDB.HSet(Ctx, "X-rauth-authtoken=token456", "data", "val")
		TokenDB.HSet(Ctx, "X-rauth-authtoken=token789", "data", "val")

		InvalidateUserSessions("testuser2")

		members, err := TokenDB.SMembers(Ctx, "user_sessions:testuser2").Result()
		require.NoError(t, err)
		require.Empty(t, members)

		exists1, _ := TokenDB.Exists(Ctx, "X-rauth-authtoken=token456").Result()
		require.Equal(t, int64(0), exists1)

		exists2, _ := TokenDB.Exists(Ctx, "X-rauth-authtoken=token789").Result()
		require.Equal(t, int64(0), exists2)
	})

	t.Run("InvalidateOtherUserSessions", func(t *testing.T) {
		AddSessionIndex("testuser3", "token_keep")
		AddSessionIndex("testuser3", "token_drop")
		TokenDB.HSet(Ctx, "X-rauth-authtoken=token_keep", "data", "val")
		TokenDB.HSet(Ctx, "X-rauth-authtoken=token_drop", "data", "val")

		InvalidateOtherUserSessions("testuser3", "token_keep")

		members, err := TokenDB.SMembers(Ctx, "user_sessions:testuser3").Result()
		require.NoError(t, err)
		require.Contains(t, members, "token_keep")
		require.NotContains(t, members, "token_drop")

		exists1, _ := TokenDB.Exists(Ctx, "X-rauth-authtoken=token_keep").Result()
		require.Equal(t, int64(1), exists1)

		exists2, _ := TokenDB.Exists(Ctx, "X-rauth-authtoken=token_drop").Result()
		require.Equal(t, int64(0), exists2)
	})

	t.Run("InvalidateOtherUserSessions_MultipleDropped", func(t *testing.T) {
		AddSessionIndex("testuser_multi", "token_keep")
		AddSessionIndex("testuser_multi", "token_drop1")
		AddSessionIndex("testuser_multi", "token_drop2")
		TokenDB.HSet(Ctx, "X-rauth-authtoken=token_keep", "data", "val")
		TokenDB.HSet(Ctx, "X-rauth-authtoken=token_drop1", "data", "val")
		TokenDB.HSet(Ctx, "X-rauth-authtoken=token_drop2", "data", "val")

		InvalidateOtherUserSessions("testuser_multi", "token_keep")

		members, err := TokenDB.SMembers(Ctx, "user_sessions:testuser_multi").Result()
		require.NoError(t, err)
		require.Contains(t, members, "token_keep")
		require.NotContains(t, members, "token_drop1")
		require.NotContains(t, members, "token_drop2")

		exists1, _ := TokenDB.Exists(Ctx, "X-rauth-authtoken=token_keep").Result()
		require.Equal(t, int64(1), exists1)
	})

	t.Run("InvalidateOtherUserSessions_RedisError", func(t *testing.T) {
		// Close token DB to simulate connection error
		oldTokenDB := TokenDB
		TokenDB = redis.NewClient(&redis.Options{Addr: "invalid:6379"})
		defer func() { TokenDB = oldTokenDB }()

		// Should not panic, but return early
		InvalidateOtherUserSessions("testuser_err", "token_keep")
	})

	t.Run("InvalidateOtherUserSessions_PipelineError", func(t *testing.T) {
		AddSessionIndex("testuser_pipe", "token_1")
		AddSessionIndex("testuser_pipe", "token_2")

		// Save and replace Ctx with a canceled context just to see if Exec fails
		oldCtx := Ctx
		var cancel context.CancelFunc
		Ctx, cancel = context.WithCancel(context.Background())
		cancel() // Cancel immediately
		defer func() { Ctx = oldCtx }()

		// SMembers will fail due to context cancellation, returning early.
		// But we still hit the SMembers error path again.

		InvalidateOtherUserSessions("testuser_pipe", "token_1")
	})

	t.Run("InvalidateOtherUserSessions_NoOtherSessions", func(t *testing.T) {
		AddSessionIndex("testuser_alone", "token_alone")

		InvalidateOtherUserSessions("testuser_alone", "token_alone")

		// Verify the session wasn't removed since it's the only one
		members, err := TokenDB.SMembers(Ctx, "user_sessions:testuser_alone").Result()
		require.NoError(t, err)
		require.Contains(t, members, "token_alone")
		require.Len(t, members, 1)
	})

	t.Run("HasActiveSessions", func(t *testing.T) {
		TokenDB.HSet(Ctx, "X-rauth-authtoken=active_token", map[string]interface{}{
			"ip":     "192.168.1.1",
			"status": "valid",
		})
		// Sessions are discoverable via the per-IP index maintained at issue time.
		AddIPSessionIndex("192.168.1.1", "active_token")

		require.True(t, HasActiveSessions("192.168.1.1"))
		require.False(t, HasActiveSessions("10.0.0.1"))
	})

	t.Run("HasActiveSessions prunes stale index entries", func(t *testing.T) {
		// Index points at a token that no longer exists -> pruned, returns false.
		AddIPSessionIndex("172.16.0.1", "ghost_token")
		require.False(t, HasActiveSessions("172.16.0.1"))
		members, _ := TokenDB.SMembers(Ctx, "ip_sessions:172.16.0.1").Result()
		require.NotContains(t, members, "ghost_token")
	})
}
