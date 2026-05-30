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

	t.Run("HasActiveSessions", func(t *testing.T) {
		TokenDB.HSet(Ctx, "X-rauth-authtoken=active_token", map[string]interface{}{
			"ip":     "192.168.1.1",
			"status": "valid",
		})

		require.True(t, HasActiveSessions("192.168.1.1"))
		require.False(t, HasActiveSessions("10.0.0.1"))
	})

	t.Run("SyncSessionIndexes", func(t *testing.T) {
		TokenDB.FlushAll(Ctx)

		// Set up data for SyncSessionIndexes
		testCases := []struct {
			key      string
			username string
			status   string
			expected int64
		}{
			{"X-rauth-authtoken=valid1", "user1", "valid", 1},
			{"X-rauth-authtoken=valid2", "user2", "valid", 1},
			{"X-rauth-authtoken=invalid_status", "user3", "invalid", 0},
			{"X-rauth-authtoken=missing_username", "", "valid", 0},
			{"bad_prefix=malformed", "user4", "valid", 0}, // Should not be picked up by scan
		}

		for _, tc := range testCases {
			TokenDB.HSet(Ctx, tc.key, map[string]interface{}{
				"username": tc.username,
				"status":   tc.status,
			})
		}

		count := SyncSessionIndexes()
		assert.Equal(t, int64(2), count)

		members1, _ := TokenDB.SMembers(Ctx, "user_sessions:user1").Result()
		assert.Contains(t, members1, "valid1")

		members2, _ := TokenDB.SMembers(Ctx, "user_sessions:user2").Result()
		assert.Contains(t, members2, "valid2")
	})
}
