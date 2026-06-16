package core

import (
	"context"
	"testing"
	"fmt"

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

// errorHook is used to simulate Redis command errors in tests.
type errorHook struct {
	cmdName string
}

func (h errorHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h errorHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == h.cmdName {
			err := fmt.Errorf("mock error for %s", h.cmdName)
			cmd.SetErr(err)
			return err
		}
		return next(ctx, cmd)
	}
}
func (h errorHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
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

	t.Run("InvalidateUserSessions_TokenDB_Nil", func(t *testing.T) {
		originalDB := TokenDB
		TokenDB = nil
		defer func() { TokenDB = originalDB }()

		// Should not panic
		InvalidateUserSessions("someuser")
	})

	t.Run("InvalidateUserSessions_SMembers_Error", func(t *testing.T) {
		originalDB := TokenDB

		clientWithHook := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		clientWithHook.AddHook(errorHook{cmdName: "smembers"})
		TokenDB = clientWithHook
		defer func() { TokenDB = originalDB }()

		// Should handle error gracefully
		InvalidateUserSessions("someuser")
	})

	t.Run("InvalidateUserSessions_Del_Error", func(t *testing.T) {
		originalDB := TokenDB

		clientWithHook := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		clientWithHook.AddHook(errorHook{cmdName: "del"})
		TokenDB = clientWithHook
		defer func() { TokenDB = originalDB }()

		// We need tokens to reach the Del call
		AddSessionIndex("testuser_del_err", "token123")

		// Should handle error gracefully (logs it)
		InvalidateUserSessions("testuser_del_err")
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
