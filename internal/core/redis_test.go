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

func TestHasActiveSessionsTable(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	TokenDB = client
	Ctx = context.Background()

	tests := []struct {
		name       string
		ip         string
		setup      func(ip string)
		wantActive bool
		wantStale  []string
	}{
		{
			name: "Valid active session",
			ip:   "1.1.1.1",
			setup: func(ip string) {
				TokenDB.HSet(Ctx, "X-rauth-authtoken=t1", "status", "valid", "ip", ip)
				AddIPSessionIndex(ip, "t1")
			},
			wantActive: true,
			wantStale:  nil,
		},
		{
			name: "Missing token (should prune)",
			ip:   "2.2.2.2",
			setup: func(ip string) {
				AddIPSessionIndex(ip, "ghost")
			},
			wantActive: false,
			wantStale:  []string{"ghost"},
		},
		{
			name: "Invalid session status (should prune)",
			ip:   "3.3.3.3",
			setup: func(ip string) {
				TokenDB.HSet(Ctx, "X-rauth-authtoken=t2", "status", "expired")
				AddIPSessionIndex(ip, "t2")
			},
			wantActive: false,
			wantStale:  []string{"t2"},
		},
		{
			name: "Mixed sessions (one valid, one stale)",
			ip:   "4.4.4.4",
			setup: func(ip string) {
				TokenDB.HSet(Ctx, "X-rauth-authtoken=t3", "status", "valid")
				TokenDB.HSet(Ctx, "X-rauth-authtoken=t4", "status", "invalid")
				AddIPSessionIndex(ip, "t3")
				AddIPSessionIndex(ip, "t4")
			},
			wantActive: true,
			wantStale:  []string{"t4"},
		},
		{
			name: "Empty session hash (should prune)",
			ip:   "5.5.5.5",
			setup: func(ip string) {
				// Key exists but no fields
				TokenDB.HSet(Ctx, "X-rauth-authtoken=t5", "dummy", "val")
				TokenDB.HDel(Ctx, "X-rauth-authtoken=t5", "dummy")
				AddIPSessionIndex(ip, "t5")
			},
			wantActive: false,
			wantStale:  []string{"t5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(tt.ip)
			active := HasActiveSessions(tt.ip)
			assert.Equal(t, tt.wantActive, active)

			members, _ := TokenDB.SMembers(Ctx, "ip_sessions:"+tt.ip).Result()
			for _, s := range tt.wantStale {
				assert.NotContains(t, members, s)
			}
			if tt.wantActive {
				// Ensure active remains
				found := false
				for _, m := range members {
					data, _ := TokenDB.HGetAll(Ctx, "X-rauth-authtoken="+m).Result()
					if data["status"] == "valid" {
						found = true
						break
					}
				}
				assert.True(t, found)
			}
		})
	}
}
