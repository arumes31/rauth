package core

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func setupTestRedis(t *testing.T) *miniredis.Miniredis {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	UserDB = client
	TokenDB = client
	RateLimitDB = client

	return mr
}

func TestRemoveIPSessionIndex(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	tests := []struct {
		name      string
		ip        string
		token     string
		setup     func()
		checkFunc func(*testing.T)
	}{
		{
			name:  "Remove existing IP session index",
			ip:    "192.168.1.1",
			token: "token1",
			setup: func() {
				TokenDB.SAdd(Ctx, "ip_sessions:192.168.1.1", "token1")
			},
			checkFunc: func(t *testing.T) {
				res := TokenDB.SIsMember(Ctx, "ip_sessions:192.168.1.1", "token1").Val()
				assert.False(t, res)
			},
		},
		{
			name:  "Remove non-existing IP session index",
			ip:    "192.168.1.2",
			token: "token2",
			setup: func() {},
			checkFunc: func(t *testing.T) {
				res := TokenDB.SIsMember(Ctx, "ip_sessions:192.168.1.2", "token2").Val()
				assert.False(t, res)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr.FlushAll()
			tt.setup()
			RemoveIPSessionIndex(tt.ip, tt.token)
			tt.checkFunc(t)
		})
	}
}

func TestSyncSessionIndexes(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	tests := []struct {
		name      string
		setup     func()
		expected  int64
		checkFunc func(*testing.T)
	}{
		{
			name: "Sync multiple sessions",
			setup: func() {
				TokenDB.SAdd(Ctx, "user_sessions:user1", "valid_token")
				TokenDB.HSet(Ctx, "X-rauth-authtoken=valid_token", "status", "valid")

				TokenDB.SAdd(Ctx, "user_sessions:user1", "invalid_token")

				TokenDB.SAdd(Ctx, "ip_sessions:10.0.0.1", "valid_ip_token")
				TokenDB.HSet(Ctx, "X-rauth-authtoken=valid_ip_token", "status", "valid")

				TokenDB.SAdd(Ctx, "ip_sessions:10.0.0.1", "invalid_ip_token")
			},
			expected: 1,
			checkFunc: func(t *testing.T) {
				assert.False(t, TokenDB.SIsMember(Ctx, "user_sessions:user1", "invalid_token").Val())
				assert.False(t, TokenDB.SIsMember(Ctx, "ip_sessions:10.0.0.1", "invalid_ip_token").Val())

				assert.True(t, TokenDB.SIsMember(Ctx, "user_sessions:user1", "valid_token").Val())
				assert.True(t, TokenDB.SIsMember(Ctx, "ip_sessions:10.0.0.1", "valid_ip_token").Val())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr.FlushAll()
			tt.setup()
			count := SyncSessionIndexes()
			assert.Equal(t, tt.expected, count)
			tt.checkFunc(t)
		})
	}
}

func TestReconcileIndexSets(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	tests := []struct {
		name      string
		pattern   string
		setup     func()
		expected  int64
		checkFunc func(*testing.T)
	}{
		{
			name:    "Reconcile user sessions",
			pattern: "user_sessions:*",
			setup: func() {
				TokenDB.SAdd(Ctx, "user_sessions:user2", "tokenA")
				TokenDB.HSet(Ctx, "X-rauth-authtoken=tokenA", "status", "valid")
				TokenDB.SAdd(Ctx, "user_sessions:user2", "tokenB")
			},
			expected: 1,
			checkFunc: func(t *testing.T) {
				assert.False(t, TokenDB.SIsMember(Ctx, "user_sessions:user2", "tokenB").Val())
				assert.True(t, TokenDB.SIsMember(Ctx, "user_sessions:user2", "tokenA").Val())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr.FlushAll()
			tt.setup()
			count := reconcileIndexSets(tt.pattern)
			assert.Equal(t, tt.expected, count)
			tt.checkFunc(t)
		})
	}
}
