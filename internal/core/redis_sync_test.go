package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestSyncSessionIndexesTable(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	TokenDB = client
	Ctx = context.Background()

	tests := []struct {
		name          string
		setup         func()
		expectedCount int64
		verify        func(t *testing.T)
	}{
		{
			name: "Valid tokens",
			setup: func() {
				TokenDB.FlushAll(Ctx)
				TokenDB.HSet(Ctx, "X-rauth-authtoken=t1", map[string]interface{}{"status": "valid"})
				TokenDB.HSet(Ctx, "X-rauth-authtoken=t2", map[string]interface{}{"status": "valid"})
				AddSessionIndex("u1", "t1")
				AddSessionIndex("u2", "t2")
			},
			expectedCount: 2,
			verify: func(t *testing.T) {
				m1, _ := TokenDB.SMembers(Ctx, "user_sessions:u1").Result()
				require.Contains(t, m1, "t1")
				m2, _ := TokenDB.SMembers(Ctx, "user_sessions:u2").Result()
				require.Contains(t, m2, "t2")
			},
		},
		{
			name: "Invalid and expired tokens",
			setup: func() {
				TokenDB.FlushAll(Ctx)
				TokenDB.HSet(Ctx, "X-rauth-authtoken=valid", map[string]interface{}{"status": "valid"})
				TokenDB.HSet(Ctx, "X-rauth-authtoken=invalid", map[string]interface{}{"status": "invalid"})
				TokenDB.HSet(Ctx, "X-rauth-authtoken=expired", map[string]interface{}{"status": "expired"})
				AddSessionIndex("u1", "valid")
				AddSessionIndex("u1", "invalid")
				AddSessionIndex("u1", "expired")
				AddSessionIndex("u1", "nonexistent")
			},
			expectedCount: 1,
			verify: func(t *testing.T) {
				m, _ := TokenDB.SMembers(Ctx, "user_sessions:u1").Result()
				require.Equal(t, []string{"valid"}, m)
			},
		},
		{
			name: "Empty sets",
			setup: func() {
				TokenDB.FlushAll(Ctx)
				AddSessionIndex("u1", "ghost")
				TokenDB.SRem(Ctx, "user_sessions:u1", "ghost") // Now it's empty
			},
			expectedCount: 0,
			verify: func(t *testing.T) {
				exists, _ := TokenDB.Exists(Ctx, "user_sessions:u1").Result()
				require.Equal(t, int64(0), exists)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			count := SyncSessionIndexes()
			require.Equal(t, tt.expectedCount, count)
			tt.verify(t)
		})
	}
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
		name     string
		ip       string
		setup    func()
		expected bool
		verify   func(t *testing.T)
	}{
		{
			name: "Active session",
			ip:   "1.2.3.4",
			setup: func() {
				TokenDB.FlushAll(Ctx)
				TokenDB.HSet(Ctx, "X-rauth-authtoken=t1", map[string]interface{}{"status": "valid"})
				AddIPSessionIndex("1.2.3.4", "t1")
			},
			expected: true,
			verify:   func(t *testing.T) {},
		},
		{
			name: "Expired session",
			ip:   "1.2.3.5",
			setup: func() {
				TokenDB.FlushAll(Ctx)
				TokenDB.HSet(Ctx, "X-rauth-authtoken=t1", map[string]interface{}{"status": "expired"})
				AddIPSessionIndex("1.2.3.5", "t1")
			},
			expected: false,
			verify: func(t *testing.T) {
				m, _ := TokenDB.SMembers(Ctx, "ip_sessions:1.2.3.5").Result()
				require.Empty(t, m)
			},
		},
		{
			name: "No sessions",
			ip:   "1.2.3.6",
			setup: func() {
				TokenDB.FlushAll(Ctx)
			},
			expected: false,
			verify:   func(t *testing.T) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			got := HasActiveSessions(tt.ip)
			require.Equal(t, tt.expected, got)
			tt.verify(t)
		})
	}
}

func TestSyncSessionIndexesLargeBatch(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	TokenDB = client
	Ctx = context.Background()

	// Setup 150 users (more than the 100 scan batch size)
	for i := 0; i < 150; i++ {
		username := fmt.Sprintf("user%d", i)
		token := fmt.Sprintf("token%d", i)
		TokenDB.HSet(Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status": "valid",
		})
		AddSessionIndex(username, token)
	}

	count := SyncSessionIndexes()
	require.Equal(t, int64(150), count)
}
