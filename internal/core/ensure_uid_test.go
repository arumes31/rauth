package core

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestEnsureUserUIDs(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	UserDB = client
	Ctx = context.Background()

	// Create a legacy user without UID
	username := "legacyuser"
	UserDB.SAdd(Ctx, "users", username)
	UserDB.HSet(Ctx, "user:"+username, map[string]interface{}{
		"username": username,
		"email":    "legacy@test.com",
	})

	// Create a modern user with UID
	modernUser := "modernuser"
	modernUID := "already-has-uid"
	UserDB.SAdd(Ctx, "users", modernUser)
	UserDB.HSet(Ctx, "user:"+modernUser, map[string]interface{}{
		"username": modernUser,
		"uid":      modernUID,
	})

	// Run EnsureUserUIDs
	EnsureUserUIDs()

	// Verify legacy user now has a UID
	uid, err := UserDB.HGet(Ctx, "user:"+username, "uid").Result()
	require.NoError(t, err)
	require.NotEmpty(t, uid)

	// Verify UID indexes exist for legacy user
	val, err := UserDB.Get(Ctx, "uid:"+uid).Result()
	require.NoError(t, err)
	require.Equal(t, username, val)

	// Verify modern user still has the same UID
	uid2, err := UserDB.HGet(Ctx, "user:"+modernUser, "uid").Result()
	require.NoError(t, err)
	require.Equal(t, modernUID, uid2)
}
