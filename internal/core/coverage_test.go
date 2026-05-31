package core

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// TestRemoveIPSessionIndex covers RemoveIPSessionIndex, which drops a token from
// its per-IP session set.
func TestRemoveIPSessionIndex(t *testing.T) {
	s := miniredis.RunT(t)
	TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	AddIPSessionIndex("10.0.0.5", "tok-a")
	AddIPSessionIndex("10.0.0.5", "tok-b")

	RemoveIPSessionIndex("10.0.0.5", "tok-a")

	members, err := TokenDB.SMembers(Ctx, "ip_sessions:10.0.0.5").Result()
	require.NoError(t, err)
	assert.NotContains(t, members, "tok-a")
	assert.Contains(t, members, "tok-b")
}

// TestSyncSessionIndexes covers SyncSessionIndexes and reconcileIndexSets: live
// tokens are counted (once, from the user set) and dead index entries pruned.
func TestSyncSessionIndexes(t *testing.T) {
	s := miniredis.RunT(t)
	TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	// A live session: valid token plus both index entries.
	TokenDB.HSet(Ctx, "X-rauth-authtoken=live", map[string]interface{}{"status": "valid"})
	AddSessionIndex("alice", "live")
	AddIPSessionIndex("10.0.0.1", "live")

	// A dead session: index entries point at a token that no longer exists.
	AddSessionIndex("bob", "ghost")
	AddIPSessionIndex("10.0.0.2", "ghost")

	count := SyncSessionIndexes()
	assert.Equal(t, int64(1), count, "only the live user session should be counted")

	// Dead entries are pruned from both index families.
	userMembers, _ := TokenDB.SMembers(Ctx, "user_sessions:bob").Result()
	assert.NotContains(t, userMembers, "ghost")
	ipMembers, _ := TokenDB.SMembers(Ctx, "ip_sessions:10.0.0.2").Result()
	assert.NotContains(t, ipMembers, "ghost")

	// Live entries survive.
	liveMembers, _ := TokenDB.SMembers(Ctx, "user_sessions:alice").Result()
	assert.Contains(t, liveMembers, "live")
}

// TestEnsureUserUIDs covers EnsureUserUIDs and ensureUID: a legacy user lacking a
// uid field is backfilled with a uid plus its string/binary lookup indexes, while
// a user that already has a uid is left untouched.
func TestEnsureUserUIDs(t *testing.T) {
	s := miniredis.RunT(t)
	UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	// Legacy user: a user hash and set membership but no uid field.
	UserDB.HSet(Ctx, "user:legacy", map[string]interface{}{
		"username": "legacy",
		"password": "x",
	})
	UserDB.SAdd(Ctx, "users", "legacy")

	// Modern user: already has a uid that must be preserved.
	UserDB.HSet(Ctx, "user:modern", map[string]interface{}{
		"username": "modern",
		"uid":      "existing-uid",
	})
	UserDB.SAdd(Ctx, "users", "modern")

	EnsureUserUIDs()

	uid, err := UserDB.HGet(Ctx, "user:legacy", "uid").Result()
	require.NoError(t, err)
	require.NotEmpty(t, uid)

	// The string lookup index now resolves back to the username.
	name, err := UserDB.Get(Ctx, "uid:"+uid).Result()
	require.NoError(t, err)
	assert.Equal(t, "legacy", name)

	// The binary lookup index also resolves back to the username.
	parsedUID, err := uuid.Parse(uid)
	require.NoError(t, err)
	binName, err := UserDB.Get(Ctx, "uid_bin:"+string(parsedUID[:])).Result()
	require.NoError(t, err)
	assert.Equal(t, "legacy", binName)

	// Modern user's uid is unchanged.
	modernUID, _ := UserDB.HGet(Ctx, "user:modern", "uid").Result()
	assert.Equal(t, "existing-uid", modernUID)
}

// TestSetBcryptCost covers SetBcryptCost: valid costs are applied and out-of-range
// values fall back to the default.
func TestSetBcryptCost(t *testing.T) {
	original := bcryptCost
	defer func() { bcryptCost = original }()

	SetBcryptCost(bcrypt.MinCost)
	assert.Equal(t, bcrypt.MinCost, bcryptCost)

	SetBcryptCost(bcrypt.MaxCost + 1)
	assert.Equal(t, 12, bcryptCost, "out-of-range cost falls back to default")

	SetBcryptCost(bcrypt.MinCost - 1)
	assert.Equal(t, 12, bcryptCost, "below-min cost falls back to default")
}

// TestEncrypt2FASecret covers Encrypt2FASecret: empty input returns empty, and a
// non-empty secret is encrypted with the "enc:" prefix and round-trips.
func TestEncrypt2FASecret(t *testing.T) {
	key := "12345678901234567890123456789012"

	assert.Equal(t, "", Encrypt2FASecret("", key))

	enc := Encrypt2FASecret("JBSWY3DPEHPK3PXP", key)
	require.True(t, len(enc) > 4)
	assert.Equal(t, "enc:", enc[:4])
	assert.Equal(t, "JBSWY3DPEHPK3PXP", Decrypt2FASecret(enc, key))
}
