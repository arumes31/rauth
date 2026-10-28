package core

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImportFromRedis(t *testing.T) {
	setupPG(t)
	ServerSecret = "32byte-secret-key-for-testing-!!"
	s := miniredis.RunT(t)
	userDB := redis.NewClient(&redis.Options{Addr: s.Addr(), DB: redisLegacyUserDB})
	auditDB := redis.NewClient(&redis.Options{Addr: s.Addr(), DB: redisLegacyAuditDB})

	aliceUID := uuid.NewString()
	userDB.HSet(Ctx, "user:alice", map[string]interface{}{
		"username": "alice", "password": "$2a$hash", "email": "a@example.com", "groups": "default",
		"is_admin": "1", "2fa_secret": "enc:abc", "uid": aliceUID, "created_at": 1700000000,
	})
	userDB.SAdd(Ctx, "users", "alice", "bob")
	// bob still has passkeys in the legacy list format and no UID.
	userDB.HSet(Ctx, "user:bob", "username", "bob", "password", "$2a$bob")
	// A stub hash without a username field is not an account.
	userDB.HSet(Ctx, "user:stub", "2fa_secret", "enc:zzz")

	k1, _ := json.Marshal(StoredCredential{Credential: webauthn.Credential{ID: []byte("k1")}, Nickname: "Laptop", CreatedAt: 5})
	userDB.HSet(Ctx, "user:alice:webauthn_creds_v2", fmt.Sprintf("%x", "k1"), string(k1))
	l1, _ := json.Marshal(StoredCredential{Credential: webauthn.Credential{ID: []byte("id1")}, Nickname: "Key 1", CreatedAt: 100})
	l2, _ := json.Marshal(StoredCredential{Credential: webauthn.Credential{ID: []byte("id2")}, Nickname: "Key 2", CreatedAt: 200})
	userDB.RPush(Ctx, "user:bob:webauthn_creds", string(l1), string(l2))

	userDB.SAdd(Ctx, "user:alice:recovery_codes", hashRecoveryCode("aaaaa-bbbbb-ccccc-ddddd"), "h2")
	userDB.Set(Ctx, "authgen:alice", "3", 0)
	userDB.Set(Ctx, "authgen:deleted", "9", 0)
	userDB.HSet(Ctx, "auth_bypass_rules", "app.example.com/hook", `{"action":"allow","note":"n"}`, "bad.example.com", "not-json")

	e1, _ := json.Marshal(AuditLog{Timestamp: 10, Action: "LOGIN", Username: "alice", IP: "1.1.1.1", Details: map[string]interface{}{"k": "v"}})
	e2, _ := json.Marshal(AuditLog{Timestamp: 20, Action: "LOGIN_FAILED", IP: "2.2.2.2"})
	e0, _ := json.Marshal(AuditLog{Timestamp: 5, Action: "OLD", Username: "alice"})
	auditDB.LPush(Ctx, "audit_logs", string(e1), string(e2))
	auditDB.LPush(Ctx, "user_audit_logs:alice", string(e0), string(e1))

	require.NoError(t, importFromRedis(Ctx, userDB, auditDB))

	users, err := ListUsers()
	require.NoError(t, err)
	require.Len(t, users, 2)
	alice, err := GetUser("alice")
	require.NoError(t, err)
	assert.Equal(t, User{Username: "alice", Password: "$2a$hash", Email: "a@example.com", Groups: "default",
		IsAdmin: "1", TwoFactor: "enc:abc", UID: aliceUID, CreatedAt: 1700000000}, alice)
	bob, err := GetUser("bob")
	require.NoError(t, err)
	assert.Equal(t, "0", bob.IsAdmin)
	assert.Empty(t, bob.UID, "EnsureUserUIDs backfills it at startup")

	// Passkeys keep their user handle binding and nickname.
	name, err := GetUsernameByUID(aliceUID)
	require.NoError(t, err)
	assert.Equal(t, "alice", name)
	require.Len(t, GetStoredCredentials("alice"), 1)
	assert.Equal(t, "Laptop", GetStoredCredentials("alice")[0].Nickname)
	bobCreds := GetStoredCredentials("bob")
	require.Len(t, bobCreds, 2)
	assert.Equal(t, "Key 1", bobCreds[0].Nickname)
	require.NoError(t, UpdateWebAuthnNickname("bob", fmt.Sprintf("%x", "id2"), "Phone"))

	assert.Equal(t, int64(2), CountRecoveryCodes("alice"))
	assert.True(t, ConsumeRecoveryCode("alice", "aaaaa-bbbbb-ccccc-ddddd"))

	gen, _ := AuthGeneration("alice")
	assert.Equal(t, "3", gen)
	gen, _ = AuthGeneration("deleted")
	assert.Equal(t, "9", gen)

	require.NoError(t, ReloadBypassRules())
	rules := activeBypass.Load().ui
	require.Len(t, rules, 2)
	for _, r := range rules {
		if r.Host == "bad.example.com" {
			assert.Equal(t, BypassDeny, r.Action, "unreadable metadata must fail closed")
		} else {
			assert.Equal(t, BypassAllow, r.Action)
			assert.Equal(t, "n", r.Note)
		}
	}

	// Global and per-user lists are merged without duplicates, oldest first.
	logs, err := RecentAuditLogs(10)
	require.NoError(t, err)
	require.Len(t, logs, 3)
	assert.Equal(t, []string{"LOGIN_FAILED", "LOGIN", "OLD"}, []string{logs[0].Action, logs[1].Action, logs[2].Action})
	assert.Equal(t, "v", logs[1].Details["k"])

	// The import runs once: a second call changes nothing.
	userDB.HSet(Ctx, "user:carol", "username", "carol")
	require.NoError(t, importFromRedis(Ctx, userDB, auditDB))
	exists, _ := UserExists("carol")
	assert.False(t, exists)
}

func TestImportFromRedisSkipsPopulatedDatabase(t *testing.T) {
	setupPG(t)
	s := miniredis.RunT(t)
	userDB := redis.NewClient(&redis.Options{Addr: s.Addr()})
	userDB.HSet(Ctx, "user:alice", "username", "alice")
	require.NoError(t, PutUser(User{Username: "existing"}))

	require.NoError(t, importFromRedis(Ctx, userDB, userDB))
	exists, _ := UserExists("alice")
	assert.False(t, exists)
	var marker string
	require.NoError(t, PG.QueryRow(Ctx, "SELECT value FROM app_meta WHERE key = $1", redisImportMarker).Scan(&marker))
}
