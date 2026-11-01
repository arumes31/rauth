package core

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"rauth/internal/authstate"
)

func TestSQLSessionFacadesWithoutRedis(t *testing.T) {
	sqlSecurityFixture(t)
	require.NoError(t, CreateUser("session-user", "Password123", "", true, ""))
	gen := currentGen(t, "session-user")
	old, next, rotated := strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)
	fields := map[string]interface{}{"auth_gen": gen, "is_admin": true, "status": "valid", "country": "unknown", "user_agent": "Firefox/120.0"}
	require.Error(t, StoreSession(strings.Repeat("a", 64), "session-user", "203.0.113.55", map[string]interface{}{"auth_gen": gen, "status": "pending"}, time.Hour))
	require.NoError(t, StoreSession(old, "session-user", "203.0.113.55", fields, time.Hour))
	data, err := ReadAuthSession(Ctx, old)
	require.NoError(t, err)
	assert.Equal(t, "1", data["is_admin"])
	assert.Equal(t, gen, data["auth_gen"])
	assert.Equal(t, "session-user", data["username"])
	assert.True(t, SessionAuthorized(data))
	assert.True(t, HasActiveSessions("203.0.113.55"))
	assert.Equal(t, int64(1), SyncSessionIndexes())
	changed, err := ReplaceSessionWithPublicAccessGrant(Ctx, old, next, "session-user", gen, 15*time.Minute)
	require.NoError(t, err)
	require.True(t, changed)
	_, err = ReadAuthSession(Ctx, old)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	remaining, err := PublicAccessGrantRemaining(Ctx, next, "session-user")
	require.NoError(t, err)
	assert.Positive(t, remaining)
	changed, err = RotateSession(next, rotated, "session-user", "203.0.113.55", time.Now().Unix(), time.Hour, 30*time.Second)
	require.NoError(t, err)
	require.True(t, changed)
	RefreshSession(next, time.Hour)
	data, err = ReadAuthSession(Ctx, next)
	require.NoError(t, err)
	assert.Equal(t, rotated, data["rotated_to"])
	require.NoError(t, LockPublicAccessGrant(Ctx, rotated))
	remaining, err = PublicAccessGrantRemaining(Ctx, rotated, "session-user")
	require.NoError(t, err)
	assert.Zero(t, remaining)
	// Logout that was authorized with the deleted pre-step-up token must still
	// revoke the current family without a Redis client or bearer-token scan.
	require.NoError(t, RevokeAuthSession(Ctx, old))
	_, err = ReadAuthSession(Ctx, rotated)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	assert.False(t, HasActiveSessions("203.0.113.55"))
}
func TestSQLSessionRestampAndSweepWithoutDoubleGeneration(t *testing.T) {
	sqlSecurityFixture(t)
	require.NoError(t, CreateUser("restamp-user", "Password123", "", false, ""))
	gen := currentGen(t, "restamp-user")
	keep, drop := strings.Repeat("4", 64), strings.Repeat("5", 64)
	for _, token := range []string{keep, drop} {
		require.NoError(t, StoreSession(token, "restamp-user", "203.0.113.66", map[string]interface{}{"auth_gen": gen}, time.Hour))
	}
	nextGen, err := BumpAuthGeneration("restamp-user")
	require.NoError(t, err)
	require.NoError(t, RestampSession(keep, nextGen))
	require.NoError(t, InvalidateOtherUserSessions("restamp-user", keep))
	_, err = ReadAuthSession(Ctx, keep)
	require.NoError(t, err)
	_, err = ReadAuthSession(Ctx, drop)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	require.NoError(t, InvalidateUserSessions("restamp-user"))
	after, err := AuthGeneration("restamp-user")
	require.NoError(t, err)
	assert.Equal(t, nextGen, after, "physical sweep must not bump an already changed generation")
	_, err = ReadAuthSession(Ctx, keep)
	require.ErrorIs(t, err, authstate.ErrNotFound)
}
func TestSQLSessionBindingRevokesFamilyWithoutRedis(t *testing.T) {
	sqlSecurityFixture(t)
	require.NoError(t, CreateUser("binding-user", "Password123", "", false, ""))
	gen := currentGen(t, "binding-user")
	tok := strings.Repeat("6", 64)
	require.NoError(t, StoreSession(tok, "binding-user", "203.0.113.77", map[string]interface{}{"auth_gen": gen, "country": "unknown", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/120.0"}, time.Hour))
	data, err := ReadAuthSession(Ctx, tok)
	require.NoError(t, err)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 15) Chrome/140.0 Mobile")
	assert.False(t, SessionBindingValid(&Config{}, req, tok, "unused-legacy-key", data, "203.0.113.77"))
	_, err = ReadAuthSession(Ctx, tok)
	require.ErrorIs(t, err, authstate.ErrNotFound)
}
func TestSelectedSQLSessionErrorNeverUsesRedisFallback(t *testing.T) {
	sqlSecurityFixture(t)
	k, err := authstate.NewKeyring(strings.Repeat("index-test-key-", 3), "v1", map[string]string{"v1": strings.Repeat("payload-test-", 3)})
	require.NoError(t, err)
	other, err := pgxpool.NewWithConfig(context.Background(), PG.Config())
	require.NoError(t, err)
	selected, err := authstate.NewPostgresSessions(Ctx, other, k)
	require.NoError(t, err)
	securitySessions = selected
	other.Close()
	fake := miniredis.RunT(t)
	TokenDB = redis.NewClient(&redis.Options{Addr: fake.Addr()})
	t.Cleanup(func() { _ = TokenDB.Close() })
	tok := strings.Repeat("7", 64)
	require.NoError(t, TokenDB.HSet(Ctx, "X-rauth-authtoken="+tok, "status", "valid", "username", "forged-redis-user").Err())
	data, err := ReadAuthSession(Ctx, tok)
	require.Error(t, err)
	assert.Nil(t, data, "unavailable SQL authority must never authorize from Redis")
	_, err = RegistrationSessionBinding(Ctx, tok, ServerSecret)
	require.Error(t, err)
	_, err = ListManagedSessions(Ctx, "", "", "", 200)
	require.Error(t, err)
	_, err = RevokeManagedSession(Ctx, "00000000-0000-4000-8000-000000000001", "")
	require.Error(t, err)
	assert.Equal(t, int64(1), TokenDB.Exists(Ctx, "X-rauth-authtoken="+tok).Val(), "management must not fall back to a different authority")
}

func TestRegistrationBindingUsesStableAuthoritativeSession(t *testing.T) {
	for _, sqlMode := range []bool{false, true} {
		name := "legacy"
		if sqlMode {
			name = "postgres"
		}
		t.Run(name, func(t *testing.T) {
			if sqlMode {
				sqlSecurityFixture(t)
			} else {
				newRegressionRedis(t)
			}
			SetBcryptCost(4)
			t.Cleanup(func() { SetBcryptCost(12) })
			user := "stable-browser-user"
			require.NoError(t, CreateUser(user, "Password123!", "", true, ""))
			gen := currentGen(t, user)
			first, next, replacement, other := strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64)
			fields := map[string]interface{}{"username": user, "ip": "203.0.113.44", "status": "valid", "auth_gen": gen, "session_family": "CUSTOM-FORGED-FAMILY"}
			if !sqlMode {
				// Sessions created before the identity field existed must also retain
				// a ceremony started immediately before their first rotation.
				require.NoError(t, TokenDB.HSet(Ctx, "X-rauth-authtoken="+first, "username", user, "ip", "203.0.113.44", "status", "valid", "auth_gen", gen).Err())
				require.NoError(t, TokenDB.Expire(Ctx, "X-rauth-authtoken="+first, time.Hour).Err())
			} else {
				require.NoError(t, StoreSession(first, user, "203.0.113.44", fields, time.Hour))
			}
			before, err := RegistrationSessionBinding(Ctx, first, ServerSecret)
			require.NoError(t, err)
			require.NotEmpty(t, before)
			changed, err := RotateSession(first, next, user, "203.0.113.44", time.Now().Unix(), time.Hour, time.Minute)
			require.NoError(t, err)
			require.True(t, changed)
			after, err := RegistrationSessionBinding(Ctx, next, ServerSecret)
			require.NoError(t, err)
			assert.Equal(t, before, after)
			require.NoError(t, StoreSession(other, user, "203.0.113.44", fields, time.Hour))
			different, err := RegistrationSessionBinding(Ctx, other, ServerSecret)
			require.NoError(t, err)
			assert.NotEqual(t, before, different, "another browser for the same account must not share the binding")
			changed, err = ReplaceSessionWithPublicAccessGrant(Ctx, next, replacement, user, gen, time.Minute)
			require.NoError(t, err)
			require.True(t, changed)
			after, err = RegistrationSessionBinding(Ctx, replacement, ServerSecret)
			require.NoError(t, err)
			assert.Equal(t, before, after)
			_, err = RegistrationSessionBinding(Ctx, next, ServerSecret)
			require.ErrorIs(t, err, authstate.ErrNotFound)
			// A hard replacement as well as a normal rotation preserves browser identity.
			final := strings.Repeat("g", 64)
			changed, err = ReplaceSession(replacement, final)
			require.NoError(t, err)
			require.True(t, changed)
			after, err = RegistrationSessionBinding(Ctx, final, ServerSecret)
			require.NoError(t, err)
			assert.Equal(t, before, after)
		})
	}
}
