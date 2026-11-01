package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"rauth/internal/authstate"
)

func TestSQLManagedSessionsWithoutRedis(t *testing.T) {
	sqlSecurityFixture(t)
	SetBcryptCost(4)
	t.Cleanup(func() { SetBcryptCost(12) })
	for _, user := range []string{"management-alice", "management-bob"} {
		require.NoError(t, CreateUser(user, "Password123", "", false, ""))
	}
	old, current, other := strings.Repeat("8", 64), strings.Repeat("9", 64), strings.Repeat("a", 64)
	gen := currentGen(t, "management-alice")
	fields := map[string]interface{}{"auth_gen": gen, "user_agent": "Firefox/120.0", "custom_secret": "PRIVATE-METADATA", "token": "FORGED-TOKEN", "rotated_to": "FORGED-SUCCESSOR"}
	// The real rotation must overwrite any custom successor-shaped payload.
	delete(fields, "rotated_to")
	require.NoError(t, StoreSession(old, "management-alice", "203.0.113.1", fields, time.Hour))
	require.NoError(t, StoreSession(other, "management-bob", "203.0.113.2", map[string]interface{}{"auth_gen": currentGen(t, "management-bob")}, time.Hour))
	changed, err := RotateSession(old, current, "management-alice", "203.0.113.1", time.Now().Unix(), time.Hour, time.Minute)
	require.NoError(t, err)
	require.True(t, changed)
	page, err := ListManagedSessions(Ctx, "management-alice", old, "", 1)
	require.NoError(t, err)
	require.Len(t, page.Sessions, 1)
	view := page.Sessions[0]
	assert.Equal(t, "1", view["is_current"], "retired grace tokens identify the same current family")
	assert.Equal(t, "management-alice", view["username"])
	assert.NotEmpty(t, view["handle"])
	for _, key := range []string{"token", "rotated_to", "custom_secret", "auth_gen"} {
		assert.NotContains(t, view, key)
	}
	data, err := json.Marshal(page)
	require.NoError(t, err)
	for _, secret := range []string{old, current, other, "PRIVATE-METADATA", "FORGED-TOKEN"} {
		assert.NotContains(t, string(data), secret)
	}
	all, err := ListManagedSessions(Ctx, "", "", "", 1)
	require.NoError(t, err)
	require.NotEmpty(t, all.Next)
	next, err := ListManagedSessions(Ctx, "", "", all.Next, 1)
	require.NoError(t, err)
	require.Len(t, next.Sessions, 1)
	assert.NotEqual(t, all.Sessions[0]["handle"], next.Sessions[0]["handle"])
	changed, err = RevokeManagedSession(Ctx, view["handle"], "management-bob")
	require.NoError(t, err)
	assert.False(t, changed)
	_, err = ReadAuthSession(Ctx, current)
	require.NoError(t, err)
	_, err = RevokeManagedSession(Ctx, current, "")
	require.ErrorIs(t, err, ErrInvalidSessionHandle, "a bearer is never a SQL management handle")
	changed, err = RevokeManagedSession(Ctx, view["handle"], "management-alice")
	require.NoError(t, err)
	assert.True(t, changed)
	_, err = ReadAuthSession(Ctx, current)
	require.ErrorIs(t, err, authstate.ErrNotFound)
	_, err = ReadAuthSession(Ctx, other)
	require.NoError(t, err)
	cancelled, cancel := context.WithCancel(Ctx)
	cancel()
	_, err = ListManagedSessions(cancelled, "", "", "", 10)
	require.Error(t, err)
}

func TestLegacyManagedSessionsUseNonBearerHandles(t *testing.T) {
	newRegressionRedis(t)
	token := strings.Repeat("b", 64)
	require.NoError(t, StoreSession(token, "legacy-alice", "203.0.113.3", map[string]interface{}{"username": "legacy-alice", "ip": "203.0.113.3", "status": "valid", "custom_secret": "PRIVATE-METADATA", "user_agent": "Firefox/120.0"}, time.Hour))
	require.NoError(t, TokenDB.Set(Ctx, "bypass_unlock:"+token, "legacy-alice", time.Minute).Err())
	page, err := ListManagedSessions(Ctx, "legacy-alice", token, "", 200)
	require.NoError(t, err)
	require.Len(t, page.Sessions, 1)
	view := page.Sessions[0]
	assert.True(t, strings.HasPrefix(view["handle"], "legacy:"))
	assert.Equal(t, "1", view["is_current"])
	data, err := json.Marshal(page)
	require.NoError(t, err)
	assert.NotContains(t, string(data), token)
	assert.NotContains(t, string(data), "PRIVATE-METADATA")
	changed, err := RevokeManagedSession(Ctx, view["handle"], "legacy-bob")
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, int64(1), TokenDB.Exists(Ctx, "X-rauth-authtoken="+token).Val())
	changed, err = RevokeManagedSession(Ctx, view["handle"], "legacy-alice")
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Zero(t, TokenDB.Exists(Ctx, "X-rauth-authtoken="+token, "bypass_unlock:"+token).Val())
	require.NoError(t, TokenDB.Close())
	_, err = ListManagedSessions(Ctx, "legacy-alice", token, "", 200)
	require.Error(t, err)
	_, err = RevokeManagedSession(Ctx, view["handle"], "")
	require.Error(t, err)
}
