package core

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestUserManagement(t *testing.T) {
	s := miniredis.RunT(t)
	TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	setupPG(t)

	err := CreateUser("newuser", "pass123", "user@test.com", false, "")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Duplicate
	err = CreateUser("newuser", "pass123", "user@test.com", false, "")
	if err == nil {
		t.Error("Should not allow creating duplicate user")
	}

	users, _ := ListUsers()
	if len(users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(users))
	}

	if users[0].Username != "newuser" {
		t.Errorf("Expected username newuser, got %s", users[0].Username)
	}

	if err := DeleteUser("newuser"); err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}
	users, _ = ListUsers()
	if len(users) != 0 {
		t.Error("User was not deleted")
	}
}

func TestDeleteUserCleanup(t *testing.T) {
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})
	TokenDB = client
	setupPG(t)

	username := "cleanupuser"
	require.NoError(t, CreateUser(username, "pass123", "u@test.com", false, ""))

	// Simulate an active session, recovery codes, and a stored passkey.
	TokenDB.HSet(Ctx, "X-rauth-authtoken=tok1", "status", "valid", "username", username)
	AddSessionIndex(username, "tok1")
	_, err := GenerateRecoveryCodes(username)
	require.NoError(t, err)
	require.NoError(t, SaveWebAuthnCredential(username, &webauthn.Credential{ID: []byte("k1")}, currentGen(t, username)))

	require.NoError(t, DeleteUser(username))

	for _, key := range []string{"X-rauth-authtoken=tok1", "user_sessions:" + username} {
		n, err := client.Exists(Ctx, key).Result()
		require.NoError(t, err)
		require.Zero(t, n, "expected %s to be deleted", key)
	}
	require.Zero(t, CountRecoveryCodes(username))
	require.Empty(t, GetStoredCredentials(username))
}

func TestUpdateUser(t *testing.T) {
	setupPG(t)

	username := "updateuser"
	err := CreateUser(username, "oldpass", "old@email.com", false, "")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	t.Run("Update email and group", func(t *testing.T) {
		updates := map[string]interface{}{
			"email":  "new@email.com",
			"groups": "admins,users",
		}
		require.NoError(t, UpdateUser(username, updates))

		u, err := GetUser(username)
		require.NoError(t, err)
		require.Equal(t, "new@email.com", u.Email)
		require.Equal(t, "admins,users", u.Groups)
	})

	t.Run("Admin flag", func(t *testing.T) {
		require.NoError(t, UpdateUser(username, map[string]interface{}{"is_admin": "1"}))
		admin, err := UserIsAdmin(username)
		require.NoError(t, err)
		require.True(t, admin)
	})

	t.Run("Unknown field and user", func(t *testing.T) {
		require.Error(t, UpdateUser(username, map[string]interface{}{"uid": "x"}))
		require.ErrorIs(t, UpdateUser("nobody", map[string]interface{}{"email": "x"}), ErrUserNotFound)
	})
}

func TestGetUsernameByUID(t *testing.T) {
	setupPG(t)
	id := uuid.New()
	require.NoError(t, PutUser(User{Username: "testuser", UID: id.String()}))

	t.Run("String Lookup", func(t *testing.T) {
		username, err := GetUsernameByUID(id.String())
		require.NoError(t, err)
		require.Equal(t, "testuser", username)
	})

	t.Run("Binary Lookup", func(t *testing.T) {
		username, err := GetUsernameByUID(string(id[:]))
		require.NoError(t, err)
		require.Equal(t, "testuser", username)
	})

	t.Run("Not Found", func(t *testing.T) {
		_, err := GetUsernameByUID(uuid.NewString())
		require.ErrorIs(t, err, ErrUserNotFound)
		_, err = GetUsernameByUID("99999")
		require.ErrorIs(t, err, ErrUserNotFound)
	})
}
