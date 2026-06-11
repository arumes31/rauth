package core

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestUserManagement(t *testing.T) {
	s := miniredis.RunT(t)

	UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	AuditDB = redis.NewClient(&redis.Options{Addr: s.Addr()}) // Reuse s for simplicity
	TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

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
	UserDB = client
	AuditDB = client
	TokenDB = client

	username := "cleanupuser"
	require.NoError(t, CreateUser(username, "pass123", "u@test.com", false, ""))

	// Simulate an active session, recovery codes, and a stored passkey.
	TokenDB.HSet(Ctx, "X-rauth-authtoken=tok1", "status", "valid", "username", username)
	AddSessionIndex(username, "tok1")
	_, err := GenerateRecoveryCodes(username)
	require.NoError(t, err)
	UserDB.HSet(Ctx, "user:"+username+":webauthn_creds_v2", "abcd", "{}")

	require.NoError(t, DeleteUser(username))

	for _, key := range []string{
		"X-rauth-authtoken=tok1",
		"user_sessions:" + username,
		"user:" + username + ":recovery_codes",
		"user:" + username + ":webauthn_creds_v2",
	} {
		n, err := client.Exists(Ctx, key).Result()
		require.NoError(t, err)
		require.Zero(t, n, "expected %s to be deleted", key)
	}
}

func TestUpdateUser(t *testing.T) {
	s := miniredis.RunT(t)
	UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

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
		err := UpdateUser(username, updates)
		if err != nil {
			t.Fatalf("UpdateUser failed: %v", err)
		}

		userData, _ := UserDB.HGetAll(Ctx, "user:"+username).Result()
		if userData["email"] != "new@email.com" {
			t.Errorf("Expected email new@email.com, got %s", userData["email"])
		}
		if userData["groups"] != "admins,users" {
			t.Errorf("Expected groups admins,users, got %s", userData["groups"])
		}
	})
}

func TestGetUsernameByUID(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	UserDB = client
	Ctx = context.Background()

	t.Run("String Lookup", func(t *testing.T) {
		UserDB.Set(Ctx, "uid:12345", "testuser", 0)

		username, err := GetUsernameByUID("12345")
		require.NoError(t, err)
		require.Equal(t, "testuser", username)
	})

	t.Run("Binary Lookup", func(t *testing.T) {
		UserDB.Set(Ctx, "uid_bin:67890", "binuser", 0)

		username, err := GetUsernameByUID("67890")
		require.NoError(t, err)
		require.Equal(t, "binuser", username)
	})

	t.Run("Not Found", func(t *testing.T) {
		_, err := GetUsernameByUID("99999")
		require.Error(t, err)
	})
}
