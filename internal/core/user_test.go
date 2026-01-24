package core

import (
	"testing"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestUserManagement(t *testing.T) {
	s := miniredis.RunT(t)
	
	UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	AuditDB = redis.NewClient(&redis.Options{Addr: s.Addr()}) // Reuse s for simplicity

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

func TestUpdateUser(t *testing.T) {
	s := miniredis.RunT(t)
	UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	username := "updateuser"
	CreateUser(username, "oldpass", "old@email.com", false, "")

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
