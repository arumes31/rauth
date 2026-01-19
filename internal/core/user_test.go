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

	err := CreateUser("newuser", "pass123", "user@test.com", false)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Duplicate
	err = CreateUser("newuser", "pass123", "user@test.com", false)
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

	DeleteUser("newuser")
	users, _ = ListUsers()
	if len(users) != 0 {
		t.Error("User was not deleted")
	}
}
