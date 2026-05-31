package core

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type User struct {
	Username  string `json:"username" redis:"username"`
	Password  string `json:"password" redis:"password"`
	Email     string `json:"email" redis:"email"`
	Groups    string `json:"groups" redis:"groups"`
	IsAdmin   string `json:"is_admin" redis:"is_admin"`
	TwoFactor string `json:"2fa_secret" redis:"2fa_secret"`
	UID       string `json:"uid" redis:"uid"`
	CreatedAt int64  `json:"created_at" redis:"created_at"`
}

func ListUsers() ([]User, error) {
	usernames, err := UserDB.SMembers(Ctx, "users").Result()
	if err != nil {
		return nil, err
	}

	if len(usernames) == 0 {
		return []User{}, nil
	}

	pipe := UserDB.Pipeline()
	cmds := make(map[string]*redis.MapStringStringCmd, len(usernames))
	for _, username := range usernames {
		cmds[username] = pipe.HGetAll(Ctx, "user:"+username)
	}

	if _, err := pipe.Exec(Ctx); err != nil {
		return nil, err
	}

	var users []User
	for _, username := range usernames {
		var user User
		err := cmds[username].Scan(&user)
		if err != nil || user.Username == "" {
			continue
		}
		// UID backfill is handled at startup by EnsureUserUIDs, so no per-row
		// mutation is needed here.
		users = append(users, user)
	}
	return users, nil
}

// GetUser reads a user record. It is side-effect free; UID backfill for legacy
// records is handled by EnsureUserUIDs at startup and by CreateUser for new users.
func GetUser(username string) (User, error) {
	var user User
	err := UserDB.HGetAll(Ctx, "user:"+username).Scan(&user)
	if err != nil {
		return user, err
	}
	if user.Username == "" {
		return user, fmt.Errorf("user not found")
	}
	return user, nil
}

// ensureUID assigns a UID and its lookup indexes to a user that lacks one.
func ensureUID(username string) (string, error) {
	newUUID := uuid.New()
	uidStr := newUUID.String()
	// Write the lookup indexes first and verify they succeed. Only then stamp the
	// "uid" field on the user hash: if an index write fails we leave the user
	// un-stamped so EnsureUserUIDs retries on the next startup, and
	// GetUsernameByUID can rely on the indexes being consistent with the field.
	if err := UserDB.Set(Ctx, "uid:"+uidStr, username, 0).Err(); err != nil {
		return "", err
	}
	// Index by binary representation as well for raw UserHandle lookups.
	if err := UserDB.Set(Ctx, "uid_bin:"+string(newUUID[:]), username, 0).Err(); err != nil {
		return "", err
	}
	if err := UserDB.HSet(Ctx, "user:"+username, "uid", uidStr).Err(); err != nil {
		return "", err
	}
	return uidStr, nil
}

// EnsureUserUIDs backfills UIDs for any legacy users created before UIDs
// existed. Run once at startup so GetUser can remain read-only.
func EnsureUserUIDs() {
	usernames, err := UserDB.SMembers(Ctx, "users").Result()
	if err != nil {
		slog.Error("EnsureUserUIDs: failed to list users", "error", err)
		return
	}
	for _, username := range usernames {
		uid, err := UserDB.HGet(Ctx, "user:"+username, "uid").Result()
		if err == nil && uid != "" {
			continue
		}
		// Only the missing-field case (redis.Nil) warrants a backfill; a real
		// Redis error must not be mistaken for "no uid" and trigger a rewrite.
		if err != nil && err != redis.Nil {
			slog.Error("EnsureUserUIDs: failed to read uid", "user", username, "error", err)
			continue
		}
		if _, err := ensureUID(username); err != nil {
			slog.Warn("EnsureUserUIDs: failed to backfill UID", "user", username, "error", err)
		}
	}
}

func CreateUser(username, password, email string, isAdmin bool, twoFactor string) error {
	exists, err := UserDB.Exists(Ctx, "user:"+username).Result()
	if err != nil {
		return err
	}
	if exists > 0 {
		return fmt.Errorf("user already exists")
	}

	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	adminVal := "0"
	if isAdmin {
		adminVal = "1"
	}

	newUUID := uuid.New()
	uidStr := newUUID.String()
	user := map[string]interface{}{
		"username":   username,
		"password":   hash,
		"email":      email,
		"is_admin":   adminVal,
		"groups":     "default",
		"uid":        uidStr,
		"created_at": time.Now().Unix(),
		"2fa_secret": Encrypt2FASecret(twoFactor, ServerSecret),
	}

	err = UserDB.HSet(Ctx, "user:"+username, user).Err()
	if err != nil {
		return err
	}

	// Add UID indexes for nameless passkey login
	UserDB.Set(Ctx, "uid:"+uidStr, username, 0)
	UserDB.Set(Ctx, "uid_bin:"+string(newUUID[:]), username, 0)

	return UserDB.SAdd(Ctx, "users", username).Err()
}

func DeleteUser(username string) error {
	user, err := GetUser(username)
	if err == nil {
		UserDB.Del(Ctx, "uid:"+user.UID)
		if u, err := uuid.Parse(user.UID); err == nil {
			UserDB.Del(Ctx, "uid_bin:"+string(u[:]))
		}
	}
	if err := UserDB.Del(Ctx, "user:"+username).Err(); err != nil {
		return err
	}
	return UserDB.SRem(Ctx, "users", username).Err()
}

func UpdateUser(username string, updates map[string]interface{}) error {
	return UserDB.HSet(Ctx, "user:"+username, updates).Err()
}

func GetUsernameByUID(uid string) (string, error) {
	// Try string lookup first
	if val, err := UserDB.Get(Ctx, "uid:"+uid).Result(); err == nil {
		return val, nil
	}
	// Try binary lookup
	return UserDB.Get(Ctx, "uid_bin:"+uid).Result()
}
