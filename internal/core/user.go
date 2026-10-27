package core

import (
	"fmt"
	"log/slog"
	"strings"
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

	pipe := UserDB.TxPipeline()
	pipe.Set(Ctx, "uid:"+uidStr, username, 0)
	pipe.Set(Ctx, "uid_bin:"+string(newUUID[:]), username, 0)
	pipe.HSet(Ctx, "user:"+username, "uid", uidStr)

	if _, err := pipe.Exec(Ctx); err != nil {
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

	if len(usernames) == 0 {
		return
	}

	pipe := UserDB.Pipeline()
	cmds := make(map[string]*redis.StringCmd, len(usernames))
	for _, username := range usernames {
		cmds[username] = pipe.HGet(Ctx, "user:"+username, "uid")
	}

	// pipe.Exec returns the first error encountered by any command in the pipeline.
	// We ignore redis.Nil here because it's expected for users needing backfill.
	_, err = pipe.Exec(Ctx)
	if err != nil && err != redis.Nil {
		slog.Error("EnsureUserUIDs: pipeline failed", "error", err)
		return
	}

	for _, username := range usernames {
		uid, err := cmds[username].Result()
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

// migratePlaintextTOTPScript re-encrypts a legacy secret only if it is still
// the exact plaintext value read, so a concurrent change is never clobbered.
var migratePlaintextTOTPScript = redis.NewScript(`
if redis.call("HGET", KEYS[1], "2fa_secret") == ARGV[1] then
	redis.call("HSET", KEYS[1], "2fa_secret", ARGV[2])
	return 1
end
return 0
`)

// MigratePlaintextTOTPSecrets encrypts TOTP secrets stored by versions that
// predate at-rest encryption, so a Redis dump no longer exposes them.
func MigratePlaintextTOTPSecrets() {
	usernames, err := UserDB.SMembers(Ctx, "users").Result()
	if err != nil {
		slog.Error("MigratePlaintextTOTPSecrets: failed to list users", "error", err)
		return
	}
	for _, username := range usernames {
		secret, err := UserDB.HGet(Ctx, "user:"+username, "2fa_secret").Result()
		if err != nil || secret == "" || strings.HasPrefix(secret, "enc:") {
			continue
		}
		encrypted, err := Encrypt2FASecret(secret, ServerSecret)
		if err != nil {
			slog.Error("MigratePlaintextTOTPSecrets: encryption failed", "user", username, "error", err)
			continue
		}
		if err := migratePlaintextTOTPScript.Run(Ctx, UserDB, []string{"user:" + username}, secret, encrypted).Err(); err != nil {
			slog.Error("MigratePlaintextTOTPSecrets: write failed", "user", username, "error", err)
			continue
		}
		slog.Info("Encrypted legacy plaintext TOTP secret", "user", username)
	}
}

func CreateUser(username, password, email string, isAdmin bool, twoFactor string) error {
	// Hash before claiming the name so a slow bcrypt never holds a half-created
	// record visible to concurrent logins.
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	// Atomically claim the username: HSETNX on the "username" field fails when a
	// real account exists, so two concurrent creations cannot overwrite each
	// other. A stub hash without a username field (left by a stale write to a
	// deleted account) is taken over and fully overwritten below.
	claimed, err := UserDB.HSetNX(Ctx, "user:"+username, "username", username).Result()
	if err != nil {
		return err
	}
	if !claimed {
		return fmt.Errorf("user already exists")
	}

	// A recreated name must not inherit satellite state that survived (or was
	// re-materialized after) a previous deletion, nor any of its sessions or
	// pending tokens.
	ClearRecoveryCodes(username)
	UserDB.Del(Ctx, "user:"+username+":webauthn_creds_v2", "user:"+username+":webauthn_creds")
	if _, err := BumpAuthGeneration(username); err != nil {
		UserDB.Del(Ctx, "user:"+username)
		return err
	}

	adminVal := "0"
	if isAdmin {
		adminVal = "1"
	}

	encryptedSecret, err := Encrypt2FASecret(twoFactor, ServerSecret)
	if err != nil {
		return err
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
		"2fa_secret": encryptedSecret,
	}

	err = UserDB.HSet(Ctx, "user:"+username, user).Err()
	if err != nil {
		UserDB.Del(Ctx, "user:"+username)
		return err
	}

	// Add UID indexes for nameless passkey login
	UserDB.Set(Ctx, "uid:"+uidStr, username, 0)
	UserDB.Set(Ctx, "uid_bin:"+string(newUUID[:]), username, 0)

	return UserDB.SAdd(Ctx, "users", username).Err()
}

func DeleteUser(username string) error {
	// Invalidate every session and pending token first, including ones the
	// session index does not know about or that are being minted concurrently.
	if _, err := BumpAuthGeneration(username); err != nil {
		return err
	}
	user, err := GetUser(username)
	if err == nil {
		UserDB.Del(Ctx, "uid:"+user.UID)
		if u, err := uuid.Parse(user.UID); err == nil {
			UserDB.Del(Ctx, "uid_bin:"+string(u[:]))
		}
	}
	AuditDB.Del(Ctx, "user_audit_logs:"+username)
	// A deleted user must not retain a usable session until token expiry.
	_ = InvalidateUserSessions(username)
	// Remove per-user satellite keys so a future account with the same name
	// does not inherit recovery codes or passkeys.
	ClearRecoveryCodes(username)
	UserDB.Del(Ctx, "user:"+username+":webauthn_creds_v2", "user:"+username+":webauthn_creds")
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
