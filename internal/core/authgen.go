package core

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Per-user auth generation.
//
// Every session hash and pending first-factor token is stamped with the user's
// current generation at issue time. Credential changes (password change, 2FA
// reset, passkey reset, account deletion/recreation) bump the generation, and
// validators reject anything stamped with an older one. Revocation therefore no
// longer depends on the user_sessions index being complete: sessions minted
// concurrently with a revocation, dropped from the index, or copied by token
// rotation all fail the generation check.
//
// The counter lives in its own key (not the user hash) so it survives account
// deletion: a recreated account with the same name starts above every token
// issued to the deleted one.

// authGenKey returns the Redis key holding a user's auth generation.
func authGenKey(username string) string {
	return "authgen:" + username
}

// AuthGeneration returns the user's current auth generation ("0" if never bumped).
func AuthGeneration(username string) (string, error) {
	v, err := UserDB.Get(Ctx, authGenKey(username)).Result()
	if err == redis.Nil {
		return "0", nil
	}
	return v, err
}

// BumpAuthGeneration invalidates every session and pending token previously
// issued to the user and returns the new generation.
func BumpAuthGeneration(username string) (string, error) {
	n, err := UserDB.Incr(Ctx, authGenKey(username)).Result()
	if err != nil {
		slog.Error("Failed to bump auth generation", "user", username, "error", err)
		return "", err
	}
	return fmt.Sprintf("%d", n), nil
}

// sessionGen returns the generation stamped into a session hash. Sessions that
// predate generations carry none and are treated as generation "0", so they stay
// valid until the user's first credential change.
func sessionGen(data map[string]string) string {
	if g := data["auth_gen"]; g != "" {
		return g
	}
	return "0"
}

// SessionAuthorized reports whether a session hash still belongs to a live
// account at the current auth generation. It fails closed on Redis errors.
func SessionAuthorized(data map[string]string) bool {
	username := data["username"]
	if username == "" {
		return false
	}
	pipe := UserDB.Pipeline()
	exists := pipe.Exists(Ctx, "user:"+username)
	gen := pipe.Get(Ctx, authGenKey(username))
	if _, err := pipe.Exec(Ctx); err != nil && !errors.Is(err, redis.Nil) {
		slog.Error("Failed to check session authorization", "user", username, "error", err)
		return false
	}
	if exists.Val() != 1 {
		return false
	}
	current := gen.Val()
	if current == "" {
		current = "0"
	}
	return current == sessionGen(data)
}

// restampScript sets auth_gen only on an existing session hash, so a session
// deleted in the meantime is never re-created as a hash without a TTL.
var restampScript = redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 1 then
	redis.call("HSET", KEYS[1], "auth_gen", ARGV[1])
	return 1
end
return 0
`)

// RestampSession moves a surviving session to generation gen (the value
// returned by BumpAuthGeneration), used after a self-service credential change
// keeps the caller signed in.
func RestampSession(token, gen string) {
	if err := restampScript.Run(Ctx, TokenDB, []string{"X-rauth-authtoken=" + token}, gen).Err(); err != nil {
		slog.Error("Failed to restamp session generation", "error", err)
	}
}

// StoreSession atomically writes a session hash, its TTL and both revocation
// indexes. A partial failure would leave a valid session that index-based
// revocation cannot find, so callers must not issue a cookie on error.
func StoreSession(token, username, ip string, fields map[string]interface{}, validity time.Duration) error {
	redisKey := "X-rauth-authtoken=" + token
	pipe := TokenDB.TxPipeline()
	pipe.HSet(Ctx, redisKey, fields)
	pipe.Expire(Ctx, redisKey, validity)
	pipe.SAdd(Ctx, "user_sessions:"+username, token)
	pipe.SAdd(Ctx, "ip_sessions:"+ip, token)
	if _, err := pipe.Exec(Ctx); err != nil {
		// Best effort: do not leave a half-written session behind.
		TokenDB.Del(Ctx, redisKey)
		return err
	}
	return nil
}

// Pending first-factor tokens (pending_2fa / pending_setup) store
// "<username>:<generation>". Usernames cannot contain ':' (ValidateUsername),
// so the last ':' separates the fields. Values without a generation predate
// this format and are treated as generation "0".

// PendingTokenValue encodes the value stored for a pending token.
func PendingTokenValue(username string) (string, error) {
	gen, err := AuthGeneration(username)
	if err != nil {
		return "", err
	}
	return username + ":" + gen, nil
}

// ResolvePendingToken decodes a pending-token value and reports whether it is
// still at the user's current generation.
func ResolvePendingToken(value string) (string, bool) {
	username, gen := value, "0"
	if i := strings.LastIndex(value, ":"); i >= 0 {
		username, gen = value[:i], value[i+1:]
	}
	current, err := AuthGeneration(username)
	if err != nil {
		return username, false
	}
	return username, current == gen
}
