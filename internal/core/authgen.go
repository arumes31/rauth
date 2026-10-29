package core

import (
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
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
// The counter lives in its own table (not the users row) so it survives
// account deletion: a recreated account with the same name starts above every
// token issued to the deleted one.

// AuthGeneration returns the user's current auth generation ("0" if never bumped).
func AuthGeneration(username string) (string, error) {
	var gen int64
	err := PG.QueryRow(Ctx, "SELECT gen FROM auth_generations WHERE username = $1", username).Scan(&gen)
	if isNoRows(err) {
		return "0", nil
	}
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(gen, 10), nil
}

// BumpAuthGeneration invalidates every session and pending token previously
// issued to the user and returns the new generation.
func BumpAuthGeneration(username string) (string, error) {
	gen, err := RevokeAuth(username, nil)
	if err != nil {
		slog.Error("Failed to bump auth generation", "user", username, "error", err)
	}
	return gen, err
}

// RevokeAuth bumps the user's generation and applies a credential change
// (change may be nil) in one transaction, returning the new generation.
//
// Authentication reads the generation before it reads credentials and stamps
// that value into what it issues, so committing both together means proof
// checked against the old credentials always carries the old generation.
// The bump comes first so its row lock is held until commit: enrollment
// writes that call lockAuthGeneration wait for the whole change, and a
// factor deleted by change cannot be re-added by one already in flight.
func RevokeAuth(username string, change func(tx pgx.Tx) error) (string, error) {
	var n int64
	err := pgx.BeginFunc(Ctx, PG, func(tx pgx.Tx) error {
		if err := tx.QueryRow(Ctx, `INSERT INTO auth_generations (username, gen) VALUES ($1, 1)
			ON CONFLICT (username) DO UPDATE SET gen = auth_generations.gen + 1
			RETURNING gen`, username).Scan(&n); err != nil {
			return err
		}
		if change == nil {
			return nil
		}
		return change(tx)
	})
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(n, 10), nil
}

// lockAuthGeneration locks the user's generation row until tx ends and
// reports whether it still equals want. Writes that add a factor on the
// strength of an earlier check (enrollment, passkey registration) run under
// it, so they either finish before a concurrent RevokeAuth (which then undoes
// them) or see the new generation and stop.
func lockAuthGeneration(tx pgx.Tx, username, want string) (bool, error) {
	// The row must exist to be locked; gen 0 is what AuthGeneration reports
	// for a missing row anyway. A concurrent first bump makes this wait.
	if _, err := tx.Exec(Ctx, "INSERT INTO auth_generations (username, gen) VALUES ($1, 0) ON CONFLICT (username) DO NOTHING", username); err != nil {
		return false, err
	}
	var gen int64
	if err := tx.QueryRow(Ctx, "SELECT gen FROM auth_generations WHERE username = $1 FOR SHARE", username).Scan(&gen); err != nil {
		return false, err
	}
	return strconv.FormatInt(gen, 10) == want, nil
}

// SessionGen returns the generation stamped into a session hash. Sessions that
// predate generations carry none and are treated as generation "0", so they stay
// valid until the user's first credential change.
func SessionGen(data map[string]string) string {
	if g := data["auth_gen"]; g != "" {
		return g
	}
	return "0"
}

// SessionAuthorized reports whether a session hash still belongs to a live
// account at the current auth generation. It fails closed on database errors.
func SessionAuthorized(data map[string]string) bool {
	username := data["username"]
	if username == "" {
		return false
	}
	var exists bool
	var gen int64
	err := PG.QueryRow(Ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE username = $1),
		COALESCE((SELECT gen FROM auth_generations WHERE username = $1), 0)`, username).Scan(&exists, &gen)
	if err != nil {
		slog.Error("Failed to check session authorization", "user", username, "error", err)
		return false
	}
	return exists && strconv.FormatInt(gen, 10) == SessionGen(data)
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

// PendingTokenValue encodes the value stored for a pending token. gen is the
// generation read before the credentials were checked, never a fresh read: a
// revocation in between must leave the token stale.
func PendingTokenValue(username, gen string) string {
	return username + ":" + gen
}

// ResolvePendingToken decodes a pending-token value and returns the username
// and generation, reporting whether that generation is still current. The
// session issued at the end of the flow carries the returned generation.
func ResolvePendingToken(value string) (string, string, bool) {
	username, gen := value, "0"
	if i := strings.LastIndex(value, ":"); i >= 0 {
		username, gen = value[:i], value[i+1:]
	}
	current, err := AuthGeneration(username)
	if err != nil {
		return username, gen, false
	}
	return username, gen, current == gen
}
