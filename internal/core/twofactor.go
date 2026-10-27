package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// totpReplayWindow is how long a consumed TOTP code is remembered. It comfortably
// covers a single 30s step plus validation skew so a captured code cannot be
// replayed within its validity window.
const totpReplayWindow = 90 * time.Second

// TOTPCodeReused records a successfully validated TOTP code and reports whether
// it had already been used for this user. The first call for a (user, code) pair
// returns false and marks it; subsequent calls within the replay window return
// true. On a Redis error it fails closed (reports reuse): replay protection
// must not silently disappear during an outage, and the rate limiters already
// fail closed under the same conditions.
func TOTPCodeReused(username, code string) bool {
	if code == "" {
		return false
	}
	key := "2fa_used:" + username + ":" + code
	ok, err := TokenDB.SetNX(Ctx, key, "1", totpReplayWindow).Result()
	if err != nil {
		slog.Error("TOTP replay check failed, failing closed", "user", username, "error", err)
		return true
	}
	return !ok
}

// setSecondFactorScript writes 2fa_secret only if the account exists (has a
// username field) and has no second factor yet, so a stale enrollment can
// neither overwrite an enrolled TOTP nor create a stub hash for a deleted user.
var setSecondFactorScript = redis.NewScript(`
if redis.call("HEXISTS", KEYS[1], "username") == 0 then
	return 0
end
local current = redis.call("HGET", KEYS[1], "2fa_secret")
if current and current ~= "" then
	return 0
end
redis.call("HSET", KEYS[1], "2fa_secret", ARGV[1])
return 1
`)

// SetSecondFactorIfUnset stores an encrypted TOTP secret only when the user
// exists and has none, reporting whether it was stored.
func SetSecondFactorIfUnset(username, encryptedSecret string) (bool, error) {
	n, err := setSecondFactorScript.Run(Ctx, UserDB, []string{"user:" + username}, encryptedSecret).Int()
	return n == 1, err
}

// recoveryCodeCount is how many single-use recovery codes are issued per batch.
const recoveryCodeCount = 10

// recoveryCodeBytes is the entropy per recovery code (80 bits).
const recoveryCodeBytes = 10

func recoveryCodesKey(username string) string { return "user:" + username + ":recovery_codes" }

// normalizeRecoveryCode lowercases a code and strips separators.
func normalizeRecoveryCode(code string) string {
	norm := strings.ToLower(strings.TrimSpace(code))
	norm = strings.ReplaceAll(norm, "-", "")
	return strings.ReplaceAll(norm, " ", "")
}

// hashRecoveryCode keys the stored hash with a secret derived from
// SERVER_SECRET, so a Redis dump alone does not allow offline guessing of the
// codes. Only hashes are stored.
func hashRecoveryCode(code string) string {
	mac := hmac.New(sha256.New, deriveKey("rauth-recovery-codes"))
	mac.Write([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(mac.Sum(nil))
}

// legacyHashRecoveryCode is the unkeyed SHA-256 used before keyed hashes;
// codes issued under it remain redeemable until regenerated.
func legacyHashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

// GenerateRecoveryCodes creates a fresh batch of single-use recovery codes,
// replacing any existing ones, and returns the plaintext codes for one-time display.
func GenerateRecoveryCodes(username string) ([]string, error) {
	codes := make([]string, 0, recoveryCodeCount)
	hashes := make([]interface{}, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		b := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		raw := hex.EncodeToString(b) // 20 hex chars
		code := fmt.Sprintf("%s-%s-%s-%s", raw[:5], raw[5:10], raw[10:15], raw[15:])
		codes = append(codes, code)
		hashes = append(hashes, hashRecoveryCode(code))
	}

	key := recoveryCodesKey(username)
	pipe := UserDB.Pipeline()
	pipe.Del(Ctx, key)
	pipe.SAdd(Ctx, key, hashes...)
	if _, err := pipe.Exec(Ctx); err != nil {
		return nil, err
	}
	return codes, nil
}

// ConsumeRecoveryCode atomically validates and consumes a recovery code,
// returning true only if it was present (and is now removed).
func ConsumeRecoveryCode(username, code string) bool {
	if strings.TrimSpace(code) == "" {
		return false
	}
	// SREM is atomic per call, so a code (keyed or legacy hash) can only be
	// consumed once even under concurrent submissions.
	removed, err := UserDB.SRem(Ctx, recoveryCodesKey(username), hashRecoveryCode(code), legacyHashRecoveryCode(code)).Result()
	if err != nil {
		return false
	}
	return removed > 0
}

// CountRecoveryCodes returns how many unused recovery codes remain.
func CountRecoveryCodes(username string) int64 {
	n, err := UserDB.SCard(Ctx, recoveryCodesKey(username)).Result()
	if err != nil {
		return 0
	}
	return n
}

// ClearRecoveryCodes removes all recovery codes for a user (used when 2FA is disabled/reset).
func ClearRecoveryCodes(username string) {
	UserDB.Del(Ctx, recoveryCodesKey(username))
}
