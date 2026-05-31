package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// totpReplayWindow is how long a consumed TOTP code is remembered. It comfortably
// covers a single 30s step plus validation skew so a captured code cannot be
// replayed within its validity window.
const totpReplayWindow = 90 * time.Second

// TOTPCodeReused records a successfully validated TOTP code and reports whether
// it had already been used for this user. The first call for a (user, code) pair
// returns false and marks it; subsequent calls within the replay window return
// true. On a Redis error it returns false so a transient outage never locks a
// legitimate user out (rate limiting still bounds abuse).
func TOTPCodeReused(username, code string) bool {
	if code == "" {
		return false
	}
	key := "2fa_used:" + username + ":" + code
	ok, err := TokenDB.SetNX(Ctx, key, "1", totpReplayWindow).Result()
	if err != nil {
		return false
	}
	return !ok
}

// recoveryCodeCount is how many single-use recovery codes are issued per batch.
const recoveryCodeCount = 10

func recoveryCodesKey(username string) string { return "user:" + username + ":recovery_codes" }

// hashRecoveryCode normalizes (lowercase, strip separators) and SHA-256 hashes a
// recovery code. Only hashes are stored, so a Redis dump never exposes usable codes.
func hashRecoveryCode(code string) string {
	norm := strings.ToLower(strings.TrimSpace(code))
	norm = strings.ReplaceAll(norm, "-", "")
	norm = strings.ReplaceAll(norm, " ", "")
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}

// GenerateRecoveryCodes creates a fresh batch of single-use recovery codes,
// replacing any existing ones, and returns the plaintext codes for one-time display.
func GenerateRecoveryCodes(username string) ([]string, error) {
	codes := make([]string, 0, recoveryCodeCount)
	hashes := make([]interface{}, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		b := make([]byte, 5)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		raw := hex.EncodeToString(b) // 10 hex chars
		code := fmt.Sprintf("%s-%s", raw[:5], raw[5:])
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
	removed, err := UserDB.SRem(Ctx, recoveryCodesKey(username), hashRecoveryCode(code)).Result()
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
