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

	"github.com/jackc/pgx/v5"
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

// SetSecondFactorIfUnset stores an encrypted TOTP secret only when the user
// exists and has none, reporting whether it was stored. A stale enrollment can
// therefore neither overwrite an enrolled TOTP nor resurrect a deleted account.
func SetSecondFactorIfUnset(username, encryptedSecret string) (bool, error) {
	tag, err := PG.Exec(Ctx, "UPDATE users SET totp_secret = $2 WHERE username = $1 AND totp_secret = ''", username, encryptedSecret)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// recoveryCodeCount is how many single-use recovery codes are issued per batch.
const recoveryCodeCount = 10

// recoveryCodeBytes is the entropy per recovery code (80 bits).
const recoveryCodeBytes = 10

// normalizeRecoveryCode lowercases a code and strips separators.
func normalizeRecoveryCode(code string) string {
	norm := strings.ToLower(strings.TrimSpace(code))
	norm = strings.ReplaceAll(norm, "-", "")
	return strings.ReplaceAll(norm, " ", "")
}

// hashRecoveryCode keys the stored hash with a secret derived from
// SERVER_SECRET, so a database dump alone does not allow offline guessing of the
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
	hashes := make([]string, 0, recoveryCodeCount)
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

	err := pgx.BeginFunc(Ctx, PG, func(tx pgx.Tx) error {
		if _, err := tx.Exec(Ctx, "DELETE FROM recovery_codes WHERE username = $1", username); err != nil {
			return err
		}
		_, err := tx.Exec(Ctx, "INSERT INTO recovery_codes (username, code_hash) SELECT $1, unnest($2::text[])", username, hashes)
		return err
	})
	if err != nil {
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
	// The DELETE is atomic, so a code (keyed or legacy hash) can only be
	// consumed once even under concurrent submissions.
	tag, err := PG.Exec(Ctx, "DELETE FROM recovery_codes WHERE username = $1 AND code_hash IN ($2, $3)",
		username, hashRecoveryCode(code), legacyHashRecoveryCode(code))
	if err != nil {
		return false
	}
	return tag.RowsAffected() > 0
}

// CountRecoveryCodes returns how many unused recovery codes remain.
func CountRecoveryCodes(username string) int64 {
	var n int64
	if err := PG.QueryRow(Ctx, "SELECT count(*) FROM recovery_codes WHERE username = $1", username).Scan(&n); err != nil {
		return 0
	}
	return n
}

// ClearRecoveryCodes removes all recovery codes for a user (used when 2FA is disabled/reset).
func ClearRecoveryCodes(username string) {
	if _, err := PG.Exec(Ctx, "DELETE FROM recovery_codes WHERE username = $1", username); err != nil {
		slog.Error("Failed to clear recovery codes", "user", username, "error", err)
	}
}
