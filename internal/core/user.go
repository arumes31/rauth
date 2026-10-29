package core

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type User struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Email     string `json:"email"`
	Groups    string `json:"groups"`
	IsAdmin   string `json:"is_admin"`
	TwoFactor string `json:"2fa_secret"`
	UID       string `json:"uid"`
	CreatedAt int64  `json:"created_at"`
}

// ErrUserNotFound reports that no account exists with the given name or UID.
var ErrUserNotFound = errors.New("user not found")

const userColumns = "username, password, email, groups, is_admin, totp_secret, COALESCE(uid::text, ''), created_at"

func scanUser(row pgx.Row) (User, error) {
	var u User
	var admin bool
	err := row.Scan(&u.Username, &u.Password, &u.Email, &u.Groups, &admin, &u.TwoFactor, &u.UID, &u.CreatedAt)
	if isNoRows(err) {
		return User{}, ErrUserNotFound
	}
	u.IsAdmin = boolFlag(admin)
	return u, err
}

func boolFlag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func ListUsers() ([]User, error) {
	rows, err := PG.Query(Ctx, "SELECT "+userColumns+" FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// GetUser reads a user record, returning ErrUserNotFound for unknown names.
func GetUser(username string) (User, error) {
	return scanUser(PG.QueryRow(Ctx, "SELECT "+userColumns+" FROM users WHERE username = $1", username))
}

// UserExists reports whether an account with the given name exists.
func UserExists(username string) (bool, error) {
	var exists bool
	err := PG.QueryRow(Ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", username).Scan(&exists)
	return exists, err
}

// UserIsAdmin reads the live admin flag. A missing account is not an admin.
func UserIsAdmin(username string) (bool, error) {
	var admin bool
	err := PG.QueryRow(Ctx, "SELECT is_admin FROM users WHERE username = $1", username).Scan(&admin)
	if isNoRows(err) {
		return false, nil
	}
	return admin, err
}

// PutUser inserts or fully replaces a user record as given, without hashing
// or encrypting anything. It is used to import existing records; new accounts
// go through CreateUser.
func PutUser(u User) error {
	var uid any
	if u.UID != "" {
		parsed, err := uuid.Parse(u.UID)
		if err != nil {
			return fmt.Errorf("invalid uid for %s: %w", u.Username, err)
		}
		uid = parsed
	}
	groups := u.Groups
	if groups == "" {
		groups = "default"
	}
	_, err := PG.Exec(Ctx, `INSERT INTO users (username, password, email, groups, is_admin, totp_secret, uid, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password, email = EXCLUDED.email,
			groups = EXCLUDED.groups, is_admin = EXCLUDED.is_admin, totp_secret = EXCLUDED.totp_secret,
			uid = EXCLUDED.uid, created_at = EXCLUDED.created_at`,
		u.Username, u.Password, u.Email, groups, u.IsAdmin == "1", u.TwoFactor, uid, u.CreatedAt)
	return err
}

// EnsureUserUIDs backfills UIDs for any legacy users created before UIDs
// existed. Run once at startup so GetUser can remain read-only.
func EnsureUserUIDs() {
	tag, err := PG.Exec(Ctx, "UPDATE users SET uid = gen_random_uuid() WHERE uid IS NULL")
	if err != nil {
		slog.Error("EnsureUserUIDs: backfill failed", "error", err)
		return
	}
	if n := tag.RowsAffected(); n > 0 {
		slog.Info("Backfilled user UIDs", "count", n)
	}
}

// MigratePlaintextTOTPSecrets encrypts TOTP secrets stored by versions that
// predate at-rest encryption, so a database dump no longer exposes them.
func MigratePlaintextTOTPSecrets() {
	rows, err := PG.Query(Ctx, "SELECT username, totp_secret FROM users WHERE totp_secret <> '' AND totp_secret NOT LIKE 'enc:%'")
	if err != nil {
		slog.Error("MigratePlaintextTOTPSecrets: failed to list users", "error", err)
		return
	}
	type legacy struct{ username, secret string }
	var pending []legacy
	for rows.Next() {
		var l legacy
		if err := rows.Scan(&l.username, &l.secret); err == nil {
			pending = append(pending, l)
		}
	}
	rows.Close()

	for _, l := range pending {
		encrypted, err := Encrypt2FASecret(l.secret, ServerSecret)
		if err != nil {
			slog.Error("MigratePlaintextTOTPSecrets: encryption failed", "user", l.username, "error", err)
			continue
		}
		// Only replace the exact plaintext read, so a concurrent change is never clobbered.
		if _, err := PG.Exec(Ctx, "UPDATE users SET totp_secret = $3 WHERE username = $1 AND totp_secret = $2", l.username, l.secret, encrypted); err != nil {
			slog.Error("MigratePlaintextTOTPSecrets: write failed", "user", l.username, "error", err)
			continue
		}
		slog.Info("Encrypted legacy plaintext TOTP secret", "user", l.username)
	}
}

// errUserExists is returned by CreateUser when the name is taken.
var errUserExists = errors.New("user already exists")

func CreateUser(username, password, email string, isAdmin bool, twoFactor string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	encryptedSecret, err := Encrypt2FASecret(twoFactor, ServerSecret)
	if err != nil {
		return err
	}

	// The primary key makes the insert the atomic claim on the name. Recovery
	// codes and passkeys cascade with the account row, so a recreated name
	// cannot inherit them. The generation bump in the same transaction keeps
	// sessions and pending tokens of an earlier account with this name dead.
	_, err = RevokeAuth(username, func(tx pgx.Tx) error {
		_, err := tx.Exec(Ctx, `INSERT INTO users (username, password, email, groups, is_admin, totp_secret, uid, created_at)
			VALUES ($1, $2, $3, 'default', $4, $5, $6, $7)`,
			username, hash, email, isAdmin, encryptedSecret, uuid.New(), time.Now().Unix())
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return errUserExists
	}
	return err
}

func DeleteUser(username string) error {
	// The generation bump commits with the delete, invalidating every session
	// and pending token, including ones the session index does not know about
	// or that are being minted concurrently. Recovery codes and passkeys are
	// removed by ON DELETE CASCADE. Audit entries are kept; profile views only
	// show entries of the current account.
	if _, err := RevokeAuth(username, func(tx pgx.Tx) error {
		_, err := tx.Exec(Ctx, "DELETE FROM users WHERE username = $1", username)
		return err
	}); err != nil {
		return err
	}
	// A deleted user must not retain a usable session until token expiry.
	_ = InvalidateUserSessions(username)
	return nil
}

// SetPassword replaces a user's password hash and revokes every session and
// pending login in the same transaction, returning the new generation.
func SetPassword(username, hash string) (string, error) {
	return RevokeAuth(username, func(tx pgx.Tx) error {
		return updateExactlyOne(tx, "UPDATE users SET password = $2 WHERE username = $1", username, hash)
	})
}

// updateExactlyOne runs an UPDATE of one users row, reporting ErrUserNotFound
// when the account is gone.
func updateExactlyOne(tx pgx.Tx, sql string, args ...any) error {
	tag, err := tx.Exec(Ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// userUpdateColumns maps the field names callers use to their columns.
var userUpdateColumns = map[string]string{
	"password":   "password",
	"email":      "email",
	"groups":     "groups",
	"is_admin":   "is_admin",
	"2fa_secret": "totp_secret",
}

// UpdateUser sets the given fields of an existing user.
func UpdateUser(username string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}
	sets := make([]string, 0, len(updates))
	args := []any{username}
	for field, value := range updates {
		col, ok := userUpdateColumns[field]
		if !ok {
			return fmt.Errorf("unknown user field %q", field)
		}
		if col == "is_admin" {
			value = fmt.Sprint(value) == "1"
		}
		args = append(args, value)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	tag, err := PG.Exec(Ctx, "UPDATE users SET "+strings.Join(sets, ", ")+" WHERE username = $1", args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// GetUsernameByUID resolves a WebAuthn user handle, given either as the UUID
// string or as its 16 raw bytes.
func GetUsernameByUID(uid string) (string, error) {
	id, err := uuid.Parse(uid)
	if err != nil {
		if len(uid) != 16 {
			return "", ErrUserNotFound
		}
		id, err = uuid.FromBytes([]byte(uid))
		if err != nil {
			return "", ErrUserNotFound
		}
	}
	var username string
	err = PG.QueryRow(Ctx, "SELECT username FROM users WHERE uid = $1", id).Scan(&username)
	if isNoRows(err) {
		return "", ErrUserNotFound
	}
	return username, err
}
