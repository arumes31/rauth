package handlers

import (
	"fmt"
	"rauth/internal/core"
	"rauth/internal/pgtest"
	"testing"
)

// seedUserFields creates username if needed and sets the given fields, which
// use the same names as core.UpdateUser ("password", "2fa_secret", ...).
func seedUserFields(t testing.TB, username string, fields map[string]interface{}) {
	t.Helper()
	exists, err := core.UserExists(username)
	if err != nil {
		t.Fatalf("seed user %s: %v", username, err)
	}
	if !exists {
		u := core.User{Username: username}
		if uid, ok := fields["uid"]; ok {
			u.UID = fmt.Sprint(uid)
		}
		if err := core.PutUser(u); err != nil {
			t.Fatalf("seed user %s: %v", username, err)
		}
	}
	updates := map[string]interface{}{}
	for k, v := range fields {
		if k != "username" && k != "uid" {
			updates[k] = v
		}
	}
	if err := core.UpdateUser(username, updates); err != nil {
		t.Fatalf("seed user %s: %v", username, err)
	}
}

// userExistsN returns 1 if the account exists, else 0.
func userExistsN(t testing.TB, username string) int64 {
	t.Helper()
	exists, err := core.UserExists(username)
	if err != nil {
		t.Fatalf("user exists %s: %v", username, err)
	}
	if exists {
		return 1
	}
	return 0
}

// userField reads one stored field of an account by its UpdateUser name.
func userField(t testing.TB, username, field string) string {
	t.Helper()
	u, err := core.GetUser(username)
	if err != nil {
		return ""
	}
	switch field {
	case "password":
		return u.Password
	case "2fa_secret":
		return u.TwoFactor
	case "email":
		return u.Email
	case "is_admin":
		return u.IsAdmin
	}
	t.Fatalf("unknown user field %q", field)
	return ""
}

// seedPasskey stores raw credential JSON under the hex credential ID.
func seedPasskey(t testing.TB, username, credID, data string) {
	t.Helper()
	if _, err := core.PG.Exec(core.Ctx, `INSERT INTO webauthn_credentials (username, cred_id, data) VALUES ($1, $2, $3)
		ON CONFLICT (username, cred_id) DO UPDATE SET data = EXCLUDED.data`, username, credID, data); err != nil {
		t.Fatalf("seed passkey: %v", err)
	}
}

func passkeyExists(t testing.TB, username, credID string) bool {
	t.Helper()
	var exists bool
	if err := core.PG.QueryRow(core.Ctx, "SELECT EXISTS (SELECT 1 FROM webauthn_credentials WHERE username = $1 AND cred_id = $2)", username, credID).Scan(&exists); err != nil {
		t.Fatalf("passkey exists: %v", err)
	}
	return exists
}

// seedRecoveryHash stores an already hashed recovery code.
func seedRecoveryHash(t testing.TB, username, hash string) {
	t.Helper()
	if _, err := core.PG.Exec(core.Ctx, "INSERT INTO recovery_codes (username, code_hash) VALUES ($1, $2)", username, hash); err != nil {
		t.Fatalf("seed recovery code: %v", err)
	}
}

// removeUserRow deletes the account row directly, without DeleteUser's
// session revocation and generation bump.
func removeUserRow(t testing.TB, username string) {
	t.Helper()
	if _, err := core.PG.Exec(core.Ctx, "DELETE FROM users WHERE username = $1", username); err != nil {
		t.Fatalf("remove user: %v", err)
	}
}

func userAuditCount(t testing.TB, username string) int {
	t.Helper()
	var n int
	if err := core.PG.QueryRow(core.Ctx, "SELECT count(*) FROM audit_logs WHERE username = $1", username).Scan(&n); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	return n
}

// usePG points core.PG at this package's empty test schema, for tests that
// set up Redis themselves instead of calling setupHandlersTest.
func usePG(t testing.TB) {
	t.Helper()
	core.PG = pgtest.Open(t, core.Migrate)
	pgtest.Reset(t, core.PG)
}
