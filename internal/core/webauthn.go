package core

import (
	"bytes"
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
)

// WebAuthnUser implements the webauthn.User interface
type WebAuthnUser struct {
	ID          []byte
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	if u == nil {
		return nil
	}
	return u.ID
}

func (u *WebAuthnUser) WebAuthnName() string {
	if u == nil {
		return ""
	}
	return u.DisplayName
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u != nil {
		return u.WebAuthnName()
	}
	return ""
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	if u == nil {
		return nil
	}
	return u.Credentials
}

func NewWebAuthnUser(user User) *WebAuthnUser {
	return &WebAuthnUser{
		ID:          []byte(user.UID),
		DisplayName: user.Username,
		Credentials: GetWebAuthnCredentials(user.Username),
	}
}

type StoredCredential struct {
	webauthn.Credential
	Nickname  string `json:"nickname"`
	CreatedAt int64  `json:"created_at"`
	LastUsed  int64  `json:"last_used"`
}

func compareStoredCredentials(a, b StoredCredential) int {
	if createdAtOrder := cmp.Compare(a.CreatedAt, b.CreatedAt); createdAtOrder != 0 {
		return createdAtOrder
	}
	return bytes.Compare(a.ID, b.ID)
}

func (s *StoredCredential) UnmarshalJSON(data []byte) error {
	type Alias struct {
		Nickname  string `json:"nickname"`
		CreatedAt int64  `json:"created_at"`
		LastUsed  int64  `json:"last_used"`
	}
	var aux Alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	s.Nickname = aux.Nickname
	s.CreatedAt = aux.CreatedAt
	s.LastUsed = aux.LastUsed
	return json.Unmarshal(data, &s.Credential)
}

var WebAuthnInstance *webauthn.WebAuthn

func InitWebAuthn(cfg *Config) error {
	var err error

	// Collect origins
	originMap := make(map[string]bool)

	if len(cfg.WebAuthnOrigins) > 0 {
		for _, o := range cfg.WebAuthnOrigins {
			trimmed := strings.TrimSuffix(strings.TrimSpace(o), "/")
			if trimmed == "" {
				continue
			}
			if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
				// WebAuthn only works in a secure context, so a bare host means
				// https. Plain http is accepted only when spelled out explicitly.
				originMap["https://"+trimmed] = true
			} else {
				originMap[trimmed] = true
			}
		}
	} else {
		// Generate defaults from CookieDomains and AllowedHosts
		for _, domain := range cfg.CookieDomains {
			originMap[fmt.Sprintf("https://%s", domain)] = true
			originMap[fmt.Sprintf("https://%s:5980", domain)] = true
		}
		for _, host := range cfg.AllowedHosts {
			originMap[fmt.Sprintf("https://%s", host)] = true
			originMap[fmt.Sprintf("https://%s:5980", host)] = true
		}
		// Always include standard local dev
		originMap["http://localhost:5980"] = true
		originMap["http://127.0.0.1:5980"] = true
		originMap["http://localhost"] = true
		originMap["http://127.0.0.1"] = true
	}

	origins := slices.Collect(maps.Keys(originMap))

	slog.Info("WebAuthn registered origins", "origins", origins)

	// A passkey login replaces password and TOTP. User verification is
	// requested ("preferred") by default so providers such as Bitwarden keep
	// working, and enforced when WEBAUTHN_USER_VERIFICATION=required.
	userVerification := protocol.VerificationPreferred
	if cfg.WebAuthnRequireUserVerification {
		userVerification = protocol.VerificationRequired
	}

	WebAuthnInstance, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "RAuth",
		RPID:          cfg.CookieDomains[0],
		RPOrigins:     origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: userVerification,
		},
	})
	return err
}

// ErrStaleGeneration reports that a credential change was authorized under a
// generation that a revocation has since replaced.
var ErrStaleGeneration = errors.New("authorization was revoked during the request")

// SaveWebAuthnCredential stores a newly registered passkey, provided the user
// is still at generation gen (the one the registration was authorized under).
// A registration that a 2FA reset or account deletion overtook is rejected
// with ErrStaleGeneration instead of re-adding a factor the reset removed.
func SaveWebAuthnCredential(username string, cred *webauthn.Credential, gen string) error {
	stored := StoredCredential{
		Credential: *cred,
		Nickname:   fmt.Sprintf("Key %d", len(GetWebAuthnCredentials(username))+1),
		CreatedAt:  time.Now().Unix(),
	}
	data, _ := json.Marshal(stored)
	return pgx.BeginFunc(Ctx, PG, func(tx pgx.Tx) error {
		current, err := lockAuthGeneration(tx, username, gen)
		if err != nil {
			return err
		}
		if !current {
			return ErrStaleGeneration
		}
		// The foreign key rejects a credential for an account deleted meanwhile.
		_, err = tx.Exec(Ctx, `INSERT INTO webauthn_credentials (username, cred_id, data, created_at) VALUES ($1, $2, $3, $4)
			ON CONFLICT (username, cred_id) DO UPDATE SET data = EXCLUDED.data`,
			username, fmt.Sprintf("%x", cred.ID), data, stored.CreatedAt)
		return err
	})
}

// DummyWebAuthnUser stands in for an unknown account, or one without
// passkeys, when a username-first passkey login starts. It carries one
// credential whose ID is derived from SERVER_SECRET and the name, so the
// options look like an enrolled account's and stay stable across requests,
// instead of an error that reveals the account does not exist.
func DummyWebAuthnUser(username string) *WebAuthnUser {
	mac := hmac.New(sha256.New, deriveKey("rauth-webauthn-dummy"))
	mac.Write([]byte(username))
	id := mac.Sum(nil)
	return &WebAuthnUser{
		ID:          id[:16],
		DisplayName: username,
		Credentials: []webauthn.Credential{{ID: id, Transport: []protocol.AuthenticatorTransport{protocol.Internal, protocol.Hybrid}}},
	}
}

func GetWebAuthnCredentials(username string) []webauthn.Credential {
	stored := GetStoredCredentials(username)
	if len(stored) == 0 {
		return nil
	}

	creds := make([]webauthn.Credential, len(stored))
	for i := range stored {
		creds[i] = stored[i].Credential
	}
	return creds
}

func GetStoredCredentials(username string) []StoredCredential {
	rows, err := PG.Query(Ctx, "SELECT data FROM webauthn_credentials WHERE username = $1", username)
	if err != nil {
		slog.Error("Failed to load passkeys", "user", username, "error", err)
		return nil
	}
	defer rows.Close()

	var creds []StoredCredential
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var c StoredCredential
		if err := json.Unmarshal(raw, &c); err == nil {
			creds = append(creds, c)
		}
	}
	// Sort by CreatedAt to maintain consistent order
	slices.SortFunc(creds, compareStoredCredentials)
	return creds
}

// ErrCredentialGone reports that a credential (or its account) was removed
// while it was being updated.
var ErrCredentialGone = errors.New("credential or account no longer exists")

// updateStoredCredential applies mutate to a stored credential. The row is
// locked for the read-modify-write, so concurrent updates (sign count,
// nickname, last used) cannot overwrite each other, and a credential removed
// concurrently is never re-created (passkeys cascade with their account).
func updateStoredCredential(username, credID string, mutate func(*StoredCredential)) error {
	return pgx.BeginFunc(Ctx, PG, func(tx pgx.Tx) error {
		var raw []byte
		err := tx.QueryRow(Ctx, "SELECT data FROM webauthn_credentials WHERE username = $1 AND cred_id = $2 FOR UPDATE", username, credID).Scan(&raw)
		if isNoRows(err) {
			return ErrCredentialGone
		}
		if err != nil {
			return err
		}
		var c StoredCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		mutate(&c)
		data, _ := json.Marshal(c)
		_, err = tx.Exec(Ctx, "UPDATE webauthn_credentials SET data = $3 WHERE username = $1 AND cred_id = $2", username, credID, data)
		return err
	})
}

func UpdateWebAuthnSignCount(username string, credID []byte, newCount uint32) error {
	return updateStoredCredential(username, fmt.Sprintf("%x", credID), func(c *StoredCredential) {
		c.Authenticator.SignCount = newCount
		c.LastUsed = time.Now().Unix()
	})
}

// DeleteAllWebAuthnCredentials removes every passkey of a user (used by the
// admin 2FA reset).
func DeleteAllWebAuthnCredentials(username string) error {
	_, err := PG.Exec(Ctx, "DELETE FROM webauthn_credentials WHERE username = $1", username)
	return err
}

func DeleteWebAuthnCredential(username string, credID string) error {
	_, err := PG.Exec(Ctx, "DELETE FROM webauthn_credentials WHERE username = $1 AND cred_id = $2", username, credID)
	return err
}

func UpdateWebAuthnNickname(username string, credID string, nickname string) error {
	return updateStoredCredential(username, credID, func(c *StoredCredential) {
		c.Nickname = nickname
	})
}

func UpdateWebAuthnLastUsed(username string, credID []byte) error {
	return updateStoredCredential(username, fmt.Sprintf("%x", credID), func(c *StoredCredential) {
		c.LastUsed = time.Now().Unix()
	})
}

func UpdateWebAuthnCredential(username string, cred *webauthn.Credential) error {
	return updateStoredCredential(username, fmt.Sprintf("%x", cred.ID), func(c *StoredCredential) {
		c.Credential = *cred
		c.LastUsed = time.Now().Unix()
	})
}
