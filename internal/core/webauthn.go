package core

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
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

func SaveWebAuthnCredential(username string, cred *webauthn.Credential) error {
	hashKey := "user:" + username + ":webauthn_creds_v2"
	stored := StoredCredential{
		Credential: *cred,
		Nickname:   fmt.Sprintf("Key %d", len(GetWebAuthnCredentials(username))+1),
		CreatedAt:  time.Now().Unix(),
	}
	data, _ := json.Marshal(stored)
	return UserDB.HSet(Ctx, hashKey, fmt.Sprintf("%x", cred.ID), data).Err()
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
	hashKey := "user:" + username + ":webauthn_creds_v2"
	listKey := "user:" + username + ":webauthn_creds"

	// 1. Try Hash
	data, err := UserDB.HGetAll(Ctx, hashKey).Result()
	if err == nil && len(data) > 0 {
		var creds []StoredCredential
		for _, r := range data {
			var c StoredCredential
			if err := json.Unmarshal([]byte(r), &c); err == nil {
				creds = append(creds, c)
			}
		}
		// Sort by CreatedAt to maintain consistent order
		slices.SortFunc(creds, compareStoredCredentials)
		return creds
	}

	// 2. Fallback to List & Migrate
	results, _ := UserDB.LRange(Ctx, listKey, 0, -1).Result()
	if len(results) > 0 {
		numWorkers := runtime.GOMAXPROCS(0)
		if numWorkers > len(results) {
			numWorkers = len(results)
		}
		if numWorkers < 1 {
			numWorkers = 1
		}
		credsArray := make([]StoredCredential, len(results))
		var wg sync.WaitGroup
		wg.Add(numWorkers)
		chunkSize := (len(results) + numWorkers - 1) / numWorkers

		for w := 0; w < numWorkers; w++ {
			start := w * chunkSize
			end := start + chunkSize
			if end > len(results) {
				end = len(results)
			}
			go func(start, end int) {
				defer wg.Done()
				for j := start; j < end; j++ {
					var c StoredCredential
					if err := json.Unmarshal([]byte(results[j]), &c); err == nil {
						credsArray[j] = c
					}
				}
			}(start, end)
		}
		wg.Wait()

		var creds []StoredCredential
		pipe := UserDB.Pipeline()
		for i, c := range credsArray {
			if len(c.ID) > 0 {
				creds = append(creds, c)
				pipe.HSet(Ctx, hashKey, fmt.Sprintf("%x", c.ID), results[i])
			}
		}
		pipe.Del(Ctx, listKey)
		// Best-effort migration: if it fails we still return what we read from
		// the list for this request, and a later call will retry the migration.
		_, _ = pipe.Exec(Ctx)

		slices.SortFunc(creds, compareStoredCredentials)
		return creds
	}

	return nil
}

// writeExistingCredentialScript updates a stored credential only while both
// the credential field and the owning account still exist. A plain HSET after
// a read could otherwise re-create the credential hash of an account deleted in
// between, which a recreated account with the same name would then inherit.
var writeExistingCredentialScript = redis.NewScript(`
if redis.call("HEXISTS", KEYS[2], "username") == 0 then
	return 0
end
if redis.call("HEXISTS", KEYS[1], ARGV[1]) == 0 then
	return 0
end
redis.call("HSET", KEYS[1], ARGV[1], ARGV[2])
return 1
`)

// errCredentialGone reports that a credential (or its account) was removed
// while it was being updated.
var errCredentialGone = errors.New("credential or account no longer exists")

func writeExistingCredential(username, field string, data []byte) error {
	n, err := writeExistingCredentialScript.Run(Ctx, UserDB,
		[]string{"user:" + username + ":webauthn_creds_v2", "user:" + username}, field, data).Int()
	if err != nil {
		return err
	}
	if n == 0 {
		return errCredentialGone
	}
	return nil
}

func UpdateWebAuthnSignCount(username string, credID []byte, newCount uint32) error {
	hashKey := "user:" + username + ":webauthn_creds_v2"
	field := fmt.Sprintf("%x", credID)

	val, err := UserDB.HGet(Ctx, hashKey, field).Result()
	if err != nil {
		// Try migration
		GetStoredCredentials(username)
		val, err = UserDB.HGet(Ctx, hashKey, field).Result()
		if err != nil {
			return err
		}
	}

	var c StoredCredential
	if err := json.Unmarshal([]byte(val), &c); err != nil {
		return err
	}
	c.Authenticator.SignCount = newCount
	c.LastUsed = time.Now().Unix()
	data, _ := json.Marshal(c)
	return writeExistingCredential(username, field, data)
}

// DeleteAllWebAuthnCredentials removes every passkey of a user, including the
// legacy list format (used by the admin 2FA reset).
func DeleteAllWebAuthnCredentials(username string) error {
	return UserDB.Del(Ctx, "user:"+username+":webauthn_creds_v2", "user:"+username+":webauthn_creds").Err()
}

func DeleteWebAuthnCredential(username string, credID string) error {
	hashKey := "user:" + username + ":webauthn_creds_v2"
	// Ensure migration
	GetStoredCredentials(username)
	return UserDB.HDel(Ctx, hashKey, credID).Err()
}

func UpdateWebAuthnNickname(username string, credID string, nickname string) error {
	hashKey := "user:" + username + ":webauthn_creds_v2"
	// Ensure migration
	GetStoredCredentials(username)

	val, err := UserDB.HGet(Ctx, hashKey, credID).Result()
	if err != nil {
		return err
	}

	var c StoredCredential
	if err := json.Unmarshal([]byte(val), &c); err != nil {
		return err
	}
	c.Nickname = nickname
	data, _ := json.Marshal(c)
	return writeExistingCredential(username, credID, data)
}

func UpdateWebAuthnLastUsed(username string, credID []byte) error {
	hashKey := "user:" + username + ":webauthn_creds_v2"
	field := fmt.Sprintf("%x", credID)
	// Ensure migration
	GetStoredCredentials(username)

	val, err := UserDB.HGet(Ctx, hashKey, field).Result()
	if err != nil {
		return err
	}

	var c StoredCredential
	if err := json.Unmarshal([]byte(val), &c); err != nil {
		return err
	}
	c.LastUsed = time.Now().Unix()
	data, _ := json.Marshal(c)
	return writeExistingCredential(username, field, data)
}

func UpdateWebAuthnCredential(username string, cred *webauthn.Credential) error {
	hashKey := "user:" + username + ":webauthn_creds_v2"
	field := fmt.Sprintf("%x", cred.ID)
	// Ensure migration
	GetStoredCredentials(username)

	val, err := UserDB.HGet(Ctx, hashKey, field).Result()
	if err != nil {
		return err
	}

	var c StoredCredential
	if err := json.Unmarshal([]byte(val), &c); err != nil {
		return err
	}
	c.Credential = *cred
	c.LastUsed = time.Now().Unix()
	data, _ := json.Marshal(c)
	return writeExistingCredential(username, field, data)
}
