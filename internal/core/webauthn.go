package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
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
				originMap["https://"+trimmed] = true
				originMap["http://"+trimmed] = true
			} else {
				originMap[trimmed] = true
			}
		}
	} else {
		// Generate defaults from CookieDomains and AllowedHosts
		for _, domain := range cfg.CookieDomains {
			originMap[fmt.Sprintf("https://%s", domain)] = true
			originMap[fmt.Sprintf("http://%s", domain)] = true
			originMap[fmt.Sprintf("https://%s:5980", domain)] = true
			originMap[fmt.Sprintf("http://%s:5980", domain)] = true
		}
		for _, host := range cfg.AllowedHosts {
			originMap[fmt.Sprintf("https://%s", host)] = true
			originMap[fmt.Sprintf("http://%s", host)] = true
			originMap[fmt.Sprintf("https://%s:5980", host)] = true
			originMap[fmt.Sprintf("http://%s:5980", host)] = true
		}
		// Always include standard local dev
		originMap["http://localhost:5980"] = true
		originMap["http://127.0.0.1:5980"] = true
		originMap["http://localhost"] = true
		originMap["http://127.0.0.1"] = true
	}

	origins := make([]string, 0, len(originMap))
	for o := range originMap {
		origins = append(origins, o)
	}

	fmt.Printf("WebAuthn Registered Origins: %v\n", origins)

	WebAuthnInstance, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "RAuth",
		RPID:          cfg.CookieDomains[0],
		RPOrigins:     origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
	})
	return err
}

func SaveWebAuthnCredential(username string, cred *webauthn.Credential) error {
	key := "user:" + username + ":webauthn_creds"
	count, _ := UserDB.LLen(Ctx, key).Result()
	stored := StoredCredential{
		Credential: *cred,
		Nickname:   fmt.Sprintf("Key %d", count+1),
		CreatedAt:  time.Now().Unix(),
	}
	data, _ := json.Marshal(stored)
	return UserDB.RPush(Ctx, key, data).Err()
}

func GetWebAuthnCredentials(username string) []webauthn.Credential {
	var creds []webauthn.Credential
	stored := GetStoredCredentials(username)
	for _, s := range stored {
		creds = append(creds, s.Credential)
	}
	return creds
}

func GetStoredCredentials(username string) []StoredCredential {
	var creds []StoredCredential
	results, _ := UserDB.LRange(Ctx, "user:"+username+":webauthn_creds", 0, -1).Result()
	for _, r := range results {
		var c StoredCredential
		if err := json.Unmarshal([]byte(r), &c); err == nil {
			creds = append(creds, c)
		}
	}
	return creds
}

func UpdateWebAuthnSignCount(username string, credID []byte, newCount uint32) error {
	stored := GetStoredCredentials(username)
	key := "user:" + username + ":webauthn_creds"
	var toPush []interface{}
	for i := range stored {
		if bytes.Equal(stored[i].ID, credID) {
			stored[i].Authenticator.SignCount = newCount
			stored[i].LastUsed = time.Now().Unix()
		}
		data, err := json.Marshal(stored[i])
		if err != nil {
			return err
		}
		toPush = append(toPush, data)
	}

	_, err := UserDB.TxPipelined(Ctx, func(pipe redis.Pipeliner) error {
		pipe.Del(Ctx, key)
		if len(toPush) > 0 {
			pipe.RPush(Ctx, key, toPush...)
		}
		return nil
	})
	return err
}

func DeleteWebAuthnCredential(username string, credID string) error {
	stored := GetStoredCredentials(username)
	key := "user:" + username + ":webauthn_creds"

	stored = slices.DeleteFunc(stored, func(c StoredCredential) bool {
		return hex.EncodeToString(c.ID) == credID
	})

	var toPush []interface{}
	for _, c := range stored {
		data, err := json.Marshal(c)
		if err != nil {
			return err
		}
		toPush = append(toPush, data)
	}

	_, err := UserDB.TxPipelined(Ctx, func(pipe redis.Pipeliner) error {
		pipe.Del(Ctx, key)
		if len(toPush) > 0 {
			pipe.RPush(Ctx, key, toPush...)
		}
		return nil
	})
	return err
}

func UpdateWebAuthnNickname(username string, credID string, nickname string) error {
	stored := GetStoredCredentials(username)
	key := "user:" + username + ":webauthn_creds"
	var toPush []interface{}
	for i := range stored {
		if hex.EncodeToString(stored[i].ID) == credID {
			stored[i].Nickname = nickname
		}
		data, err := json.Marshal(stored[i])
		if err != nil {
			return err
		}
		toPush = append(toPush, data)
	}

	_, err := UserDB.TxPipelined(Ctx, func(pipe redis.Pipeliner) error {
		pipe.Del(Ctx, key)
		if len(toPush) > 0 {
			pipe.RPush(Ctx, key, toPush...)
		}
		return nil
	})
	return err
}

func UpdateWebAuthnLastUsed(username string, credID []byte) error {
	stored := GetStoredCredentials(username)
	key := "user:" + username + ":webauthn_creds"
	var toPush []interface{}
	for i := range stored {
		if bytes.Equal(stored[i].ID, credID) {
			stored[i].LastUsed = time.Now().Unix()
		}
		data, err := json.Marshal(stored[i])
		if err != nil {
			return err
		}
		toPush = append(toPush, data)
	}

	_, err := UserDB.TxPipelined(Ctx, func(pipe redis.Pipeliner) error {
		pipe.Del(Ctx, key)
		if len(toPush) > 0 {
			pipe.RPush(Ctx, key, toPush...)
		}
		return nil
	})
	return err
}

func UpdateWebAuthnCredential(username string, cred *webauthn.Credential) error {
	stored := GetStoredCredentials(username)
	key := "user:" + username + ":webauthn_creds"
	var toPush []interface{}
	for i := range stored {
		if bytes.Equal(stored[i].ID, cred.ID) {
			stored[i].Credential = *cred
			stored[i].LastUsed = time.Now().Unix()
		}
		data, err := json.Marshal(stored[i])
		if err != nil {
			return err
		}
		toPush = append(toPush, data)
	}

	_, err := UserDB.TxPipelined(Ctx, func(pipe redis.Pipeliner) error {
		pipe.Del(Ctx, key)
		if len(toPush) > 0 {
			pipe.RPush(Ctx, key, toPush...)
		}
		return nil
	})
	return err
}
