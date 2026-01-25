package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

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
	if u == nil { return nil }
	return u.ID
}

func (u *WebAuthnUser) WebAuthnName() string {
	if u == nil { return "" }
	return u.DisplayName
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u == nil { return u.WebAuthnName() }
	return u.DisplayName
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	if u == nil { return nil }
	return u.Credentials
}

type StoredCredential struct {
	webauthn.Credential
	Nickname  string `json:"nickname"`
	CreatedAt int64  `json:"created_at"`
	LastUsed  int64  `json:"last_used"`
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
	stored := StoredCredential{
		Credential: *cred,
		Nickname:   fmt.Sprintf("Key %d", len(GetWebAuthnCredentials(username))+1),
		CreatedAt:  time.Now().Unix(),
	}
	data, _ := json.Marshal(stored)
	return UserDB.RPush(Ctx, "user:"+username+":webauthn_creds", data).Err()
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

func DeleteWebAuthnCredential(username string, credID string) error {
	stored := GetStoredCredentials(username)
	UserDB.Del(Ctx, "user:"+username+":webauthn_creds")
	for _, c := range stored {
		// We use hex encoding or base64 for ID in the request
		if fmt.Sprintf("%x", c.ID) != credID {
			data, _ := json.Marshal(c)
			UserDB.RPush(Ctx, "user:"+username+":webauthn_creds", data)
		}
	}
	return nil
}

func UpdateWebAuthnNickname(username string, credID string, nickname string) error {
	stored := GetStoredCredentials(username)
	UserDB.Del(Ctx, "user:"+username+":webauthn_creds")
	for _, c := range stored {
		if fmt.Sprintf("%x", c.ID) == credID {
			c.Nickname = nickname
		}
		data, _ := json.Marshal(c)
		UserDB.RPush(Ctx, "user:"+username+":webauthn_creds", data)
	}
	return nil
}

func UpdateWebAuthnLastUsed(username string, credID []byte) {
	stored := GetStoredCredentials(username)
	UserDB.Del(Ctx, "user:"+username+":webauthn_creds")
	for _, c := range stored {
		if fmt.Sprintf("%x", c.ID) == fmt.Sprintf("%x", credID) {
			c.LastUsed = time.Now().Unix()
		}
		data, _ := json.Marshal(c)
		UserDB.RPush(Ctx, "user:"+username+":webauthn_creds", data)
	}
}

func UpdateWebAuthnCredential(username string, cred *webauthn.Credential) {
	stored := GetStoredCredentials(username)
	UserDB.Del(Ctx, "user:"+username+":webauthn_creds")
	for _, c := range stored {
		if fmt.Sprintf("%x", c.ID) == fmt.Sprintf("%x", cred.ID) {
			c.Credential = *cred
			c.LastUsed = time.Now().Unix()
		}
		data, _ := json.Marshal(c)
		UserDB.RPush(Ctx, "user:"+username+":webauthn_creds", data)
	}
}
