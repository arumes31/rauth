package core

import (
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnUser implements the webauthn.User interface
type WebAuthnUser struct {
	ID          []byte
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.ID
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.DisplayName
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

var WebAuthnInstance *webauthn.WebAuthn

func InitWebAuthn(cfg *Config) error {
	var err error
	origins := []string{fmt.Sprintf("https://%s", cfg.CookieDomains[0])}
	// Add common local dev origins
	origins = append(origins, "http://localhost:5980", "http://127.0.0.1:5980", "http://localhost", "http://127.0.0.1")
	
	WebAuthnInstance, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "RAuth",
		RPID:          cfg.CookieDomains[0],
		RPOrigins:     origins,
	})
	return err
}

func SaveWebAuthnCredential(username string, cred *webauthn.Credential) error {
	data, _ := json.Marshal(cred)
	return UserDB.RPush(Ctx, "user:"+username+":webauthn_creds", data).Err()
}

func GetWebAuthnCredentials(username string) []webauthn.Credential {
	var creds []webauthn.Credential
	results, _ := UserDB.LRange(Ctx, "user:"+username+":webauthn_creds", 0, -1).Result()
	for _, r := range results {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(r), &c); err == nil {
			creds = append(creds, c)
		}
	}
	return creds
}
