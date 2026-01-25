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
	
	// Collect origins
	originMap := make(map[string]bool)
	
	if len(cfg.WebAuthnOrigins) > 0 {
		for _, o := range cfg.WebAuthnOrigins {
			originMap[o] = true
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
