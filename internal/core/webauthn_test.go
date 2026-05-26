package core

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
)

func TestInitWebAuthn(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *Config
		expectedOrigins []string
	}{
		{
			name: "Default origins from CookieDomains",
			cfg: &Config{
				CookieDomains: []string{"example.com"},
				AllowedHosts:  []string{"auth.example.com"},
			},
			expectedOrigins: []string{
				"https://example.com",
				"http://example.com",
				"https://example.com:5980",
				"http://example.com:5980",
				"https://auth.example.com",
				"http://auth.example.com",
				"https://auth.example.com:5980",
				"http://auth.example.com:5980",
				"http://localhost:5980",
				"http://127.0.0.1:5980",
				"http://localhost",
				"http://127.0.0.1",
			},
		},
		{
			name: "Normalization of origins",
			cfg: &Config{
				CookieDomains:   []string{"example.com"},
				WebAuthnOrigins: []string{"https://domain.com/", "domain2.com", "  domain3.com  "},
			},
			expectedOrigins: []string{
				"https://domain.com",
				"https://domain2.com",
				"http://domain2.com",
				"https://domain3.com",
				"http://domain3.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := InitWebAuthn(tt.cfg)
			assert.NoError(t, err)
			assert.NotNil(t, WebAuthnInstance)
		})
	}
}

func TestWebAuthnOperations(t *testing.T) {
	s := miniredis.RunT(t)
	cfg := &Config{
		RedisHost: "127.0.0.1",
		RedisPort: s.Port(),
	}
	err := InitRedis(cfg)
	assert.NoError(t, err)

	username := "testuser"
	cred1 := &webauthn.Credential{ID: []byte("cred1")}
	cred2 := &webauthn.Credential{ID: []byte("cred2")}

	t.Run("SaveWebAuthnCredential", func(t *testing.T) {
		err := SaveWebAuthnCredential(username, cred1)
		assert.NoError(t, err)
		err = SaveWebAuthnCredential(username, cred2)
		assert.NoError(t, err)

		creds := GetWebAuthnCredentials(username)
		assert.Len(t, creds, 2)
	})

	t.Run("UpdateWebAuthnNickname", func(t *testing.T) {
		credID := hex.EncodeToString(cred1.ID)
		newNickname := "My Phone"
		err := UpdateWebAuthnNickname(username, credID, newNickname)
		assert.NoError(t, err)

		stored := GetStoredCredentials(username)
		found := false
		for _, c := range stored {
			if fmt.Sprintf("%x", c.ID) == credID {
				assert.Equal(t, newNickname, c.Nickname)
				found = true
			}
		}
		assert.True(t, found)
	})

	t.Run("DeleteWebAuthnCredential", func(t *testing.T) {
		credID := hex.EncodeToString(cred1.ID)
		err := DeleteWebAuthnCredential(username, credID)
		assert.NoError(t, err)

		creds := GetWebAuthnCredentials(username)
		assert.Len(t, creds, 1)
		assert.Equal(t, cred2.ID, creds[0].ID)
	})
}
