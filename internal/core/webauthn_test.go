package core

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitWebAuthn(t *testing.T) {
	tests := []struct {
		name            string
		cfg             *Config
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

func TestWebAuthnCredentialManagement(t *testing.T) {
	s := miniredis.RunT(t)
	UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	username := "testuser"
	c1 := &webauthn.Credential{ID: []byte("id1"), Authenticator: webauthn.Authenticator{SignCount: 1}}
	c2 := &webauthn.Credential{ID: []byte("id2"), Authenticator: webauthn.Authenticator{SignCount: 2}}

	assert.NoError(t, SaveWebAuthnCredential(username, c1))
	assert.NoError(t, SaveWebAuthnCredential(username, c2))

	creds := GetWebAuthnCredentials(username)
	assert.Equal(t, 2, len(creds))

	// Test Nickname Update
	id1Hex := fmt.Sprintf("%x", c1.ID)
	err := UpdateWebAuthnNickname(username, id1Hex, "New Nickname")
	assert.NoError(t, err)
	stored := GetStoredCredentials(username)
	found := false
	for _, sc := range stored {
		if fmt.Sprintf("%x", sc.ID) == id1Hex {
			assert.Equal(t, "New Nickname", sc.Nickname)
			found = true
		}
	}
	assert.True(t, found)

	// Test Last Used Update
	assert.NoError(t, UpdateWebAuthnLastUsed(username, c2.ID))
	stored = GetStoredCredentials(username)
	for _, sc := range stored {
		if fmt.Sprintf("%x", sc.ID) == fmt.Sprintf("%x", c2.ID) {
			assert.NotZero(t, sc.LastUsed)
		}
	}

	// Test Credential Update
	c2Updated := *c2
	c2Updated.Authenticator.SignCount = 100
	assert.NoError(t, UpdateWebAuthnCredential(username, &c2Updated))
	creds = GetWebAuthnCredentials(username)
	found = false
	for _, c := range creds {
		if string(c.ID) == string(c2.ID) {
			assert.Equal(t, uint32(100), c.Authenticator.SignCount)
			found = true
		}
	}
	assert.True(t, found)

	// Test Deletion
	err = DeleteWebAuthnCredential(username, id1Hex)
	assert.NoError(t, err)
	creds = GetWebAuthnCredentials(username)
	assert.Equal(t, 1, len(creds))
	assert.Equal(t, string(c2.ID), string(creds[0].ID))
}

func TestWebAuthnUserInterface(t *testing.T) {
	u := &WebAuthnUser{
		ID:          []byte("123"),
		DisplayName: "Test User",
		Credentials: []webauthn.Credential{},
	}

	require.Equal(t, []byte("123"), u.WebAuthnID())
	require.Equal(t, "Test User", u.WebAuthnName())
	require.Equal(t, "Test User", u.WebAuthnDisplayName())
	require.Equal(t, "", u.WebAuthnIcon())
	require.Equal(t, []webauthn.Credential{}, u.WebAuthnCredentials())

	// Nil receiver tests
	var nilUser *WebAuthnUser
	require.Nil(t, nilUser.WebAuthnID())
	require.Equal(t, "", nilUser.WebAuthnName())
}

func TestNewWebAuthnUser(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	UserDB = client
	Ctx = context.Background()

	user := User{
		UID:      "123",
		Username: "testuser",
	}

	wu := NewWebAuthnUser(user)
	require.NotNil(t, wu)
	require.Equal(t, []byte("123"), wu.ID)
	require.Equal(t, "testuser", wu.DisplayName)
}

func TestUpdateWebAuthnSignCount(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	UserDB = client
	Ctx = context.Background()

	cred := webauthn.Credential{
		ID: []byte("cred1"),
		Authenticator: webauthn.Authenticator{
			SignCount: 10,
		},
	}
	stored := StoredCredential{
		Credential: cred,
	}

	data, err := json.Marshal(stored)
	require.NoError(t, err)

	UserDB.RPush(Ctx, "user:testuser:webauthn_creds", string(data))

	UpdateWebAuthnSignCount("testuser", []byte("cred1"), 20)

	results, err := UserDB.LRange(Ctx, "user:testuser:webauthn_creds", 0, -1).Result()
	require.NoError(t, err)
	require.Len(t, results, 1)

	var updated StoredCredential
	err = json.Unmarshal([]byte(results[0]), &updated)
	require.NoError(t, err)
	require.Equal(t, uint32(20), updated.Authenticator.SignCount)
}
