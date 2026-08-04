package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompareStoredCredentials(t *testing.T) {
	tests := []struct {
		name string
		a    StoredCredential
		b    StoredCredential
		want int
	}{
		{
			name: "older credential first",
			a:    StoredCredential{CreatedAt: 10},
			b:    StoredCredential{CreatedAt: 20},
			want: -1,
		},
		{
			name: "timestamp comparison does not overflow",
			a:    StoredCredential{CreatedAt: math.MinInt64},
			b:    StoredCredential{CreatedAt: math.MaxInt64},
			want: -1,
		},
		{
			name: "newer credential last",
			a:    StoredCredential{CreatedAt: 20},
			b:    StoredCredential{CreatedAt: 10},
			want: 1,
		},
		{
			name: "identifier breaks timestamp tie",
			a:    StoredCredential{Credential: webauthn.Credential{ID: []byte{0x01, 0xff}}, CreatedAt: 10},
			b:    StoredCredential{Credential: webauthn.Credential{ID: []byte{0x02, 0x00}}, CreatedAt: 10},
			want: -1,
		},
		{
			name: "equal credentials",
			a:    StoredCredential{Credential: webauthn.Credential{ID: []byte("same")}, CreatedAt: 10},
			b:    StoredCredential{Credential: webauthn.Credential{ID: []byte("same")}, CreatedAt: 10},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, compareStoredCredentials(tt.a, tt.b))
		})
	}
}

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

	// Seed directly in Hash
	UserDB.HSet(Ctx, "user:testuser:webauthn_creds_v2", "6372656431", string(data))

	err = UpdateWebAuthnSignCount("testuser", []byte("cred1"), 20)
	require.NoError(t, err)

	val, err := UserDB.HGet(Ctx, "user:testuser:webauthn_creds_v2", "6372656431").Result()
	require.NoError(t, err)

	var updated StoredCredential
	err = json.Unmarshal([]byte(val), &updated)
	require.NoError(t, err)
	require.Equal(t, uint32(20), updated.Authenticator.SignCount)
}

func TestWebAuthnMigration(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	UserDB = client
	Ctx = context.Background()

	username := "migrationuser"
	listKey := "user:" + username + ":webauthn_creds"
	hashKey := "user:" + username + ":webauthn_creds_v2"

	c1 := StoredCredential{Credential: webauthn.Credential{ID: []byte("id1")}, Nickname: "Key 1", CreatedAt: 100}
	c2 := StoredCredential{Credential: webauthn.Credential{ID: []byte("id2")}, Nickname: "Key 2", CreatedAt: 200}

	d1, _ := json.Marshal(c1)
	d2, _ := json.Marshal(c2)

	// Seed List (Legacy format)
	UserDB.RPush(Ctx, listKey, string(d1), string(d2))

	// Trigger lazy migration via GetStoredCredentials
	creds := GetStoredCredentials(username)
	require.Len(t, creds, 2)
	require.Equal(t, "Key 1", creds[0].Nickname)
	require.Equal(t, "Key 2", creds[1].Nickname)

	// Verify Hash exists and List is gone
	exists, err := UserDB.Exists(Ctx, hashKey).Result()
	require.NoError(t, err)
	require.Equal(t, int64(1), exists)

	exists, err = UserDB.Exists(Ctx, listKey).Result()
	require.NoError(t, err)
	require.Equal(t, int64(0), exists)

	// Verify Hash content
	val1, err := UserDB.HGet(Ctx, hashKey, "696431").Result()
	require.NoError(t, err)
	var sc1 StoredCredential
	require.NoError(t, json.Unmarshal([]byte(val1), &sc1))
	require.Equal(t, "Key 1", sc1.Nickname)

	// Test case: missing keys
	credsEmpty := GetStoredCredentials("nonexistent")
	require.Nil(t, credsEmpty)
}

func TestStoredCredential_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
		check   func(t *testing.T, cred *StoredCredential)
	}{
		{
			name:    "Valid JSON with all fields",
			json:    `{"id":"dGVzdA==","nickname":"My Key","created_at":1234567890,"last_used":1234567899,"authenticator":{"signCount":42}}`,
			wantErr: false,
			check: func(t *testing.T, cred *StoredCredential) {
				require.NotNil(t, cred)
				assert.Equal(t, "My Key", cred.Nickname)
				assert.Equal(t, int64(1234567890), cred.CreatedAt)
				assert.Equal(t, int64(1234567899), cred.LastUsed)
				assert.Equal(t, []byte("test"), cred.ID)
				assert.Equal(t, uint32(42), cred.Authenticator.SignCount)
			},
		},
		{
			name:    "Invalid JSON syntax",
			json:    `{"id":"dGVzdA==","nickname":"My Key",`, // Truncated JSON
			wantErr: true,
		},
		{
			name:    "Invalid type for integer field",
			json:    `{"nickname":"My Key","created_at":"not_a_number"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cred StoredCredential
			err := json.Unmarshal([]byte(tt.json), &cred)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.check != nil {
					tt.check(t, &cred)
				}
			}
		})
	}
}
