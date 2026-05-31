package core

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetEnvIntBool_Coverage(t *testing.T) {
	t.Run("getEnvInt valid", func(t *testing.T) {
		t.Setenv("RAUTH_TEST_INT", "42")
		assert.Equal(t, 42, getEnvInt("RAUTH_TEST_INT", 7))
	})
	t.Run("getEnvInt invalid falls back", func(t *testing.T) {
		t.Setenv("RAUTH_TEST_INT", "notanint")
		assert.Equal(t, 7, getEnvInt("RAUTH_TEST_INT", 7))
	})
	t.Run("getEnvInt unset falls back", func(t *testing.T) {
		assert.Equal(t, 7, getEnvInt("RAUTH_TEST_INT_UNSET", 7))
	})
	t.Run("getEnvBool valid", func(t *testing.T) {
		t.Setenv("RAUTH_TEST_BOOL", "true")
		assert.True(t, getEnvBool("RAUTH_TEST_BOOL", false))
	})
	t.Run("getEnvBool invalid falls back", func(t *testing.T) {
		t.Setenv("RAUTH_TEST_BOOL", "notabool")
		assert.True(t, getEnvBool("RAUTH_TEST_BOOL", true))
	})
	t.Run("getEnvBool unset falls back", func(t *testing.T) {
		assert.False(t, getEnvBool("RAUTH_TEST_BOOL_UNSET", false))
	})
}

func TestIsAllowedHost_Coverage(t *testing.T) {
	cfg := &Config{
		AllowedHosts:    []string{"explicit.example.com"},
		WebAuthnOrigins: []string{"https://wa.example.com"},
		CookieDomains:   []string{"example.com"},
	}

	assert.False(t, cfg.IsAllowedHost(""), "empty host rejected")
	assert.True(t, cfg.IsAllowedHost("explicit.example.com"), "explicit allowed host")
	assert.True(t, cfg.IsAllowedHost("wa.example.com"), "webauthn origin host")
	assert.True(t, cfg.IsAllowedHost("example.com"), "cookie domain exact match")
	assert.True(t, cfg.IsAllowedHost("app.example.com"), "cookie domain subdomain match")
	assert.False(t, cfg.IsAllowedHost("evil-example.com"), "suffix abuse rejected")
	assert.False(t, cfg.IsAllowedHost("unrelated.org"), "unrelated host rejected")
}

func TestIsCommonPassword_Coverage(t *testing.T) {
	original := commonPasswordsOn
	defer func() { commonPasswordsOn = original }()

	commonPasswordsOn = false
	assert.False(t, isCommonPassword("password"), "disabled check always returns false")

	commonPasswordsOn = true
	InitCommonPasswords(true)
	assert.True(t, isCommonPassword("password"), "well-known password is blocked")
	assert.False(t, isCommonPassword("a-very-unlikely-passphrase-xyz-9182"), "uncommon password is allowed")
}

func TestRecoveryCodeHelpers_Coverage(t *testing.T) {
	s := miniredis.RunT(t)
	UserDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	TokenDB = UserDB

	assert.False(t, ConsumeRecoveryCode("u", ""), "empty code is not consumed")
	assert.Equal(t, int64(0), CountRecoveryCodes("u"), "no codes initially")

	codes, err := GenerateRecoveryCodes("u")
	require.NoError(t, err)
	require.Len(t, codes, 10)
	assert.Equal(t, int64(10), CountRecoveryCodes("u"))

	assert.True(t, ConsumeRecoveryCode("u", codes[0]), "valid code consumed")
	assert.False(t, ConsumeRecoveryCode("u", codes[0]), "already-consumed code not reusable")
	assert.Equal(t, int64(9), CountRecoveryCodes("u"))

	// TOTPCodeReused: empty code short-circuits to false.
	assert.False(t, TOTPCodeReused("u", ""))
	assert.False(t, TOTPCodeReused("u", "123456"), "first use is not a reuse")
	assert.True(t, TOTPCodeReused("u", "123456"), "second use within window is a reuse")
}

func TestWebAuthnUser_NilReceiver(t *testing.T) {
	var u *WebAuthnUser
	assert.Nil(t, u.WebAuthnID())
	assert.Equal(t, "", u.WebAuthnName())
	assert.Equal(t, "", u.WebAuthnDisplayName())
	assert.Equal(t, "", u.WebAuthnIcon())
	assert.Nil(t, u.WebAuthnCredentials())

	// Non-nil receiver exercises the populated branches.
	populated := &WebAuthnUser{ID: []byte("id"), DisplayName: "alice"}
	assert.Equal(t, []byte("id"), populated.WebAuthnID())
	assert.Equal(t, "alice", populated.WebAuthnDisplayName())
}
