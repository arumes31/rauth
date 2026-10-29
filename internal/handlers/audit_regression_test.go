package handlers

import (
	"net/http"
	"net/url"
	"rauth/internal/core"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression tests for the 2026-10-27 security audit findings.

func regressionConfig() *core.Config {
	return &core.Config{
		ServerSecret:                "32byte-secret-key-for-testing-!!",
		CookieDomains:               []string{"example.com"},
		InitialUser:                 "root",
		TokenValidityMinutes:        60,
		RateLimitLoginMax:           1000,
		RateLimitLoginDecay:         60,
		RateLimitValidateMax:        1000,
		RateLimitValidateDecay:      60,
		RateLimitLoginAccessMax:     1000,
		RateLimitLoginAccessDecay:   60,
		RateLimitLoginFailUserMax:   10,
		RateLimitLoginFailUserDecay: 300,
		RateLimitLoginFailIPMax:     1000,
		RateLimitLoginFailIPDecay:   60,
		MinPasswordLength:           8,
	}
}

func loginPost(t *testing.T, h *AuthHandler, e *echo.Echo, ip, username, password string) (echo.Context, int) {
	t.Helper()
	f := url.Values{"username": {username}, "password": {password}}
	c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)
	c.Request().Header.Set(echo.HeaderXRealIP, ip)
	require.NoError(t, h.Login(c))
	return c, rec.Code
}

func cookieFrom(rec interface{ Result() *http.Response }, name string) *http.Cookie {
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

// Finding 2: a pending_setup token obtained with the old password must die when
// an admin changes the password (and on delete/recreate).
func TestRegression_PendingSetupRevokedByAdminPasswordChange(t *testing.T) {
	setupHandlersTest(t)
	cfg := regressionConfig()
	h := &AuthHandler{Cfg: cfg}
	admin := &AdminHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	require.NoError(t, core.CreateUser("victim", "OldPassword1", "", false, ""))
	require.NoError(t, core.CreateUser("boss", "BossPassword1", "", true, ""))

	// Attacker logs in with the leaked password and receives a setup cookie.
	f := url.Values{"username": {"victim"}, "password": {"OldPassword1"}}
	c, rec := createTestContext(e, http.MethodPost, "/rauthlogin", f)
	require.NoError(t, h.Login(c))
	setupCookie := cookieFrom(rec, "rauth_setup_pending")
	require.NotNil(t, setupCookie)

	// Admin rotates the password to evict the attacker.
	af := url.Values{"username": {"victim"}, "new_password": {"NewPassword1"}}
	ac, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/change-password", af)
	ac.Set("username", "boss")
	require.NoError(t, admin.ChangeUserPassword(ac))

	// The stale cookie can no longer reach the enrollment page or complete it.
	gc, grec := createTestContext(e, http.MethodGet, "/rauthsetup2fa", nil)
	gc.Request().AddCookie(setupCookie)
	require.NoError(t, h.Setup2FA(gc))
	assert.Equal(t, http.StatusFound, grec.Code)
	assert.Equal(t, "/rauthlogin", grec.Header().Get("Location"))

	secret := userField(t, "victim", "2fa_secret")
	assert.Empty(t, secret, "no TOTP may be enrolled through the stale setup token")
}

// Finding 2 (overwrite variant): a setup token issued while the account had no
// TOTP must not replace a TOTP enrolled afterwards.
func TestRegression_CompleteSetupDoesNotOverwriteEnrolledTOTP(t *testing.T) {
	setupHandlersTest(t)
	cfg := regressionConfig()
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	require.NoError(t, core.CreateUser("alice", "Password123", "", false, ""))
	setupToken := "stale-setup"
	value := core.PendingTokenValue("alice", mustGen(t, "alice"))
	core.TokenDB.Set(core.Ctx, "pending_setup:"+setupToken, value, 10*time.Minute)
	attackerSecret := "JBSWY3DPEHPK3PXP"
	core.TokenDB.Set(core.Ctx, "pending_setup_secret:"+setupToken, attackerSecret, 5*time.Minute)

	// Victim enrolls their own TOTP in the meantime.
	victimEnc, _ := core.Encrypt2FASecret("KRSXG5CTMVRXEZLU", cfg.ServerSecret)
	seedUserFields(t, "alice", map[string]interface{}{"2fa_secret": victimEnc})

	code, _ := totp.GenerateCode(attackerSecret, time.Now())
	encrypted, _ := core.EncryptToken(setupToken, cfg.ServerSecret)
	c, rec := createTestContext(e, http.MethodPost, "/rauthsetup2fa", url.Values{"totp_code": {code}})
	c.Request().AddCookie(&http.Cookie{Name: "rauth_setup_pending", Value: encrypted})
	require.NoError(t, h.CompleteSetup2FA(c))

	assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	stored := userField(t, "alice", "2fa_secret")
	assert.Equal(t, victimEnc, stored)
	assert.Nil(t, cookieFrom(rec, "X-rauth-authtoken"))
}

// Finding 6: failures from one network must not lock the account for others.
func TestRegression_LockoutScopedToSource(t *testing.T) {
	setupHandlersTest(t)
	cfg := regressionConfig()
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}
	require.NoError(t, core.CreateUser("root", "RootPassword1", "", true, ""))

	for i := 0; i < cfg.RateLimitLoginFailUserMax+2; i++ {
		loginPost(t, h, e, "203.0.113.10", "root", "wrong-password")
	}
	_, code := loginPost(t, h, e, "203.0.113.10", "root", "RootPassword1")
	assert.Equal(t, http.StatusTooManyRequests, code, "the attacking source stays locked")

	_, code = loginPost(t, h, e, "198.51.100.20", "root", "RootPassword1")
	assert.NotEqual(t, http.StatusTooManyRequests, code, "the legitimate user on another network is not locked out")
}

// Findings 9/10: a session of a deleted account, or one issued before a
// credential change, is rejected even if it is still stored (e.g. minted
// concurrently with the revocation or missing from the index).
func TestRegression_ValidateRejectsRevokedGeneration(t *testing.T) {
	setupHandlersTest(t)
	cfg := regressionConfig()
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	require.NoError(t, core.CreateUser("bob", "Password123", "", false, ""))
	gen, _ := core.AuthGeneration("bob")

	token := "session-bob"
	require.NoError(t, core.StoreSession(token, "bob", "127.0.0.1", map[string]interface{}{
		"status": "valid", "username": "bob", "ip": "127.0.0.1", "country": "Internal", "auth_gen": gen,
	}, time.Hour))
	enc, _ := core.EncryptToken(token, cfg.ServerSecret)

	validate := func() int {
		c, rec := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
		c.Request().AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: enc})
		require.NoError(t, h.Validate(c))
		return rec.Code
	}
	assert.Equal(t, http.StatusOK, validate())

	// Simulate a revocation that missed this token in the index.
	core.TokenDB.SRem(core.Ctx, "user_sessions:bob", token)
	_, err := core.BumpAuthGeneration("bob")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, validate())

	// Deleted account: a re-stored session for it is rejected too.
	require.NoError(t, core.StoreSession(token, "bob", "127.0.0.1", map[string]interface{}{
		"status": "valid", "username": "bob", "ip": "127.0.0.1", "country": "Internal",
	}, time.Hour))
	require.NoError(t, core.DeleteUser("bob"))
	assert.Equal(t, http.StatusUnauthorized, validate())
}

// Finding 15: replaying a rotated-away cookie must not fork new sessions or
// renew its own grace period.
func TestRegression_RotationReplayDoesNotFork(t *testing.T) {
	setupHandlersTest(t)
	cfg := regressionConfig()
	cfg.TokenRotationMinutes = 5
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	seedAccount(t, "carol")

	old := "old-token"
	core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+old, map[string]interface{}{
		"status": "valid", "username": "carol", "ip": "127.0.0.1", "country": "Internal",
		"created_at": time.Now().Add(-10 * time.Minute).Unix(),
	})
	core.TokenDB.SAdd(core.Ctx, "user_sessions:carol", old)
	enc, _ := core.EncryptToken(old, cfg.ServerSecret)

	validate := func() {
		c, rec := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
		c.Request().AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: enc})
		require.NoError(t, h.Validate(c))
		require.Equal(t, http.StatusOK, rec.Code)
	}

	validate() // rotates
	members, _ := core.TokenDB.SMembers(core.Ctx, "user_sessions:carol").Result()
	require.Len(t, members, 2)
	sharedMiniredis.FastForward(20 * time.Second)

	validate() // replay within grace
	members, _ = core.TokenDB.SMembers(core.Ctx, "user_sessions:carol").Result()
	assert.Len(t, members, 2, "a replay must not mint another session")
	ttl := core.TokenDB.TTL(core.Ctx, "X-rauth-authtoken="+old).Val()
	assert.LessOrEqual(t, ttl, 10*time.Second, "a replay must not renew the old token's grace")
}

// Finding 5: an admin 2FA reset removes passkeys too.
func TestRegression_ResetUser2FAClearsPasskeys(t *testing.T) {
	setupHandlersTest(t)
	cfg := regressionConfig()
	admin := &AdminHandler{Cfg: cfg}
	e := echo.New()
	require.NoError(t, core.CreateUser("dave", "Password123", "", false, ""))
	require.NoError(t, core.CreateUser("boss", "BossPassword1", "", true, ""))
	require.NoError(t, core.SaveWebAuthnCredential("dave", &webauthn.Credential{ID: []byte("planted")}, mustGen(t, "dave")))
	require.NotEmpty(t, core.GetWebAuthnCredentials("dave"))

	c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/reset-2fa", url.Values{"username": {"dave"}})
	c.Set("username", "boss")
	require.NoError(t, admin.ResetUser2FA(c))
	assert.Empty(t, core.GetWebAuthnCredentials("dave"))
}

// Hardening: other admins cannot take over the root administrator.
func TestRegression_RootAdminGuard(t *testing.T) {
	setupHandlersTest(t)
	cfg := regressionConfig()
	admin := &AdminHandler{Cfg: cfg}
	e := echo.New()
	require.NoError(t, core.CreateUser("root", "RootPassword1", "", true, ""))
	require.NoError(t, core.CreateUser("other", "OtherPassword1", "", true, ""))

	c, _ := createTestContext(e, http.MethodPost, "/rauthmgmt/user/change-password",
		url.Values{"username": {"root"}, "new_password": {"Hijacked123"}})
	c.Set("username", "other")
	err := admin.ChangeUserPassword(c)
	var he *echo.HTTPError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, http.StatusForbidden, he.Code)
}

// Handing out administrator credentials needs the acting admin's step-up, so
// a hijacked admin session cannot mint an admin it controls and then pass the
// Public Access unlock with that admin's credentials.
func TestRegression_AdminCredentialsNeedStepUp(t *testing.T) {
	setupHandlersTest(t)
	cfg := regressionConfig()
	cfg.MinPasswordLength = 8
	admin := &AdminHandler{Cfg: cfg}
	e := echo.New()
	require.NoError(t, core.CreateUser("boss", "BossPassword1", "", true, ""))
	require.NoError(t, core.CreateUser("peer", "PeerPassword1", "", true, ""))
	require.NoError(t, core.CreateUser("member", "MemberPassword1", "", false, ""))

	run := func(fn func(echo.Context) error, path string, f url.Values) int {
		c, rec := createTestContext(e, http.MethodPost, path, f)
		c.Set("username", "boss")
		if err := fn(c); err != nil {
			var he *echo.HTTPError
			require.ErrorAs(t, err, &he)
			return he.Code
		}
		return rec.Code
	}
	newAdmin := url.Values{"new_username": {"mallory"}, "new_password": {"MalloryPass1"}, "is_admin": {"on"}}

	assert.Equal(t, http.StatusBadRequest, run(admin.CreateUser, "/rauthmgmt/user/create", newAdmin))
	exists, _ := core.UserExists("mallory")
	assert.False(t, exists, "no administrator without the acting admin's step-up")
	assert.Equal(t, http.StatusBadRequest, run(admin.ChangeUserPassword, "/rauthmgmt/user/change-password",
		url.Values{"username": {"peer"}, "new_password": {"Hijacked123"}}))
	assert.Equal(t, http.StatusBadRequest, run(admin.ResetUser2FA, "/rauthmgmt/user/reset-2fa", url.Values{"username": {"peer"}}))

	// Non-admin targets need no step-up; admin targets pass with it.
	assert.Equal(t, http.StatusFound, run(admin.ChangeUserPassword, "/rauthmgmt/user/change-password",
		url.Values{"username": {"member"}, "new_password": {"NewMember123"}}))
	newAdmin.Set("current_password", "BossPassword1")
	assert.Equal(t, http.StatusFound, run(admin.CreateUser, "/rauthmgmt/user/create", newAdmin))
	assert.Equal(t, http.StatusFound, run(admin.ResetUser2FA, "/rauthmgmt/user/reset-2fa",
		url.Values{"username": {"peer"}, "current_password": {"BossPassword1"}}))
}
