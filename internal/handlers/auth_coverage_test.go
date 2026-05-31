package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"rauth/internal/core"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const authTestSecret = "32byte-secret-key-for-testing-!!"

func authCoverageCfg() *core.Config {
	return &core.Config{
		ServerSecret:              authTestSecret,
		CookieDomains:             []string{"example.com"},
		TokenValidityMinutes:      60,
		RateLimitLoginMax:         1000,
		RateLimitLoginDecay:       60,
		RateLimitLoginAccessMax:   1000,
		RateLimitLoginFailUserMax: 1000,
		RateLimitLoginFailIPMax:   1000,
	}
}

func TestAuthHandler_Root_Coverage(t *testing.T) {
	setupHandlersTest(t)
	h := &AuthHandler{Cfg: authCoverageCfg()}
	e := echo.New()

	t.Run("Undecryptable cookie redirects to login", func(t *testing.T) {
		c, rec := createTestContext(e, http.MethodGet, "/", nil)
		c.Request().AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: "not-valid-base64!!"})
		err := h.Root(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Valid session redirects to profile", func(t *testing.T) {
		token := "root-valid-token"
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{
			"status":   "valid",
			"username": "rootuser",
		})
		enc, err := core.EncryptToken(token, authTestSecret)
		require.NoError(t, err)

		c, rec := createTestContext(e, http.MethodGet, "/", nil)
		c.Request().AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: enc})
		err = h.Root(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthprofile", rec.Header().Get("Location"))
	})

	t.Run("Valid cookie but missing/invalid session redirects to login", func(t *testing.T) {
		enc, _ := core.EncryptToken("no-such-token", authTestSecret)
		c, rec := createTestContext(e, http.MethodGet, "/", nil)
		c.Request().AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: enc})
		err := h.Root(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})
}

// verify2FARequest builds a POST /rauthlogin context carrying an encrypted
// pending-2fa cookie for the given pending token.
func verify2FARequest(e *echo.Echo, pendingToken, code string) (echo.Context, *httptest.ResponseRecorder) {
	f := url.Values{}
	f.Set("totp_code", code)
	req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	enc, _ := core.EncryptToken(pendingToken, authTestSecret)
	req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: enc})
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func TestAuthHandler_Verify2FA_Coverage(t *testing.T) {
	setupHandlersTest(t)
	cfg := authCoverageCfg()
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	key, _ := totp.Generate(totp.GenerateOpts{Issuer: "RAuth", AccountName: "v2fa@example.com"})
	secret := key.Secret()
	enc2fa := core.Encrypt2FASecret(secret, cfg.ServerSecret)
	core.UserDB.HSet(core.Ctx, "user:v2fa", map[string]interface{}{
		"username":   "v2fa",
		"2fa_secret": enc2fa,
		"email":      "v2fa@example.com",
	})

	t.Run("No pending cookie redirects to login", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		err := h.Verify2FA(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
	})

	t.Run("Undecryptable pending cookie redirects to login", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", nil)
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: "bad!!"})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		err := h.Verify2FA(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
	})

	t.Run("Pending token without session redirects to login", func(t *testing.T) {
		c, rec := verify2FARequest(e, "ghost-pending", "000000")
		err := h.Verify2FA(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Invalid code re-renders login", func(t *testing.T) {
		pending := "pending-invalid"
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pending, "v2fa", 5*time.Minute)
		c, rec := verify2FARequest(e, pending, "000000")
		err := h.Verify2FA(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Valid code issues token", func(t *testing.T) {
		pending := "pending-valid"
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pending, "v2fa", 5*time.Minute)
		code, _ := totp.GenerateCode(secret, time.Now())
		c, rec := verify2FARequest(e, pending, code)
		err := h.Verify2FA(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		// Pending session consumed.
		exists, _ := core.TokenDB.Exists(core.Ctx, "pending_2fa:"+pending).Result()
		assert.Equal(t, int64(0), exists)
	})

	t.Run("Replayed code is blocked", func(t *testing.T) {
		pending := "pending-replay"
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pending, "v2fa", 5*time.Minute)
		code, _ := totp.GenerateCode(secret, time.Now())
		// Mark the code as already used so the replay branch triggers.
		core.TOTPCodeReused("v2fa", code)
		c, rec := verify2FARequest(e, pending, code)
		err := h.Verify2FA(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("Recovery code authenticates", func(t *testing.T) {
		pending := "pending-recovery"
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pending, "v2fa", 5*time.Minute)
		codes, err := core.GenerateRecoveryCodes("v2fa")
		require.NoError(t, err)
		require.NotEmpty(t, codes)
		c, rec := verify2FARequest(e, pending, codes[0])
		err = h.Verify2FA(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
	})
}
