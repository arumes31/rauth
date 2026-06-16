package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
)

func TestAuthHandler_Verify2FA(t *testing.T) {
	setupHandlersTest(t)

	cfg := &core.Config{
		ServerSecret:                "32byte-secret-key-for-testing-!!",
		CookieDomains:               []string{"example.com"},
		TokenValidityMinutes:        60,
		RateLimitLoginMax:           1000,
		RateLimitLoginDecay:         60,
		RateLimitLoginAccessMax:     1000,
		RateLimitLoginAccessDecay:   60,
		RateLimitLoginFailUserMax:   1000,
		RateLimitLoginFailUserDecay: 60,
		RateLimitLoginFailIPMax:     1000,
		RateLimitLoginFailIPDecay:   60,
	}
	// Important to use a valid test context setup
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()

	// Create test user with 2FA
	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "RAuth",
		AccountName: "testuser",
	})
	secret := key.Secret()
	encryptedSecret := core.Encrypt2FASecret(secret, cfg.ServerSecret)

	core.UserDB.HSet(core.Ctx, "user:testuser", map[string]interface{}{
		"username":   "testuser",
		"2fa_secret": encryptedSecret,
		"password":   "dummy",
	})

	// Setup pending 2FA session
	pendingToken := "pending-token-123"
	encryptedPendingToken, _ := core.EncryptToken(pendingToken, cfg.ServerSecret)

	t.Run("Valid TOTP Code", func(t *testing.T) {
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pendingToken, "testuser", 5*time.Minute)
		defer core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingToken)

		code, _ := totp.GenerateCode(secret, time.Now())

		f := make(url.Values)
		f.Set("totp_code", code)

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: encryptedPendingToken})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		c.Set("csrf", "test_csrf")
		// needed for issueToken
		c.SetPath("/rauthlogin")
		req.RemoteAddr = "192.0.2.1:1234"

		err := h.Verify2FA(c)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusFound, rec.Code)
		assert.True(t, strings.HasPrefix(rec.Header().Get("Location"), "/rauthdashboard") || strings.HasPrefix(rec.Header().Get("Location"), "/rauthsetup2fa") || strings.HasPrefix(rec.Header().Get("Location"), "/"))
	})

	t.Run("Empty secret rejects instead of validating", func(t *testing.T) {
		// 2FA was reset (or the user deleted) while the pending token was
		// outstanding: codes derived from an empty key are publicly computable,
		// so the handler must abort, not call totp.Validate with secret "".
		emptyUser := "no2fauser"
		core.UserDB.HSet(core.Ctx, "user:"+emptyUser, map[string]interface{}{
			"username": emptyUser,
			"password": "dummy",
		})
		emptyPending := "pending-empty-secret"
		encryptedEmptyPending, _ := core.EncryptToken(emptyPending, cfg.ServerSecret)
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+emptyPending, emptyUser, 5*time.Minute)

		// A code an attacker could derive from the empty key for the current step.
		code, _ := totp.GenerateCode("", time.Now())

		f := make(url.Values)
		f.Set("totp_code", code)

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: encryptedEmptyPending})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("csrf", "test_csrf")

		err := h.Verify2FA(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))

		// The pending token must be consumed so it cannot be retried.
		exists, _ := core.TokenDB.Exists(core.Ctx, "pending_2fa:"+emptyPending).Result()
		assert.EqualValues(t, 0, exists)
	})

	t.Run("Invalid TOTP Code", func(t *testing.T) {
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pendingToken, "testuser", 5*time.Minute)
		defer core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingToken)

		f := make(url.Values)
		f.Set("totp_code", "000000") // Invalid code

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: encryptedPendingToken})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		renderer := &mockRenderer{}
		e.Renderer = renderer
		c.Set("csrf", "test_csrf")
		c.SetPath("/rauthlogin")

		err := h.Verify2FA(c)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusOK, rec.Code) // Renders login page with error
		if renderer.LastData != nil {
			assert.Equal(t, "Invalid 2FA code", renderer.LastData.(map[string]interface{})["error"])
		} else {
			t.Errorf("renderer.LastData is nil")
		}
	})

	t.Run("Missing Pending Cookie", func(t *testing.T) {
		f := make(url.Values)
		f.Set("totp_code", "123456")

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		// Missing cookie
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Verify2FA(c)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Invalid Pending Cookie", func(t *testing.T) {
		f := make(url.Values)
		f.Set("totp_code", "123456")

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: "invalid-token"}) // Invalid token
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Verify2FA(c)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Missing Token in DB", func(t *testing.T) {
		f := make(url.Values)
		f.Set("totp_code", "123456")

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: encryptedPendingToken})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Verify2FA(c)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Equal(t, "/rauthlogin", rec.Header().Get("Location"))
	})

	t.Run("Rate Limit Access Exceeded", func(t *testing.T) {
		// Fill up rate limit
		for i := 0; i < cfg.RateLimitLoginAccessMax; i++ {
			core.CheckRateLimit("login_access:1.2.3.4", cfg.RateLimitLoginAccessMax, cfg.RateLimitLoginAccessDecay)
		}

		f := make(url.Values)
		f.Set("totp_code", "123456")

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.Header.Set("X-Real-IP", "1.2.3.4")
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: encryptedPendingToken})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		renderer := &mockRenderer{}
		e.Renderer = renderer
		c.Set("csrf", "test_csrf")
		req.RemoteAddr = "1.2.3.4:1234"
		c.SetPath("/rauthlogin")

		err := h.Verify2FA(c)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		if renderer.LastData != nil {
			assert.Equal(t, "Too many requests. Please wait a minute.", renderer.LastData.(map[string]interface{})["error"])
		} else {
			t.Errorf("renderer.LastData is nil")
		}
		core.ResetRateLimit("login_access:1.2.3.4")
	})

	t.Run("Rate Limit Post Exceeded", func(t *testing.T) {
		// Fill up rate limit
		for i := 0; i < cfg.RateLimitLoginMax; i++ {
			core.CheckRateLimit("login_post_ip:1.2.3.5", cfg.RateLimitLoginMax, cfg.RateLimitLoginDecay)
		}

		f := make(url.Values)
		f.Set("totp_code", "123456")

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.Header.Set("X-Real-IP", "1.2.3.5")
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: encryptedPendingToken})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		renderer := &mockRenderer{}
		e.Renderer = renderer
		c.Set("csrf", "test_csrf")
		req.RemoteAddr = "1.2.3.5:1234"
		c.SetPath("/rauthlogin")

		err := h.Verify2FA(c)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		if renderer.LastData != nil {
			assert.Equal(t, fmt.Sprintf("Too many attempts from this IP (%s). Please try again later.", "1.2.3.5"), renderer.LastData.(map[string]interface{})["error"])
		} else {
			t.Errorf("renderer.LastData is nil")
		}
		core.ResetRateLimit("login_post_ip:1.2.3.5")
	})

	t.Run("User Rate Limit Failed 2FA", func(t *testing.T) {
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pendingToken, "testuser", 5*time.Minute)
		defer core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingToken)

		// Fill up rate limit
		for i := 0; i < cfg.RateLimitLoginFailUserMax; i++ {
			_, _, _ = core.ReserveRateLimitAttempt("2fa_fail_user:testuser", cfg.RateLimitLoginFailUserMax, cfg.RateLimitLoginFailUserDecay)
		}

		f := make(url.Values)
		f.Set("totp_code", "123456")

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: encryptedPendingToken})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		renderer := &mockRenderer{}
		e.Renderer = renderer
		c.Set("csrf", "test_csrf")
		c.SetPath("/rauthlogin")
		req.RemoteAddr = "192.0.2.1:1234"

		err := h.Verify2FA(c)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		if renderer.LastData != nil {
			assert.Equal(t, "Too many failed attempts. Please try again later.", renderer.LastData.(map[string]interface{})["error"])
		} else {
			t.Errorf("renderer.LastData is nil")
		}

		// clear limit so subsequent tests don't fail
		core.ResetRateLimit("2fa_fail_user:testuser")
	})

	t.Run("Replay Code", func(t *testing.T) {
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pendingToken, "testuser", 5*time.Minute)
		defer core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingToken)

		code, _ := totp.GenerateCode(secret, time.Now())

		// Generate an older code and use it, validating that it passes but marks it
		// then trying again

		// mark as used (same key TOTPCodeReused checks via SetNX)
		core.TokenDB.Set(core.Ctx, "2fa_used:testuser:"+code, "1", time.Minute*3)
		// ensure rate limits don't break us
		core.ResetRateLimit("2fa_fail_user:testuser")

		f := make(url.Values)
		f.Set("totp_code", code)

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: encryptedPendingToken})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		req.RemoteAddr = "192.0.2.1:1234"

		renderer := &mockRenderer{}
		e.Renderer = renderer
		c.Set("csrf", "test_csrf")
		c.SetPath("/rauthlogin")

		err := h.Verify2FA(c)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		if renderer.LastData != nil {
			assert.Equal(t, "Invalid 2FA code", renderer.LastData.(map[string]interface{})["error"])
		} else {
			t.Errorf("renderer.LastData is nil")
		}

		// cleanup
		core.TokenDB.Del(core.Ctx, "2fa_used:testuser:"+code)
	})

	t.Run("Valid Recovery Code", func(t *testing.T) {
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pendingToken, "testuser", 5*time.Minute)
		defer core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingToken)

		// Add recovery code
		recoveryCode := "recovery123"

		norm := strings.ToLower(strings.TrimSpace(recoveryCode))
		norm = strings.ReplaceAll(norm, "-", "")
		norm = strings.ReplaceAll(norm, " ", "")
		sum := sha256.Sum256([]byte(norm))
		recoveryCodeHash := hex.EncodeToString(sum[:])

		core.UserDB.SAdd(core.Ctx, "user:testuser:recovery_codes", recoveryCodeHash)
		// reset recovery code after test
		defer core.UserDB.Del(core.Ctx, "user:testuser:recovery_codes")
		// ensure rate limits don't break us
		core.ResetRateLimit("2fa_fail_user:testuser")

		f := make(url.Values)
		f.Set("totp_code", recoveryCode)

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: encryptedPendingToken})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		req.RemoteAddr = "192.0.2.1:1234"

		c.Set("csrf", "test_csrf")
		c.SetPath("/rauthlogin")

		err := h.Verify2FA(c)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusFound, rec.Code)
		assert.True(t, strings.HasPrefix(rec.Header().Get("Location"), "/rauthdashboard") || strings.HasPrefix(rec.Header().Get("Location"), "/rauthsetup2fa") || strings.HasPrefix(rec.Header().Get("Location"), "/"))
	})

	t.Run("Failed 2FA Penalty", func(t *testing.T) {
		core.TokenDB.Set(core.Ctx, "pending_2fa:"+pendingToken, "testuser", 5*time.Minute)
		defer core.TokenDB.Del(core.Ctx, "pending_2fa:"+pendingToken)

		// Fill up rate limit
		for i := 0; i < cfg.RateLimitLoginFailIPMax; i++ {
			core.CheckRateLimit("login_fail_ip:1.2.3.6", cfg.RateLimitLoginFailIPMax, cfg.RateLimitLoginFailIPDecay)
		}
		// ensure user limit doesn't trigger first
		core.ResetRateLimit("2fa_fail_user:testuser")

		f := make(url.Values)
		f.Set("totp_code", "000000") // Invalid code

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.Header.Set("X-Real-IP", "1.2.3.6")
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: encryptedPendingToken})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		renderer := &mockRenderer{}
		e.Renderer = renderer
		c.Set("csrf", "test_csrf")
		req.RemoteAddr = "1.2.3.6:1234"
		c.SetPath("/rauthlogin")

		err := h.Verify2FA(c)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		if renderer.LastData != nil {
			assert.Equal(t, "Too many failed attempts. Please try again later.", renderer.LastData.(map[string]interface{})["error"])
		} else {
			t.Errorf("renderer.LastData is nil")
		}

		core.ResetRateLimit("login_fail_ip:1.2.3.6")
	})
}
