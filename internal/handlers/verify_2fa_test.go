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
)

func TestAuthHandler_Verify2FA_Reproduction(t *testing.T) {
	setupHandlersTest(t)

	cfg := &core.Config{
		ServerSecret: "32byte-secret-key-for-testing-!!",
		CookieDomains: []string{"example.com"},
		TokenValidityMinutes: 60,
	}
	h := &AuthHandler{Cfg: cfg}
	e := echo.New()
	e.Renderer = &mockRenderer{}

	// Create test user with 2FA
	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "RAuth",
		AccountName: "testuser@example.com",
	})
	secret := key.Secret()

	core.UserDB.HSet(core.Ctx, "user:testuser", map[string]interface{}{
		"username":   "testuser",
		"2fa_secret": secret,
	})

	// Setup pending 2FA session
	pendingToken := "pending-token-123"
	core.TokenDB.Set(core.Ctx, "pending_2fa:"+pendingToken, "testuser", 5*time.Minute)

	t.Run("Valid TOTP Code", func(t *testing.T) {
		code, _ := totp.GenerateCode(secret, time.Now())

		f := make(url.Values)
		f.Set("totp_code", code)

		req := httptest.NewRequest(http.MethodPost, "/rauthlogin", strings.NewReader(f.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.AddCookie(&http.Cookie{Name: "rauth_2fa_pending", Value: pendingToken})
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h.Verify2FA(c)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusFound, rec.Code)
	})
}