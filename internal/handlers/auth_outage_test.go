package handlers

import (
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"rauth/internal/core"
)

func TestAuthStateOutagePreservesRestrictedPublicPolicy(t *testing.T) {
	for _, failure := range []string{"sessions", "accounts"} {
		t.Run(failure, func(t *testing.T) {
			setupHandlersTest(t)
			resetBypassRules(t)
			core.SetEnvBypassRules([]string{"public-outage.example.com"})
			_, err := core.AddBypassRule("restricted-outage.example.com", "allow", "", "admin", core.RulePolicy{DefaultFeedConfigured: true, CountryMode: core.CountrySelected, AllowedCountries: []string{"AT"}})
			require.NoError(t, err)
			seedAccount(t, "outage-user")
			cfg := bypassTestConfig()
			h := &AuthHandler{Cfg: cfg}
			token := "outage-session"
			require.NoError(t, core.StoreSession(token, "outage-user", "127.0.0.1", map[string]interface{}{"username": "outage-user", "status": "valid", "auth_gen": mustGen(t, "outage-user"), "ip": "127.0.0.1"}, time.Hour))
			encrypted, err := core.EncryptToken(token, cfg.ServerSecret)
			require.NoError(t, err)
			cookie := &http.Cookie{Name: "X-rauth-authtoken", Value: encrypted}
			if failure == "sessions" {
				require.NoError(t, core.TokenDB.Close())
			} else {
				original := core.PG
				unavailable, err := pgxpool.New(core.Ctx, "postgres://localhost:1/none?connect_timeout=1")
				require.NoError(t, err)
				unavailable.Close()
				core.PG = unavailable
				defer func() { core.PG = original }()
			}
			status, headers := validateWith(t, h, "private-outage.example.com", "/", "127.0.0.1:5000", cookie)
			assert.Equal(t, http.StatusServiceUnavailable, status)
			assert.Empty(t, headers.Get("Location"))
			assert.Empty(t, headers.Get("X-RAuth-User"))
			status, headers = validateWith(t, h, "public-outage.example.com", "/dav/file%3Bname", "127.0.0.1:5000", cookie)
			assert.Equal(t, http.StatusOK, status)
			assert.Equal(t, "1", headers.Get("X-RAuth-Anonymous"))
			assert.Empty(t, headers.Get("X-RAuth-User"))
			status, _ = validateWith(t, h, "restricted-outage.example.com", "/", "127.0.0.1:5000", cookie)
			assert.Equal(t, http.StatusForbidden, status, "country/private-network restrictions remain effective during backend failure")
			if failure == "sessions" {
				status, _ = validateWith(t, h, "private-outage.example.com", "/", "127.0.0.1:5000", nil)
				assert.Equal(t, http.StatusServiceUnavailable, status, "unavailable global throttle is not a rate-limit violation")
				c, _ := createTestContext(echo.New(), http.MethodGet, "/", nil)
				c.Request().AddCookie(cookie)
				err = h.Root(c)
				require.Error(t, err)
				assert.Equal(t, http.StatusServiceUnavailable, err.(*echo.HTTPError).Code)
			}
		})
	}
}
