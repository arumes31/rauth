package middleware

import (
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestFeedDecisionsAndTrustedMetadata(t *testing.T) {
	old := core.LiveRequests
	t.Cleanup(func() { core.LiveRequests = old })
	cases := []struct {
		status    int
		anonymous bool
		action    string
	}{
		{200, false, "authenticated"}, {200, true, "bypass"}, {401, false, "login_required"},
		{403, false, "blocked"}, {429, false, "rate_limited"}, {500, false, "error"},
	}
	for _, tc := range cases {
		core.LiveRequests = core.NewRequestFeed(5)
		e := echo.New()
		e.IPExtractor = func(*http.Request) string { return "100.64.1.2" }
		e.Use(RequestFeed(&core.Config{TrustedProxies: []string{"10.0.0.0/8"}, AuthBypassHostHeader: "X-Forwarded-Host", AuthBypassURIHeader: "X-Forwarded-Uri"}))
		e.GET("/rauthvalidate", func(c echo.Context) error {
			if tc.anonymous {
				c.Response().Header().Set("X-RAuth-Anonymous", "1")
			}
			if tc.status == 500 {
				return echo.NewHTTPError(500)
			}
			return c.NoContent(tc.status)
		})
		req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
		req.RemoteAddr = "10.1.2.3:1234"
		req.Header.Set("X-Forwarded-Host", "cloud.example.com")
		req.Header.Set("X-Forwarded-Uri", "/file;C?token=secret")
		req.Header.Set("X-Forwarded-Proto", "https")
		e.ServeHTTP(httptest.NewRecorder(), req)
		events := core.LiveRequests.After(0).Events
		require.Len(t, events, 1)
		assert.Equal(t, tc.action, events[0].Action)
		assert.Equal(t, tc.status, events[0].Status)
		assert.Equal(t, "https://cloud.example.com/file;C", events[0].URL)
		assert.Equal(t, "100.64.1.2", events[0].Source)
		assert.Equal(t, "Tailscale", events[0].Country)
	}
}

func TestRequestFeedRejectsSpoofedTargetAndIgnoresOtherRoutes(t *testing.T) {
	old := core.LiveRequests
	core.LiveRequests = core.NewRequestFeed(5)
	t.Cleanup(func() { core.LiveRequests = old })
	e := echo.New()
	e.Use(RequestFeed(&core.Config{TrustedProxies: []string{"10.0.0.0/8"}, AuthBypassHostHeader: "X-Forwarded-Host", AuthBypassURIHeader: "X-Forwarded-Uri"}))
	e.GET("/rauthvalidate", func(c echo.Context) error { return c.NoContent(401) })
	e.GET("/health", func(c echo.Context) error { return c.NoContent(200) })
	req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
	req.RemoteAddr = "203.0.113.1:1234"
	req.Header.Set("X-Forwarded-Host", "cloud.example.com")
	req.Header.Set("X-Forwarded-Uri", "/secret")
	e.ServeHTTP(httptest.NewRecorder(), req)
	events := core.LiveRequests.After(0).Events
	require.Len(t, events, 1)
	assert.Empty(t, events[0].URL)
	e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))
	assert.Len(t, core.LiveRequests.After(0).Events, 1)
}

func TestRequestFeedOptionalOriginalIPDoesNotChangeAuthenticationIP(t *testing.T) {
	old := core.LiveRequests
	t.Cleanup(func() { core.LiveRequests = old })
	for _, tc := range []struct{ peer, header, want string }{
		{"10.1.2.3:1234", "203.0.113.42", "203.0.113.42"},
		{"203.0.113.1:1234", "203.0.113.42", "100.64.1.2"},
		{"10.1.2.3:1234", "invalid, forwarded", "100.64.1.2"},
	} {
		core.LiveRequests = core.NewRequestFeed(3)
		e := echo.New()
		e.IPExtractor = func(*http.Request) string { return "100.64.1.2" }
		e.Use(RequestFeed(&core.Config{TrustedProxies: []string{"10.0.0.0/8"}, RequestFeedIPHeader: "X-RAuth-Observed-IP"}))
		e.GET("/rauthvalidate", func(c echo.Context) error {
			assert.Equal(t, "100.64.1.2", c.RealIP(), "telemetry must not alter authorization IP")
			return c.NoContent(401)
		})
		req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
		req.RemoteAddr = tc.peer
		req.Header.Set("X-RAuth-Observed-IP", tc.header)
		e.ServeHTTP(httptest.NewRecorder(), req)
		events := core.LiveRequests.After(0).Events
		require.Len(t, events, 1)
		assert.Equal(t, tc.want, events[0].Source)
	}
}
