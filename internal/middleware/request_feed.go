package middleware

import (
	"errors"
	"net"
	"net/http"
	"rauth/internal/core"
	"strings"

	"github.com/labstack/echo/v4"
)

// RequestFeed observes forward-auth decisions, including rejections by the
// security middleware inside it. It does not record bodies, cookies or tokens.
func RequestFeed(cfg *core.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Path() != "/rauthvalidate" {
				return next(c)
			}
			err := next(c)
			status := c.Response().Status
			if err != nil && !c.Response().Committed {
				status = http.StatusInternalServerError
				var he *echo.HTTPError
				if errors.As(err, &he) {
					status = he.Code
				}
			}
			action := "blocked"
			switch {
			case status >= 500:
				action = "error"
			case status == http.StatusTooManyRequests:
				action = "rate_limited"
			case status == http.StatusUnauthorized || (status >= 300 && status < 400):
				action = "login_required"
			case status >= 200 && status < 300:
				action = "authenticated"
				if c.Response().Header().Get("X-RAuth-Anonymous") == "1" {
					action = "bypass"
				}
			}
			target, source := requestFeedTarget(c, cfg)
			var country string
			if captured, ok := c.Get(policyFeedCountryKey).(policyFeedCountry); ok {
				country = "unknown"
				if captured.source == source {
					country = captured.country
				}
			} else {
				country = core.CountryCodeForContext(c.Request().Context(), source)
			}
			reason, _ := c.Get("policy_reason").(string)
			rule, _ := c.Get("policy_rule").(string)
			feedID, _ := c.Get("policy_feed_id").(string)
			core.LiveRequests.Append(core.RequestEvent{Reason: reason, Rule: rule, FeedID: feedID, URL: target, Source: source, Country: country, Action: action, Status: status})
			return err
		}
	}
}

func requestFeedTarget(c echo.Context, cfg *core.Config) (target, source string) {
	source = c.RealIP()
	if cfg.IsTrustedProxyPeer(c.Request().RemoteAddr) {
		headers := c.Request().Header
		target = core.ProtectedRequestURL(headers.Get("X-Forwarded-Proto"), headers.Get(cfg.AuthBypassHostHeader), headers.Get(cfg.AuthBypassURIHeader))
		if cfg.RequestFeedIPHeader != "" {
			if ip := net.ParseIP(strings.TrimSpace(headers.Get(cfg.RequestFeedIPHeader))); ip != nil {
				source = ip.String()
			}
		}
	}
	return target, source
}
