package middleware

import (
	"net"
	"net/http"
	"rauth/internal/core"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// RequestFeed observes forward-auth decisions, including rejections by the
// security middleware inside it. It does not record bodies, cookies or tokens.
func RequestFeed(cfg *core.Config) echo.MiddlewareFunc { return RequestFeedSink(cfg, nil) }

// RequestFeedSink adds an optional nonblocking local observer. It must not do I/O.
func RequestFeedSink(cfg *core.Config, sink func(core.RequestEvent)) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if c.Path() != "/rauthvalidate" {
				return next(c)
			}
			started := time.Now()
			err := next(c)
			status, committed := 0, false
			if resp, uerr := echo.UnwrapResponse(c.Response()); uerr == nil {
				status, committed = resp.Status, resp.Committed
			}
			if err != nil && !committed {
				// echo.StatusCode also covers predefined errors such as
				// echo.ErrNotFound, which are not *echo.HTTPError in v5.
				status = http.StatusInternalServerError
				if code := echo.StatusCode(err); code != 0 {
					status = code
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
			version, _ := c.Get(policyFeedVersionKey).(int64)
			event := core.RequestEvent{Time: time.Now().UTC(), Reason: reason, Rule: rule, FeedID: feedID, URL: target, Source: source, Country: country, Action: action, Status: status, PolicyVersion: version, ProcessingMicros: max(time.Since(started).Microseconds(), 1)}
			core.ForwardAuthDecisionsTotal.WithLabelValues(action).Inc()
			core.ForwardAuthProcessingSeconds.Observe(float64(event.ProcessingMicros) / 1e6)
			core.LiveRequests.Append(event)
			if sink != nil {
				sink(event)
			}
			return err
		}
	}
}

func requestFeedTarget(c *echo.Context, cfg *core.Config) (target, source string) {
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
