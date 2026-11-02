package middleware

import (
	"errors"
	"github.com/labstack/echo/v4"
	"net/http"
	"rauth/internal/clusterpolicy"
	"rauth/internal/core"
)

// PolicyPinner is satisfied by clusterworker.Worker[*core.PolicySnapshot].
type PolicyPinner interface {
	WithPolicy(func(*core.PolicySnapshot) error) error
}

const policyFeedVersionKey = "rauth.pinned_policy_feed_version"

const policyFeedCountryKey = "rauth.pinned_policy_feed_country"

type policyFeedCountry struct{ source, country string }

// WorkerPolicyAdmission wraps every public auth/UI request once cluster mode is
// enabled. It never calls the handler without a fresh complete bundle. RequestFeed
// belongs outside it so denied admission is observed; captured string metadata
// remains safe after the pin releases and the old GeoIP reader closes.
func WorkerPolicyAdmission(cfg *core.Config, pinner PolicyPinner) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			admitted := false
			err := error(clusterpolicy.ErrNotCurrent)
			if pinner != nil {
				err = pinner.WithPolicy(func(snapshot *core.PolicySnapshot) error {
					if snapshot == nil {
						return clusterpolicy.ErrNotCurrent
					}
					c.Set(policyFeedVersionKey, snapshot.Identity().Revision)
					admitted = true
					original := c.Request()
					c.SetRequest(original.WithContext(core.WithPolicySnapshot(original.Context(), snapshot)))
					defer c.SetRequest(original)
					_, source := requestFeedTarget(c, cfg)
					c.Set(policyFeedCountryKey, policyFeedCountry{source: source, country: snapshot.CountryCode(source)})
					return next(c)
				})
			}
			if admitted {
				return err
			}
			_, source := requestFeedTarget(c, cfg)
			c.Set(policyFeedCountryKey, policyFeedCountry{source: source, country: "unknown"})
			c.Set("policy_reason", "policy_unavailable")
			for _, name := range []string{"X-RAuth-User", "X-RAuth-Groups", "X-RAuth-Admin", "X-RAuth-Anonymous"} {
				c.Response().Header().Del(name)
			}
			c.Response().Header().Set("Retry-After", "5")
			if err == nil {
				err = errors.New("policy pin did not invoke request callback")
			}
			return echo.NewHTTPError(http.StatusServiceUnavailable, "Policy service is temporarily unavailable; retry").SetInternal(err)
		}
	}
}
