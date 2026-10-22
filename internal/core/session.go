package core

import (
	"log/slog"
	"net/http"
	"strings"
)

// SessionBindingValid enforces the geo-fence and device binding of an existing
// session for the current request. It is shared by the forward-auth endpoint
// (/rauthvalidate) and AuthMiddleware so a stolen cookie is rejected the same
// way on rauth's own pages. On any violation the session is invalidated and
// false is returned.
func SessionBindingValid(cfg *Config, req *http.Request, token, redisKey string, data map[string]string, clientIP string) bool {
	if !sessionGeoAllowed(cfg, token, redisKey, data, clientIP) {
		return false
	}
	return sessionUAMatches(req, token, redisKey, data, clientIP)
}

// invalidateSession removes a session token and both its user and per-IP index
// entries, so HasActiveSessions does not keep seeing a stale ip_sessions entry.
// The session's origin IP entry is removed as well when it differs from the
// current request IP.
func invalidateSession(token, redisKey string, data map[string]string, clientIP string) {
	RemoveSessionIndex(data["username"], token)
	RemoveIPSessionIndex(clientIP, token)
	if data["ip"] != "" && data["ip"] != clientIP {
		RemoveIPSessionIndex(data["ip"], token)
	}
	TokenDB.Del(Ctx, redisKey)
}

// sessionGeoAllowed enforces the geo-fence: it blocks access from disallowed
// countries and invalidates a session whose origin country has changed.
// On any violation it invalidates the session and returns false.
func sessionGeoAllowed(cfg *Config, token, redisKey string, data map[string]string, clientIP string) bool {
	currentCountry := GetCountryCode(clientIP)

	if !cfg.IsCountryAllowed(currentCountry) {
		slog.Warn("Access from blocked country", "country", currentCountry, "ip", clientIP)
		LogAudit("BLOCKED_COUNTRY_ACCESS", data["username"], clientIP, map[string]interface{}{"country": currentCountry})
		invalidateSession(token, redisKey, data, clientIP)
		return false
	}

	if data["country"] != "unknown" && currentCountry != "unknown" && data["country"] != currentCountry {
		details := map[string]interface{}{"old": data["country"], "new": currentCountry, "current_ip": clientIP}

		// In lenient mode, tolerate the change (still inside the allowlist) and
		// update the stored country so it is not repeatedly flagged. This avoids
		// spurious logouts for roaming/VPN/CGNAT users.
		if cfg.GeoChangeMode == "lenient" {
			LogAudit("COUNTRY_CHANGE_TOLERATED", data["username"], clientIP, details)
			TokenDB.HSet(Ctx, redisKey, "country", currentCountry)
			return true
		}

		LogAudit("COUNTRY_CHANGE_DETECTED", data["username"], clientIP, details)
		invalidateSession(token, redisKey, data, clientIP)
		return false
	}

	return true
}

// sessionUAMatches runs the dual-layer device check (User-Agent Client Hints
// with a lenient User-Agent parser fallback). On a mismatch it invalidates the
// session and returns false.
func sessionUAMatches(req *http.Request, token, redisKey string, data map[string]string, clientIP string) bool {
	chPlatform := req.Header.Get("Sec-CH-UA-Platform")
	chMobile := req.Header.Get("Sec-CH-UA-Mobile")
	chModel := req.Header.Get("Sec-CH-UA-Model")

	storedPlatform := data["ua_ch_platform"]
	storedMobile := data["ua_ch_mobile"]
	storedModel := data["ua_ch_model"]

	normalizeCH := func(val string) string { return strings.Trim(val, `"`) }

	uaIsValid := true
	useClientHints := false

	// If session HAS Hints, we enforce binding if the current request also HAS Hints.
	// If the current request has NO hints but the session DOES, we fall back to UA matching
	// unless we want to be extremely strict (which might break on proxy header stripping).
	//
	// A hint is only compared when it is present on BOTH the stored session and the
	// current request. A hint that is absent on the current request is NOT a mismatch:
	// high-entropy hints (notably Sec-CH-UA-Model) are delivered inconsistently. They are
	// sent to rauth's own origin at login (it advertises Accept-CH/Critical-CH), but the
	// /rauthvalidate auth_request subrequest carries the headers the client sent to the
	// protected app, which usually does not request Client Hints. Treating the missing
	// model hint as a mismatch invalidated every mobile session on the next validation
	// (e.g. stored model "SM-S921B" vs an empty current model), causing a login loop.
	if storedPlatform != "" || storedMobile != "" || storedModel != "" {
		if chPlatform != "" || chMobile != "" || chModel != "" {
			useClientHints = true
			if storedPlatform != "" && chPlatform != "" && normalizeCH(storedPlatform) != normalizeCH(chPlatform) {
				uaIsValid = false
			}
			if uaIsValid && storedMobile != "" && chMobile != "" && normalizeCH(storedMobile) != normalizeCH(chMobile) {
				uaIsValid = false
			}
			if uaIsValid && storedModel != "" && chModel != "" && normalizeCH(storedModel) != normalizeCH(chModel) {
				uaIsValid = false
			}
		}
	}

	if !useClientHints {
		// Fallback to lenient User-Agent parser matching.
		uaIsValid = IsUserAgentCompatible(data["user_agent"], req.UserAgent())
	}

	if uaIsValid {
		return true
	}

	details := map[string]interface{}{
		"use_ch":              useClientHints,
		"stored_ua":           data["user_agent"],
		"current_ua":          req.UserAgent(),
		"stored_ch_platform":  storedPlatform,
		"current_ch_platform": chPlatform,
		"stored_ch_model":     storedModel,
		"current_ch_model":    chModel,
	}
	slog.Warn("Session validation failed due to User-Agent/Client-Hint mismatch, invalidating session",
		"username", data["username"], "use_ch", useClientHints,
		"stored_ua", data["user_agent"], "current_ua", req.UserAgent(),
		"stored_ch_platform", storedPlatform, "current_ch_platform", chPlatform,
		"stored_ch_model", storedModel, "current_ch_model", chModel,
	)
	LogAudit("USER_AGENT_MISMATCH_INVALIDATED", data["username"], clientIP, details)
	invalidateSession(token, redisKey, data, clientIP)
	return false
}
