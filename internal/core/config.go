package core

import (
	"log/slog"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type Config struct {
	ListenAddr           string
	ServerSecret         string
	RedisHost            string
	RedisPort            string
	RedisPassword        string
	CookieDomains        []string
	TokenValidityMinutes int
	AllowedHosts         []string
	GeoApiHost           string
	GeoApiPort           string
	MaxMindDBPath        string
	MetricsAllowedIPs    []string
	InitialUser          string
	InitialPassword      string
	InitialEmail         string
	Initial2FASecret     string
	WebAuthnOrigins      []string
	AllowedCountries     []string
	// MaxMind
	MaxMindAccountID  string
	MaxMindLicenseKey string
	MaxMindEditionIDs string
	// Password Policy
	MinPasswordLength      int
	RequirePasswordUpper   bool
	RequirePasswordLower   bool
	RequirePasswordNumber  bool
	RequirePasswordSpecial bool
	// SMTP Configuration
	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string
	SMTPFrom string
	// URLs
	PublicURL            string
	TokenRotationMinutes int
	// IP Trust
	TrustCloudflareIP  bool
	TrustXRealIP       bool
	TrustXForwardedFor bool
	// TrustedProxies lists the reverse proxy IPs/CIDRs whose forwarding headers
	// are honoured. Empty means legacy "smart" mode (any private peer).
	TrustedProxies []string
	// CloudflareIPRanges are the Cloudflare edge networks. With
	// TRUST_CLOUDFLARE_IP, CF-Connecting-IP is only honoured when the request
	// demonstrably arrived from one of them, so a client reaching the origin
	// directly cannot forge it.
	CloudflareIPRanges []string
	// CloudflareAutoUpdate refreshes CloudflareIPRanges from Cloudflare's
	// published lists at startup and daily (CLOUDFLARE_IP_AUTO_UPDATE).
	CloudflareAutoUpdate bool
	// Rate Limiting
	RateLimitLoginMax           int
	RateLimitLoginDecay         int
	RateLimitRegistrationMax    int
	RateLimitRegistrationDecay  int
	RateLimitValidateMax        int
	RateLimitValidateDecay      int
	RateLimitLoginAccessMax     int
	RateLimitLoginAccessDecay   int
	RateLimitLoginFailUserMax   int
	RateLimitLoginFailUserDecay int
	RateLimitLoginFailIPMax     int
	RateLimitLoginFailIPDecay   int
	// Logging
	LogLevel string
	// Security tuning
	BcryptCost           int
	CheckCommonPasswords bool
	// Geo-fence behavior on a detected country change for an existing session:
	//   "strict"  - invalidate the session immediately (default)
	//   "lenient" - log/audit the change but tolerate it, updating the stored
	//               country (helps roaming/VPN/CGNAT users avoid spurious logouts)
	// The ALLOWED_COUNTRIES allowlist is always enforced regardless of this mode.
	GeoChangeMode string
	// WebAuthnRequireUserVerification makes passkey logins prove user
	// verification (PIN/biometric). Off by default so passkey providers that do
	// not always report UV (e.g. Bitwarden) keep working;
	// WEBAUTHN_USER_VERIFICATION=required turns it on.
	WebAuthnRequireUserVerification bool
	// CSRFTrustedOrigins lists extra origins (scheme://host[:port]) allowed to
	// send state-changing requests besides rauth's own origin.
	CSRFTrustedOrigins []string
	// AuthBypassRules are read-only bypass rules from AUTH_BYPASS_RULES (more
	// can be managed in the admin UI). See bypass.go for the syntax.
	AuthBypassRules []string
	// AuthBypassHostHeader / AuthBypassURIHeader name the headers carrying the
	// originally requested host and URI on the forward-auth subrequest. The
	// reverse proxy must set (overwrite) them.
	AuthBypassHostHeader string
	AuthBypassURIHeader  string
}

// DefaultCloudflareIPRanges is Cloudflare's published edge list
// (https://www.cloudflare.com/ips/). Override with CLOUDFLARE_IP_RANGES if it
// changes before a release picks it up.
var DefaultCloudflareIPRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

func LoadConfig() *Config {
	return &Config{
		ListenAddr:           getEnv("LISTEN_ADDR", ":80"),
		ServerSecret:         getEnv("SERVER_SECRET", ""),
		RedisHost:            getEnv("REDIS_HOST", "rauth-auth-redis"),
		RedisPort:            getEnv("REDIS_PORT", "6379"),
		RedisPassword:        getEnv("REDIS_PASSWORD", ""),
		CookieDomains:        getEnvSlice("COOKIE_DOMAIN", []string{"example.com"}),
		TokenValidityMinutes: getEnvInt("TOKEN_VALIDITY_MINUTES", 2880),
		AllowedHosts:         getEnvSlice("ALLOWED_HOSTS", []string{"localhost", "127.0.0.1"}),
		GeoApiHost:           getEnv("GEO_API_HOST", "rauth-geo-service"),
		GeoApiPort:           getEnv("GEO_API_PORT", "3000"),
		MaxMindDBPath:        getEnv("MAXMIND_DB_PATH", "/app/geoip/GeoLite2-Country.mmdb"),
		MetricsAllowedIPs:    getEnvSlice("METRICS_ALLOWED_IPS", []string{"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fd7a:115c:a1e0::/48"}),
		InitialUser:          getEnv("INITIAL_USER", "admin"),
		InitialPassword:      getEnv("INITIAL_PASSWORD", ""),
		InitialEmail:         getEnv("INITIAL_EMAIL", "admin@local"),
		Initial2FASecret:     getEnv("INITIAL_2FA_SECRET", ""),
		WebAuthnOrigins:      getEnvSlice("WEBAUTHN_ORIGINS", []string{}),
		AllowedCountries:     getEnvSlice("ALLOWED_COUNTRIES", []string{}),
		// MaxMind
		MaxMindAccountID:  getEnv("MAXMIND_ACCOUNT_ID", ""),
		MaxMindLicenseKey: getEnv("MAXMIND_LICENSE_KEY", ""),
		MaxMindEditionIDs: getEnv("MAXMIND_EDITION_IDS", "GeoLite2-Country"),
		// Password Policy Defaults
		MinPasswordLength:      getEnvInt("PWD_MIN_LENGTH", 8),
		RequirePasswordUpper:   getEnvBool("PWD_REQUIRE_UPPER", true),
		RequirePasswordLower:   getEnvBool("PWD_REQUIRE_LOWER", true),
		RequirePasswordNumber:  getEnvBool("PWD_REQUIRE_NUMBER", true),
		RequirePasswordSpecial: getEnvBool("PWD_REQUIRE_SPECIAL", true),
		// SMTP Defaults
		SMTPHost: getEnv("SMTP_HOST", ""),
		SMTPPort: getEnvInt("SMTP_PORT", 587),
		SMTPUser: getEnv("SMTP_USER", ""),
		SMTPPass: getEnv("SMTP_PASS", ""),
		SMTPFrom: getEnv("SMTP_FROM", ""),
		// URLs
		PublicURL:            getEnv("PUBLIC_URL", "http://localhost:5980"),
		TokenRotationMinutes: getEnvInt("TOKEN_ROTATION_MINUTES", 0),
		// IP Trust
		TrustCloudflareIP:    getEnvBool("TRUST_CLOUDFLARE_IP", false),
		TrustXRealIP:         getEnvBool("TRUST_X_REAL_IP", false),
		TrustXForwardedFor:   getEnvBool("TRUST_X_FORWARDED_FOR", false),
		TrustedProxies:       getEnvSlice("TRUSTED_PROXIES", []string{}),
		CloudflareIPRanges:   getEnvSlice("CLOUDFLARE_IP_RANGES", DefaultCloudflareIPRanges),
		CloudflareAutoUpdate: getEnvBool("CLOUDFLARE_IP_AUTO_UPDATE", true),
		// Rate Limiting Defaults
		RateLimitLoginMax:           getEnvInt("RATE_LIMIT_LOGIN_MAX", 30),
		RateLimitLoginDecay:         getEnvInt("RATE_LIMIT_LOGIN_DECAY", 300),
		RateLimitRegistrationMax:    getEnvInt("RATE_LIMIT_REG_MAX", 10),
		RateLimitRegistrationDecay:  getEnvInt("RATE_LIMIT_REG_DECAY", 300),
		RateLimitValidateMax:        getEnvInt("RATE_LIMIT_VALIDATE_MAX", 1000),
		RateLimitValidateDecay:      getEnvInt("RATE_LIMIT_VALIDATE_DECAY", 60),
		RateLimitLoginAccessMax:     getEnvInt("RATE_LIMIT_LOGIN_ACCESS_MAX", 300),
		RateLimitLoginAccessDecay:   getEnvInt("RATE_LIMIT_LOGIN_ACCESS_DECAY", 60),
		RateLimitLoginFailUserMax:   getEnvInt("RATE_LIMIT_LOGIN_FAIL_USER_MAX", 10),
		RateLimitLoginFailUserDecay: getEnvInt("RATE_LIMIT_LOGIN_FAIL_USER_DECAY", 300),
		RateLimitLoginFailIPMax:     getEnvInt("RATE_LIMIT_LOGIN_FAIL_IP_MAX", 50),
		RateLimitLoginFailIPDecay:   getEnvInt("RATE_LIMIT_LOGIN_FAIL_IP_DECAY", 600),
		// Logging
		LogLevel: getEnv("LOG_LEVEL", "info"),
		// Security tuning
		BcryptCost:           getEnvInt("BCRYPT_COST", 12),
		CheckCommonPasswords: getEnvBool("PWD_CHECK_COMMON", true),
		GeoChangeMode:        strings.ToLower(getEnv("GEO_CHANGE_MODE", "strict")),
		// Passkeys / CSRF
		WebAuthnRequireUserVerification: strings.ToLower(strings.TrimSpace(getEnv("WEBAUTHN_USER_VERIFICATION", "preferred"))) == "required",
		CSRFTrustedOrigins:              getEnvSlice("CSRF_TRUSTED_ORIGINS", []string{}),
		// Auth bypass (anonymous access)
		AuthBypassRules:      getEnvSlice("AUTH_BYPASS_RULES", []string{}),
		AuthBypassHostHeader: getEnv("AUTH_BYPASS_HOST_HEADER", "X-Forwarded-Host"),
		AuthBypassURIHeader:  getEnv("AUTH_BYPASS_URI_HEADER", "X-Forwarded-Uri"),
	}
}

func (c *Config) IsAllowedHost(host string) bool {
	host = normalizeHostname(host)
	if host == "" {
		return false
	}

	// Check explicit allowed hosts
	for _, h := range c.AllowedHosts {
		if normalizeHostname(h) == host {
			return true
		}
	}

	// Also check WebAuthn origins
	for _, o := range c.WebAuthnOrigins {
		parsed, err := url.Parse(o)
		var h string
		if err == nil {
			h = parsed.Hostname()
			if h == "" {
				h = o
			}
		} else {
			h = o
		}
		if normalizeHostname(h) == host {
			return true
		}
	}

	// Check if host is part of any cookie domain
	for _, domain := range c.CookieDomains {
		// Normalize domain
		domain = normalizeHostname(domain)
		if domain == "" {
			continue
		}

		// Exact match
		if host == domain {
			return true
		}
		// Subdomain match (e.g., app.example.com for example.com)
		// Ensure we match a dot before the domain to avoid suffix abuse (e.g. evil-example.com)
		if strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
}

// CSPFormActionSources returns validated CSP sources for login form redirects.
func (c *Config) CSPFormActionSources() []string {
	sources := []string{"'self'"}
	seen := map[string]struct{}{"'self'": {}}

	add := func(source string) {
		if _, exists := seen[source]; exists {
			return
		}
		seen[source] = struct{}{}
		sources = append(sources, source)
	}
	addExactHost := func(raw string) {
		host, ok := normalizeCSPHostname(raw)
		if ok {
			add("https://" + formatCSPHostname(host))
		}
	}

	for _, host := range c.AllowedHosts {
		addExactHost(host)
	}

	for _, domain := range c.CookieDomains {
		host, ok := normalizeCSPHostname(domain)
		if !ok {
			continue
		}

		if net.ParseIP(host) != nil || host == "localhost" {
			add("https://" + formatCSPHostname(host))
			continue
		}

		if _, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil {
			continue
		}

		add("https://" + host)
		add("https://*." + host)
	}

	return sources
}

func normalizeCSPHostname(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "/\\;?#@%\"'") || strings.Contains(raw, "://") {
		return "", false
	}
	if strings.ContainsFunc(raw, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return "", false
	}

	host := normalizeHostname(raw)
	if host == "" {
		return "", false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), true
	}

	host, err := idna.Lookup.ToASCII(host)
	if err != nil || len(host) > 253 || strings.Contains(host, ":") {
		return "", false
	}
	host = strings.ToLower(host)
	for _, label := range strings.Split(host, ".") {
		if !validDNSLabel(label) {
			return "", false
		}
	}

	return host, true
}

func validDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, char := range label {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func formatCSPHostname(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func (c *Config) IsCountryAllowed(country string) bool {
	if len(c.AllowedCountries) == 0 {
		return true // No restriction if empty
	}
	country = strings.TrimSpace(country)
	for _, allowed := range c.AllowedCountries {
		if strings.EqualFold(strings.TrimSpace(allowed), country) {
			return true
		}
	}
	return false
}

func (c *Config) IsIPAllowed(ipStr string, allowedList []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, allowed := range allowedList {
		// Check if it's a CIDR
		if strings.Contains(allowed, "/") {
			_, ipNet, err := net.ParseCIDR(allowed)
			if err == nil && ipNet.Contains(ip) {
				return true
			}
		} else {
			allowedIP := net.ParseIP(allowed)
			if allowedIP != nil && allowedIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func normalizeHostname(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))

	// Remove port if present. net.SplitHostPort is the robust way.
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	} else {
		// No port, or invalid format.
		// Strip brackets if it's an IPv6 literal like [::1]
		h = strings.TrimPrefix(h, "[")
		h = strings.TrimSuffix(h, "]")
	}

	// Trim all leading/trailing dots (handles example.com.. and .example.com)
	h = strings.Trim(h, ".")

	// Normalize IP addresses to their canonical string representation
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}

	return h
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvSlice(key string, fallback []string) []string {
	if value, ok := os.LookupEnv(key); ok {
		parts := strings.Split(value, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return slices.DeleteFunc(parts, func(p string) bool {
			return p == ""
		})
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			return i
		}
		slog.Warn("Invalid integer for env var, using fallback", "key", key, "value", value, "fallback", fallback)
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(value)); err == nil {
			return b
		}
		slog.Warn("Invalid boolean for env var, using fallback", "key", key, "value", value, "fallback", fallback)
	}
	return fallback
}
