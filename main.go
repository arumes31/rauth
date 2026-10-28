package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"rauth/internal/core"
	"rauth/internal/handlers"
	"rauth/internal/middleware"
	"strings"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed static/*
var staticFS embed.FS

//go:embed templates/*
var templateFS embed.FS

func main() {
	// Initialize the structured logger before parsing config so the
	// getEnvInt/getEnvBool warnings about invalid env values are emitted through
	// the same handler (LOG_LEVEL is read directly here since LoadConfig hasn't
	// run yet; parseLogLevel defaults to Info on an empty value). A text handler
	// keeps logs human-readable in `docker logs`/journald.
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(os.Getenv("LOG_LEVEL"))}))
	slog.SetDefault(logger)

	cfg := core.LoadConfig()

	// Fail fast on a missing/weak server secret: it derives the AES key for
	// session tokens and 2FA secrets, so an empty value is catastrophic.
	if err := validateServerSecret(cfg.ServerSecret); err != nil {
		slog.Error("Invalid SERVER_SECRET", "error", err)
		os.Exit(1)
	}

	// Fail fast on an empty cookie domain list: CookieDomains[0] is used for
	// every session cookie and as the WebAuthn RPID, so an empty COOKIE_DOMAIN
	// would otherwise panic at runtime on the first login.
	if len(cfg.CookieDomains) == 0 {
		slog.Error("COOKIE_DOMAIN must contain at least one domain")
		os.Exit(1)
	}

	// Apply the configurable bcrypt cost (BCRYPT_COST).
	core.SetBcryptCost(cfg.BcryptCost)

	// Load the common-password blocklist if enabled (PWD_CHECK_COMMON).
	core.InitCommonPasswords(cfg.CheckCommonPasswords)

	if err := core.InitRedis(cfg); err != nil {
		slog.Error("Redis initialization failed", "error", err)
		os.Exit(1)
	}

	if err := core.InitWebAuthn(cfg); err != nil {
		slog.Error("WebAuthn initialization failed", "error", err)
	}

	// Startup Initialization
	stopSync := initializeSystem(cfg)
	defer stopSync()

	e := echo.New()
	e.HideBanner = true

	// Configure real IP extraction from headers behind reverse proxies
	if len(cfg.TrustedProxies) == 0 {
		slog.Warn("TRUSTED_PROXIES is not set; using legacy smart mode: forwarding headers are trusted from any private-network peer, and enabled TRUST_* flags apply to every peer. Set TRUSTED_PROXIES to your reverse proxy's IP.")
	}
	e.IPExtractor = CreateIPExtractor(cfg)

	// Setup everything
	setupMiddleware(e, cfg)
	setupRenderer(e)
	setupRoutes(e, cfg)

	configureServerTimeouts(e.Server)

	go func() {
		if err := e.Start(cfg.ListenAddr); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	slog.Info("Shutdown signal received, draining connections")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}

// knownPlaceholderSecrets are example values shipped in docs/config templates.
// Running with one of them makes every session cookie and stored TOTP secret
// decryptable by anyone who has read the docs.
var knownPlaceholderSecrets = []string{
	"your_random_32_character_secret_here",
	"change_me",
	"changeme",
	"secret",
}

// validateServerSecret rejects missing, short, placeholder and trivially
// low-entropy secrets. SERVER_SECRET derives the AES key for session tokens and
// 2FA secrets, so a weak value is catastrophic.
func validateServerSecret(secret string) error {
	if len(secret) < 16 {
		return fmt.Errorf("must be at least 16 characters (got %d)", len(secret))
	}
	lower := strings.ToLower(secret)
	for _, p := range knownPlaceholderSecrets {
		if lower == p {
			return fmt.Errorf("is a documented placeholder value; generate one with `openssl rand -hex 32`")
		}
	}
	distinct := map[rune]bool{}
	for _, r := range secret {
		distinct[r] = true
	}
	if len(distinct) < 8 {
		return fmt.Errorf("has too little variety (%d distinct characters); generate one with `openssl rand -hex 32`", len(distinct))
	}
	return nil
}

// configureServerTimeouts bounds how long a client may hold a connection.
// Without them a slow or idle client keeps a goroutine and socket forever,
// and every protected app depends on this forward-auth server answering.
func configureServerTimeouts(s *http.Server) {
	s.ReadHeaderTimeout = 10 * time.Second
	s.ReadTimeout = 30 * time.Second
	s.WriteTimeout = 30 * time.Second
	s.IdleTimeout = 120 * time.Second
	s.MaxHeaderBytes = 64 << 10
}

// parseLogLevel maps a LOG_LEVEL string to an slog.Level (defaults to Info).
func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func setupMiddleware(e *echo.Echo, cfg *core.Config) {
	// Order matters: Secure headers and BodyLimit run first, then Client Hints
	// and the request logger, then Recover and CSRF last. Keeping the logger
	// ahead of Recover/CSRF ensures every request — including CSRF rejections —
	// is logged.
	setupSecurityMiddleware(e, cfg)
	setupClientHintsMiddleware(e)
	setupLoggingMiddleware(e)
	e.Use(echoMiddleware.Recover())
	setupErrorHandlers(e)
	setupCSRFMiddleware(e, cfg)
}

func setupSecurityMiddleware(e *echo.Echo, cfg *core.Config) {
	// Security headers and hardening. Secure()'s defaults leave HSTS disabled
	// and set no CSP, so configure both explicitly. The CSP allows inline
	// scripts/styles because the templates rely on inline <script> blocks and
	// style="" attributes (matrix/glassmorphism UI).
	formActionSources := strings.Join(cfg.CSPFormActionSources(), " ")
	e.Use(echoMiddleware.SecureWithConfig(echoMiddleware.SecureConfig{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "SAMEORIGIN",
		// HSTS with preload is a hard-to-reverse commitment: it emits
		// `includeSubDomains; preload`, so every subdomain of COOKIE_DOMAIN MUST
		// be served exclusively over HTTPS before this is left enabled (and
		// before submitting the domain to the preload list). If any subdomain
		// needs plain HTTP, set HSTSPreloadEnabled:false and/or lower HSTSMaxAge.
		HSTSMaxAge:            31536000,
		HSTSPreloadEnabled:    true,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action " + formActionSources + "; frame-ancestors 'self'",
	}))
	e.Use(echoMiddleware.BodyLimit("1M"))
}

func setupCSRFMiddleware(e *echo.Echo, cfg *core.Config) {
	// 1. Origin-based protection (net/http CrossOriginProtection): rejects
	// state-changing requests whose Sec-Fetch-Site / Origin show they come from
	// another origin — including same-site sibling subdomains, which share the
	// session cookie and could otherwise plant a matching double-submit cookie.
	e.Use(echo.WrapMiddleware(newCrossOriginProtection(cfg).Handler))

	// 2. Token-based protection for clients that send neither header. The
	// __Host- prefix pins the cookie to this exact host so no other subdomain
	// can set or overwrite it.
	e.Use(echoMiddleware.CSRFWithConfig(echoMiddleware.CSRFConfig{ // #nosec G101
		TokenLookup:    "header:X-CSRF-Token,form:csrf",
		CookieName:     "__Host-csrf",
		CookiePath:     "/",
		CookieHTTPOnly: true,
		CookieSecure:   true,
		CookieSameSite: http.SameSiteLaxMode,
	}))
}

// newCrossOriginProtection builds the origin check, trusting any extra origins
// configured in CSRF_TRUSTED_ORIGINS. Invalid entries are logged and skipped.
func newCrossOriginProtection(cfg *core.Config) *http.CrossOriginProtection {
	cop := http.NewCrossOriginProtection()
	for _, origin := range cfg.CSRFTrustedOrigins {
		if err := cop.AddTrustedOrigin(strings.TrimSuffix(strings.TrimSpace(origin), "/")); err != nil {
			slog.Warn("Ignoring invalid CSRF_TRUSTED_ORIGINS entry", "origin", origin, "error", err)
		}
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Warn("Cross-origin state-changing request blocked", "path", r.URL.Path, "origin", r.Header.Get("Origin"), "sec_fetch_site", r.Header.Get("Sec-Fetch-Site"))
		http.Error(w, "Cross-origin request blocked", http.StatusForbidden)
	}))
	return cop
}

func setupLoggingMiddleware(e *echo.Echo) {
	// Structured logging middleware
	e.Use(echoMiddleware.RequestLoggerWithConfig(echoMiddleware.RequestLoggerConfig{
		LogStatus:   true,
		LogURI:      true,
		LogMethod:   true,
		LogRemoteIP: true,
		LogLatency:  true,
		LogError:    true,
		HandleError: true,
		LogValuesFunc: func(c echo.Context, v echoMiddleware.RequestLoggerValues) error {
			req := c.Request()

			// client_ip is the IP resolved by CreateIPExtractor (honouring the
			// configured trust settings). The raw forwarding headers are logged
			// only when present so the common case stays uncluttered and, when
			// the resolved IP looks wrong, the chain is visible for debugging.
			attrs := []slog.Attr{
				slog.String("client_ip", v.RemoteIP),
				slog.String("method", v.Method),
				slog.String("uri", redactURI(v.URI)),
				slog.Int("status", v.Status),
				slog.Duration("latency", v.Latency),
				slog.String("geo", core.GetCountryCode(v.RemoteIP)),
			}
			if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
				attrs = append(attrs, slog.String("x_forwarded_for", xff))
			}
			if xri := req.Header.Get("X-Real-IP"); xri != "" {
				attrs = append(attrs, slog.String("x_real_ip", xri))
			}
			if cf := req.Header.Get("CF-Connecting-IP"); cf != "" {
				attrs = append(attrs, slog.String("cf_ip", cf))
			}

			level := slog.LevelInfo
			msg := "request"
			if v.Error != nil {
				level = slog.LevelError
				msg = "request error"
				attrs = append(attrs, slog.String("err", v.Error.Error()))
			}
			slog.LogAttrs(req.Context(), level, msg, attrs...)
			return nil
		},
	}))
}

// sensitiveQueryParams are query parameters that carry bearer secrets (e.g.
// single-use invite tokens) and must never reach the logs.
var sensitiveQueryParams = []string{"token"}

// redactURI masks sensitive query parameter values in a request URI.
func redactURI(uri string) string {
	path, rawQuery, found := strings.Cut(uri, "?")
	if !found {
		return uri
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return path + "?[unparseable]"
	}
	redacted := false
	for _, p := range sensitiveQueryParams {
		if values.Has(p) {
			values.Set(p, "REDACTED")
			redacted = true
		}
	}
	if !redacted {
		return uri
	}
	return path + "?" + values.Encode()
}

func setupClientHintsMiddleware(e *echo.Echo) {
	// User-Agent Client Hints negotiation middleware
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set("Accept-CH", "Sec-CH-UA-Platform, Sec-CH-UA-Mobile, Sec-CH-UA-Model")

			// Only negotiate Critical-CH on idempotent GET/HEAD requests to prevent non-idempotent retries (like POST logins)
			if c.Request().Method == http.MethodGet || c.Request().Method == http.MethodHead {
				c.Response().Header().Set("Critical-CH", "Sec-CH-UA-Platform, Sec-CH-UA-Mobile, Sec-CH-UA-Model")
			}

			c.Response().Header().Add("Vary", "Sec-CH-UA-Platform")
			c.Response().Header().Add("Vary", "Sec-CH-UA-Mobile")
			c.Response().Header().Add("Vary", "Sec-CH-UA-Model")
			return next(c)
		}
	})
}

func setupErrorHandlers(e *echo.Echo) {
	// Custom HTTP Error Handler
	e.HTTPErrorHandler = func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}
		code := http.StatusInternalServerError
		message := "An unexpected error occurred."
		if he, ok := err.(*echo.HTTPError); ok {
			code = he.Code
			if he.Message != nil {
				message = fmt.Sprintf("%v", he.Message)
			}
		}

		// API and forward-auth endpoints expect machine-readable responses, not
		// the HTML error page. The /rauthvalidate endpoint in particular is
		// polled by nginx auth_request and must stay body-less.
		path := c.Request().URL.Path
		switch {
		case path == "/rauthvalidate":
			_ = c.NoContent(code)
			return
		case strings.HasPrefix(path, "/webauthn/") || path == "/metrics" || path == "/health" || wantsJSON(c.Request()):
			if jsonErr := c.JSON(code, map[string]interface{}{"error": message, "code": code}); jsonErr != nil {
				slog.Error("Failed to render JSON error", "error", jsonErr)
			}
			return
		}

		errorData := map[string]interface{}{
			"Code":    code,
			"Title":   "Error",
			"Message": "An unexpected error occurred.",
			"Icon":    "bi-exclamation-triangle",
			"Color":   "warning",
		}

		switch code {
		case http.StatusNotFound:
			errorData["Title"] = "Page Not Found"
			errorData["Message"] = "The identity you are looking for does not exist or has moved to another dimension."
			errorData["Icon"] = "bi-exclamation-octagon"
			errorData["Color"] = "danger"
		case http.StatusForbidden:
			errorData["Title"] = "Access Forbidden"
			errorData["Message"] = "You do not have the required clearance to access this sector."
			errorData["Icon"] = "bi-shield-lock"
			errorData["Color"] = "danger"
		case http.StatusInternalServerError:
			errorData["Title"] = "System Error"
			errorData["Message"] = "Something went wrong in the core. Our engineers have been notified."
			errorData["Icon"] = "bi-cpu"
			errorData["Color"] = "primary"
		default:
			// Generic handler for other codes
			errorData["Title"] = http.StatusText(code)
		}

		if renderErr := c.Render(code, "error.html", errorData); renderErr != nil {
			slog.Error("Failed to render error page", "error", renderErr)
		}
	}

	// Explicitly set NotFoundHandler to use our error handler
	echo.NotFoundHandler = func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusNotFound)
	}
}

// wantsJSON reports whether the client asked for a JSON error, as the console
// pages do when they submit forms with fetch so they can show the message
// in place instead of navigating to the error page.
func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func setupRoutes(e *echo.Echo, cfg *core.Config) {
	e.GET("/static/*", echo.WrapHandler(http.FileServer(http.FS(noDirListingFS{staticFS}))))

	authHandler := &handlers.AuthHandler{Cfg: cfg}
	adminHandler := &handlers.AdminHandler{Cfg: cfg}
	profileHandler := &handlers.ProfileHandler{Cfg: cfg}
	webauthnHandler := &handlers.WebAuthnHandler{Cfg: cfg}
	healthHandler := &handlers.HealthHandler{Cfg: cfg}
	inviteHandler := &handlers.InviteHandler{Cfg: cfg}

	// Public Routes
	e.GET("/", authHandler.Root)
	e.GET("/rauthvalidate", authHandler.Validate)
	e.GET("/rauthlogin", authHandler.Login)
	e.POST("/rauthlogin", authHandler.Login)
	e.POST("/verify-2fa", authHandler.Verify2FA)
	e.GET("/rauthsetup2fa", authHandler.Setup2FA)
	e.POST("/rauthsetup2fa", authHandler.CompleteSetup2FA)
	e.GET("/rauthredeem", inviteHandler.RedeemPage)
	e.POST("/rauthredeem", inviteHandler.Redeem)

	e.GET("/health", healthHandler.Check)

	// WebAuthn Public Login
	e.GET("/webauthn/login/begin", webauthnHandler.BeginLogin)
	e.POST("/webauthn/login/finish", webauthnHandler.FinishLogin)

	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()), func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if cfg.IsIPAllowed(c.RealIP(), cfg.MetricsAllowedIPs) {
				return next(c)
			}
			slog.Warn("Metrics access denied", "ip", c.RealIP())
			return echo.NewHTTPError(http.StatusForbidden, "Access Denied")
		}
	})

	// Protected Routes
	protected := e.Group("")
	protected.Use(middleware.AuthMiddleware(cfg))

	// WebAuthn Protected Registration
	protected.POST("/webauthn/register/begin", webauthnHandler.BeginRegistration)
	protected.POST("/webauthn/register/finish", webauthnHandler.FinishRegistration)

	protected.POST("/logout", func(c echo.Context) error {
		// Get token from context (set by AuthMiddleware)
		if token, ok := c.Get("token").(string); ok {
			if username, ok := c.Get("username").(string); ok {
				core.RemoveSessionIndex(username, token)
			}
			core.TokenDB.Del(core.Ctx, "X-rauth-authtoken="+token)
		}

		cookie := &http.Cookie{
			Name:     "X-rauth-authtoken",
			Value:    "",
			Path:     "/",
			Domain:   cfg.CookieDomains[0],
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
		c.SetCookie(cookie)
		return c.Redirect(http.StatusFound, "/rauthlogin")
	})

	// Profile Routes
	protected.GET("/rauthprofile", profileHandler.Show)
	protected.POST("/rauthprofile/password", profileHandler.ChangePassword)
	protected.POST("/rauthprofile/session/terminate", profileHandler.TerminateSession)
	protected.POST("/rauthprofile/session/terminate-others", profileHandler.TerminateAllOtherSessions)
	protected.POST("/rauthprofile/passkey/rename", profileHandler.RenamePasskey)
	protected.POST("/rauthprofile/passkey/revoke", profileHandler.RevokePasskey)
	protected.POST("/rauthprofile/disable-totp", profileHandler.DisableTOTP)
	protected.POST("/rauthprofile/recovery/generate", profileHandler.GenerateRecoveryCodes)

	// Admin Routes
	admin := protected.Group("/rauthmgmt")
	admin.Use(middleware.AdminMiddleware)
	admin.GET("", adminHandler.Dashboard)
	admin.POST("/user/create", adminHandler.CreateUser)
	admin.POST("/user/delete", adminHandler.DeleteUser)
	admin.POST("/user/reset-2fa", adminHandler.ResetUser2FA)
	admin.POST("/user/change-password", adminHandler.ChangeUserPassword)
	admin.POST("/user/update-email", adminHandler.UpdateUserEmail)
	admin.POST("/session/invalidate", adminHandler.InvalidateSession)
	admin.POST("/invite/create", inviteHandler.Create)
	admin.POST("/bypass/unlock", adminHandler.UnlockBypass)
	admin.POST("/bypass/lock", adminHandler.LockBypass)
	admin.POST("/bypass/add", adminHandler.AddBypassRule)
	admin.POST("/bypass/update", adminHandler.UpdateBypassRule)
	admin.POST("/bypass/delete", adminHandler.DeleteBypassRule)
}

// bypassRefreshInterval bounds how long another instance keeps serving a rule
// set that an admin changed elsewhere.
const bypassRefreshInterval = 15 * time.Second

// noDirListingFS hides directories from http.FileServer so /static/ and its
// subdirectories return 404 instead of an index of the embedded assets.
type noDirListingFS struct{ fs.FS }

func (n noDirListingFS) Open(name string) (fs.File, error) {
	f, err := n.FS.Open(name)
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err == nil && info.IsDir() {
		_ = f.Close()
		return nil, fs.ErrNotExist
	}
	return f, nil
}

// initializeSystem performs startup tasks and launches the background
// metrics/index synchronization loop. It returns a stop function that signals
// the background goroutine to exit and blocks until it has fully stopped — this
// lets callers (notably tests) tear down shared state without racing the loop.
func initializeSystem(cfg *core.Config) func() {
	// Start GeoIP Updater
	core.StartGeoUpdater(cfg)

	// Backfill UIDs for legacy users so GetUser stays read-only at runtime.
	core.EnsureUserUIDs()
	// Encrypt TOTP secrets stored before at-rest encryption existed.
	core.MigratePlaintextTOTPSecrets()

	if cfg.InitialUser != "" && cfg.InitialPassword != "" {
		slog.Info("Checking initial user", "user", cfg.InitialUser)
		exists, err := core.UserDB.Exists(core.Ctx, "user:"+cfg.InitialUser).Result()
		switch {
		case err != nil:
			slog.Error("Initial user check failed", "error", err)
		case exists > 0:
			slog.Info("Initial user already exists")
		case core.ValidatePassword(cfg.InitialPassword, cfg) != nil:
			// The root admin enrolls TOTP on first login, so a weak bootstrap
			// password would let whoever guesses it first own the account.
			slog.Error("INITIAL_PASSWORD does not meet the password policy (see PWD_* settings); initial admin not created")
		default:
			if err := core.CreateUser(cfg.InitialUser, cfg.InitialPassword, cfg.InitialEmail, true, cfg.Initial2FASecret); err == nil {
				slog.Info("Initial admin user created")
			} else {
				slog.Info("Initial user creation failed", "error", err)
			}
		}
	}

	// Background metrics and index synchronization
	ctx, cancel := context.WithCancel(context.Background())

	// Cloudflare edge ranges: seeded from config, refreshed at boot and daily.
	core.StartCloudflareUpdater(ctx, cfg)

	// Auth bypass rules: read-only ones from AUTH_BYPASS_RULES plus UI-managed
	// ones from Redis, refreshed so every instance sees admin changes.
	core.SetEnvBypassRules(cfg.AuthBypassRules)
	core.StartBypassRefresher(ctx, bypassRefreshInterval)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			count := core.SyncSessionIndexes()
			core.ActiveSessionsGauge.Set(float64(count))
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}

// CreateIPExtractor returns a function that extracts the real client IP from request headers.
//
// Forwarding headers are only honoured when the immediate peer (RemoteAddr) is a
// trusted proxy. Trusted proxies are configured explicitly via TRUSTED_PROXIES
// (IPs/CIDRs). When it is unset, a legacy "smart" mode treats any private or
// loopback peer (e.g. a Docker-network proxy) as trusted; that mode relies on the
// proxy overwriting X-Real-IP and should be replaced by an explicit list.
func CreateIPExtractor(cfg *core.Config) echo.IPExtractor {
	explicit := len(cfg.TrustedProxies) > 0
	isTrustedProxy := func(ip string) bool {
		if explicit {
			return cfg.IsIPAllowed(ip, cfg.TrustedProxies)
		}
		return core.IsPrivateIP(ip)
	}

	return func(req *http.Request) string {
		remoteHost, _, _ := net.SplitHostPort(req.RemoteAddr)
		if remoteHost == "" {
			remoteHost = req.RemoteAddr
		}
		peerTrusted := isTrustedProxy(remoteHost)

		// With an explicit proxy allowlist, a peer outside it can never choose
		// its own IP through headers, whatever the TRUST_* flags say.
		if explicit && !peerTrusted {
			return remoteHost
		}

		// 1. Check Cloudflare (if explicitly trusted). CF-Connecting-IP is only
		// meaningful when the request really came through Cloudflare: the edge
		// must be either the direct peer or, behind a local proxy, the address
		// that proxy reports in X-Real-IP. Anyone reaching the origin directly
		// could otherwise forge the header.
		if cfg.TrustCloudflareIP {
			edge := remoteHost
			if peerTrusted {
				if ip := net.ParseIP(strings.TrimSpace(req.Header.Get("X-Real-IP"))); ip != nil {
					edge = ip.String()
				}
			}
			if core.IsCloudflareIP(edge) {
				if ip := net.ParseIP(strings.TrimSpace(req.Header.Get("CF-Connecting-IP"))); ip != nil {
					return ip.String()
				}
			}
		}

		// 2. Check X-Real-IP
		if ip := net.ParseIP(strings.TrimSpace(req.Header.Get("X-Real-IP"))); ip != nil {
			realIP := ip.String()
			// If explicitly trusted, return it regardless
			if cfg.TrustXRealIP {
				return realIP
			}
			// Legacy smart mode: accept only a public header IP from a private
			// peer. Any private host (not just the proxy) counts as a trusted
			// peer here, so accepting private values would let a LAN client claim
			// any private address. A private value falls through to the
			// proxy-appended X-Forwarded-For hop below. With TRUSTED_PROXIES set,
			// X-Real-IP is only used when TRUST_X_REAL_IP is enabled, since not
			// every proxy overwrites it.
			if !explicit && peerTrusted && !core.IsPrivateIP(realIP) {
				return realIP
			}
		}

		// 3. Check X-Forwarded-For
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" && (cfg.TrustXForwardedFor || peerTrusted) {
			// In smart mode only the immediate peer is known to be a proxy, so
			// only the hop it appended (the rightmost) is trustworthy. Walking
			// further left past "private" hops would skip the real client's own
			// LAN address and return an entry the client wrote itself.
			walkTrust := isTrustedProxy
			if !explicit {
				walkTrust = func(string) bool { return false }
			}
			if ip := clientIPFromXFF(strings.Split(xff, ","), walkTrust); ip != "" {
				return ip
			}
		}

		return remoteHost
	}
}

// clientIPFromXFF walks an X-Forwarded-For chain right-to-left and returns the
// first hop that is not a trusted proxy. Proxies append to the header, so the
// leftmost entries are entirely client-controlled and are never preferred. If
// every hop is trusted (purely internal traffic), the rightmost valid entry is
// returned since it was written by the closest proxy.
func clientIPFromXFF(hops []string, isTrustedProxy func(string) bool) string {
	rightmost := ""
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(hops[i]))
		if ip == nil {
			continue
		}
		ipStr := ip.String()
		if rightmost == "" {
			rightmost = ipStr
		}
		if !isTrustedProxy(ipStr) {
			return ipStr
		}
	}
	return rightmost
}
