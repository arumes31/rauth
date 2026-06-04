package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"rauth/internal/core"
	"rauth/internal/handlers"
	"rauth/internal/middleware"
	"strconv"
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

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

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
	if len(cfg.ServerSecret) < 16 {
		slog.Error("SERVER_SECRET must be set to at least 16 characters", "length", len(cfg.ServerSecret))
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
	e.IPExtractor = CreateIPExtractor(cfg)

	// Setup everything
	setupMiddleware(e)
	setupRenderer(e)
	setupRoutes(e, cfg)

	go func() {
		if err := e.Start(":80"); err != nil && err != http.ErrServerClosed {
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

func setupMiddleware(e *echo.Echo) {
	// Order matters: Secure headers and BodyLimit run first, then Client Hints
	// and the request logger, then Recover and CSRF last. Keeping the logger
	// ahead of Recover/CSRF ensures every request — including CSRF rejections —
	// is logged.
	setupSecurityMiddleware(e)
	setupClientHintsMiddleware(e)
	setupLoggingMiddleware(e)
	e.Use(echoMiddleware.Recover())
	setupErrorHandlers(e)
	setupCSRFMiddleware(e)
}

func setupSecurityMiddleware(e *echo.Echo) {
	// Security headers and hardening. Secure()'s defaults leave HSTS disabled
	// and set no CSP, so configure both explicitly. The CSP allows inline
	// scripts/styles because the templates rely on inline <script> blocks and
	// style="" attributes (matrix/glassmorphism UI).
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
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'",
	}))
	e.Use(echoMiddleware.BodyLimit("1M"))
}

func setupCSRFMiddleware(e *echo.Echo) {
	// CSRF Protection
	e.Use(echoMiddleware.CSRFWithConfig(echoMiddleware.CSRFConfig{ // #nosec G101
		TokenLookup:    "header:X-CSRF-Token,form:csrf",
		CookieName:     "_csrf",
		CookiePath:     "/",
		CookieHTTPOnly: true,
		CookieSecure:   true,
		CookieSameSite: http.SameSiteLaxMode,
	}))
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
				slog.String("uri", v.URI),
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
		case strings.HasPrefix(path, "/webauthn/") || path == "/metrics" || path == "/health":
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

func setupRenderer(e *echo.Echo) {
	funcMap := template.FuncMap{
		"formatTime": func(input interface{}) string {
			var timestamp int64
			switch v := input.(type) {
			case int64:
				timestamp = v
			case int:
				timestamp = int64(v)
			case string:
				timestamp, _ = strconv.ParseInt(v, 10, 64)
			default:
				return "N/A"
			}
			if timestamp == 0 {
				return "N/A"
			}
			return time.Unix(timestamp, 0).Format("2006-01-02 15:04:05")
		},
		"formatSeconds": func(s string) string {
			sec, _ := strconv.Atoi(s)
			return fmt.Sprintf("%dm %ds", sec/60, sec%60)
		},
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			return string(a)
		},
		"statusColor": func(action string) string {
			if action == "LOGIN_SUCCESS" || action == "2FA_SETUP_SUCCESS" {
				return "text-success"
			}
			if action == "LOGIN_FAILED" || action == "2FA_FAILED" || action == "COUNTRY_CHANGE_DETECTED" {
				return "text-danger"
			}
			return "text-info"
		},
	}

	renderer := &TemplateRenderer{
		templates: template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html")),
	}
	e.Renderer = renderer
}

func setupRoutes(e *echo.Echo, cfg *core.Config) {
	e.GET("/static/*", echo.WrapHandler(http.FileServer(http.FS(staticFS))))

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
	protected.GET("/webauthn/register/begin", webauthnHandler.BeginRegistration)
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
			Expires:  time.Now().Add(-1 * time.Hour),
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

	if cfg.InitialUser != "" && cfg.InitialPassword != "" {
		slog.Info("Checking initial user", "user", cfg.InitialUser)
		err := core.CreateUser(cfg.InitialUser, cfg.InitialPassword, cfg.InitialEmail, true, cfg.Initial2FASecret)
		if err == nil {
			slog.Info("Initial admin user created")
		} else {
			slog.Info("Initial user already exists or check failed", "error", err)
		}
	}

	// Background metrics and index synchronization
	ctx, cancel := context.WithCancel(context.Background())
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
// It prioritizes explicit trust configuration but falls back to a "smart" detection mode
// where it trusts headers if the immediate connection originates from a private IP (e.g. Docker proxy).
func CreateIPExtractor(cfg *core.Config) echo.IPExtractor {
	return func(req *http.Request) string {
		remoteHost, _, _ := net.SplitHostPort(req.RemoteAddr)
		if remoteHost == "" {
			remoteHost = req.RemoteAddr
		}

		// 1. Check Cloudflare (if explicitly trusted)
		if cfg.TrustCloudflareIP {
			if cfIP := req.Header.Get("CF-Connecting-IP"); cfIP != "" {
				if ip := net.ParseIP(cfIP); ip != nil {
					return ip.String()
				}
			}
		}

		// 2. Check X-Real-IP
		realIPHeader := req.Header.Get("X-Real-IP")
		if realIPHeader != "" {
			// If explicitly trusted, return it regardless
			if cfg.TrustXRealIP {
				if ip := net.ParseIP(realIPHeader); ip != nil {
					return ip.String()
				}
			}
			// In Smart Mode, only return it if the source is private AND the header IP is public.
			// If the header IP is ALSO private, we continue to check X-Forwarded-For which might have the real IP.
			if core.IsPrivateIP(remoteHost) && !core.IsPrivateIP(realIPHeader) {
				if ip := net.ParseIP(realIPHeader); ip != nil {
					return ip.String()
				}
			}
		}

		// 3. Check X-Forwarded-For
		xff := req.Header.Get("X-Forwarded-For")
		if xff != "" {
			ips := strings.Split(xff, ",")
			// If explicitly trusted, return the leftmost (original client) IP
			if cfg.TrustXForwardedFor {
				for i := 0; i < len(ips); i++ {
					cleaned := strings.TrimSpace(ips[i])
					if ip := net.ParseIP(cleaned); ip != nil {
						return ip.String()
					}
				}
			}

			// In Smart Mode, only look at XFF if the remote host is private.
			// We walk the chain from right-to-left and return the first non-private IP.
			if core.IsPrivateIP(remoteHost) {
				for i := len(ips) - 1; i >= 0; i-- {
					cleaned := strings.TrimSpace(ips[i])
					if ip := net.ParseIP(cleaned); ip != nil {
						ipStr := ip.String()
						if !core.IsPrivateIP(ipStr) {
							return ipStr
						}
					}
				}
				// Fallback: If everyone in the chain is private (local traffic), take the leftmost
				cleaned := strings.TrimSpace(ips[0])
				if ip := net.ParseIP(cleaned); ip != nil {
					return ip.String()
				}
			}
		}

		return remoteHost
	}
}
