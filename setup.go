package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"rauth/internal/core"
	"rauth/internal/handlers"
	"rauth/internal/middleware"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func setupMiddleware(e *echo.Echo, cfg *core.Config) {
	// Security headers and hardening
	e.Use(echoMiddleware.Secure())
	e.Use(echoMiddleware.BodyLimit("1M"))

	// User-Agent Client Hints negotiation middleware
	e.Use(middleware.UACHMiddleware())

	// Structured logging middleware
	e.Use(middleware.LoggingMiddleware())

	e.Use(echoMiddleware.Recover())

	// Custom HTTP Error Handler
	e.HTTPErrorHandler = handlers.NewHTTPErrorHandler(e)

	// Explicitly set NotFoundHandler to use our error handler
	echo.NotFoundHandler = func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusNotFound)
	}

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

	protected.POST("/logout", authHandler.Logout)

	// Profile Routes
	protected.GET("/rauthprofile", profileHandler.Show)
	protected.POST("/rauthprofile/password", profileHandler.ChangePassword)
	protected.POST("/rauthprofile/session/terminate", profileHandler.TerminateSession)
	protected.POST("/rauthprofile/session/terminate-others", profileHandler.TerminateAllOtherSessions)
	protected.POST("/rauthprofile/passkey/rename", profileHandler.RenamePasskey)
	protected.POST("/rauthprofile/passkey/revoke", profileHandler.RevokePasskey)
	protected.POST("/rauthprofile/disable-totp", profileHandler.DisableTOTP)

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

func initializeSystem(cfg *core.Config) {
	// Start GeoIP Updater
	core.StartGeoUpdater(cfg)

	if cfg.InitialUser != "" && cfg.InitialPassword != "" {
		slog.Info("Checking initial user", "user", cfg.InitialUser)
		err := core.CreateUser(cfg.InitialUser, cfg.InitialPassword, cfg.InitialEmail, true, cfg.Initial2FASecret)
		if err == nil {
			slog.Info("Initial admin user created")
		} else {
			slog.Info("Initial user already exists or check failed", "error", err)
		}
	}

	// Background metrics updater
	core.StartMetricsUpdater()
}
