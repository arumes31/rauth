package main

import (
	"context"
	"embed"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"rauth/internal/core"
	"rauth/internal/handlers"
	"rauth/internal/middleware"
	"time"

	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
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
	// Initialize slog
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := core.LoadConfig()

	if err := core.InitRedis(cfg); err != nil {
		slog.Error("Redis initialization failed", "error", err)
		os.Exit(1)
	}

	// Startup Initialization
	initializeSystem(cfg)

	e := echo.New()
	e.HideBanner = true

	// Security headers and hardening
	e.Use(echoMiddleware.Secure())
	e.Use(echoMiddleware.BodyLimit("1M"))
	
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
			if v.Error == nil {
				slog.Info("request",
					slog.String("ip", v.RemoteIP),
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.Duration("latency", v.Latency),
				)
			} else {
				slog.Error("request error",
					slog.String("ip", v.RemoteIP),
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.Duration("latency", v.Latency),
					slog.String("err", v.Error.Error()),
				)
			}
			return nil
		},
	}))
	
	e.Use(echoMiddleware.Recover())
	
	// CSRF Protection
	e.Use(echoMiddleware.CSRFWithConfig(echoMiddleware.CSRFConfig{
		TokenLookup: "form:csrf", // Look for 'csrf' field in forms
		CookieName:  "_csrf",
		CookiePath:  "/",
	}))

	funcMap := template.FuncMap{
		"formatTime": func(timestamp int64) string {
			return time.Unix(timestamp, 0).Format("2006-01-02 15:04:05")
		},
		"statusColor": func(action string) string {
			// Simple check: if contains SUCCESS -> green, FAILED -> red
			// We can do exact matches or substring. Substring is robust for future actions.
			// Using basic string contains logic since strings package isn't imported in main specifically for this,
			// but wait, I can import "strings". Or I can just do a range of checks.
			// Let's stick to explicit checks or just basic logic.
			// Actually I need to add "strings" to imports if I use strings.Contains.
			// Or just checking the suffix/substring manually.
			// Let's assume standard actions: LOGIN_SUCCESS, LOGIN_FAILED, 2FA_FAILED.
			
			// Re-implementing simplified contains to avoid import mess if possible, but importing "strings" is better.
			// I will add "strings" to imports in a separate step or assume it is there?
			// It is NOT in imports. I will just use basic if/else for known actions.
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

	e.GET("/static/*", echo.WrapHandler(http.FileServer(http.FS(staticFS))))

	authHandler := &handlers.AuthHandler{Cfg: cfg}
	adminHandler := &handlers.AdminHandler{Cfg: cfg}
	profileHandler := &handlers.ProfileHandler{Cfg: cfg}

	// Public Routes
	e.GET("/", authHandler.Root)
	e.GET("/rauthvalidate", authHandler.Validate)
	e.GET("/rauthlogin", func(c echo.Context) error { return c.Render(http.StatusOK, "login.html", map[string]interface{}{"csrf": c.Get("csrf"), "rd": c.QueryParam("rd")}) })
	e.POST("/rauthlogin", authHandler.Login)
	e.POST("/verify-2fa", authHandler.Verify2FA)
	e.GET("/rauthsetup2fa", authHandler.Setup2FA)
	e.POST("/rauthsetup2fa", authHandler.CompleteSetup2FA)

	// Protected Routes
	protected := e.Group("")
	protected.Use(middleware.AuthMiddleware(cfg))
	
	protected.POST("/logout", func(c echo.Context) error {
		// Get token from context (set by AuthMiddleware)
		if token, ok := c.Get("token").(string); ok {
			core.TokenDB.Del(core.Ctx, "X-rauth-authtoken="+token)
		}

		cookie := &http.Cookie{
			Name:     "X-rauth-authtoken",
			Value:    "",
			Path:     "/",
			Domain:   cfg.CookieDomains[0],
			Expires:  time.Now().Add(-1 * time.Hour),
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

	// Admin Routes
	admin := protected.Group("/rauthmgmt")
	admin.Use(middleware.AdminMiddleware)
	admin.GET("", adminHandler.Dashboard)
	admin.POST("/user/create", adminHandler.CreateUser)
	admin.POST("/user/delete", adminHandler.DeleteUser)
	admin.POST("/session/invalidate", adminHandler.InvalidateSession)

	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "OK"})
	})

	go func() {
		if err := e.Start(":80"); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}

func initializeSystem(cfg *core.Config) {
	if cfg.InitialUser != "" && cfg.InitialPassword != "" {
		slog.Info("Checking initial user", "user", cfg.InitialUser)
		err := core.CreateUser(cfg.InitialUser, cfg.InitialPassword, cfg.InitialEmail, true, cfg.Initial2FASecret)
		if err == nil {
			slog.Info("Initial admin user created")
		} else {
			slog.Info("Initial user already exists or check failed", "error", err)
		}
	}
}
