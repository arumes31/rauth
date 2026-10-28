package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// templatePatterns lists the page templates and the partials they include.
// Partials only contain {{define}} blocks, so names must be unique across all
// files (prefix them with their page or "console_").
var templatePatterns = []string{
	"templates/*.html",
	"templates/partials/*/*.html",
}

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func setupRenderer(e *echo.Echo) {
	e.Renderer = &TemplateRenderer{
		templates: template.Must(template.New("").Funcs(templateFuncs()).ParseFS(templateFS, templatePatterns...)),
	}
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"formatTime":    formatTime,
		"formatSeconds": formatSeconds,
		"eventClass":    eventClass,
		"humanAction":   humanAction,
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			return string(a)
		},
	}
}

// formatTime renders a unix timestamp (int, int64 or numeric string).
func formatTime(input interface{}) string {
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
}

// formatSeconds renders a remaining TTL in seconds as "3d 4h", "2h 5m" or "4m 10s".
func formatSeconds(s string) string {
	sec, _ := strconv.Atoi(s)
	switch {
	case sec <= 0:
		return "expired"
	case sec >= 86400:
		return fmt.Sprintf("%dd %dh", sec/86400, sec%86400/3600)
	case sec >= 3600:
		return fmt.Sprintf("%dh %dm", sec/3600, sec%3600/60)
	}
	return fmt.Sprintf("%dm %ds", sec/60, sec%60)
}

// eventClass groups an audit action for colouring and filtering in the
// consoles: "bad" (failures, blocks, warnings), "ok" (successful sign-ins and
// enrolments), "admin" (administrator actions) or "info".
func eventClass(action string) string {
	switch {
	case strings.HasPrefix(action, "ADMIN_"):
		return "admin"
	case strings.Contains(action, "FAILED"), strings.Contains(action, "BLOCKED"),
		strings.Contains(action, "WARNING"), strings.Contains(action, "MISMATCH"),
		strings.Contains(action, "MISSING"), action == "COUNTRY_CHANGE_DETECTED":
		return "bad"
	case strings.HasPrefix(action, "LOGIN_SUCCESS"), strings.HasSuffix(action, "_SUCCESS"),
		action == "PASSKEY_REGISTER", action == "USER_INVITE_REDEEMED":
		return "ok"
	}
	return "info"
}

// humanAction turns an audit action such as ADMIN_RESET_2FA into "Admin reset 2FA".
func humanAction(action string) string {
	words := strings.Split(strings.ToLower(action), "_")
	for i, w := range words {
		switch w {
		case "2fa", "totp", "ip", "uv":
			words[i] = strings.ToUpper(w)
		}
	}
	out := strings.Join(words, " ")
	if out == "" {
		return action
	}
	return strings.ToUpper(out[:1]) + out[1:]
}
