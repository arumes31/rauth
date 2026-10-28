package main

import (
	"bytes"
	"io/fs"
	"path"
	"rauth/internal/core"
	"rauth/internal/handlers"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Templates are registered by base name, so two partials with the same file
// name would silently replace each other's top-level content.
func TestTemplatePartialNamesUnique(t *testing.T) {
	seen := map[string]string{}
	for _, pattern := range templatePatterns {
		matches, err := fs.Glob(templateFS, pattern)
		require.NoError(t, err)
		for _, m := range matches {
			base := path.Base(m)
			if prev, ok := seen[base]; ok {
				t.Errorf("template file name %q used twice: %s and %s", base, prev, m)
			}
			seen[base] = m
		}
	}
	assert.Contains(t, seen, "admin_users.html")
	assert.Contains(t, seen, "profile_security.html")
}

func TestProfileTemplateRenders(t *testing.T) {
	e := echo.New()
	setupRenderer(e)
	for _, has2FA := range []bool{true, false} {
		var page bytes.Buffer
		err := e.Renderer.Render(&page, "profile.html", map[string]interface{}{
			"username":      "alice",
			"email":         "alice@example.com",
			"groups":        "staff",
			"isAdmin":       true,
			"isRoot":        false,
			"createdAt":     "1700000000",
			"has2FA":        has2FA,
			"recoveryCount": int64(2),
			"sessions": []map[string]string{
				{"token": "t1", "is_current": "1", "friendly_ua": "Firefox", "device_icon": "bi-laptop", "ip": "10.0.0.1", "country": "AT", "created_at": "1700000000", "ttl": "3600"},
				{"token": "t2", "is_current": "0", "friendly_ua": "Safari", "device_icon": "bi-phone", "ip": "10.0.0.2", "country": "Tailscale", "created_at": "1700000100", "ttl": "60"},
			},
			"logs":     []core.AuditLog{{Timestamp: 1700000000, Action: "LOGIN_FAILED", Username: "alice", IP: "10.0.0.1", Details: map[string]interface{}{"country": "AT"}}},
			"passkeys": []core.StoredCredential{{Nickname: "YubiKey", CreatedAt: 1700000000}},
			"csrf":     "test-csrf",
		}, nil)
		require.NoError(t, err)
		body := page.String()
		assert.Contains(t, body, `<meta name="csrf-token" content="test-csrf">`)
		assert.Contains(t, body, `/static/js/profile.js`)
		assert.Contains(t, body, "YubiKey")
		assert.Contains(t, body, "This device")
		assert.Contains(t, body, `href="/rauthmgmt"`)
		// Only the other session can be signed out from the list.
		assert.Contains(t, body, `name="token" value="t2"`)
		assert.NotContains(t, body, `name="token" value="t1"`)
		if has2FA {
			assert.Contains(t, body, "/rauthprofile/disable-totp")
			assert.Contains(t, body, `name="otp_code"`)
		} else {
			assert.NotContains(t, body, "/rauthprofile/disable-totp")
			assert.Contains(t, body, `data-stepup-name="current_password"`)
		}
	}
}

func TestManagementTemplateNeverRendersSecrets(t *testing.T) {
	e := echo.New()
	setupRenderer(e)
	var page bytes.Buffer
	err := e.Renderer.Render(&page, "management.html", map[string]interface{}{
		"username":  "boss",
		"root_user": "boss",
		"csrf":      "test-csrf",
		"users":     []handlers.AdminUserView{{Username: "boss", IsAdmin: "1", Has2FA: true, Sessions: 2}},
		"stats":     handlers.AdminStats{Users: 1, Admins: 1, With2FA: 1, Sessions: 2, FailedLogins: 1},
		"sessions":  []map[string]string{{"username": "boss", "token": "tok", "ttl": "90000", "created_at": "1700000000"}},
		"logs":      []core.AuditLog{{Action: "ADMIN_RESET_2FA", Username: "boss", Details: map[string]interface{}{"target": "x"}}},
		"bypass_rules": []handlers.BypassRuleView{
			{BypassRule: core.BypassRule{Rule: "app.example.com/", Action: core.BypassAllow, Source: "env"}, Scope: "Only the root page"},
		},
	}, nil)
	require.NoError(t, err)
	body := page.String()
	assert.Contains(t, body, "/static/js/management.js")
	assert.Contains(t, body, "1d 1h", "session TTL is humanised")
	assert.Contains(t, body, "Admin reset 2FA")
	assert.Contains(t, body, `data-kind="admin"`)
	assert.Contains(t, body, "app.example.com/")
}

func TestEventClass(t *testing.T) {
	cases := map[string]string{
		"LOGIN_SUCCESS":                   "ok",
		"LOGIN_SUCCESS_PASSKEY":           "ok",
		"2FA_SETUP_SUCCESS":               "ok",
		"PASSKEY_REGISTER":                "ok",
		"LOGIN_FAILED":                    "bad",
		"2FA_FAILED":                      "bad",
		"BLOCKED_COUNTRY_LOGIN_ATTEMPT":   "bad",
		"PASSKEY_CLONE_WARNING":           "bad",
		"USER_AGENT_MISMATCH_INVALIDATED": "bad",
		"COUNTRY_CHANGE_DETECTED":         "bad",
		"ADMIN_DELETE_USER":               "admin",
		"ADMIN_BYPASS_UNLOCK":             "admin",
		"USER_CHANGE_PASSWORD":            "info",
		"COUNTRY_CHANGE_TOLERATED":        "info",
	}
	for action, want := range cases {
		assert.Equal(t, want, eventClass(action), action)
	}
}

func TestHumanAction(t *testing.T) {
	assert.Equal(t, "Admin reset 2FA", humanAction("ADMIN_RESET_2FA"))
	assert.Equal(t, "User disable TOTP", humanAction("USER_DISABLE_TOTP"))
	assert.Equal(t, "Login success", humanAction("LOGIN_SUCCESS"))
	assert.Equal(t, "", humanAction(""))
}

func TestFormatSeconds(t *testing.T) {
	assert.Equal(t, "expired", formatSeconds("0"))
	assert.Equal(t, "expired", formatSeconds("-2"))
	assert.Equal(t, "0m 59s", formatSeconds("59"))
	assert.Equal(t, "59m 59s", formatSeconds("3599"))
	assert.Equal(t, "1h 0m", formatSeconds("3600"))
	assert.Equal(t, "1d 1h", formatSeconds("90000"))
}
