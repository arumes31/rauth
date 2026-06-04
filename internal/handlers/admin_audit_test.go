package handlers

import (
	"html/template"
	"net/http"
	"rauth/internal/core"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestAdminHandler_Dashboard_AuditLogFormat(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{}
	h := &AdminHandler{Cfg: cfg}
	e := echo.New()
	mr := &mockRenderer{}
	e.Renderer = mr

	// Seed an audit log
	core.LogAudit("DASHBOARD_TEST", "admin", "127.0.0.1", map[string]interface{}{"status": "verified"})

	c, rec := createTestContext(e, http.MethodGet, "/rauthmgmt", nil)
	c.Set("username", "admin")

	err := h.Dashboard(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	data, ok := mr.LastData.(map[string]interface{})
	assert.True(t, ok)

	logs, ok := data["logs"].(template.JS)
	assert.True(t, ok)

	// The logs should be a JSON array string
	logsStr := string(logs)
	assert.Contains(t, logsStr, "DASHBOARD_TEST")
	assert.Contains(t, logsStr, "admin")
	assert.Contains(t, logsStr, "127.0.0.1")
	assert.Contains(t, logsStr, "verified")

	// Basic JSON array format check
	assert.True(t, len(logsStr) >= 2)
	assert.Equal(t, uint8('['), logsStr[0])
	assert.Equal(t, uint8(']'), logsStr[len(logsStr)-1])
}
