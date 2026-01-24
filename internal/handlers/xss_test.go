package handlers

import (
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestXSSProtection(t *testing.T) {
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})
	
	// Force override globals for this test
	oldUserDB := core.UserDB
	oldAuditDB := core.AuditDB
	core.UserDB = client
	core.AuditDB = client
	defer func() {
		core.UserDB = oldUserDB
		core.AuditDB = oldAuditDB
	}()

	h := &AdminHandler{Cfg: &core.Config{}}
	e := echo.New()

	// Setup template with standard escaping
	tmpl := template.Must(template.New("management.html").Parse(`<html><body>{{range .users}}{{.Username}}{{end}}</body></html>`))
	e.Renderer = &xssMockRenderer{tmpl: tmpl}

	maliciousUser := "<script>alert('XSS')</script>"
	core.UserDB.SAdd(core.Ctx, "users", maliciousUser)
	core.UserDB.HSet(core.Ctx, "user:"+maliciousUser, map[string]interface{}{"username": maliciousUser})

	req := httptest.NewRequest(http.MethodGet, "/rauthmgmt", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("username", "admin")

	err := h.Dashboard(c)
	assert.NoError(t, err)

	output := rec.Body.String()
	// Should be escaped
	assert.False(t, strings.Contains(output, "<script>"), "Output should not contain raw script tag")
	assert.True(t, strings.Contains(output, "&lt;script&gt;"), "Output should contain escaped script tag")
}

type xssMockRenderer struct {
	tmpl *template.Template
}

func (r *xssMockRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return r.tmpl.Execute(w, data)
}