package handlers

import (
	"io"
	"net/http/httptest"
	"net/url"
	"rauth/internal/core"
	"strings"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

var (
	globalTestMu sync.Mutex
	sharedMiniredis *miniredis.Miniredis
)

func setupHandlersTest(t *testing.T) {
	globalTestMu.Lock()
	if sharedMiniredis == nil {
		s, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to run miniredis: %v", err)
		}
		sharedMiniredis = s
	}
	
	client := redis.NewClient(&redis.Options{Addr: sharedMiniredis.Addr()})
	core.TokenDB = client
	core.UserDB = client
	core.AuditDB = client
	core.RateLimitDB = client
	
	// Clean slate for each test
	sharedMiniredis.FlushAll()
	
	t.Cleanup(func() {
		globalTestMu.Unlock()
	})
}

func createTestContext(e *echo.Echo, method, path string, f url.Values) (echo.Context, *httptest.ResponseRecorder) {
	var body io.Reader
	if f != nil {
		body = strings.NewReader(f.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if f != nil {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		// Explicitly parse or set Form/PostForm for Echo
		req.Form = f
		req.PostForm = f
	}
	// Default RemoteAddr for testing
	req.RemoteAddr = "127.0.0.1:1234"
	
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

type mockRenderer struct {
	LastData interface{}
}

func (r *mockRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	r.LastData = data
	return nil
}
