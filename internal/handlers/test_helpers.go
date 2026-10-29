package handlers

import (
	"io"
	"net/http/httptest"
	"net/url"
	"rauth/internal/core"
	"rauth/internal/pgtest"
	"strings"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

var (
	globalTestMu    sync.Mutex
	sharedMiniredis *miniredis.Miniredis
)

func setupHandlersTest(t *testing.T) {
	globalTestMu.Lock()
	if sharedMiniredis == nil {
		// The cost-12 dummy hash makes brute-force tests (~130 failed logins)
		// exceed the 10m test timeout under -race; use MinCost in tests.
		cheapHash, err := bcrypt.GenerateFromPassword([]byte("test-dummy"), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("failed to generate test dummy hash: %v", err)
		}
		dummyBcryptHash = string(cheapHash)
		s, err := miniredis.Run()
		if err != nil {
			t.Fatalf("failed to run miniredis: %v", err)
		}
		sharedMiniredis = s
	}

	client := redis.NewClient(&redis.Options{Addr: sharedMiniredis.Addr()})
	core.TokenDB = client
	core.RateLimitDB = client
	core.InviteDB = client

	// Clean slate for each test
	sharedMiniredis.FlushAll()
	core.PG = pgtest.Open(t, core.Migrate)
	pgtest.Reset(t, core.PG)

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

// mustGen returns the user's current auth generation.
func mustGen(t *testing.T, username string) string {
	t.Helper()
	gen, err := core.AuthGeneration(username)
	if err != nil {
		t.Fatalf("auth generation of %s: %v", username, err)
	}
	return gen
}

// seedAccount creates a minimal user record so sessions issued for username
// pass core.SessionAuthorized (which rejects sessions of non-existent accounts).
func seedAccount(t *testing.T, username string) {
	t.Helper()
	if err := core.PutUser(core.User{Username: username}); err != nil {
		t.Fatalf("seed account %s: %v", username, err)
	}
}
