package handlers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"rauth/internal/clusterpolicy"
	"rauth/internal/core"
	"rauth/internal/middleware"
	"strings"
	"testing"
	"time"
)

type handlerPolicyPin struct {
	snapshot   *core.PolicySnapshot
	err        error
	closeAfter bool
}

func (p *handlerPolicyPin) WithPolicy(use func(*core.PolicySnapshot) error) error {
	if p.err != nil {
		return p.err
	}
	err := use(p.snapshot)
	if p.closeAfter {
		_ = p.snapshot.Close()
	}
	return err
}
func handlerSnapshot(t *testing.T) *core.PolicySnapshot {
	t.Helper()
	node := "8dfce137-b989-4228-b737-600b99b44835"
	cluster := "1c721287-eab7-490b-8ec0-f511227fd4c5"
	feed := "86bd2ae7-a61e-4681-be33-65df5fbc6b89"
	fingerprint := strings.Repeat("a", 64)
	doc := core.WorkerPolicyDocument{Schema: 1, NodeProfiles: map[string]string{node: fingerprint}, Rules: []core.WorkerPolicyRule{{Rule: "cloud.example.test", Action: core.BypassAllow, Source: "ui", Policy: core.RulePolicy{BlockedFeedIDs: []string{feed}}}, {Rule: "private.example.test", Action: core.BypassDeny, Source: "ui"}}, Feeds: []core.WorkerPolicyFeed{{ID: feed, Version: 1}}}
	policy, err := json.Marshal(doc)
	require.NoError(t, err)
	body := []byte("203.0.113.42/32")
	blob := func(kind, id string, data []byte) clusterpolicy.Blob {
		sum := sha256.Sum256(data)
		return clusterpolicy.Blob{Kind: kind, ID: id, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(data))}
	}
	blobs := []clusterpolicy.Blob{blob("policy", "policy", policy), blob("feed", feed, body)}
	bodies := map[string][]byte{blobs[0].SHA256: policy, blobs[1].SHA256: body}
	seed := sha256.Sum256([]byte("synthetic-handler-policy-key"))
	key := ed25519.NewKeyFromSeed(seed[:])
	v, err := clusterpolicy.NewVerifier(cluster, map[string]ed25519.PublicKey{"v1": key.Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	raw, err := clusterpolicy.Sign(clusterpolicy.Manifest{Schema: 1, ClusterID: cluster, Revision: 1, PublishedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Blobs: blobs}, "v1", key)
	require.NoError(t, err)
	head, err := v.Verify(raw)
	require.NoError(t, err)
	compiler, err := core.NewWorkerPolicyCompiler(core.WorkerPolicyOptions{NodeID: node, SecurityFingerprint: fingerprint})
	require.NoError(t, err)
	defer func() { _ = compiler.Close() }()
	bundle, err := clusterpolicy.VerifyBundle(head, func(b clusterpolicy.Blob) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodies[b.SHA256])), nil
	}, func(b clusterpolicy.Blob, r io.Reader) error { return compiler.Validate(context.Background(), b, r) })
	require.NoError(t, err)
	snapshot, err := compiler.Finish(context.Background(), bundle)
	require.NoError(t, err)
	t.Cleanup(func() { _ = snapshot.Close() })
	return snapshot
}
func TestPinnedWorkerPolicyHTTPValidationAndFeed(t *testing.T) {
	setupHandlersTest(t)
	snapshot := handlerSnapshot(t)
	cfg := bypassTestConfig()
	cfg.TrustedProxies = []string{"10.0.0.1"}
	core.SetEnvBypassRules(nil)
	t.Cleanup(func() { core.SetEnvBypassRules(nil) })
	oldFeed := core.LiveRequests
	core.LiveRequests = core.NewRequestFeed(30)
	t.Cleanup(func() { core.LiveRequests = oldFeed })
	pin := &handlerPolicyPin{snapshot: snapshot}
	handler := &AuthHandler{Cfg: cfg}
	e := echo.New()
	e.IPExtractor = func(r *http.Request) string { return r.Header.Get("X-Synthetic-Client") }
	e.Use(middleware.RequestFeed(cfg))
	e.Use(middleware.WorkerPolicyAdmission(cfg, pin))
	e.GET("/rauthvalidate", handler.Validate)
	request := func(ip, host, uri string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
		r.RemoteAddr = "10.0.0.1:1234"
		r.Header.Set("X-Synthetic-Client", ip)
		r.Header.Set("X-Forwarded-Host", host)
		r.Header.Set("X-Forwarded-Uri", uri)
		r.Header.Set("X-Forwarded-Proto", "https")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		e.ServeHTTP(response, r)
		_, escaped := core.PolicySnapshotFromContext(r.Context())
		assert.False(t, escaped)
		return response
	}
	anonymous := request("203.0.113.43", "cloud.example.test", "/remote.php/dav/files/a/file;name?x=a&b=c", nil)
	assert.Equal(t, 200, anonymous.Code)
	assert.Equal(t, "1", anonymous.Header().Get("X-RAuth-Anonymous"))
	blocked := request("203.0.113.42", "cloud.example.test", "/", nil)
	assert.Equal(t, 403, blocked.Code)
	assert.Empty(t, blocked.Header().Get("X-RAuth-Anonymous"))
	private := request("203.0.113.43", "private.example.test", "/", nil)
	assert.Equal(t, 401, private.Code)
	seedAccount(t, "pinned-user")
	token := "pinned-valid-token"
	encrypted, err := core.EncryptToken(token, cfg.ServerSecret)
	require.NoError(t, err)
	require.NoError(t, core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken="+token, map[string]interface{}{"status": "valid", "username": "pinned-user", "ip": "203.0.113.42", "country": "unknown"}).Err())
	authenticatedBlocked := request("203.0.113.42", "cloud.example.test", "/", &http.Cookie{Name: cfg.SessionCookieName(), Value: encrypted})
	assert.Equal(t, 403, authenticatedBlocked.Code, "a session cannot bypass the pinned feed")
	pin.err = errors.New("private backend diagnosis must not be in response")
	unavailable := request("203.0.113.43", "cloud.example.test", "/", nil)
	assert.Equal(t, 503, unavailable.Code)
	assert.Equal(t, "5", unavailable.Header().Get("Retry-After"))
	assert.NotContains(t, unavailable.Body.String(), "private backend diagnosis")
	assert.Empty(t, unavailable.Header().Get("X-RAuth-Anonymous"))
	events := core.LiveRequests.After(0).Events
	require.Len(t, events, 5)
	assert.Equal(t, "bypass", events[0].Action)
	assert.Equal(t, "https://cloud.example.test/remote.php/dav/files/a/file;name", events[0].URL)
	assert.Equal(t, "blocked", events[1].Action)
	assert.Equal(t, "login_required", events[2].Action)
	assert.Equal(t, "error", events[4].Action)
	assert.Equal(t, "policy_unavailable", events[4].Reason)
}
func TestWorkerAdmissionPreservesInnerErrorAndPinnedTelemetryAfterRelease(t *testing.T) {
	snapshot := handlerSnapshot(t)
	cfg := bypassTestConfig()
	cfg.TrustedProxies = []string{"10.0.0.1"}
	oldFeed := core.LiveRequests
	core.LiveRequests = core.NewRequestFeed(5)
	t.Cleanup(func() { core.LiveRequests = oldFeed })
	core.GeoCache.Put("203.0.113.43", "DE")
	pin := &handlerPolicyPin{snapshot: snapshot, closeAfter: true}
	e := echo.New()
	e.IPExtractor = func(*http.Request) string { return "203.0.113.43" }
	e.Use(middleware.RequestFeed(cfg))
	e.Use(middleware.WorkerPolicyAdmission(cfg, pin))
	e.GET("/rauthvalidate", func(c echo.Context) error {
		active, ok := core.PolicySnapshotFromContext(c.Request().Context())
		require.True(t, ok)
		require.Same(t, snapshot, active)
		assert.Equal(t, "unknown", core.CountryCodeForContext(c.Request().Context(), "203.0.113.43"))
		return echo.NewHTTPError(http.StatusForbidden, "original handler refusal")
	})
	req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	response := httptest.NewRecorder()
	e.ServeHTTP(response, req)
	assert.Equal(t, 403, response.Code)
	assert.Contains(t, response.Body.String(), "original handler refusal")
	events := core.LiveRequests.After(0).Events
	require.Len(t, events, 1)
	assert.Equal(t, "unknown", events[0].Country, "captured country must not fall back to another global generation after the pin releases")
}
