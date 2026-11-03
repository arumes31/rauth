package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"rauth/internal/clusterconfig"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clustertransport"
	"rauth/internal/core"
	"rauth/internal/middleware"
	"strings"
	"testing"
	"time"
)

type testRPCClient func(*http.Request) (*http.Response, error)

func (f testRPCClient) Do(r *http.Request) (*http.Response, error) { return f(r) }
func relayConfig() *core.Config {
	return &core.Config{CookieDomains: []string{"example.com"}, SSOCanonicalOrigin: "https://auth.example.com", TrustedProxies: []string{"10.253.42.2"}, TrustXRealIP: true}
}
func relayWorker(client privateRPCClient) *clusterRuntime {
	return &clusterRuntime{spec: clusterconfig.Config{Role: clusterconfig.Worker, Controller: clusterconfig.Controller{Endpoint: "https://100.72.1.1:9443"}}, relayClient: client, adminRelayClient: client}
}
func TestClusterAdminRelayPreservesBrowserContextAndResponse(t *testing.T) {
	cfg := relayConfig()
	called := 0
	runtime := relayWorker(testRPCClient(func(request *http.Request) (*http.Response, error) {
		called++
		assert.Equal(t, "https://100.72.1.1:9443/v1/admin-relay", request.URL.String())
		assert.Equal(t, http.MethodPost, request.Method)
		assert.Empty(t, request.Header.Get("Cookie"))
		var e adminRelayEnvelope
		require.NoError(t, json.NewDecoder(request.Body).Decode(&e))
		assert.Equal(t, "203.0.113.7", e.Source)
		assert.Equal(t, "auth.example.com", e.Host)
		assert.Equal(t, "/rauthmgmt/user/create", e.Path)
		assert.Equal(t, "view=users", e.Query)
		assert.Equal(t, "csrf=one&username=example", string(e.Body))
		assert.Equal(t, "__Host-csrf=one", e.Headers.Get("Cookie"))
		assert.Equal(t, "https://auth.example.com", e.Headers.Get("Origin"))
		assert.Equal(t, "one", e.Headers.Get("X-CSRF-Token"))
		assert.Empty(t, e.Headers.Get("X-RAuth-User"))
		assert.Empty(t, e.Headers.Get("X-Forwarded-For"))
		return &http.Response{StatusCode: http.StatusSeeOther, Header: http.Header{"Location": []string{"/rauthmgmt"}, "Set-Cookie": []string{"one=1; Secure", "two=2; Secure"}, "Connection": []string{"X-Hop"}, "X-Hop": []string{"drop"}}, Body: io.NopCloser(strings.NewReader("control response"))}, nil
	}))
	e := echo.New()
	e.IPExtractor = CreateIPExtractor(cfg)
	e.Use(runtime.AdminRelay(cfg))
	e.POST("/rauthmgmt/user/create", func(echo.Context) error { t.Fatal("worker must not run local mutation"); return nil })
	req := httptest.NewRequest(http.MethodPost, "https://auth.example.com/rauthmgmt/user/create?view=users", strings.NewReader("csrf=one&username=example"))
	req.RemoteAddr = "10.253.42.2:45000"
	req.Header.Set("X-Real-IP", "203.0.113.7")
	req.Header.Set("X-Forwarded-For", "spoofed")
	req.Header.Set("X-RAuth-User", "spoofed-admin")
	req.Header.Set("Cookie", "__Host-csrf=one")
	req.Header.Set("Origin", "https://auth.example.com")
	req.Header.Set("X-CSRF-Token", "one")
	out := httptest.NewRecorder()
	e.ServeHTTP(out, req)
	assert.Equal(t, 1, called)
	assert.Equal(t, http.StatusSeeOther, out.Code)
	assert.Equal(t, "/rauthmgmt", out.Header().Get("Location"))
	assert.Len(t, out.Header().Values("Set-Cookie"), 2)
	assert.Empty(t, out.Header().Get("X-Hop"))
	assert.Empty(t, out.Header().Get("Connection"))
	assert.Equal(t, "control response", out.Body.String())
}
func TestClusterWorkerRegistersNoLocalAdminMutations(t *testing.T) {
	e := echo.New()
	setupRoutesRole(e, relayConfig(), true)
	for _, route := range e.Routes() {
		assert.False(t, adminNamespace(route.Path), route.Method+" "+route.Path)
	}
	paths := map[string]bool{}
	for _, route := range e.Routes() {
		paths[route.Path] = true
	}
	assert.True(t, paths["/rauthlogin"])
	assert.True(t, paths["/verify-2fa"])
	assert.True(t, paths["/webauthn/login/finish"])
	assert.True(t, paths["/rauthprofile"])
}
func TestClusterAdminRelayRejectsInvalidTargetsBoundsAndUnavailableControl(t *testing.T) {
	cfg := relayConfig()
	called := 0
	runtime := relayWorker(testRPCClient(func(*http.Request) (*http.Response, error) {
		called++
		return nil, errors.New("synthetic-private-database-secret")
	}))
	e := echo.New()
	e.Use(runtime.AdminRelay(cfg))
	e.Any("/rauthmgmt/*", func(echo.Context) error { t.Fatal("local administration must never run"); return nil })
	for _, target := range []string{"https://evil.example/rauthmgmt/user/create", "https://auth.example.com/rauthmgmt/user/../create", "https://auth.example.com/rauthmgmt//user/create"} {
		out := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, target, nil)
		e.ServeHTTP(out, req)
		assert.Equal(t, http.StatusBadRequest, out.Code)
		assert.NotContains(t, out.Body.String(), "private-database-secret")
	}
	assert.Zero(t, called)
	out := httptest.NewRecorder()
	e.ServeHTTP(out, httptest.NewRequest(http.MethodPost, "https://auth.example.com/rauthmgmt/user/create", strings.NewReader(strings.Repeat("x", relayBodyLimit+1))))
	assert.Equal(t, http.StatusRequestEntityTooLarge, out.Code)
	assert.Zero(t, called)
	out = httptest.NewRecorder()
	e.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "https://auth.example.com/rauthmgmt/live-feed", nil))
	assert.Equal(t, http.StatusServiceUnavailable, out.Code)
	assert.Equal(t, 1, called)
	assert.NotContains(t, out.Body.String(), "private-database-secret")
}
func relayGateFixture(t *testing.T, scope clustertransport.Scope, handler http.Handler) http.Handler {
	t.Helper()
	gate, err := clustertransport.NewGate("4378060a-b9ce-446b-9bd6-e4b675f84b1d", func(context.Context, clustertransport.Peer, clustertransport.Scope) error { return nil })
	require.NoError(t, err)
	wrapped, err := gate.Protect(scope, handler)
	require.NoError(t, err)
	return wrapped
}
func relayPrivateRequest(t *testing.T, e adminRelayEnvelope) *http.Request {
	t.Helper()
	body, err := json.Marshal(e)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "https://100.72.1.1:9443/v1/admin-relay", bytes.NewReader(body))
	request.RemoteAddr = "100.72.1.2:45000"
	uri, err := clustertransport.NodeURI("4378060a-b9ce-446b-9bd6-e4b675f84b1d", "8120081d-2a31-419b-9d35-1b74f373b07e")
	require.NoError(t, err)
	// Synthetic post-handshake state composes the gate; transport tests separately
	// cover real private TLS handshakes, pinning and registry revocation.
	leaf := &x509.Certificate{URIs: []*url.URL{uri}, Raw: []byte("synthetic-leaf"), RawSubjectPublicKeyInfo: []byte("synthetic-key"), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	return request
}
func TestClusterAdminReceiverRechecksBrowserAuthAndCSRF(t *testing.T) {
	cfg := relayConfig()
	runtime := &clusterRuntime{publicConfig: cfg}
	public := echo.New()
	public.IPExtractor = CreateIPExtractor(cfg)
	setupCSRFMiddleware(public, cfg)
	mutations := 0
	group := public.Group("/rauthmgmt")
	group.Use(middleware.AuthMiddleware(cfg))
	group.GET("", func(c echo.Context) error { mutations++; return c.NoContent(http.StatusOK) })
	group.POST("/user/create", func(c echo.Context) error { mutations++; return c.NoContent(http.StatusOK) })
	handler := relayGateFixture(t, clustertransport.AdminRelay, runtime.receiveAdminRelay(public))
	envelope := adminRelayEnvelope{Method: http.MethodGet, Host: "auth.example.com", Path: "/rauthmgmt", Source: "203.0.113.9", Headers: http.Header{}}
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, relayPrivateRequest(t, envelope))
	assert.Equal(t, http.StatusFound, out.Code)
	assert.Contains(t, out.Header().Get("Location"), "rd=%2Frauthmgmt")
	assert.Zero(t, mutations, "node enrollment must not act as a browser session")
	envelope.Method = http.MethodPost
	envelope.Path = "/rauthmgmt/user/create"
	envelope.Headers.Set("Cookie", "__Host-csrf=planted")
	envelope.Headers.Set("Content-Type", echo.MIMEApplicationForm)
	envelope.Headers.Set("Origin", "https://evil.example")
	envelope.Headers.Set("Sec-Fetch-Site", "cross-site")
	envelope.Body = []byte("csrf=planted")
	out = httptest.NewRecorder()
	handler.ServeHTTP(out, relayPrivateRequest(t, envelope))
	assert.Equal(t, http.StatusForbidden, out.Code)
	assert.Zero(t, mutations)
	out = httptest.NewRecorder()
	runtime.receiveAdminRelay(public).ServeHTTP(out, relayPrivateRequest(t, envelope))
	assert.Equal(t, http.StatusForbidden, out.Code, "private TLS alone without an exact scope proof is insufficient")
	wrongScope := relayGateFixture(t, clustertransport.PolicyRead, runtime.receiveAdminRelay(public))
	out = httptest.NewRecorder()
	wrongScope.ServeHTTP(out, relayPrivateRequest(t, envelope))
	assert.Equal(t, http.StatusForbidden, out.Code)
}
func TestClusterAdminReceiverReconstructsOnlyCanonicalAdminRequests(t *testing.T) {
	cfg := relayConfig()
	runtime := &clusterRuntime{publicConfig: cfg}
	called := 0
	public := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		assert.Equal(t, "203.0.113.9:0", r.RemoteAddr)
		assert.Equal(t, "auth.example.com", r.Host)
		assert.NotNil(t, r.TLS)
		assert.Equal(t, "/rauthmgmt?view=users", r.RequestURI)
		w.WriteHeader(http.StatusNoContent)
	})
	handler := relayGateFixture(t, clustertransport.AdminRelay, runtime.receiveAdminRelay(public))
	e := adminRelayEnvelope{Method: http.MethodGet, Host: "auth.example.com", Path: "/rauthmgmt", Query: "view=users", Source: "203.0.113.9", Headers: http.Header{}}
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, relayPrivateRequest(t, e))
	assert.Equal(t, http.StatusNoContent, out.Code)
	assert.Equal(t, 1, called)
	for _, change := range []func(*adminRelayEnvelope){func(e *adminRelayEnvelope) { e.Path = "/rauthmgmt/../rauthprofile" }, func(e *adminRelayEnvelope) { e.Host = "other.example" }, func(e *adminRelayEnvelope) { e.Headers = http.Header{"X-Rauth-User": []string{"admin"}} }, func(e *adminRelayEnvelope) { e.Source = "203.0.113.9:1234" }, func(e *adminRelayEnvelope) { e.Query = "bad=%zz" }} {
		altered := e
		change(&altered)
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, relayPrivateRequest(t, altered))
		assert.Equal(t, http.StatusBadRequest, out.Code)
	}
	assert.Equal(t, 1, called)
}
func TestClusterAdminRelayFlushesAnEventBeforeStreamCloses(t *testing.T) {
	runtime := relayWorker(testRPCClient(func(request *http.Request) (*http.Response, error) {
		reader, writer := io.Pipe()
		go func() {
			_, _ = writer.Write([]byte("data: instant-event\n\n"))
			<-request.Context().Done()
			_ = writer.Close()
		}()
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: reader}, nil
	}))
	e := echo.New()
	e.Use(runtime.AdminRelay(relayConfig()))
	server := httptest.NewServer(e)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/rauthmgmt/live-feed", nil)
	require.NoError(t, err)
	request.Host = "auth.example.com"
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	first, err := bufio.NewReader(response.Body).ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "data: instant-event\n", first)
}

type unavailablePolicyPin struct{ calls int }

func (p *unavailablePolicyPin) WithPolicy(func(*core.PolicySnapshot) error) error {
	p.calls++
	return clusterpolicy.ErrNotCurrent
}
func TestClusterAdmissionKeepsLivenessIndependentAndRejectsAuthWithoutPolicy(t *testing.T) {
	cfg := relayConfig()
	pinner := &unavailablePolicyPin{}
	e := echo.New()
	setupMiddlewarePolicy(e, cfg, pinner)
	setupRenderer(e)
	for _, path := range []string{"/health", "/livez", "/metrics", "/static/status", "/rauthvalidate", "/static-looking"} {
		e.GET(path, func(c echo.Context) error { return c.NoContent(http.StatusOK) })
	}
	for _, path := range []string{"/health", "/livez", "/metrics", "/static/status"} {
		out := httptest.NewRecorder()
		e.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "https://auth.example.com"+path, nil))
		assert.Equal(t, http.StatusOK, out.Code)
	}
	assert.Zero(t, pinner.calls)
	for _, path := range []string{"/rauthvalidate", "/static-looking"} {
		out := httptest.NewRecorder()
		e.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "https://auth.example.com"+path, nil))
		assert.Equal(t, http.StatusServiceUnavailable, out.Code)
		assert.Equal(t, "5", out.Header().Get("Retry-After"))
	}
	assert.Equal(t, 2, pinner.calls)
}

func TestClusterBootstrapKeepsLegacyAndRejectsUnsafeOptinBeforeDatabase(t *testing.T) {
	t.Setenv("CLUSTER_CONFIG_FILE", "")
	cfg := core.LoadConfig()
	material, err := loadClusterBootstrap(cfg)
	require.NoError(t, err)
	assert.Nil(t, material)
	t.Setenv("CLUSTER_CONFIG_FILE", "/definitely-missing-rauth-test/node.json")
	cfg = core.LoadConfig()
	require.Equal(t, "/definitely-missing-rauth-test/node.json", cfg.ClusterConfigFile)
	material, err = loadClusterBootstrap(cfg)
	require.Error(t, err)
	assert.Nil(t, material)
}

func TestClusterIPExtractionUsesOnlyFrozenCloudflareRanges(t *testing.T) {
	cfg := relayConfig()
	cfg.ClusterConfigFile = "/private/node.json"
	cfg.TrustCloudflareIP = true
	cfg.TrustXRealIP = false
	cfg.CloudflareIPRanges = []string{"198.51.100.0/24"}
	extract := CreateIPExtractor(cfg)
	request := httptest.NewRequest(http.MethodGet, "https://auth.example.com/rauthvalidate", nil)
	request.RemoteAddr = "10.253.42.2:45000"
	request.Header.Set("X-Real-IP", "198.51.100.22")
	request.Header.Set("CF-Connecting-IP", "203.0.113.7")
	assert.Equal(t, "203.0.113.7", extract(request))
	request.Header.Set("X-Real-IP", "104.16.0.1")
	request.Header.Set("X-Forwarded-For", "104.16.0.1")
	assert.Equal(t, "104.16.0.1", extract(request), "the process-global default must not override the enrolled frozen list")
}

func TestClusterAdminRelayUsesDedicatedClient(t *testing.T) {
	runtime := relayWorker(testRPCClient(func(*http.Request) (*http.Response, error) {
		t.Fatal("ordinary private RPC client used for administration")
		return nil, errors.New("wrong client")
	}))
	runtime.adminRelayClient = testRPCClient(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("dedicated-admin"))}, nil
	})
	e := echo.New()
	e.Use(runtime.AdminRelay(relayConfig()))
	out := httptest.NewRecorder()
	e.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "https://auth.example.com/rauthmgmt/live-feed", nil))
	require.Equal(t, http.StatusOK, out.Code)
	require.Equal(t, "dedicated-admin", out.Body.String())
}
