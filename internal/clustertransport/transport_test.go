package clustertransport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const clusterID = "39d94e78-8844-4f10-9c5c-943a4d17e62f"
const serverID = "d5c79e2a-191b-429c-8d22-1fe5c06fa378"
const clientID = "7f64761a-1869-4c0b-a50f-a25823741583"
const otherID = "26585ff5-081d-4ddb-b393-af2dd6f4c966"

type issuer struct {
	cert   *x509.Certificate
	key    ed25519.PrivateKey
	roots  *x509.CertPool
	serial int64
}

func key(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("synthetic-node-transport-" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}
func newIssuer(t *testing.T, name string) *issuer {
	t.Helper()
	private := key("ca-" + name)
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only-private-ca-" + name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, private.Public(), private)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return &issuer{cert: parsed, key: private, roots: roots, serial: 1}
}
func (i *issuer) issue(t *testing.T, node, name string, change func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	i.serial++
	private := key(name)
	uri, err := NodeURI(clusterID, node)
	require.NoError(t, err)
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(i.serial), Subject: pkix.Name{CommonName: "ignored-cn-" + name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}, DNSNames: []string{"node.example.test"}}
	if change != nil {
		change(cert)
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, i.cert, private.Public(), i.key)
	require.NoError(t, err)
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	require.NoError(t, err)
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	require.NoError(t, err)
	return pair
}
func pin(t *testing.T, pair tls.Certificate) [32]byte {
	t.Helper()
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	require.NoError(t, err)
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}
func tlsFixture(t *testing.T, auth Authorizer, configure ...func(*Gate)) (*issuer, tls.Certificate, tls.Certificate, *Gate, *httptest.Server, *http.Client) {
	t.Helper()
	ca := newIssuer(t, "main")
	server := ca.issue(t, serverID, "server", nil)
	client := ca.issue(t, clientID, "client", nil)
	cfg, err := ServerTLS(server, ca.roots, clusterID, serverID)
	require.NoError(t, err)
	gate, err := NewGate(clusterID, auth)
	require.NoError(t, err)
	gate.requireServiceIP = false // Real TLS over loopback in this fixture only.
	for _, option := range configure {
		option(gate)
	}
	handler, err := gate.Protect(PolicyRead, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := PeerForScope(r.Context(), PolicyRead)
		if !ok {
			http.Error(w, "missing verified peer", http.StatusForbidden)
			return
		}
		if _, wrong := PeerForScope(r.Context(), AdminRelay); wrong {
			http.Error(w, "scope confused", http.StatusInternalServerError)
			return
		}
		w.Header().Set("X-Test-Node", peer.NodeID)
		w.Header().Set("X-Test-Connection", r.RemoteAddr)
		w.WriteHeader(http.StatusNoContent)
	}))
	require.NoError(t, err)
	serverHTTP := httptest.NewUnstartedServer(handler)
	serverHTTP.TLS = cfg
	serverHTTP.Config.ErrorLog = log.New(io.Discard, "", 0)
	serverHTTP.StartTLS()
	t.Cleanup(serverHTTP.Close)
	clientConfig, err := ClientTLS(client, ca.roots, "node.example.test", clusterID, clientID, serverID, [][32]byte{pin(t, server)})
	require.NoError(t, err)
	transport := &http.Transport{TLSClientConfig: clientConfig, TLSHandshakeTimeout: 2 * time.Second, IdleConnTimeout: time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	return ca, server, client, gate, serverHTTP, &http.Client{Transport: transport, Timeout: 4 * time.Second}
}
func get(t *testing.T, client *http.Client, address string) (int, http.Header, string) {
	t.Helper()
	r, err := client.Get(address)
	require.NoError(t, err)
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	return r.StatusCode, r.Header, string(body)
}
func TestMutualTLSIdentityAndScopeIgnoreSubmittedHeaders(t *testing.T) {
	var calls atomic.Int32
	_, _, _, _, server, client := tlsFixture(t, func(ctx context.Context, peer Peer, scope Scope) error {
		calls.Add(1)
		assert.Equal(t, clientID, peer.NodeID)
		assert.Equal(t, clusterID, peer.ClusterID)
		assert.Equal(t, PolicyRead, scope)
		assert.Equal(t, netip.MustParseAddr("127.0.0.1"), peer.ServiceIP)
		return nil
	})
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Node-ID", otherID)
	req.Header.Set("X-Node-Scope", string(AdminRelay))
	req.Header.Set("Cookie", "__Host-rauth-auth=browser-cookie")
	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, res.StatusCode)
	assert.Equal(t, clientID, res.Header.Get("X-Test-Node"))
	assert.EqualValues(t, 1, calls.Load())
}
func TestRevocationIsCheckedOnReusedTLSConnections(t *testing.T) {
	var revoked atomic.Bool
	var calls atomic.Int32
	_, _, _, _, server, client := tlsFixture(t, func(_ context.Context, _ Peer, _ Scope) error {
		calls.Add(1)
		if revoked.Load() {
			return ErrDenied
		}
		return nil
	})
	status, firstHeaders, _ := get(t, client, server.URL)
	assert.Equal(t, http.StatusNoContent, status)
	revoked.Store(true)
	var reused atomic.Bool
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) }}), http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	status, deniedHeaders, body := resp.StatusCode, resp.Header, string(bodyBytes)
	assert.True(t, reused.Load(), "revocation must apply without a new TLS handshake")
	assert.Equal(t, http.StatusForbidden, status)
	assert.NotContains(t, body, "node")
	assert.EqualValues(t, 2, calls.Load())
	assert.NotEmpty(t, firstHeaders.Get("X-Test-Connection"))
	assert.Empty(t, deniedHeaders.Get("X-Test-Node"))
}
func TestPermissionBackendOutageFailsClosedWithoutDisclosingCause(t *testing.T) {
	_, _, _, _, server, client := tlsFixture(t, func(context.Context, Peer, Scope) error {
		return errors.New("private diagnostic which must not reach the client")
	})
	status, headers, body := get(t, client, server.URL)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "5", headers.Get("Retry-After"))
	assert.NotContains(t, body, "diagnostic")
}
func TestPlainHTTPAndNonServicePeersCannotUseThePrivateGate(t *testing.T) {
	var calls atomic.Int32
	ca, _, clientCert, gate, server, client := tlsFixture(t, func(context.Context, Peer, Scope) error { calls.Add(1); return nil })
	handler, err := gate.Protect(PolicyRead, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "http://private.invalid/", nil)
	req.Header.Set("X-Client-Certificate", "pretend-client-cert")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Zero(t, calls.Load())
	strict, err := NewGate(clusterID, func(context.Context, Peer, Scope) error { calls.Add(1); return nil })
	require.NoError(t, err)
	strictHandler, err := strict.Protect(PolicyRead, http.NotFoundHandler())
	require.NoError(t, err)
	leaf, err := certificateLeaf(clientCert)
	require.NoError(t, err)
	req = httptest.NewRequest(http.MethodGet, "https://private.invalid/", nil)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, ca.cert}}}
	req.RemoteAddr = "127.0.0.1:49152"
	rec = httptest.NewRecorder()
	strictHandler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Zero(t, calls.Load())
	_ = client
	// A browser session cookie cannot substitute for mutual TLS.
	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.roots, ServerName: "node.example.test"}}, Timeout: 3 * time.Second}
	defer noCert.CloseIdleConnections()
	_, err = noCert.Get(server.URL)
	require.Error(t, err)
	// The client helper rejects another node's local certificate/config pairing.
	_, err = ClientTLS(clientCert, ca.roots, "node.example.test", clusterID, otherID, serverID, [][32]byte{pin(t, clientCert)})
	require.ErrorIs(t, err, ErrConfiguration)
}
func TestClientRejectsWrongCAHostnameNodeOrPublicKey(t *testing.T) {
	ca, serverCert, clientCert, _, server, _ := tlsFixture(t, func(context.Context, Peer, Scope) error { return nil })
	foreign := newIssuer(t, "foreign")
	for _, mode := range []string{"wrong-ca", "wrong-host", "wrong-node", "wrong-pin"} {
		t.Run(mode, func(t *testing.T) {
			roots := ca.roots
			host := "node.example.test"
			node := serverID
			pins := [][32]byte{pin(t, serverCert)}
			switch mode {
			case "wrong-ca":
				roots = foreign.roots
			case "wrong-host":
				host = "other.example.test"
			case "wrong-node":
				node = otherID
			case "wrong-pin":
				pins = [][32]byte{pin(t, clientCert)}
			}
			cfg, err := ClientTLS(clientCert, ca.roots, host, clusterID, clientID, node, pins)
			require.NoError(t, err)
			cfg.RootCAs = roots
			tr := &http.Transport{TLSClientConfig: cfg, TLSHandshakeTimeout: 2 * time.Second}
			defer tr.CloseIdleConnections()
			c := &http.Client{Transport: tr, Timeout: 3 * time.Second}
			_, err = c.Get(server.URL)
			require.Error(t, err)
		})
	}
}
func TestNodeIdentityHasNoCommonNameOrMalformedURIFallback(t *testing.T) {
	ca := newIssuer(t, "identity")
	for _, mode := range []string{"common-name-only", "wrong-cluster", "multiple-uri", "query", "encoded-path", "expired", "future"} {
		t.Run(mode, func(t *testing.T) {
			pair := ca.issue(t, clientID, mode, func(c *x509.Certificate) {
				switch mode {
				case "common-name-only":
					c.Subject.CommonName = clientID
					c.URIs = nil
				case "wrong-cluster":
					u, _ := NodeURI(otherID, clientID)
					c.URIs = []*url.URL{u}
				case "multiple-uri":
					c.URIs = append(c.URIs, c.URIs[0])
				case "query":
					u := *c.URIs[0]
					u.RawQuery = "role=admin"
					c.URIs = []*url.URL{&u}
				case "encoded-path":
					u := *c.URIs[0]
					u.RawPath = strings.Replace(u.Path, "node", "%6eode", 1)
					c.URIs = []*url.URL{&u}
				case "expired":
					c.NotAfter = time.Now().Add(-time.Second)
				case "future":
					c.NotBefore = time.Now().Add(time.Minute)
				}
			})
			leaf, err := certificateLeaf(pair)
			require.NoError(t, err)
			_, err = identity(leaf, clusterID, time.Now())
			require.ErrorIs(t, err, ErrIdentity)
		})
	}
}
func TestCertificateExpiryIsRecheckedAfterHandshake(t *testing.T) {
	var advance atomic.Int64
	_, _, _, _, server, client := tlsFixture(t, func(context.Context, Peer, Scope) error { return nil }, func(g *Gate) { g.now = func() time.Time { return time.Now().Add(time.Duration(advance.Load())) } })
	status, _, _ := get(t, client, server.URL)
	assert.Equal(t, http.StatusNoContent, status)
	advance.Store(int64(2 * time.Hour))
	status, _, _ = get(t, client, server.URL)
	assert.Equal(t, http.StatusForbidden, status)
}
func TestEndpointAndScopeValidation(t *testing.T) {
	for _, s := range []string{"https://100.64.0.1:9443", "https://[fd7a:115c:a1e0::1]:9443"} {
		u, err := PrivateEndpoint(s)
		require.NoError(t, err)
		_, err = PrivateListenAddress(u.Host)
		require.NoError(t, err)
	}
	for _, s := range []string{"http://100.64.0.1:9443", "https://127.0.0.1:9443", "https://0.0.0.0:9443", "https://10.0.0.1:9443", "https://8.8.8.8:9443", "https://[::]:9443", "https://[::ffff:100.64.0.1]:9443", "https://100.64.0.1:9443/", "https://100.64.0.1:9443?", "https://u@100.64.0.1:9443", "https://100.64.0.1:0", "https://100.64.0.1:09443", "https://public.example.com:9443"} {
		_, err := PrivateEndpoint(s)
		require.ErrorIs(t, err, ErrConfiguration, s)
	}
	_, err := NewGate(clusterID, nil)
	require.ErrorIs(t, err, ErrConfiguration)
	gate, err := NewGate(clusterID, func(context.Context, Peer, Scope) error { return nil })
	require.NoError(t, err)
	_, err = gate.Protect(Scope("*"), http.NotFoundHandler())
	require.ErrorIs(t, err, ErrConfiguration)
	_, ok := PeerForScope(context.Background(), PolicyRead)
	assert.False(t, ok)
}

func TestMutualTLSIncludesSuppliedIntermediateChain(t *testing.T) {
	root := newIssuer(t, "root-for-intermediate")
	private := key("intermediate-ca")
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic-intermediate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, root.cert, private.Public(), root.key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	intermediate := &issuer{cert: parsed, key: private, roots: root.roots, serial: 2}
	server := intermediate.issue(t, serverID, "server-with-intermediate", nil)
	client := intermediate.issue(t, clientID, "client-with-intermediate", nil)
	_, err = ServerTLS(server, root.roots, clusterID, serverID)
	require.ErrorIs(t, err, ErrConfiguration, "missing intermediate cannot validate")
	_, err = ClientTLS(client, root.roots, "node.example.test", clusterID, clientID, serverID, [][32]byte{pin(t, server)})
	require.ErrorIs(t, err, ErrConfiguration)
	server.Certificate = append(server.Certificate, der)
	client.Certificate = append(client.Certificate, der)
	serverConfig, err := ServerTLS(server, root.roots, clusterID, serverID)
	require.NoError(t, err)
	clientConfig, err := ClientTLS(client, root.roots, "node.example.test", clusterID, clientID, serverID, [][32]byte{pin(t, server)})
	require.NoError(t, err)
	endpoint := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	endpoint.TLS = serverConfig
	endpoint.StartTLS()
	defer endpoint.Close()
	transport := &http.Transport{TLSClientConfig: clientConfig}
	defer transport.CloseIdleConnections()
	status, _, _ := get(t, &http.Client{Transport: transport, Timeout: 3 * time.Second}, endpoint.URL)
	assert.Equal(t, http.StatusNoContent, status)
	malformed := server
	malformed.Certificate = [][]byte{server.Certificate[0], []byte("invalid DER")}
	_, err = ServerTLS(malformed, root.roots, clusterID, serverID)
	require.ErrorIs(t, err, ErrConfiguration)
	unrelated := newIssuer(t, "unrelated-root")
	_, err = ServerTLS(server, unrelated.roots, clusterID, serverID)
	require.ErrorIs(t, err, ErrConfiguration, "intermediates do not replace explicit root trust")
}
