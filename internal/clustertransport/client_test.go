package clustertransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func endpointClientFixture(t *testing.T, handler http.Handler) (*Client, *httptest.Server, *atomic.Int32) {
	t.Helper()
	ca := newIssuer(t, "endpoint-client")
	serverPair := ca.issue(t, serverID, "endpoint-server", func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("100.64.0.12")} })
	clientPair := ca.issue(t, clientID, "endpoint-client", func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("100.64.0.11")} })
	cfg, err := ServerTLS(serverPair, ca.roots, clusterID, serverID)
	require.NoError(t, err)
	gate, err := NewGate(clusterID, func(context.Context, Peer, Scope) error { return nil })
	require.NoError(t, err)
	gate.requireServiceIP = false
	protected, err := gate.Protect(PolicyRead, handler)
	require.NoError(t, err)
	server := httptest.NewUnstartedServer(protected)
	server.TLS = cfg
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)
	c, err := NewClient(ClientConfig{Endpoint: "https://100.64.0.12:" + port, LocalServiceIP: "100.64.0.11", ClusterID: clusterID, LocalNodeID: clientID, RemoteNodeID: serverID, RemoteKeys: [][32]byte{pin(t, serverPair)}, Certificate: clientPair, Roots: ca.roots})
	require.NoError(t, err)
	t.Cleanup(c.CloseIdleConnections)
	calls := new(atomic.Int32)
	// Test-only TCP mapping: TLS still verifies the enrolled literal IP, node URI
	// and key pin. Production's dialer binds its actual service Tailscale address.
	c.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		calls.Add(1)
		assert.Equal(t, c.endpoint.Host, address)
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	return c, server, calls
}
func TestPrivateClientPinsEndpointAndOverwritesHTTPHost(t *testing.T) {
	c, _, _ := endpointClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Observed-Host", r.Host)
		w.WriteHeader(http.StatusNoContent)
	}))
	assert.Nil(t, c.transport.Proxy, "environment proxy settings must not replace the node service route")
	assert.Nil(t, c.http.Jar, "browser cookies must not persist across private RPCs")
	req, err := http.NewRequest(http.MethodGet, c.endpoint.String()+"/v1/policy", nil)
	require.NoError(t, err)
	req.Host = "untrusted.example.test"
	resp, err := c.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, c.endpoint.Host, resp.Header.Get("X-Observed-Host"))
}
func TestPrivateClientRejectsAlternateURLsBeforeDialing(t *testing.T) {
	c, _, calls := endpointClientFixture(t, http.NotFoundHandler())
	for _, target := range []string{"http://" + c.endpoint.Host + "/v1/policy", "https://public.example.test/v1/policy", c.endpoint.String() + "/v1/../admin-relay", c.endpoint.String() + "/v1/policy?token=secret", c.endpoint.String() + "/v1/policy?", c.endpoint.String() + "/v1/policy#fragment", c.endpoint.String() + "/%76%31/policy", c.endpoint.String() + "//v1/policy", c.endpoint.String() + "/v1/space%20here"} {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		require.NoError(t, err)
		_, err = c.Do(req)
		require.ErrorIs(t, err, ErrConfiguration, target)
	}
	assert.Zero(t, calls.Load())
}
func TestPrivateClientNeverFollowsRedirects(t *testing.T) {
	c, _, calls := endpointClientFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://public.example.test/steal", http.StatusFound)
	}))
	req, err := http.NewRequest(http.MethodPost, c.endpoint.String()+"/v1/policy", strings.NewReader("private-body"))
	require.NoError(t, err)
	response, err := c.Do(req)
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, http.StatusFound, response.StatusCode)
	assert.Equal(t, "http://public.example.test/steal", response.Header.Get("Location"))
	assert.EqualValues(t, 1, calls.Load(), "the response must be returned without following its Location")
	if response != nil {
		_ = response.Body.Close()
	}
}
func TestPrivateClientRejectsUnenrolledSourceAndWrongLocalCertificateIP(t *testing.T) {
	ca := newIssuer(t, "config")
	server := ca.issue(t, serverID, "s", nil)
	client := ca.issue(t, clientID, "c", nil)
	base := ClientConfig{Endpoint: "https://100.64.0.12:9443", LocalServiceIP: "100.64.0.11", ClusterID: clusterID, LocalNodeID: clientID, RemoteNodeID: serverID, RemoteKeys: [][32]byte{pin(t, server)}, Certificate: client, Roots: ca.roots}
	_, err := NewClient(base)
	require.ErrorIs(t, err, ErrConfiguration, "certificate must cover its own service IP")
	client = ca.issue(t, clientID, "c-with-ip", func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("100.64.0.11")} })
	base.Certificate = client
	c, err := NewClient(base)
	require.NoError(t, err)
	c.CloseIdleConnections()
	for _, change := range []func(*ClientConfig){func(c *ClientConfig) { c.LocalServiceIP = "127.0.0.1" }, func(c *ClientConfig) { c.Endpoint = "https://127.0.0.1:9443" }, func(c *ClientConfig) { c.Timeout = 10 * time.Minute }, func(c *ClientConfig) { c.Timeout = time.Millisecond }} {
		copy := base
		change(&copy)
		_, err := NewClient(copy)
		require.ErrorIs(t, err, ErrConfiguration)
	}
}
func TestPrivateClientKeyPinsAreDefensivelyCopied(t *testing.T) {
	ca, server, client, _, httpServer, _ := tlsFixture(t, func(context.Context, Peer, Scope) error { return nil })
	pins := [][32]byte{pin(t, server)}
	cfg, err := ClientTLS(client, ca.roots, "node.example.test", clusterID, clientID, serverID, pins)
	require.NoError(t, err)
	pins[0][0] ^= 0xff
	tr := &http.Transport{TLSClientConfig: cfg}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	status, _, _ := get(t, c, httpServer.URL)
	assert.Equal(t, http.StatusNoContent, status)
}
func TestTLS12IsNotAccepted(t *testing.T) {
	ca, _, client, _, server, _ := tlsFixture(t, func(context.Context, Peer, Scope) error { return nil })
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, RootCAs: ca.roots, ServerName: "node.example.test", Certificates: []tls.Certificate{client}}}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	_, err := c.Get(server.URL)
	require.Error(t, err)
}
