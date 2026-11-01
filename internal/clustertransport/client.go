package clustertransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

type ClientConfig struct {
	Endpoint       string
	LocalServiceIP string
	ClusterID      string
	LocalNodeID    string
	RemoteNodeID   string
	RemoteKeys     [][32]byte
	Certificate    tls.Certificate
	Roots          *x509.CertPool
	Timeout        time.Duration
}
type Client struct {
	endpoint  *url.URL
	http      *http.Client
	transport *http.Transport
}

// NewClient pins destination and source service identities. An environment
// proxy, redirect, alternate URL or host-daemon route cannot replace them.
// Dialing fails if LocalServiceIP is absent from the dedicated node namespace.
func NewClient(cfg ClientConfig) (*Client, error) {
	endpoint, err := PrivateEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	local, err := netip.ParseAddr(cfg.LocalServiceIP)
	if err != nil || !serviceIP(local) {
		return nil, ErrConfiguration
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	if timeout < time.Second || timeout > 120*time.Second {
		return nil, ErrConfiguration
	}
	leaf, err := certificateLeaf(cfg.Certificate)
	if err != nil || leaf.VerifyHostname(local.String()) != nil {
		return nil, ErrConfiguration
	}
	secure, err := ClientTLS(cfg.Certificate, cfg.Roots, endpoint.Hostname(), cfg.ClusterID, cfg.LocalNodeID, cfg.RemoteNodeID, cfg.RemoteKeys)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(local.AsSlice())}}
	destination := endpoint.Host
	// Enforce the enrolled socket destination independently of URL validation.
	// This also protects future callers/changes from an accidental alternate URL.
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != destination {
			return nil, ErrConfiguration
		}
		return dialer.DialContext(ctx, network, address)
	}
	tr := &http.Transport{Proxy: nil, DialContext: dial, TLSClientConfig: secure, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 90 * time.Second, MaxConnsPerHost: 8, MaxIdleConns: 8, MaxIdleConnsPerHost: 4, DisableCompression: true}
	c := &Client{endpoint: endpoint, transport: tr}
	c.http = &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c, nil
}

// Do permits only this enrolled endpoint. Private RPC parameters belong in a
// bounded body or validated path, never query credentials. Host is overwritten
// and no implicit cookie jar is installed. The caller owns response.Body.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if c == nil || c.http == nil || req == nil || req.URL == nil {
		return nil, ErrConfiguration
	}
	u := req.URL
	if u.Scheme != c.endpoint.Scheme || u.Host != c.endpoint.Host || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || !safeRPCPath(u.Path) || req.RequestURI != "" {
		return nil, ErrConfiguration
	}
	outgoing := req.Clone(req.Context())
	// Rebuild the URL from our owned enrollment, never carry the caller's URL
	// object through to the transport after validation.
	outgoing.URL = &url.URL{Scheme: c.endpoint.Scheme, Host: c.endpoint.Host, Path: u.Path}
	outgoing.Host = c.endpoint.Host
	// #nosec G704 -- Only the validated RPC path is caller-controlled. URL host/scheme are rebuilt from enrollment, the dialer independently pins the literal socket destination, and proxies/redirects are disabled.
	return c.http.Do(outgoing)
}
func (c *Client) CloseIdleConnections() {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

func safeRPCPath(raw string) bool {
	if len(raw) > 2048 || raw == "" || path.Clean(raw) != raw {
		return false
	}
	for _, c := range raw {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '/' && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}
