package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"github.com/labstack/echo/v4"
	"golang.org/x/net/http/httpguts"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"rauth/internal/clusterconfig"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clustertransport"
	"rauth/internal/core"
	"strings"
)

const relayBodyLimit = 1 << 20

var relayHeaderNames = map[string]bool{"Accept": true, "Accept-Language": true, "Content-Type": true, "Cookie": true, "Origin": true, "Referer": true, "Sec-Fetch-Site": true, "Sec-Fetch-Mode": true, "Sec-Fetch-Dest": true, "X-Csrf-Token": true, "User-Agent": true, "Last-Event-Id": true}

type adminRelayEnvelope struct {
	Method  string      `json:"method"`
	Host    string      `json:"host"`
	Path    string      `json:"path"`
	Query   string      `json:"query"`
	Source  string      `json:"source"`
	Headers http.Header `json:"headers"`
	Body    []byte      `json:"body"`
}

func adminNamespace(raw string) bool {
	return raw == "/rauthmgmt" || strings.HasPrefix(raw, "/rauthmgmt/")
}
func adminPath(raw string) bool {
	for _, c := range raw {
		if c == 92 || c == 0 || c == 13 || c == 10 {
			return false
		}
	}
	return adminNamespace(raw) && path.Clean(raw) == raw
}
func canonicalAdminHost(cfg *core.Config, host string) bool {
	canonical, err := url.Parse(cfg.SSOCanonicalOrigin)
	return err == nil && canonical.Scheme == "https" && canonical.Host != "" && strings.EqualFold(host, canonical.Host)
}
func validRelayEnvelope(cfg *core.Config, e adminRelayEnvelope) bool {
	if (e.Method != http.MethodGet && e.Method != http.MethodPost && e.Method != http.MethodHead) || !adminPath(e.Path) || !canonicalAdminHost(cfg, e.Host) || len(e.Path) > 2048 || len(e.Query) > 8192 || len(e.Body) > relayBodyLimit {
		return false
	}
	if _, err := url.ParseQuery(e.Query); err != nil {
		return false
	}
	ip, err := netip.ParseAddr(e.Source)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || ip.String() != e.Source {
		return false
	}
	size := 0
	for name, values := range e.Headers {
		if http.CanonicalHeaderKey(name) != name || !relayHeaderNames[name] {
			return false
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return false
			}
			size += len(name) + len(value)
		}
	}
	return size <= 32<<10
}
func (r *clusterRuntime) AdminRelay(cfg *core.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if r.spec.Role != clusterconfig.Worker || !adminNamespace(c.Request().URL.Path) {
				return next(c)
			}
			if r.relayClient == nil {
				return echo.NewHTTPError(http.StatusServiceUnavailable, "Administration is temporarily unavailable")
			}
			request := c.Request()
			if !adminPath(request.URL.Path) {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid administration request")
			}
			if request.Body == nil {
				request.Body = http.NoBody
			}
			body, err := io.ReadAll(http.MaxBytesReader(c.Response(), request.Body, relayBodyLimit))
			if err != nil {
				return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Request too large")
			}
			headers := http.Header{}
			for name, values := range request.Header {
				canonical := http.CanonicalHeaderKey(name)
				if relayHeaderNames[canonical] {
					headers[canonical] = append([]string(nil), values...)
				}
			}
			e := adminRelayEnvelope{Method: request.Method, Host: request.Host, Path: request.URL.Path, Query: request.URL.RawQuery, Source: c.RealIP(), Headers: headers, Body: body}
			if !validRelayEnvelope(cfg, e) {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid administration request")
			}
			payload, err := json.Marshal(e)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, "Invalid administration request")
			}
			upstream, err := http.NewRequestWithContext(request.Context(), http.MethodPost, r.spec.Controller.Endpoint+"/v1/admin-relay", bytes.NewReader(payload))
			if err != nil {
				return echo.NewHTTPError(http.StatusServiceUnavailable, "Administration is temporarily unavailable")
			}
			upstream.Header.Set("Content-Type", "application/json")
			response, err := r.relayClient.Do(upstream)
			if err != nil {
				return echo.NewHTTPError(http.StatusServiceUnavailable, "Administration is temporarily unavailable")
			}
			defer func() { _ = response.Body.Close() }()
			copyRelayHeaders(c.Response().Header(), response.Header)
			c.Response().WriteHeader(response.StatusCode)
			var output io.Writer = c.Response()
			if strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
				output = flushRelayWriter{c.Response()}
			}
			_, _ = io.Copy(output, response.Body)
			return nil
		}
	}
}
func (r *clusterRuntime) receiveAdminRelay(public http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if _, ok := clustertransport.PeerForScope(request.Context(), clustertransport.AdminRelay); !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		var e adminRelayEnvelope
		decoder := json.NewDecoder(http.MaxBytesReader(w, request.Body, 2<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&e) != nil || decoder.Decode(new(any)) != io.EOF || !validRelayEnvelope(r.publicConfig, e) {
			http.Error(w, "Invalid administration request", http.StatusBadRequest)
			return
		}
		target := url.URL{Scheme: "https", Host: e.Host, Path: e.Path, RawQuery: e.Query}
		incoming, err := http.NewRequestWithContext(request.Context(), e.Method, target.String(), bytes.NewReader(e.Body))
		if err != nil {
			http.Error(w, "Invalid administration request", http.StatusBadRequest)
			return
		}
		incoming.RequestURI = target.RequestURI()
		incoming.Host = e.Host
		incoming.Header = e.Headers.Clone()
		incoming.RemoteAddr = net.JoinHostPort(e.Source, "0")
		incoming.TLS = &tls.ConnectionState{} // trusted reconstruction of the original HTTPS browser hop
		// The public stack independently authenticates the browser cookie, admin role,
		// origin and CSRF token. Node enrollment does not confer browser privileges.
		public.ServeHTTP(w, incoming)
	})
}
func copyRelayHeaders(dst, src http.Header) {
	hop := map[string]bool{"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true}
	for _, value := range src.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			hop[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	for name, values := range src {
		if !hop[http.CanonicalHeaderKey(name)] {
			dst[name] = append([]string(nil), values...)
		}
	}
}

type flushRelayWriter struct{ w http.ResponseWriter }

func (f flushRelayWriter) Write(body []byte) (int, error) {
	n, err := f.w.Write(body)
	if err == nil {
		err = http.NewResponseController(f.w).Flush()
	}
	return n, err
}
func writeClusterStatus(w io.Writer, node string, status clusterpolicy.Status) error {
	return json.NewEncoder(w).Encode(map[string]any{"node_id": node, "ready": status.Ready, "applied": status.Applied.Revision, "desired": status.Desired.Revision, "lease_expires_at": status.LeaseExpiresAt})
}
