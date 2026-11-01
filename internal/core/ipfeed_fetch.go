package core

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// validateFeedURL never resolves or fetches a URL. The dialer separately checks
// every DNS result and connects to those exact addresses, including redirects.
func validateFeedURL(raw string) (*url.URL, error) {
	if len(raw) > 2048 {
		return nil, errors.New("feed URL is too long")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("use an HTTPS feed URL without credentials or fragment")
	}
	if strings.ContainsAny(u.Host, "\\\r\n\t%") {
		return nil, errors.New("invalid feed host")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !publicFeedAddress(ip) {
		return nil, errors.New("feed destination is not public")
	}
	if port := u.Port(); port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return nil, errors.New("invalid feed port")
		}
	}
	return u, nil
}

var disallowedFeedNets = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("::/96"),
}

func publicFeedAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
		return false
	}
	for _, prefix := range disallowedFeedNets {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

type feedResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type feedDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

func dialPublicFeed(resolver feedResolver, dialer feedDialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid feed destination")
		}
		ips, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("feed DNS lookup failed")
		}
		for _, ip := range ips {
			if !publicFeedAddress(ip) {
				return nil, errors.New("feed DNS includes a non-public destination")
			}
		}
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, errors.New("could not connect to feed destination")
	}
}
func newFeedClient() *http.Client {
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialPublicFeed(net.DefaultResolver, &net.Dialer{Timeout: 5 * time.Second}),
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 32 << 10,
		DisableKeepAlives:      true,
	}
	return &http.Client{
		Timeout: 20 * time.Second, Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many feed redirects")
			}
			_, err := validateFeedURL(req.URL.String())
			return err
		},
	}
}
func fetchIPFeed(ctx context.Context, client *http.Client, raw string) ([]byte, error) {
	u, err := validateFeedURL(raw)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("invalid feed request")
	}
	request.Header.Set("Accept", "text/plain, application/octet-stream;q=0.9")
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("feed HTTPS request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("feed server did not return HTTP 200")
	}
	if strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/html") {
		return nil, errors.New("feed server returned HTML")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxFeedBytes+1))
	if err != nil {
		return nil, errors.New("failed reading feed response")
	}
	if len(body) > MaxFeedBytes {
		return nil, errors.New("feed exceeds download size limit")
	}
	return body, nil
}
