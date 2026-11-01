// Package clustertransport authenticates private RAuth node requests. It does
// not enroll certificates, publish listeners or authorize browser sessions.
package clustertransport

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
)

var ErrIdentity = errors.New("private node identity is invalid")
var ErrConfiguration = errors.New("private node transport configuration is invalid")
var ErrDenied = errors.New("private node permission denied")
var ErrUnavailable = errors.New("private node permission authority is unavailable")

func validID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}
func NodeURI(cluster, node string) (*url.URL, error) {
	if !validID(cluster) || !validID(node) {
		return nil, ErrConfiguration
	}
	return &url.URL{Scheme: "spiffe", Host: "rauth", Path: "/" + cluster + "/node/" + node}, nil
}

type Peer struct {
	ClusterID string
	NodeID    string
	SPKI      [32]byte
	ExpiresAt time.Time
	ServiceIP netip.Addr
}

func identity(cert *x509.Certificate, cluster string, now time.Time) (Peer, error) {
	if cert == nil || !validID(cluster) || cert.IsCA || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || len(cert.URIs) != 1 {
		return Peer{}, ErrIdentity
	}
	u := cert.URIs[0]
	if u == nil || u.Scheme != "spiffe" || u.Host != "rauth" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return Peer{}, ErrIdentity
	}
	// UUIDs have fixed lengths. No CommonName, DNS SAN or forwarded-header
	// fallback is permitted for node identity.
	prefix := "/" + cluster + "/node/"
	if len(u.Path) != len(prefix)+36 || u.Path[:len(prefix)] != prefix {
		return Peer{}, ErrIdentity
	}
	node := u.Path[len(prefix):]
	expected, err := NodeURI(cluster, node)
	if err != nil || u.String() != expected.String() {
		return Peer{}, ErrIdentity
	}
	return Peer{ClusterID: cluster, NodeID: node, SPKI: sha256.Sum256(cert.RawSubjectPublicKeyInfo), ExpiresAt: cert.NotAfter}, nil
}
func peerFromTLS(state tls.ConnectionState, cluster string, now time.Time) (Peer, error) {
	if state.Version < tls.VersionTLS13 || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return Peer{}, ErrIdentity
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil {
		return Peer{}, ErrIdentity
	}
	matched := false
	for _, chain := range state.VerifiedChains {
		if len(chain) == 0 || chain[0] == nil || !bytes.Equal(chain[0].Raw, leaf.Raw) {
			continue
		}
		valid := true
		for _, cert := range chain {
			if cert == nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				valid = false
				break
			}
		}
		if valid {
			matched = true
			break
		}
	}
	if !matched {
		return Peer{}, ErrIdentity
	}
	return identity(leaf, cluster, now)
}

var tailV4 = netip.MustParsePrefix("100.64.0.0/10")
var tailV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

func serviceIP(addr netip.Addr) bool {
	return addr.IsValid() && addr.Zone() == "" && !addr.Is4In6() && (tailV4.Contains(addr) || tailV6.Contains(addr))
}

// PrivateEndpoint accepts literal service Tailscale addresses only. It never
// falls back to a host daemon's address, public DNS, wildcard or loopback bind.
func PrivateEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, ErrConfiguration
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil || !serviceIP(addr) {
		return nil, ErrConfiguration
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != u.Port() {
		return nil, ErrConfiguration
	}
	canonical := "https://" + net.JoinHostPort(addr.String(), u.Port())
	if raw != canonical {
		return nil, ErrConfiguration
	}
	return u, nil
}
func PrivateListenAddress(raw string) (string, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", ErrConfiguration
	}
	u, err := PrivateEndpoint("https://" + net.JoinHostPort(host, port))
	if err != nil {
		return "", err
	}
	return u.Host, nil
}
