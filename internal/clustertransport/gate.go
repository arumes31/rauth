package clustertransport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"
)

type Scope string

const (
	PolicyRead  Scope = "policy:read"
	EventsWrite Scope = "events:write"
	AdminRelay  Scope = "admin:relay"
	StatusRead  Scope = "status:read"
)

func (s Scope) valid() bool {
	switch s {
	case PolicyRead, EventsWrite, AdminRelay, StatusRead:
		return true
	}
	return false
}

type Authorizer func(context.Context, Peer, Scope) error

type Gate struct {
	cluster          string
	authorize        Authorizer
	now              func() time.Time
	requireServiceIP bool
}

func NewGate(cluster string, authorize Authorizer) (*Gate, error) {
	if !validID(cluster) || authorize == nil {
		return nil, ErrConfiguration
	}
	return &Gate{cluster: cluster, authorize: authorize, now: time.Now, requireServiceIP: true}, nil
}

// Protect applies a server-selected scope. Client headers/cookies never choose
// identity or scope. Authorizer must check current node enrollment, key pin and
// permission (including revocation); do not cache a handshake's positive grant.
func (g *Gate) Protect(scope Scope, next http.Handler) (http.Handler, error) {
	if g == nil || !validID(g.cluster) || g.authorize == nil || g.now == nil || !scope.valid() || next == nil {
		return nil, ErrConfiguration
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		peer, err := peerFromTLS(*r.TLS, g.cluster, g.now())
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		observed, err := netip.ParseAddr(host)
		if err != nil || observed.Zone() != "" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		observed = observed.Unmap()
		if g.requireServiceIP && !serviceIP(observed) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		peer.ServiceIP = observed
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		err = g.authorize(ctx, peer, scope)
		cancel()
		if errors.Is(err, ErrDenied) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if err != nil {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		operation, cancelOperation := context.WithDeadline(r.Context(), peer.ExpiresAt)
		defer cancelOperation()
		next.ServeHTTP(w, r.WithContext(context.WithValue(operation, authorizationKey{}, authorization{peer: peer, scope: scope})))
	}), nil
}

type authorizationKey struct{}
type authorization struct {
	peer  Peer
	scope Scope
}

// PeerForScope returns only the certificate identity authorized for this exact
// server-selected operation. Ingestion/relay handlers must use it instead of a
// submitted node ID or a peer verified for some weaker endpoint.
func PeerForScope(ctx context.Context, expected Scope) (Peer, bool) {
	if ctx == nil {
		return Peer{}, false
	}
	claim, ok := ctx.Value(authorizationKey{}).(authorization)
	if !ok || !expected.valid() || claim.scope != expected {
		return Peer{}, false
	}
	return claim.peer, true
}
