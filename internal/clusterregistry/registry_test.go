package clusterregistry_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"rauth/internal/clusterregistry"
	"rauth/internal/clustertransport"
	"rauth/internal/core"
	"rauth/internal/pgtest"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()
var cluster = uuid.NewString()

const node = "937f4ba6-8615-47cb-909c-238214b43c39"

func entry() clusterregistry.Entry {
	return clusterregistry.Entry{NodeID: node, Role: "worker", ServiceIP: netip.MustParseAddr("100.72.1.2"), Pins: [][32]byte{sha256.Sum256([]byte("synthetic-node-key-one"))}, Scopes: []clustertransport.Scope{clustertransport.PolicyRead}, Enabled: true, ExpiresAt: time.Now().Add(time.Hour)}
}
func peer(e clusterregistry.Entry) clustertransport.Peer {
	return clustertransport.Peer{ClusterID: cluster, NodeID: e.NodeID, SPKI: e.Pins[0], ServiceIP: e.ServiceIP, ExpiresAt: time.Now().Add(30 * time.Minute)}
}
func fixture(t *testing.T) (*pgxpool.Pool, *pgxpool.Pool, *clusterregistry.Reader, *clusterregistry.Registrar) {
	t.Helper()
	write := pgtest.Open(t, core.Migrate)
	pgtest.Reset(t, write)
	cfg := write.Config()
	cfg.MaxConns = 1
	read, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(read.Close)
	r, err := clusterregistry.NewReader(read, cluster)
	require.NoError(t, err)
	w, err := clusterregistry.NewRegistrar(write, cluster)
	require.NoError(t, err)
	return write, read, r, w
}
func TestNodeRegistryRejectsUnverifiedDatabaseAndInvalidCluster(t *testing.T) {
	_, err := clusterregistry.NewReader(nil, cluster)
	require.ErrorIs(t, err, clusterregistry.ErrInvalid)
	cfg, err := pgxpool.ParseConfig("postgres://test:synthetic@localhost/test?sslmode=disable")
	require.NoError(t, err)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	_, err = clusterregistry.NewReader(pool, cluster)
	require.ErrorIs(t, err, clusterregistry.ErrInvalid)
	_, err = clusterregistry.NewRegistrar(pool, "other")
	require.ErrorIs(t, err, clusterregistry.ErrInvalid)
}
func TestNodeRegistryChecksExactCurrentPeerAndScope(t *testing.T) {
	_, read, r, w := fixture(t)
	e := entry()
	rev, err := w.Put(ctx, 0, e)
	require.NoError(t, err)
	require.EqualValues(t, 1, rev)
	require.NoError(t, r.Authorize(ctx, peer(e), clustertransport.PolicyRead))
	mutations := []func(*clustertransport.Peer){
		func(p *clustertransport.Peer) { p.ClusterID = uuid.NewString() },
		func(p *clustertransport.Peer) { p.NodeID = uuid.NewString() },
		func(p *clustertransport.Peer) { p.NodeID = "not-a-node" },
		func(p *clustertransport.Peer) { p.SPKI = sha256.Sum256([]byte("other")) },
		func(p *clustertransport.Peer) { p.ServiceIP = netip.MustParseAddr("100.72.1.3") },
		func(p *clustertransport.Peer) { p.ServiceIP = netip.MustParseAddr("192.168.1.2") },
		func(p *clustertransport.Peer) { p.ExpiresAt = time.Now().Add(-time.Second) },
	}
	for i, mutate := range mutations {
		p := peer(e)
		mutate(&p)
		require.ErrorIs(t, r.Authorize(ctx, p, clustertransport.PolicyRead), clustertransport.ErrDenied, "mutation %d", i)
	}
	require.ErrorIs(t, r.Authorize(ctx, peer(e), clustertransport.EventsWrite), clustertransport.ErrDenied)
	require.ErrorIs(t, r.Authorize(ctx, peer(e), "*"), clustertransport.ErrDenied)
	foreignCluster := uuid.NewString()
	other, err := clusterregistry.NewReader(read, foreignCluster)
	require.NoError(t, err)
	foreign := peer(e)
	foreign.ClusterID = foreignCluster
	require.ErrorIs(t, other.Authorize(ctx, foreign, clustertransport.PolicyRead), clustertransport.ErrDenied)
}

func TestNodeRegistryRevocationAndRotationAreImmediateOnReusedConnection(t *testing.T) {
	_, read, r, w := fixture(t)
	e := entry()
	rev, err := w.Put(ctx, 0, e)
	require.NoError(t, err)
	var before, after int
	require.NoError(t, read.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&before))
	old := peer(e)
	require.NoError(t, r.Authorize(ctx, old, clustertransport.PolicyRead))
	second := sha256.Sum256([]byte("synthetic-node-key-two"))
	e.Pins = append(e.Pins, second)
	rev, err = w.Put(ctx, rev, e)
	require.NoError(t, err)
	rotated := old
	rotated.SPKI = second
	require.NoError(t, r.Authorize(ctx, old, clustertransport.PolicyRead))
	require.NoError(t, r.Authorize(ctx, rotated, clustertransport.PolicyRead))
	e.Pins = e.Pins[1:]
	rev, err = w.Put(ctx, rev, e)
	require.NoError(t, err)
	require.ErrorIs(t, r.Authorize(ctx, old, clustertransport.PolicyRead), clustertransport.ErrDenied)
	require.NoError(t, r.Authorize(ctx, rotated, clustertransport.PolicyRead))
	stale := rev
	e.Enabled = false
	rev, err = w.Put(ctx, rev, e)
	require.NoError(t, err)
	assert.Equal(t, stale+1, rev)
	require.ErrorIs(t, r.Authorize(ctx, rotated, clustertransport.PolicyRead), clustertransport.ErrDenied)
	e.Enabled = true
	_, err = w.Put(ctx, stale, e)
	require.ErrorIs(t, err, clusterregistry.ErrConflict)
	require.ErrorIs(t, r.Authorize(ctx, rotated, clustertransport.PolicyRead), clustertransport.ErrDenied)
	require.NoError(t, read.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&after))
	assert.Equal(t, before, after, "no reconnect is required to observe revocation")
}
func TestNodeRegistryDatabaseExpiryAndAddressUniqueness(t *testing.T) {
	write, _, r, w := fixture(t)
	e := entry()
	_, err := w.Put(ctx, 0, e)
	require.NoError(t, err)
	other := e
	other.NodeID = uuid.NewString()
	_, err = w.Put(ctx, 0, other)
	require.ErrorIs(t, err, clusterregistry.ErrConflict)
	_, err = write.Exec(ctx, "UPDATE cluster_nodes SET expires_at=clock_timestamp()-interval '1 second' WHERE cluster_id=$1", cluster)
	require.NoError(t, err)
	require.ErrorIs(t, r.Authorize(ctx, peer(e), clustertransport.PolicyRead), clustertransport.ErrDenied)
	e.Enabled = false
	e.ExpiresAt = time.Now().Add(-time.Hour)
	_, err = w.Put(ctx, 1, e)
	require.NoError(t, err, "already-expired enrollment may still be explicitly revoked")
}
func TestNodeRegistryStaleConcurrentWritersCannotOverwriteEachOther(t *testing.T) {
	_, _, _, w := fixture(t)
	e := entry()
	rev, err := w.Put(ctx, 0, e)
	require.NoError(t, err)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		copy := e
		copy.Enabled = i == 0
		copy.Scopes = []clustertransport.Scope{clustertransport.EventsWrite}
		wg.Go(func() { _, err := w.Put(ctx, rev, copy); results <- err })
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, clusterregistry.ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	assert.Equal(t, 1, success)
	assert.Equal(t, 1, conflict)
}
func TestNodeRegistryRejectsInvalidEnrollment(t *testing.T) {
	_, _, _, w := fixture(t)
	mutations := []func(*clusterregistry.Entry){
		func(e *clusterregistry.Entry) { e.NodeID = "bad" }, func(e *clusterregistry.Entry) { e.Role = "admin" }, func(e *clusterregistry.Entry) { e.ServiceIP = netip.MustParseAddr("127.0.0.1") }, func(e *clusterregistry.Entry) { e.ServiceIP = netip.MustParseAddr("::ffff:100.72.1.2") }, func(e *clusterregistry.Entry) { e.Pins = nil }, func(e *clusterregistry.Entry) { e.Pins = append(e.Pins, e.Pins[0]) }, func(e *clusterregistry.Entry) { e.Pins[0] = [32]byte{} }, func(e *clusterregistry.Entry) { e.Scopes = nil }, func(e *clusterregistry.Entry) { e.Scopes = []clustertransport.Scope{"*"} }, func(e *clusterregistry.Entry) { e.Scopes = append(e.Scopes, e.Scopes[0]) }, func(e *clusterregistry.Entry) { e.ExpiresAt = time.Time{} }, func(e *clusterregistry.Entry) { e.ExpiresAt = time.Now().Add(-time.Hour) },
	}
	for i, mutate := range mutations {
		e := entry()
		mutate(&e)
		_, err := w.Put(ctx, 0, e)
		require.ErrorIs(t, err, clusterregistry.ErrInvalid, "mutation %d", i)
	}
}
func TestNodeRegistryReadOnlyAuthorityAndPoolExhaustionFailClosed(t *testing.T) {
	_, read, r, w := fixture(t)
	e := entry()
	_, err := w.Put(ctx, 0, e)
	require.NoError(t, err)
	require.NoError(t, r.Authorize(ctx, peer(e), clustertransport.PolicyRead))
	_, err = read.Exec(ctx, "SET default_transaction_read_only=on")
	require.NoError(t, err)
	require.ErrorIs(t, r.Authorize(ctx, peer(e), clustertransport.PolicyRead), clustertransport.ErrUnavailable)
	_, err = read.Exec(ctx, "SET default_transaction_read_only=off")
	require.NoError(t, err)
	conn, err := read.Acquire(ctx)
	require.NoError(t, err)
	deadline, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	require.ErrorIs(t, r.Authorize(deadline, peer(e), clustertransport.PolicyRead), clustertransport.ErrUnavailable)
	assert.Less(t, time.Since(started), time.Second)
	conn.Release()
	require.NoError(t, r.Authorize(ctx, peer(e), clustertransport.PolicyRead))
}
func TestNodeRegistryDatabaseRoleCannotEnrollOrRevoke(t *testing.T) {
	write, _, _, w := fixture(t)
	e := entry()
	_, err := w.Put(ctx, 0, e)
	require.NoError(t, err)
	role := "rauth_registry_" + fmt.Sprintf("%x", sha256.Sum256([]byte(uuid.NewString())))[:16]
	ident := pgx.Identifier{role}.Sanitize()
	var schema string
	require.NoError(t, write.QueryRow(ctx, "SELECT current_schema()").Scan(&schema))
	_, err = write.Exec(ctx, "CREATE ROLE "+ident+" LOGIN PASSWORD 'synthetic-registry-test-only'")
	require.NoError(t, err)
	defer func() { _, _ = write.Exec(ctx, "DROP OWNED BY "+ident); _, _ = write.Exec(ctx, "DROP ROLE "+ident) }()
	_, err = write.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO "+ident)
	require.NoError(t, err)
	_, err = write.Exec(ctx, "GRANT SELECT ON cluster_nodes TO "+ident)
	require.NoError(t, err)
	cfg := write.Config()
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = "synthetic-registry-test-only"
	cfg.MaxConns = 1
	read, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer read.Close()
	r, err := clusterregistry.NewReader(read, cluster)
	require.NoError(t, err)
	require.NoError(t, r.Authorize(ctx, peer(e), clustertransport.PolicyRead))
	for _, query := range []string{"DELETE FROM cluster_nodes", "UPDATE cluster_nodes SET enabled=false", "INSERT INTO cluster_nodes SELECT * FROM cluster_nodes"} {
		_, err = read.Exec(ctx, query)
		require.Error(t, err)
		var pge *pgconn.PgError
		require.ErrorAs(t, err, &pge)
		assert.Equal(t, "42501", pge.Code)
	}
	forbidden, err := clusterregistry.NewRegistrar(read, cluster)
	require.NoError(t, err)
	e.Enabled = false
	_, err = forbidden.Put(ctx, 1, e)
	require.ErrorIs(t, err, clustertransport.ErrUnavailable)
	require.NoError(t, r.Authorize(ctx, peer(e), clustertransport.PolicyRead), "failed worker write must not revoke enrollment")
}

func TestRegistryGateRechecksSameVerifiedTLSState(t *testing.T) {
	_, read, r, w := fixture(t)
	e := entry()
	uri, err := clustertransport.NodeURI(cluster, e.NodeID)
	require.NoError(t, err)
	// Synthetic post-handshake state composes Gate with real SQL authorization.
	// Real TLS chain/handshake tests are in clustertransport; no wire claim here.
	now := time.Now()
	leaf := &x509.Certificate{URIs: []*url.URL{uri}, Raw: []byte("synthetic-verified-leaf"), RawSubjectPublicKeyInfo: []byte("synthetic-verified-key"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	e.Pins = [][32]byte{sha256.Sum256(leaf.RawSubjectPublicKeyInfo)}
	rev, err := w.Put(ctx, 0, e)
	require.NoError(t, err)
	gate, err := clustertransport.NewGate(cluster, r.Authorize)
	require.NoError(t, err)
	called := 0
	protected, err := gate.Protect(clustertransport.PolicyRead, http.HandlerFunc(func(out http.ResponseWriter, req *http.Request) {
		verified, ok := clustertransport.PeerForScope(req.Context(), clustertransport.PolicyRead)
		require.True(t, ok)
		assert.Equal(t, node, verified.NodeID)
		called++
		out.WriteHeader(http.StatusNoContent)
	}))
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "https://100.72.1.1:9443/v1/policy", nil)
	request.RemoteAddr = e.ServiceIP.String() + ":45000"
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	send := func() *httptest.ResponseRecorder {
		out := httptest.NewRecorder()
		protected.ServeHTTP(out, request)
		return out
	}
	assert.Equal(t, http.StatusNoContent, send().Code)
	request.RemoteAddr = "100.72.1.3:45000"
	request.Header.Set("X-Forwarded-For", e.ServiceIP.String())
	assert.Equal(t, http.StatusForbidden, send().Code, "headers cannot replace the actual socket source")
	request.RemoteAddr = e.ServiceIP.String() + ":45000"
	_, err = read.Exec(ctx, "SET default_transaction_read_only=on")
	require.NoError(t, err)
	unavailable := send()
	assert.Equal(t, http.StatusServiceUnavailable, unavailable.Code)
	assert.Equal(t, "5", unavailable.Header().Get("Retry-After"))
	_, err = read.Exec(ctx, "SET default_transaction_read_only=off")
	require.NoError(t, err)
	e.Enabled = false
	_, err = w.Put(ctx, rev, e)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, send().Code, "the exact same verified TLS state must be reauthorized")
	assert.Equal(t, 1, called)
}

func TestNodeRegistryLookupOwnsCopiesAndSupportsRevocationRecovery(t *testing.T) {
	_, _, r, w := fixture(t)
	e := entry()
	rev, err := w.Put(ctx, 0, e)
	require.NoError(t, err)
	got, err := r.Lookup(ctx, node)
	require.NoError(t, err)
	assert.Equal(t, rev, got.Revision)
	assert.Equal(t, e.Pins, got.Pins)
	assert.Equal(t, e.ServiceIP, got.ServiceIP)
	got.Pins[0][0] ^= 0xff
	got.Scopes[0] = clustertransport.EventsWrite
	current, err := r.Lookup(ctx, node)
	require.NoError(t, err)
	assert.Equal(t, e.Pins, current.Pins)
	assert.Equal(t, e.Scopes, current.Scopes)
	_, err = r.Lookup(ctx, uuid.NewString())
	require.ErrorIs(t, err, clusterregistry.ErrNotFound)
	_, err = r.Lookup(ctx, "private-secret-invalid-node")
	require.ErrorIs(t, err, clusterregistry.ErrInvalid)
	assert.NotContains(t, err.Error(), "private-secret")
	e.Enabled = false
	rev, err = w.Put(ctx, rev, e)
	require.NoError(t, err)
	revoked, err := r.Lookup(ctx, node)
	require.NoError(t, err)
	assert.False(t, revoked.Enabled)
	assert.Equal(t, rev, revoked.Revision)
}
