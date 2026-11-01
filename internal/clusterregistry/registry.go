// Package clusterregistry authorizes private node RPCs against the current
// PostgreSQL enrollment. It does not issue certificates or grant tailnet access.
package clusterregistry

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"math"
	"net"
	"net/netip"
	"rauth/internal/clustertransport"
	"time"
)

var ErrInvalid = errors.New("invalid private node enrollment")
var ErrNotFound = errors.New("private node is not enrolled")
var ErrConflict = errors.New("private node enrollment changed or service address is already assigned")

// Reader must use a dedicated SELECT-only pool independent of auth, policy
// downloads and event ingestion. Positive grants are never cached.
type Reader struct {
	pool    *pgxpool.Pool
	cluster string
}

// Registrar is a separate control/operator-only write capability. No worker
// should receive its database credentials, and it has no public HTTP endpoint.
type Registrar struct{ reader *Reader }

type Entry struct {
	NodeID    string
	Role      string
	ServiceIP netip.Addr
	Pins      [][32]byte
	Scopes    []clustertransport.Scope
	Enabled   bool
	ExpiresAt time.Time
}

func validScope(scope clustertransport.Scope) bool {
	switch scope {
	case clustertransport.PolicyRead, clustertransport.EventsWrite, clustertransport.AdminRelay, clustertransport.StatusRead:
		return true
	}
	return false
}
func validIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Is4In6() {
		return false
	}
	_, err := clustertransport.PrivateListenAddress(net.JoinHostPort(ip.String(), "9443"))
	return err == nil
}
func (e Entry) validate(cluster string, now time.Time) error {
	if _, err := clustertransport.NodeURI(cluster, e.NodeID); err != nil {
		return ErrInvalid
	}
	if (e.Role != "control" && e.Role != "worker") || !validIP(e.ServiceIP) || len(e.Pins) < 1 || len(e.Pins) > 2 || len(e.Scopes) < 1 || len(e.Scopes) > 4 || (e.ExpiresAt.IsZero() || (e.Enabled && !e.ExpiresAt.After(now))) {
		return ErrInvalid
	}
	for i, pin := range e.Pins {
		if pin == ([32]byte{}) || (i > 0 && pin == e.Pins[0]) {
			return ErrInvalid
		}
	}
	seen := map[clustertransport.Scope]bool{}
	for _, scope := range e.Scopes {
		if !validScope(scope) || seen[scope] {
			return ErrInvalid
		}
		seen[scope] = true
	}
	return nil
}
func NewReader(pool *pgxpool.Pool, cluster string) (*Reader, error) {
	if _, err := clustertransport.NodeURI(cluster, "00000000-0000-0000-0000-000000000001"); err != nil || pool == nil {
		return nil, ErrInvalid
	}
	cfg := pool.Config()
	verified := func(c *tls.Config) bool { return c != nil && !c.InsecureSkipVerify && c.ServerName != "" }
	if !verified(cfg.ConnConfig.TLSConfig) {
		return nil, ErrInvalid
	}
	for _, fallback := range cfg.ConnConfig.Fallbacks {
		if !verified(fallback.TLSConfig) {
			return nil, ErrInvalid
		}
	}
	return &Reader{pool: pool, cluster: cluster}, nil
}
func NewRegistrar(pool *pgxpool.Pool, cluster string) (*Registrar, error) {
	reader, err := NewReader(pool, cluster)
	if err != nil {
		return nil, err
	}
	return &Registrar{reader: reader}, nil
}
func begin(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, clustertransport.ErrUnavailable
	}
	var primary bool
	if err = tx.QueryRow(ctx, `SELECT NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off'`).Scan(&primary); err != nil || !primary {
		rollback(tx)
		return nil, clustertransport.ErrUnavailable
	}
	return tx, nil
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

// Authorize implements clustertransport.Authorizer. Gate supplies the verified
// certificate identity and actual socket source; request fields cannot enroll a
// peer. Each call queries the current writable authority, even on reused TLS or
// database connections. A revoked/expired/unassigned peer is denied immediately
// after commit; unavailable state returns a generic operational error.
func (r *Reader) Authorize(parent context.Context, peer clustertransport.Peer, scope clustertransport.Scope) error {
	if r == nil || peer.ClusterID != r.cluster || !validScope(scope) || !validIP(peer.ServiceIP) || peer.SPKI == ([32]byte{}) || !peer.ExpiresAt.After(time.Now()) {
		return clustertransport.ErrDenied
	}
	if _, err := clustertransport.NodeURI(peer.ClusterID, peer.NodeID); err != nil {
		return clustertransport.ErrDenied
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	tx, err := begin(ctx, r.pool)
	if err != nil {
		return err
	}
	defer rollback(tx)
	var allowed bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cluster_nodes
 WHERE cluster_id=$1 AND node_id=$2 AND enabled AND expires_at>clock_timestamp()
 AND service_ip=$3::inet AND $4::bytea=ANY(spki_pins) AND $5::text=ANY(scopes))`, r.cluster, peer.NodeID, peer.ServiceIP.String(), peer.SPKI[:], string(scope)).Scan(&allowed)
	if err != nil {
		return clustertransport.ErrUnavailable
	}
	if !allowed {
		return clustertransport.ErrDenied
	}
	return nil
}

// Put creates with expected=0 or replaces exactly expected revision. Changing
// pins, address, scopes or enabled state is atomic; stale writers cannot undo a
// revocation. Commit timeouts remain ambiguous: re-read state before retrying.
func (r *Registrar) Put(parent context.Context, expected int64, e Entry) (int64, error) {
	if r == nil || expected < 0 || expected == math.MaxInt64 || e.validate(r.reader.cluster, time.Now()) != nil {
		return 0, ErrInvalid
	}
	pins := make([][]byte, len(e.Pins))
	for i, pin := range e.Pins {
		pins[i] = append([]byte(nil), pin[:]...)
	}
	scopes := make([]string, len(e.Scopes))
	for i, scope := range e.Scopes {
		scopes[i] = string(scope)
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	tx, err := begin(ctx, r.reader.pool)
	if err != nil {
		return 0, err
	}
	defer rollback(tx)
	var revision int64
	args := []any{r.reader.cluster, e.NodeID, e.Role, e.ServiceIP.String(), pins, scopes, e.Enabled, e.ExpiresAt}
	if expected == 0 {
		err = tx.QueryRow(ctx, `INSERT INTO cluster_nodes(cluster_id,node_id,revision,role,service_ip,spki_pins,scopes,enabled,expires_at)
   VALUES($1,$2,1,$3,$4::inet,$5,$6,$7,$8) ON CONFLICT DO NOTHING RETURNING revision`, args...).Scan(&revision)
	} else {
		args = append(args, expected)
		err = tx.QueryRow(ctx, `UPDATE cluster_nodes SET revision=revision+1,role=$3,service_ip=$4::inet,spki_pins=$5,scopes=$6,enabled=$7,expires_at=$8,updated_at=clock_timestamp()
    WHERE cluster_id=$1 AND node_id=$2 AND revision=$9 RETURNING revision`, args...).Scan(&revision)
	}
	var pgerr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgerr) && pgerr.Code == "23505") {
		return 0, ErrConflict
	}
	if err != nil {
		return 0, clustertransport.ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return 0, clustertransport.ErrUnavailable
	}
	return revision, nil
}

// Enrollment is public-key metadata, never a certificate private key or browser
// credential. Lookup returns copies suitable for operator CAS/recovery logic.
type Enrollment struct {
	Entry
	Revision  int64
	UpdatedAt time.Time
}

func (r *Reader) Lookup(parent context.Context, node string) (Enrollment, error) {
	if r == nil {
		return Enrollment{}, ErrInvalid
	}
	if _, err := clustertransport.NodeURI(r.cluster, node); err != nil {
		return Enrollment{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	tx, err := begin(ctx, r.pool)
	if err != nil {
		return Enrollment{}, err
	}
	defer rollback(tx)
	var result Enrollment
	var address string
	var pins [][]byte
	var scopes []string
	err = tx.QueryRow(ctx, `SELECT revision,role,host(service_ip),spki_pins,scopes,enabled,expires_at,updated_at
      FROM cluster_nodes WHERE cluster_id=$1 AND node_id=$2`, r.cluster, node).Scan(&result.Revision, &result.Role, &address, &pins, &scopes, &result.Enabled, &result.ExpiresAt, &result.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Enrollment{}, ErrNotFound
	}
	if err != nil {
		return Enrollment{}, clustertransport.ErrUnavailable
	}
	result.NodeID = node
	result.ServiceIP, err = netip.ParseAddr(address)
	if err != nil || !validIP(result.ServiceIP) || result.Revision < 1 || len(pins) < 1 || len(pins) > 2 {
		return Enrollment{}, clustertransport.ErrUnavailable
	}
	for _, pin := range pins {
		if len(pin) != 32 {
			return Enrollment{}, clustertransport.ErrUnavailable
		}
		result.Pins = append(result.Pins, [32]byte(pin))
	}
	for _, scope := range scopes {
		if !validScope(clustertransport.Scope(scope)) {
			return Enrollment{}, clustertransport.ErrUnavailable
		}
		result.Scopes = append(result.Scopes, clustertransport.Scope(scope))
	}
	return result, nil
}
