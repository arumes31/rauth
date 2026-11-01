package clusterpolicy

import (
	"errors"
	"sync"
	"time"
)

const DefaultLease = 120 * time.Second
const MaxLease = 300 * time.Second
const HeadCheckInterval = 10 * time.Second

var ErrNotCurrent = errors.New("complete policy does not match a fresh authoritative head")

type Freshness struct {
	mu        sync.Mutex
	scope     [32]byte
	now       func() time.Time
	lease     time.Duration
	minimum   Identity
	active    Identity
	desired   Identity
	headUntil time.Time
}
type Status struct {
	Ready          bool
	Applied        Identity
	Desired        Identity
	LeaseExpiresAt time.Time
}

// NewFreshness requires the durable high-water mark from the host-mounted store.
// A fresh process never inherits readiness from a persisted wall-clock deadline.
// A new verified head withdraws readiness before disk I/O; persist its
// watermark before replacement activation. This object implements lease
// decisions, not filesystem persistence.
func NewFreshness(v *Verifier, minimum Identity, lease time.Duration) (*Freshness, error) {
	if lease == 0 {
		lease = DefaultLease
	}
	if v == nil || v.scope == ([32]byte{}) || lease < HeadCheckInterval || lease > MaxLease || (minimum != (Identity{}) && !minimum.valid()) {
		return nil, ErrInvalid
	}
	return &Freshness{minimum: minimum, lease: lease, now: time.Now, scope: v.scope}, nil
}
func (f *Freshness) acceptable(id Identity) bool {
	return id.valid() && (f.minimum.Revision == 0 || id.Revision > f.minimum.Revision || id == f.minimum)
}

// Restore makes a verified complete persisted generation available for a head
// comparison, but never authorizes traffic before a new authoritative read.
func (f *Freshness) Restore(bundle VerifiedBundle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !bundle.valid || bundle.head.scope != f.scope || !f.acceptable(bundle.Identity()) {
		return ErrRollback
	}
	f.active = bundle.Identity()
	f.minimum = f.active
	f.headUntil = time.Time{}
	f.desired = Identity{}
	return nil
}

// ObserveHead must receive the current signed envelope from the HA write leader,
// not an arbitrary cached control response. A matching head renews availability
// with the controller offline; a new/invalid/rollback head withdraws it now.
func (f *Freshness) ObserveHead(head VerifiedManifest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !head.valid || head.scope != f.scope || !f.acceptable(head.Identity()) || head.identity.Revision < f.desired.Revision || (head.identity.Revision == f.desired.Revision && head.identity != f.desired) {
		f.headUntil = time.Time{}
		return ErrRollback
	}
	f.desired = head.Identity()
	f.minimum = f.desired
	f.headUntil = f.now().Add(f.lease)
	return nil
}

// HeadUnavailable deliberately does not renew the old lease. A transient SQL
// outage may use only its remaining lifetime, never a control-host fallback.
func (f *Freshness) HeadUnavailable() {}

// Activate is called only after durable staging/atomic pointer publication. A
// delayed download cannot activate an old head or reset its last-read deadline.
func (f *Freshness) Activate(bundle VerifiedBundle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !bundle.valid || bundle.head.scope != f.scope || bundle.Identity() != f.desired || !f.now().Before(f.headUntil) || !f.acceptable(bundle.Identity()) {
		return ErrNotCurrent
	}
	f.active = bundle.Identity()
	f.minimum = f.active
	return nil
}

// Status binds readiness to the exact immutable bundle pinned by a request.
// If disk/runtime publication races a head change or a failed Activate, callers
// cannot authorize a different generation using the old generation's lease.
func (f *Freshness) Status(bundle VerifiedBundle) Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Status{Ready: bundle.valid && bundle.head.scope == f.scope && bundle.Identity() == f.active && f.active.valid() && f.active == f.desired && f.now().Before(f.headUntil), Applied: f.active, Desired: f.desired, LeaseExpiresAt: f.headUntil}
}
