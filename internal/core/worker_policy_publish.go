package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"math"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clusterstate"
	"slices"
	"sync"
	"time"
)

var ErrPolicyPublisherBusy = errors.New("policy publication is already running")

// ControllerPolicyPublisher belongs only to the control role. Dedicated source,
// head, payload and write pools keep capture/upload out of auth request budgets.
// Database grants and host-mounted signing-key permissions are still mandatory.
type ControllerPolicyPublisher struct {
	mu         sync.Mutex
	write      *clusterstate.Publisher
	current    *clusterstate.Reader
	sourcePool *pgxpool.Pool
	verifier   *clusterpolicy.Verifier
	keyID      string
	key        ed25519.PrivateKey
	capture    WorkerPolicyCaptureOptions
	compiler   WorkerPolicyOptions
}
type PolicyPublication struct {
	Identity       clusterpolicy.Identity
	SourceSHA256   string
	SourceRevision int64
	Changed        bool
}

func NewControllerPolicyPublisher(writePool, sourcePool, headPool, blobPool *pgxpool.Pool, v *clusterpolicy.Verifier, keyID string, key ed25519.PrivateKey, capture WorkerPolicyCaptureOptions) (*ControllerPolicyPublisher, error) {
	if writePool == nil || sourcePool == nil || headPool == nil || blobPool == nil || v == nil {
		return nil, clusterpolicy.ErrInvalid
	}
	pools := []*pgxpool.Pool{writePool, sourcePool, headPool, blobPool}
	for i, pool := range pools {
		for _, other := range pools[:i] {
			if pool == other {
				return nil, errors.New("controller policy pools must have independent budgets")
			}
		}
	}
	options, err := WorkerPolicyOptionsForConfig(capture.NodeID, capture.Config)
	if err != nil {
		return nil, err
	}
	// Validate key ID, private/public consistency and that the configured verifier
	// actually trusts this signer, without publishing or logging key material.
	probe := clusterpolicy.Manifest{Schema: 1, ClusterID: v.ClusterID(), Revision: 1, PublishedAt: time.Unix(1, 0).UTC(), Blobs: []clusterpolicy.Blob{policyContent("policy", "policy", nil)}}
	raw, err := clusterpolicy.Sign(probe, keyID, key)
	if err != nil {
		return nil, err
	}
	if _, err = v.Verify(raw); err != nil {
		return nil, err
	}
	write, err := clusterstate.NewPublisher(writePool, v)
	if err != nil {
		return nil, err
	}
	current, err := clusterstate.NewReader(headPool, blobPool, v)
	if err != nil {
		return nil, err
	}
	if err = configureAuthStateDatabase(capture.Config, sourcePool.Config()); err != nil {
		return nil, err
	}
	frozen := *capture.Config
	// Copy every slice before storing the otherwise scalar configuration. The
	// explicit classifier rejects newly added Config fields until reviewed.
	frozen.CookieDomains = slices.Clone(frozen.CookieDomains)
	frozen.AllowedHosts = slices.Clone(frozen.AllowedHosts)
	frozen.MetricsAllowedIPs = slices.Clone(frozen.MetricsAllowedIPs)
	frozen.WebAuthnOrigins = slices.Clone(frozen.WebAuthnOrigins)
	frozen.AllowedCountries = slices.Clone(frozen.AllowedCountries)
	frozen.TrustedProxies = slices.Clone(frozen.TrustedProxies)
	frozen.CloudflareIPRanges = slices.Clone(frozen.CloudflareIPRanges)
	frozen.CSRFTrustedOrigins = slices.Clone(frozen.CSRFTrustedOrigins)
	frozen.AuthBypassRules = slices.Clone(frozen.AuthBypassRules)
	frozen.SSOApplicationOrigins = slices.Clone(frozen.SSOApplicationOrigins)
	profiles := make(map[string]WorkerPolicyNodeProfile, len(capture.Profiles))
	for id, profile := range capture.Profiles {
		profiles[id] = profile
	}
	capture.Config = &frozen
	capture.Profiles = profiles
	return &ControllerPolicyPublisher{write: write, current: current, sourcePool: sourcePool, verifier: v, keyID: keyID, key: bytes.Clone(key), capture: capture, compiler: options}, nil
}

// Reconcile reads the current authoritative base before taking a new consistent
// source snapshot. A conflict is returned; the next attempt must recapture both.
// Never retry an old captured edit under a later revision. Unchanged dependency
// identities and signing key preserve the current head across process restarts.
func (p *ControllerPolicyPublisher) Reconcile(parent context.Context) (PolicyPublication, error) {
	if !p.mu.TryLock() {
		return PolicyPublication{}, ErrPolicyPublisherBusy
	}
	defer p.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	current, err := p.current.Current(ctx)
	base := clusterpolicy.Identity{}
	if err != nil && !errors.Is(err, clusterstate.ErrNoHead) {
		return PolicyPublication{}, err
	}
	if err == nil {
		base = current.Verified.Identity()
	}
	if base.Revision == math.MaxInt64 {
		return PolicyPublication{}, errors.New("policy revision exhausted")
	}
	source, err := CaptureWorkerPolicy(ctx, p.sourcePool, p.capture)
	if err != nil {
		return PolicyPublication{}, err
	}
	result := PolicyPublication{Identity: base, SourceSHA256: source.digest, SourceRevision: source.sourceRevision}
	if base.Revision > 0 && slices.Equal(current.Verified.Manifest().Blobs, source.blobs) {
		var envelope struct {
			KeyID string `json:"key_id"`
		}
		if json.Unmarshal(current.Envelope, &envelope) != nil {
			return result, clusterstate.ErrCorrupt
		}
		if envelope.KeyID == p.keyID {
			return result, nil
		}
	}
	manifest := clusterpolicy.Manifest{Schema: 1, ClusterID: p.verifier.ClusterID(), Revision: base.Revision + 1, PublishedAt: time.Now().UTC(), Blobs: slices.Clone(source.blobs)}
	raw, err := clusterpolicy.Sign(manifest, p.keyID, p.key)
	if err != nil {
		return result, err
	}
	head, err := p.verifier.Verify(raw)
	if err != nil {
		return result, err
	}
	compiler, err := NewWorkerPolicyCompiler(p.compiler)
	if err != nil {
		return result, err
	}
	defer func() { _ = compiler.Close() }()
	validated := 0
	published, err := p.write.Publish(ctx, base, raw, source.open, func(b clusterpolicy.Blob, r io.Reader) error {
		if e := compiler.Validate(ctx, b, r); e != nil {
			return e
		}
		validated++
		if validated == len(manifest.Blobs) {
			// Validate independently checks each blob hash/length. Complete semantic
			// validation therefore happens inside the transaction before head commit;
			// outer VerifyBundle additionally confirms every signed dependency.
			value, e := compiler.finishManifest(ctx, head.Identity(), head.Manifest())
			if e != nil {
				return e
			}
			return value.Close()
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	result.Identity = published.Verified.Identity()
	result.Changed = true
	return result, nil
}
