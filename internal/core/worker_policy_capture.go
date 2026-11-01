package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"os"
	"rauth/internal/clusterpolicy"
	"sort"
	"time"
)

type WorkerPolicyNodeProfile struct {
	SecurityFingerprint string `json:"security_fingerprint"`
	RequireGeoIP        bool   `json:"require_geoip"`
}
type WorkerPolicyCaptureOptions struct {
	NodeID    string
	Config    *Config // frozen process configuration; never mutate after startup
	Profiles  map[string]WorkerPolicyNodeProfile
	OpenGeoIP func(context.Context) (io.ReadCloser, error)
}

// CapturedWorkerPolicy owns immutable public payloads. Source URLs, credentials,
// audit identities and key material are never included. It is not an HA head.
type CapturedWorkerPolicy struct {
	document       WorkerPolicyDocument
	blobs          []clusterpolicy.Blob
	bodies         map[string][]byte
	digest         string
	sourceRevision int64
}

func (s *CapturedWorkerPolicy) Digest() string { return s.digest }
func policyContent(kind, id string, body []byte) clusterpolicy.Blob {
	sum := sha256.Sum256(body)
	return clusterpolicy.Blob{Kind: kind, ID: id, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(body))}
}
func (s *CapturedWorkerPolicy) open(b clusterpolicy.Blob) (io.ReadCloser, error) {
	for _, allowed := range s.blobs {
		if allowed == b {
			return io.NopCloser(bytes.NewReader(s.bodies[b.SHA256])), nil
		}
	}
	return nil, clusterpolicy.ErrInvalid
}
func rollbackPolicyCapture(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

// CaptureWorkerPolicy reads rules and feed versions from one primary SQL
// snapshot, independently of the legacy process-global caches. Call it again
// after any publication conflict instead of resigning an older captured source.
func CaptureWorkerPolicy(parent context.Context, pool *pgxpool.Pool, options WorkerPolicyCaptureOptions) (*CapturedWorkerPolicy, error) {
	own, err := WorkerPolicyOptionsForConfig(options.NodeID, options.Config)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, errors.New("missing policy capture database")
	}
	if err = configureAuthStateDatabase(options.Config, pool.Config()); err != nil {
		return nil, err
	}
	if len(options.Profiles) < 1 || len(options.Profiles) > 64 {
		return nil, errors.New("invalid desired node profiles")
	}
	profiles := make(map[string]string, len(options.Profiles))
	requireGeo := own.RequireGeoIP
	for id, profile := range options.Profiles {
		if !policyUUID(id) || !policyHash(profile.SecurityFingerprint) {
			return nil, errors.New("invalid desired node profile")
		}
		profiles[id] = profile.SecurityFingerprint
		requireGeo = requireGeo || profile.RequireGeoIP
	}
	if profiles[options.NodeID] != own.SecurityFingerprint {
		return nil, errors.New("controller configuration does not match desired node profile")
	}
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer rollbackPolicyCapture(tx)
	var primary bool
	if err = tx.QueryRow(ctx, `SELECT NOT pg_is_in_recovery() AND current_setting('default_transaction_read_only')='off'`).Scan(&primary); err != nil {
		return nil, err
	}
	if !primary {
		return nil, errors.New("policy source is not the primary")
	}
	source := &CapturedWorkerPolicy{document: WorkerPolicyDocument{Schema: 1, NodeProfiles: profiles, RequireGeoIP: requireGeo, DefaultFeedConfigured: true}, bodies: map[string][]byte{}}
	if err = tx.QueryRow(ctx, "SELECT revision FROM cluster_policy_source_state WHERE singleton").Scan(&source.sourceRevision); err != nil {
		return nil, err
	}
	// Environmental allow rules inherit the managed default just as in legacy mode.
	envRules := map[string]BypassRule{}
	for _, raw := range options.Config.AuthBypassRules {
		r, e := ParseBypassRule(raw)
		if e != nil {
			return nil, e
		}
		old, exists := envRules[r.Rule]
		if !exists || r.Action == BypassDeny || old.Action != BypassDeny {
			envRules[r.Rule] = r
		}
	}
	for _, r := range envRules {
		p := RulePolicy{}
		if r.Allows() {
			p.DefaultFeedConfigured = true
			p.BlockedFeedIDs = []string{DefaultIPFeedID}
		}
		source.document.Rules = append(source.document.Rules, WorkerPolicyRule{Rule: r.Rule, Action: r.Action, Source: "env", Policy: p})
	}
	rows, err := tx.Query(ctx, `SELECT rule,meta FROM bypass_rules ORDER BY rule`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var text string
		var meta []byte
		if err = rows.Scan(&text, &meta); err != nil {
			rows.Close()
			return nil, err
		}
		r, e := ParseBypassRule(text)
		if e != nil || r.Rule != text {
			rows.Close()
			return nil, errors.New("invalid stored policy rule")
		}
		var stored BypassRule
		if json.Unmarshal(meta, &stored) != nil {
			rows.Close()
			return nil, errors.New("invalid stored policy metadata")
		}
		action, e := normalizeAction(stored.Action)
		if e != nil {
			rows.Close()
			return nil, e
		}
		p, e := NormalizeRulePolicy(stored.RulePolicy)
		if e != nil {
			rows.Close()
			return nil, e
		}
		if action == BypassAllow && !p.DefaultFeedConfigured {
			rows.Close()
			return nil, errors.New("managed default rule bootstrap must complete before policy publication")
		}
		source.document.RequireGeoIP = source.document.RequireGeoIP || p.CountryMode == CountrySelected
		source.document.Rules = append(source.document.Rules, WorkerPolicyRule{Rule: text, Action: action, Source: "ui", Policy: p})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(source.document.Rules) > maxBypassRules {
		return nil, errBypassTooMany
	}
	rows, err = tx.Query(ctx, `SELECT f.id::text,f.enabled,f.active_version,v.checksum,v.payload FROM ip_feeds f LEFT JOIN ip_feed_versions v ON v.feed_id=f.id AND v.version=f.active_version ORDER BY f.id`)
	if err != nil {
		return nil, err
	}
	defaultReady := false
	for rows.Next() {
		var id string
		var enabled bool
		var version int64
		var checksum *string
		var body []byte
		if err = rows.Scan(&id, &enabled, &version, &checksum, &body); err != nil {
			rows.Close()
			return nil, err
		}
		if !enabled || version <= 0 || checksum == nil {
			if id == DefaultIPFeedID {
				rows.Close()
				return nil, errors.New("managed default feed is not ready")
			}
			continue
		}
		blob := policyContent("feed", id, body)
		if len(body) > MaxFeedBytes || blob.SHA256 != *checksum {
			rows.Close()
			return nil, errors.New("stored feed integrity check failed")
		}
		source.blobs = append(source.blobs, blob)
		source.bodies[blob.SHA256] = bytes.Clone(body)
		// The existing refresh transaction only commits an empty active version after
		// explicit AcceptEmpty approval. Preserve that recorded version's semantics.
		source.document.Feeds = append(source.document.Feeds, WorkerPolicyFeed{ID: id, Version: version, ApprovedEmpty: len(body) == 0})
		defaultReady = defaultReady || id == DefaultIPFeedID
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if !defaultReady {
		return nil, errors.New("managed default feed bootstrap must complete before publication")
	}
	if len(source.document.Feeds) > MaxIPFeeds {
		return nil, errors.New("too many active policy feeds")
	}
	if err = tx.Rollback(ctx); err != nil {
		return nil, err
	} // release source snapshot before file I/O
	if options.OpenGeoIP != nil {
		reader, e := options.OpenGeoIP(ctx)
		if e != nil {
			if !errors.Is(e, os.ErrNotExist) || source.document.RequireGeoIP {
				return nil, e
			}
		} else {
			if reader == nil {
				return nil, errors.New("nil GeoIP source")
			}
			body, readErr := io.ReadAll(io.LimitReader(contextPolicyReader{ctx: ctx, r: reader}, clusterpolicy.MaxGeoIPBytes+1))
			closeErr := reader.Close()
			if readErr != nil {
				return nil, readErr
			}
			if closeErr != nil {
				return nil, closeErr
			}
			if int64(len(body)) > clusterpolicy.MaxGeoIPBytes {
				return nil, errors.New("GeoIP source exceeds policy limit")
			}
			b := policyContent("geoip", "geoip", body)
			source.blobs = append(source.blobs, b)
			source.bodies[b.SHA256] = body
		}
	}
	if source.document.RequireGeoIP && len(source.blobs) > 0 {
		found := false
		for _, b := range source.blobs {
			found = found || b.Kind == "geoip"
		}
		if !found {
			return nil, errors.New("required GeoIP source is unavailable")
		}
	}
	sort.Slice(source.document.Rules, func(i, j int) bool {
		a, b := source.document.Rules[i], source.document.Rules[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.Rule < b.Rule
	})
	body, err := json.Marshal(source.document)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > clusterpolicy.MaxPolicyBytes {
		return nil, errors.New("policy document exceeds limit")
	}
	policy := policyContent("policy", "policy", body)
	source.blobs = append([]clusterpolicy.Blob{policy}, source.blobs...)
	source.bodies[policy.SHA256] = body
	metadata, err := json.Marshal(source.blobs)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte("rauth-policy-source-v1\x00"), metadata...))
	source.digest = hex.EncodeToString(sum[:])
	return source, nil
}

type contextPolicyReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextPolicyReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
