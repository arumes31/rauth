package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/oschwald/geoip2-golang"
	"io"
	"net"
	"net/netip"
	"rauth/internal/clusterpolicy"
	"strings"
	"sync"
)

// WorkerPolicyDocument contains public policy/config metadata only. Profiles are
// hashes of versioned node-specific security configuration, never secret values.
// The controller must publish its complete rules and every active feed version.
type WorkerPolicyDocument struct {
	Schema                int                `json:"schema"`
	NodeProfiles          map[string]string  `json:"node_profiles"`
	Rules                 []WorkerPolicyRule `json:"rules"`
	Feeds                 []WorkerPolicyFeed `json:"feeds"`
	DefaultFeedConfigured bool               `json:"default_feed_configured"`
	RequireGeoIP          bool               `json:"require_geoip"`
}
type WorkerPolicyRule struct {
	Rule   string     `json:"rule"`
	Action string     `json:"action"`
	Source string     `json:"source"`
	Policy RulePolicy `json:"policy"`
}
type WorkerPolicyFeed struct {
	ID            string `json:"id"`
	Version       int64  `json:"version"`
	ApprovedEmpty bool   `json:"approved_empty"`
}

// WorkerPolicyOptions must be frozen before reconciliation starts. Startup will
// derive SecurityFingerprint from the node's validated security configuration;
// an unmatched policy cannot be hot-activated using stale proxy/origin settings.
type WorkerPolicyOptions struct {
	NodeID              string
	SecurityFingerprint string
	RequireGeoIP        bool
}

// PolicySnapshot owns immutable matching, prefix indexes and a GeoIP reader.
// Use it only inside clusterworker.WithPolicy; it closes after the final pin.
type PolicySnapshot struct {
	identity  clusterpolicy.Identity
	rules     bypassSet
	feeds     feedSnapshot
	geo       geoCountryReader
	countries *GeoLRUCache
	closeOnce sync.Once
	closeErr  error
}

func (s *PolicySnapshot) Identity() clusterpolicy.Identity { return s.identity }
func (s *PolicySnapshot) Close() error {
	s.closeOnce.Do(func() {
		if s.geo != nil {
			s.closeErr = s.geo.Close()
			s.geo = nil
		}
	})
	return s.closeErr
}
func copyPolicyRule(r BypassRule) BypassRule {
	r.AllowedCountries = append([]string(nil), r.AllowedCountries...)
	r.BlockedFeedIDs = append([]string(nil), r.BlockedFeedIDs...)
	return r
}
func (s *PolicySnapshot) SelectRule(host, uri string) (BypassRule, bool, error) {
	r, ok, err := selectBypassRule(&s.rules, host, uri)
	return copyPolicyRule(r), ok, err
}
func (s *PolicySnapshot) HasRules() bool {
	for _, list := range [][]BypassRule{s.rules.env, s.rules.ui} {
		for _, r := range list {
			if r.Allows() {
				return true
			}
		}
	}
	return false
}
func (s *PolicySnapshot) RestrictedForHost(raw string) bool {
	host := normalizeRequestHost(raw)
	if host == "" {
		return false
	}
	for _, list := range [][]BypassRule{s.rules.env, s.rules.ui} {
		for _, r := range list {
			if r.matchesHost(host) && r.Restricted() {
				return true
			}
		}
	}
	return false
}
func (s *PolicySnapshot) Evaluate(r RulePolicy, ip string) PolicyDecision {
	return r.evaluate(ip, s.CountryCode(ip), &s.feeds)
}
func (s *PolicySnapshot) CountryCode(raw string) string {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return "unknown"
	}
	ip = ip.Unmap()
	if netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(ip) {
		return "Tailscale"
	}
	parsed := net.IP(ip.AsSlice())
	if isPrivateNetIP(parsed) {
		return "Internal"
	}
	canonical := ip.String()
	if value, ok := s.countries.Get(canonical); ok {
		return value
	}
	if s.geo == nil {
		return "unknown"
	}
	record, err := s.geo.Country(parsed)
	if err != nil {
		return "unknown"
	}
	code := record.Country.IsoCode
	if code == "" {
		code = "unknown"
	}
	s.countries.Put(canonical, code)
	return code
}

// WorkerPolicyCompiler implements the worker's staging compiler structurally,
// keeping core independent of its reconciliation implementation.
type WorkerPolicyCompiler struct {
	options  WorkerPolicyOptions
	document *WorkerPolicyDocument
	payloads map[string]clusterpolicy.Blob
	indexes  map[string]*compiledIPFeed
	geo      geoCountryReader
	openGeo  func([]byte) (geoCountryReader, error)
	finished bool
	closed   bool
}

func policyHash(raw string) bool {
	if len(raw) != 64 {
		return false
	}
	b, err := hex.DecodeString(raw)
	return err == nil && hex.EncodeToString(b) == raw
}
func policyUUID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}
func NewWorkerPolicyCompiler(options WorkerPolicyOptions) (*WorkerPolicyCompiler, error) {
	if !policyUUID(options.NodeID) || !policyHash(options.SecurityFingerprint) {
		return nil, clusterpolicy.ErrInvalid
	}
	return &WorkerPolicyCompiler{options: options, payloads: map[string]clusterpolicy.Blob{}, indexes: map[string]*compiledIPFeed{}, openGeo: func(body []byte) (geoCountryReader, error) { return geoip2.FromBytes(body) }}, nil
}
func policyBytes(b clusterpolicy.Blob, r io.Reader, limit int64) ([]byte, error) {
	if b.Bytes < 0 || b.Bytes > limit {
		return nil, clusterpolicy.ErrInvalid
	}
	body := make([]byte, int(b.Bytes))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	extra, err := io.ReadAll(io.LimitReader(r, 1))
	if err != nil {
		return nil, err
	}
	if len(extra) > 0 {
		return nil, clusterpolicy.ErrInvalid
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != b.SHA256 {
		return nil, clusterpolicy.ErrInvalid
	}
	return body, nil
}
func (c *WorkerPolicyCompiler) Validate(ctx context.Context, b clusterpolicy.Blob, r io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.closed || c.finished || r == nil {
		return clusterpolicy.ErrInvalid
	}
	r = policyCompileReader{ctx: ctx, r: r}
	name := b.Kind + ":" + b.ID
	if _, duplicate := c.payloads[name]; duplicate {
		return clusterpolicy.ErrInvalid
	}
	switch b.Kind {
	case "policy":
		if b.ID != "policy" || c.document != nil {
			return clusterpolicy.ErrInvalid
		}
		body, err := policyBytes(b, r, clusterpolicy.MaxPolicyBytes)
		if err != nil {
			return err
		}
		var document WorkerPolicyDocument
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF {
			return clusterpolicy.ErrInvalid
		}
		canonical, err := json.Marshal(document)
		if err != nil || !bytes.Equal(canonical, body) {
			return clusterpolicy.ErrInvalid
		}
		c.document = &document
	case "feed":
		if !policyUUID(b.ID) {
			return clusterpolicy.ErrInvalid
		}
		body, err := policyBytes(b, r, MaxFeedBytes)
		if err != nil {
			return err
		}
		index, _, err := parseFeed(body, true)
		if err != nil {
			return err
		}
		c.indexes[b.ID] = index
	case "geoip":
		if b.ID != "geoip" || c.geo != nil {
			return clusterpolicy.ErrInvalid
		}
		body, err := policyBytes(b, r, clusterpolicy.MaxGeoIPBytes)
		if err != nil {
			return err
		}
		reader, err := c.openGeo(body)
		if err != nil {
			return err
		}
		databaseType := reader.Metadata().DatabaseType
		if !strings.Contains(databaseType, "Country") && !strings.Contains(databaseType, "City") {
			_ = reader.Close()
			return errors.New("GeoIP policy dependency has no country data")
		}
		c.geo = reader
	default:
		return clusterpolicy.ErrInvalid
	}
	c.payloads[name] = b
	return nil
}
func (c *WorkerPolicyCompiler) Finish(ctx context.Context, bundle clusterpolicy.VerifiedBundle) (*PolicySnapshot, error) {
	return c.finishManifest(ctx, bundle.Identity(), bundle.Manifest())
}

// finishManifest is also used by the controller after every dependency has
// independently passed Validate's exact size/hash check, before the SQL head
// commit. It remains private: callers must hold verified signed-head evidence.
func (c *WorkerPolicyCompiler) finishManifest(ctx context.Context, identity clusterpolicy.Identity, manifest clusterpolicy.Manifest) (*PolicySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.closed || c.finished || c.document == nil || identity.Revision <= 0 || identity.Revision != manifest.Revision || !policyHash(identity.SHA256) {
		return nil, clusterpolicy.ErrInvalid
	}
	doc := c.document
	if doc.Schema != 1 || len(doc.NodeProfiles) < 1 || len(doc.NodeProfiles) > 64 || len(doc.Rules) > maxBypassRules || len(doc.Feeds) > MaxIPFeeds {
		return nil, clusterpolicy.ErrInvalid
	}
	for id, fingerprint := range doc.NodeProfiles {
		if !policyUUID(id) || !policyHash(fingerprint) {
			return nil, clusterpolicy.ErrInvalid
		}
	}
	if doc.NodeProfiles[c.options.NodeID] != c.options.SecurityFingerprint {
		return nil, errors.New("worker security configuration does not match signed policy")
	}
	blobs := manifest.Blobs
	if len(blobs) != len(c.payloads) {
		return nil, clusterpolicy.ErrInvalid
	}
	for _, b := range blobs {
		if c.payloads[b.Kind+":"+b.ID] != b {
			return nil, clusterpolicy.ErrInvalid
		}
	}
	snapshot := &PolicySnapshot{identity: identity, feeds: feedSnapshot{indexes: map[string]*compiledIPFeed{}, versions: map[string]int64{}, defaultConfigured: doc.DefaultFeedConfigured}, countries: NewGeoLRUCache(geoCacheCapacity)}
	total := 0
	for _, feed := range doc.Feeds {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		index, ok := c.indexes[feed.ID]
		if !policyUUID(feed.ID) || feed.Version < 1 || !ok || snapshot.feeds.versions[feed.ID] != 0 {
			return nil, clusterpolicy.ErrInvalid
		}
		if index.count == 0 && !feed.ApprovedEmpty {
			return nil, errors.New("empty signed feed requires explicit approval")
		}
		total += index.count
		if total > MaxWorkerFeedPrefixes {
			return nil, errors.New("combined feed prefix limit exceeded")
		}
		snapshot.feeds.indexes[feed.ID] = index
		snapshot.feeds.versions[feed.ID] = feed.Version
	}
	if len(snapshot.feeds.indexes) != len(c.indexes) {
		return nil, errors.New("feed payload missing policy metadata")
	}
	if doc.DefaultFeedConfigured && snapshot.feeds.indexes[DefaultIPFeedID] == nil {
		return nil, errors.New("managed default feed missing from policy")
	}
	requireGeo := doc.RequireGeoIP || c.options.RequireGeoIP
	seen := map[string]bool{}
	for _, input := range doc.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r, err := ParseBypassRule(input.Rule)
		if err != nil || r.Rule != input.Rule {
			return nil, clusterpolicy.ErrInvalid
		}
		action, err := normalizeAction(input.Action)
		if err != nil || action != input.Action {
			return nil, clusterpolicy.ErrInvalid
		}
		r.Action = action
		if input.Source != "ui" && input.Source != "env" {
			return nil, clusterpolicy.ErrInvalid
		}
		r.Source = input.Source
		normalized, err := NormalizeRulePolicy(input.Policy)
		if err != nil {
			return nil, err
		}
		// A managed-default bundle must distinguish inherited selection from
		// an explicit administrator opt-out. Missing declaration is incomplete;
		// an explicit choice may intentionally omit the managed feed.
		if doc.DefaultFeedConfigured && r.Allows() && !normalized.DefaultFeedConfigured {
			return nil, errors.New("public rule lacks a managed-default selection declaration")
		}
		r.RulePolicy = normalized
		if seen[r.Source+":"+r.Rule] {
			return nil, errors.New("duplicate worker rule")
		}
		seen[r.Source+":"+r.Rule] = true
		for _, id := range r.BlockedFeedIDs {
			if snapshot.feeds.indexes[id] == nil {
				return nil, errors.New("rule requires a missing feed")
			}
		}
		if r.CountryMode == CountrySelected {
			requireGeo = true
		}
		if r.Source == "env" {
			snapshot.rules.env = append(snapshot.rules.env, r)
		} else {
			snapshot.rules.ui = append(snapshot.rules.ui, r)
		}
	}
	if requireGeo && c.geo == nil {
		return nil, errors.New("country policy requires a GeoIP dependency")
	}
	snapshot.geo = c.geo
	c.geo = nil
	c.finished = true
	return snapshot, nil
}
func (c *WorkerPolicyCompiler) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	if c.geo != nil {
		err := c.geo.Close()
		c.geo = nil
		return err
	}
	return nil
}

type policyCompileReader struct {
	ctx context.Context
	r   io.Reader
}

func (r policyCompileReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
