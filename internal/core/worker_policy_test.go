package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"rauth/internal/clusterpolicy"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const snapshotNode = "93146fde-67c3-48b7-8842-fafc7bfd2d03"
const snapshotCluster = "258d7bed-aa73-4516-817b-235107206a99"
const snapshotFeed = "5fa88ecb-ceab-44ce-8496-fc5b70ba56fd"

func snapshotOptions() WorkerPolicyOptions {
	return WorkerPolicyOptions{NodeID: snapshotNode, SecurityFingerprint: strings.Repeat("a", 64)}
}
func snapshotDocument() WorkerPolicyDocument {
	return WorkerPolicyDocument{Schema: 1, NodeProfiles: map[string]string{snapshotNode: snapshotOptions().SecurityFingerprint}, Rules: []WorkerPolicyRule{{Rule: "cloud.example.test", Action: BypassAllow, Source: "ui", Policy: RulePolicy{BlockedFeedIDs: []string{snapshotFeed}}}}, Feeds: []WorkerPolicyFeed{{ID: snapshotFeed, Version: 1}}}
}
func snapshotKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("synthetic-core-policy-signing-key"))
	return ed25519.NewKeyFromSeed(seed[:])
}
func snapshotBlob(kind, id string, body []byte) clusterpolicy.Blob {
	sum := sha256.Sum256(body)
	return clusterpolicy.Blob{Kind: kind, ID: id, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(body))}
}
func compileSnapshot(t *testing.T, document WorkerPolicyDocument, contents map[string][]byte, configure func(*WorkerPolicyCompiler), rawTransform func([]byte) []byte) (*PolicySnapshot, error) {
	t.Helper()
	body, err := json.Marshal(document)
	require.NoError(t, err)
	if rawTransform != nil {
		body = rawTransform(body)
	}
	blobs := []clusterpolicy.Blob{snapshotBlob("policy", "policy", body)}
	bodies := map[string][]byte{blobs[0].SHA256: body}
	for id, payload := range contents {
		kind := "feed"
		if id == "geoip" {
			kind = "geoip"
		}
		b := snapshotBlob(kind, id, payload)
		blobs = append(blobs, b)
		bodies[b.SHA256] = payload
	}
	raw, err := clusterpolicy.Sign(clusterpolicy.Manifest{Schema: 1, ClusterID: snapshotCluster, Revision: 1, PublishedAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Blobs: blobs}, "v1", snapshotKey())
	require.NoError(t, err)
	v, err := clusterpolicy.NewVerifier(snapshotCluster, map[string]ed25519.PublicKey{"v1": snapshotKey().Public().(ed25519.PublicKey)})
	require.NoError(t, err)
	head, err := v.Verify(raw)
	require.NoError(t, err)
	compiler, err := NewWorkerPolicyCompiler(snapshotOptions())
	require.NoError(t, err)
	defer func() { _ = compiler.Close() }()
	if configure != nil {
		configure(compiler)
	}
	bundle, err := clusterpolicy.VerifyBundle(head, func(b clusterpolicy.Blob) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodies[b.SHA256])), nil
	}, compiler.Validate)
	if err != nil {
		return nil, err
	}
	return compiler.Finish(bundle)
}
func TestWorkerPolicySnapshotKeepsRulesAndFeedsIndependentOfGlobals(t *testing.T) {
	doc := snapshotDocument()
	snapshot, err := compileSnapshot(t, doc, map[string][]byte{snapshotFeed: []byte("203.0.113.42/32\n")}, nil, nil)
	require.NoError(t, err)
	defer func() { _ = snapshot.Close() }()
	oldRules, oldFeeds := activeBypass.Load(), activeFeeds.Load()
	t.Cleanup(func() { activeBypass.Store(oldRules); activeFeeds.Store(oldFeeds) })
	activeBypass.Store(&bypassSet{})
	activeFeeds.Store(&feedSnapshot{indexes: map[string]*compiledIPFeed{}})
	rule, found, err := snapshot.SelectRule("cloud.example.test", "/remote.php/dav/files/a/file;name?x=a&b=c")
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, rule.Allows())
	require.True(t, snapshot.RestrictedForHost("cloud.example.test"))
	require.True(t, snapshot.HasRules())
	assert.Equal(t, PolicyDecision{Allowed: false, Reason: "ip_feed_blocked", FeedID: snapshotFeed}, snapshot.Evaluate(rule.RulePolicy, "203.0.113.42"))
	assert.True(t, snapshot.Evaluate(rule.RulePolicy, "203.0.113.43").Allowed)
	rule.BlockedFeedIDs[0] = "mutated"
	again, found, err := snapshot.SelectRule("cloud.example.test", "/")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []string{snapshotFeed}, again.BlockedFeedIDs, "caller cannot mutate immutable rules through a returned slice")
	assert.EqualValues(t, 1, snapshot.Identity().Revision)
}
func TestWorkerPolicyCompilerRejectsIncompleteOrIncompatibleInputs(t *testing.T) {
	cases := []struct {
		name   string
		change func(*WorkerPolicyDocument, map[string][]byte)
	}{
		{"wrong-schema", func(d *WorkerPolicyDocument, _ map[string][]byte) { d.Schema = 2 }},
		{"missing-node-profile", func(d *WorkerPolicyDocument, _ map[string][]byte) { d.NodeProfiles = map[string]string{} }},
		{"wrong-security-profile", func(d *WorkerPolicyDocument, _ map[string][]byte) {
			d.NodeProfiles[snapshotNode] = strings.Repeat("b", 64)
		}},
		{"invalid-profile-node", func(d *WorkerPolicyDocument, _ map[string][]byte) {
			d.NodeProfiles["../node"] = strings.Repeat("a", 64)
		}},
		{"missing-feed", func(_ *WorkerPolicyDocument, b map[string][]byte) { delete(b, snapshotFeed) }},
		{"missing-feed-metadata", func(d *WorkerPolicyDocument, _ map[string][]byte) { d.Feeds = nil }},
		{"duplicate-feed", func(d *WorkerPolicyDocument, _ map[string][]byte) { d.Feeds = append(d.Feeds, d.Feeds[0]) }},
		{"zero-feed-version", func(d *WorkerPolicyDocument, _ map[string][]byte) { d.Feeds[0].Version = 0 }},
		{"missing-managed-default", func(d *WorkerPolicyDocument, _ map[string][]byte) { d.DefaultFeedConfigured = true }},
		{"duplicate-rule", func(d *WorkerPolicyDocument, _ map[string][]byte) { d.Rules = append(d.Rules, d.Rules[0]) }},
		{"invalid-rule", func(d *WorkerPolicyDocument, _ map[string][]byte) { d.Rules[0].Rule = "https://cloud.example.test" }},
		{"invalid-source", func(d *WorkerPolicyDocument, _ map[string][]byte) { d.Rules[0].Source = "unknown" }},
		{"invalid-action", func(d *WorkerPolicyDocument, _ map[string][]byte) { d.Rules[0].Action = "maybe" }},
		{"rule-missing-reference", func(d *WorkerPolicyDocument, _ map[string][]byte) {
			d.Rules[0].Policy.BlockedFeedIDs = []string{DefaultIPFeedID}
		}},
		{"country-without-geoip", func(d *WorkerPolicyDocument, _ map[string][]byte) {
			d.Rules[0].Policy.CountryMode = CountrySelected
			d.Rules[0].Policy.AllowedCountries = []string{"AT"}
		}},
		{"required-geoip-missing", func(d *WorkerPolicyDocument, _ map[string][]byte) { d.RequireGeoIP = true }},
		{"malformed-feed", func(_ *WorkerPolicyDocument, b map[string][]byte) { b[snapshotFeed] = []byte("<html>error</html>") }},
		{"unapproved-empty-feed", func(_ *WorkerPolicyDocument, b map[string][]byte) { b[snapshotFeed] = nil }},
		{"malformed-geoip", func(_ *WorkerPolicyDocument, b map[string][]byte) { b["geoip"] = []byte("invalid database") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := snapshotDocument()
			bodies := map[string][]byte{snapshotFeed: []byte("203.0.113.42/32")}
			tc.change(&doc, bodies)
			snapshot, err := compileSnapshot(t, doc, bodies, nil, nil)
			if snapshot != nil {
				_ = snapshot.Close()
			}
			require.Error(t, err)
		})
	}
}
func TestWorkerPolicyCompilerApprovesExplicitEmptyAndRejectsAlternateJSON(t *testing.T) {
	doc := snapshotDocument()
	doc.Feeds[0].ApprovedEmpty = true
	snapshot, err := compileSnapshot(t, doc, map[string][]byte{snapshotFeed: nil}, nil, nil)
	require.NoError(t, err)
	defer func() { _ = snapshot.Close() }()
	rule, _, err := snapshot.SelectRule("cloud.example.test", "/")
	require.NoError(t, err)
	assert.True(t, snapshot.Evaluate(rule.RulePolicy, "203.0.113.42").Allowed)
	for _, transform := range []func([]byte) []byte{
		func(body []byte) []byte { return append([]byte(" "), body...) },
		func(body []byte) []byte {
			return bytes.Replace(body, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
		},
		func(body []byte) []byte {
			return bytes.Replace(body, []byte(`"schema":1`), []byte(`"schema":1,"unknown":true`), 1)
		},
		func(body []byte) []byte { return append(body, []byte(`{}`)...) },
	} {
		_, err := compileSnapshot(t, doc, map[string][]byte{snapshotFeed: nil}, nil, transform)
		require.Error(t, err)
	}
}

type snapshotGeo struct {
	code   string
	calls  atomic.Int32
	closes atomic.Int32
}

func (g *snapshotGeo) Country(net.IP) (*geoip2.Country, error) {
	g.calls.Add(1)
	country := &geoip2.Country{}
	country.Country.IsoCode = g.code
	return country, nil
}
func (g *snapshotGeo) Metadata() maxminddb.Metadata {
	return maxminddb.Metadata{DatabaseType: "GeoLite2-Country"}
}
func (g *snapshotGeo) Close() error { g.closes.Add(1); return nil }
func TestWorkerPolicySnapshotOwnsCountryCacheAndReader(t *testing.T) {
	doc := snapshotDocument()
	doc.Rules[0].Policy.CountryMode = CountrySelected
	doc.Rules[0].Policy.AllowedCountries = []string{"AT"}
	old := GeoCache
	GeoCache = NewGeoLRUCache(1)
	GeoCache.Put("203.0.113.43", "DE")
	defer func() { GeoCache = old }()
	reader := &snapshotGeo{code: "AT"}
	snapshot, err := compileSnapshot(t, doc, map[string][]byte{snapshotFeed: []byte("203.0.113.42/32"), "geoip": []byte("synthetic-geo-reader")}, func(c *WorkerPolicyCompiler) {
		c.openGeo = func([]byte) (geoCountryReader, error) { return reader, nil }
	}, nil)
	require.NoError(t, err)
	rule, found, err := snapshot.SelectRule("cloud.example.test", "/")
	require.NoError(t, err)
	require.True(t, found)
	assert.True(t, snapshot.Evaluate(rule.RulePolicy, "203.0.113.43").Allowed, "global GeoCache does not contaminate pinned policy")
	assert.Equal(t, "AT", snapshot.CountryCode("203.0.113.43"))
	assert.EqualValues(t, 1, reader.calls.Load())
	assert.Equal(t, "Tailscale", snapshot.CountryCode("100.64.1.1"))
	assert.Equal(t, "Tailscale", snapshot.CountryCode("fd7a:115c:a1e0::1"))
	assert.Equal(t, "Internal", snapshot.CountryCode("192.168.1.1"))
	assert.Equal(t, "unknown", snapshot.CountryCode("invalid"))
	require.NoError(t, snapshot.Close())
	require.NoError(t, snapshot.Close())
	assert.EqualValues(t, 1, reader.closes.Load())
}
func TestWorkerPolicyCompilerReleasesGeoIPAfterLaterSemanticFailure(t *testing.T) {
	doc := snapshotDocument()
	doc.Feeds[0].Version = 0
	reader := &snapshotGeo{code: "AT"}
	_, err := compileSnapshot(t, doc, map[string][]byte{snapshotFeed: []byte("203.0.113.42/32"), "geoip": []byte("synthetic-geo-reader")}, func(c *WorkerPolicyCompiler) {
		c.openGeo = func([]byte) (geoCountryReader, error) { return reader, nil }
	}, nil)
	require.Error(t, err)
	assert.EqualValues(t, 1, reader.closes.Load())
}

func TestWorkerPolicyCompilerAcceptsManagedDefaultFeed(t *testing.T) {
	require.True(t, policyUUID(DefaultIPFeedID), "the managed feed uses a stable UUID")
	doc := snapshotDocument()
	doc.DefaultFeedConfigured = true
	doc.Feeds[0].ID = DefaultIPFeedID
	doc.Rules[0].Policy.BlockedFeedIDs = []string{DefaultIPFeedID}
	doc.Rules[0].Policy.DefaultFeedConfigured = true
	snapshot, err := compileSnapshot(t, doc, map[string][]byte{DefaultIPFeedID: []byte("203.0.113.42/32")}, nil, nil)
	require.NoError(t, err)
	defer func() { _ = snapshot.Close() }()
	rule, found, err := snapshot.SelectRule("cloud.example.test", "/")
	require.NoError(t, err)
	require.True(t, found)
	decision := snapshot.Evaluate(rule.RulePolicy, "203.0.113.42")
	require.False(t, decision.Allowed)
	assert.Equal(t, DefaultIPFeedID, decision.FeedID)
	assert.True(t, snapshot.Evaluate(rule.RulePolicy, "203.0.113.43").Allowed)
}
