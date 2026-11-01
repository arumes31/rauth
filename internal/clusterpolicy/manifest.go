// Package clusterpolicy verifies immutable worker policy bundles. It is not a
// worker runtime: transport, durable activation and request admission integrate
// these primitives only after their own rollout gates pass.
package clusterpolicy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const verifierScopeVersion = "rauth-policy-verifier-v1"
const SchemaVersion = 1
const MaxManifestBytes = 64 << 10
const MaxEnvelopeBytes = 96 << 10
const MaxPolicyBytes int64 = 1 << 20
const MaxFeedBytes int64 = 10 << 20
const MaxGeoIPBytes int64 = 256 << 20
const MaxBundleBytes int64 = 512 << 20
const MaxFeeds = 32

var ErrInvalid = errors.New("invalid signed policy or dependency")
var ErrRollback = errors.New("policy revision rollback or equivocation")

// Blob IDs are logical names, never paths. Storage must address content by its
// validated lowercase SHA256, not a remote URL or an operator-supplied filename.
type Blob struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type Manifest struct {
	Schema      int       `json:"schema"`
	ClusterID   string    `json:"cluster_id"`
	Revision    int64     `json:"revision"`
	PublishedAt time.Time `json:"published_at"`
	Blobs       []Blob    `json:"blobs"`
}
type envelope struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type Identity struct {
	Revision int64  `json:"revision"`
	SHA256   string `json:"sha256"`
}

func (id Identity) valid() bool { return id.Revision > 0 && validHash(id.SHA256) }
func validHash(raw string) bool {
	if len(raw) != 64 || raw != strings.ToLower(raw) {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}
func validCluster(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}
func validKeyID(id string) bool {
	if len(id) < 1 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
func blobLimit(b Blob) int64 {
	switch b.Kind {
	case "policy":
		if b.ID == "policy" {
			return MaxPolicyBytes
		}
	case "feed":
		if validCluster(b.ID) {
			return MaxFeedBytes
		}
	case "geoip":
		if b.ID == "geoip" {
			return MaxGeoIPBytes
		}
	}
	return -1
}
func (m Manifest) validate() error {
	if m.Schema != SchemaVersion || !validCluster(m.ClusterID) || m.Revision <= 0 || m.PublishedAt.IsZero() || m.PublishedAt.Year() < 1 || m.PublishedAt.Year() > 9999 || len(m.Blobs) < 1 || len(m.Blobs) > MaxFeeds+2 {
		return ErrInvalid
	}
	policies, feeds, geoip := 0, 0, 0
	var total int64
	seen := make(map[string]bool)
	for _, b := range m.Blobs {
		limit := int64(0)
		switch b.Kind {
		case "policy":
			policies++
			limit = MaxPolicyBytes
			if b.ID != "policy" {
				return ErrInvalid
			}
		case "feed":
			feeds++
			limit = MaxFeedBytes
			if !validCluster(b.ID) {
				return ErrInvalid
			}
		case "geoip":
			geoip++
			limit = MaxGeoIPBytes
			if b.ID != "geoip" {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		name := b.Kind + ":" + b.ID
		if seen[name] || !validHash(b.SHA256) || b.Bytes < 0 || b.Bytes > limit {
			return ErrInvalid
		}
		seen[name] = true
		if total > MaxBundleBytes-b.Bytes {
			return ErrInvalid
		}
		total += b.Bytes
	}
	if policies != 1 || feeds > MaxFeeds || geoip > 1 {
		return ErrInvalid
	}
	return nil
}
func strictJSON(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return ErrInvalid
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
func signingInput(keyID string, payload []byte) []byte {
	out := []byte("rauth-worker-policy-v1\x00" + keyID + "\x00")
	return append(out, payload...)
}

// Sign serializes once and signs those exact bytes, including the cluster and
// revision. The key ID is in the signature domain, preventing alias substitution.
func Sign(m Manifest, keyID string, key ed25519.PrivateKey) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	if !validKeyID(keyID) || len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) {
		return nil, ErrInvalid
	}
	payload, err := json.Marshal(m)
	if err != nil || len(payload) > MaxManifestBytes {
		return nil, ErrInvalid
	}
	sig := ed25519.Sign(key, signingInput(keyID, payload))
	return json.Marshal(envelope{KeyID: keyID, Payload: base64.RawStdEncoding.EncodeToString(payload), Signature: base64.RawStdEncoding.EncodeToString(sig)})
}

type Verifier struct {
	cluster string
	keys    map[string]ed25519.PublicKey
	scope   [32]byte
}

func NewVerifier(clusterID string, keys map[string]ed25519.PublicKey) (*Verifier, error) {
	if !validCluster(clusterID) || len(keys) < 1 || len(keys) > 3 {
		return nil, ErrInvalid
	}
	v := &Verifier{cluster: clusterID, keys: make(map[string]ed25519.PublicKey, len(keys))}
	for id, key := range keys {
		if !validKeyID(id) || len(key) != ed25519.PublicKeySize || bytes.Equal(key, make([]byte, ed25519.PublicKeySize)) {
			return nil, ErrInvalid
		}
		v.keys[id] = bytes.Clone(key)
	}
	ids := make([]string, 0, len(v.keys))
	for id := range v.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	h := sha256.New()
	_, _ = h.Write([]byte(verifierScopeVersion + "\x00" + clusterID + "\x00"))
	for _, id := range ids {
		_, _ = h.Write([]byte(id + "\x00"))
		_, _ = h.Write(v.keys[id])
	}
	copy(v.scope[:], h.Sum(nil))
	return v, nil
}

// VerifiedManifest proves signature/schema, not dependency availability. It may
// be used as a fresh authoritative head without downloading large payloads.
// Its private fields cannot be changed after verification by external callers.
type VerifiedManifest struct {
	manifest Manifest
	identity Identity
	valid    bool
	scope    [32]byte
}

// ClusterID identifies the trust scope without exposing its copied verification keys.
func (v *Verifier) ClusterID() string {
	if v == nil {
		return ""
	}
	return v.cluster
}

func (v VerifiedManifest) Identity() Identity { return v.identity }
func (v VerifiedManifest) Manifest() Manifest {
	m := v.manifest
	m.Blobs = append([]Blob(nil), m.Blobs...)
	return m
}
func (v *Verifier) Verify(raw []byte) (VerifiedManifest, error) {
	invalid := VerifiedManifest{}
	if v == nil || len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return invalid, ErrInvalid
	}
	var e envelope
	if strictJSON(raw, &e) != nil || !validKeyID(e.KeyID) || len(e.Payload) > base64.RawStdEncoding.EncodedLen(MaxManifestBytes) || len(e.Signature) != base64.RawStdEncoding.EncodedLen(ed25519.SignatureSize) || strings.ContainsAny(e.Payload+e.Signature, "\r\n\t ") {
		return invalid, ErrInvalid
	}
	canonical, err := json.Marshal(e)
	if err != nil || !bytes.Equal(canonical, raw) {
		return invalid, ErrInvalid
	}
	key, ok := v.keys[e.KeyID]
	if !ok {
		return invalid, ErrInvalid
	}
	payload, err := base64.RawStdEncoding.Strict().DecodeString(e.Payload)
	if err != nil || len(payload) > MaxManifestBytes {
		return invalid, ErrInvalid
	}
	sig, err := base64.RawStdEncoding.Strict().DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key, signingInput(e.KeyID, payload), sig) {
		return invalid, ErrInvalid
	}
	var m Manifest
	if strictJSON(payload, &m) != nil || m.validate() != nil || m.ClusterID != v.cluster {
		return invalid, ErrInvalid
	}
	canonical, err = json.Marshal(m)
	if err != nil || !bytes.Equal(canonical, payload) {
		return invalid, ErrInvalid
	}
	sum := sha256.Sum256(raw)
	return VerifiedManifest{manifest: m, identity: Identity{Revision: m.Revision, SHA256: hex.EncodeToString(sum[:])}, valid: true, scope: v.scope}, nil
}

// VerifyBlob streams bounded content, detects truncation and excess bytes, and
// never allocates a blob-sized buffer. A zero-byte feed is a signed publisher
// choice; policy semantics must separately reject unapproved empty updates.
func VerifyBlob(b Blob, r io.Reader) error {
	if r == nil || !validHash(b.SHA256) || b.Bytes < 0 || b.Bytes > blobLimit(b) {
		return ErrInvalid
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, b.Bytes+1))
	if err != nil {
		return err
	}
	if n != b.Bytes || hex.EncodeToString(h.Sum(nil)) != b.SHA256 {
		return ErrInvalid
	}
	return nil
}

type VerifiedBundle struct {
	head  VerifiedManifest
	valid bool
}

func (b VerifiedBundle) Identity() Identity { return b.head.identity }

// Manifest returns copied metadata for compiling this exact complete bundle.
func (b VerifiedBundle) Manifest() Manifest { return b.head.Manifest() }

// VerifyBundle requires every signed dependency and a semantic validator. The
// callback must stage parsing results, never publish process-wide policy while
// later resources could still fail. It must reject malformed/trailing input.
// Streaming continues to the signed length to check integrity even if a parser
// finishes early. Activate only the complete returned bundle, atomically.
func VerifyBundle(head VerifiedManifest, open func(Blob) (io.ReadCloser, error), validate func(Blob, io.Reader) error) (VerifiedBundle, error) {
	if !head.valid || open == nil || validate == nil {
		return VerifiedBundle{}, ErrInvalid
	}
	for _, blob := range head.manifest.Blobs {
		r, err := open(blob)
		if err != nil {
			return VerifiedBundle{}, err
		}
		if r == nil {
			return VerifiedBundle{}, ErrInvalid
		}
		h := sha256.New()
		bounded := &io.LimitedReader{R: r, N: blob.Bytes + 1}
		tee := io.TeeReader(bounded, h)
		err = validate(blob, tee)
		if err == nil {
			_, err = io.Copy(io.Discard, tee)
		}
		closeErr := r.Close()
		if err != nil {
			return VerifiedBundle{}, err
		}
		if closeErr != nil {
			return VerifiedBundle{}, closeErr
		}
		if blob.Bytes+1-bounded.N != blob.Bytes || hex.EncodeToString(h.Sum(nil)) != blob.SHA256 {
			return VerifiedBundle{}, ErrInvalid
		}
	}
	return VerifiedBundle{head: head, valid: true}, nil
}
