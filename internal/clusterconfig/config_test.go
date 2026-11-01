package clusterconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

const clusterID = "75b418cf-cd1e-4299-b187-408b1e3cab84"
const nodeID = "efbcefc6-55b1-47d7-b4d8-a905ff55b081"
const controllerID = "91b7dd52-f651-47d5-9cde-21050306fbd8"

func policyKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("synthetic-runtime-policy-signer"))
	return ed25519.NewKeyFromSeed(seed[:])
}
func document(root string) Config {
	pin := sha256.Sum256([]byte("synthetic-controller-spki"))
	return Config{Schema: 1, Role: Worker, ClusterID: clusterID, NodeID: nodeID, ServiceIP: "100.72.1.2", PrivatePort: 9443, DataRoot: root, MountDevice: "8:1", MountFilesystem: "ext4", CacheRoot: root + "/cache", CertificateFile: root + "/identity/node.crt", PrivateKeyFile: root + "/identity/node.key", CAFile: root + "/identity/ca.crt", PolicyKeys: map[string]string{"one": base64.StdEncoding.EncodeToString(policyKey().Public().(ed25519.PublicKey))}, Databases: DatabaseFiles{Registry: root + "/secrets/registry.url", Head: root + "/secrets/head.url", Payload: root + "/secrets/payload.url"}, Controller: Controller{NodeID: controllerID, Endpoint: "https://100.72.1.1:9443", Pins: []string{base64.StdEncoding.EncodeToString(pin[:])}}}
}
func TestRuntimeConfigValidatesExactNodeScopeAndRoleCapabilities(t *testing.T) {
	good := document("/var/lib/rauth")
	require.NoError(t, good.Validate())
	raw, err := json.MarshalIndent(good, "", "  ")
	require.NoError(t, err)
	parsed, err := Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, good, parsed)
	mutations := []func(*Config){func(c *Config) { c.Databases.Registry = "" }, func(c *Config) { c.Databases.Registrar = c.DataRoot + "/secrets/registrar.url" }, func(c *Config) { c.Role = "unknown" }, func(c *Config) { c.ClusterID = "other" }, func(c *Config) { c.NodeID = "../node" }, func(c *Config) { c.ServiceIP = "192.168.1.2" }, func(c *Config) { c.ServiceIP = "::" }, func(c *Config) { c.PrivatePort = 0 }, func(c *Config) { c.CacheRoot = "/tmp/cache" }, func(c *Config) { c.PrivateKeyFile = c.CertificateFile }, func(c *Config) { c.CertificateFile = c.DataRoot + "/../node.crt" }, func(c *Config) { c.MountDevice = "08:1" }, func(c *Config) { c.MountFilesystem = "overlay" }, func(c *Config) { c.SignerFile = c.DataRoot + "/signer.json" }, func(c *Config) { c.Databases.Publisher = c.DataRoot + "/writer.url" }, func(c *Config) { c.Controller.NodeID = c.NodeID }, func(c *Config) { c.Controller.Endpoint = "https://public.example.test:9443" }, func(c *Config) { c.Controller.Pins = append(c.Controller.Pins, c.Controller.Pins[0]) }, func(c *Config) { c.PolicyKeys["one"] = base64.StdEncoding.EncodeToString(make([]byte, 32)) }}
	for i, change := range mutations {
		c := document("/var/lib/rauth")
		change(&c)
		assert.Error(t, c.Validate(), "mutation %d", i)
	}
}
func TestRuntimeConfigRejectsDuplicateUnknownAndTrailingDocuments(t *testing.T) {
	raw, err := json.Marshal(document("/var/lib/rauth"))
	require.NoError(t, err)
	for _, data := range [][]byte{
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"Schema":1`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"ſchema":1`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1), bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"unexpected":"private-secret"`), 1), append(bytes.Clone(raw), []byte(`{}`)...), []byte(strings.Repeat("[", 22) + "0" + strings.Repeat("]", 22))} {
		_, err = Parse(data)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "private-secret")
	}
}
func TestRuntimeConfigControlNeedsItsOwnEnrolledEndpointAndAllHostFiles(t *testing.T) {
	c := document("/var/lib/rauth")
	c.Role = Control
	c.Controller.NodeID = c.NodeID
	c.Controller.Endpoint = "https://100.72.1.2:9443"
	c.SignerFile = c.DataRoot + "/secrets/signer.json"
	c.ProfilesFile = c.DataRoot + "/config/profiles.json"
	c.Databases.Source = c.DataRoot + "/secrets/source.url"
	c.Databases.Publisher = c.DataRoot + "/secrets/publisher.url"
	c.Databases.Registrar = c.DataRoot + "/secrets/registrar.url"
	require.NoError(t, c.Validate())
	c.Controller.Endpoint = "https://100.72.1.1:9443"
	require.Error(t, c.Validate())
}

func TestControllerProfilesRequireBoundedTypedSelfEnrollment(t *testing.T) {
	sum := sha256.Sum256([]byte("synthetic-profile"))
	good := Profiles{Schema: 1, Nodes: map[string]NodeProfile{nodeID: {SecurityFingerprint: fmt.Sprintf("%x", sum)}}}
	raw, err := json.Marshal(good)
	require.NoError(t, err)
	profiles, err := ParseProfiles(raw, clusterID, nodeID)
	require.NoError(t, err)
	assert.Equal(t, good, profiles)
	invalid := []string{
		`{"schema":1,"nodes":{}}`,
		`{"schema":2,"nodes":{}}`,
		`{"schema":1,"nodes":{"unknown":{"security_fingerprint":"private-secret"}}}`,
		strings.Replace(string(raw), fmt.Sprintf("%x", sum), "private-secret", 1),
		strings.Replace(string(raw), `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.Replace(string(raw), `"schema":1`, `"schema":1,"private_field":"private-secret"`, 1),
		strings.Replace(string(raw), nodeID, controllerID, 1),
		string(raw) + `{}`,
	}
	for _, input := range invalid {
		_, err := ParseProfiles([]byte(input), clusterID, nodeID)
		require.ErrorIs(t, err, ErrInvalid)
		assert.NotContains(t, err.Error(), "private-secret")
	}
}

func TestStrictJSONRejectsCaseAndUnicodeAliasesInSignerFields(t *testing.T) {
	var signer struct {
		KeyID string `json:"key_id"`
		Seed  string `json:"seed"`
	}
	for _, raw := range []string{
		`{"key_id":"one","Key_ID":"two","seed":"private-secret"}`,
		`{"key_id":"one","Key_id":"two","seed":"private-secret"}`,
		`{"key_id":"one","seed":"private-secret","ſeed":"other-secret"}`,
	} {
		require.ErrorIs(t, strictJSON([]byte(raw), &signer), ErrInvalid)
	}
}

func TestRuntimeConfigReservesEntireCacheNamespace(t *testing.T) {
	for _, location := range []string{"state.json", "manifests/operator.json", "blobs/node.key"} {
		c := document("/var/lib/rauth")
		c.PrivateKeyFile = c.CacheRoot + "/" + location
		require.ErrorIs(t, c.Validate(), ErrInvalid)
	}
	c := document("/var/lib/rauth")
	c.PrivateKeyFile = "/var/lib/rauth/cache-old/node.key"
	require.NoError(t, c.Validate(), "a sibling with a similar prefix is independent of the cache")
	c.PrivateKeyFile = "/var/lib/rauth/cache-parent"
	c.CacheRoot = c.PrivateKeyFile + "/cache"
	require.ErrorIs(t, c.Validate(), ErrInvalid, "a protected file cannot be the cache's parent either")
}
