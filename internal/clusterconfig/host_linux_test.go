//go:build linux

package clusterconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"rauth/internal/clustertransport"
	"syscall"
	"testing"
	"time"
)

func writeFixture(t *testing.T, path string, body []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, body, 0o600))
}
func loadedFixture(t *testing.T, role string) (string, Config) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0o700))
	c := document(root)
	c.Role = role
	writeFixture(t, c.CookieSecretFile, []byte("synthetic-cookie-secret-file-content-1234567890"))
	writeFixture(t, c.AuthStateKeyFile, []byte(`{"synthetic":"validated by SQL authority initializer"}`))
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-node-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	require.NoError(t, err)
	uri, err := clustertransport.NodeURI(c.ClusterID, c.NodeID)
	require.NoError(t, err)
	_, nodeKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{uri}, IPAddresses: []net.IP{net.ParseIP(c.ServiceIP)}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, nodeKey.Public(), caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(nodeKey)
	require.NoError(t, err)
	writeFixture(t, c.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	writeFixture(t, c.CertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	writeFixture(t, c.PrivateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if role == Control {
		c.Controller.NodeID = c.NodeID
		c.Controller.Endpoint = "https://100.72.1.2:9443"
		leaf, err := x509.ParseCertificate(leafDER)
		require.NoError(t, err)
		pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		c.Controller.Pins = []string{base64.StdEncoding.EncodeToString(pin[:])}
		c.SignerFile = root + "/secrets/signer.json"
		c.ProfilesFile = root + "/config/profiles.json"
		c.Databases.Source = root + "/secrets/source.url"
		c.Databases.Publisher = root + "/secrets/publisher.url"
		c.Databases.Registrar = root + "/secrets/registrar.url"
		signer, err := json.Marshal(map[string]string{"key_id": "one", "seed": base64.StdEncoding.EncodeToString(policyKey().Seed())})
		require.NoError(t, err)
		writeFixture(t, c.SignerFile, signer)
		fingerprint := sha256.Sum256([]byte("synthetic-security-profile"))
		profiles, err := json.Marshal(Profiles{Schema: 1, Nodes: map[string]NodeProfile{c.NodeID: {SecurityFingerprint: hex.EncodeToString(fingerprint[:])}}})
		require.NoError(t, err)
		writeFixture(t, c.ProfilesFile, profiles)
	}
	for _, filename := range []string{c.Databases.Auth, c.Databases.Head, c.Databases.Payload, c.Databases.Source, c.Databases.Publisher, c.Databases.Registry, c.Databases.Registrar} {
		if filename != "" {
			writeFixture(t, filename, []byte("postgres://test:synthetic-database-password@100.72.99.1:6543/auth?sslmode=verify-full&target_session_attrs=read-write"))
		}
	}
	filename := root + "/config/node.json"
	raw, err := json.Marshal(c)
	require.NoError(t, err)
	writeFixture(t, filename, raw)
	return filename, c
}
func TestPrivateHostFileRejectsSymlinkFIFOAndBroadPermissions(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "private.json")
	writeFixture(t, file, []byte("private"))
	body, err := readPrivate(file, 100)
	require.NoError(t, err)
	assert.Equal(t, "private", string(body))
	require.NoError(t, os.Chmod(file, 0o640))
	_, err = readPrivate(file, 100)
	require.ErrorIs(t, err, ErrPrivateFile)
	require.NoError(t, os.Chmod(file, 0o600))
	_, err = readPrivate(file, 3)
	require.ErrorIs(t, err, ErrPrivateFile)
	link := filepath.Join(root, "link")
	require.NoError(t, os.Symlink(file, link))
	_, err = readPrivate(link, 100)
	require.ErrorIs(t, err, ErrPrivateFile)
	directoryLink := filepath.Join(t.TempDir(), "redirect")
	require.NoError(t, os.Symlink(root, directoryLink))
	_, err = readPrivate(filepath.Join(directoryLink, "private.json"), 100)
	require.ErrorIs(t, err, ErrPrivateFile, "a symlink in an ancestor must not escape the host tree")
	fifo := filepath.Join(root, "pipe")
	require.NoError(t, unix.Mkfifo(fifo, 0o600))
	_, err = readPrivate(fifo, 100)
	require.ErrorIs(t, err, ErrPrivateFile)
	if os.Geteuid() == 0 {
		require.NoError(t, os.Chown(file, 12345, 12345))
		_, err = readPrivate(file, 100)
		require.ErrorIs(t, err, ErrPrivateFile)
	}
}
func TestMountGuardRequiresExactWritablePersistentMount(t *testing.T) {
	good := "100 90 8:1 /rauth /var/lib/rauth rw,relatime - ext4 /dev/sda1 rw\n"
	require.NoError(t, matchingMount(good, "/var/lib/rauth", "8:1", "ext4"))
	for _, raw := range []string{"", bytes.NewBufferString(good).String() + good, "100 90 8:1 / /var/lib/rauth ro - ext4 /dev/sda1 rw", "100 90 0:1 / /var/lib/rauth rw - overlay overlay rw", "100 90 8:2 / /var/lib/rauth rw - ext4 /dev/sdb1 rw", "100 90 8:1 / /var/lib/rauth rw - ext4 /dev/sda1 ro"} {
		require.ErrorIs(t, matchingMount(raw, "/var/lib/rauth", "8:1", "ext4"), ErrMount)
	}
	c := document(t.TempDir())
	require.ErrorIs(t, validateMount(c), ErrMount, "an ordinary system-disk directory is never a substitute")
}
func TestRuntimeLoadWorkerAndControllerKeepSecretsPrivate(t *testing.T) {
	for _, role := range []string{Worker, Control} {
		t.Run(role, func(t *testing.T) {
			file, c := loadedFixture(t, role)
			called := false
			loaded, err := load(file, func(got Config) error { called = true; assert.Equal(t, c, got); return nil })
			require.NoError(t, err)
			assert.True(t, called)
			assert.Equal(t, role, loaded.Config().Role)
			assert.Equal(t, "synthetic-cookie-secret-file-content-1234567890", loaded.CookieSecret())
			clone := loaded.Config()
			clone.PolicyKeys["one"] = "caller-mutated"
			assert.NotEqual(t, clone.PolicyKeys, loaded.Config().PolicyKeys)
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			logger.Info("node", "loaded", loaded)
			assert.NotContains(t, output.String(), "synthetic-database-password")
			assert.NotContains(t, output.String(), "synthetic-cookie-secret-file-content")
			assert.NotContains(t, output.String(), base64.StdEncoding.EncodeToString(policyKey().Seed()))
			id, key := loaded.Signer()
			if role == Worker {
				assert.Empty(t, id)
				assert.Empty(t, key)
				assert.Empty(t, loaded.DatabaseURL("publisher"))
				assert.Empty(t, loaded.DatabaseURL("registrar"))
			} else {
				assert.Equal(t, "one", id)
				key[0] ^= 0xff
				_, again := loaded.Signer()
				assert.NotEqual(t, key, again)
				profiles := loaded.Profiles()
				delete(profiles, nodeID)
				assert.Contains(t, loaded.Profiles(), nodeID)
			}
		})
	}
}
func TestRuntimeLoadStopsBeforeSecretsOnMountFailure(t *testing.T) {
	file, c := loadedFixture(t, Worker)
	require.NoError(t, os.Remove(c.PrivateKeyFile))
	_, err := load(file, func(Config) error { return ErrMount })
	require.ErrorIs(t, err, ErrMount)
}
func TestRuntimeLoadRejectsWrongSignerAndPlaintextDatabase(t *testing.T) {
	file, c := loadedFixture(t, Control)
	writeFixture(t, c.SignerFile, []byte(`{"key_id":"one","seed":"private-secret-not-base64"}`))
	_, err := load(file, func(Config) error { return nil })
	require.ErrorIs(t, err, ErrInvalid)
	assert.NotContains(t, err.Error(), "private-secret")
	file, c = loadedFixture(t, Worker)
	writeFixture(t, c.Databases.Head, []byte("postgres://test:private-secret@127.0.0.1/test?sslmode=disable"))
	_, err = load(file, func(Config) error { return nil })
	require.ErrorIs(t, err, ErrInvalid)
	assert.NotContains(t, err.Error(), "private-secret")
}

func TestRuntimeLoadRejectsKeyPurposeReuseAndUnenrolledCertificates(t *testing.T) {
	for _, change := range []string{"node-key", "ca-key", "wrong-node", "wrong-ip", "ca-private-key"} {
		t.Run(change, func(t *testing.T) {
			file, c := loadedFixture(t, Worker)
			switch change {
			case "node-key", "ca-key":
				certPath := c.CertificateFile
				if change == "ca-key" {
					certPath = c.CAFile
				}
				body, err := os.ReadFile(certPath)
				require.NoError(t, err)
				block, _ := pem.Decode(body)
				cert, err := x509.ParseCertificate(block.Bytes)
				require.NoError(t, err)
				c.PolicyKeys["one"] = base64.StdEncoding.EncodeToString(cert.PublicKey.(ed25519.PublicKey))
			case "wrong-node":
				c.NodeID = "c648412c-b393-4c2d-a43c-8ec65a74e3af"
			case "wrong-ip":
				c.ServiceIP = "100.72.1.3"
			case "ca-private-key":
				key, err := os.ReadFile(c.PrivateKeyFile)
				require.NoError(t, err)
				ca, err := os.ReadFile(c.CAFile)
				require.NoError(t, err)
				writeFixture(t, c.CAFile, append(ca, key...))
			}
			raw, err := json.Marshal(c)
			require.NoError(t, err)
			writeFixture(t, file, raw)
			_, err = load(file, func(Config) error { return nil })
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}
func TestRuntimeLoadRequiresWritableLeaderAndValidProfiles(t *testing.T) {
	for _, suffix := range []string{"", "&target_session_attrs=read-only", "&target_session_attrs=read-write&target_session_attrs=any"} {
		file, c := loadedFixture(t, Worker)
		writeFixture(t, c.Databases.Head, []byte("postgres://test:private-secret@100.72.99.1/auth?sslmode=verify-full"+suffix))
		_, err := load(file, func(Config) error { return nil })
		require.ErrorIs(t, err, ErrInvalid)
		assert.NotContains(t, err.Error(), "private-secret")
	}
	file, c := loadedFixture(t, Control)
	writeFixture(t, c.ProfilesFile, []byte(`{"schema":1,"nodes":{}}`))
	_, err := load(file, func(Config) error { return nil })
	require.ErrorIs(t, err, ErrInvalid)
}

func TestRuntimeLoadRejectsNodeDocumentInCacheNamespace(t *testing.T) {
	filename, c := loadedFixture(t, Worker)
	body, err := os.ReadFile(filename)
	require.NoError(t, err)
	nested := c.CacheRoot + "/state.json"
	writeFixture(t, nested, body)
	checked := false
	_, err = load(nested, func(Config) error { checked = true; return nil })
	require.ErrorIs(t, err, ErrInvalid)
	assert.False(t, checked, "cache collision is rejected before mount/secret loading")
}

func TestCacheAndGeoSourceDirectoriesStayOnValidatedPersistence(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0o700))
	c := document(root)
	info, err := os.Stat(root)
	require.NoError(t, err)
	stat := info.Sys().(*syscall.Stat_t)
	c.MountDevice = fmt.Sprintf("%d:%d", unix.Major(uint64(stat.Dev)), unix.Minor(uint64(stat.Dev)))
	require.ErrorIs(t, validateCacheRoot(c), ErrMount, "missing cache must never be created on fallback storage")
	require.NoError(t, os.Mkdir(c.CacheRoot, 0o700))
	require.NoError(t, validateCacheRoot(c))
	require.NoError(t, os.Chmod(c.CacheRoot, 0o777))
	require.ErrorIs(t, validateCacheRoot(c), ErrMount)
	require.NoError(t, os.Chmod(c.CacheRoot, 0o700))
	c.Role = Control
	c.GeoIPFile = root + "/geo/source.mmdb"
	require.ErrorIs(t, validateSourceDirectory(c), ErrMount)
	require.NoError(t, os.Mkdir(root+"/geo", 0o700))
	require.NoError(t, validateSourceDirectory(c))
	writeFixture(t, c.GeoIPFile, []byte("synthetic-public-geo-bytes"))
	require.NoError(t, os.Chmod(c.GeoIPFile, 0o644))
	source, err := openGeoSource(c)
	require.NoError(t, err)
	require.NoError(t, source.Close())
	require.NoError(t, os.Chmod(c.GeoIPFile, 0o666))
	_, err = openGeoSource(c)
	require.ErrorIs(t, err, ErrPrivateFile)
	link := root + "/linked-cache"
	require.NoError(t, os.Symlink(c.CacheRoot, link))
	c.CacheRoot = link
	require.ErrorIs(t, validateCacheRoot(c), ErrMount)
}

func TestEventHostLoadNoWorkerDatabaseAndNoDirectoryFallback(t *testing.T) {
	for _, role := range []string{Worker, Control} {
		t.Run(role, func(t *testing.T) {
			file, c := loadedFixture(t, role)
			c.Events = &EventConfig{LocalRoot: c.DataRoot + "/events", NodeName: role}
			if role == Control {
				c.Databases.Events = c.DataRoot + "/secrets/events.url"
				writeFixture(t, c.Databases.Events, []byte("postgres://events:synthetic-event-password@100.72.99.1:6543/events?sslmode=verify-full&target_session_attrs=read-write"))
			}
			raw, err := json.Marshal(c)
			require.NoError(t, err)
			writeFixture(t, file, raw)
			loaded, err := load(file, func(Config) error { return nil })
			require.NoError(t, err)
			if role == Worker {
				require.Empty(t, loaded.DatabaseURL("events"))
			} else {
				require.NotEmpty(t, loaded.DatabaseURL("events"))
			}
			require.ErrorIs(t, loaded.CheckEventRoot(), ErrMount)
			_, err = os.Stat(c.Events.LocalRoot)
			require.True(t, os.IsNotExist(err))
			require.NoError(t, os.Mkdir(c.Events.LocalRoot, 0o700))
			info, err := os.Stat(c.Events.LocalRoot)
			require.NoError(t, err)
			stat := info.Sys().(*syscall.Stat_t)
			loaded.config.MountDevice = fmt.Sprintf("%d:%d", unix.Major(uint64(stat.Dev)), unix.Minor(uint64(stat.Dev)))
			require.NoError(t, loaded.CheckEventRoot())
			clone := loaded.Config()
			clone.Events.NodeName = "mutated"
			require.Equal(t, role, loaded.Config().Events.NodeName)
		})
	}
}

func TestEventOperatorCredentialIsGuardedAndNeverAvailableToWorkers(t *testing.T) {
	for _, role := range []string{Control, Worker} {
		t.Run(role, func(t *testing.T) {
			file, c := loadedFixture(t, role)
			c.Events = &EventConfig{LocalRoot: c.DataRoot + "/events", NodeName: role}
			if role == Control {
				c.Databases.Events = c.DataRoot + "/secrets/events.url"
				writeFixture(t, c.Databases.Events, []byte("postgres://events:synthetic-events@100.72.99.1:6543/events?sslmode=verify-full&target_session_attrs=read-write"))
			}
			raw, err := json.Marshal(c)
			require.NoError(t, err)
			writeFixture(t, file, raw)
			loaded, err := load(file, func(Config) error { return nil })
			require.NoError(t, err)
			operator := c.DataRoot + "/config/event-operator.url"
			writeFixture(t, operator, []byte("postgres://owner:synthetic-operator@100.72.99.1:6543/events?sslmode=verify-full&target_session_attrs=read-write"))
			dsn, err := loaded.EventOperatorURL(operator)
			if role == Worker {
				require.ErrorIs(t, err, ErrInvalid)
				require.Empty(t, dsn)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, dsn)
			for _, bad := range []string{c.CacheRoot + "/operator.url", c.Events.LocalRoot + "/operator.url", "/outside/operator.url"} {
				_, err = loaded.EventOperatorURL(bad)
				require.Error(t, err)
			}
			require.NoError(t, os.Chmod(operator, 0o644))
			_, err = loaded.EventOperatorURL(operator)
			require.ErrorIs(t, err, ErrPrivateFile)
			writeFixture(t, operator, []byte("postgres://owner:synthetic-operator@100.72.99.1:6543/events?sslmode=disable&target_session_attrs=read-write"))
			_, err = loaded.EventOperatorURL(operator)
			require.Error(t, err)
		})
	}
}
