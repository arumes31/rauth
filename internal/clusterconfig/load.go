package clusterconfig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"log/slog"
	"net/url"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clustertransport"
	"strings"
	"time"
)

type Loaded struct {
	cookieSecret string
	config       Config
	certificate  tls.Certificate
	roots        *x509.CertPool
	verifier     *clusterpolicy.Verifier
	databases    map[string]string
	signerID     string
	signer       ed25519.PrivateKey
	profiles     Profiles
}

// LogValue prevents accidental whole-configuration logging from disclosing keys
// or database credentials. Callers still must never log individual secret values.
func (l *Loaded) LogValue() slog.Value {
	return slog.GroupValue(slog.String("role", l.config.Role), slog.String("node_id", l.config.NodeID))
}
func (l *Loaded) Config() Config {
	raw, _ := json.Marshal(l.config)
	var clone Config
	_ = json.Unmarshal(raw, &clone)
	return clone
}
func (l *Loaded) CheckCacheRoot() error {
	if err := validateCacheRoot(l.config); err != nil {
		return err
	}
	return validateSourceDirectory(l.config)
}
func (l *Loaded) CheckEventRoot() error {
	if l.config.Events == nil {
		return ErrInvalid
	}
	return validateEventDirectory(l.config)
}

func (l *Loaded) CookieSecret() string { return l.cookieSecret }
func (l *Loaded) OpenGeoIP(ctx context.Context) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if l.config.Role != Control || l.config.GeoIPFile == "" {
		return nil, ErrInvalid
	}
	return openGeoSource(l.config)
}
func (l *Loaded) Verifier() *clusterpolicy.Verifier    { return l.verifier }
func (l *Loaded) DatabaseURL(name string) string       { return l.databases[name] }
func (l *Loaded) Signer() (string, ed25519.PrivateKey) { return l.signerID, bytes.Clone(l.signer) }
func (l *Loaded) Profiles() map[string]NodeProfile {
	clone := make(map[string]NodeProfile, len(l.profiles.Nodes))
	for id, profile := range l.profiles.Nodes {
		clone[id] = profile
	}
	return clone
}
func (l *Loaded) ServerTLS() (*tls.Config, error) {
	return clustertransport.ServerTLS(l.certificate, l.roots, l.config.ClusterID, l.config.NodeID)
}
func (l *Loaded) ControllerClient() (*clustertransport.Client, error) {
	pins, err := l.config.ControllerPins()
	if err != nil {
		return nil, err
	}
	return clustertransport.NewClient(clustertransport.ClientConfig{Endpoint: l.config.Controller.Endpoint, LocalServiceIP: l.config.ServiceIP, ClusterID: l.config.ClusterID, LocalNodeID: l.config.NodeID, RemoteNodeID: l.config.Controller.NodeID, RemoteKeys: pins, Certificate: l.certificate, Roots: l.roots})
}

// Load validates its existing host mount before reading further node files. It
// never creates directories or substitutes a writable container/system path.
func Load(filename string) (*Loaded, error) { return load(filename, validateMount) }
func load(filename string, checkMount func(Config) error) (*Loaded, error) {
	raw, err := readPrivate(filename, 64<<10)
	if err != nil {
		return nil, err
	}
	c, err := Parse(raw)
	if err != nil || !inside(c.DataRoot, filename) || filename == c.CacheRoot || inside(c.CacheRoot, filename) || inside(filename, c.CacheRoot) || (c.Events != nil && (filename == c.Events.LocalRoot || inside(c.Events.LocalRoot, filename) || inside(filename, c.Events.LocalRoot))) {
		return nil, ErrInvalid
	}
	if err = checkMount(c); err != nil {
		return nil, err
	}
	loaded := &Loaded{config: c, databases: map[string]string{}}
	secret, e := readPrivate(c.CookieSecretFile, 4096)
	if e != nil {
		return nil, e
	}
	loaded.cookieSecret = strings.TrimSpace(string(secret))
	if loaded.cookieSecret == "" {
		return nil, ErrInvalid
	}
	if _, e = readPrivate(c.AuthStateKeyFile, 64<<10); e != nil {
		return nil, e
	}
	loaded.verifier, err = c.Verifier()
	if err != nil {
		return nil, ErrInvalid
	}
	cert, err := readPrivate(c.CertificateFile, 128<<10)
	if err != nil {
		return nil, err
	}
	key, err := readPrivate(c.PrivateKeyFile, 16<<10)
	if err != nil {
		return nil, err
	}
	loaded.certificate, err = tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, ErrInvalid
	}
	ca, err := readPrivate(c.CAFile, 128<<10)
	if err != nil {
		return nil, err
	}
	loaded.roots = x509.NewCertPool()
	caKeys := [][]byte{}
	rootsSeen := 0
	for len(bytes.TrimSpace(ca)) > 0 {
		block, rest := pem.Decode(ca)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrInvalid
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, ErrInvalid
		}
		rootsSeen++
		if rootsSeen > 3 {
			return nil, ErrInvalid
		}
		loaded.roots.AddCert(cert)
		caKeys = append(caKeys, cert.RawSubjectPublicKeyInfo)
		ca = rest
	}
	if rootsSeen == 0 {
		return nil, ErrInvalid
	}
	if _, err = loaded.ServerTLS(); err != nil {
		return nil, ErrInvalid
	}
	leaf, err := x509.ParseCertificate(loaded.certificate.Certificate[0])
	if err != nil || leaf.VerifyHostname(c.ServiceIP) != nil {
		return nil, ErrInvalid
	}
	for _, der := range loaded.certificate.Certificate[1:] {
		chainCert, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, ErrInvalid
		}
		caKeys = append(caKeys, chainCert.RawSubjectPublicKeyInfo)
	}
	for _, encoded := range c.PolicyKeys {
		key, _ := decode(encoded, ed25519.PublicKeySize)
		public, e := x509.MarshalPKIXPublicKey(ed25519.PublicKey(key))
		if e != nil {
			return nil, ErrInvalid
		}
		if bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
			return nil, ErrInvalid
		}
		for _, caKey := range caKeys {
			if bytes.Equal(public, caKey) {
				return nil, ErrInvalid
			}
		}
	}
	if c.Role == Control {
		pins, _ := c.ControllerPins()
		self := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		found := false
		for _, pin := range pins {
			found = found || pin == self
		}
		if !found {
			return nil, ErrInvalid
		}
	}
	client, err := loaded.ControllerClient()
	if err != nil {
		return nil, ErrInvalid
	}
	client.CloseIdleConnections()
	paths := map[string]string{"auth": c.Databases.Auth, "head": c.Databases.Head, "payload": c.Databases.Payload, "registry": c.Databases.Registry}
	if c.Role == Control {
		if c.Events != nil {
			paths["events"] = c.Databases.Events
		}
		paths["source"] = c.Databases.Source
		paths["registrar"] = c.Databases.Registrar
		paths["publisher"] = c.Databases.Publisher
	}
	for name, filename := range paths {
		dsn, e := databaseFileURL(filename)
		if e != nil {
			return nil, e
		}
		loaded.databases[name] = dsn
	}
	if c.Role == Control {
		body, e := readPrivate(c.SignerFile, 4096)
		if e != nil {
			return nil, e
		}
		var signer struct {
			KeyID string `json:"key_id"`
			Seed  string `json:"seed"`
		}
		if strictJSON(body, &signer) != nil {
			return nil, ErrInvalid
		}
		seed, e := decode(signer.Seed, ed25519.SeedSize)
		if e != nil {
			return nil, ErrInvalid
		}
		loaded.signer = ed25519.NewKeyFromSeed(seed)
		loaded.signerID = signer.KeyID
		sum := sha256.Sum256(nil)
		probe := clusterpolicy.Manifest{Schema: 1, ClusterID: c.ClusterID, Revision: 1, PublishedAt: time.Unix(1, 0).UTC(), Blobs: []clusterpolicy.Blob{{Kind: "policy", ID: "policy", SHA256: hex.EncodeToString(sum[:]), Bytes: 0}}}
		envelope, e := clusterpolicy.Sign(probe, loaded.signerID, loaded.signer)
		if e != nil {
			return nil, ErrInvalid
		}
		if _, e = loaded.verifier.Verify(envelope); e != nil {
			return nil, ErrInvalid
		}
		profiles, e := readPrivate(c.ProfilesFile, 64<<10)
		if e != nil {
			return nil, e
		}
		loaded.profiles, e = ParseProfiles(profiles, c.ClusterID, c.NodeID)
		if e != nil {
			return nil, ErrInvalid
		}
	}
	return loaded, nil
}

// EventOperatorURL is deliberately separate from runtime database credentials.
// It reads an existing guarded private host file for offline operator tooling.
// Worker nodes cannot load an event operator credential.
func (l *Loaded) EventOperatorURL(filename string) (string, error) {
	c := l.config
	if c.Role != Control || c.Events == nil || !inside(c.DataRoot, filename) || filename == c.CacheRoot || inside(c.CacheRoot, filename) || filename == c.Events.LocalRoot || inside(c.Events.LocalRoot, filename) {
		return "", ErrInvalid
	}
	return databaseFileURL(filename)
}
func databaseFileURL(filename string) (string, error) {
	body, e := readPrivate(filename, 8192)
	if e != nil {
		return "", e
	}
	dsn := strings.TrimSpace(string(body))
	if dsn == "" {
		return "", ErrInvalid
	}
	// Require explicit leader selection, rather than allowing a first
	// reachable standby to become the authority after failover.
	u, e := url.Parse(dsn)
	if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" || u.User == nil || u.User.Username() == "" || (u.Path == "" || u.Path == "/") || u.Fragment != "" {
		return "", ErrInvalid
	}
	query, e := url.ParseQuery(u.RawQuery)
	if e != nil || len(query["target_session_attrs"]) != 1 || query.Get("target_session_attrs") != "read-write" || len(query["sslmode"]) != 1 || query.Get("sslmode") != "verify-full" {
		return "", ErrInvalid
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil || cfg.ConnConfig.TLSConfig == nil || cfg.ConnConfig.TLSConfig.InsecureSkipVerify || cfg.ConnConfig.TLSConfig.ServerName == "" {
		return "", ErrInvalid
	}
	for _, fallback := range cfg.ConnConfig.Fallbacks {
		if fallback.TLSConfig == nil || fallback.TLSConfig.InsecureSkipVerify || fallback.TLSConfig.ServerName == "" {
			return "", ErrInvalid
		}
	}
	return dsn, nil
}
