// Package clusterconfig loads opt-in Linux node configuration and host secrets.
// It does not enroll nodes, migrate state or start network listeners.
package clusterconfig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"path"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clustertransport"
	"strconv"
	"strings"
	"unicode"
)

const Control = "control"
const Worker = "worker"

var ErrInvalid = errors.New("invalid cluster runtime configuration")
var ErrPrivateFile = errors.New("cluster host file is missing, unsafe or unreadable")
var ErrMount = errors.New("cluster persistence is not on its required host bind mount")
var ErrUnsupported = errors.New("cluster runtime host files require Linux")

type DatabaseFiles struct {
	Head      string `json:"head"`
	Registry  string `json:"registry"`
	Registrar string `json:"registrar,omitempty"`
	Payload   string `json:"payload"`
	Source    string `json:"source,omitempty"`
	Publisher string `json:"publisher,omitempty"`
}
type Controller struct {
	NodeID   string   `json:"node_id"`
	Endpoint string   `json:"endpoint"`
	Pins     []string `json:"spki_sha256"`
}
type Config struct {
	Schema          int               `json:"schema"`
	Role            string            `json:"role"`
	ClusterID       string            `json:"cluster_id"`
	NodeID          string            `json:"node_id"`
	ServiceIP       string            `json:"service_ip"`
	PrivatePort     int               `json:"private_port"`
	DataRoot        string            `json:"data_root"`
	MountDevice     string            `json:"mount_device"`
	MountFilesystem string            `json:"mount_filesystem"`
	CacheRoot       string            `json:"cache_root"`
	CertificateFile string            `json:"certificate_file"`
	PrivateKeyFile  string            `json:"private_key_file"`
	CAFile          string            `json:"ca_file"`
	PolicyKeys      map[string]string `json:"policy_public_keys"`
	SignerFile      string            `json:"signer_file,omitempty"`
	ProfilesFile    string            `json:"profiles_file,omitempty"`
	Databases       DatabaseFiles     `json:"database_files"`
	Controller      Controller        `json:"controller"`
}

func inside(root, filename string) bool {
	return privatePath(filename) && strings.HasPrefix(filename, root+"/")
}
func privatePath(raw string) bool {
	return path.IsAbs(raw) && path.Clean(raw) == raw && raw != "/" && strings.IndexByte(raw, 0) < 0
}
func (c Config) Validate() error {
	if c.Schema != 1 || (c.Role != Control && c.Role != Worker) || !privatePath(c.DataRoot) || !inside(c.DataRoot, c.CacheRoot) {
		return ErrInvalid
	}
	if _, err := clustertransport.NodeURI(c.ClusterID, c.NodeID); err != nil {
		return ErrInvalid
	}
	if c.PrivatePort < 1024 || c.PrivatePort > 65535 {
		return ErrInvalid
	}
	ip, err := netip.ParseAddr(c.ServiceIP)
	if err != nil || ip.String() != c.ServiceIP {
		return ErrInvalid
	}
	if _, err = clustertransport.PrivateListenAddress(net.JoinHostPort(c.ServiceIP, strconv.Itoa(c.PrivatePort))); err != nil {
		return ErrInvalid
	}
	fields := strings.Split(c.MountDevice, ":")
	if len(fields) != 2 {
		return ErrInvalid
	}
	for _, part := range fields {
		value, e := strconv.ParseUint(part, 10, 32)
		if e != nil || strconv.FormatUint(value, 10) != part {
			return ErrInvalid
		}
	}
	switch c.MountFilesystem {
	case "ext4", "xfs", "btrfs", "zfs":
	default:
		return ErrInvalid
	}
	paths := []string{c.CertificateFile, c.PrivateKeyFile, c.CAFile, c.Databases.Head, c.Databases.Payload, c.Databases.Registry}
	if c.Role == Control {
		paths = append(paths, c.SignerFile, c.ProfilesFile, c.Databases.Source, c.Databases.Publisher, c.Databases.Registrar)
	} else if c.SignerFile != "" || c.ProfilesFile != "" || c.Databases.Source != "" || c.Databases.Publisher != "" || c.Databases.Registrar != "" {
		return ErrInvalid
	}
	seen := map[string]bool{c.CacheRoot: true}
	for _, filename := range paths {
		if !inside(c.DataRoot, filename) || seen[filename] || inside(c.CacheRoot, filename) || inside(filename, c.CacheRoot) {
			return ErrInvalid
		}
		seen[filename] = true
	}
	if len(c.PolicyKeys) < 1 || len(c.PolicyKeys) > 3 {
		return ErrInvalid
	}
	if _, err = c.Verifier(); err != nil {
		return err
	}
	if _, err = clustertransport.NodeURI(c.ClusterID, c.Controller.NodeID); err != nil {
		return ErrInvalid
	}
	endpoint, err := clustertransport.PrivateEndpoint(c.Controller.Endpoint)
	if err != nil {
		return ErrInvalid
	}
	if c.Role == Control && (c.Controller.NodeID != c.NodeID || endpoint.Host != net.JoinHostPort(c.ServiceIP, strconv.Itoa(c.PrivatePort))) {
		return ErrInvalid
	}
	if c.Role == Worker && c.Controller.NodeID == c.NodeID {
		return ErrInvalid
	}
	_, err = c.ControllerPins()
	return err
}
func (c Config) Verifier() (*clusterpolicy.Verifier, error) {
	keys := map[string]ed25519.PublicKey{}
	for id, raw := range c.PolicyKeys {
		key, err := decode(raw, ed25519.PublicKeySize)
		if err != nil {
			return nil, ErrInvalid
		}
		keys[id] = ed25519.PublicKey(key)
	}
	return clusterpolicy.NewVerifier(c.ClusterID, keys)
}
func decode(raw string, size int) ([]byte, error) {
	if strings.ContainsAny(raw, "\r\n\t ") {
		return nil, ErrInvalid
	}
	value, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(value) != size {
		return nil, ErrInvalid
	}
	return value, nil
}
func (c Config) ControllerPins() ([][32]byte, error) {
	if len(c.Controller.Pins) < 1 || len(c.Controller.Pins) > 2 {
		return nil, ErrInvalid
	}
	pins := make([][32]byte, len(c.Controller.Pins))
	for i, raw := range c.Controller.Pins {
		pin, err := decode(raw, 32)
		if err != nil || bytes.Equal(pin, make([]byte, 32)) {
			return nil, ErrInvalid
		}
		copy(pins[i][:], pin)
		if i > 0 && pins[0] == pins[i] {
			return nil, ErrInvalid
		}
	}
	return pins, nil
}

// Parse accepts ordinary formatted operator JSON while rejecting duplicate,
// unknown/trailing fields. Errors never include submitted values or secrets.
func Parse(raw []byte) (Config, error) {
	var c Config
	if len(raw) == 0 || len(raw) > 64<<10 || strictJSON(raw, &c) != nil || c.Validate() != nil {
		return Config{}, ErrInvalid
	}
	return c, nil
}
func strictJSON(raw []byte, target any) error {
	tokens := json.NewDecoder(bytes.NewReader(raw))
	if uniqueValue(tokens, 0) != nil {
		return ErrInvalid
	}
	if _, err := tokens.Token(); err != io.EOF {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 20 {
		return ErrInvalid
	}
	token, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			token, e := d.Token()
			if e != nil {
				return ErrInvalid
			}
			key, ok := token.(string)
			// encoding/json matches struct fields by Unicode simple folding.
			// Distinct spellings that decode to one field are duplicates too.
			folded := foldJSONKey(key)
			if !ok || seen[folded] {
				return ErrInvalid
			}
			seen[folded] = true
			if uniqueValue(d, depth+1) != nil {
				return ErrInvalid
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for d.More() {
			if uniqueValue(d, depth+1) != nil {
				return ErrInvalid
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func foldJSONKey(key string) string {
	var folded strings.Builder
	for _, r := range key {
		smallest := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < smallest {
				smallest = next
			}
		}
		folded.WriteRune(smallest)
	}
	return folded.String()
}
