// Package hostguard verifies host-attested bind sources before a container writer starts.
package hostguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strconv"
	"strings"
)

const MaxWitnessBytes = 64 << 10

var ErrGuard = errors.New("host storage guard verification failed")

type Target struct {
	Path       string
	Device     uint64
	Filesystem uint64
	Inode      uint64
	Writable   bool
}
type Witness struct {
	UUID, Role, BootID string
	Targets            []Target
}

var requiredTargets = map[string]map[string]bool{
	"tailscale": {"/var/lib/tailscale": true},
	"etcd":      {"/var/lib/etcd": true},
	"patroni":   {"/var/lib/postgresql": true, "/var/lib/rauth-wal": true, "/var/lib/rauth-archive": true},
	"router":    {"/etc/haproxy/haproxy.cfg": false, "/etc/rauth-router": false},
	"app":       {"/app/data": true},
	"observer":  {"/output": true, "/pki": false, "/observer/config.json": false, "/observer/observe.py": false},
}

func canonicalPath(p string) bool {
	if p == "/" || !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.Contains(p, "\\") || len(p) > 2048 {
		return false
	}
	for _, c := range p {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func identifier(s string) bool {
	if len(s) < 8 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
func object(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, ErrGuard
	}
	values := map[string]json.RawMessage{}
	for d.More() {
		t, err = d.Token()
		k, ok := t.(string)
		if err != nil || !ok || !allowed[k] || values[k] != nil {
			return nil, ErrGuard
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrGuard
		}
		values[k] = value
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') || len(values) != len(keys) {
		return nil, ErrGuard
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, ErrGuard
	}
	return values, nil
}
func text(raw json.RawMessage) (string, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil || len(s) == 0 {
		return "", ErrGuard
	}
	return s, nil
}
func integer(raw json.RawMessage) (uint64, error) {
	s, err := text(raw)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != s {
		return 0, ErrGuard
	}
	return n, nil
}

// Decode rejects aliases, duplicate keys, missing paths and ambiguous numeric encodings.
func Decode(raw []byte, uuid, role string) (Witness, error) {
	var w Witness
	if len(raw) == 0 || len(raw) > MaxWitnessBytes || !identifier(uuid) || requiredTargets[role] == nil {
		return w, ErrGuard
	}
	root, err := object(raw, "schema", "uuid", "role", "boot_id", "targets")
	if err != nil {
		return w, err
	}
	var schema int
	if json.Unmarshal(root["schema"], &schema) != nil || schema != 1 {
		return w, ErrGuard
	}
	w.UUID, err = text(root["uuid"])
	if err != nil || w.UUID != uuid {
		return Witness{}, ErrGuard
	}
	w.Role, err = text(root["role"])
	if err != nil || w.Role != role {
		return Witness{}, ErrGuard
	}
	w.BootID, err = text(root["boot_id"])
	if err != nil || !identifier(w.BootID) {
		return Witness{}, ErrGuard
	}
	var targets []json.RawMessage
	if json.Unmarshal(root["targets"], &targets) != nil || len(targets) == 0 || len(targets) > 64 {
		return Witness{}, ErrGuard
	}
	seen := map[string]bool{}
	for _, raw := range targets {
		row, err := object(raw, "path", "device", "fsid", "inode", "writable")
		if err != nil {
			return Witness{}, err
		}
		var t Target
		t.Path, err = text(row["path"])
		if err != nil || !canonicalPath(t.Path) || seen[t.Path] {
			return Witness{}, ErrGuard
		}
		seen[t.Path] = true
		if t.Device, err = integer(row["device"]); err != nil {
			return Witness{}, err
		}
		if t.Filesystem, err = integer(row["fsid"]); err != nil {
			return Witness{}, err
		}
		if t.Inode, err = integer(row["inode"]); err != nil || t.Inode == 0 {
			return Witness{}, ErrGuard
		}
		value := string(bytes.TrimSpace(row["writable"]))
		if value != "true" && value != "false" {
			return Witness{}, ErrGuard
		}
		t.Writable = value == "true"
		if want, ok := requiredTargets[role][t.Path]; ok && t.Writable != want {
			return Witness{}, ErrGuard
		}
		w.Targets = append(w.Targets, t)
	}
	for target := range requiredTargets[role] {
		if !seen[target] {
			return Witness{}, ErrGuard
		}
	}
	return w, nil
}
