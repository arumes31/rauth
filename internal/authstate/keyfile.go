package authstate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// LoadKeyring reads the private host-mounted JSON file. Errors never include
// key material. Unlike environment defaults, missing/unknown keys are fatal.
func LoadKeyring(path string) (*Keyring, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("authentication key file must use an absolute path")
	}
	file, err := os.Open(path) // #nosec G304 -- Operator-only startup path, never HTTP input; absolute, regular-file and size checks bound this intended key read.
	if err != nil {
		return nil, errors.New("authentication key file cannot be opened")
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return nil, errors.New("authentication key file must be a regular file")
	}
	if err := validateKeyFilePermissions(file, stat); err != nil {
		return nil, err
	}
	const maxBytes = 16384
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return nil, errors.New("authentication key file exceeds limit or cannot be read")
	}
	var config struct {
		IndexKey       string            `json:"index_key"`
		ActiveKeyID    string            `json:"active_key_id"`
		EncryptionKeys map[string]string `json:"encryption_keys"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&config); err != nil {
		return nil, errors.New("invalid authentication key file")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("authentication key file has trailing content")
	}
	decode := func(value string) (string, error) {
		data, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(data) != 32 {
			return "", errors.New("authentication keys must be base64-encoded 32-byte values")
		}
		return string(data), nil
	}
	index, err := decode(config.IndexKey)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]string, len(config.EncryptionKeys))
	seen := map[string]bool{index: true}
	for id, value := range config.EncryptionKeys {
		secret, err := decode(value)
		if err != nil {
			return nil, err
		}
		if seen[secret] {
			return nil, errors.New("authentication index and encryption keys must be distinct")
		}
		seen[secret] = true
		keys[id] = secret
	}
	return NewKeyring(index, config.ActiveKeyID, keys)
}
