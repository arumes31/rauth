// Package authstate provides the transactional SQL security state used by the
// active-active deployment. It is not enabled by the legacy runtime yet.
package authstate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"regexp"

	"golang.org/x/crypto/hkdf"
)

var ErrKeyMismatch = errors.New("authentication state key configuration does not match the database")
var validKeyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// Keyring separates the stable token-index secret from rotatable encryption
// keys. Key IDs select exactly one key; decryption never tries arbitrary keys.
// Keep the index secret stable during encryption-key rotation. Changing it is
// an explicit all-session expiry operation, never a rolling-node change.
type Keyring struct {
	indexKey []byte
	active   string
	keys     map[string]cipher.AEAD
	checks   map[string][]byte
}

func derive(secret, purpose string) []byte {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(secret), nil, []byte(purpose)), key); err != nil {
		panic(err)
	}
	return key
}
func NewKeyring(indexSecret, activeID string, secrets map[string]string) (*Keyring, error) {
	if len(indexSecret) < 32 || len(secrets) == 0 || len(secrets) > 3 || !validKeyID.MatchString(activeID) {
		return nil, errors.New("invalid authentication state keyring")
	}
	k := &Keyring{indexKey: derive(indexSecret, "rauth-authstate-index-v1"), active: activeID, keys: map[string]cipher.AEAD{}, checks: map[string][]byte{}}
	for id, secret := range secrets {
		if !validKeyID.MatchString(id) || len(secret) < 32 {
			return nil, errors.New("invalid authentication state encryption key")
		}
		block, err := aes.NewCipher(derive(secret, "rauth-authstate-payload-v1"))
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		k.keys[id] = aead
		k.checks[id] = digest(derive(secret, "rauth-authstate-keycheck-v1"), []byte(id))
	}
	if k.keys[activeID] == nil {
		return nil, errors.New("active authentication state key is missing")
	}
	return k, nil
}
func digest(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}
func (k *Keyring) tokenHash(token string) ([]byte, error) {
	if len(token) < 32 || len(token) > 256 {
		return nil, errors.New("invalid session token")
	}
	return digest(k.indexKey, []byte(token)), nil
}
func aad(domain, id string, hash []byte) []byte {
	return append(append([]byte(domain+":"+id+":"), hash...), byte(0))
}
func (k *Keyring) seal(hash, payload []byte) (string, []byte, error) {
	return k.sealFor("rauth-session-v1", hash, payload)
}
func (k *Keyring) sealFor(domain string, hash, payload []byte) (string, []byte, error) {
	a := k.keys[k.active]
	nonce := make([]byte, a.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", nil, err
	}
	return k.active, a.Seal(nonce, nonce, payload, aad(domain, k.active, hash)), nil
}
func (k *Keyring) open(id string, hash, payload []byte) ([]byte, error) {
	return k.openFor("rauth-session-v1", id, hash, payload)
}
func (k *Keyring) openFor(domain, id string, hash, payload []byte) ([]byte, error) {
	a := k.keys[id]
	if a == nil || len(payload) < a.NonceSize()+a.Overhead() {
		return nil, errors.New("session payload could not be decrypted")
	}
	out, err := a.Open(nil, payload[:a.NonceSize()], payload[a.NonceSize():], aad(domain, id, hash))
	if err != nil {
		return nil, errors.New("session payload could not be decrypted")
	}
	return out, nil
}

func (k *Keyring) stateHash(kind, id string) []byte {
	return digest(k.indexKey, []byte(kind+"\x00"+id))
}
