package authstate

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
)

const SSOTransactionTTL = 5 * time.Minute
const SSOCodeTTL = 60 * time.Second

var ErrSSOInvalid = errors.New("SSO transaction is invalid or expired")

// SSOOrigin accepts only canonical exact HTTPS DNS origins on the standard
// port. Enrollment never inherits wildcard/suffix host or redirect permissions.
func SSOOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Host != strings.ToLower(u.Host) || u.Port() != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || raw != "https://"+u.Host || net.ParseIP(u.Host) != nil || len(u.Host) > 253 || !strings.Contains(u.Host, ".") {
		return false
	}
	for _, label := range strings.Split(u.Host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// SSOLocalReturn preserves opaque application paths and query strings. Check
// both raw and decoded leading separators, and reserve the integration paths.
func SSOLocalReturn(raw string) bool {
	if raw == "" || len(raw) > 4096 || strings.ContainsAny(raw, "\\\r\n") || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Opaque != "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || strings.Contains(u.Path, "\\") || strings.IndexFunc(u.Path, unicode.IsControl) >= 0 {
		return false
	}
	clean := path.Clean(u.Path)
	return clean != "/_rauth" && !strings.HasPrefix(clean, "/_rauth/")
}

type ssoPayload struct {
	ReturnURI string            `json:"return_uri"`
	IP        string            `json:"ip,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}

func (s *PostgresSessions) ssoHash(kind, value string) ([]byte, error) {
	if len(value) != 64 {
		return nil, ErrSSOInvalid
	}
	if _, err := hex.DecodeString(value); err != nil {
		return nil, ErrSSOInvalid
	}
	return s.keys.stateHash("sso:"+kind, value), nil
}
func (s *PostgresSessions) sealSSO(hash []byte, p ssoPayload) (string, []byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", nil, err
	}
	if len(b) > 16000 {
		return "", nil, ErrSSOInvalid
	}
	return s.keys.sealFor("rauth-sso-v1", hash, b)
}
func (s *PostgresSessions) openSSO(hash []byte, key string, body []byte) (ssoPayload, error) {
	var p ssoPayload
	b, err := s.keys.openFor("rauth-sso-v1", key, hash, body)
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(b, &p); err != nil || !SSOLocalReturn(p.ReturnURI) {
		return p, ErrSSOInvalid
	}
	return p, nil
}

func (s *PostgresSessions) BeginSSO(ctx context.Context, id, browser, origin, returnURI string) error {
	hash, err := s.ssoHash("transaction", id)
	if err != nil {
		return err
	}
	binding, err := s.ssoHash("browser", browser)
	if err != nil {
		return err
	}
	if !SSOOrigin(origin) || !SSOLocalReturn(returnURI) {
		return ErrSSOInvalid
	}
	key, body, err := s.sealSSO(hash, ssoPayload{ReturnURI: returnURI})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	_, err = s.pool.Exec(ctx, `INSERT INTO auth_sso_transactions(transaction_hash,browser_hash,origin,key_id,payload,expires_at)
 VALUES($1,$2,$3,$4,$5,clock_timestamp()+$6::interval)`, hash, binding, origin, key, body, SSOTransactionTTL.String())
	return sqlError(err)
}

// AuthorizeSSO holds the same generation/family locks as rotation/revocation.
// A retired token cannot authorize a new code. The caller may first follow a
// validated grace successor. Repeated authorization never replaces a live code.
func (s *PostgresSessions) AuthorizeSSO(ctx context.Context, id, code, sourceToken string) (string, error) {
	hash, err := s.ssoHash("transaction", id)
	if err != nil {
		return "", err
	}
	codeHash, err := s.ssoHash("code", code)
	if err != nil {
		return "", err
	}
	source, err := s.keys.tokenHash(sourceToken)
	if err != nil {
		return "", ErrSSOInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	var origin string
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		r, _, err := s.locked(ctx, tx, source)
		if err != nil {
			return err
		}
		if r.retired || r.audience != "" {
			return ErrSSOInvalid
		}
		session, err := s.decode(r)
		if err != nil {
			return err
		}
		var key string
		var body []byte
		err = tx.QueryRow(ctx, `SELECT origin,key_id,payload FROM auth_sso_transactions WHERE transaction_hash=$1
   AND expires_at>clock_timestamp() AND code_hash IS NULL AND consumed_at IS NULL FOR UPDATE`, hash).Scan(&origin, &key, &body)
		if err != nil {
			return sqlError(err)
		}
		p, err := s.openSSO(hash, key, body)
		if err != nil {
			return err
		}
		p.IP = session.IP
		p.Fields = session.Fields
		key, body, err = s.sealSSO(hash, p)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE auth_sso_transactions SET code_hash=$2,code_expires_at=LEAST(expires_at,clock_timestamp()+$3::interval),
   family_id=$4,auth_gen=$5,key_id=$6,payload=$7 WHERE transaction_hash=$1 AND expires_at>clock_timestamp()`, hash, codeHash, SSOCodeTTL.String(), r.family, r.generation, key, body)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrSSOInvalid
		}
		return err
	})
	return origin, sqlError(err)
}

// RedeemSSO consumes a browser- and exact-origin-bound code and creates the
// audience-restricted child token in one transaction. Failed binding or token
// conflicts roll back consumption. Generation -> family -> transaction is the
// common lock order, so logout and credential changes cannot revive access.
func (s *PostgresSessions) RedeemSSO(ctx context.Context, id, code, browser, origin, newToken string, idleTTL time.Duration) (string, error) {
	hash, err := s.ssoHash("transaction", id)
	if err != nil {
		return "", err
	}
	codeHash, err := s.ssoHash("code", code)
	if err != nil {
		return "", err
	}
	binding, err := s.ssoHash("browser", browser)
	if err != nil {
		return "", err
	}
	newHash, err := s.keys.tokenHash(newToken)
	if err != nil {
		return "", err
	}
	if !SSOOrigin(origin) || !validTTL(idleTTL) {
		return "", ErrSSOInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	var returnURI string
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var family, user string
		err := tx.QueryRow(ctx, `SELECT f.id::text,f.username FROM auth_sso_transactions t JOIN auth_session_families f ON f.id=t.family_id
   WHERE t.transaction_hash=$1`, hash).Scan(&family, &user)
		if err != nil {
			return sqlError(err)
		}
		gen, err := lockGeneration(ctx, tx, user)
		if err != nil {
			return err
		}
		var familyGen int64
		var absolute time.Time
		var revoked *time.Time
		err = tx.QueryRow(ctx, `SELECT auth_gen,absolute_expires_at,revoked_at FROM auth_session_families WHERE id=$1 FOR UPDATE`, family).Scan(&familyGen, &absolute, &revoked)
		if err != nil {
			return sqlError(err)
		}
		var wantCode, wantBrowser, body []byte
		var wantOrigin, key string
		var proofGen int64
		var expires, codeExpires time.Time
		var consumed *time.Time
		err = tx.QueryRow(ctx, `SELECT code_hash,browser_hash,origin,key_id,payload,auth_gen,expires_at,code_expires_at,consumed_at
   FROM auth_sso_transactions WHERE transaction_hash=$1 AND family_id=$2 FOR UPDATE`, hash, family).Scan(&wantCode, &wantBrowser, &wantOrigin, &key, &body, &proofGen, &expires, &codeExpires, &consumed)
		if err != nil {
			return sqlError(err)
		}
		var now time.Time
		if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			return err
		}
		if revoked != nil || consumed != nil || gen != familyGen || gen != proofGen || !absolute.After(now) || !expires.After(now) || !codeExpires.After(now) || wantOrigin != origin || !hmac.Equal(codeHash, wantCode) || !hmac.Equal(binding, wantBrowser) {
			return ErrSSOInvalid
		}
		p, err := s.openSSO(hash, key, body)
		if err != nil {
			return err
		}
		key, body, err = s.payload(newHash, sessionPayload{IP: p.IP, Fields: p.Fields})
		if err != nil {
			return err
		}
		ipHash, _ := s.ipHash(p.IP)
		idle := now.Add(idleTTL)
		if idle.After(absolute) {
			idle = absolute
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth_session_tokens(token_hash,family_id) VALUES($1,$2)`, newHash, family)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth_sessions(token_hash,family_id,key_id,payload,issued_at,idle_expires_at,last_refreshed_at,ip_hash,audience)
   VALUES($1,$2,$3,$4,$5,$6,$5,$7,$8)`, newHash, family, key, body, now, idle, ipHash, origin)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE auth_sso_transactions SET consumed_at=$2 WHERE transaction_hash=$1`, hash, now)
		if err == nil {
			returnURI = p.ReturnURI
		}
		return err
	})
	return returnURI, sqlError(err)
}
