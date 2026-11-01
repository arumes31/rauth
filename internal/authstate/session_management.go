package authstate

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PublicAccessGrant binds fresh step-up proof to the replacement token and the
// exact account generation that performed it. It never elevates the old token.
type PublicAccessGrant struct {
	Username   string
	Generation int64
	TTL        time.Duration
}

// SessionSummary exposes only a non-bearer family handle and display metadata.
// The allowlist excludes rotation successors and any token-shaped custom field.
type SessionSummary struct {
	Handle            string
	Username          string
	IP                string
	Fields            map[string]string
	IssuedAt          time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}
type SessionPage struct {
	Sessions   []SessionSummary
	Next       string
	ObservedAt time.Time
}

func (s *PostgresSessions) ipHash(ip string) ([]byte, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return nil, errors.New("invalid session IP")
	}
	return s.keys.stateHash("session-ip", addr.Unmap().String()), nil
}

func (s *PostgresSessions) ReplaceWithGrant(ctx context.Context, oldToken, newToken string, grant PublicAccessGrant) (bool, error) {
	if grant.Username == "" || grant.Generation < 0 || grant.TTL < time.Second || grant.TTL > 15*time.Minute {
		return false, errors.New("invalid step-up grant")
	}
	return s.move(ctx, oldToken, newToken, 0, 0, true, &grant)
}
func (s *PostgresSessions) GrantRemaining(ctx context.Context, token, user string) (time.Duration, error) {
	hash, err := s.keys.tokenHash(token)
	if err != nil {
		return 0, err
	}
	if user == "" {
		return 0, errors.New("grant owner is required")
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var seconds float64
	err = s.pool.QueryRow(ctx, `SELECT COALESCE((SELECT GREATEST(0,EXTRACT(epoch FROM LEAST(g.expires_at,s.idle_expires_at,f.absolute_expires_at)-clock_timestamp()))
 FROM auth_step_up_grants g JOIN auth_sessions s ON s.token_hash=g.token_hash JOIN auth_session_families f ON f.id=s.family_id
 JOIN users u ON u.username=f.username LEFT JOIN auth_generations a ON a.username=f.username
 WHERE g.token_hash=$1 AND g.username=$2 AND g.username=f.username AND u.is_admin AND NOT s.retired
 AND f.revoked_at IS NULL AND g.auth_gen=f.auth_gen AND f.auth_gen=COALESCE(a.gen,0)),0)`, hash, user).Scan(&seconds)
	return time.Duration(seconds * float64(time.Second)), err
}
func (s *PostgresSessions) LockGrant(ctx context.Context, token string) error {
	hash, err := s.keys.tokenHash(token)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	_, err = s.pool.Exec(ctx, "DELETE FROM auth_step_up_grants WHERE token_hash=$1", hash)
	return err
}

// List uses bounded keyset pagination over live families, selecting one current
// device session per family. No raw token or encrypted successor is returned.
// Empty user selects all families for the separately authorized admin caller.
func (s *PostgresSessions) List(ctx context.Context, user, after string, limit int) (SessionPage, error) {
	var page SessionPage
	if limit < 1 || limit > 200 {
		return page, errors.New("session page size must be between 1 and 200")
	}
	cursor := uuid.Nil.String()
	if after != "" {
		id, err := uuid.Parse(after)
		if err != nil {
			return page, errors.New("invalid session cursor")
		}
		cursor = id.String()
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT `+sessionColumns+`,clock_timestamp() FROM auth_session_families f JOIN users u ON u.username=f.username
 LEFT JOIN auth_generations g ON g.username=f.username JOIN LATERAL
 (SELECT * FROM auth_sessions a WHERE a.family_id=f.id AND NOT a.retired AND a.idle_expires_at>clock_timestamp() ORDER BY a.issued_at DESC,a.token_hash LIMIT 1) s ON true
 WHERE ($1='' OR f.username=$1) AND f.id>$2::uuid AND f.revoked_at IS NULL AND f.absolute_expires_at>clock_timestamp()
 AND f.auth_gen=COALESCE(g.gen,0) ORDER BY f.id LIMIT $3`, user, cursor, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var r sessionRow
		if err := rows.Scan(&r.hash, &r.family, &r.username, &r.generation, &r.key, &r.payload, &r.issued, &r.idle, &r.absolute, &r.retired, &page.ObservedAt); err != nil {
			return SessionPage{}, err
		}
		if len(page.Sessions) == limit {
			page.Next = page.Sessions[len(page.Sessions)-1].Handle
			break
		}
		value, err := s.decode(r)
		if err != nil {
			return SessionPage{}, err
		}
		fields := make(map[string]string)
		for _, key := range []string{"country", "user_agent", "ua_ch_platform", "ua_ch_mobile", "ua_ch_model", "groups", "is_admin"} {
			if v, ok := value.Fields[key]; ok {
				fields[key] = v
			}
		}
		page.Sessions = append(page.Sessions, SessionSummary{Handle: value.FamilyID, Username: value.Username, IP: value.IP, Fields: fields, IssuedAt: value.IssuedAt, IdleExpiresAt: value.IdleExpiresAt, AbsoluteExpiresAt: value.AbsoluteExpiresAt})
	}
	return page, rows.Err()
}
func (s *PostgresSessions) RevokeFamily(ctx context.Context, handle, user string) (bool, error) {
	id, err := uuid.Parse(handle)
	if err != nil {
		return false, errors.New("invalid session handle")
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	tag, err := s.pool.Exec(ctx, `UPDATE auth_session_families SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1 AND ($2='' OR username=$2)`, id.String(), user)
	return tag.RowsAffected() == 1, err
}
func (s *PostgresSessions) RevokeOthers(ctx context.Context, user, keepToken string) error {
	if user == "" {
		return errors.New("username is required")
	}
	hash, err := s.keys.tokenHash(keepToken)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var owner string
		if err := tx.QueryRow(ctx, "SELECT f.username FROM auth_sessions s JOIN auth_session_families f ON f.id=s.family_id WHERE s.token_hash=$1", hash).Scan(&owner); err != nil {
			return sqlError(err)
		}
		if owner != user {
			return ErrNotFound
		}
		// An exclusive generation lock serializes this operation with all new
		// issues/rotations, without changing the surviving family's generation.
		if _, err := tx.Exec(ctx, `INSERT INTO auth_generations(username,gen) VALUES($1,0) ON CONFLICT(username) DO UPDATE SET gen=auth_generations.gen`, user); err != nil {
			return err
		}
		r, _, err := s.locked(ctx, tx, hash)
		if err != nil {
			return err
		}
		if r.retired || r.username != user {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, "UPDATE auth_session_families SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE username=$1 AND id<>$2::uuid", user, r.family)
		return err
	})
}
func (s *PostgresSessions) HasActiveForIP(ctx context.Context, ip string) (bool, error) {
	hash, err := s.ipHash(ip)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var active bool
	err = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth_sessions s JOIN auth_session_families f ON f.id=s.family_id JOIN users u ON u.username=f.username
 LEFT JOIN auth_generations g ON g.username=f.username WHERE s.ip_hash=$1 AND NOT s.retired AND s.idle_expires_at>clock_timestamp()
 AND f.absolute_expires_at>clock_timestamp() AND f.revoked_at IS NULL AND f.auth_gen=COALESCE(g.gen,0))`, hash).Scan(&active)
	return active, err
}
func (s *PostgresSessions) ActiveCount(ctx context.Context) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var count int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM auth_session_families f JOIN users u ON u.username=f.username LEFT JOIN auth_generations g ON g.username=f.username
 WHERE f.revoked_at IS NULL AND f.absolute_expires_at>clock_timestamp() AND f.auth_gen=COALESCE(g.gen,0)
 AND EXISTS(SELECT 1 FROM auth_sessions s WHERE s.family_id=f.id AND NOT s.retired AND s.idle_expires_at>clock_timestamp())`).Scan(&count)
	return count, err
}
func (s *PostgresSessions) UpdateCountry(ctx context.Context, token, country string) (bool, error) {
	if country != "unknown" && (len(country) != 2 || strings.IndexFunc(country, func(r rune) bool { return r < 'A' || r > 'Z' }) >= 0) {
		return false, errors.New("invalid session country")
	}
	hash, err := s.keys.tokenHash(token)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	changed := false
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		r, _, err := s.locked(ctx, tx, hash)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if r.retired {
			return nil
		}
		value, err := s.decode(r)
		if err != nil {
			return err
		}
		if value.Fields == nil {
			value.Fields = map[string]string{}
		}
		value.Fields["country"] = country
		key, body, err := s.payload(hash, sessionPayload{IP: value.IP, Fields: value.Fields})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE auth_sessions SET key_id=$2,payload=$3 WHERE token_hash=$1", hash, key, body)
		changed = err == nil
		return err
	})
	return changed && err == nil, err
}
