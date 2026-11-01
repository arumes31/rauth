package authstate

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const operationTimeout = 3 * time.Second
const mutationTimeout = 10 * time.Second
const keyConfigurationTimeout = 15 * time.Second
const keyConfigurationLock int64 = 0x72617574686b
const maxSessionPayload = 32768

// PostgresSessions is not a Redis fallback. Select one authority for the whole
// fleet only after all security-state adapters support the coordinated cutover.
type PostgresSessions struct {
	pool *pgxpool.Pool
	keys *Keyring
}

var _ SessionStore = (*PostgresSessions)(nil)

func NewPostgresSessions(ctx context.Context, pool *pgxpool.Pool, keys *Keyring) (*PostgresSessions, error) {
	if pool == nil || keys == nil {
		return nil, errors.New("SQL session store requires a database and keyring")
	}
	ctx, cancel := context.WithTimeout(ctx, keyConfigurationTimeout)
	defer cancel()
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", keyConfigurationLock); err != nil {
			return err
		}
		check := digest(keys.indexKey, []byte("rauth-authstate-index-check-v1"))
		if _, err := tx.Exec(ctx, "INSERT INTO auth_state_settings(index_key_check) VALUES($1) ON CONFLICT DO NOTHING", check); err != nil {
			return err
		}
		var stored []byte
		if err := tx.QueryRow(ctx, "SELECT index_key_check FROM auth_state_settings WHERE singleton").Scan(&stored); err != nil {
			return err
		}
		if !hmac.Equal(stored, check) {
			return ErrKeyMismatch
		}
		for id, check := range keys.checks {
			if _, err := tx.Exec(ctx, "INSERT INTO auth_state_keys(key_id,key_check) VALUES($1,$2) ON CONFLICT DO NOTHING", id, check); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, "SELECT key_check FROM auth_state_keys WHERE key_id=$1", id).Scan(&stored); err != nil {
				return err
			}
			if !hmac.Equal(stored, check) {
				return ErrKeyMismatch
			}
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT s.key_id FROM auth_sessions s JOIN auth_session_families f ON f.id=s.family_id
   WHERE f.revoked_at IS NULL AND f.absolute_expires_at>clock_timestamp() AND s.idle_expires_at>clock_timestamp()`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			if keys.keys[id] == nil {
				return errors.New("a live session encryption key is missing")
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return &PostgresSessions{pool: pool, keys: keys}, nil
}
func validTTL(ttl time.Duration) bool { return ttl >= time.Second && ttl <= 365*24*time.Hour }
func (s *PostgresSessions) payload(hash []byte, p sessionPayload) (string, []byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", nil, err
	}
	if len(b) > maxSessionPayload-64 {
		return "", nil, errors.New("session metadata is too large")
	}
	return s.keys.seal(hash, b)
}
func (s *PostgresSessions) decode(r sessionRow) (Session, error) {
	b, err := s.keys.open(r.key, r.hash, r.payload)
	if err != nil {
		return Session{}, err
	}
	var p sessionPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return Session{}, errors.New("invalid session payload")
	}
	return Session{Username: r.username, Generation: r.generation, IP: p.IP, FamilyID: r.family, Fields: p.Fields, Successor: p.Successor, IssuedAt: r.issued, IdleExpiresAt: r.idle, AbsoluteExpiresAt: r.absolute}, nil
}
func sqlError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrConflict
	}
	return err
}

// lockGeneration shares the same row lock as core.RevokeAuth. It must precede
// family and session locks, so rotation cannot race a credential revocation.
func lockGeneration(ctx context.Context, tx pgx.Tx, user string) (int64, error) {
	var gen int64
	// Existing accounts take one read/lock round trip; avoid a redundant INSERT
	// on every rotation. The first use still creates and locks generation zero.
	err := tx.QueryRow(ctx, "SELECT gen FROM auth_generations WHERE username=$1 FOR SHARE", user).Scan(&gen)
	if !errors.Is(err, pgx.ErrNoRows) {
		return gen, err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO auth_generations(username,gen) VALUES($1,0) ON CONFLICT DO NOTHING", user); err != nil {
		return 0, err
	}
	err = tx.QueryRow(ctx, "SELECT gen FROM auth_generations WHERE username=$1 FOR SHARE", user).Scan(&gen)
	return gen, err
}

func (s *PostgresSessions) Issue(ctx context.Context, token string, p IssueSession) error {
	hash, err := s.keys.tokenHash(token)
	if err != nil {
		return err
	}
	if p.Username == "" || p.Generation < 0 || !validTTL(p.IdleTTL) || !validTTL(p.AbsoluteTTL) {
		return errors.New("invalid session parameters")
	}
	key, body, err := s.payload(hash, sessionPayload{IP: p.IP, Fields: p.Fields})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	return sqlError(pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		gen, err := lockGeneration(ctx, tx, p.Username)
		if err != nil {
			return err
		}
		if gen != p.Generation {
			return ErrStaleGeneration
		}
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", p.Username).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrStaleGeneration
		}
		var now time.Time
		if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			return err
		}
		family := uuid.NewString()
		absolute := now.Add(p.AbsoluteTTL)
		idle := now.Add(p.IdleTTL)
		if idle.After(absolute) {
			idle = absolute
		}
		if _, err := tx.Exec(ctx, "INSERT INTO auth_session_families(id,username,auth_gen,absolute_expires_at) VALUES($1,$2,$3,$4)", family, p.Username, gen, absolute); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO auth_sessions(token_hash,family_id,key_id,payload,issued_at,idle_expires_at,last_refreshed_at) VALUES($1,$2,$3,$4,$5,$6,$5)", hash, family, key, body, now, idle)
		return err
	}))
}

type sessionRow struct {
	hash                   []byte
	family, username, key  string
	generation             int64
	payload                []byte
	issued, idle, absolute time.Time
	retired                bool
}

func scanSession(row pgx.Row) (sessionRow, error) {
	var r sessionRow
	err := row.Scan(&r.hash, &r.family, &r.username, &r.generation, &r.key, &r.payload, &r.issued, &r.idle, &r.absolute, &r.retired)
	return r, sqlError(err)
}

const sessionColumns = "s.token_hash,s.family_id::text,f.username,f.auth_gen,s.key_id,s.payload,s.issued_at,s.idle_expires_at,f.absolute_expires_at,s.retired"

func (s *PostgresSessions) Get(ctx context.Context, token string) (Session, error) {
	hash, err := s.keys.tokenHash(token)
	if err != nil {
		return Session{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	r, err := scanSession(s.pool.QueryRow(ctx, `SELECT `+sessionColumns+` FROM auth_sessions s
  JOIN auth_session_families f ON f.id=s.family_id JOIN users u ON u.username=f.username
  LEFT JOIN auth_generations g ON g.username=f.username WHERE s.token_hash=$1
  AND s.idle_expires_at>clock_timestamp() AND f.absolute_expires_at>clock_timestamp()
  AND f.revoked_at IS NULL AND f.auth_gen=COALESCE(g.gen,0)`, hash))
	if err != nil {
		return Session{}, err
	}
	return s.decode(r)
}

// locked validates generation, family and expiry while holding locks in the
// common order. Concurrent rotations use SKIP LOCKED for the family: a losing
// request need not queue behind the winner. The clock is read after lock waits,
// never from a worker clock.
func (s *PostgresSessions) locked(ctx context.Context, tx pgx.Tx, hash []byte) (sessionRow, time.Time, error) {
	var family, user string
	var want int64
	if err := tx.QueryRow(ctx, `SELECT f.id::text,f.username,f.auth_gen FROM auth_sessions s JOIN auth_session_families f ON f.id=s.family_id WHERE s.token_hash=$1`, hash).Scan(&family, &user, &want); err != nil {
		return sessionRow{}, time.Time{}, sqlError(err)
	}
	gen, err := lockGeneration(ctx, tx, user)
	if err != nil {
		return sessionRow{}, time.Time{}, err
	}
	if gen != want {
		return sessionRow{}, time.Time{}, ErrNotFound
	}
	var revoked *time.Time
	var current int64
	if err := tx.QueryRow(ctx, "SELECT revoked_at,auth_gen FROM auth_session_families WHERE id=$1 FOR UPDATE SKIP LOCKED", family).Scan(&revoked, &current); err != nil {
		return sessionRow{}, time.Time{}, sqlError(err)
	}
	r, err := scanSession(tx.QueryRow(ctx, "SELECT "+sessionColumns+" FROM auth_sessions s JOIN auth_session_families f ON f.id=s.family_id WHERE s.token_hash=$1 FOR UPDATE OF s", hash))
	if err != nil {
		return r, time.Time{}, err
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return r, now, err
	}
	if revoked != nil || current != gen || !r.idle.After(now) || !r.absolute.After(now) {
		return r, now, ErrNotFound
	}
	return r, now, nil
}
func (s *PostgresSessions) move(ctx context.Context, oldToken, newToken string, idleTTL, grace time.Duration, replace bool) (bool, error) {
	oldHash, err := s.keys.tokenHash(oldToken)
	if err != nil {
		return false, err
	}
	newHash, err := s.keys.tokenHash(newToken)
	if err != nil {
		return false, err
	}
	if hmac.Equal(oldHash, newHash) {
		return false, errors.New("replacement token must be distinct")
	}
	if !replace && (!validTTL(idleTTL) || grace < time.Second || grace > time.Minute) {
		return false, errors.New("invalid rotation duration")
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	changed := false
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		r, now, err := s.locked(ctx, tx, oldHash)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if r.retired {
			return nil
		}
		p, err := s.decode(r)
		if err != nil {
			return err
		}
		key, body, err := s.payload(newHash, sessionPayload{IP: p.IP, Fields: p.Fields})
		if err != nil {
			return err
		}
		idle := r.idle
		issued := r.issued
		refreshed := now
		if !replace {
			idle = now.Add(idleTTL)
			if idle.After(r.absolute) {
				idle = r.absolute
			}
			issued = now
		}
		if _, err := tx.Exec(ctx, "INSERT INTO auth_sessions(token_hash,family_id,key_id,payload,issued_at,idle_expires_at,last_refreshed_at) VALUES($1,$2,$3,$4,$5,$6,$7)", newHash, r.family, key, body, issued, idle, refreshed); err != nil {
			return err
		}
		if replace {
			_, err = tx.Exec(ctx, "DELETE FROM auth_sessions WHERE token_hash=$1", oldHash)
		} else {
			key, body, err = s.payload(oldHash, sessionPayload{IP: p.IP, Fields: p.Fields, Successor: newToken})
			if err != nil {
				return err
			}
			expiry := now.Add(grace)
			if expiry.After(r.idle) {
				expiry = r.idle
			}
			if expiry.After(r.absolute) {
				expiry = r.absolute
			}
			_, err = tx.Exec(ctx, "UPDATE auth_sessions SET retired=true,key_id=$2,payload=$3,idle_expires_at=$4 WHERE token_hash=$1", oldHash, key, body, expiry)
		}
		if err == nil {
			changed = true
		}
		return err
	})
	return changed && err == nil, sqlError(err)
}
func (s *PostgresSessions) Rotate(ctx context.Context, oldToken, newToken string, idleTTL, grace time.Duration) (bool, error) {
	return s.move(ctx, oldToken, newToken, idleTTL, grace, false)
}
func (s *PostgresSessions) Replace(ctx context.Context, oldToken, newToken string) (bool, error) {
	return s.move(ctx, oldToken, newToken, 0, 0, true)
}
func (s *PostgresSessions) Refresh(ctx context.Context, token string, idleTTL time.Duration) (bool, error) {
	hash, err := s.keys.tokenHash(token)
	if err != nil {
		return false, err
	}
	if !validTTL(idleTTL) {
		return false, errors.New("invalid idle duration")
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	// Bound refresh writes while allowing short configured idle lifetimes.
	interval := min(30*time.Second, idleTTL/4)
	tag, err := s.pool.Exec(ctx, `UPDATE auth_sessions s SET idle_expires_at=LEAST(clock_timestamp()+$2::interval,f.absolute_expires_at),last_refreshed_at=clock_timestamp()
  FROM auth_session_families f,users u WHERE s.token_hash=$1 AND f.id=s.family_id AND u.username=f.username
  AND NOT s.retired AND s.idle_expires_at>clock_timestamp() AND f.absolute_expires_at>clock_timestamp()
  AND f.revoked_at IS NULL AND f.auth_gen=COALESCE((SELECT gen FROM auth_generations WHERE username=f.username),0)
  AND s.last_refreshed_at<clock_timestamp()-$3::interval`, hash, idleTTL.String(), interval.String())
	return tag.RowsAffected() > 0, err
}
func (s *PostgresSessions) Revoke(ctx context.Context, token string) error {
	hash, err := s.keys.tokenHash(token)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	// Family UPDATE conflicts with the family lock used by rotate/replace. A
	// successor committed before this update is revoked in the same operation.
	_, err = s.pool.Exec(ctx, `UPDATE auth_session_families SET revoked_at=COALESCE(revoked_at,clock_timestamp())
  WHERE id=(SELECT family_id FROM auth_sessions WHERE token_hash=$1)`, hash)
	return err
}
func (s *PostgresSessions) RevokeUser(ctx context.Context, user string) error {
	if user == "" {
		return errors.New("username is required")
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Bump and revoke together so a proof checked before global logout cannot
		// issue a new family after the operation commits.
		if _, err := tx.Exec(ctx, `INSERT INTO auth_generations(username,gen) VALUES($1,1) ON CONFLICT(username) DO UPDATE SET gen=auth_generations.gen+1`, user); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "UPDATE auth_session_families SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE username=$1", user)
		return err
	})
}
func (s *PostgresSessions) Restamp(ctx context.Context, token string, oldGeneration, newGeneration int64) (bool, error) {
	hash, err := s.keys.tokenHash(token)
	if err != nil {
		return false, err
	}
	if oldGeneration < 0 || newGeneration <= oldGeneration {
		return false, errors.New("invalid restamp generation")
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	changed := false
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var user, family string
		if err := tx.QueryRow(ctx, "SELECT f.username,f.id::text FROM auth_sessions s JOIN auth_session_families f ON f.id=s.family_id WHERE s.token_hash=$1", hash).Scan(&user, &family); errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		gen, err := lockGeneration(ctx, tx, user)
		if err != nil {
			return err
		}
		if gen != newGeneration {
			return nil
		}
		var revoked *time.Time
		var current int64
		if err := tx.QueryRow(ctx, "SELECT revoked_at,auth_gen FROM auth_session_families WHERE id=$1 FOR UPDATE", family).Scan(&revoked, &current); errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		if revoked != nil || current != oldGeneration {
			return nil
		}
		r, err := scanSession(tx.QueryRow(ctx, "SELECT "+sessionColumns+" FROM auth_sessions s JOIN auth_session_families f ON f.id=s.family_id WHERE s.token_hash=$1 FOR UPDATE OF s", hash))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		var now time.Time
		if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			return err
		}
		if r.retired || !r.idle.After(now) || !r.absolute.After(now) {
			return nil
		}
		_, err = tx.Exec(ctx, "UPDATE auth_session_families SET auth_gen=$2 WHERE id=$1", family, newGeneration)
		changed = err == nil
		return err
	})
	return changed && err == nil, err
}

// Cleanup deletes only expired families/sessions. Revoked records remain until
// their absolute deadline so an ambiguous mutation cannot resurrect a token.
func (s *PostgresSessions) Cleanup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if _, err := s.pool.Exec(ctx, "DELETE FROM auth_sessions WHERE idle_expires_at<=clock_timestamp()"); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, "DELETE FROM auth_session_families WHERE absolute_expires_at<=clock_timestamp()")
	return err
}
