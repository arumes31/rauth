package authstate

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"strings"
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
	pool     *pgxpool.Pool
	keys     *Keyring
	counters counterCoalescer
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
   WHERE f.revoked_at IS NULL AND f.absolute_expires_at>clock_timestamp() AND s.idle_expires_at>clock_timestamp()
   UNION SELECT key_id FROM auth_artifacts WHERE consumed_at IS NULL AND expires_at>clock_timestamp()
   UNION SELECT key_id FROM auth_sso_transactions WHERE consumed_at IS NULL AND expires_at>clock_timestamp()`)
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
				return errors.New("a live session or challenge encryption key is missing")
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
	return Session{Username: r.username, Generation: r.generation, IP: p.IP, FamilyID: r.family, Audience: r.audience, Fields: p.Fields, Successor: p.Successor, IssuedAt: r.issued, IdleExpiresAt: r.idle, AbsoluteExpiresAt: r.absolute}, nil
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
	// This is an optional throttle index, not a new authentication precondition.
	// Historical or absent IP metadata must not strand an otherwise valid proof.
	ipHash, _ := s.ipHash(p.IP)
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
		if _, err := tx.Exec(ctx, "INSERT INTO auth_session_families(id,username,auth_gen,absolute_expires_at,created_at) VALUES($1,$2,$3,$4,$5)", family, p.Username, gen, absolute, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO auth_session_tokens(token_hash,family_id) VALUES($1,$2)", hash, family); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO auth_sessions(token_hash,family_id,key_id,payload,issued_at,idle_expires_at,last_refreshed_at,ip_hash) VALUES($1,$2,$3,$4,$5,$6,$5,$7)", hash, family, key, body, now, idle, ipHash)
		return err
	}))
}

type sessionRow struct {
	hash                   []byte
	family, username, key  string
	audience               string
	generation             int64
	payload                []byte
	issued, idle, absolute time.Time
	retired                bool
}

func scanSession(row pgx.Row) (sessionRow, error) {
	var r sessionRow
	err := row.Scan(&r.hash, &r.family, &r.username, &r.generation, &r.key, &r.payload, &r.issued, &r.idle, &r.absolute, &r.retired, &r.audience)
	return r, sqlError(err)
}

const sessionColumns = "s.token_hash,s.family_id::text,f.username,f.auth_gen,s.key_id,s.payload,s.issued_at,s.idle_expires_at,f.absolute_expires_at,s.retired,s.audience"

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
	var retired bool
	if err := tx.QueryRow(ctx, `SELECT f.id::text,f.username,f.auth_gen,s.retired FROM auth_sessions s JOIN auth_session_families f ON f.id=s.family_id WHERE s.token_hash=$1`, hash).Scan(&family, &user, &want, &retired); err != nil {
		return sessionRow{}, time.Time{}, sqlError(err)
	}
	// Retirement is monotonic. In-flight requests using an old grace token
	// must not contend with the live successor's rotation or replacement.
	if retired {
		return sessionRow{retired: true}, time.Time{}, nil
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
		if errors.Is(err, pgx.ErrNoRows) {
			var exists bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM auth_session_families WHERE id=$1)", family).Scan(&exists); err != nil {
				return sessionRow{}, time.Time{}, err
			}
			if exists {
				return sessionRow{}, time.Time{}, ErrBusy
			}
		}
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
func (s *PostgresSessions) move(ctx context.Context, oldToken, newToken string, idleTTL, grace time.Duration, replace bool, grant *PublicAccessGrant) (bool, error) {
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
		if grant != nil && (grant.Username != r.username || grant.Generation != r.generation) {
			return ErrStaleGeneration
		}
		// Keep older/unparseable encrypted metadata rotatable; unknown addresses
		// have no IP shortcut rather than sharing a permissive fallback index.
		ipHash, _ := s.ipHash(p.IP)
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
		if _, err := tx.Exec(ctx, "INSERT INTO auth_sessions(token_hash,family_id,key_id,payload,issued_at,idle_expires_at,last_refreshed_at,ip_hash,audience) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", newHash, r.family, key, body, issued, idle, refreshed, ipHash, r.audience); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO auth_session_tokens(token_hash,family_id) VALUES($1,$2)", newHash, r.family); err != nil {
			return err
		}
		if !replace {
			// Rotation preserves an existing grant's original deadline, never its TTL.
			if _, err := tx.Exec(ctx, `INSERT INTO auth_step_up_grants(token_hash,username,auth_gen,expires_at)
    SELECT $2,username,auth_gen,LEAST(expires_at,$3::timestamptz) FROM auth_step_up_grants WHERE token_hash=$1 AND auth_gen=$4 AND username=$5 AND expires_at>clock_timestamp()`, oldHash, newHash, idle, r.generation, r.username); err != nil {
				return err
			}
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
		if err == nil && grant != nil {
			expires := now.Add(grant.TTL)
			if expires.After(idle) {
				expires = idle
			}
			if expires.After(r.absolute) {
				expires = r.absolute
			}
			var admin bool
			if err = tx.QueryRow(ctx, "SELECT is_admin FROM users WHERE username=$1 FOR SHARE", r.username).Scan(&admin); err != nil {
				return err
			}
			if !admin {
				return errors.New("step-up grant requires administrator")
			}
			_, err = tx.Exec(ctx, "INSERT INTO auth_step_up_grants(token_hash,username,auth_gen,expires_at) VALUES($1,$2,$3,$4)", newHash, r.username, r.generation, expires)
		}
		if err == nil {
			changed = true
		}
		return err
	})
	return changed && err == nil, sqlError(err)
}
func (s *PostgresSessions) Rotate(ctx context.Context, oldToken, newToken string, idleTTL, grace time.Duration) (bool, error) {
	return s.move(ctx, oldToken, newToken, idleTTL, grace, false, nil)
}
func (s *PostgresSessions) Replace(ctx context.Context, oldToken, newToken string) (bool, error) {
	return s.move(ctx, oldToken, newToken, 0, 0, true, nil)
}

const refreshSessionSQL = `UPDATE auth_sessions s SET idle_expires_at=LEAST(clock_timestamp()+$2::interval,f.absolute_expires_at),last_refreshed_at=clock_timestamp()
  FROM auth_session_families f,users u WHERE s.token_hash=$1 AND f.id=s.family_id AND u.username=f.username
  AND NOT s.retired AND s.idle_expires_at>clock_timestamp() AND f.absolute_expires_at>clock_timestamp()
  AND f.revoked_at IS NULL AND f.auth_gen=COALESCE((SELECT gen FROM auth_generations WHERE username=f.username),0)
  AND s.last_refreshed_at<clock_timestamp()-$3::interval`

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
	tag, err := s.pool.Exec(ctx, refreshSessionSQL, hash, idleTTL.String(), interval.String())
	return tag.RowsAffected() > 0, err
}

// RefreshValidation batches successful-validation bookkeeping. The caller has
// already checked the live session and its client binding. Matching the counter
// store prevents mixing selected authorities; only the validate throttle may be
// reset here. The refresh uses the same SQL and database-clock bounds as Refresh.
func (s *PostgresSessions) RefreshValidation(ctx context.Context, counters *PostgresCounters, token string, idleTTL time.Duration, rateKey string) (bool, error) {
	if counters == nil || counters.s != s || !strings.HasPrefix(rateKey, "rate_limit:validate:") || rateKey == "rate_limit:validate:" {
		return false, errors.New("invalid validation bookkeeping authority or counter")
	}
	hash, err := s.keys.tokenHash(token)
	if err != nil {
		return false, err
	}
	counterHash, err := counters.hash(rateKey)
	if err != nil {
		return false, err
	}
	if !validTTL(idleTTL) {
		return false, errors.New("invalid idle duration")
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	interval := min(30*time.Second, idleTTL/4)
	batch := &pgx.Batch{}
	batch.Queue("DELETE FROM auth_security_counters WHERE key_hash=$1", counterHash)
	batch.Queue(refreshSessionSQL, hash, idleTTL.String(), interval.String())
	results := s.pool.SendBatch(ctx, batch)
	_, resetErr := results.Exec()
	tag, refreshErr := results.Exec()
	closeErr := results.Close()
	if err := errors.Join(resetErr, refreshErr, closeErr); err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *PostgresSessions) Revoke(ctx context.Context, token string) error {
	hash, err := s.keys.tokenHash(token)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	// Stable keyed-token aliases survive replacement and grace cleanup. Family
	// UPDATE conflicts with rotate/replace, so a logout that already read the old
	// token still revokes a successor committed before it acquires the lock.
	_, err = s.pool.Exec(ctx, `UPDATE auth_session_families SET revoked_at=COALESCE(revoked_at,clock_timestamp())
  WHERE id=(SELECT family_id FROM auth_session_tokens WHERE token_hash=$1)`, hash)
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
		// A credential change keeps only the caller. Restamping the family alone
		// would also reauthorize retired grace tokens (and linked app sessions).
		// Keep stable token aliases so racing logout still reaches this family.
		if _, err := tx.Exec(ctx, "DELETE FROM auth_sessions WHERE family_id=$1 AND token_hash<>$2", family, hash); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE auth_session_families SET auth_gen=$2 WHERE id=$1", family, newGeneration)
		changed = err == nil
		return err
	})
	return changed && err == nil, err
}

// Cleanup deletes only expired families/sessions. Revoked families remain until
// their absolute deadline; expired child token rows can be pruned sooner.
func (s *PostgresSessions) Cleanup(ctx context.Context) error {
	// A fixed DB cutoff gives this run a finite backlog. Each independently
	// committed batch makes progress even if a later batch times out/cancels.
	var cutoff time.Time
	bounded, cancel := context.WithTimeout(ctx, operationTimeout)
	err := s.pool.QueryRow(bounded, "SELECT clock_timestamp()").Scan(&cutoff)
	cancel()
	if err != nil {
		return err
	}
	queries := []string{
		`WITH doomed AS (SELECT transaction_hash FROM auth_sso_transactions WHERE expires_at<=$1 ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)
 DELETE FROM auth_sso_transactions a USING doomed d WHERE a.transaction_hash=d.transaction_hash`,
		`WITH doomed AS (SELECT token_hash FROM auth_step_up_grants WHERE expires_at<=$1 ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)
 DELETE FROM auth_step_up_grants g USING doomed d WHERE g.token_hash=d.token_hash`,

		`WITH doomed AS (SELECT kind,token_hash FROM auth_artifacts WHERE expires_at<=$1 ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)
         DELETE FROM auth_artifacts a USING doomed d WHERE a.kind=d.kind AND a.token_hash=d.token_hash`,
		`WITH doomed AS (SELECT key_hash FROM auth_security_counters WHERE expires_at<=$1 ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)
         DELETE FROM auth_security_counters a USING doomed d WHERE a.key_hash=d.key_hash`,
		`WITH doomed AS (SELECT key_hash FROM auth_replay_markers WHERE expires_at<=$1 ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)
         DELETE FROM auth_replay_markers a USING doomed d WHERE a.key_hash=d.key_hash`,
		`WITH doomed AS (SELECT token_hash FROM auth_sessions WHERE idle_expires_at<=$1 ORDER BY idle_expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)
   DELETE FROM auth_sessions s USING doomed d WHERE s.token_hash=d.token_hash`,
		`WITH doomed AS (SELECT s.token_hash FROM auth_session_families f JOIN auth_sessions s ON s.family_id=f.id WHERE f.absolute_expires_at<=$1
   ORDER BY f.absolute_expires_at LIMIT 1000 FOR UPDATE OF s SKIP LOCKED)
   DELETE FROM auth_sessions s USING doomed d WHERE s.token_hash=d.token_hash`,
		`WITH doomed AS (SELECT a.token_hash FROM auth_session_tokens a JOIN auth_session_families f ON f.id=a.family_id WHERE f.absolute_expires_at<=$1 ORDER BY f.absolute_expires_at LIMIT 1000 FOR UPDATE OF a SKIP LOCKED)
 DELETE FROM auth_session_tokens a USING doomed d WHERE a.token_hash=d.token_hash`,
		`WITH doomed AS (SELECT f.id FROM auth_session_families f WHERE f.absolute_expires_at<=$1 AND NOT EXISTS(SELECT 1 FROM auth_sessions s WHERE s.family_id=f.id) AND NOT EXISTS(SELECT 1 FROM auth_session_tokens t WHERE t.family_id=f.id)
   ORDER BY f.absolute_expires_at LIMIT 1000 FOR UPDATE OF f SKIP LOCKED)
   DELETE FROM auth_session_families f USING doomed d WHERE f.id=d.id`,
	}
	for _, query := range queries {
		for {
			bounded, cancel := context.WithTimeout(ctx, operationTimeout)
			tag, err := s.pool.Exec(bounded, query, cutoff)
			cancel()
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				break
			}
		}
	}
	return nil
}
