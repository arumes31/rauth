package authstate

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type ArtifactKind string

const (
	Pending2FA          ArtifactKind = "pending_2fa"
	PendingEnrollment   ArtifactKind = "pending_setup"
	EnrollmentSecret    ArtifactKind = "pending_setup_secret" // #nosec G101 -- Public challenge-purpose identifier, not a credential.
	PasskeyRegistration ArtifactKind = "webauthn_reg"         // #nosec G101 -- Public challenge-purpose identifier, not a credential.
	PasskeyLogin        ArtifactKind = "webauthn_login_session"
	Invitation          ArtifactKind = "invite"
)

func (k ArtifactKind) valid() bool {
	switch k {
	case Pending2FA, PendingEnrollment, EnrollmentSecret, PasskeyRegistration, PasskeyLogin, Invitation:
		return true
	}
	return false
}
func (k ArtifactKind) ownerRequired() bool {
	return k == Pending2FA || k == PendingEnrollment || k == EnrollmentSecret || k == PasskeyRegistration
}

// Artifact data is private encrypted server state. Username/generation bind a
// first-factor or enrollment proof to the account version that authorized it.
type Artifact struct {
	Data       []byte
	Username   string
	Generation int64
	ExpiresAt  time.Time
}

// ArtifactStore guarantees atomic one-use Take. IDs are fresh random browser
// tokens, not usernames. EnrollmentSecret alone may replace an expired slot.
type ArtifactStore interface {
	Put(context.Context, ArtifactKind, string, Artifact, time.Duration) error
	Get(context.Context, ArtifactKind, string) (Artifact, error)
	Take(context.Context, ArtifactKind, string) (Artifact, error)
	Delete(context.Context, ArtifactKind, string) error
}
type PostgresArtifacts struct{ s *PostgresSessions }

func (s *PostgresSessions) Artifacts() *PostgresArtifacts { return &PostgresArtifacts{s: s} }

var _ ArtifactStore = (*PostgresArtifacts)(nil)

func (a *PostgresArtifacts) hash(kind ArtifactKind, id string) ([]byte, error) {
	if !kind.valid() || len(id) < 32 || len(id) > 512 || strings.ContainsRune(id, 0) {
		return nil, errors.New("invalid challenge identifier")
	}
	return a.s.keys.stateHash("artifact:"+string(kind), id), nil
}
func (a *PostgresArtifacts) Put(ctx context.Context, kind ArtifactKind, id string, value Artifact, ttl time.Duration) error {
	hash, err := a.hash(kind, id)
	if err != nil {
		return err
	}
	limit := 15 * time.Minute
	if kind == Invitation {
		limit = 7 * 24 * time.Hour
	}
	if ttl < time.Second || ttl > limit || len(value.Data) > 65500 || value.Generation < 0 || kind.ownerRequired() && value.Username == "" {
		return errors.New("invalid challenge parameters")
	}
	key, body, err := a.s.keys.sealFor("rauth-artifact-v1:"+string(kind), hash, value.Data)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	return sqlError(pgx.BeginFunc(ctx, a.s.pool, func(tx pgx.Tx) error {
		var owner any
		var generation any
		if value.Username != "" {
			gen, err := lockGeneration(ctx, tx, value.Username)
			if err != nil {
				return err
			}
			if gen != value.Generation {
				return ErrStaleGeneration
			}
			var exists bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", value.Username).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrStaleGeneration
			}
			owner = value.Username
			generation = value.Generation
		}
		tag, err := tx.Exec(ctx, `INSERT INTO auth_artifacts(kind,token_hash,username,auth_gen,key_id,payload,expires_at)
   VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()+make_interval(secs=>$7))
   ON CONFLICT(kind,token_hash) DO UPDATE SET username=EXCLUDED.username,auth_gen=EXCLUDED.auth_gen,key_id=EXCLUDED.key_id,payload=EXCLUDED.payload,expires_at=EXCLUDED.expires_at,consumed_at=NULL
   WHERE auth_artifacts.kind='pending_setup_secret' AND auth_artifacts.expires_at<=clock_timestamp()`, string(kind), hash, owner, generation, key, body, ttl.Seconds())
		if err == nil && tag.RowsAffected() == 0 {
			return ErrConflict
		}
		return err
	}))
}
func (a *PostgresArtifacts) read(row pgx.Row, kind ArtifactKind, hash []byte) (Artifact, error) {
	var value Artifact
	var key string
	var body []byte
	err := row.Scan(&value.Username, &value.Generation, &key, &body, &value.ExpiresAt)
	if err != nil {
		return value, sqlError(err)
	}
	value.Data, err = a.s.keys.openFor("rauth-artifact-v1:"+string(kind), key, hash, body)
	return value, err
}

const artifactColumns = "COALESCE(a.username,''),COALESCE(a.auth_gen,0),a.key_id,a.payload,a.expires_at"

func (a *PostgresArtifacts) Get(ctx context.Context, kind ArtifactKind, id string) (Artifact, error) {
	hash, err := a.hash(kind, id)
	if err != nil {
		return Artifact{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	return a.read(a.s.pool.QueryRow(ctx, `SELECT `+artifactColumns+` FROM auth_artifacts a LEFT JOIN users u ON u.username=a.username LEFT JOIN auth_generations g ON g.username=a.username
  WHERE a.kind=$1 AND a.token_hash=$2 AND a.consumed_at IS NULL AND a.expires_at>clock_timestamp()
  AND (a.username IS NULL OR (u.username IS NOT NULL AND a.auth_gen=COALESCE(g.gen,0)))`, string(kind), hash), kind, hash)
}

// Consume runs apply in the same transaction as the claim. A failed callback
// rolls back both effects; an ambiguous commit requires a fresh challenge and
// must never trigger a consume-then-restore fallback.
func (a *PostgresArtifacts) Consume(ctx context.Context, kind ArtifactKind, id string, apply func(context.Context, pgx.Tx, Artifact) error) (Artifact, error) {
	hash, err := a.hash(kind, id)
	if err != nil {
		return Artifact{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, mutationTimeout)
	defer cancel()
	var result Artifact
	err = pgx.BeginFunc(ctx, a.s.pool, func(tx pgx.Tx) error {
		var user string
		var generation int64
		if err := tx.QueryRow(ctx, "SELECT COALESCE(username,''),COALESCE(auth_gen,0) FROM auth_artifacts WHERE kind=$1 AND token_hash=$2 AND consumed_at IS NULL AND expires_at>clock_timestamp()", string(kind), hash).Scan(&user, &generation); err != nil {
			return sqlError(err)
		}
		if user != "" {
			current, err := lockGeneration(ctx, tx, user)
			if err != nil {
				return err
			}
			if current != generation {
				return ErrStaleGeneration
			}
		}
		value, err := a.read(tx.QueryRow(ctx, "SELECT "+artifactColumns+" FROM auth_artifacts a WHERE kind=$1 AND token_hash=$2 AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE", string(kind), hash), kind, hash)
		if err != nil {
			return err
		}
		if value.Username != user || value.Generation != generation {
			return ErrStaleGeneration
		}
		// Expiry is checked again after row-lock waits, using the DB clock.
		var alive bool
		if err := tx.QueryRow(ctx, "SELECT expires_at>clock_timestamp() FROM auth_artifacts WHERE kind=$1 AND token_hash=$2", string(kind), hash).Scan(&alive); err != nil {
			return err
		}
		if !alive {
			return ErrNotFound
		}
		if apply != nil {
			if err := apply(ctx, tx, value); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "UPDATE auth_artifacts SET consumed_at=clock_timestamp() WHERE kind=$1 AND token_hash=$2", string(kind), hash); err != nil {
			return err
		}
		result = value
		return nil
	})
	if err != nil {
		// Preserve callback errors (e.g. duplicate account) so the caller can
		// distinguish a failed account claim from a challenge-key collision.
		return Artifact{}, err
	}
	return result, nil
}
func (a *PostgresArtifacts) Take(ctx context.Context, kind ArtifactKind, id string) (Artifact, error) {
	return a.Consume(ctx, kind, id, nil)
}
func (a *PostgresArtifacts) Delete(ctx context.Context, kind ArtifactKind, id string) error {
	hash, err := a.hash(kind, id)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	_, err = a.s.pool.Exec(ctx, "UPDATE auth_artifacts SET consumed_at=COALESCE(consumed_at,clock_timestamp()) WHERE kind=$1 AND token_hash=$2", string(kind), hash)
	return err
}

// DeleteInTx lets enrollment atomically retire its temporary secret along with
// the parent proof and account update. It never opens a second authority.
func (a *PostgresArtifacts) DeleteInTx(ctx context.Context, tx pgx.Tx, kind ArtifactKind, id string) error {
	hash, err := a.hash(kind, id)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE auth_artifacts SET consumed_at=COALESCE(consumed_at,clock_timestamp()) WHERE kind=$1 AND token_hash=$2", string(kind), hash)
	return err
}
