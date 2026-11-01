package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"rauth/internal/authstate"
)

type AuthArtifactKind = authstate.ArtifactKind

const (
	PendingSecondFactor = authstate.Pending2FA
	PendingEnrollment   = authstate.PendingEnrollment
	EnrollmentSecret    = authstate.EnrollmentSecret
	PasskeyRegistration = authstate.PasskeyRegistration
	PasskeyLogin        = authstate.PasskeyLogin
	Invitation          = authstate.Invitation
)

var ErrAuthArtifactMissing = authstate.ErrNotFound

// Selected once before serving requests. Nil retains the legacy development
// adapter; SQL mode will select all authorities together after call-site migration.
var securityArtifacts authstate.ArtifactStore
var securityCounters authstate.CounterStore

func artifactAuthority() authstate.ArtifactStore {
	if securityArtifacts != nil {
		return securityArtifacts
	}
	return redisArtifacts{}
}
func StoreAuthArtifact(kind AuthArtifactKind, id string, data []byte, user, gen string, ttl time.Duration) error {
	if (kind == PendingSecondFactor || kind == PendingEnrollment) && string(data) != PendingTokenValue(user, gen) {
		return errors.New("pending proof does not match its owner")
	}
	var generation int64
	var err error
	if user != "" {
		generation, err = strconv.ParseInt(gen, 10, 64)
		if err != nil || generation < 0 {
			return authstate.ErrStaleGeneration
		}
	}
	if kind != Invitation && ttl > 15*time.Minute {
		return errors.New("challenge duration exceeds its limit")
	}
	return artifactAuthority().Put(Ctx, kind, id, authstate.Artifact{Data: data, Username: user, Generation: generation}, ttl)
}
func validArtifactGeneration(a authstate.Artifact) error {
	if a.Username == "" {
		return nil
	}
	current, err := AuthGeneration(a.Username)
	if err != nil {
		return err
	}
	if current != strconv.FormatInt(a.Generation, 10) {
		return authstate.ErrStaleGeneration
	}
	return nil
}
func GetAuthArtifact(kind AuthArtifactKind, id string) ([]byte, error) {
	a, err := artifactAuthority().Get(Ctx, kind, id)
	if err == nil {
		err = validArtifactGeneration(a)
	}
	if err != nil {
		return nil, err
	}
	return a.Data, nil
}
func TakeAuthArtifact(kind AuthArtifactKind, id string) ([]byte, error) {
	a, err := artifactAuthority().Take(Ctx, kind, id)
	if err == nil {
		err = validArtifactGeneration(a)
	}
	if err != nil {
		return nil, err
	}
	return a.Data, nil
}
func DeleteAuthArtifact(kind AuthArtifactKind, id string) error {
	return artifactAuthority().Delete(Ctx, kind, id)
}

// EnrollmentSecretValue makes repeated page loads and node handoffs display the
// same temporary secret. Only an expired secret can be replaced.
func EnrollmentSecretValue(id, user, gen, candidate string) (string, error) {
	if err := StoreAuthArtifact(EnrollmentSecret, id, []byte(candidate), user, gen, 5*time.Minute); err != nil && !errors.Is(err, authstate.ErrConflict) {
		return "", err
	}
	value, err := GetAuthArtifact(EnrollmentSecret, id)
	return string(value), err
}

type redisArtifacts struct{}

func artifactRedis(kind AuthArtifactKind) (*redis.Client, error) {
	switch kind {
	case PendingSecondFactor, PendingEnrollment, EnrollmentSecret, PasskeyRegistration, PasskeyLogin:
		if TokenDB != nil {
			return TokenDB, nil
		}
	case Invitation:
		if InviteDB != nil {
			return InviteDB, nil
		}
	default:
		return nil, errors.New("invalid authentication artifact kind")
	}
	return nil, errors.New("authentication store unavailable")
}
func artifactKeys(kind AuthArtifactKind, id string) (string, string, error) {
	if id == "" || len(id) > 512 || strings.ContainsRune(id, 0) {
		return "", "", errors.New("invalid challenge identifier")
	}
	key := string(kind) + ":" + id
	return key, "auth_artifact_meta:" + key, nil
}

var putArtifactScript = redis.NewScript(`
if redis.call("EXISTS",KEYS[1])==1 then return 0 end
redis.call("PSETEX",KEYS[1],ARGV[3],ARGV[1])
redis.call("PSETEX",KEYS[2],ARGV[3],ARGV[2])
return 1`)
var readArtifactScript = redis.NewScript(`
local value=redis.call("GET",KEYS[1]);if not value then return false end
local meta=redis.call("GET",KEYS[2]) or ""
return {value,meta,redis.call("PTTL",KEYS[1])}`)
var takeArtifactScript = redis.NewScript(`
local value=redis.call("GET",KEYS[1]);if not value then return false end
local meta=redis.call("GET",KEYS[2]) or ""
local ttl=redis.call("PTTL",KEYS[1]);redis.call("DEL",KEYS[1],KEYS[2]);return {value,meta,ttl}`)

func (redisArtifacts) Put(ctx context.Context, kind AuthArtifactKind, id string, a authstate.Artifact, ttl time.Duration) error {
	client, err := artifactRedis(kind)
	if err != nil {
		return err
	}
	key, meta, err := artifactKeys(kind, id)
	if err != nil {
		return err
	}
	if ttl < time.Second || ttl > 7*24*time.Hour || len(a.Data) > 65500 {
		return errors.New("invalid authentication artifact")
	}
	metadata, err := json.Marshal(struct {
		Username   string
		Generation int64
	}{a.Username, a.Generation})
	if err != nil {
		return err
	}
	n, err := putArtifactScript.Run(ctx, client, []string{key, meta}, a.Data, metadata, ttl.Milliseconds()).Int()
	if err == nil && n == 0 {
		return authstate.ErrConflict
	}
	return err
}
func decodeRedisArtifact(values []interface{}) (authstate.Artifact, error) {
	var a authstate.Artifact
	if len(values) != 3 {
		return a, authstate.ErrNotFound
	}
	data, ok := values[0].(string)
	if !ok {
		return a, errors.New("invalid authentication artifact")
	}
	a.Data = []byte(data)
	metadata, _ := values[1].(string)
	if metadata != "" {
		if err := json.Unmarshal([]byte(metadata), &a); err != nil {
			return a, errors.New("invalid authentication metadata")
		}
	}
	ttl, _ := values[2].(int64)
	if ttl > 0 {
		a.ExpiresAt = time.Now().Add(time.Duration(ttl) * time.Millisecond)
	}
	return a, nil
}
func readRedisArtifact(ctx context.Context, kind AuthArtifactKind, id string, take bool) (authstate.Artifact, error) {
	client, err := artifactRedis(kind)
	if err != nil {
		return authstate.Artifact{}, err
	}
	key, meta, err := artifactKeys(kind, id)
	if err != nil {
		return authstate.Artifact{}, err
	}
	script := readArtifactScript
	if take {
		script = takeArtifactScript
	}
	values, err := script.Run(ctx, client, []string{key, meta}).Slice()
	if errors.Is(err, redis.Nil) {
		return authstate.Artifact{}, authstate.ErrNotFound
	}
	if err != nil {
		return authstate.Artifact{}, err
	}
	return decodeRedisArtifact(values)
}
func (redisArtifacts) Get(ctx context.Context, kind AuthArtifactKind, id string) (authstate.Artifact, error) {
	return readRedisArtifact(ctx, kind, id, false)
}
func (redisArtifacts) Take(ctx context.Context, kind AuthArtifactKind, id string) (authstate.Artifact, error) {
	return readRedisArtifact(ctx, kind, id, true)
}
func (redisArtifacts) Delete(ctx context.Context, kind AuthArtifactKind, id string) error {
	client, err := artifactRedis(kind)
	if err != nil {
		return err
	}
	key, meta, err := artifactKeys(kind, id)
	if err != nil {
		return err
	}
	return client.Del(ctx, key, meta).Err()
}

// CompleteSecondFactorEnrollment claims the parent proof and stores the factor
// in one SQL transaction. Legacy development mode claims once before writing;
// it never restores an ambiguous proof.
func CompleteSecondFactorEnrollment(id, user, gen, encrypted string) (bool, error) {
	expected := PendingTokenValue(user, gen)
	if sql, ok := securityArtifacts.(*authstate.PostgresArtifacts); ok {
		_, err := sql.Consume(Ctx, PendingEnrollment, id, func(ctx context.Context, tx pgx.Tx, a authstate.Artifact) error {
			if string(a.Data) != expected {
				return authstate.ErrStaleGeneration
			}
			current, err := lockAuthGenerationContext(ctx, tx, user, gen)
			if err != nil {
				return err
			}
			if !current {
				return authstate.ErrStaleGeneration
			}
			tag, err := tx.Exec(ctx, "UPDATE users SET totp_secret=$2 WHERE username=$1 AND totp_secret=''", user, encrypted)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return errEnrollmentIneligible
			}
			return sql.DeleteInTx(ctx, tx, EnrollmentSecret, id)
		})
		if errors.Is(err, errEnrollmentIneligible) || errors.Is(err, authstate.ErrNotFound) || errors.Is(err, authstate.ErrStaleGeneration) {
			return false, nil
		}
		return err == nil, err
	}
	data, err := TakeAuthArtifact(PendingEnrollment, id)
	if errors.Is(err, ErrAuthArtifactMissing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !PendingArtifactMatches(data, user, gen) {
		return false, nil
	}
	stored, err := SetSecondFactorIfUnset(user, encrypted, gen)
	_ = DeleteAuthArtifact(EnrollmentSecret, id)
	return stored, err
}

var errEnrollmentIneligible = errors.New("second factor enrollment is no longer eligible")

// RedeemInvitation atomically creates the account and consumes the invitation
// under SQL authority. Callback failure rolls back both; there is no restore
// window that can recreate a successfully redeemed invitation.
func RedeemInvitation(id, user, password string) error {
	if sql, ok := securityArtifacts.(*authstate.PostgresArtifacts); ok {
		hash, err := HashPassword(password)
		if err != nil {
			return err
		}
		_, err = sql.Consume(Ctx, Invitation, id, func(ctx context.Context, tx pgx.Tx, a authstate.Artifact) error {
			if _, err := tx.Exec(ctx, `INSERT INTO auth_generations(username,gen) VALUES($1,1) ON CONFLICT(username) DO UPDATE SET gen=auth_generations.gen+1`, user); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO users(username,password,email,groups,is_admin,totp_secret,uid,created_at) VALUES($1,$2,$3,'default',false,'',$4,$5)`, user, hash, string(a.Data), uuid.New(), time.Now().Unix())
			return err
		})
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return errUserExists
		}
		return err
	}
	a, err := artifactAuthority().Take(Ctx, Invitation, id)
	if err != nil {
		return err
	}
	// The legacy adapter retains existing single-node behavior until coordinated
	// cutover. Its failed-account restore uses the remaining original TTL.
	err = CreateUser(user, password, string(a.Data), false, "")
	if err != nil {
		ttl := time.Until(a.ExpiresAt)
		if a.ExpiresAt.IsZero() {
			ttl = 24 * time.Hour
		}
		if ttl > time.Second {
			_ = artifactAuthority().Put(Ctx, Invitation, id, a, ttl)
		}
	}
	return err
}

func RegistrationBrowserBinding(identity, secret string) string {
	m := hmac.New(sha256.New, hkdfKey(secret, "rauth-passkey-registration-binding-v1"))
	m.Write([]byte(identity))
	return hex.EncodeToString(m.Sum(nil))
}

// PendingArtifactMatches preserves the legacy generation-zero encoding while
// requiring the same account/generation after the one-use claim.
func PendingArtifactMatches(data []byte, user, gen string) bool {
	resolved, generation, current := ResolvePendingToken(string(data))
	return current && resolved == user && generation == gen
}
