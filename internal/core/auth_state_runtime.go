package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"rauth/internal/authstate"
)

const authStateAuthorityKey = "auth_state_authority"

// Stop all authentication writers before cutover. This interval also ages out
// every legacy TOTP proof, which is deliberately not imported from Redis.
const authStateCutoverQuarantine = 2 * time.Minute

var ErrAuthStateQuarantine = errors.New("SQL authentication activation is waiting for legacy proofs to expire")

type authStateAuthorityRecord struct {
	Mode           string    `json:"mode"`
	ServerKeyCheck string    `json:"server_key_check"`
	CutoverAt      time.Time `json:"cutover_at"`
	ReadyAfter     time.Time `json:"ready_after"`
	LegacyExpired  bool      `json:"legacy_expired"`
}

func serverKeyCheck(secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("rauth-cluster-cookie-key-v1"))
	return hex.EncodeToString(mac.Sum(nil))
}
func validServerKeyCheck(check string) bool {
	decoded, err := hex.DecodeString(check)
	return err == nil && len(decoded) == 32
}
func configuredAuthStateMode(cfg *Config) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.AuthStateMode))
	if mode == "" {
		mode = "redis"
	}
	if mode != "redis" && mode != "postgres" {
		return "", errors.New("AUTH_STATE_MODE must be redis or postgres")
	}
	return mode, nil
}

// parseAuthStateAuthority keeps offline cutover and runtime activation on the
// same authority-marker contract.
func parseAuthStateAuthority(data string) (authStateAuthorityRecord, bool) {
	var record authStateAuthorityRecord
	if err := json.Unmarshal([]byte(data), &record); err != nil {
		return authStateAuthorityRecord{}, false
	}
	if record.Mode != "postgres-v1" || !validServerKeyCheck(record.ServerKeyCheck) || !record.LegacyExpired || record.CutoverAt.IsZero() || record.ReadyAfter.Before(record.CutoverAt.Add(authStateCutoverQuarantine)) {
		return authStateAuthorityRecord{}, false
	}
	return record, true
}
func readAuthStateAuthority(ctx context.Context) (authStateAuthorityRecord, error) {
	var record authStateAuthorityRecord
	if PG == nil {
		return record, errors.New("authentication database is not initialized")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var data string
	err := PG.QueryRow(ctx, "SELECT value FROM app_meta WHERE key=$1", authStateAuthorityKey).Scan(&data)
	if isNoRows(err) {
		return record, nil
	}
	if err != nil {
		return record, err
	}
	record, valid := parseAuthStateAuthority(data)
	if !valid {
		return authStateAuthorityRecord{}, errors.New("invalid durable authentication authority marker")
	}
	return record, nil
}
func sqlAuthStateConfig(cfg *Config) (*authstate.Keyring, time.Duration, error) {
	if len(cfg.ServerSecret) < 16 {
		return nil, 0, errors.New("SQL authentication requires the existing validated SERVER_SECRET")
	}
	// Validate minutes before multiplying, including integer-overflow inputs.
	if cfg.TokenValidityMinutes < 1 || cfg.AuthStateAbsoluteMinutes < cfg.TokenValidityMinutes || cfg.AuthStateAbsoluteMinutes > 365*24*60 {
		return nil, 0, errors.New("SQL authentication requires idle duration >=1 minute and absolute duration between idle and 365 days")
	}
	keys, err := authstate.LoadKeyring(cfg.AuthStateKeyFile)
	return keys, time.Duration(cfg.AuthStateAbsoluteMinutes) * time.Minute, err
}

// InitAuthenticationState must run once before any HTTP/background handlers.
// Marker checks prevent a new compatible binary from silently restarting with
// legacy authorization after cutover. Older binaries must be drained explicitly.
func InitAuthenticationState(cfg *Config) error {
	mode, err := configuredAuthStateMode(cfg)
	if err != nil {
		return err
	}
	record, err := readAuthStateAuthority(Ctx)
	if err != nil {
		return err
	}
	if mode == "redis" {
		if record.Mode != "" {
			return errors.New("SQL is authoritative; restarting Redis authorization is prohibited")
		}
		if err := InitRedis(cfg); err != nil {
			return err
		}
		if err := ImportFromRedis(cfg); err != nil {
			return err
		}
		securitySessions = nil
		securityArtifacts = nil
		securityCounters = nil
		securitySessionAbsoluteTTL = 0
		return nil
	}
	if record.Mode != "postgres-v1" {
		return errors.New("coordinated SQL authentication cutover has not been committed")
	}
	if !hmac.Equal([]byte(record.ServerKeyCheck), []byte(serverKeyCheck(cfg.ServerSecret))) {
		return errors.New("SERVER_SECRET does not match the SQL authentication fleet")
	}
	ctx, cancel := context.WithTimeout(Ctx, 3*time.Second)
	defer cancel()
	var imported, ready, primary bool
	err = PG.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM app_meta WHERE key=$1),clock_timestamp()>=$2,NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off'`, redisImportMarker, record.ReadyAfter).Scan(&imported, &ready, &primary)
	if err != nil {
		return err
	}
	if !imported || !primary {
		return errors.New("SQL authentication requires completed durable import and a writable primary")
	}
	if !ready {
		return ErrAuthStateQuarantine
	}
	keys, absolute, err := sqlAuthStateConfig(cfg)
	if err != nil {
		return err
	}
	sessions, err := authstate.NewPostgresSessions(Ctx, PG, keys)
	if err != nil {
		return err
	}
	// Publish all three authorities only after every validation succeeds. There
	// is no environment flag that enables only half of the SQL state paths.
	ServerSecret = cfg.ServerSecret // TOTP initialization is independent of Redis.
	securitySessions = sessions
	securityArtifacts = sessions.Artifacts()
	securityCounters = sessions.Counters()
	securitySessionAbsoluteTTL = absolute
	TokenDB = nil
	RateLimitDB = nil
	InviteDB = nil
	return nil
}

// CommitSQLAuthenticationCutover is an explicit offline operation, never a
// normal startup side effect. The deployment must first stop every old writer,
// back up the database, and keep it stopped until the fleet starts in SQL mode.
// Repeating a committed cutover never expires new SQL sessions again.
func CommitSQLAuthenticationCutover(ctx context.Context, cfg *Config) (time.Time, error) {
	mode, err := configuredAuthStateMode(cfg)
	if err != nil {
		return time.Time{}, err
	}
	if mode != "postgres" {
		return time.Time{}, errors.New("cutover requires AUTH_STATE_MODE=postgres")
	}
	keys, _, err := sqlAuthStateConfig(cfg)
	if err != nil {
		return time.Time{}, err
	}
	if _, err = authstate.NewPostgresSessions(ctx, PG, keys); err != nil {
		return time.Time{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var readyAfter time.Time
	err = pgx.BeginFunc(ctx, PG, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "LOCK TABLE app_meta IN EXCLUSIVE MODE"); err != nil {
			return err
		}
		var imported bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM app_meta WHERE key=$1)", redisImportMarker).Scan(&imported); err != nil {
			return err
		}
		if !imported {
			return errors.New("durable Redis import marker is required before SQL cutover")
		}
		var previous string
		err := tx.QueryRow(ctx, "SELECT value FROM app_meta WHERE key=$1", authStateAuthorityKey).Scan(&previous)
		if err == nil {
			record, valid := parseAuthStateAuthority(previous)
			if !valid {
				return errors.New("invalid existing authentication authority marker")
			}
			if !hmac.Equal([]byte(record.ServerKeyCheck), []byte(serverKeyCheck(cfg.ServerSecret))) {
				return errors.New("SERVER_SECRET does not match committed SQL authentication")
			}
			readyAfter = record.ReadyAfter
			return nil
		}
		if !isNoRows(err) {
			return err
		}
		var now time.Time
		if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			return err
		}
		// New SQL proofs start after a deliberate one-time expiry. Account IDs,
		// password hashes, factors and recovery codes remain in the durable store.
		if _, err := tx.Exec(ctx, `INSERT INTO auth_generations(username,gen) SELECT username,1 FROM users ON CONFLICT(username) DO UPDATE SET gen=auth_generations.gen+1`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "TRUNCATE auth_session_families,auth_sessions,auth_session_tokens,auth_step_up_grants,auth_artifacts,auth_security_counters,auth_sso_transactions"); err != nil {
			return err
		}
		readyAfter = now.Add(authStateCutoverQuarantine)
		data, err := json.Marshal(authStateAuthorityRecord{Mode: "postgres-v1", ServerKeyCheck: serverKeyCheck(cfg.ServerSecret), CutoverAt: now, ReadyAfter: readyAfter, LegacyExpired: true})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO app_meta(key,value) VALUES($1,$2)", authStateAuthorityKey, string(data))
		return err
	})
	return readyAfter, err
}

func SQLAuthenticationEnabled() bool { return securitySessions != nil }
func CheckAuthenticationAuthority(ctx context.Context) error {
	if !SQLAuthenticationEnabled() {
		return nil
	}
	record, err := readAuthStateAuthority(ctx)
	if err != nil {
		return err
	}
	if record.Mode != "postgres-v1" {
		return errors.New("SQL authentication authority marker missing")
	}
	if !hmac.Equal([]byte(record.ServerKeyCheck), []byte(serverKeyCheck(ServerSecret))) {
		return errors.New("SQL authentication server key no longer matches")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var ready bool
	err = PG.QueryRow(ctx, "SELECT clock_timestamp()>=$1 AND NOT pg_is_in_recovery() AND current_setting('transaction_read_only')='off'", record.ReadyAfter).Scan(&ready)
	if err != nil {
		return err
	}
	if !ready {
		return fmt.Errorf("SQL authentication primary is not ready")
	}
	return nil
}
func CleanupAuthenticationState(ctx context.Context) error {
	if !SQLAuthenticationEnabled() {
		return nil
	}
	cleanup, ok := securitySessions.(interface{ Cleanup(context.Context) error })
	if !ok {
		return errors.New("selected SQL authority does not support cleanup")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return cleanup.Cleanup(ctx)
}
