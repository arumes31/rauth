package core

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"rauth/internal/testfile"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"rauth/internal/authstate"
)

func runtimeAuthStateFixture(t *testing.T) *Config {
	t.Helper()
	newRegressionRedis(t)
	data, err := json.Marshal(map[string]any{"index_key": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("i", 32))), "active_key_id": "v1", "encryption_keys": map[string]string{"v1": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32)))}})
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "auth-state.json")
	testfile.WritePrivate(t, file, data)
	return &Config{ServerSecret: ServerSecret, AuthStateMode: "postgres", AuthStateKeyFile: file, TokenValidityMinutes: 30, AuthStateAbsoluteMinutes: 60, RedisHost: "must-not-be-used.invalid", RedisPort: "6379"}
}
func TestSQLAuthStateCutoverIsExplicitAtomicAndIdempotent(t *testing.T) {
	cfg := runtimeAuthStateFixture(t)
	SetBcryptCost(4)
	t.Cleanup(func() { SetBcryptCost(12) })
	require.NoError(t, CreateUser("cutover-user", "Password123!", "unchanged@example.com", true, ""))
	original, err := GetUser("cutover-user")
	require.NoError(t, err)
	before := currentGen(t, "cutover-user")
	require.Error(t, InitAuthenticationState(cfg), "SQL cannot silently activate before offline cutover")
	_, err = CommitSQLAuthenticationCutover(Ctx, cfg)
	require.Error(t, err, "missing durable import must abort")
	assert.Equal(t, before, currentGen(t, "cutover-user"))
	require.NoError(t, func() error {
		_, err := PG.Exec(Ctx, "INSERT INTO app_meta(key,value) VALUES($1,'already imported')", redisImportMarker)
		return err
	}())
	var group sync.WaitGroup
	var deadlines [2]time.Time
	var failures [2]error
	for i := range deadlines {
		group.Add(1)
		go func(i int) { defer group.Done(); deadlines[i], failures[i] = CommitSQLAuthenticationCutover(Ctx, cfg) }(i)
	}
	group.Wait()
	for _, err := range failures {
		require.NoError(t, err)
	}
	assert.True(t, deadlines[0].Equal(deadlines[1]), "cutover deadlines must represent the same instant")
	require.ErrorIs(t, InitAuthenticationState(cfg), ErrAuthStateQuarantine)
	assert.False(t, SQLAuthenticationEnabled())
	legacy := *cfg
	legacy.AuthStateMode = "redis"
	require.Error(t, InitAuthenticationState(&legacy), "rollback must not reopen Redis authorization")
	// Simulate elapsed DB time without sleeping through the production gate.
	record, err := readAuthStateAuthority(Ctx)
	require.NoError(t, err)
	require.NoError(t, PG.QueryRow(Ctx, "SELECT clock_timestamp()-interval '3 minutes'").Scan(&record.CutoverAt))
	record.ReadyAfter = record.CutoverAt.Add(authStateCutoverQuarantine)
	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	_, err = PG.Exec(Ctx, "UPDATE app_meta SET value=$2 WHERE key=$1", authStateAuthorityKey, string(encoded))
	require.NoError(t, err)
	require.NoError(t, InitAuthenticationState(cfg))
	assert.True(t, SQLAuthenticationEnabled())
	require.NotNil(t, securityArtifacts)
	require.NotNil(t, securityCounters)
	assert.Nil(t, TokenDB)
	assert.Nil(t, RateLimitDB)
	assert.Nil(t, InviteDB)
	wrong := *cfg
	wrong.ServerSecret = strings.Repeat("wrong-cookie-key-", 3)
	require.Error(t, InitAuthenticationState(&wrong))
	_, err = CommitSQLAuthenticationCutover(Ctx, &wrong)
	require.Error(t, err)
	assert.Equal(t, cfg.ServerSecret, ServerSecret, "failed initialization cannot replace the current fleet key")
	require.NoError(t, CheckAuthenticationAuthority(Ctx))
	after := currentGen(t, "cutover-user")
	assert.NotEqual(t, before, after)
	sameUser, err := GetUser("cutover-user")
	require.NoError(t, err)
	assert.Equal(t, original, sameUser, "cutover must preserve account identity and credentials")
	token := strings.Repeat("a", 64)
	require.NoError(t, StoreSession(token, "cutover-user", "203.0.113.1", map[string]interface{}{"auth_gen": after}, time.Minute))
	deadline, err := CommitSQLAuthenticationCutover(Ctx, cfg)
	require.NoError(t, err)
	assert.True(t, record.ReadyAfter.Equal(deadline), "idempotent cutover preserves the activation instant")
	assert.Equal(t, after, currentGen(t, "cutover-user"))
	_, err = ReadAuthSession(Ctx, token)
	require.NoError(t, err)
	require.NoError(t, CleanupAuthenticationState(Ctx))
	cfg.AuthStateKeyFile = filepath.Join(t.TempDir(), "missing-key-file")
	require.Error(t, InitAuthenticationState(cfg))
	_, err = ReadAuthSession(Ctx, token)
	require.NoError(t, err, "failed initialization cannot switch an existing selected authority to Redis")
	require.NoError(t, RevokeAuthSession(Ctx, token))
	_, err = ReadAuthSession(Ctx, token)
	require.ErrorIs(t, err, authstate.ErrNotFound)
}
func TestAuthStateRuntimeRejectsInvalidConfigurationAndMarker(t *testing.T) {
	cfg := runtimeAuthStateFixture(t)
	cfg.AuthStateMode = "unknown"
	require.Error(t, InitAuthenticationState(cfg))
	cfg.AuthStateMode = "postgres"
	_, err := PG.Exec(Ctx, "INSERT INTO app_meta(key,value) VALUES($1,'corrupt')", authStateAuthorityKey)
	require.NoError(t, err)
	require.Error(t, InitAuthenticationState(cfg))
	assert.False(t, SQLAuthenticationEnabled())
	cfg.AuthStateMode = "redis"
	require.Error(t, InitAuthenticationState(cfg))
	cfg.AuthStateAbsoluteMinutes = 0
	_, _, err = sqlAuthStateConfig(cfg)
	require.Error(t, err)
	cfg.AuthStateAbsoluteMinutes = 366 * 24 * 60
	_, _, err = sqlAuthStateConfig(cfg)
	require.Error(t, err)
}

func TestSQLAuthenticationDatabaseRequiresVerifiedTLS(t *testing.T) {
	for _, test := range []struct {
		mode, ssl string
		valid     bool
	}{
		{"redis", "disable", true},
		{"postgres", "disable", false},
		{"postgres", "prefer", false},
		{"postgres", "require", false},
		{"postgres", "verify-ca", false},
		{"postgres", "verify-full", true},
	} {
		t.Run(test.mode+"-"+test.ssl, func(t *testing.T) {
			pool, err := pgxpool.ParseConfig("postgres://example.com/rauth?sslmode=" + test.ssl)
			require.NoError(t, err)
			err = configureAuthStateDatabase(&Config{AuthStateMode: test.mode}, pool)
			if test.valid {
				require.NoError(t, err)
				if test.mode == "postgres" {
					require.NotNil(t, pool.AfterConnect)
				}
			} else {
				require.Error(t, err)
			}
		})
	}
}
