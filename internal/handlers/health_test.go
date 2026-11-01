package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"rauth/internal/core"
	"rauth/internal/testfile"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthCheck(t *testing.T) {
	setupHandlersTest(t)
	cfg := &core.Config{}
	h := &HealthHandler{Cfg: cfg}
	e := echo.New()

	t.Run("Success or GeoIP Degraded", func(t *testing.T) {
		c, rec := createTestContext(e, http.MethodGet, "/health", nil)

		err := h.Check(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "\"status\"")
	})

	// Postgres and Redis are required dependencies, so a failed ping makes the
	// service unready: status FAIL with HTTP 503 (readiness), not merely degraded.
	t.Run("Postgres Failure", func(t *testing.T) {
		originalPG := core.PG
		failPool, err := pgxpool.New(core.Ctx, "postgres://localhost:1/none?connect_timeout=1")
		assert.NoError(t, err)
		failPool.Close()
		core.PG = failPool
		defer func() { core.PG = originalPG }()

		c, rec := createTestContext(e, http.MethodGet, "/health", nil)

		err = h.Check(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "FAIL")
	})

	t.Run("Redis TokenDB Failure", func(t *testing.T) {
		originalTokenDB := core.TokenDB
		failClient := redis.NewClient(&redis.Options{Addr: "localhost:1"})
		core.TokenDB = failClient
		defer func() { core.TokenDB = originalTokenDB }()

		c, rec := createTestContext(e, http.MethodGet, "/health", nil)

		err := h.Check(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "FAIL")
	})
}

func setupSQLRuntimeTest(t *testing.T) *core.Config {
	t.Helper()
	setupHandlersTest(t)
	originalSecret := core.ServerSecret
	cfg := core.LoadConfig()
	cfg.ServerSecret = "32byte-secret-key-for-testing-!!"
	cfg.CookieDomains = []string{"example.com"}
	cfg.TokenValidityMinutes = 60
	cfg.RateLimitLoginAccessMax = 1000
	cfg.RateLimitLoginMax = 1000
	cfg.RateLimitLoginFailUserMax = 1000
	cfg.RateLimitLoginFailIPMax = 1000
	cfg.RateLimitValidateMax = 1000
	cfg.AuthStateMode = "postgres"
	cfg.AuthStateAbsoluteMinutes = 120
	data, err := json.Marshal(map[string]any{"index_key": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("i", 32))), "active_key_id": "v1", "encryption_keys": map[string]string{"v1": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32)))}})
	require.NoError(t, err)
	cfg.AuthStateKeyFile = filepath.Join(t.TempDir(), "auth-state.json")
	testfile.WritePrivate(t, cfg.AuthStateKeyFile, data)
	_, err = core.PG.Exec(core.Ctx, "INSERT INTO app_meta(key,value) VALUES('redis_import','already imported')")
	require.NoError(t, err)
	_, err = core.CommitSQLAuthenticationCutover(core.Ctx, cfg)
	require.NoError(t, err)
	_, err = core.PG.Exec(core.Ctx, `UPDATE app_meta SET value=jsonb_set(jsonb_set(value::jsonb,'{cutover_at}',to_jsonb(clock_timestamp()-interval '3 minutes')),'{ready_after}',to_jsonb(clock_timestamp()-interval '1 minute'))::text WHERE key='auth_state_authority'`)
	require.NoError(t, err)
	require.NoError(t, core.InitAuthenticationState(cfg))
	t.Cleanup(func() {
		_, err := core.PG.Exec(core.Ctx, "DELETE FROM app_meta WHERE key='auth_state_authority'")
		require.NoError(t, err)
		require.NoError(t, core.InitAuthenticationState(&core.Config{ServerSecret: originalSecret, RedisHost: "127.0.0.1", RedisPort: sharedMiniredis.Port()}))
	})
	require.Nil(t, core.TokenDB)
	require.Nil(t, core.RateLimitDB)
	require.Nil(t, core.InviteDB)
	return cfg
}

func TestSQLHealthRequiresNoRedisAuthority(t *testing.T) {
	cfg := setupSQLRuntimeTest(t)
	c, rec := createTestContext(echo.New(), http.MethodGet, "/health", nil)
	require.NoError(t, (&HealthHandler{Cfg: cfg}).Check(c))
	assert.Equal(t, http.StatusOK, rec.Code)
	var status HealthStatus
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &status))
	assert.Equal(t, "OK", status.Checks["postgres"])
	assert.Equal(t, "OK", status.Checks["auth_state"])
	for _, check := range []string{"redis_token", "redis_rate", "redis_invite"} {
		assert.NotContains(t, status.Checks, check)
	}
}
