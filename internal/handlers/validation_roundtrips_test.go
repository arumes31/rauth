package handlers

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"rauth/internal/core"
)

type validationDispatchTracer struct {
	enabled atomic.Bool
	calls   atomic.Int32
}

func (t *validationDispatchTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	if t.enabled.Load() {
		t.calls.Add(1)
	}
	return ctx
}
func (*validationDispatchTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (t *validationDispatchTracer) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	if t.enabled.Load() {
		t.calls.Add(1)
	}
	return ctx
}
func (*validationDispatchTracer) TraceBatchQuery(context.Context, *pgx.Conn, pgx.TraceBatchQueryData) {
}
func (*validationDispatchTracer) TraceBatchEnd(context.Context, *pgx.Conn, pgx.TraceBatchEndData) {}

func TestSQLValidationUsesTwoDispatchesAndKeepsLiveRevocation(t *testing.T) {
	cfg := setupSQLRuntimeTest(t)
	cfg.TokenRotationMinutes = 0
	core.SetBcryptCost(4)
	t.Cleanup(func() { core.SetBcryptCost(12) })
	original := core.PG
	trace := &validationDispatchTracer{}
	config := original.Config()
	config.MaxConns = 1
	config.MinConns = 0
	config.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	require.NoError(t, err)
	core.PG = pool
	t.Cleanup(func() {
		trace.enabled.Store(false)
		core.PG = original
		require.NoError(t, core.InitAuthenticationState(cfg))
		pool.Close()
	})
	require.NoError(t, core.InitAuthenticationState(cfg))
	const user = "validation-dispatch-user"
	require.NoError(t, core.CreateUser(user, "Password123!", "", false, ""))
	generation, err := core.AuthGeneration(user)
	require.NoError(t, err)
	token := strings.Repeat("dispatch-token-", 4)
	encrypted, err := core.EncryptToken(token, cfg.ServerSecret)
	require.NoError(t, err)
	e := echo.New()
	c, _ := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
	ip := c.RealIP()
	require.NoError(t, core.StoreSession(token, user, ip, map[string]interface{}{"auth_gen": generation, "user_agent": c.Request().UserAgent(), "country": "unknown"}, 10*time.Minute))
	cookie := &http.Cookie{Name: "X-rauth-authtoken", Value: encrypted}
	handler := &AuthHandler{Cfg: cfg}
	validate := func() (int, string) {
		c, rec := createTestContext(e, http.MethodGet, "/rauthvalidate", nil)
		c.Request().AddCookie(cookie)
		require.NoError(t, handler.Validate(c))
		return rec.Code, rec.Header().Get("X-RAuth-User")
	}
	status, identity := validate() // Prime prepared statements outside the measured dispatch window.
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, user, identity)
	rateKey := "validate:" + core.RateLimitIP(ip)
	require.True(t, core.CheckRateLimit(rateKey, 1000, 300))
	require.True(t, core.IsRateLimitExceeded(rateKey, 1))
	_, err = pool.Exec(context.Background(), "UPDATE auth_sessions SET last_refreshed_at=clock_timestamp()-interval '40 seconds', idle_expires_at=clock_timestamp()+interval '1 minute'")
	require.NoError(t, err)
	trace.calls.Store(0)
	trace.enabled.Store(true)
	status, identity = validate()
	trace.enabled.Store(false)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, user, identity)
	require.Equal(t, int32(2), trace.calls.Load(), "live session check plus one batch must replace four serialized SQL dispatches")
	require.False(t, core.IsRateLimitExceeded(rateKey, 1))
	var refreshed, after time.Time
	require.NoError(t, pool.QueryRow(context.Background(), "SELECT last_refreshed_at FROM auth_sessions").Scan(&refreshed))
	status, identity = validate()
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, user, identity)
	require.NoError(t, pool.QueryRow(context.Background(), "SELECT last_refreshed_at FROM auth_sessions").Scan(&after))
	require.True(t, refreshed.Equal(after), "repeated validation must retain the existing refresh write bound")
	require.NoError(t, core.RevokeAuthSession(context.Background(), token))
	status, identity = validate()
	require.Equal(t, http.StatusUnauthorized, status)
	require.Empty(t, identity, "the next validation after an acknowledged revocation must not authorize")
}

func TestSQLBindingFailureKeepsCounterResetSemantics(t *testing.T) {
	cfg := setupSQLRuntimeTest(t)
	core.SetBcryptCost(4)
	t.Cleanup(func() { core.SetBcryptCost(12) })
	const user = "validation-binding-user"
	require.NoError(t, core.CreateUser(user, "Password123!", "", false, ""))
	generation, err := core.AuthGeneration(user)
	require.NoError(t, err)
	raw := strings.Repeat("binding-token-", 4)
	encrypted, err := core.EncryptToken(raw, cfg.ServerSecret)
	require.NoError(t, err)
	c, rec := createTestContext(echo.New(), http.MethodGet, "/rauthvalidate", nil)
	c.Request().Header.Set("User-Agent", "mismatched-agent")
	key := "validate:" + core.RateLimitIP(c.RealIP())
	require.NoError(t, core.StoreSession(raw, user, c.RealIP(), map[string]interface{}{"auth_gen": generation, "country": "unknown", "user_agent": "expected-agent"}, time.Minute))
	require.True(t, core.CheckRateLimit(key, 1000, 300))
	c.Request().AddCookie(&http.Cookie{Name: "X-rauth-authtoken", Value: encrypted})
	require.NoError(t, (&AuthHandler{Cfg: cfg}).Validate(c))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Empty(t, rec.Header().Get("X-RAuth-User"))
	require.False(t, core.IsRateLimitExceeded(key, 1), "binding failure keeps the previous counter reset effect")
}

func validationFixtureCookie(t *testing.T, cfg *core.Config, user string) *http.Cookie {
	t.Helper()
	core.SetBcryptCost(4)
	t.Cleanup(func() { core.SetBcryptCost(12) })
	cfg.TokenRotationMinutes = 0
	require.NoError(t, core.CreateUser(user, "Password123!", "", false, ""))
	generation, err := core.AuthGeneration(user)
	require.NoError(t, err)
	raw := strings.Repeat(user+"-token", 4)
	c, _ := createTestContext(echo.New(), http.MethodGet, "/rauthvalidate", nil)
	require.NoError(t, core.StoreSession(raw, user, c.RealIP(), map[string]interface{}{"auth_gen": generation, "country": "unknown", "user_agent": c.Request().UserAgent()}, time.Minute))
	encrypted, err := core.EncryptToken(raw, cfg.ServerSecret)
	require.NoError(t, err)
	return &http.Cookie{Name: "X-rauth-authtoken", Value: encrypted}
}

func TestSQLValidationRejectsEmptyAuthoritativeUsername(t *testing.T) {
	cfg := setupSQLRuntimeTest(t)
	cookie := validationFixtureCookie(t, cfg, "empty-name-fixture")
	generation, err := core.AuthGeneration("empty-name-fixture")
	require.NoError(t, err)
	_, err = core.PG.Exec(core.Ctx, "INSERT INTO users(username) VALUES('')")
	require.NoError(t, err)
	_, err = core.PG.Exec(core.Ctx, "INSERT INTO auth_generations(username,gen) VALUES('', $1::bigint)", generation)
	require.NoError(t, err)
	_, err = core.PG.Exec(core.Ctx, "UPDATE auth_session_families SET username=''")
	require.NoError(t, err)
	c, rec := createTestContext(echo.New(), http.MethodGet, "/rauthvalidate", nil)
	c.Request().AddCookie(cookie)
	require.NoError(t, (&AuthHandler{Cfg: cfg}).Validate(c))
	require.Equal(t, http.StatusUnauthorized, rec.Code, "the fast SQL read must preserve the empty-username gate")
	require.Empty(t, rec.Header().Get("X-RAuth-User"))
}

func TestSQLValidationRequiresPublishedDatabaseHandle(t *testing.T) {
	cfg := setupSQLRuntimeTest(t)
	cookie := validationFixtureCookie(t, cfg, "unpublished-pg-fixture")
	original := core.PG
	defer func() { core.PG = original }()
	core.PG = nil
	c, rec := createTestContext(echo.New(), http.MethodGet, "/rauthvalidate", nil)
	c.Request().AddCookie(cookie)
	require.NoError(t, (&AuthHandler{Cfg: cfg}).Validate(c))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "a partial authority teardown must still fail closed")
	require.Empty(t, rec.Header().Get("X-RAuth-User"))
}
