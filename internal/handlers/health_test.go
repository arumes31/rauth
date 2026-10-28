package handlers

import (
	"net/http"
	"rauth/internal/core"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
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
