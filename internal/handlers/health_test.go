package handlers

import (
	"net/http"
	"rauth/internal/core"
	"testing"

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

	// Redis is a required dependency, so a failed ping makes the service
	// unready: status FAIL with HTTP 503 (readiness), not merely degraded.
	t.Run("Redis UserDB Failure", func(t *testing.T) {
		originalUserDB := core.UserDB
		failClient := redis.NewClient(&redis.Options{Addr: "localhost:1"})
		core.UserDB = failClient
		defer func() { core.UserDB = originalUserDB }()

		c, rec := createTestContext(e, http.MethodGet, "/health", nil)

		err := h.Check(c)
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
