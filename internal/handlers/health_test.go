package handlers

import (
	"time"
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

	t.Run("Redis RateLimitDB Failure", func(t *testing.T) {
		originalRateLimitDB := core.RateLimitDB
		failClient := redis.NewClient(&redis.Options{Addr: "localhost:1"})
		core.RateLimitDB = failClient
		defer func() { core.RateLimitDB = originalRateLimitDB }()

		c, rec := createTestContext(e, http.MethodGet, "/health", nil)

		err := h.Check(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "FAIL")
	})

	t.Run("Redis AuditDB Failure", func(t *testing.T) {
		originalAuditDB := core.AuditDB
		failClient := redis.NewClient(&redis.Options{Addr: "localhost:1"})
		core.AuditDB = failClient
		defer func() { core.AuditDB = originalAuditDB }()

		c, rec := createTestContext(e, http.MethodGet, "/health", nil)

		err := h.Check(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "FAIL")
	})

	t.Run("Redis InviteDB Failure", func(t *testing.T) {
		originalInviteDB := core.InviteDB
		failClient := redis.NewClient(&redis.Options{Addr: "localhost:1"})
		core.InviteDB = failClient
		defer func() { core.InviteDB = originalInviteDB }()

		c, rec := createTestContext(e, http.MethodGet, "/health", nil)

		err := h.Check(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Contains(t, rec.Body.String(), "FAIL")
	})

	t.Run("Multiple Redis Failure Concurrency Check", func(t *testing.T) {
		originalUser := core.UserDB
		originalToken := core.TokenDB
		failClient := redis.NewClient(&redis.Options{Addr: "localhost:1", DialTimeout: 1 * time.Second})
		core.UserDB = failClient
		core.TokenDB = failClient
		defer func() {
			core.UserDB = originalUser
			core.TokenDB = originalToken
		}()

		c, rec := createTestContext(e, http.MethodGet, "/health", nil)
		err := h.Check(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})
}
