package handlers

import (
	"encoding/json"
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

		var response HealthStatus
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)

		// status should be OK if GeoIP is loaded, or DEGRADED if not.
		// Redis should be OK because setupHandlersTest sets it up.
		assert.Equal(t, "OK", response.Checks["redis_user"])
		assert.Equal(t, "OK", response.Checks["redis_token"])

		geoLoaded := response.GeoIP["loaded"].(bool)
		if geoLoaded {
			assert.Equal(t, "OK", response.Status)
			assert.Equal(t, "OK", response.Checks["geoip_database"])
		} else {
			assert.Equal(t, "DEGRADED", response.Status)
			assert.Equal(t, "WARN: Not Loaded", response.Checks["geoip_database"])
		}
	})

	t.Run("Redis UserDB Failure", func(t *testing.T) {
		originalUserDB := core.UserDB
		// Point to an unreachable address to simulate failure
		failClient := redis.NewClient(&redis.Options{Addr: "localhost:1"})
		core.UserDB = failClient
		defer func() { core.UserDB = originalUserDB }()

		c, rec := createTestContext(e, http.MethodGet, "/health", nil)

		err := h.Check(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response HealthStatus
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "DEGRADED", response.Status)
		assert.Contains(t, response.Checks["redis_user"], "FAIL")
	})

	t.Run("Redis TokenDB Failure", func(t *testing.T) {
		originalTokenDB := core.TokenDB
		failClient := redis.NewClient(&redis.Options{Addr: "localhost:1"})
		core.TokenDB = failClient
		defer func() { core.TokenDB = originalTokenDB }()

		c, rec := createTestContext(e, http.MethodGet, "/health", nil)

		err := h.Check(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response HealthStatus
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "DEGRADED", response.Status)
		assert.Contains(t, response.Checks["redis_token"], "FAIL")
	})
}
