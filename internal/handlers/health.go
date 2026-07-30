package handlers

import (
	"net/http"
	"rauth/internal/core"
	"runtime"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

type HealthHandler struct {
	Cfg *core.Config
}

type HealthStatus struct {
	Status    string                 `json:"status"`
	Timestamp string                 `json:"timestamp"`
	Checks    map[string]string      `json:"checks"`
	GeoIP     map[string]interface{} `json:"geoip"`
	System    map[string]interface{} `json:"system"`
}

func (h *HealthHandler) Check(c echo.Context) error {
	status := "OK"
	checks := make(map[string]string, 4)

	// Redis checks. These back-ends are required for the service to function,
	// so a failure makes the service unready (503), not merely degraded.
	redisChecks := []struct {
		name   string
		client *redis.Client
	}{
		{"redis_user", core.UserDB},
		{"redis_token", core.TokenDB},
		{"redis_rate", core.RateLimitDB},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, check := range redisChecks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := check.client.Ping(core.Ctx).Err()

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				checks[check.name] = "FAIL: " + err.Error()
				status = "FAIL"
			} else {
				checks[check.name] = "OK"
			}
		}()
	}
	wg.Wait()

	// GeoIP Metadata
	geoMetadata := core.GetGeoMetadata()
	if geoMetadata["loaded"].(bool) {
		checks["geoip_database"] = "OK"
	} else {
		checks["geoip_database"] = "WARN: Not Loaded"
		if status == "OK" {
			status = "DEGRADED"
		}
	}

	// System Info
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	systemInfo := map[string]interface{}{
		"goroutines":     runtime.NumGoroutine(),
		"memory_alloc":   m.Alloc / 1024 / 1024, // MB
		"go_version":     runtime.Version(),
		"uptime_seconds": int(time.Since(core.StartTime).Seconds()),
	}

	response := HealthStatus{
		Status:    status,
		Timestamp: time.Now().Format(time.RFC3339),
		Checks:    checks,
		GeoIP:     geoMetadata,
		System:    systemInfo,
	}

	httpStatus := http.StatusOK
	if status == "FAIL" {
		httpStatus = http.StatusServiceUnavailable
	}

	return c.JSON(httpStatus, response)
}
