package handlers

import (
	"errors"
	"log/slog"
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
	System    map[string]interface{} `json:"system,omitempty"`
}

func redisPing(client *redis.Client) func() error {
	return func() error { return client.Ping(core.Ctx).Err() }
}

func (h *HealthHandler) Check(c echo.Context) error {
	// /health is public. File paths and runtime details are only returned to
	// clients inside METRICS_ALLOWED_IPS; everyone gets the status and
	// per-check verdicts. Raw errors are logged, never returned.
	detailed := h.Cfg.IsClientAllowed(c.RealIP(), c.Request().RemoteAddr, h.Cfg.MetricsAllowedIPs)
	status := "OK"
	checks := make(map[string]string, 4)

	// Back-end checks. These are required for the service to function, so a
	// failure makes the service unready (503), not merely degraded.
	checkFuncs := []struct {
		name string
		ping func() error
	}{
		{"postgres", func() error {
			if core.PG == nil {
				return errors.New("postgres not initialized")
			}
			return core.PG.Ping(core.Ctx)
		}},
		{"redis_token", redisPing(core.TokenDB)},
		{"redis_rate", redisPing(core.RateLimitDB)},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, check := range checkFuncs {
		name := check.name
		ping := check.ping
		wg.Add(1)
		go func(name string, ping func() error) {
			defer wg.Done()
			err := ping()

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// The raw error can contain dial addresses; keep it in the logs.
				slog.Error("Health check failed", "check", name, "error", err)
				checks[name] = "FAIL"
				status = "FAIL"
			} else {
				checks[name] = "OK"
			}
		}(name, ping)
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

	// System Info (trusted clients only)
	var systemInfo map[string]interface{}
	if detailed {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		systemInfo = map[string]interface{}{
			"goroutines":     runtime.NumGoroutine(),
			"memory_alloc":   m.Alloc / 1024 / 1024, // MB
			"go_version":     runtime.Version(),
			"uptime_seconds": int(time.Since(core.StartTime).Seconds()),
		}
	} else {
		geoMetadata = map[string]interface{}{"loaded": geoMetadata["loaded"]}
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
