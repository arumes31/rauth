package handlers

import (
	"net/http"
	"rauth/internal/core"
	"runtime"
	"time"

	"github.com/labstack/echo/v4"
)

type HealthHandler struct {
	Cfg *core.Config
}

type HealthStatus struct {
	Status    string            `json:"status"`
	Timestamp string            `json:"timestamp"`
	Checks    map[string]string `json:"checks"`
	System    map[string]interface{} `json:"system"`
}

func (h *HealthHandler) Check(c echo.Context) error {
	status := "OK"
	checks := make(map[string]string)

	// Redis Checks
	if err := core.UserDB.Ping(core.Ctx).Err(); err != nil {
		checks["redis_user"] = "FAIL: " + err.Error()
		status = "DEGRADED"
	} else {
		checks["redis_user"] = "OK"
	}

	if err := core.TokenDB.Ping(core.Ctx).Err(); err != nil {
		checks["redis_token"] = "FAIL: " + err.Error()
		status = "DEGRADED"
	} else {
		checks["redis_token"] = "OK"
	}

	// GeoIP Check
	if core.GetGeoReaderStatus() {
		checks["geoip_database"] = "OK"
	} else {
		checks["geoip_database"] = "WARN: Not Loaded"
		if status == "OK" { status = "DEGRADED" }
	}

	// System Info
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	systemInfo := map[string]interface{}{
		"goroutines":    runtime.NumGoroutine(),
		"memory_alloc":  m.Alloc / 1024 / 1024, // MB
		"go_version":    runtime.Version(),
		"uptime_seconds": int(time.Since(core.StartTime).Seconds()),
	}

	response := HealthStatus{
		Status:    status,
		Timestamp: time.Now().Format(time.RFC3339),
		Checks:    checks,
		System:    systemInfo,
	}

	httpStatus := http.StatusOK
	if status == "FAIL" {
		httpStatus = http.StatusServiceUnavailable
	}

	return c.JSON(httpStatus, response)
}
