package core

import (
	"encoding/json"
	"log/slog"
	"time"
)

// auditLogMaxEntries caps the global audit log ring buffer in Redis.
const auditLogMaxEntries = 1000

// userAuditLogMaxEntries caps the per-user audit log ring buffer.
const userAuditLogMaxEntries = 100

type AuditLog struct {
	Timestamp int64                  `json:"timestamp"`
	Action    string                 `json:"action"`
	Username  string                 `json:"username"`
	IP        string                 `json:"ip"`
	Details   map[string]interface{} `json:"details"`
}

func LogAudit(action, username, ip string, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}

	// Automatically add country if not provided
	if _, ok := details["country"]; !ok {
		details["country"] = GetCountryCode(ip)
	}

	slog.Info("audit log", "action", action, "username", username, "ip", ip, "details", details)

	// Increment metrics
	AuditLogsTotal.WithLabelValues(action).Inc()

	entry := AuditLog{
		Timestamp: time.Now().Unix(),
		Action:    action,
		Username:  username,
		IP:        ip,
		Details:   details,
	}
	data, _ := json.Marshal(entry)

	pipe := AuditDB.Pipeline()
	// Global audit log
	pipe.LPush(Ctx, "audit_logs", data)
	pipe.LTrim(Ctx, "audit_logs", 0, auditLogMaxEntries-1)

	// Per-user audit log for performance (avoids filtering global logs)
	if username != "" {
		userLogKey := "user_audit_logs:" + username
		pipe.LPush(Ctx, userLogKey, data)
		pipe.LTrim(Ctx, userLogKey, 0, userAuditLogMaxEntries-1)
	}

	if _, err := pipe.Exec(Ctx); err != nil {
		slog.Error("Failed to execute LogAudit pipeline", "error", err)
	}
}
