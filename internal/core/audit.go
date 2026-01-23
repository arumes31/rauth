package core

import (
	"encoding/json"
	"log/slog"
	"time"
)

type AuditLog struct {
	Timestamp int64                  `json:"timestamp"`
	Action    string                 `json:"action"`
	Username  string                 `json:"username"`
	IP        string                 `json:"ip"`
	Details   map[string]interface{} `json:"details"`
}

func LogAudit(action, username, ip string, details map[string]interface{}) {
	slog.Info("audit log", "action", action, "username", username, "ip", ip, "details", details)

	entry := AuditLog{
		Timestamp: time.Now().Unix(),
		Action:    action,
		Username:  username,
		IP:        ip,
		Details:   details,
	}
	data, _ := json.Marshal(entry)
	AuditDB.LPush(Ctx, "audit_logs", data)
	AuditDB.LTrim(Ctx, "audit_logs", 0, 999)
}
