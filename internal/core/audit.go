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
	if PG == nil {
		return
	}
	detailsJSON, _ := json.Marshal(entry.Details)
	if _, err := PG.Exec(Ctx, "INSERT INTO audit_logs (ts, action, username, ip, details) VALUES ($1, $2, $3, $4, $5)",
		entry.Timestamp, entry.Action, entry.Username, entry.IP, detailsJSON); err != nil {
		slog.Error("Failed to store audit log entry", "error", err)
	}
}

func queryAuditLogs(sql string, args ...any) ([]AuditLog, error) {
	rows, err := PG.Query(Ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	logs := []AuditLog{}
	for rows.Next() {
		var l AuditLog
		var details []byte
		if err := rows.Scan(&l.Timestamp, &l.Action, &l.Username, &l.IP, &details); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(details, &l.Details)
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

// RecentAuditLogs returns the newest entries of the global audit log.
func RecentAuditLogs(limit int) ([]AuditLog, error) {
	return queryAuditLogs("SELECT ts, action, username, ip, details FROM audit_logs ORDER BY id DESC LIMIT $1", limit)
}

// UserAuditLogs returns the newest entries owned by username. Entries older
// than the account are left out, so a recreated account does not see the
// history of a deleted one with the same name.
func UserAuditLogs(username string, limit int) ([]AuditLog, error) {
	return queryAuditLogs(`SELECT ts, action, username, ip, details FROM audit_logs
		WHERE username = $1 AND ts >= COALESCE((SELECT created_at FROM users WHERE username = $1), 0)
		ORDER BY id DESC LIMIT $2`, username, limit)
}

// PruneAuditLogs deletes entries older than retentionDays (0 keeps everything).
func PruneAuditLogs(retentionDays int) {
	if retentionDays <= 0 || PG == nil {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Unix()
	tag, err := PG.Exec(Ctx, "DELETE FROM audit_logs WHERE ts < $1", cutoff)
	if err != nil {
		slog.Error("Failed to prune audit log", "error", err)
		return
	}
	if n := tag.RowsAffected(); n > 0 {
		slog.Info("Pruned old audit log entries", "count", n, "retention_days", retentionDays)
	}
}
