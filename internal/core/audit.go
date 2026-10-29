package core

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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
	if err := insertAuditLog(Ctx, PG, entry, true); err != nil {
		slog.Error("Failed to store audit log entry", "error", err)
	}
}

// insertAuditLog stores one entry. Audit fields can carry attacker input, and
// Postgres text and jsonb values cannot hold NUL, so NULs are replaced with
// U+FFFD instead of failing the insert (which would drop the entry).
//
// With linkOwner the entry records the UID of the account currently holding
// the username, which UserAuditLogs selects by. The Redis import passes
// false: its entries may belong to an earlier account with the same name.
func insertAuditLog(ctx context.Context, db interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, l AuditLog, linkOwner bool) error {
	_, err := db.Exec(ctx, `INSERT INTO audit_logs (ts, action, username, ip, details, user_uid)
		VALUES ($1, $2, $3, $4, $5, CASE WHEN $6::boolean THEN (SELECT uid FROM users WHERE username = $3) END)`,
		l.Timestamp, stripNUL(l.Action), stripNUL(l.Username), stripNUL(l.IP), auditDetailsJSON(l.Details), linkOwner && l.Username != "")
	return err
}

func stripNUL(s string) string {
	return strings.ReplaceAll(s, "\x00", "�")
}

// auditDetailsJSON encodes details for the jsonb column, which rejects the
// \u0000 escape. Only payloads containing it take the slower rewrite path.
func auditDetailsJSON(details map[string]interface{}) []byte {
	if details == nil {
		return []byte("{}")
	}
	b, err := json.Marshal(details)
	if err != nil {
		return []byte("{}")
	}
	if !bytes.Contains(b, []byte(`\u0000`)) {
		return b
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return []byte("{}")
	}
	b, _ = json.Marshal(stripNULDeep(v))
	return b
}

func stripNULDeep(v any) any {
	switch t := v.(type) {
	case string:
		return stripNUL(t)
	case []any:
		for i := range t {
			t[i] = stripNULDeep(t[i])
		}
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[stripNUL(k)] = stripNULDeep(x)
		}
		return m
	}
	return v
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

// UserAuditLogs returns the newest entries owned by the account currently
// named username, so a recreated account does not see the history of a
// deleted one with the same name. Entries carry the owner's UID; older ones
// without it are shown only when strictly newer than the account (timestamps
// have one-second precision, so the creation second itself is ambiguous).
func UserAuditLogs(username string, limit int) ([]AuditLog, error) {
	return queryAuditLogs(`SELECT a.ts, a.action, a.username, a.ip, a.details
		FROM audit_logs a LEFT JOIN users u ON u.username = $1
		WHERE a.username = $1
			AND (a.user_uid = u.uid OR (a.user_uid IS NULL AND a.ts > COALESCE(u.created_at, -1)))
		ORDER BY a.id DESC LIMIT $2`, username, limit)
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
