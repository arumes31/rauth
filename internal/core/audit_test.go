package core

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogAudit(t *testing.T) {
	setupPG(t)

	t.Run("Record log entry", func(t *testing.T) {
		LogAudit("TEST_ACTION", "testuser", "1.2.3.4", map[string]interface{}{"foo": "bar"})

		logs, err := RecentAuditLogs(100)
		require.NoError(t, err)
		require.Len(t, logs, 1)
		assert.Equal(t, "TEST_ACTION", logs[0].Action)
		assert.Equal(t, "testuser", logs[0].Username)
		assert.Equal(t, "1.2.3.4", logs[0].IP)
		assert.Equal(t, "bar", logs[0].Details["foo"])
	})

	t.Run("NUL bytes are replaced, not dropped", func(t *testing.T) {
		LogAudit("NUL_TEST", "x\x00y", "1.2.3.4", map[string]interface{}{"k\x00": []interface{}{"v\x00", 12345678901234567}})

		logs, err := RecentAuditLogs(1)
		require.NoError(t, err)
		require.Len(t, logs, 1)
		assert.Equal(t, "NUL_TEST", logs[0].Action)
		assert.Equal(t, "x�y", logs[0].Username)
		assert.Equal(t, []interface{}{"v�", 12345678901234567.0}, logs[0].Details["k�"])
	})

	t.Run("Newest first and limited", func(t *testing.T) {
		for i := 0; i < 105; i++ {
			LogAudit("FILL", "user", "127.0.0.1", map[string]interface{}{"i": i})
		}
		logs, err := RecentAuditLogs(100)
		require.NoError(t, err)
		assert.Len(t, logs, 100)
		assert.EqualValues(t, 104, logs[0].Details["i"])
	})

	t.Run("Per-user logs", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			LogAudit("ACTION_user1", "user1", "127.0.0.1", map[string]interface{}{"i": i})
		}
		logs, err := UserAuditLogs("user1", 100)
		require.NoError(t, err)
		require.Len(t, logs, 5)
		assert.Equal(t, "user1", logs[0].Username)
		assert.Equal(t, fmt.Sprintf("ACTION_%s", "user1"), logs[0].Action)
	})

	t.Run("Recreated account does not inherit history", func(t *testing.T) {
		_, err := PG.Exec(Ctx, "INSERT INTO audit_logs (ts, action, username) VALUES ($1, 'OLD', 'reborn')", time.Now().Add(-time.Hour).Unix())
		require.NoError(t, err)
		require.NoError(t, PutUser(User{Username: "reborn", CreatedAt: time.Now().Unix()}))
		LogAudit("NEW", "reborn", "127.0.0.1", nil)
		logs, err := UserAuditLogs("reborn", 100)
		require.NoError(t, err)
		require.Len(t, logs, 1)
		assert.Equal(t, "NEW", logs[0].Action)
	})

	t.Run("Prune by retention", func(t *testing.T) {
		_, err := PG.Exec(Ctx, "INSERT INTO audit_logs (ts, action) VALUES ($1, 'ANCIENT')", time.Now().AddDate(0, 0, -40).Unix())
		require.NoError(t, err)
		PruneAuditLogs(30)
		var n int
		require.NoError(t, PG.QueryRow(Ctx, "SELECT count(*) FROM audit_logs WHERE action = 'ANCIENT'").Scan(&n))
		assert.Equal(t, 0, n)
		require.NoError(t, PG.QueryRow(Ctx, "SELECT count(*) FROM audit_logs WHERE action = 'NEW'").Scan(&n))
		assert.Equal(t, 1, n)
	})
}
