package core

import (
	"encoding/json"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func TestLogAudit(t *testing.T) {
	s := miniredis.RunT(t)
	AuditDB = redis.NewClient(&redis.Options{Addr: s.Addr()})

	t.Run("Record log entry", func(t *testing.T) {
		LogAudit("TEST_ACTION", "testuser", "1.2.3.4", map[string]interface{}{"foo": "bar"})

		val, err := AuditDB.LRange(Ctx, "audit_logs", 0, -1).Result()
		assert.NoError(t, err)
		assert.Len(t, val, 1)

		var log AuditLog
		err = json.Unmarshal([]byte(val[0]), &log)
		assert.NoError(t, err)
		assert.Equal(t, "TEST_ACTION", log.Action)
		assert.Equal(t, "testuser", log.Username)
		assert.Equal(t, "1.2.3.4", log.IP)
		assert.Equal(t, "bar", log.Details["foo"])
	})

	t.Run("Log trimming", func(t *testing.T) {
		// Log 1005 times
		for i := 0; i < 1005; i++ {
			LogAudit("FILL", "user", "127.0.0.1", nil)
		}

		val, _ := AuditDB.LRange(Ctx, "audit_logs", 0, -1).Result()
		// LTrim 0, 999 keeps 1000 elements
		assert.Equal(t, 1000, len(val))
	})
}
