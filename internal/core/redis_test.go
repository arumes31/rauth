package core

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func TestInitRedis(t *testing.T) {
	s := miniredis.RunT(t)

	cfg := &Config{
		RedisHost: "127.0.0.1",
		RedisPort: s.Port(),
	}

	err := InitRedis(cfg)
	assert.NoError(t, err)

	assert.NotNil(t, UserDB)
	assert.NotNil(t, TokenDB)
	assert.NotNil(t, RateLimitDB)
	assert.NotNil(t, AuditDB)

	// Verify they point to different DBs
	assert.Equal(t, 0, UserDB.Options().DB)
	assert.Equal(t, 1, TokenDB.Options().DB)
	assert.Equal(t, 2, RateLimitDB.Options().DB)
	assert.Equal(t, 3, AuditDB.Options().DB)
}

func TestHasActiveSessions(t *testing.T) {
	s := miniredis.RunT(t)
	defer s.Close()

	TokenDB = redis.NewClient(&redis.Options{
		Addr: s.Addr(),
		DB:   1,
	})
	Ctx = context.Background()

	ip := "1.2.3.4"
	otherIP := "5.6.7.8"

	// No sessions
	assert.False(t, HasActiveSessions(ip))

	// Session with different IP
	TokenDB.HSet(Ctx, "X-rauth-authtoken=token1", map[string]interface{}{
		"ip":     otherIP,
		"status": "valid",
	})
	assert.False(t, HasActiveSessions(ip))

	// Valid session with matching IP
	TokenDB.HSet(Ctx, "X-rauth-authtoken=token2", map[string]interface{}{
		"ip":     ip,
		"status": "valid",
	})
	assert.True(t, HasActiveSessions(ip))

	// Invalid session with matching IP
	TokenDB.HSet(Ctx, "X-rauth-authtoken=token3", map[string]interface{}{
		"ip":     ip,
		"status": "expired",
	})
	// Still true because of token2
	assert.True(t, HasActiveSessions(ip))

	// Remove token2, should be false (only token3 left which is expired)
	TokenDB.Del(Ctx, "X-rauth-authtoken=token2")
	assert.False(t, HasActiveSessions(ip))
}
