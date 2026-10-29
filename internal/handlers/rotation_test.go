package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"rauth/internal/core"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenRotation_Coverage(t *testing.T) {
	s := miniredis.RunT(t)
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	usePG(t)
	core.RateLimitDB = core.TokenDB
	seedAccount(t, "alice")

	cfg := &core.Config{
		TokenValidityMinutes: 10,
		TokenRotationMinutes: 5,
		CookieDomains:        []string{"example.com"},
		ServerSecret:         "12345678901234567890123456789012",
	}
	h := &AuthHandler{Cfg: cfg}

	// 1. Create an "old" session
	token := "old-token"
	redisKey := "X-rauth-authtoken=" + token
	oldTime := time.Now().Add(-6 * time.Minute).Unix()

	core.TokenDB.HSet(core.Ctx, redisKey, map[string]interface{}{
		"status":     "valid",
		"username":   "alice",
		"ip":         "127.0.0.1",
		"country":    "Internal",
		"created_at": fmt.Sprintf("%d", oldTime),
		"user_agent": "Mozilla/5.0",
	})
	core.AddSessionIndex("alice", token)
	core.AddIPSessionIndex("127.0.0.1", token)

	encrypted, _ := core.EncryptToken(token, cfg.ServerSecret)
	cookie := &http.Cookie{Name: "X-rauth-authtoken", Value: encrypted}

	// 2. Validate and trigger rotation
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/rauthvalidate", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.AddCookie(cookie)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h.Validate(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// 3. Verify new token is issued
	respCookies := rec.Result().Cookies()
	var newTokenEncrypted string
	for _, ck := range respCookies {
		if ck.Name == "X-rauth-authtoken" {
			newTokenEncrypted = ck.Value
		}
	}
	require.NotEmpty(t, newTokenEncrypted)

	newToken, err := core.DecryptToken(newTokenEncrypted, cfg.ServerSecret)
	require.NoError(t, err)
	assert.NotEqual(t, token, newToken)

	// 4. Verify new token data in Redis
	newData, err := core.TokenDB.HGetAll(core.Ctx, "X-rauth-authtoken="+newToken).Result()
	require.NoError(t, err)
	assert.Equal(t, "alice", newData["username"])

	newCreatedAt, _ := strconv.ParseInt(newData["created_at"], 10, 64)
	assert.Greater(t, newCreatedAt, oldTime)

	// 5. Verify old token has short expiry (grace period)
	ttl := core.TokenDB.TTL(core.Ctx, redisKey).Val()
	assert.LessOrEqual(t, ttl.Seconds(), float64(30))
}

// Rotation and refresh must not resurrect or extend a session that changed
// after Validate read it.
func TestTokenRotation_RacesWithTermination(t *testing.T) {
	s := miniredis.RunT(t)
	core.TokenDB = redis.NewClient(&redis.Options{Addr: s.Addr()})
	usePG(t)
	core.RateLimitDB = core.TokenDB
	seedAccount(t, "alice")
	h := &AuthHandler{Cfg: &core.Config{TokenValidityMinutes: 10, TokenRotationMinutes: 5}}
	old := time.Now().Add(-6 * time.Minute).Unix()

	t.Run("terminated session is not re-created", func(t *testing.T) {
		// Validate read the session, then the owner terminated it.
		newToken, ok := h.rotateSession("gone", "alice", "127.0.0.1", old, 10*time.Minute)
		assert.False(t, ok)
		assert.Zero(t, core.TokenDB.Exists(core.Ctx, "X-rauth-authtoken=gone", "X-rauth-authtoken="+newToken).Val())
	})

	t.Run("second rotation and refresh leave the retired token alone", func(t *testing.T) {
		core.TokenDB.HSet(core.Ctx, "X-rauth-authtoken=live", "status", "valid", "username", "alice", "created_at", old)
		core.TokenDB.Expire(core.Ctx, "X-rauth-authtoken=live", 10*time.Minute)
		first, ok := h.rotateSession("live", "alice", "127.0.0.1", time.Now().Unix(), 10*time.Minute)
		require.True(t, ok)
		assert.Equal(t, "valid", core.TokenDB.HGet(core.Ctx, "X-rauth-authtoken="+first, "status").Val())
		assert.True(t, core.TokenDB.SIsMember(core.Ctx, "user_sessions:alice", first).Val())

		// A concurrent request that read "live" before the rotation loses.
		_, ok = h.rotateSession("live", "alice", "127.0.0.1", time.Now().Unix(), 10*time.Minute)
		assert.False(t, ok)
		core.RefreshSession("live", 10*time.Minute)
		assert.LessOrEqual(t, core.TokenDB.TTL(core.Ctx, "X-rauth-authtoken=live").Val(), rotationGrace)
		assert.Equal(t, first, core.TokenDB.HGet(core.Ctx, "X-rauth-authtoken=live", "rotated_to").Val())
	})
}
