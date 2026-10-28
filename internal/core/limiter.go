package core

import (
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

// incrAndExpireScript atomically increments a counter and, on its first
// increment, sets the decay TTL. Doing both in one round-trip removes the race
// where a crash between INCR and EXPIRE could leave a counter without a TTL
// (a permanent lock).
var incrAndExpireScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then
	redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return count
`)

// ipv6BucketBits is the prefix length IPv6 clients are aggregated to for rate
// limiting. A single subscriber usually controls a whole /64, so keying on the
// full address would hand them 2^64 independent budgets.
const ipv6BucketBits = 64

// RateLimitIP returns the rate-limit bucket for a client IP: IPv4 addresses are
// used as-is, IPv6 addresses are masked to their /64. Unparseable input is
// returned unchanged.
func RateLimitIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return parsed.Mask(net.CIDRMask(ipv6BucketBits, 128)).String() + "/64"
}

func incrAndExpire(fullKey string, decaySeconds int) (int64, error) {
	return incrAndExpireScript.Run(Ctx, RateLimitDB, []string{fullKey}, decaySeconds).Int64()
}

func CheckRateLimit(key string, maxAttempts int, decaySeconds int) bool {
	fullKey := "rate_limit:" + key

	count, err := incrAndExpire(fullKey, decaySeconds)
	if err != nil {
		// Fail closed: if Redis is unavailable we cannot account for attempts,
		// so deny rather than allow. This matches IsRateLimitExceeded's policy.
		slog.Error("Rate limit check failed, failing closed", "key", key, "error", err)
		return false
	}

	if int(count) > maxAttempts {
		metricType := strings.SplitN(key, ":", 2)[0]
		RateLimitHitsTotal.WithLabelValues(metricType).Inc()
		return false
	}

	return true
}

func ResetRateLimit(key string) {
	RateLimitDB.Del(Ctx, "rate_limit:"+key)
}

func IsRateLimitExceeded(key string, maxAttempts int) bool {
	fullKey := "rate_limit:" + key
	countStr, err := RateLimitDB.Get(Ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			return false
		}
		slog.Error("Redis rate limit check failed", "key", key, "error", err)
		// Redis error, fail closed
		return true
	}
	count, err := strconv.Atoi(countStr)
	if err != nil {
		slog.Error("Failed to parse rate limit count", "key", key, "countStr", countStr, "error", err)
		// Parse error, fail closed
		return true
	}
	return count >= maxAttempts
}

func ReserveRateLimitAttempt(key string, limit int, decaySeconds int) (bool, int, error) {
	fullKey := "rate_limit:" + key

	count, err := incrAndExpire(fullKey, decaySeconds)
	if err != nil {
		// Fail closed: treat an unavailable backend as "exceeded".
		return true, 0, err
	}

	exceeded := int(count) > limit
	if exceeded {
		metricType := strings.SplitN(key, ":", 2)[0]
		RateLimitHitsTotal.WithLabelValues(metricType).Inc()
	}

	return exceeded, int(count), nil
}
