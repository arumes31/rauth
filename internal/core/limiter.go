package core

import (
	"time"
	"strings"
)

func CheckRateLimit(key string, maxAttempts int, decaySeconds int) bool {
	fullKey := "rate_limit:" + key

	count, err := RateLimitDB.Incr(Ctx, fullKey).Result()
	if err != nil {
		return true // Fail open if Redis is down? Or return false? Let's stay with true for now.
	}

	if count == 1 {
		RateLimitDB.Expire(Ctx, fullKey, time.Duration(decaySeconds)*time.Second)
	}

	if int(count) > maxAttempts {
		metricType := strings.SplitN(key, ":", 2)[0]
		RateLimitHitsTotal.WithLabelValues(metricType).Inc()
		return false
	}

	return true
}

func IsRateLimitExceeded(key string, maxAttempts int) bool {
	fullKey := "rate_limit:" + key
	count, err := RateLimitDB.Get(Ctx, fullKey).Int()
	if err != nil {
		return false // Treat missing or error as not exceeded
	}
	return count > maxAttempts
}

func ResetRateLimit(key string) {
	RateLimitDB.Del(Ctx, "rate_limit:"+key)
}
