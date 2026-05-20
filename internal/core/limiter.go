package core

import (
	"strconv"
	"strings"
	"time"
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

func ResetRateLimit(key string) {
	RateLimitDB.Del(Ctx, "rate_limit:"+key)
}

func IsRateLimitExceeded(key string, maxAttempts int) bool {
	fullKey := "rate_limit:" + key
	countStr, err := RateLimitDB.Get(Ctx, fullKey).Result()
	if err != nil {
		return false
	}
	count, _ := strconv.Atoi(countStr)
	return count >= maxAttempts
}
