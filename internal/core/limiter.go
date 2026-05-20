package core

import (
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
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
		if err == redis.Nil {
			return false
		}
		// Redis error, fail closed
		return true
	}
	count, err := strconv.Atoi(countStr)
	if err != nil {
		// Parse error, fail closed
		return true
	}
	return count >= maxAttempts
}

func ReserveRateLimitAttempt(key string, limit int, decaySeconds int) (bool, int, error) {
	fullKey := "rate_limit:" + key

	count, err := RateLimitDB.Incr(Ctx, fullKey).Result()
	if err != nil {
		return true, 0, err
	}

	if count == 1 {
		RateLimitDB.Expire(Ctx, fullKey, time.Duration(decaySeconds)*time.Second)
	}

	exceeded := int(count) > limit
	if exceeded {
		metricType := strings.SplitN(key, ":", 2)[0]
		RateLimitHitsTotal.WithLabelValues(metricType).Inc()
	}

	return exceeded, int(count), nil
}
