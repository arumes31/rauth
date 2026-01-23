package core

import (
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

	return int(count) <= maxAttempts
}

func ResetRateLimit(key string) {
	RateLimitDB.Del(Ctx, "rate_limit:"+key)
}

func AccountLockout(username string, maxAttempts int, lockoutMinutes int) bool {
	key := "lockout:" + username
	
	count, err := RateLimitDB.Get(Ctx, key).Int()
	if err != nil && err.Error() != "redis: nil" {
		return true // Fail open
	}

	if count >= maxAttempts {
		return false // Locked
	}

	return true
}

func IncrementLockout(username string, lockoutMinutes int) {
	key := "lockout:" + username
	RateLimitDB.Incr(Ctx, key)
	RateLimitDB.Expire(Ctx, key, time.Duration(lockoutMinutes)*time.Minute)
}
