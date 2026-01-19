package core

import (
	"time"
)

func CheckRateLimit(key string, maxAttempts int, decaySeconds int) bool {
	fullKey := "rate_limit:" + key
	
	count, err := RateLimitDB.Get(Ctx, fullKey).Int()
	if err != nil { // Key doesn't exist
		RateLimitDB.Set(Ctx, fullKey, 1, time.Duration(decaySeconds)*time.Second)
		return true
	}

	if count >= maxAttempts {
		return false
	}

	RateLimitDB.Incr(Ctx, fullKey)
	return true
}

func ResetRateLimit(key string) {
	RateLimitDB.Del(Ctx, "rate_limit:"+key)
}
