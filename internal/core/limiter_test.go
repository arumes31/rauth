package core

import (
	"testing"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRateLimiter(t *testing.T) {
	s := miniredis.RunT(t)
	
	// Override RateLimitDB for testing
	RateLimitDB = redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	key := "test_ip"
	max := 3
	decay := 60

	// 1st attempt
	if !CheckRateLimit(key, max, decay) {
		t.Error("1st attempt should be allowed")
	}

	// 2nd and 3rd attempts
	CheckRateLimit(key, max, decay)
	CheckRateLimit(key, max, decay)

	// 4th attempt should be blocked
	if CheckRateLimit(key, max, decay) {
		t.Error("4th attempt should be blocked")
	}

	// Reset
	ResetRateLimit(key)
	if !CheckRateLimit(key, max, decay) {
		t.Error("Attempt after reset should be allowed")
	}
}
