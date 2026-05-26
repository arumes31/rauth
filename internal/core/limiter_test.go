package core

import (
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"testing"
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

func TestIsRateLimitExceeded(t *testing.T) {
	s := miniredis.RunT(t)
	originalDB := RateLimitDB
	defer func() { RateLimitDB = originalDB }()

	RateLimitDB = redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	key := "test_exceed_ip"
	max := 3

	// Initially not exceeded
	if IsRateLimitExceeded(key, max) {
		t.Error("Should not be exceeded initially")
	}

	// Make 3 failures
	for i := 0; i < 3; i++ {
		CheckRateLimit(key, max, 60)
	}

	// Now it should be exceeded (count is 3 >= max)
	if !IsRateLimitExceeded(key, max) {
		t.Error("Should be exceeded after 3 attempts")
	}

	// Test fail-closed on DB error/disconnection
	RateLimitDB = redis.NewClient(&redis.Options{
		Addr: "localhost:12345", // Non-existent port to force connection failure
	})

	if !IsRateLimitExceeded(key, max) {
		t.Error("Should fail closed (return true) when DB is down or connection fails")
	}
}

func TestReserveRateLimitAttempt(t *testing.T) {
	s := miniredis.RunT(t)
	originalDB := RateLimitDB
	defer func() { RateLimitDB = originalDB }()

	RateLimitDB = redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})

	key := "test_reserve_ip"
	limit := 3
	decay := 60

	// 1st attempt: reserve 1 (exceeded = 1 > 3 -> false)
	exceeded, count, err := ReserveRateLimitAttempt(key, limit, decay)
	if err != nil || exceeded || count != 1 {
		t.Errorf("1st attempt failed: exceeded=%v, count=%d, err=%v", exceeded, count, err)
	}

	// 2nd and 3rd attempts: reserve 2 and 3 (exceeded = 2/3 > 3 -> false)
	_, _, _ = ReserveRateLimitAttempt(key, limit, decay)
	exceeded, count, err = ReserveRateLimitAttempt(key, limit, decay)
	if err != nil || exceeded || count != 3 {
		t.Errorf("3rd attempt failed: exceeded=%v, count=%d, err=%v", exceeded, count, err)
	}

	// 4th attempt: reserve 4 (exceeded = 4 > 3 -> true!)
	exceeded, count, err = ReserveRateLimitAttempt(key, limit, decay)
	if err != nil || !exceeded || count != 4 {
		t.Errorf("4th attempt should exceed: exceeded=%v, count=%d, err=%v", exceeded, count, err)
	}

	// Reset
	ResetRateLimit(key)
	exceeded, count, err = ReserveRateLimitAttempt(key, limit, decay)
	if err != nil || exceeded || count != 1 {
		t.Errorf("Attempt after reset failed: exceeded=%v, count=%d, err=%v", exceeded, count, err)
	}
}
