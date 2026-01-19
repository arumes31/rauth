package core

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	os.Setenv("SERVER_SECRET", "testsecret1234567890123456789012")
	os.Setenv("INITIAL_USER", "tester")

	cfg := LoadConfig()

	if cfg.ServerSecret != "testsecret1234567890123456789012" {
		t.Errorf("Expected SERVER_SECRET to be testsecret1234567890123456789012, got %s", cfg.ServerSecret)
	}

	if cfg.InitialUser != "tester" {
		t.Errorf("Expected INITIAL_USER to be tester, got %s", cfg.InitialUser)
	}

	// Test fallback
	os.Unsetenv("REDIS_PORT")
	cfg2 := LoadConfig()
	if cfg2.RedisPort != "6379" {
		t.Errorf("Expected default REDIS_PORT 6379, got %s", cfg2.RedisPort)
	}
}
