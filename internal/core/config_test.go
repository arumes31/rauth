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

func TestIsAllowedHost(t *testing.T) {
	cfg := &Config{
		CookieDomains: []string{"example.com", "other.org"},
		AllowedHosts:  []string{"localhost"},
	}

	tests := []struct {
		host     string
		expected bool
	}{
		{"example.com", true},
		{"app.example.com", true},
		{"sub.app.example.com", true},
		{"other.org", true},
		{"localhost", true},
		{"evil.com", false},
		{"notexample.com", false},
		{"example.com.evil.com", false},
	}

	for _, tt := range tests {
		if got := cfg.IsAllowedHost(tt.host); got != tt.expected {
			t.Errorf("IsAllowedHost(%s) = %v; want %v", tt.host, got, tt.expected)
		}
	}
}
