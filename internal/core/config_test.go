package core

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	_ = os.Setenv("SERVER_SECRET", "testsecret1234567890123456789012")
	_ = os.Setenv("INITIAL_USER", "tester")
	_ = os.Setenv("INITIAL_PASS", "TestPass123!")
	_ = os.Setenv("AUTH_DOMAIN", "example.com")
	_ = os.Setenv("REDIS_HOST", "localhost")

	cfg := LoadConfig()

	if cfg.ServerSecret != "testsecret1234567890123456789012" {
		t.Errorf("Expected SERVER_SECRET to be testsecret1234567890123456789012, got %s", cfg.ServerSecret)
	}

	if cfg.InitialUser != "tester" {
		t.Errorf("Expected INITIAL_USER to be tester, got %s", cfg.InitialUser)
	}

	// Test fallback
	_ = os.Unsetenv("REDIS_PORT")
	cfg2 := LoadConfig()
	if cfg2.RedisPort != "6379" {
		t.Errorf("Expected default REDIS_PORT 6379, got %s", cfg2.RedisPort)
	}
}

func TestGetEnvHelpers(t *testing.T) {
	_ = os.Setenv("TEST_INT", "123")
	_ = os.Setenv("TEST_BOOL", "true")
	_ = os.Setenv("TEST_SLICE", "a,b,c")

	if v := getEnvInt("TEST_INT", 0); v != 123 {
		t.Errorf("getEnvInt failed, got %d", v)
	}
	if v := getEnvBool("TEST_BOOL", false); v != true {
		t.Errorf("getEnvBool failed")
	}
	vSlice := getEnvSlice("TEST_SLICE", []string{})
	if len(vSlice) != 3 || vSlice[0] != "a" {
		t.Errorf("getEnvSlice failed")
	}

	// Fallbacks
	if v := getEnvInt("NONEXISTENT", 456); v != 456 {
		t.Errorf("getEnvInt fallback failed")
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
