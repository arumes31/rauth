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
		{"evil-example.com", false},
		{"example.com.evil.com", false},
	}

	for _, tt := range tests {
		if got := cfg.IsAllowedHost(tt.host); got != tt.expected {
			t.Errorf("IsAllowedHost(%s) = %v; want %v", tt.host, got, tt.expected)
		}
	}
}

func TestIsCountryAllowed(t *testing.T) {
	tests := []struct {
		name             string
		allowedCountries []string
		country          string
		want             bool
	}{
		{"Empty list allowed all", []string{}, "US", true},
		{"Exact match", []string{"US", "GB"}, "US", true},
		{"Case insensitive match", []string{"us", "gb"}, "US", true},
		{"Case insensitive match 2", []string{"US", "GB"}, "gb", true},
		{"No match", []string{"US", "GB"}, "FR", false},
		{"Empty country input", []string{"US", "GB"}, "", false},
		{"Internal access match", []string{"Internal", "US"}, "Internal", true},
		{"Internal access case insensitive", []string{"internal", "us"}, "Internal", true},
		{"Tailscale access match", []string{"Tailscale", "US"}, "Tailscale", true},
		{"Unknown country match", []string{"unknown", "US"}, "unknown", true},
		{"Whitespace in allowed list", []string{" US ", "GB"}, "US", true},
		{"Whitespace in input", []string{"US", "GB"}, " US ", true},
		{"Whitespace in both", []string{" US ", "GB"}, " US ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{AllowedCountries: tt.allowedCountries}
			if got := cfg.IsCountryAllowed(tt.country); got != tt.want {
				t.Errorf("IsCountryAllowed(%s) with allowed %v = %v, want %v", tt.country, tt.allowedCountries, got, tt.want)
			}
		})
	}
}

func TestIsIPAllowed(t *testing.T) {
	cfg := &Config{}
	tests := []struct {
		name        string
		ipStr       string
		allowedList []string
		want        bool
	}{
		{"Invalid IP", "not-an-ip", []string{"127.0.0.1"}, false},
		{"Empty IP", "", []string{"127.0.0.1"}, false},
		{"Empty allowed list", "127.0.0.1", []string{}, false},
		{"Exact match IPv4", "127.0.0.1", []string{"127.0.0.1"}, true},
		{"Exact match IPv6", "::1", []string{"::1"}, true},
		{"CIDR match IPv4", "192.168.1.5", []string{"192.168.1.0/24"}, true},
		{"CIDR match IPv6", "2001:db8::1", []string{"2001:db8::/32"}, true},
		{"No match", "1.1.1.1", []string{"127.0.0.1", "192.168.1.0/24"}, false},
		{"Invalid CIDR in list", "127.0.0.1", []string{"invalid/cidr"}, false},
		{"Mixed list match", "192.168.1.5", []string{"127.0.0.1", "192.168.1.0/24"}, true},
		{"IPv4-mapped IPv6 match", "::ffff:127.0.0.1", []string{"127.0.0.1"}, true},
		{"IPv4-mapped IPv6 match reversed", "127.0.0.1", []string{"::ffff:127.0.0.1"}, true},
		{"Expanded IPv6 match", "0:0:0:0:0:0:0:1", []string{"::1"}, true},
		{"Compressed IPv6 match", "::1", []string{"0:0:0:0:0:0:0:1"}, true},
		{"CIDR IPv4-mapped IPv6 match", "::ffff:192.168.1.5", []string{"192.168.1.0/24"}, true},
		{"CIDR match with host bits set", "192.168.1.5", []string{"192.168.1.5/24"}, true},
		{"IPv4 in IPv6 range match", "2001:db8::1", []string{"2001:db8::/32"}, true},
		{"Mismatch IPv4 and IPv6", "127.0.0.1", []string{"::1"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cfg.IsIPAllowed(tt.ipStr, tt.allowedList); got != tt.want {
				t.Errorf("IsIPAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
