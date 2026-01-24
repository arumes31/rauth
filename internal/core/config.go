package core

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ServerSecret             string
	RedisHost                string
	RedisPort                string
	RedisPassword            string
	CookieDomains            []string
	TokenValidityMinutes     int
	AllowedHosts             []string
	GeoApiHost               string
	GeoApiPort               string
	MaxMindDBPath            string
	MetricsAllowedIPs        []string
	InitialUser              string
	InitialPassword          string
	InitialEmail             string
	Initial2FASecret         string
	// Password Policy
	MinPasswordLength    int
	RequirePasswordUpper  bool
	RequirePasswordLower  bool
	RequirePasswordNumber bool
	RequirePasswordSpecial bool
}

func LoadConfig() *Config {
	return &Config{
		ServerSecret:         getEnv("SERVER_SECRET", ""),
		RedisHost:            getEnv("REDIS_HOST", "rauth-auth-redis"),
		RedisPort:            getEnv("REDIS_PORT", "6379"),
		RedisPassword:        getEnv("REDIS_PASSWORD", ""),
		CookieDomains:        getEnvSlice("COOKIE_DOMAIN", []string{"example.com"}),
		TokenValidityMinutes: getEnvInt("TOKEN_VALIDITY_MINUTES", 2880),
		AllowedHosts:         getEnvSlice("ALLOWED_HOSTS", []string{"localhost", "127.0.0.1"}),
		GeoApiHost:           getEnv("GEO_API_HOST", "rauth-geo-service"),
		GeoApiPort:           getEnv("GEO_API_PORT", "3000"),
		MaxMindDBPath:        getEnv("MAXMIND_DB_PATH", "/app/geoip/GeoLite2-Country.mmdb"),
		MetricsAllowedIPs:    getEnvSlice("METRICS_ALLOWED_IPS", []string{"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}),
		InitialUser:          getEnv("INITIAL_USER", "admin"),
		InitialPassword:      getEnv("INITIAL_PASSWORD", ""),
		InitialEmail:         getEnv("INITIAL_EMAIL", "admin@local"),
		Initial2FASecret:     getEnv("INITIAL_2FA_SECRET", ""),
		// Password Policy Defaults
		MinPasswordLength:     getEnvInt("PWD_MIN_LENGTH", 8),
		RequirePasswordUpper:  getEnvBool("PWD_REQUIRE_UPPER", true),
		RequirePasswordLower:  getEnvBool("PWD_REQUIRE_LOWER", true),
		RequirePasswordNumber: getEnvBool("PWD_REQUIRE_NUMBER", true),
		RequirePasswordSpecial: getEnvBool("PWD_REQUIRE_SPECIAL", true),
	}
}

func (c *Config) IsAllowedHost(host string) bool {
	// Remove port if present
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	// Check explicit allowed hosts
	for _, h := range c.AllowedHosts {
		if h == host {
			return true
		}
	}

	// Check if host is part of any cookie domain
	for _, domain := range c.CookieDomains {
		// Exact match
		if host == domain {
			return true
		}
		// Subdomain match (e.g., app.example.com for example.com)
		// Fix: Ensure we match a dot before the domain to avoid suffix abuse (e.g. evil-example.com)
		if strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
}

func (c *Config) IsIPAllowed(ipStr string, allowedList []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, allowed := range allowedList {
		// Check if it's a CIDR
		if strings.Contains(allowed, "/") {
			_, ipNet, err := net.ParseCIDR(allowed)
			if err == nil && ipNet.Contains(ip) {
				return true
			}
		} else {
			// Check for exact IP match
			if allowed == ipStr {
				return true
			}
		}
	}
	return false
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvSlice(key string, fallback []string) []string {
	if value, ok := os.LookupEnv(key); ok {
		return strings.Split(value, ",")
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		var i int
		if _, err := fmt.Sscanf(value, "%d", &i); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if value, ok := os.LookupEnv(key); ok {
		return strings.ToLower(value) == "true" || value == "1"
	}
	return fallback
}
