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
	CookieDomain             string
	TokenValidityMinutes     int
	AllowedHosts             []string
	GeoApiHost               string
	GeoApiPort               string
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
		CookieDomain:         getEnv("COOKIE_DOMAIN", "example.com"),
		TokenValidityMinutes: getEnvInt("TOKEN_VALIDITY_MINUTES", 2880),
		AllowedHosts:         getEnvSlice("ALLOWED_HOSTS", []string{"localhost", "127.0.0.1"}),
		GeoApiHost:           getEnv("GEO_API_HOST", "rauth-geo-service"),
		GeoApiPort:           getEnv("GEO_API_PORT", "3000"),
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
	for _, h := range c.AllowedHosts {
		if h == host {
			return true
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
