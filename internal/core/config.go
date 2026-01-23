package core

import (
	"fmt"
	"os"
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
}

func LoadConfig() *Config {
	return &Config{
		ServerSecret:         getEnv("SERVER_SECRET", ""),
		RedisHost:            getEnv("REDIS_HOST", "rauth-auth-redis"),
		RedisPort:            getEnv("REDIS_PORT", "6379"),
		RedisPassword:        getEnv("REDIS_PASSWORD", ""),
		CookieDomain:         getEnv("COOKIE_DOMAIN", "reitetschlaeger.com"),
		TokenValidityMinutes: getEnvInt("TOKEN_VALIDITY_MINUTES", 2880),
		GeoApiHost:           getEnv("GEO_API_HOST", "rauth-geo-service"),
		GeoApiPort:           getEnv("GEO_API_PORT", "3000"),
		InitialUser:          getEnv("INITIAL_USER", "admin"),
		InitialPassword:      getEnv("INITIAL_PASSWORD", ""),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
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
