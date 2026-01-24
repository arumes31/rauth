package core

import (
	"log/slog"
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

var (
	GeoCache     = make(map[string]string)
	GeoCacheLock sync.RWMutex
	geoReader    *geoip2.Reader
	once         sync.Once
)

// InitGeoReader initializes the MaxMind database reader
func InitGeoReader() {
	once.Do(func() {
		cfg := LoadConfig()
		reader, err := geoip2.Open(cfg.MaxMindDBPath)
		if err != nil {
			slog.Warn("Failed to open MaxMind database", "path", cfg.MaxMindDBPath, "error", err)
			return
		}
		geoReader = reader
	})
}

func GetCountryCode(ipStr string) string {
	if IsPrivateIP(ipStr) {
		return "Internal"
	}

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return "unknown"
	}

	// Check for Tailscale (CGNAT range 100.64.0.0/10)
	_, tailscaleNet, _ := net.ParseCIDR("100.64.0.0/10")
	if tailscaleNet.Contains(parsedIP) {
		return "Tailscale"
	}

	// Memory Cache Check
	GeoCacheLock.RLock()
	if code, ok := GeoCache[ipStr]; ok {
		GeoCacheLock.RUnlock()
		return code
	}
	GeoCacheLock.RUnlock()

	// Native lookup
	InitGeoReader()
	if geoReader == nil {
		return "unknown"
	}

	record, err := geoReader.Country(parsedIP)
	if err != nil {
		return "unknown"
	}

	countryCode := record.Country.IsoCode
	if countryCode == "" {
		countryCode = "unknown"
	}

	// Cache result
	GeoCacheLock.Lock()
	if len(GeoCache) > 1000 {
		GeoCache = make(map[string]string)
	}
	GeoCache[ipStr] = countryCode
	GeoCacheLock.Unlock()

	return countryCode
}

func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Private ranges
	_, private24, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16, _ := net.ParseCIDR("192.168.0.0/16")

	return private24.Contains(ip) || private20.Contains(ip) || private16.Contains(ip)
}
