package core

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type GeoResponse struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
}

var (
	GeoCache     = make(map[string]string)
	GeoCacheLock sync.RWMutex
)

func GetCountryCode(ip string) string {
	if IsPrivateIP(ip) {
		return "Internal"
	}
	
	// Validate IP to prevent SSRF/Injection
	if net.ParseIP(ip) == nil {
		return "unknown"
	}
	
	// Check for Tailscale (CGNAT range 100.64.0.0/10)
	// Using basic string prefix check for speed or net package if desired.
	// 100.64.0.0/10 covers 100.64.0.0 to 100.127.255.255
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		_, tailscaleNet, _ := net.ParseCIDR("100.64.0.0/10")
		if tailscaleNet.Contains(parsedIP) {
			return "Tailscale"
		}
	}

	GeoCacheLock.RLock()
	if code, ok := GeoCache[ip]; ok {
		GeoCacheLock.RUnlock()
		return code
	}
	GeoCacheLock.RUnlock()

	// Since LoadConfig is cheap but we want to avoid it in tight loops, 
	// ideally we'd pass it in. For now, let's keep it but minimize impact.
	cfg := LoadConfig()
	url := fmt.Sprintf("http://%s:%s/?ip=%s", cfg.GeoApiHost, cfg.GeoApiPort, ip)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "unknown"
	}
	defer resp.Body.Close()

	var geo GeoResponse
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return "unknown"
	}

	if geo.Country != "" {
		GeoCacheLock.Lock()
		// Basic cache eviction - if cache gets too big, clear it
		if len(GeoCache) > 1000 {
			GeoCache = make(map[string]string)
		}
		GeoCache[ip] = geo.Country
		GeoCacheLock.Unlock()
	}

	return geo.Country
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
