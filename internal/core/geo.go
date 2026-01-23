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
	geoCache     = make(map[string]string)
	geoCacheLock sync.RWMutex
)

func GetCountryCode(ip string) string {
	if IsPrivateIP(ip) {
		return "Internal"
	}

	geoCacheLock.RLock()
	if code, ok := geoCache[ip]; ok {
		geoCacheLock.RUnlock()
		return code
	}
	geoCacheLock.RUnlock()

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
		geoCacheLock.Lock()
		// Basic cache eviction - if cache gets too big, clear it
		if len(geoCache) > 1000 {
			geoCache = make(map[string]string)
		}
		geoCache[ip] = geo.Country
		geoCacheLock.Unlock()
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
