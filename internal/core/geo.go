package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type GeoResponse struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
}

func GetCountryCode(ip string) string {
	if IsPrivateIP(ip) {
		return "Internal"
	}

	cfg := LoadConfig()
	url := fmt.Sprintf("http://%s:%s/?ip=%s", cfg.GeoApiHost, cfg.GeoApiPort, ip)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		LogAudit("GEO_API_ERROR", "system", ip, map[string]interface{}{"error": err.Error()})
		return "unknown"
	}
	defer resp.Body.Close()

	var geo GeoResponse
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return "unknown"
	}

	return geo.Country
}

func IsPrivateIP(ip string) bool {
	// Simple check for common private ranges
	return strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "172.16.") || strings.HasPrefix(ip, "127.0.0.1")
}
