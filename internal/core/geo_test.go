package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"100.64.0.5", false}, // Tailscale is not "private" in the RFC1918 sense for this function
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"invalid", true}, // Invalid parses to nil, returns true
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, IsPrivateIP(tt.ip), "IP: "+tt.ip)
	}
}

func TestGetCountryCode(t *testing.T) {
	// Mock Tailscale
	assert.Equal(t, "Tailscale", GetCountryCode("100.64.0.1"))
	assert.Equal(t, "Tailscale", GetCountryCode("100.127.255.254"))

	// Mock Internal
	assert.Equal(t, "Internal", GetCountryCode("192.168.1.50"))

	// Mock Cache behavior
	GeoCacheLock.Lock()
	GeoCache["8.8.4.4"] = "cached-country"
	GeoCacheLock.Unlock()
	assert.Equal(t, "cached-country", GetCountryCode("8.8.4.4"))
}
