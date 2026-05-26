package core

import (
	"fmt"
	"net"
	"testing"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
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
	GeoCache.Put("8.8.4.4", "cached-country")
	assert.Equal(t, "cached-country", GetCountryCode("8.8.4.4"))
}

type mockGeoReader struct {
	countryFunc  func(net.IP) (*geoip2.Country, error)
	metadataFunc func() maxminddb.Metadata
	closeFunc    func() error
}

func (m *mockGeoReader) Country(ip net.IP) (*geoip2.Country, error) {
	if m.countryFunc != nil {
		return m.countryFunc(ip)
	}
	return &geoip2.Country{}, nil
}

func (m *mockGeoReader) Metadata() maxminddb.Metadata {
	if m.metadataFunc != nil {
		return m.metadataFunc()
	}
	return maxminddb.Metadata{}
}

func (m *mockGeoReader) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func TestGetCountryCode_EdgeCases(t *testing.T) {
	// 1. Unloaded reader
	geoLock.Lock()
	oldReader := geoReader
	geoReader = nil
	geoLock.Unlock()

	defer func() {
		geoLock.Lock()
		geoReader = oldReader
		geoLock.Unlock()
	}()

	assert.Equal(t, "unknown", GetCountryCode("8.8.8.8"))

	// 2. Reader lookup error
	mock := &mockGeoReader{
		countryFunc: func(ip net.IP) (*geoip2.Country, error) {
			return nil, fmt.Errorf("lookup error")
		},
	}
	geoLock.Lock()
	geoReader = mock
	geoLock.Unlock()

	assert.Equal(t, "unknown", GetCountryCode("8.8.8.9"))

	// 3. Reader returns empty country code
	mock = &mockGeoReader{
		countryFunc: func(ip net.IP) (*geoip2.Country, error) {
			return &geoip2.Country{}, nil
		},
	}
	geoLock.Lock()
	geoReader = mock
	geoLock.Unlock()

	assert.Equal(t, "unknown", GetCountryCode("8.8.8.10"))

	// 4. Successful lookup
	mock = &mockGeoReader{
		countryFunc: func(ip net.IP) (*geoip2.Country, error) {
			record := &geoip2.Country{}
			record.Country.IsoCode = "US"
			return record, nil
		},
	}
	geoLock.Lock()
	geoReader = mock
	geoLock.Unlock()

	assert.Equal(t, "US", GetCountryCode("8.8.8.11"))
}

func TestGetCountryCode_InvalidIP(t *testing.T) {
	// IsPrivateIP returns true for "invalid", so GetCountryCode should return "Internal"
	assert.Equal(t, "Internal", GetCountryCode("invalid"))

	// Test an IP that net.ParseIP fails on but IsPrivateIP handles
	assert.Equal(t, "Internal", GetCountryCode("999.999.999.999"))
}
