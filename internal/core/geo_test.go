package core

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

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
		{"invalid", false}, // Invalid parses to nil, returns false
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
	assert.Equal(t, "unknown", GetCountryCode("invalid"))
	assert.Equal(t, "unknown", GetCountryCode("999.999.999.999"))
}

func TestGetGeoMetadata(t *testing.T) {
	// 1. Unloaded
	geoLock.Lock()
	oldReader := geoReader
	geoReader = nil
	geoLock.Unlock()

	defer func() {
		geoLock.Lock()
		geoReader = oldReader
		geoLock.Unlock()
	}()

	meta := GetGeoMetadata()
	assert.False(t, meta["loaded"].(bool))

	// 2. Loaded (Mock)
	mock := &mockGeoReader{
		metadataFunc: func() maxminddb.Metadata {
			return maxminddb.Metadata{BuildEpoch: 123456789}
		},
	}
	geoLock.Lock()
	geoReader = mock
	geoLock.Unlock()

	meta = GetGeoMetadata()
	assert.True(t, meta["loaded"].(bool))
	assert.Equal(t, uint64(123456789), meta["build_date"].(uint64))
}

func TestGetGeoReaderStatus(t *testing.T) {
	geoLock.Lock()
	oldReader := geoReader
	geoReader = nil
	geoLock.Unlock()

	defer func() {
		geoLock.Lock()
		geoReader = oldReader
		geoLock.Unlock()
	}()

	assert.False(t, GetGeoReaderStatus())

	geoLock.Lock()
	geoReader = &mockGeoReader{}
	geoLock.Unlock()

	assert.True(t, GetGeoReaderStatus())
}

func TestGeoLRUCache_Eviction(t *testing.T) {
	cache := NewGeoLRUCache(2)
	cache.Put("a", "1")
	cache.Put("b", "2")
	cache.Put("c", "3") // Should evict "a"

	_, ok := cache.Get("a")
	assert.False(t, ok)
	val, ok := cache.Get("b")
	assert.True(t, ok)
	assert.Equal(t, "2", val)
	val, ok = cache.Get("c")
	assert.True(t, ok)
	assert.Equal(t, "3", val)

	// Test update existing
	cache.Put("b", "22")
	val, ok = cache.Get("b")
	assert.True(t, ok)
	assert.Equal(t, "22", val)
}

func TestReloadReader_Errors(t *testing.T) {
	geoLock.Lock()
	oldReader := geoReader
	geoReader = nil
	geoLock.Unlock()

	defer func() {
		geoLock.Lock()
		geoReader = oldReader
		geoLock.Unlock()
	}()

	// 1. Invalid path
	reloadReader("/nonexistent/path")
	assert.Nil(t, geoReader)

	// 2. Close error
	closeCalled := false
	mock := &mockGeoReader{
		closeFunc: func() error {
			closeCalled = true
			return fmt.Errorf("close error")
		},
	}
	geoLock.Lock()
	geoReader = mock
	geoLock.Unlock()

	reloadReader("/nonexistent/path/2")
	assert.True(t, closeCalled)
}

func TestGetGeoMetadataAndStatus(t *testing.T) {
	// Not loaded initially
	status := GetGeoReaderStatus()
	require.False(t, status)

	metadata := GetGeoMetadata()
	require.False(t, metadata["loaded"].(bool))
	require.Equal(t, uint64(0), metadata["build_date"])
	require.Equal(t, "", metadata["path"])

	// Note: Fully testing when loaded requires setting up a real maxminddb,
	// which is complex for a unit test. We cover the not-loaded path.
}
