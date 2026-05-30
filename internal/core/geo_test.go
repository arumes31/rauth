package core

import (
	"fmt"
	"net"
	"os/exec"
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
		// IPv4
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"100.64.0.5", false}, // Tailscale is not "private" in the RFC1918 sense for this function
		{"8.8.8.8", false},
		{"1.1.1.1", false},

		// IPv6
		{"::1", true},
		{"fe80::1", true},
		{"fd00::1", true},
		{"2001:db8::1", false},

		{"invalid", false}, // Invalid parses to nil, returns false
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, IsPrivateIP(tt.ip), "IP: "+tt.ip)
	}
}

func TestGetCountryCode_Table(t *testing.T) {
	// Clear cache to avoid interference
	GeoCache = NewGeoLRUCache(1000)

	tests := []struct {
		ip       string
		expected string
	}{
		// IPv4
		{"127.0.0.1", "Internal"},
		{"10.0.0.1", "Internal"},
		{"100.64.0.1", "Tailscale"},
		{"8.8.8.8", "unknown"}, // Assuming no reader loaded

		// IPv6
		{"::1", "Internal"},
		{"fd00::1", "Internal"},
		{"fd7a:115c:a1e0::1", "Tailscale"},
		{"2001:db8::1", "unknown"},

		// Edge
		{"invalid", "unknown"},
		{"", "unknown"},
	}

	// Ensure reader is nil for these tests
	geoLock.Lock()
	oldReader := geoReader
	geoReader = nil
	geoLock.Unlock()
	defer func() {
		geoLock.Lock()
		geoReader = oldReader
		geoLock.Unlock()
	}()

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			assert.Equal(t, tt.expected, GetCountryCode(tt.ip))
		})
	}
}

func TestGetCountryCode_Mocked(t *testing.T) {
	// Clear cache
	GeoCache = NewGeoLRUCache(1000)

	mock := &mockGeoReader{
		countryFunc: func(ip net.IP) (*geoip2.Country, error) {
			if ip.String() == "8.8.8.8" {
				record := &geoip2.Country{}
				record.Country.IsoCode = "US"
				return record, nil
			}
			return &geoip2.Country{}, nil
		},
	}
	geoLock.Lock()
	oldReader := geoReader
	geoReader = mock
	geoLock.Unlock()
	defer func() {
		geoLock.Lock()
		geoReader = oldReader
		geoLock.Unlock()
	}()

	assert.Equal(t, "US", GetCountryCode("8.8.8.8"))
	assert.Equal(t, "unknown", GetCountryCode("8.8.4.4"))
}

func TestUpdateGeoDB_Mocked(t *testing.T) {
	origRunner := commandRunner
	defer func() { commandRunner = origRunner }()

	cfg := &Config{
		MaxMindAccountID:  "id",
		MaxMindLicenseKey: "key",
		MaxMindDBPath:     "/tmp/test.mmdb",
	}

	// 1. Success
	commandRunner = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("true")
	}
	err := UpdateGeoDB(cfg)
	assert.NoError(t, err)

	// 2. Failure
	commandRunner = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("false")
	}
	err = UpdateGeoDB(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "geoipupdate failed")
}

func TestGetCountryCode_Cache(t *testing.T) {
	GeoCache = NewGeoLRUCache(1000)
	GeoCache.Put("1.2.3.4", "TEST")
	assert.Equal(t, "TEST", GetCountryCode("1.2.3.4"))
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
	GeoCache = NewGeoLRUCache(1000)

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
	GeoCache = NewGeoLRUCache(1000)
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
	// Isolate from global state
	geoLock.Lock()
	oldReader := geoReader
	geoReader = nil
	geoLock.Unlock()

	defer func() {
		geoLock.Lock()
		geoReader = oldReader
		geoLock.Unlock()
	}()

	// Not loaded
	status := GetGeoReaderStatus()
	require.False(t, status)

	metadata := GetGeoMetadata()
	require.False(t, metadata["loaded"].(bool))
	require.Equal(t, uint64(0), metadata["build_date"])
	require.Equal(t, "", metadata["path"])

	// Note: Fully testing when loaded requires setting up a real maxminddb,
	// which is complex for a unit test. We cover the not-loaded path.
}
