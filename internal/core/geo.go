package core

import (
	"container/list"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

type lruEntry struct {
	key   string
	value string
}

type GeoLRUCache struct {
	capacity int
	cache    map[string]*list.Element
	list     *list.List
	lock     sync.Mutex
}

func NewGeoLRUCache(capacity int) *GeoLRUCache {
	return &GeoLRUCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		list:     list.New(),
	}
}

func (c *GeoLRUCache) Get(key string) (string, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if elem, ok := c.cache[key]; ok {
		c.list.MoveToFront(elem)
		return elem.Value.(*lruEntry).value, true
	}
	return "", false
}

func (c *GeoLRUCache) Put(key, value string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if elem, ok := c.cache[key]; ok {
		c.list.MoveToFront(elem)
		elem.Value.(*lruEntry).value = value
		return
	}
	if c.list.Len() >= c.capacity {
		oldest := c.list.Back()
		if oldest != nil {
			c.list.Remove(oldest)
			delete(c.cache, oldest.Value.(*lruEntry).key)
		}
	}
	entry := &lruEntry{key, value}
	elem := c.list.PushFront(entry)
	c.cache[key] = elem
}

var (
	GeoCache     = NewGeoLRUCache(1000)
	geoReader    *geoip2.Reader
	geoLock      sync.RWMutex
	once         sync.Once

	// For testing
	geoUpdateFunc = UpdateGeoDB
)

// InitGeoReader initializes the MaxMind database reader
func InitGeoReader() {
	once.Do(func() {
		cfg := LoadConfig()
		reloadReader(cfg.MaxMindDBPath)
	})
}

func reloadReader(path string) {
	geoLock.Lock()
	defer geoLock.Unlock()

	if geoReader != nil {
		if err := geoReader.Close(); err != nil {
			slog.Warn("Failed to close MaxMind database", "error", err)
		}
	}

	reader, err := geoip2.Open(path)
	if err != nil {
		slog.Warn("Failed to open MaxMind database", "path", path, "error", err)
		return
	}
	geoReader = reader
	
	// Update metadata metric
	metadata := reader.Metadata()
	GeoIPDBBuildTimestamp.Set(float64(metadata.BuildEpoch))
	
	slog.Info("MaxMind database loaded", "path", path, "build_epoch", metadata.BuildEpoch)
}

func StartGeoUpdater(cfg *Config) {
	dbDir := filepath.Dir(cfg.MaxMindDBPath)

	// Ensure directory exists
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		slog.Error("Failed to create GeoIP directory", "path", dbDir, "error", err)
		return
	}

	// 1. Download on startup only if no database exists
	if _, err := os.Stat(cfg.MaxMindDBPath); os.IsNotExist(err) {
		slog.Info("GeoIP database missing, performing initial download")
		if err := geoUpdateFunc(cfg); err != nil {
			slog.Error("Initial GeoIP download failed", "error", err)
		} else {
			reloadReader(cfg.MaxMindDBPath)
		}
	} else {
		slog.Info("GeoIP database exists, skipping initial download")
		InitGeoReader()
	}

	// 2. Update only every 72h
	go func() {
		ticker := time.NewTicker(72 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			slog.Info("Running scheduled GeoIP update")
			if err := geoUpdateFunc(cfg); err != nil {
				slog.Error("Scheduled GeoIP update failed", "error", err)
				// If download fails, don't replace - geoipupdate handles this by downloading to .new
				continue
			}
			reloadReader(cfg.MaxMindDBPath)
		}
	}()
}

func UpdateGeoDB(cfg *Config) error {
	if cfg.MaxMindAccountID == "" || cfg.MaxMindLicenseKey == "" {
		return fmt.Errorf("MAXMIND_ACCOUNT_ID or MAXMIND_LICENSE_KEY not set")
	}

	dbDir := filepath.Dir(cfg.MaxMindDBPath)
	confPath := filepath.Join(dbDir, "GeoIP.conf")

	content := fmt.Sprintf("AccountID %s\nLicenseKey %s\nEditionIDs %s\nDatabaseDirectory %s\n",
		cfg.MaxMindAccountID, cfg.MaxMindLicenseKey, cfg.MaxMindEditionIDs, dbDir)

	if err := os.WriteFile(confPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write GeoIP.conf: %w", err)
	}

	cmd := exec.Command("geoipupdate", "-v", "-f", confPath, "-d", dbDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("geoipupdate failed: %w, output: %s", err, string(output))
	}

	slog.Info("GeoIP database updated successfully")
	return nil
}

func GetCountryCode(ipStr string) string {
	if IsPrivateIP(ipStr) {
		GeoIPLookupsTotal.WithLabelValues("internal").Inc()
		return "Internal"
	}

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		GeoIPLookupsTotal.WithLabelValues("invalid").Inc()
		return "unknown"
	}

	// Check for Tailscale (CGNAT range 100.64.0.0/10)
	_, tailscaleNet, _ := net.ParseCIDR("100.64.0.0/10")
	if tailscaleNet.Contains(parsedIP) {
		GeoIPLookupsTotal.WithLabelValues("tailscale").Inc()
		return "Tailscale"
	}

	// Memory Cache Check
	if code, ok := GeoCache.Get(ipStr); ok {
		GeoIPLookupsTotal.WithLabelValues("hit").Inc()
		return code
	}

	// Native lookup
	geoLock.RLock()
	reader := geoReader
	geoLock.RUnlock()

	if reader == nil {
		GeoIPLookupsTotal.WithLabelValues("unloaded").Inc()
		return "unknown"
	}

	record, err := reader.Country(parsedIP)
	if err != nil {
		GeoIPLookupsTotal.WithLabelValues("error").Inc()
		return "unknown"
	}

	countryCode := record.Country.IsoCode
	if countryCode == "" {
		countryCode = "unknown"
		GeoIPLookupsTotal.WithLabelValues("miss").Inc()
	} else {
		GeoIPLookupsTotal.WithLabelValues("lookup").Inc()
	}

	// Cache result
	GeoCache.Put(ipStr, countryCode)

	return countryCode
}

func GetGeoMetadata() map[string]interface{} {
	geoLock.RLock()
	defer geoLock.RUnlock()

	loaded := geoReader != nil
	var buildDate int64
	var path string
	if loaded {
		m := geoReader.Metadata()
		buildDate = int64(m.BuildEpoch)
		cfg := LoadConfig()
		path = cfg.MaxMindDBPath
	}

	return map[string]interface{}{
		"loaded":     loaded,
		"build_date": buildDate,
		"path":       path,
	}
}

func GetGeoReaderStatus() bool {
	geoLock.RLock()
	defer geoLock.RUnlock()
	return geoReader != nil
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
