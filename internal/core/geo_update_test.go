package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStartGeoUpdater_Logic(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "geotest")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	dbPath := filepath.Join(tempDir, "GeoLite2-Country.mmdb")
	cfg := &Config{
		MaxMindDBPath: dbPath,
	}

	updateCalled := 0
	origUpdateFunc := geoUpdateFunc
	geoUpdateFunc = func(c *Config) error {
		updateCalled++
		// Simulate successful download by creating an empty file
		return os.WriteFile(c.MaxMindDBPath, []byte("fake db"), 0644)
	}
	defer func() { geoUpdateFunc = origUpdateFunc }()

	// Case 1: Database doesn't exist - should call update
	StartGeoUpdater(cfg)
	assert.Equal(t, 1, updateCalled, "Should call update when DB is missing")

	// Case 2: Database exists - should NOT call update again on startup
	updateCalled = 0
	StartGeoUpdater(cfg)
	assert.Equal(t, 0, updateCalled, "Should NOT call update when DB exists")
}

func TestUpdateGeoDB_ConfigGeneration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "geoconf")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	dbPath := filepath.Join(tempDir, "GeoLite2-Country.mmdb")
	cfg := &Config{
		MaxMindDBPath:    dbPath,
		MaxMindAccountID: "test-id",
		MaxMindLicenseKey: "test-key",
		MaxMindEditionIDs: "test-edition",
	}

	// Since we can't easily run 'geoipupdate' in many environments,
	// we just test the part before the command execution if we refactor more,
	// or we can just verify the file generation if we split the function.
	
	// For now, let's just ensure it errors if binary is missing but config is written.
	err = UpdateGeoDB(cfg)
	assert.Error(t, err) // Likely fails because geoipupdate is not in path

	confPath := filepath.Join(tempDir, "GeoIP.conf")
	_, err = os.Stat(confPath)
	assert.NoError(t, err, "GeoIP.conf should have been created")

	content, _ := os.ReadFile(confPath)
	assert.Contains(t, string(content), "AccountID test-id")
	assert.Contains(t, string(content), "LicenseKey test-key")
}
