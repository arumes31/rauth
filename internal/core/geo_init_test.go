package core

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitGeoReader(t *testing.T) {
	// Create a temporary directory for the dummy maxmind db
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.mmdb")

	writer, err := mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType: "GeoIP2-Country",
			RecordSize:   24,
		},
	)
	require.NoError(t, err)

	fh, err := os.Create(dbPath)
	require.NoError(t, err)

	_, err = writer.WriteTo(fh)
	require.NoError(t, err)
	fh.Close()

	// Save existing environment and set a custom one
	t.Setenv("MAXMIND_DB_PATH", dbPath)

	// Reset global state
	geoLock.Lock()
	oldReader := geoReader
	geoReader = nil
	geoLock.Unlock()

	defer func() {
		geoLock.Lock()
		geoReader = oldReader
		geoLock.Unlock()
	}()

	// Reset the sync.Once
	once = sync.Once{}

	// Call InitGeoReader
	InitGeoReader()

	// It should load the db successfully
	geoLock.RLock()
	reader := geoReader
	geoLock.RUnlock()

	assert.NotNil(t, reader)

	// To verify the sync.Once works, we can try calling it again
	// and observe nothing panics or fails
	InitGeoReader()
}
