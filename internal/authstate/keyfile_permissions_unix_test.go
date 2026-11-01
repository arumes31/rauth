//go:build !windows

package authstate

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"rauth/internal/testfile"
	"testing"
)

func TestKeyfilePOSIXPermissions(t *testing.T) {
	for _, test := range []struct {
		mode  os.FileMode
		valid bool
	}{{0600, true}, {0640, true}, {0644, false}, {0620, false}, {0601, false}} {
		t.Run(test.mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.json")
			testfile.WritePrivate(t, path, keyfilePermissionFixture(t))
			require.NoError(t, os.Chmod(path, test.mode))
			_, err := LoadKeyring(path)
			if test.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
