//go:build windows

package authstate

import (
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"path/filepath"
	"rauth/internal/testfile"
	"testing"
)

func TestKeyfileWindowsACL(t *testing.T) {
	for _, grant := range []string{"", "(A;;GR;;;WD)", "(A;;GW;;;AU)"} {
		t.Run("extra-grant-"+grant, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.json")
			testfile.WritePrivate(t, path, keyfilePermissionFixture(t))
			user, err := windows.GetCurrentProcessToken().GetTokenUser()
			require.NoError(t, err)
			sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")" + grant)
			require.NoError(t, err)
			acl, _, err := sd.DACL()
			require.NoError(t, err)
			require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil))
			_, err = LoadKeyring(path)
			if grant == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "null-dacl.json")
	testfile.WritePrivate(t, path, keyfilePermissionFixture(t))
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil))
	_, err := LoadKeyring(path)
	require.Error(t, err, "a NULL DACL grants everyone access")
}
