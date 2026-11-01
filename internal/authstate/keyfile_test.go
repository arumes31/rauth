package authstate

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"rauth/internal/testfile"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadKeyringRequiresBoundedPrivateFile(t *testing.T) {
	first := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("i", 32)))
	second := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32)))
	valid := map[string]any{"index_key": first, "active_key_id": "v1", "encryption_keys": map[string]string{"v1": second}}
	data, err := json.Marshal(valid)
	require.NoError(t, err)
	for _, test := range []struct {
		name, data string
		valid      bool
	}{
		{"valid", string(data), true},
		{"unknown field", strings.TrimSuffix(string(data), "}") + `,"extra":"no"}`, false},
		{"trailing object", string(data) + ` {}`, false},
		{"oversized", strings.Repeat("x", 16385), false},
		{"invalid base64", `{"index_key":"bad","active_key_id":"v1","encryption_keys":{"v1":"bad"}}`, false},
		{"same index and encryption", strings.ReplaceAll(string(data), second, first), false},
		{"active key missing", strings.ReplaceAll(string(data), `"active_key_id":"v1"`, `"active_key_id":"v2"`), false},
		{"null", `null`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "auth-state.json")
			testfile.WritePrivate(t, path, []byte(test.data))
			keys, err := LoadKeyring(path)
			if test.valid {
				require.NoError(t, err)
				require.NotNil(t, keys)
			} else {
				require.Error(t, err)
				require.Nil(t, keys)
				require.NotContains(t, err.Error(), first)
				require.NotContains(t, err.Error(), second)
			}
		})
	}
	_, err = LoadKeyring("relative.json")
	require.Error(t, err)
	_, err = LoadKeyring(t.TempDir())
	require.Error(t, err)
	_, err = LoadKeyring(filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)
}

func keyfilePermissionFixture(t testing.TB) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"index_key": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("i", 32))), "active_key_id": "v1", "encryption_keys": map[string]string{"v1": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32)))}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
