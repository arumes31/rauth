package hostguard

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const testUUID = "11111111-1111-4111-8111-111111111111"

func fixtureWitness() map[string]any {
	return map[string]any{"schema": 1, "uuid": testUUID, "role": "app", "boot_id": testUUID, "targets": []any{map[string]any{"path": "/app/data", "device": "1", "fsid": "2", "inode": "3", "writable": true}}}
}
func TestWitnessScopeAndRequiredTargets(t *testing.T) {
	raw, err := json.Marshal(fixtureWitness())
	require.NoError(t, err)
	w, err := Decode(raw, testUUID, "app")
	require.NoError(t, err)
	require.Equal(t, uint64(2), w.Targets[0].Filesystem)
	_, err = Decode(raw, "22222222-2222-4222-8222-222222222222", "app")
	require.ErrorIs(t, err, ErrGuard)
	_, err = Decode(raw, testUUID, "etcd")
	require.ErrorIs(t, err, ErrGuard)
	for name, edit := range map[string]func(map[string]any){
		"schema":             func(w map[string]any) { w["schema"] = true },
		"unknown":            func(w map[string]any) { w["extra"] = 1 },
		"alias":              func(w map[string]any) { w["UUID"] = w["uuid"]; delete(w, "uuid") },
		"no-targets":         func(w map[string]any) { w["targets"] = []any{} },
		"boot":               func(w map[string]any) { w["boot_id"] = "" },
		"missing-required":   func(w map[string]any) { w["targets"].([]any)[0].(map[string]any)["path"] = "/other" },
		"escape":             func(w map[string]any) { w["targets"].([]any)[0].(map[string]any)["path"] = "/app/../data" },
		"leading-zero":       func(w map[string]any) { w["targets"].([]any)[0].(map[string]any)["device"] = "01" },
		"numeric":            func(w map[string]any) { w["targets"].([]any)[0].(map[string]any)["device"] = 1 },
		"fraction":           func(w map[string]any) { w["targets"].([]any)[0].(map[string]any)["fsid"] = "2.0" },
		"zero-inode":         func(w map[string]any) { w["targets"].([]any)[0].(map[string]any)["inode"] = "0" },
		"wrong-write-policy": func(w map[string]any) { w["targets"].([]any)[0].(map[string]any)["writable"] = false },
		"null-write-policy":  func(w map[string]any) { w["targets"].([]any)[0].(map[string]any)["writable"] = nil },
		"duplicate-target":   func(w map[string]any) { w["targets"] = append(w["targets"].([]any), w["targets"].([]any)[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			w := fixtureWitness()
			edit(w)
			raw, err := json.Marshal(w)
			require.NoError(t, err)
			_, err = Decode(raw, testUUID, "app")
			require.ErrorIs(t, err, ErrGuard)
		})
	}
}
func TestWitnessRejectsDuplicateAliasTrailingAndOversizedJSON(t *testing.T) {
	raw, err := json.Marshal(fixtureWitness())
	require.NoError(t, err)
	for _, bad := range []string{
		strings.Replace(string(raw), `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.Replace(string(raw), `"device":"1"`, `"device":"1","device":"1"`, 1),
		strings.Replace(string(raw), `"fsid":"2"`, `"FSID":"2"`, 1),
		string(raw) + `{}`, strings.Repeat(" ", MaxWitnessBytes+1),
	} {
		_, err := Decode([]byte(bad), testUUID, "app")
		require.ErrorIs(t, err, ErrGuard)
	}
}
func TestPKIRoleRequiresWritablePKIAndState(t *testing.T) {
	target := func(path string, writable bool) map[string]any {
		return map[string]any{"path": path, "device": "1", "fsid": "2", "inode": "3", "writable": writable}
	}
	witness := func(targets ...any) []byte {
		raw, err := json.Marshal(map[string]any{"schema": 1, "uuid": testUUID, "role": "pki", "boot_id": testUUID, "targets": targets})
		require.NoError(t, err)
		return raw
	}
	_, err := Decode(witness(target("/pki", true), target("/var/lib/rauth-pki", true), target("/authority", false)), testUUID, "pki")
	require.NoError(t, err)
	_, err = Decode(witness(target("/pki", false), target("/var/lib/rauth-pki", true)), testUUID, "pki")
	require.ErrorIs(t, err, ErrGuard)
	_, err = Decode(witness(target("/pki", true)), testUUID, "pki")
	require.ErrorIs(t, err, ErrGuard)
}
