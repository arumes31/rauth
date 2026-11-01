// Package testfile creates private synthetic key fixtures on every test OS.
package testfile

import (
	"os"
	"testing"
)

func WritePrivate(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restrict(path); err != nil {
		t.Fatal(err)
	}
}
