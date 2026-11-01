//go:build !windows

package testfile

import "os"

func restrict(path string) error { return os.Chmod(path, 0600) }
