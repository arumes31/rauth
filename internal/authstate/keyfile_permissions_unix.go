//go:build !windows

package authstate

import (
	"errors"
	"os"
)

func validateKeyFilePermissions(_ *os.File, info os.FileInfo) error {
	if info.Mode().Perm()&0o027 != 0 {
		return errors.New("authentication key file must not be group-writable or accessible to other users")
	}
	return nil
}
