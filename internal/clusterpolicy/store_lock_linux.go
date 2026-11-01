//go:build linux

package clusterpolicy

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func lockStoreFile(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return ErrStoreLocked
	}
	return err
}
