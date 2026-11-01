//go:build !linux

package clusterpolicy

import "os"

func lockStoreFile(_ *os.File) error { return ErrStoreUnsupported }
