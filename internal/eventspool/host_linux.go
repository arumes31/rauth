//go:build linux

package eventspool

import (
	"golang.org/x/sys/unix"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func openDirectory(root string) (*os.File, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return nil, ErrUnsafe
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	for _, part := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return nil, ErrUnsafe
		}
		fd = next
	}
	file := os.NewFile(uintptr(fd), root)
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, ErrUnsafe
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && int64(st.Uid) != int64(os.Geteuid())) {
		_ = file.Close()
		return nil, ErrUnsafe
	}
	return file, nil
}
func openFile(dir *os.File, root, path string, flags int, _ os.FileMode) (*os.File, error) {
	if path != filepath.Join(root, "spool.db") {
		return nil, ErrUnsafe
	}
	rawFD := dir.Fd()
	if rawFD > math.MaxInt {
		return nil, ErrUnsafe
	}
	fd, err := unix.Openat(int(rawFD), "spool.db", flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, ErrUnsafe
	}
	f := os.NewFile(uintptr(fd), path)
	info, e := f.Stat()
	parent, pe := dir.Stat()
	safe := e == nil && pe == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0
	if safe {
		st, ok := info.Sys().(*syscall.Stat_t)
		ps, pok := parent.Sys().(*syscall.Stat_t)
		safe = ok && pok && st.Nlink == 1 && st.Dev == ps.Dev && (st.Uid == 0 || int64(st.Uid) == int64(os.Geteuid()))
	}
	if !safe {
		_ = f.Close()
		return nil, ErrUnsafe
	}
	return f, nil
}
