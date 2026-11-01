//go:build linux

package clusterconfig

import (
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func readPrivate(filename string, limit int64) ([]byte, error) {
	if limit < 1 || limit > 1<<20 {
		return nil, ErrPrivateFile
	}
	file, err := openPrivate(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, ErrPrivateFile
	}
	return body, nil
}
func openPrivate(filename string) (*os.File, error) {
	if !privatePath(filename) || !filepath.IsAbs(filename) {
		return nil, ErrPrivateFile
	}
	fd, err := openNoSymlinks(filename, unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil {
		return nil, ErrPrivateFile
	}
	file := os.NewFile(uintptr(fd), filename)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrPrivateFile
	}
	fail := func() (*os.File, error) { _ = file.Close(); return nil, ErrPrivateFile }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fail()
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid())) {
		return fail()
	}
	return file, nil
}

// Resolve every component through an opened directory, so a symlink in an
// ancestor cannot redirect a private file outside the configured host tree.
func openNoSymlinks(filename string, flags int) (int, error) {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(filename, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.Openat(fd, parts[len(parts)-1], flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}
func validateMount(c Config) error {
	info, err := os.Lstat(c.DataRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o027 != 0 {
		return ErrMount
	}
	root, err := os.OpenRoot(c.DataRoot)
	if err != nil {
		return ErrMount
	}
	defer func() { _ = root.Close() }()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) || opened.Mode().Perm()&0o027 != 0 {
		return ErrMount
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid())) {
		return ErrMount
	}
	actual := fmt.Sprintf("%d:%d", unix.Major(uint64(stat.Dev)), unix.Minor(uint64(stat.Dev)))
	if actual != c.MountDevice {
		return ErrMount
	}
	body, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ErrMount
	}
	return matchingMount(string(body), c.DataRoot, c.MountDevice, c.MountFilesystem)
}
func matchingMount(raw, root, device, filesystem string) error {
	found := false
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		separator := 0
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if separator == 0 || len(fields) < separator+4 {
			continue
		}
		mount := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\").Replace(fields[4])
		if mount != root {
			continue
		}
		if found || fields[2] != device || fields[separator+1] != filesystem {
			return ErrMount
		}
		found = true
		if !writableMountOptions(fields[5]) || !writableMountOptions(fields[separator+3]) {
			return ErrMount
		}
	}
	if !found {
		return ErrMount
	}
	return nil
}

func writableMountOptions(raw string) bool {
	writable := false
	for _, option := range strings.Split(raw, ",") {
		if option == "ro" {
			return false
		}
		if option == "rw" {
			writable = true
		}
	}
	return writable
}

func validateCacheRoot(c Config) error { return validateDataDirectory(c.CacheRoot, c.MountDevice) }
func validateSourceDirectory(c Config) error {
	if c.Role != Control || c.GeoIPFile == "" {
		return nil
	}
	return validateDataDirectory(filepath.Dir(c.GeoIPFile), c.MountDevice)
}
func validateDataDirectory(directory, device string) error {
	fd, err := openNoSymlinks(directory, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return ErrMount
	}
	file := os.NewFile(uintptr(fd), directory)
	if file == nil {
		_ = unix.Close(fd)
		return ErrMount
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o027 != 0 {
		return ErrMount
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid())) {
		return ErrMount
	}
	actual := fmt.Sprintf("%d:%d", unix.Major(uint64(stat.Dev)), unix.Minor(uint64(stat.Dev)))
	if actual != device {
		return ErrMount
	}
	return nil
}
func openGeoSource(c Config) (*os.File, error) {
	if validateSourceDirectory(c) != nil {
		return nil, ErrMount
	}
	fd, err := openNoSymlinks(c.GeoIPFile, unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil {
		return nil, ErrPrivateFile
	}
	file := os.NewFile(uintptr(fd), c.GeoIPFile)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrPrivateFile
	}
	fail := func() (*os.File, error) { _ = file.Close(); return nil, ErrPrivateFile }
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return fail()
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid())) {
		return fail()
	}
	if fmt.Sprintf("%d:%d", unix.Major(uint64(stat.Dev)), unix.Minor(uint64(stat.Dev))) != c.MountDevice {
		return fail()
	}
	return file, nil
}
