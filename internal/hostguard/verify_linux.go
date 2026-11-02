//go:build linux

package hostguard

import (
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func openPinned(name string) (int, error) {
	if !canonicalPath(name) {
		return -1, ErrGuard
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, ErrGuard
	}
	components := strings.Split(strings.TrimPrefix(name, "/"), "/")
	for i, part := range components {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(components)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, part, flags, 0)
		_ = unix.Close(fd)
		if e != nil {
			return -1, ErrGuard
		}
		fd = next
	}
	return fd, nil
}
func fsid(s *unix.Statfs_t) uint64 {
	// Linux exposes two signed words; reinterpret their bits, not their signs.
	return uint64(uint32(s.Fsid.Val[0])) | uint64(uint32(s.Fsid.Val[1]))<<32 // #nosec G115 -- intentional lossless raw-bit reinterpretation of fsid words.
}

// Describe returns raw Linux filesystem identity from an inherited, held fd.
// Both attestation and verification use this encoding; libc statvfs conversions
// cannot truncate or sign-extend filesystem IDs on a different host userspace.
func Describe(fd int) (map[string]string, error) {
	var info unix.Stat_t
	var fs unix.Statfs_t
	if fd < 0 || unix.Fstat(fd, &info) != nil || unix.Fstatfs(fd, &fs) != nil || (info.Mode&unix.S_IFMT != unix.S_IFREG && info.Mode&unix.S_IFMT != unix.S_IFDIR) {
		return nil, ErrGuard
	}
	return map[string]string{"device": strconv.FormatUint(uint64(info.Dev), 10), "fsid": strconv.FormatUint(fsid(&fs), 10), "inode": strconv.FormatUint(info.Ino, 10)}, nil
}

// Verify reads a root-owned, immutable tmpfs witness and verifies every physical
// bind identity. It never creates data paths or opens a watchdog device.
func Verify(filename, uuid, role string) error {
	fd, err := openPinned(filename)
	if err != nil {
		return ErrGuard
	}
	f := os.NewFile(uintptr(fd), filename)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0222 != 0 || st.Nlink != 1 || st.Size <= 0 || st.Size > MaxWitnessBytes || fs.Type != unix.TMPFS_MAGIC || fs.Flags&unix.ST_RDONLY == 0 {
		return ErrGuard
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxWitnessBytes+1))
	if err != nil {
		return ErrGuard
	}
	w, err := Decode(raw, uuid, role)
	if err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != w.BootID {
		return ErrGuard
	}
	for _, target := range w.Targets {
		targetFD, e := openPinned(target.Path)
		if e != nil {
			return ErrGuard
		}
		var info unix.Stat_t
		var statfs unix.Statfs_t
		failed := unix.Fstat(targetFD, &info) != nil || unix.Fstatfs(targetFD, &statfs) != nil
		_ = unix.Close(targetFD)
		kind := info.Mode & unix.S_IFMT
		if failed || (kind != unix.S_IFDIR && kind != unix.S_IFREG) || uint64(info.Dev) != target.Device || info.Ino != target.Inode || fsid(&statfs) != target.Filesystem || (statfs.Flags&unix.ST_RDONLY == 0) != target.Writable {
			return ErrGuard
		}
	}
	return nil
}

// Execute replaces PID 1 with the original image command after verification.
func Execute(filename, uuid, role string, args []string) error {
	if len(args) == 0 || !canonicalPath(args[0]) {
		return ErrGuard
	}
	if err := Verify(filename, uuid, role); err != nil {
		return err
	}
	return unix.Exec(args[0], args, os.Environ())
}
