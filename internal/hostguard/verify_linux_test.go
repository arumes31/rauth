//go:build linux

package hostguard

import (
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"testing"
)

func TestRawFilesystemIDPreservesAllBits(t *testing.T) {
	for _, pair := range [][2]int32{{-1, 0}, {-2147483648, 1}, {1, -1}, {-1, -1}} {
		var s unix.Statfs_t
		s.Fsid.Val = pair
		want := uint64(uint32(pair[0])) | uint64(uint32(pair[1]))<<32
		if got := fsid(&s); got != want {
			t.Fatalf("raw id lost bits: %x != %x", got, want)
		}
	}
}

func TestDescribeUsesHeldDescriptorAndRejectsNonFiles(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "held-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	identity, err := Describe(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(int(f.Fd()), &st) != nil || unix.Fstatfs(int(f.Fd()), &fs) != nil {
		t.Fatal("stat failed")
	}
	for key, want := range map[string]uint64{"device": uint64(st.Dev), "fsid": fsid(&fs), "inode": st.Ino} {
		if identity[key] != strconv.FormatUint(want, 10) {
			t.Fatalf("%s mismatch", key)
		}
	}
	if _, err := Describe(-1); err == nil {
		t.Fatal("negative descriptor accepted")
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = read.Close() }()
	defer func() { _ = write.Close() }()
	if _, err := Describe(int(read.Fd())); err == nil {
		t.Fatal("pipe accepted")
	}
}
