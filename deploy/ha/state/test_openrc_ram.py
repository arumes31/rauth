import stat
from types import SimpleNamespace as N
import unittest
from unittest import mock

import openrc_ram as ram


def info(mode=stat.S_IFDIR | 0o700, uid=0):
    return N(st_mode=mode, st_uid=uid, st_dev=1, st_ino=2, st_nlink=1)


def row():
    return {"target": ram.RAM, "fstype": "tmpfs", "options": "rw,nosuid,nodev,size=32768k,mode=700"}


def vfs():
    return N(f_frsize=4096, f_blocks=8192, f_flag=0)


class RAMPolicyTests(unittest.TestCase):
    def setUp(self):
        self.flags = mock.patch.multiple(ram.os, ST_RDONLY=1, ST_NOEXEC=8, create=True)
        self.flags.start(); self.addCleanup(self.flags.stop)

    def test_exact_safe_private_bounded_exec_tmpfs(self):
        ram.verify(row(), info(), vfs())
        smaller = vfs(); smaller.f_blocks = 4096
        ram.verify(row(), info(), smaller)

    def test_wrong_mount_flag_owner_type_and_capacity_refused(self):
        edits = [None, {**row(), "target": "/else"}, {**row(), "fstype": "ext4"}]
        edits += [{**row(), "options": value} for value in
                  ["ro,nosuid,nodev", "rw,nodev", "rw,nosuid", "rw,nosuid,nodev,noexec"]]
        for value in edits:
            with self.subTest(row=value), self.assertRaises(ram.Fault):
                ram.verify(value, info(), vfs())
        for value in [info(uid=10001), info(mode=stat.S_IFDIR | 0o755),
                      info(mode=stat.S_IFLNK | 0o700), info(mode=stat.S_IFREG | 0o700)]:
            with self.subTest(info=value), self.assertRaises(ram.Fault):
                ram.verify(row(), value, vfs())
        for value in [N(f_frsize=4096, f_blocks=8193, f_flag=0),
                      N(f_frsize=4096, f_blocks=0, f_flag=0),
                      N(f_frsize=4096, f_blocks=8192, f_flag=1),
                      N(f_frsize=4096, f_blocks=8192, f_flag=8)]:
            with self.subTest(vfs=value), self.assertRaises(ram.Fault):
                ram.verify(row(), info(), value)

    def test_observation_absence_distinguished_from_failed_probe(self):
        import subprocess
        with mock.patch.object(ram.subprocess, "check_output",
                               side_effect=subprocess.CalledProcessError(1, "findmnt")):
            self.assertIsNone(ram.observation(ram.RAM))
        with mock.patch.object(ram.subprocess, "check_output",
                               side_effect=subprocess.CalledProcessError(2, "findmnt")):
            with self.assertRaises(ram.Fault): ram.observation(ram.RAM)
        with mock.patch.object(ram.subprocess, "check_output", return_value=b"x" * 16385):
            with self.assertRaises(ram.Fault): ram.observation(ram.RAM)

    def test_malformed_findmnt_shape_is_static_refusal(self):
        for raw in [b'[]', b'{"filesystems":{}}', b'{"filesystems":[null]}']:
            with self.subTest(raw=raw), mock.patch.object(ram.subprocess, "check_output", return_value=raw):
                with self.assertRaises(ram.Fault): ram.observation(ram.RAM)

    def test_live_path_substitution_refused(self):
        other = info(); other.st_ino = 8
        with mock.patch.object(ram, "observation", return_value=row()), \
             mock.patch.object(ram.os, "fstat", return_value=info()), \
             mock.patch.object(ram.os, "fstatvfs", return_value=vfs(), create=True), \
             mock.patch.object(ram.os, "stat", return_value=other):
            with self.assertRaises(ram.Fault): ram.checked(9)


class RAMLifecycleTests(unittest.TestCase):
    def setUp(self):
        patches = [mock.patch.object(ram.sys, "platform", "linux"),
                   mock.patch.object(ram.os, "geteuid", return_value=0, create=True),
                   mock.patch.object(ram, "fcntl", mock.Mock()),
                   mock.patch.object(ram, "opened", return_value=9),
                   mock.patch.object(ram, "checked"),
                   mock.patch.object(ram.os, "close"),
                   mock.patch.object(ram.os, "listdir", return_value=[]),
                   mock.patch.object(ram, "no_active_supervisor"),
                   mock.patch.object(ram.subprocess, "run")]
        names = ["platform", "uid", "fcntl", "opened", "checked", "close", "listdir", "locks", "run"]
        for name, patcher in zip(names, patches):
            setattr(self, name, patcher.start()); self.addCleanup(patcher.stop)

    def test_first_start_mounts_exact_bounded_flags_then_verifies(self):
        with mock.patch.object(ram, "observation", side_effect=[{"fstype": "tmpfs"}, None]):
            ram.manage("start")
        self.run.assert_called_once()
        args = self.run.call_args.args[0]
        self.assertEqual(args, ["/bin/mount", "-t", "tmpfs", "-o", ram.OPTIONS, "tmpfs", ram.RAM])
        self.opened.assert_has_calls([mock.call(create=True), mock.call()])
        self.checked.assert_called_once_with(9)

    def test_existing_mount_is_checked_without_remount(self):
        with mock.patch.object(ram, "observation", side_effect=[{"fstype": "tmpfs"}, row()]):
            ram.manage("start")
        self.checked.assert_called_once_with(9)
        self.run.assert_not_called()

    def test_nonempty_unmounted_directory_never_hidden_by_mount(self):
        self.listdir.return_value = ["old-witness"]
        with mock.patch.object(ram, "observation", side_effect=[{"fstype": "tmpfs"}, None]):
            with self.assertRaises(ram.Fault): ram.manage("start")
        self.run.assert_not_called()
        self.close.assert_called_once_with(9)

    def test_unsafe_existing_mount_does_not_get_replaced(self):
        self.checked.side_effect = ram.Fault("foreign")
        with mock.patch.object(ram, "observation", side_effect=[{"fstype": "tmpfs"}, row()]):
            with self.assertRaises(ram.Fault): ram.manage("start")
        self.run.assert_not_called()
        self.close.assert_called_once_with(9)

    def test_stop_waits_for_locks_then_plain_unmount_only(self):
        with mock.patch.object(ram, "observation", side_effect=[{"fstype": "tmpfs"}, row()]):
            ram.manage("stop")
        self.locks.assert_called_once_with(9)
        self.run.assert_called_once()
        self.assertEqual(self.run.call_args.args[0], ["/bin/umount", ram.RAM])
        self.opened.assert_called_once_with(create=False)

    def test_active_supervisor_prevents_unmount(self):
        self.locks.side_effect = ram.Fault("active_supervisor")
        with mock.patch.object(ram, "observation", side_effect=[{"fstype": "tmpfs"}, row()]):
            with self.assertRaises(ram.Fault): ram.manage("stop")
        self.run.assert_not_called()

    def test_wrong_run_filesystem_stops_before_any_creation(self):
        with mock.patch.object(ram, "observation", return_value={"fstype": "ext4"}):
            with self.assertRaises(ram.Fault): ram.manage("start")
        self.opened.assert_not_called(); self.run.assert_not_called()

    def test_stop_of_absent_directory_is_idempotent_and_creates_nothing(self):
        self.opened.side_effect = FileNotFoundError()
        with mock.patch.object(ram, "observation", return_value={"fstype": "tmpfs"}):
            ram.manage("stop")
        self.opened.assert_called_once_with(create=False)
        self.run.assert_not_called()
        self.close.assert_not_called()

    def test_non_native_platform_never_mounts(self):
        with mock.patch.object(ram.sys, "platform", "win32"):
            with self.assertRaises(ram.Fault): ram.manage("start")
        self.opened.assert_not_called(); self.run.assert_not_called()

class LockAndDirectoryTests(unittest.TestCase):
    def test_symlink_directory_open_uses_no_follow_and_closes_parent(self):
        flags = {"O_DIRECTORY": 65536, "O_NOFOLLOW": 131072}
        with mock.patch.multiple(ram.os, **flags, create=True), \
             mock.patch.object(ram.os, "open", side_effect=[7, OSError("symlink")]) as opened, \
             mock.patch.object(ram.os, "fstat", return_value=info(mode=stat.S_IFDIR | 0o755)), \
             mock.patch.object(ram.os, "close") as closed:
            with self.assertRaises(OSError): ram.opened()
        self.assertTrue(opened.call_args_list[0].args[1] & flags["O_NOFOLLOW"])
        self.assertTrue(opened.call_args_list[1].args[1] & flags["O_NOFOLLOW"])
        closed.assert_called_once_with(7)

    def test_unsafe_child_owner_is_not_chmodded_and_descriptors_close(self):
        with mock.patch.multiple(ram.os, O_DIRECTORY=65536, O_NOFOLLOW=131072, create=True), \
             mock.patch.object(ram.os, "open", side_effect=[7, 8]), \
             mock.patch.object(ram.os, "fstat", side_effect=[info(mode=stat.S_IFDIR | 0o755), info(uid=10001)]), \
             mock.patch.object(ram.os, "close") as closed:
            with self.assertRaises(ram.Fault): ram.opened()
        self.assertEqual(closed.call_args_list, [mock.call(8), mock.call(7)])

    def test_live_lock_blocks_ram_release_and_closes_all_descriptors(self):
        locks = mock.Mock(); locks.LOCK_EX = 2; locks.LOCK_NB = 4; locks.flock.side_effect = BlockingIOError()
        with mock.patch.object(ram, "fcntl", locks), \
             mock.patch.multiple(ram.os, O_DIRECTORY=65536, O_NOFOLLOW=131072, O_NONBLOCK=2048, create=True), \
             mock.patch.object(ram.os, "listdir", return_value=["worker-d"]), \
             mock.patch.object(ram.os, "stat", return_value=info()), \
             mock.patch.object(ram.os, "open", side_effect=[8, 9]), \
             mock.patch.object(ram.os, "fstat", side_effect=[info(), info(mode=stat.S_IFREG | 0o600)]), \
             mock.patch.object(ram.os, "close") as closed:
            with self.assertRaisesRegex(ram.Fault, "active_supervisor"): ram.no_active_supervisor(7)
        self.assertEqual(closed.call_args_list, [mock.call(9), mock.call(8)])
