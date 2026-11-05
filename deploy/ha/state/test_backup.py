import datetime
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import backup

NOW = datetime.datetime(2026, 11, 5, 12, 0, tzinfo=datetime.timezone.utc)


def wal_tar(path, members=None):
    members = members if members is not None else [("000000010000000000000005", b"w" * 64)]
    with tarfile.open(path, "w:gz") as tar:
        status = tarfile.TarInfo("archive_status")
        status.type = tarfile.DIRTYPE
        tar.addfile(status)
        for name, data in members:
            info = tarfile.TarInfo(name)
            if isinstance(data, bytes):
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            else:
                info.type, info.linkname = tarfile.SYMTYPE, data
                tar.addfile(info)


def fake_runner(start_lsn="0/5000028", timeline=1, fail_verify=False, fail_waldump=False, members=None, calls=None):
    def run(cmd, **kwargs):
        if calls is not None:
            calls.append(cmd)
        if "pg_verifybackup" in cmd[0]:
            if fail_verify:
                raise subprocess.CalledProcessError(1, cmd)
            return subprocess.CompletedProcess(cmd, 0)
        if "pg_waldump" in cmd[0]:
            wal = Path(cmd[2].split("=", 1)[1])
            assert (wal / "000000010000000000000005").is_file()
            assert cmd[3:] == ["--timeline=%d" % timeline, "--start=" + start_lsn, "--end=0/6000000"]
            if fail_waldump:
                raise subprocess.CalledProcessError(1, cmd)
            return subprocess.CompletedProcess(cmd, 0)
        target = Path(cmd[cmd.index("-D") + 1])
        assert kwargs["env"]["PGSSLMODE"] == "verify-full"
        assert "--manifest-checksums=SHA256" in cmd and "stream" in cmd
        (target / "base.tar.gz").write_bytes(b"base")
        wal_tar(target / "pg_wal.tar.gz", members)
        (target / "backup_manifest").write_text(json.dumps({"WAL-Ranges": [{"Timeline": timeline, "Start-LSN": start_lsn, "End-LSN": "0/6000000"}]}))
        return subprocess.CompletedProcess(cmd, 0)
    return run


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.archive = Path(self.dir.name)
        self.cfg = {"archive": str(self.archive), "host": "100.64.0.1", "user": "replicator", "password": "x" * 40, "sslrootcert": "/ca", "keep": 2, "reserve": 0}

    def tearDown(self):
        self.dir.cleanup()

    def test_segment_end_math(self):
        self.assertEqual(backup.segment_end("000000010000000000000001"), 2 * 16 * 1024**2)
        self.assertEqual(backup.segment_end("000000020000000100000000"), (256 + 1) * 16 * 1024**2)
        self.assertEqual(backup.segment_end("000000010000000000000003.partial"), 4 * 16 * 1024**2)
        self.assertIsNone(backup.segment_end("00000002.history"))
        self.assertEqual(backup.lsn_value("1/5000028"), (1 << 32) + 0x5000028)

    def test_backup_publishes_verified_and_retention_prunes_only_covered_wal(self):
        for i in range(1, 9):
            (self.archive / ("0000000100000000%08X" % i)).write_bytes(b"w")
        (self.archive / "00000002.history").write_text("1\t0/3000000\tno recovery target specified\n")
        info = backup.run_backup(self.cfg, now=NOW, runner=fake_runner("0/3000028"))
        self.assertTrue(info["verified"])
        backup.run_backup(self.cfg, now=NOW + datetime.timedelta(hours=6), runner=fake_runner("0/5000028"))
        backup.run_backup(self.cfg, now=NOW + datetime.timedelta(hours=12), runner=fake_runner("0/7000028"))
        result = backup.retain(self.cfg, now=NOW + datetime.timedelta(hours=12))
        self.assertEqual(result["removed"], ["20261105T120000Z"])
        self.assertEqual(result["kept"], ["20261105T180000Z", "20261106T000000Z"])
        # Oldest kept backup starts in segment 5; segments 1-4 end at or before it.
        remaining = sorted(p.name for p in self.archive.iterdir() if p.is_file())
        self.assertEqual(remaining[0], "000000010000000000000005")
        self.assertIn("00000002.history", remaining)
        self.assertEqual(result["pruned_segments"], 4)

    def test_failed_verification_leaves_no_backup_and_no_pruning(self):
        (self.archive / "000000010000000000000001").write_bytes(b"w")
        with self.assertRaises(subprocess.CalledProcessError):
            backup.run_backup(self.cfg, now=NOW, runner=fake_runner(fail_verify=True))
        self.assertEqual(list((self.archive / "base").iterdir()), [])
        result = backup.retain(self.cfg, now=NOW)
        self.assertEqual(result["pruned_segments"], 0)
        self.assertTrue((self.archive / "000000010000000000000001").exists())

    def test_stale_pending_directories_are_removed(self):
        stale = self.archive / "base" / "20261101T000000Z.pending"
        stale.mkdir(parents=True)
        old = (NOW - datetime.timedelta(days=1)).timestamp()
        os.utime(stale, (old, old))
        self.assertIn(stale.name, backup.retain(self.cfg, now=NOW)["removed"])

    def test_stale_pending_is_removed_before_a_run_even_if_it_fails(self):
        base = self.archive / "base"
        stale = base / "20261101T000000Z.pending"
        fresh = base / "20261105T113000Z.pending"
        stale.mkdir(parents=True)
        fresh.mkdir()
        old = (NOW - datetime.timedelta(days=1)).timestamp()
        os.utime(stale, (old, old))
        with self.assertRaises(subprocess.CalledProcessError):
            backup.run_backup(self.cfg, now=NOW, runner=fake_runner(fail_verify=True))
        self.assertEqual([p.name for p in base.iterdir()], [fresh.name])

    def test_streamed_wal_is_parsed_before_publication(self):
        calls = []
        info = backup.run_backup(self.cfg, now=NOW, runner=fake_runner(calls=calls))
        self.assertTrue(info["verified"])
        self.assertEqual([Path(c[0]).name for c in calls], ["pg_basebackup", "pg_verifybackup", "pg_waldump"])
        published = self.archive / "base" / info["stamp"]
        self.assertEqual(sorted(p.name for p in published.iterdir()), ["backup.json", "backup_manifest", "base.tar.gz", "pg_wal.tar.gz"])

    def test_unparseable_wal_is_not_published(self):
        with self.assertRaises(subprocess.CalledProcessError):
            backup.run_backup(self.cfg, now=NOW, runner=fake_runner(fail_waldump=True))
        self.assertEqual(list((self.archive / "base").iterdir()), [])

    def test_unsafe_wal_archive_members_are_refused(self):
        for members in (
            [("000000010000000000000005", b"w"), ("../escape", b"x")],
            [("000000010000000000000005", b"w"), ("000000010000000000000006", "/etc/passwd")],
            [("000000010000000000000005", b"w"), ("sub/000000010000000000000006", b"x")],
        ):
            with self.assertRaises(ValueError):
                backup.run_backup(self.cfg, now=NOW, runner=fake_runner(members=members))
            self.assertEqual(list((self.archive / "base").iterdir()), [])
        self.assertFalse((self.archive / "escape").exists())

    def test_corrupt_wal_archive_is_refused(self):
        def runner(cmd, **kwargs):
            result = fake_runner()(cmd, **kwargs)
            if "pg_basebackup" in cmd[0]:
                (Path(cmd[cmd.index("-D") + 1]) / "pg_wal.tar.gz").write_bytes(b"not a tar")
            return result
        with self.assertRaises((ValueError, OSError)):
            backup.run_backup(self.cfg, now=NOW, runner=runner)
        self.assertEqual(list((self.archive / "base").iterdir()), [])

    def test_insufficient_free_space_refuses_before_pg_basebackup(self):
        backup.run_backup(self.cfg, now=NOW, runner=fake_runner())
        calls = []
        free = backup.shutil.disk_usage(self.archive).free
        cfg = dict(self.cfg, reserve=free + 1)
        with self.assertRaises(ValueError):
            backup.run_backup(cfg, now=NOW + datetime.timedelta(hours=6), runner=fake_runner(calls=calls))
        self.assertEqual(calls, [])
        self.assertEqual([p.name for p in (self.archive / "base").iterdir()], ["20261105T120000Z"])
        # The largest retained backup counts against free space too.
        with mock.patch.object(backup.shutil, "disk_usage", return_value=mock.Mock(free=10)):
            with self.assertRaises(ValueError):
                backup.run_backup(self.cfg, now=NOW + datetime.timedelta(hours=6), runner=fake_runner(calls=calls))
        self.assertEqual(calls, [])

    def test_main_failed_run_skips_retention(self):
        backup.run_backup(self.cfg, now=NOW, runner=fake_runner("0/3000028"))
        backup.run_backup(self.cfg, now=NOW + datetime.timedelta(hours=6), runner=fake_runner("0/5000028"))
        segment = self.archive / "000000010000000000000001"
        segment.write_bytes(b"w")
        cfg = dict(self.cfg, keep=1)
        with mock.patch.object(backup, "load_config", return_value=cfg),                 mock.patch.object(backup.subprocess, "run", fake_runner(fail_verify=True)),                 mock.patch("sys.argv", ["backup.py", "--keep", "1"]),                 mock.patch.object(backup.os, "umask"):
            with self.assertRaises(subprocess.CalledProcessError):
                backup.main()
        # keep=1 would have removed the first backup and pruned the segment.
        self.assertTrue(segment.exists())
        self.assertEqual(len(backup.published(self.archive / "base")), 2)


if __name__ == "__main__":
    unittest.main()
