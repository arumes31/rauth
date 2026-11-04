import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import backup

NOW = datetime.datetime(2026, 11, 5, 12, 0, tzinfo=datetime.timezone.utc)


def fake_runner(start_lsn="0/5000028", timeline=1, fail_verify=False):
    def run(cmd, **kwargs):
        if "pg_verifybackup" in cmd[0]:
            if fail_verify:
                raise subprocess.CalledProcessError(1, cmd)
            return subprocess.CompletedProcess(cmd, 0)
        target = Path(cmd[cmd.index("-D") + 1])
        assert kwargs["env"]["PGSSLMODE"] == "verify-full"
        assert "--manifest-checksums=SHA256" in cmd and "stream" in cmd
        (target / "base.tar.gz").write_bytes(b"base")
        (target / "pg_wal.tar.gz").write_bytes(b"wal")
        (target / "backup_manifest").write_text(json.dumps({"WAL-Ranges": [{"Timeline": timeline, "Start-LSN": start_lsn, "End-LSN": "0/6000000"}]}))
        return subprocess.CompletedProcess(cmd, 0)
    return run


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.archive = Path(self.dir.name)
        self.cfg = {"archive": str(self.archive), "host": "100.64.0.1", "user": "replicator", "password": "x" * 40, "sslrootcert": "/ca", "keep": 2}

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


if __name__ == "__main__":
    unittest.main()
