"""Automated tests for the seal store.

Crash windows are exercised by running real subprocesses that kill
themselves with SIGKILL at exact points inside Seal/Recover (selected
via the SEALSTORE_KILL_AT environment variable).
"""

import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from sealstore import (  # noqa: E402
    Entry,
    Receipt,
    RecoverError,
    SealStore,
    VerifyError,
)

WORKER = os.path.join(REPO_ROOT, "tests", "worker.py")


def _sigkilled(proc):
    return proc.returncode == -signal.SIGKILL


class SealStoreTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sealstore-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.src_dir = os.path.join(self.tmp, "src")
        os.makedirs(self.src_dir)
        self.store_dir = os.path.join(self.tmp, "store")
        self.store = SealStore(self.store_dir)

    def make_source(self, name, data):
        path = os.path.join(self.src_dir, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def run_worker(self, *args, kill_at=None):
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT
        if kill_at is not None:
            env["SEALSTORE_KILL_AT"] = kill_at
        return subprocess.run(
            [sys.executable, WORKER, self.store_dir] + list(args),
            capture_output=True,
            text=True,
            env=env,
        )

    def worker_seal(self, appeal_id, request_id, entries, kill_at=None):
        spec_path = os.path.join(self.tmp, "spec-%s.json" % request_id)
        with open(spec_path, "w", encoding="utf-8") as handle:
            json.dump(
                [
                    {
                        "logical_id": e.logical_id,
                        "etype": e.etype,
                        "source_path": e.source_path,
                    }
                    for e in entries
                ],
                handle,
            )
        return self.run_worker("seal", appeal_id, request_id, spec_path,
                               kill_at=kill_at)

    def worker_recover(self, kill_at=None):
        return self.run_worker("recover", kill_at=kill_at)

    def reopen_store(self):
        self.store = SealStore(self.store_dir)
        return self.store

    def db(self):
        conn = sqlite3.connect(os.path.join(self.store_dir, "seal.db"))
        self.addCleanup(conn.close)
        return conn

    def evidence_files(self):
        result = []
        root = os.path.join(self.store_dir, "evidence")
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                result.append(os.path.join(dirpath, name))
        return sorted(result)

    def committed_evidence_files(self):
        conn = self.db()
        rows = conn.execute(
            "SELECT appeal_id, version, seq FROM entries"
        ).fetchall()
        expected = set()
        for appeal_id, version, seq in rows:
            expected.add(self.store._version_dir(appeal_id, version)
                         + os.sep + str(seq))
        return expected


class BasicSealVerifyTest(SealStoreTestBase):
    def test_seal_supplement_and_verify_chain(self):
        p1 = self.make_source("photo.jpg", b"\xff\xd8photo-bytes" * 500)
        p2 = self.make_source("chat.txt", "聊天记录".encode("utf-8") * 300)
        p3 = self.make_source("pay.ref", b"pay:txn:12345")

        r1 = self.store.seal("appeal-A", "req-1",
                             [Entry("photo", "image", p1)])
        self.assertEqual((r1.appeal_id, r1.version), ("appeal-A", 1))
        self.assertEqual(len(r1.root_digest), 64)

        r2 = self.store.seal(
            "appeal-A", "req-2",
            [Entry("chat", "chatlog", p2), Entry("pay", "payment", p3)],
        )
        self.assertEqual(r2.version, 2)
        self.assertNotEqual(r1.root_digest, r2.root_digest)

        manifests = self.store.verify(r2)
        self.assertEqual(len(manifests), 2)
        self.assertEqual([m.logical_id for m in manifests[0]], ["photo"])
        self.assertEqual([m.logical_id for m in manifests[1]], ["chat", "pay"])
        self.assertEqual([m.etype for m in manifests[1]], ["chatlog", "payment"])

        # Old receipt still independently verifies its history prefix.
        old_manifests = self.store.verify(r1)
        self.assertEqual(len(old_manifests), 1)
        self.assertEqual(old_manifests, manifests[:1])

        # Receipt survives a dict round-trip (caller-side persistence).
        self.assertEqual(
            self.store.verify(Receipt.from_dict(r2.to_dict())), manifests
        )

    def test_source_modified_and_deleted_after_seal(self):
        p1 = self.make_source("a.bin", b"original-bytes" * 100)
        p2 = self.make_source("b.bin", b"other-bytes" * 100)
        receipt = self.store.seal(
            "appeal-B", "req-1",
            [Entry("x", "image", p1), Entry("y", "chatlog", p2)],
        )
        with open(p1, "wb") as handle:
            handle.write(b"modified-after-seal")
        os.unlink(p2)
        manifests = self.store.verify(receipt)
        self.assertEqual(len(manifests), 1)
        self.assertEqual([m.logical_id for m in manifests[0]], ["x", "y"])

    def test_request_id_retry_returns_original_receipt(self):
        p1 = self.make_source("a.bin", b"aaa")
        p2 = self.make_source("b.bin", b"bbb")
        r1 = self.store.seal("appeal-C", "req-1", [Entry("x", "image", p1)])
        self.store.seal("appeal-C", "req-2", [Entry("y", "image", p2)])
        os.unlink(p1)
        # Retry of an accepted request returns the original receipt even
        # though a newer version exists and the source file is gone.
        retry = self.store.seal("appeal-C", "req-1", [Entry("x", "image", p1)])
        self.assertEqual(retry, r1)
        conn = self.db()
        versions = [row[0] for row in conn.execute(
            "SELECT version FROM versions WHERE appeal_id='appeal-C' "
            "ORDER BY version")]
        self.assertEqual(versions, [1, 2])


class TamperDetectionTest(SealStoreTestBase):
    def setUp(self):
        super().setUp()
        p1 = self.make_source("a.bin", b"alpha" * 200)
        p2 = self.make_source("b.bin", b"beta" * 200)
        self.receipt = self.store.seal(
            "appeal-T", "req-1",
            [Entry("first", "image", p1), Entry("second", "payment", p2)],
        )

    def test_tampered_evidence_bytes_fail(self):
        path = self.store._version_dir("appeal-T", 1) + os.sep + "0"
        with open(path, "r+b") as handle:
            handle.write(b"X")
        with self.assertRaises(VerifyError):
            self.store.verify(self.receipt)

    def test_tampered_entry_order_fails(self):
        conn = self.db()
        where = "appeal_id = 'appeal-T' AND version = 1"
        conn.execute("UPDATE entries SET seq = 99 WHERE %s AND seq = 0" % where)
        conn.execute("UPDATE entries SET seq = 0 WHERE %s AND seq = 1" % where)
        conn.execute("UPDATE entries SET seq = 1 WHERE %s AND seq = 99" % where)
        conn.commit()
        with self.assertRaises(VerifyError):
            self.store.verify(self.receipt)

    def test_tampered_logical_id_fails(self):
        conn = self.db()
        conn.execute("UPDATE entries SET logical_id = 'forged' "
                     "WHERE appeal_id = 'appeal-T' AND seq = 0")
        conn.commit()
        with self.assertRaises(VerifyError):
            self.store.verify(self.receipt)

    def test_recover_refuses_to_hide_committed_corruption(self):
        path = self.store._version_dir("appeal-T", 1) + os.sep + "1"
        os.unlink(path)
        with self.assertRaises(RecoverError):
            self.store.recover()
        # Records are untouched: verification still fails explicitly,
        # and the accepted record was not deleted or rewritten.
        with self.assertRaises(VerifyError):
            self.store.verify(self.receipt)
        conn = self.db()
        count = conn.execute("SELECT COUNT(*) FROM versions").fetchone()[0]
        self.assertEqual(count, 1)


class ReceiptAnchorTest(SealStoreTestBase):
    def test_verify_rejects_self_consistent_old_prefix(self):
        p1 = self.make_source("a.bin", b"v1-data" * 100)
        p2 = self.make_source("b.bin", b"v2-data" * 100)
        r1 = self.store.seal("appeal-R", "req-1", [Entry("x", "image", p1)])
        r2 = self.store.seal("appeal-R", "req-2", [Entry("y", "chatlog", p2)])

        # Remove the latest version, leaving an internally consistent
        # old prefix behind (rows + evidence files of version 2 gone).
        conn = self.db()
        conn.execute("DELETE FROM entries WHERE appeal_id='appeal-R' "
                     "AND version = 2")
        conn.execute("DELETE FROM versions WHERE appeal_id='appeal-R' "
                     "AND version = 2")
        conn.commit()
        shutil.rmtree(self.store._version_dir("appeal-R", 2))

        # The independently kept latest receipt must be rejected.
        with self.assertRaises(VerifyError):
            self.store.verify(r2)
        # The old receipt still verifies its own prefix.
        self.assertEqual(len(self.store.verify(r1)), 1)


class CrashRecoveryTest(SealStoreTestBase):
    def setUp(self):
        super().setUp()
        self.p1 = self.make_source("one.bin", b"first-version" * 500)
        self.p2 = self.make_source("two.bin", b"second-version" * 500)
        self.p3 = self.make_source("three.bin", b"third-version" * 500)
        self.r1 = self.store.seal("appeal-K", "req-v1",
                                  [Entry("doc", "image", self.p1)])
        self.v2_entries = [
            Entry("chat", "chatlog", self.p2),
            Entry("pay", "payment", self.p3),
        ]

    def assert_only_version1_remains(self):
        self.reopen_store()
        self.assertEqual(len(self.store.verify(self.r1)), 1)
        conn = self.db()
        versions = [row[0] for row in conn.execute(
            "SELECT version FROM versions WHERE appeal_id='appeal-K'")]
        self.assertEqual(versions, [1])
        self.assertEqual(
            set(self.evidence_files()), self.committed_evidence_files()
        )

    def test_crash_during_partial_file_write(self):
        proc = self.worker_seal("appeal-K", "req-v2", self.v2_entries,
                                kill_at="after_first_file")
        self.assertTrue(_sigkilled(proc), proc)

        # Kill the first recovery run mid-cleanup, then recover again;
        # recovery must still converge.
        proc = self.worker_recover(kill_at="recover_after_delete")
        self.assertTrue(_sigkilled(proc), proc)
        proc = self.worker_recover()
        self.assertEqual(proc.returncode, 0, proc.stderr)

        self.assert_only_version1_remains()

        # The interrupted request may still be accepted later; it must
        # land on version 2 with no gap and no duplicate.
        r2 = self.store.seal("appeal-K", "req-v2", self.v2_entries)
        self.assertEqual(r2.version, 2)
        self.assertEqual(len(self.store.verify(r2)), 2)
        conn = self.db()
        versions = [row[0] for row in conn.execute(
            "SELECT version FROM versions WHERE appeal_id='appeal-K' "
            "ORDER BY version")]
        self.assertEqual(versions, [1, 2])

    def test_crash_after_files_before_commit(self):
        proc = self.worker_seal("appeal-K", "req-v2", self.v2_entries,
                                kill_at="after_files")
        self.assertTrue(_sigkilled(proc), proc)
        # Evidence bytes are fully on disk but no acceptance exists yet.
        orphan_dir = self.store._version_dir("appeal-K", 2)
        self.assertTrue(os.path.isdir(orphan_dir))

        proc = self.worker_recover()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # A complete recovery leaves no unaccepted evidence behind.
        self.assertFalse(os.path.exists(orphan_dir))
        self.assert_only_version1_remains()

        # Retry with the same request_id is accepted cleanly as v2.
        r2 = self.store.seal("appeal-K", "req-v2", self.v2_entries)
        self.assertEqual(r2.version, 2)
        self.assertEqual(len(self.store.verify(r2)), 2)

    def test_crash_after_commit_before_receipt(self):
        proc = self.worker_seal("appeal-K", "req-v2", self.v2_entries,
                                kill_at="after_commit")
        self.assertTrue(_sigkilled(proc), proc)

        proc = self.worker_recover()
        self.assertEqual(proc.returncode, 0, proc.stderr)

        # The committed version survives; nothing is rolled back.
        self.reopen_store()
        conn = self.db()
        versions = [row[0] for row in conn.execute(
            "SELECT version FROM versions WHERE appeal_id='appeal-K' "
            "ORDER BY version")]
        self.assertEqual(versions, [1, 2])
        stored_root = conn.execute(
            "SELECT root_digest FROM versions WHERE appeal_id='appeal-K' "
            "AND version = 2").fetchone()[0]

        # Retrying the same request_id returns the original receipt,
        # even though the caller never saw it.
        retry = self.store.seal("appeal-K", "req-v2", self.v2_entries)
        self.assertEqual(retry.version, 2)
        self.assertEqual(retry.root_digest, stored_root)
        self.assertEqual(len(self.store.verify(retry)), 2)
        # Old receipt still verifies its prefix.
        self.assertEqual(len(self.store.verify(self.r1)), 1)
        # No duplicate version was created by the retry.
        versions = [row[0] for row in conn.execute(
            "SELECT version FROM versions WHERE appeal_id='appeal-K' "
            "ORDER BY version")]
        self.assertEqual(versions, [1, 2])


if __name__ == "__main__":
    unittest.main()
