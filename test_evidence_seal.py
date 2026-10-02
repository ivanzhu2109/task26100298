"""Automated tests for the appeal evidence sealing store.

Crash windows are exercised by running real child processes and killing
them with SIGKILL at instrumented points (never by raising exceptions).
"""

import signal
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from evidence_seal import EntryInput, Receipt, SealStore, VerifyError

ROOT = Path(__file__).resolve().parent
CHILD = ROOT / "crash_child.py"

APPEAL = "appeal-1"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make_sources(src: Path) -> None:
    src.mkdir(parents=True, exist_ok=True)
    (src / "a.png").write_bytes(b"\x89PNG fake image v1")
    (src / "b.png").write_bytes(b"\x89PNG fake image v2")
    (src / "chat.txt").write_bytes(b"alice: hi\nbob: hello\n")
    (src / "pay.txt").write_bytes(b"payment-ref: TXN-123\n")


def v2_entries(src: Path):
    return [
        EntryInput("img2", "image", str(src / "b.png")),
        EntryInput("chat2", "chat", str(src / "chat.txt")),
        EntryInput("pay2", "payment", str(src / "pay.txt")),
    ]


def run_child(mode, store, src, crash=""):
    cmd = [sys.executable, str(CHILD), mode, str(store), str(src)]
    if crash:
        cmd.append(crash)
    return subprocess.run(cmd, capture_output=True, timeout=60)


def db(store: Path, sql: str, args=()):
    con = sqlite3.connect(str(store / "seal.db"))
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def db_exec(store: Path, statements):
    con = sqlite3.connect(str(store / "seal.db"))
    try:
        for sql, args in statements:
            con.execute(sql, args)
        con.commit()
    finally:
        con.close()


def seal_v1(store: SealStore, src: Path) -> Receipt:
    return store.seal(APPEAL, "req-v1",
                      [EntryInput("img1", "image", str(src / "a.png"))])


def assert_no_unaccepted_files(store: Path) -> None:
    staging = store / "staging"
    assert list(staging.iterdir()) == [], "staging leftovers after recover"
    accepted = {(a, v) for a, v in db(store, "SELECT appeal_id, version"
                                             " FROM versions")}
    evidence = store / "evidence"
    for appeal_dir in evidence.iterdir():
        for vdir in appeal_dir.iterdir():
            assert (appeal_dir.name, int(vdir.name)) in accepted, \
                f"unaccepted evidence left behind: {vdir}"


def assert_versions_continuous(store: Path) -> None:
    versions = sorted(r[0] for r in db(
        store, "SELECT version FROM versions WHERE appeal_id = ?",
        (APPEAL,)))
    assert versions == list(range(1, len(versions) + 1))


# ---------------------------------------------------------------------------
# basic behaviour
# ---------------------------------------------------------------------------

def test_seal_supplement_retry_and_source_removal(tmp_path):
    store_path, src = tmp_path / "store", tmp_path / "src"
    make_sources(src)
    store = SealStore(str(store_path))

    r1 = seal_v1(store, src)
    assert (r1.appeal_id, r1.version) == (APPEAL, 1)
    assert len(r1.root_hash) == 64

    r2 = store.seal(APPEAL, "req-v2", v2_entries(src))
    assert r2.version == 2 and r2.root_hash != r1.root_hash

    # Same request_id retries return the original receipt, even with
    # different arguments and even after newer versions exist.
    r3 = store.seal(APPEAL, "req-v3",
                    [EntryInput("img3", "image", str(src / "a.png"))])
    assert r3.version == 3
    assert store.seal(APPEAL, "req-v2",
                      [EntryInput("other", "image",
                                  str(src / "a.png"))]) == r2

    # Modify and delete every source file: verification must still pass.
    (src / "a.png").write_bytes(b"tampered after sealing")
    for f in ("b.png", "chat.txt", "pay.txt"):
        (src / f).unlink()

    m1 = store.verify(r1)
    assert len(m1) == 1 and m1[0].entries[0].logical_id == "img1"
    m2 = store.verify(r2)
    assert len(m2) == 2
    assert [e.logical_id for e in m2[1].entries] == ["img2", "chat2", "pay2"]
    assert [e.type for e in m2[1].entries] == ["image", "chat", "payment"]
    m3 = store.verify(r3)
    assert len(m3) == 3
    store.close()


# ---------------------------------------------------------------------------
# crash windows during a supplementing commit
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("crash_point,committed", [
    ("stage_partial", False),   # killed while only part of the files staged
    ("after_blobs", False),     # blobs landed, acceptance not yet persisted
    ("after_commit", True),     # acceptance persisted, receipt not returned
])
def test_crash_window_then_recover(tmp_path, crash_point, committed):
    store_path, src = tmp_path / "store", tmp_path / "src"
    make_sources(src)
    store = SealStore(str(store_path))
    r1 = seal_v1(store, src)
    store.close()

    # Forcibly kill a child process in the middle of the v2 commit.
    proc = run_child("seal-v2", store_path, src, crash_point)
    assert proc.returncode == -signal.SIGKILL, proc.stderr

    # Forcibly kill a recovery run in the middle, then converge.
    proc = run_child("recover", store_path, src, "recover_mid")
    assert proc.returncode == -signal.SIGKILL, proc.stderr

    # Restart (fresh process state) and finish recovery.
    store = SealStore(str(store_path))
    store.recover()
    store.recover()  # recovery is idempotent

    # The old receipt still verifies its history prefix.
    assert len(store.verify(r1)) == 1

    # No garbage files, no empty/duplicate version numbers.
    assert_no_unaccepted_files(store_path)
    assert_versions_continuous(store_path)

    if committed:
        # The request was accepted before the kill; the receipt never
        # reached the caller. Retry must return the original receipt even
        # though the source files are now deleted.
        for f in src.iterdir():
            f.unlink()
        r2 = store.seal(APPEAL, "req-v2", v2_entries(src))
        assert r2.version == 2
        manifests = store.verify(r2)
        assert len(manifests) == 2
        assert [e.logical_id for e in manifests[1].entries] == \
            ["img2", "chat2", "pay2"]
    else:
        # The request was never accepted: exactly one version exists and
        # the same request_id may still complete as a whole.
        assert db(store_path, "SELECT COUNT(*) FROM versions"
                              " WHERE appeal_id = ?", (APPEAL,)) == [(1,)]
        r2 = store.seal(APPEAL, "req-v2", v2_entries(src))
        assert r2.version == 2
        assert len(store.verify(r2)) == 2
        assert_no_unaccepted_files(store_path)
        assert_versions_continuous(store_path)
    store.close()


# ---------------------------------------------------------------------------
# tamper detection
# ---------------------------------------------------------------------------

def test_tampered_evidence_bytes_fail(tmp_path):
    store_path, src = tmp_path / "store", tmp_path / "src"
    make_sources(src)
    store = SealStore(str(store_path))
    seal_v1(store, src)
    r2 = store.seal(APPEAL, "req-v2", v2_entries(src))
    store.close()

    blob = store_path / "evidence" / APPEAL / "2" / "0"
    with open(blob, "ab") as f:
        f.write(b"x")
    store = SealStore(str(store_path))
    with pytest.raises(VerifyError):
        store.verify(r2)
    store.close()


def test_missing_evidence_bytes_fail(tmp_path):
    store_path, src = tmp_path / "store", tmp_path / "src"
    make_sources(src)
    store = SealStore(str(store_path))
    r1 = seal_v1(store, src)
    store.close()

    (store_path / "evidence" / APPEAL / "1" / "0").unlink()
    store = SealStore(str(store_path))
    with pytest.raises(VerifyError):
        store.verify(r1)
    store.close()


def test_tampered_entry_order_fails(tmp_path):
    store_path, src = tmp_path / "store", tmp_path / "src"
    make_sources(src)
    store = SealStore(str(store_path))
    seal_v1(store, src)
    r2 = store.seal(APPEAL, "req-v2", v2_entries(src))
    store.close()

    # Swap the first two entries of version 2 inside the database.
    db_exec(store_path, [
        ("UPDATE entries SET seq = seq + 100"
         " WHERE appeal_id = ? AND version = 2", (APPEAL,)),
        ("UPDATE entries SET seq = CASE seq"
         " WHEN 100 THEN 1 WHEN 101 THEN 0 ELSE seq END"
         " WHERE appeal_id = ? AND version = 2", (APPEAL,)),
    ])
    store = SealStore(str(store_path))
    with pytest.raises(VerifyError):
        store.verify(r2)
    store.close()


def test_tampered_logical_id_fails(tmp_path):
    store_path, src = tmp_path / "store", tmp_path / "src"
    make_sources(src)
    store = SealStore(str(store_path))
    r1 = seal_v1(store, src)
    store.close()

    db_exec(store_path, [
        ("UPDATE entries SET logical_id = ?"
         " WHERE appeal_id = ? AND version = 1 AND seq = 0",
         ("forged", APPEAL)),
    ])
    store = SealStore(str(store_path))
    with pytest.raises(VerifyError):
        store.verify(r1)
    store.close()


# ---------------------------------------------------------------------------
# trust anchor: an internally consistent old prefix is not enough
# ---------------------------------------------------------------------------

def test_old_prefix_cannot_impersonate_latest_receipt(tmp_path):
    store_path, src = tmp_path / "store", tmp_path / "src"
    make_sources(src)
    store = SealStore(str(store_path))
    r1 = seal_v1(store, src)
    r2 = store.seal(APPEAL, "req-v2", v2_entries(src))
    store.close()

    # Remove the latest version entirely, leaving an internally
    # consistent old prefix behind.
    db_exec(store_path, [
        ("DELETE FROM requests WHERE request_id = ?", ("req-v2",)),
        ("DELETE FROM entries WHERE appeal_id = ? AND version = 2",
         (APPEAL,)),
        ("DELETE FROM versions WHERE appeal_id = ? AND version = 2",
         (APPEAL,)),
    ])
    import shutil
    shutil.rmtree(store_path / "evidence" / APPEAL / "2")

    store = SealStore(str(store_path))
    # The independently kept latest receipt must be rejected...
    with pytest.raises(VerifyError):
        store.verify(r2)
    # ...while the genuine old receipt still verifies.
    assert len(store.verify(r1)) == 1
    store.close()


# ---------------------------------------------------------------------------
# recovery never hides corruption of accepted versions
# ---------------------------------------------------------------------------

def test_recover_does_not_hide_accepted_corruption(tmp_path):
    store_path, src = tmp_path / "store", tmp_path / "src"
    make_sources(src)
    store = SealStore(str(store_path))
    r1 = seal_v1(store, src)
    store.close()

    (store_path / "evidence" / APPEAL / "1" / "0").unlink()
    store = SealStore(str(store_path))
    store.recover()
    # The acceptance record must survive recovery untouched...
    assert db(store_path, "SELECT COUNT(*) FROM versions"
                          " WHERE appeal_id = ?", (APPEAL,)) == [(1,)]
    # ...and verification must explicitly fail, not be "repaired".
    with pytest.raises(VerifyError):
        store.verify(r1)
    store.close()
