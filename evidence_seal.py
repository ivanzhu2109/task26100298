"""Appeal evidence sealing store.

SQLite keeps acceptance records; evidence bytes live in content-sealed
files on local disk. Every accepted submission produces an immutable
version. Calls are serial; the process may be killed at any point.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import signal
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EntryInput:
    """One evidence item to seal: logical id, type tag, source file path."""

    logical_id: str
    type: str
    source_path: str


@dataclass(frozen=True)
class Receipt:
    """Trust anchor returned by a successful seal; kept by the caller."""

    appeal_id: str
    version: int
    root_hash: str


@dataclass(frozen=True)
class EntryManifest:
    """Description of one sealed evidence entry inside a version."""

    seq: int
    logical_id: str
    type: str
    sha256: str
    size: int


@dataclass(frozen=True)
class VersionManifest:
    """Evidence listing of one accepted version."""

    appeal_id: str
    version: int
    root_hash: str
    prev_root_hash: str
    entries: List[EntryManifest] = field(default_factory=list)


class SealError(Exception):
    """Base error of the sealing store."""


class VerifyError(SealError):
    """Raised when verification of a receipt fails."""


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class SealStore:
    """Evidence sealing store backed by SQLite + local files."""

    ZERO_ROOT = "0" * 64

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS requests(
        request_id TEXT PRIMARY KEY,
        appeal_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        root_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS versions(
        appeal_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        root_hash TEXT NOT NULL,
        prev_root_hash TEXT NOT NULL,
        request_id TEXT NOT NULL,
        PRIMARY KEY(appeal_id, version)
    );
    CREATE TABLE IF NOT EXISTS entries(
        appeal_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        seq INTEGER NOT NULL,
        logical_id TEXT NOT NULL,
        type TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size INTEGER NOT NULL,
        PRIMARY KEY(appeal_id, version, seq)
    );
    """

    def __init__(self, root: str) -> None:
        self._root = Path(root)
        self._staging = self._root / "staging"
        self._evidence = self._root / "evidence"
        self._staging.mkdir(parents=True, exist_ok=True)
        self._evidence.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self._root / "seal.db"))
        self._db.execute("PRAGMA journal_mode=DELETE")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(self._SCHEMA)
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    # -- path helpers ------------------------------------------------------

    @staticmethod
    def _check_name(kind: str, value: str) -> None:
        if (not value or "/" in value or "\\" in value
                or value in (".", "..") or "\x00" in value):
            raise SealError(f"invalid {kind}: {value!r}")

    def _version_dir(self, appeal_id: str, version: int) -> Path:
        return self._evidence / appeal_id / str(version)

    # -- low-level durability helpers --------------------------------------

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _hash_file(path: Path) -> "tuple[str, int]":
        h = hashlib.sha256()
        size = 0
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
                size += len(chunk)
        return h.hexdigest(), size

    # -- test-only crash injection -----------------------------------------

    @staticmethod
    def _crash_point(name: str) -> None:
        """Kill this process when SEAL_CRASH_AT names this point.

        Used exclusively by the test-suite to simulate a forced kill in
        the middle of a commit or recovery. Never triggers in normal use.
        """
        if os.environ.get("SEAL_CRASH_AT") == name:
            os.kill(os.getpid(), signal.SIGKILL)

    # -- operations --------------------------------------------------------

    def seal(self, appeal_id: str, request_id: str,
             entries: List[EntryInput]) -> Receipt:
        """Seal an ordered group of evidence; return an immutable receipt."""
        self._check_name("appeal_id", appeal_id)
        self._check_name("request_id", request_id)
        if not entries:
            raise SealError("entries must not be empty")
        for e in entries:
            self._check_name("logical_id", e.logical_id)
            self._check_name("type", e.type)

        # Idempotent retry: an accepted request always returns its receipt,
        # even if newer versions exist or the source files are gone.
        row = self._db.execute(
            "SELECT appeal_id, version, root_hash FROM requests"
            " WHERE request_id = ?", (request_id,)).fetchone()
        if row is not None:
            return Receipt(appeal_id=row[0], version=row[1], root_hash=row[2])

        # Phase 1: copy source bytes into a private staging directory,
        # hashing while copying. Anything left here by a killed process is
        # garbage that recover() removes.
        stage_dir = self._staging / request_id
        if stage_dir.exists():
            shutil.rmtree(stage_dir)
        stage_dir.mkdir(parents=True)
        metas: List[tuple] = []  # (logical_id, type, sha256, size)
        for seq, entry in enumerate(entries):
            dst = stage_dir / str(seq)
            h = hashlib.sha256()
            size = 0
            with open(entry.source_path, "rb") as src, \
                    open(dst, "wb") as out:
                for chunk in iter(lambda: src.read(1 << 20), b""):
                    out.write(chunk)
                    h.update(chunk)
                    size += len(chunk)
                out.flush()
                os.fsync(out.fileno())
            metas.append((entry.logical_id, entry.type, h.hexdigest(), size))
            if seq == 0:
                self._crash_point("stage_partial")
        self._fsync_dir(stage_dir)

        # Phase 2: decide the version number from accepted history only.
        row = self._db.execute(
            "SELECT MAX(version) FROM versions WHERE appeal_id = ?",
            (appeal_id,)).fetchone()
        version = (row[0] or 0) + 1
        if version > 1:
            prev_root = self._db.execute(
                "SELECT root_hash FROM versions WHERE appeal_id = ?"
                " AND version = ?", (appeal_id, version - 1)).fetchone()[0]
        else:
            prev_root = self.ZERO_ROOT
        root_hash = self._root_hash(appeal_id, version, prev_root, metas)

        # Phase 3: move staged blobs into their final, version-scoped
        # location. Renames are atomic; directories are fsynced so the
        # blobs survive a kill before the acceptance record commits.
        vdir = self._version_dir(appeal_id, version)
        vdir.mkdir(parents=True, exist_ok=False)
        for seq in range(len(metas)):
            os.replace(str(stage_dir / str(seq)), str(vdir / str(seq)))
        self._fsync_dir(vdir)
        self._fsync_dir(vdir.parent)
        self._crash_point("after_blobs")

        # Phase 4: acceptance = one SQLite transaction. Before this commit
        # the submission does not exist; after it, it is fully accepted.
        try:
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute(
                "INSERT INTO versions(appeal_id, version, root_hash,"
                " prev_root_hash, request_id) VALUES(?,?,?,?,?)",
                (appeal_id, version, root_hash, prev_root, request_id))
            for seq, (logical_id, type_, sha, size) in enumerate(metas):
                self._db.execute(
                    "INSERT INTO entries(appeal_id, version, seq,"
                    " logical_id, type, sha256, size)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (appeal_id, version, seq, logical_id, type_, sha, size))
            self._db.execute(
                "INSERT INTO requests(request_id, appeal_id, version,"
                " root_hash) VALUES(?,?,?,?)",
                (request_id, appeal_id, version, root_hash))
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise
        self._crash_point("after_commit")

        # Phase 5: staging directory is empty now; drop it.
        stage_dir.rmdir()
        self._fsync_dir(self._staging)

        return Receipt(appeal_id=appeal_id, version=version,
                       root_hash=root_hash)

    # -- root digest ---------------------------------------------------------

    @classmethod
    def _root_hash(cls, appeal_id: str, version: int, prev_root: str,
                   metas: List[tuple]) -> str:
        """Bind appeal, version, previous root and ordered entry metadata."""
        h = hashlib.sha256()

        def feed(text: str) -> None:
            b = text.encode("utf-8")
            h.update(len(b).to_bytes(8, "big"))
            h.update(b)

        feed("evidence-seal-root-v1")
        feed(appeal_id)
        feed(str(version))
        feed(prev_root)
        for logical_id, type_, sha, _size in metas:
            feed(logical_id)
            feed(type_)
            feed(sha)
        return h.hexdigest()

    def verify(self, receipt: Receipt) -> List[VersionManifest]:
        """Verify the receipt's version and its full history prefix."""
        self._check_name("appeal_id", receipt.appeal_id)
        if receipt.version < 1:
            raise VerifyError(f"invalid version: {receipt.version}")

        manifests: List[VersionManifest] = []
        prev_root = self.ZERO_ROOT
        for version in range(1, receipt.version + 1):
            row = self._db.execute(
                "SELECT root_hash, prev_root_hash FROM versions"
                " WHERE appeal_id = ? AND version = ?",
                (receipt.appeal_id, version)).fetchone()
            if row is None:
                raise VerifyError(
                    f"version {version} of appeal {receipt.appeal_id!r}"
                    " is missing")
            stored_root, stored_prev = row
            if stored_prev != prev_root:
                raise VerifyError(
                    f"version {version}: prev_root_hash chain broken")

            rows = self._db.execute(
                "SELECT seq, logical_id, type, sha256, size FROM entries"
                " WHERE appeal_id = ? AND version = ? ORDER BY seq",
                (receipt.appeal_id, version)).fetchall()
            if not rows:
                raise VerifyError(f"version {version}: no entries")
            if [r[0] for r in rows] != list(range(len(rows))):
                raise VerifyError(
                    f"version {version}: entry sequence is not contiguous")

            metas: List[tuple] = []
            manifests_entries: List[EntryManifest] = []
            vdir = self._version_dir(receipt.appeal_id, version)
            for seq, logical_id, type_, sha, size in rows:
                blob = vdir / str(seq)
                if not blob.is_file():
                    raise VerifyError(
                        f"version {version} entry {seq}: evidence bytes"
                        f" missing ({blob})")
                actual_sha, actual_size = self._hash_file(blob)
                if actual_sha != sha or actual_size != size:
                    raise VerifyError(
                        f"version {version} entry {seq}: evidence bytes"
                        " do not match the sealed digest")
                metas.append((logical_id, type_, sha, size))
                manifests_entries.append(EntryManifest(
                    seq=seq, logical_id=logical_id, type=type_,
                    sha256=sha, size=size))

            recomputed = self._root_hash(receipt.appeal_id, version,
                                         prev_root, metas)
            if recomputed != stored_root:
                raise VerifyError(
                    f"version {version}: stored root hash does not match"
                    " the sealed evidence")
            manifests.append(VersionManifest(
                appeal_id=receipt.appeal_id, version=version,
                root_hash=stored_root, prev_root_hash=stored_prev,
                entries=manifests_entries))
            prev_root = stored_root

        # The caller-supplied receipt is the trust anchor: the recomputed
        # chain must reproduce exactly the root hash it carries.
        if prev_root != receipt.root_hash:
            raise VerifyError(
                "receipt root hash does not match the sealed chain")
        return manifests

    def recover(self) -> None:
        """Recover interrupted operations and remove unaccepted files."""
        # Phase A: drop every staging directory. A staging directory only
        # ever contains bytes of a submission that was never accepted, so
        # it is always safe to delete. Deleting one directory at a time
        # keeps a killed recovery convergent: rerunning simply continues.
        first = True
        for child in sorted(self._staging.iterdir()):
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
            if first:
                self._crash_point("recover_mid")
                first = False
        self._fsync_dir(self._staging)

        # Phase B: drop evidence directories that no accepted version
        # references. These belong to submissions killed after their blobs
        # landed but before the acceptance record committed. Accepted
        # versions are never touched here, even if their bytes are damaged
        # -- that is corruption for verify() to report, not garbage.
        accepted = set()
        for appeal_id, version in self._db.execute(
                "SELECT appeal_id, version FROM versions"):
            accepted.add((appeal_id, version))
        for appeal_dir in sorted(self._evidence.iterdir()):
            if not appeal_dir.is_dir():
                continue
            for vdir in sorted(appeal_dir.iterdir()):
                if not vdir.is_dir():
                    continue
                try:
                    version = int(vdir.name)
                except ValueError:
                    version = -1
                if (appeal_dir.name, version) not in accepted:
                    shutil.rmtree(vdir)
            if not any(appeal_dir.iterdir()):
                appeal_dir.rmdir()
            self._fsync_dir(self._evidence)
