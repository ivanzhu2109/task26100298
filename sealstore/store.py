"""Core sealing store implementation.

Layout under ``base_dir``::

    seal.db                              SQLite acceptance records
    evidence/<appeal-hash>/<version>/<seq>   sealed evidence bytes

Seal writes evidence bytes to their final location first (tmp file +
fsync + atomic rename + directory fsync), then records acceptance in a
single SQLite transaction. A crash therefore leaves either unreferenced
files (cleaned by recover) or a fully committed version. Recover never
deletes records and never touches evidence referenced by committed
records; missing/corrupt committed evidence is a hard error.

Test hook: if the environment variable ``SEALSTORE_KILL_AT`` matches a
named point, the process kills itself with SIGKILL at that point. This
exists so tests can force-terminate real subprocesses at exact windows.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import sqlite3
from dataclasses import dataclass
from typing import List, Optional, Tuple

_SCHEMA = """
CREATE TABLE IF NOT EXISTS versions (
    appeal_id   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    root_digest TEXT NOT NULL,
    prev_root   TEXT NOT NULL,
    PRIMARY KEY (appeal_id, version)
);
CREATE TABLE IF NOT EXISTS entries (
    appeal_id  TEXT NOT NULL,
    version    INTEGER NOT NULL,
    seq        INTEGER NOT NULL,
    logical_id TEXT NOT NULL,
    etype      TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    size       INTEGER NOT NULL,
    PRIMARY KEY (appeal_id, version, seq)
);
CREATE TABLE IF NOT EXISTS requests (
    request_id  TEXT PRIMARY KEY,
    appeal_id   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    root_digest TEXT NOT NULL
);
"""

_GENESIS_ROOT = "0" * 64
_TMP_PREFIX = ".tmp-"
_KILL_ENV = "SEALSTORE_KILL_AT"


class SealStoreError(Exception):
    """Base error for the seal store."""


class VerifyError(SealStoreError):
    """Raised when verification of a receipt fails."""


class RecoverError(SealStoreError):
    """Raised when recovery finds committed evidence missing or corrupt."""


@dataclass(frozen=True)
class Entry:
    """One evidence item to seal: logical id, type tag, source path."""

    logical_id: str
    etype: str
    source_path: str


@dataclass(frozen=True)
class Receipt:
    """Receipt returned by a successful Seal. Caller keeps it safely."""

    appeal_id: str
    version: int
    root_digest: str

    def to_dict(self) -> dict:
        return {
            "appeal_id": self.appeal_id,
            "version": self.version,
            "root_digest": self.root_digest,
        }

    @staticmethod
    def from_dict(data: dict) -> "Receipt":
        return Receipt(
            appeal_id=data["appeal_id"],
            version=int(data["version"]),
            root_digest=data["root_digest"],
        )


@dataclass(frozen=True)
class ManifestEntry:
    """One verified evidence item inside a version manifest."""

    seq: int
    logical_id: str
    etype: str
    sha256: str
    size: int


class SealStore:
    """Sealing store backed by SQLite + local evidence files."""

    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir
        self.db_path = os.path.join(base_dir, "seal.db")
        self.evidence_dir = os.path.join(base_dir, "evidence")
        os.makedirs(self.evidence_dir, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    @staticmethod
    def _appeal_dir_name(appeal_id: str) -> str:
        return hashlib.sha256(appeal_id.encode("utf-8")).hexdigest()

    def _version_dir(self, appeal_id: str, version: int) -> str:
        return os.path.join(
            self.evidence_dir, self._appeal_dir_name(appeal_id), str(version)
        )

    @staticmethod
    def _maybe_kill(point: str) -> None:
        if os.environ.get(_KILL_ENV) == point:
            os.kill(os.getpid(), signal.SIGKILL)

    @staticmethod
    def _fsync_dir(path: str) -> None:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _feed(hasher, data: bytes) -> None:
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(data)

    @classmethod
    def _root_digest(
        cls,
        appeal_id: str,
        version: int,
        prev_root: str,
        entries: List[Tuple[str, str, str, int]],
    ) -> str:
        hasher = hashlib.sha256()
        cls._feed(hasher, b"SEALSTORE-ROOT-V1")
        cls._feed(hasher, appeal_id.encode("utf-8"))
        cls._feed(hasher, str(version).encode("ascii"))
        cls._feed(hasher, prev_root.encode("ascii"))
        cls._feed(hasher, str(len(entries)).encode("ascii"))
        for logical_id, etype, sha256_hex, size in entries:
            cls._feed(hasher, logical_id.encode("utf-8"))
            cls._feed(hasher, etype.encode("utf-8"))
            cls._feed(hasher, sha256_hex.encode("ascii"))
            cls._feed(hasher, str(size).encode("ascii"))
        return hasher.hexdigest()

    def _copy_evidence_file(self, source_path: str, dest_path: str) -> Tuple[str, int]:
        """Copy source bytes to dest via tmp+rename; return (sha256, size)."""
        tmp_path = os.path.join(
            os.path.dirname(dest_path),
            _TMP_PREFIX + os.path.basename(dest_path) + "-" + str(os.getpid()),
        )
        hasher = hashlib.sha256()
        size = 0
        with open(source_path, "rb") as src, open(tmp_path, "wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                hasher.update(chunk)
                size += len(chunk)
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp_path, dest_path)
        return hasher.hexdigest(), size

    def seal(self, appeal_id: str, request_id: str, entries: List[Entry]) -> Receipt:
        """Seal an ordered group of evidence; return the version receipt.

        Idempotent per ``request_id``: a retry of an already-accepted
        request returns the original receipt without touching anything.
        """
        if not appeal_id:
            raise SealStoreError("appeal_id must be non-empty")
        if not request_id:
            raise SealStoreError("request_id must be non-empty")

        with self._connect() as conn:
            row = conn.execute(
                "SELECT appeal_id, version, root_digest FROM requests "
                "WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is not None:
                return Receipt(appeal_id=row[0], version=row[1], root_digest=row[2])
            row = conn.execute(
                "SELECT MAX(version) FROM versions WHERE appeal_id = ?",
                (appeal_id,),
            ).fetchone()
            version = (row[0] or 0) + 1
            if version > 1:
                prev_root = conn.execute(
                    "SELECT root_digest FROM versions "
                    "WHERE appeal_id = ? AND version = ?",
                    (appeal_id, version - 1),
                ).fetchone()[0]
            else:
                prev_root = _GENESIS_ROOT

        # Stage evidence bytes at their final location before committing.
        version_dir = self._version_dir(appeal_id, version)
        os.makedirs(version_dir, exist_ok=True)
        sealed: List[Tuple[str, str, str, int]] = []
        for seq, entry in enumerate(entries):
            dest_path = os.path.join(version_dir, str(seq))
            sha256_hex, size = self._copy_evidence_file(entry.source_path, dest_path)
            sealed.append((entry.logical_id, entry.etype, sha256_hex, size))
            if seq == 0:
                self._maybe_kill("after_first_file")
        self._fsync_dir(version_dir)
        self._fsync_dir(os.path.dirname(version_dir))
        self._maybe_kill("after_files")

        root_digest = self._root_digest(appeal_id, version, prev_root, sealed)

        # Single atomic acceptance transaction.
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT appeal_id, version, root_digest FROM requests "
                "WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is not None:
                conn.rollback()
                return Receipt(appeal_id=row[0], version=row[1], root_digest=row[2])
            conn.execute(
                "INSERT INTO versions (appeal_id, version, root_digest, prev_root) "
                "VALUES (?, ?, ?, ?)",
                (appeal_id, version, root_digest, prev_root),
            )
            for seq, (logical_id, etype, sha256_hex, size) in enumerate(sealed):
                conn.execute(
                    "INSERT INTO entries "
                    "(appeal_id, version, seq, logical_id, etype, sha256, size) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (appeal_id, version, seq, logical_id, etype, sha256_hex, size),
                )
            conn.execute(
                "INSERT INTO requests (request_id, appeal_id, version, root_digest) "
                "VALUES (?, ?, ?, ?)",
                (request_id, appeal_id, version, root_digest),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        self._maybe_kill("after_commit")
        return Receipt(appeal_id=appeal_id, version=version, root_digest=root_digest)

    def verify(self, receipt: Receipt) -> List[List[ManifestEntry]]:
        """Verify the receipt's version and its full history prefix.

        The receipt is the trust anchor: every version from 1 up to
        ``receipt.version`` is recomputed from stored metadata and the
        actual evidence bytes, the chain linkage is checked, and the
        final recomputed root must equal ``receipt.root_digest``.
        Returns the per-version evidence manifests on success.
        """
        if receipt.version < 1:
            raise VerifyError("receipt version must be >= 1")

        with self._connect() as conn:
            version_rows = conn.execute(
                "SELECT version, root_digest, prev_root FROM versions "
                "WHERE appeal_id = ? AND version <= ? ORDER BY version",
                (receipt.appeal_id, receipt.version),
            ).fetchall()
            present = {row[0] for row in version_rows}
            for v in range(1, receipt.version + 1):
                if v not in present:
                    raise VerifyError(
                        "version %d of appeal %r is missing from storage"
                        % (v, receipt.appeal_id)
                    )
            entry_rows = conn.execute(
                "SELECT version, seq, logical_id, etype, sha256, size "
                "FROM entries WHERE appeal_id = ? AND version <= ? "
                "ORDER BY version, seq",
                (receipt.appeal_id, receipt.version),
            ).fetchall()

        entries_by_version: dict = {}
        for version, seq, logical_id, etype, sha256_hex, size in entry_rows:
            entries_by_version.setdefault(version, []).append(
                (seq, logical_id, etype, sha256_hex, size)
            )

        manifests: List[List[ManifestEntry]] = []
        prev_root = _GENESIS_ROOT
        for v in range(1, receipt.version + 1):
            row = next(r for r in version_rows if r[0] == v)
            stored_root, stored_prev = row[1], row[2]
            if stored_prev != prev_root:
                raise VerifyError(
                    "version %d prev_root does not chain to version %d" % (v, v - 1)
                )
            raw_entries = entries_by_version.get(v, [])
            seqs = [e[0] for e in raw_entries]
            if seqs != list(range(len(raw_entries))):
                raise VerifyError("version %d entry sequence is not contiguous" % v)

            version_dir = self._version_dir(receipt.appeal_id, v)
            digest_entries: List[Tuple[str, str, str, int]] = []
            manifest: List[ManifestEntry] = []
            for seq, logical_id, etype, sha256_hex, size in raw_entries:
                path = os.path.join(version_dir, str(seq))
                actual_sha, actual_size = self._hash_file(path, v, seq)
                if actual_sha != sha256_hex or actual_size != size:
                    raise VerifyError(
                        "evidence bytes for version %d entry %d do not match "
                        "the accepted record" % (v, seq)
                    )
                digest_entries.append((logical_id, etype, sha256_hex, size))
                manifest.append(
                    ManifestEntry(
                        seq=seq,
                        logical_id=logical_id,
                        etype=etype,
                        sha256=sha256_hex,
                        size=size,
                    )
                )

            recomputed = self._root_digest(
                receipt.appeal_id, v, prev_root, digest_entries
            )
            if recomputed != stored_root:
                raise VerifyError(
                    "stored root digest of version %d does not match "
                    "recomputation" % v
                )
            prev_root = recomputed
            manifests.append(manifest)

        if prev_root != receipt.root_digest:
            raise VerifyError(
                "receipt root digest does not match the verified chain head; "
                "the receipt does not anchor this stored history"
            )
        return manifests

    def _hash_file(self, path: str, version: int, seq: int) -> Tuple[str, int]:
        try:
            hasher = hashlib.sha256()
            size = 0
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(1 << 20)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    size += len(chunk)
            return hasher.hexdigest(), size
        except OSError as exc:
            raise VerifyError(
                "evidence file for version %d entry %d is unreadable: %s"
                % (version, seq, exc)
            ) from exc

    def recover(self) -> None:
        """Recover from interrupted operations.

        Removes leftover temp files and evidence not referenced by any
        accepted record, then verifies that every accepted record's
        evidence is present and intact. Missing or corrupt committed
        evidence raises RecoverError; records are never deleted or
        rewritten. Safe to re-run after being killed at any point.
        """
        with self._connect() as conn:
            committed = conn.execute(
                "SELECT appeal_id, version, seq, sha256, size FROM entries"
            ).fetchall()

        referenced_dirs = set()
        referenced_files = set()
        for appeal_id, version, seq, _sha, _size in committed:
            appeal_dir = self._appeal_dir_name(appeal_id)
            referenced_dirs.add((appeal_dir, str(version)))
            referenced_files.add((appeal_dir, str(version), str(seq)))

        killed_once = False
        if os.path.isdir(self.evidence_dir):
            for appeal_dir in os.listdir(self.evidence_dir):
                appeal_path = os.path.join(self.evidence_dir, appeal_dir)
                if not os.path.isdir(appeal_path):
                    os.unlink(appeal_path)
                    continue
                for version_name in os.listdir(appeal_path):
                    version_path = os.path.join(appeal_path, version_name)
                    if (appeal_dir, version_name) not in referenced_dirs:
                        shutil.rmtree(version_path, ignore_errors=True)
                        if not killed_once:
                            killed_once = True
                            self._maybe_kill("recover_after_delete")
                        continue
                    for name in os.listdir(version_path):
                        file_path = os.path.join(version_path, name)
                        referenced = (appeal_dir, version_name, name) in referenced_files
                        if name.startswith(_TMP_PREFIX) or not referenced:
                            if os.path.isfile(file_path):
                                os.unlink(file_path)
                                if not killed_once:
                                    killed_once = True
                                    self._maybe_kill("recover_after_delete")
                if not os.listdir(appeal_path):
                    os.rmdir(appeal_path)
        if os.path.isdir(self.evidence_dir):
            self._fsync_dir(self.evidence_dir)

        # Integrity check: committed evidence must be present and intact.
        for appeal_id, version, seq, sha256_hex, size in committed:
            path = os.path.join(
                self._version_dir(appeal_id, version), str(seq)
            )
            try:
                actual_sha, actual_size = self._hash_file(path, version, seq)
            except VerifyError as exc:
                raise RecoverError(str(exc)) from exc
            if actual_sha != sha256_hex or actual_size != size:
                raise RecoverError(
                    "committed evidence for appeal %r version %d entry %d is "
                    "missing or corrupt; refusing to hide it" % (appeal_id, version, seq)
                )
