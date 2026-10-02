"""Appeal evidence sealing store.

SQLite holds acceptance records; local files hold evidence bytes.
"""

from .store import (
    Entry,
    ManifestEntry,
    Receipt,
    RecoverError,
    SealStore,
    SealStoreError,
    VerifyError,
)

__all__ = [
    "Entry",
    "ManifestEntry",
    "Receipt",
    "RecoverError",
    "SealStore",
    "SealStoreError",
    "VerifyError",
]
