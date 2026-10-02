"""Child-process helper for the crash-window tests.

Runs a single store operation in a fresh process so the test-suite can
forcibly kill it (SIGKILL) at instrumented points via SEAL_CRASH_AT.
This file is a test helper, not part of the library.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from evidence_seal import EntryInput, SealStore


def main() -> None:
    mode, store, src = sys.argv[1], sys.argv[2], sys.argv[3]
    crash = sys.argv[4] if len(sys.argv) > 4 else ""
    if crash:
        os.environ["SEAL_CRASH_AT"] = crash
    store_obj = SealStore(store)
    if mode == "seal-v2":
        store_obj.seal("appeal-1", "req-v2", [
            EntryInput("img2", "image", os.path.join(src, "b.png")),
            EntryInput("chat2", "chat", os.path.join(src, "chat.txt")),
            EntryInput("pay2", "payment", os.path.join(src, "pay.txt")),
        ])
    elif mode == "recover":
        store_obj.recover()
    else:
        raise SystemExit(f"unknown mode: {mode}")
    store_obj.close()


if __name__ == "__main__":
    main()
