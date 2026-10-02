"""Subprocess worker used by crash-window tests.

Usage:
    python -m tests.worker <base_dir> seal <appeal_id> <request_id> <spec.json>
    python -m tests.worker <base_dir> recover

The kill point is selected with the SEALSTORE_KILL_AT environment
variable; the store kills itself with SIGKILL at the matching point.
On a successful seal the receipt JSON is printed to stdout.
"""

import json
import sys

from sealstore import Entry, Receipt, SealStore


def main(argv) -> int:
    base_dir = argv[1]
    command = argv[2]
    store = SealStore(base_dir)
    if command == "seal":
        appeal_id, request_id, spec_path = argv[3], argv[4], argv[5]
        with open(spec_path, "r", encoding="utf-8") as handle:
            spec = json.load(handle)
        entries = [
            Entry(logical_id=e["logical_id"], etype=e["etype"],
                  source_path=e["source_path"])
            for e in spec
        ]
        receipt = store.seal(appeal_id, request_id, entries)
        print(json.dumps(receipt.to_dict()), flush=True)
        return 0
    if command == "recover":
        store.recover()
        print("recovered", flush=True)
        return 0
    raise SystemExit("unknown command: %s" % command)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
