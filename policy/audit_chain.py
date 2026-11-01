"""Hash-chained audit records.

The chain detects tampering of stored rows. It is not cryptographic immutability:
anyone who can rewrite the database and the trust anchor can rebuild the chain.
"""

from __future__ import annotations

import hashlib
import json

GENESIS = "0" * 64


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def link(prev_hash: str, payload: dict) -> str:
    material = f"{prev_hash}\n{canonical(payload)}".encode()
    return hashlib.sha256(material).hexdigest()


def verify(rows: list[dict]) -> dict:
    prev = GENESIS
    for index, row in enumerate(rows):
        payload = row["payload"]
        expected = link(prev, payload)
        if row.get("prev_hash") != prev or row.get("row_hash") != expected:
            return {"valid": False, "broken_at": index, "expected": expected, "prev": prev}
        prev = expected
    return {"valid": True, "length": len(rows), "head": prev}
