"""Signed, append-only audit log for every tool-call decision.

Each entry is chained (prev_hash) and Ed25519-signed, so the audit trail is
tamper-evident -- you can prove after the fact exactly what the agent was
allowed to do and why.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass
class AuditEntry:
    ts: float
    tool: str
    decision: str
    reason: str
    prev_hash: str
    entry_hash: str
    signature: str


class AuditLog:
    def __init__(self, priv: Ed25519PrivateKey | None = None):
        self._priv = priv or Ed25519PrivateKey.generate()
        self._pub: Ed25519PublicKey = self._priv.public_key()
        self._entries: list[AuditEntry] = []

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._pub

    def record(self, tool: str, decision: str, reason: str) -> AuditEntry:
        prev_hash = self._entries[-1].entry_hash if self._entries else ""
        payload = {"ts": time.time(), "tool": tool, "decision": decision, "reason": reason, "prev_hash": prev_hash}
        entry_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        signature = self._priv.sign(entry_hash.encode()).hex()
        entry = AuditEntry(**payload, entry_hash=entry_hash, signature=signature)
        self._entries.append(entry)
        return entry

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def verify_chain(self) -> bool:
        prev = ""
        for e in self._entries:
            payload = {"ts": e.ts, "tool": e.tool, "decision": e.decision, "reason": e.reason, "prev_hash": prev}
            expected = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
            if expected != e.entry_hash:
                return False
            try:
                self._pub.verify(bytes.fromhex(e.signature), e.entry_hash.encode())
            except InvalidSignature:
                return False
            prev = e.entry_hash
        return True

    def to_json(self) -> str:
        return json.dumps([asdict(e) for e in self._entries], indent=2)
