from __future__ import annotations
import hashlib, json, os, secrets, time
from pathlib import Path
from .config import ensure_home

ZERO = "0" * 64


def _path() -> Path:
    return ensure_home() / "audit.jsonl"


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def append_event(event_type: str, details: dict) -> dict:
    path = _path()
    previous = ZERO
    if path.exists():
        rows = path.read_text(encoding="utf-8").splitlines()
        if rows:
            previous = json.loads(rows[-1])["event_hash"]
    event = {"event_id": secrets.token_hex(16), "timestamp": int(time.time()), "event_type": event_type, "details": details, "previous_hash": previous}
    event["event_hash"] = hashlib.sha256(_canonical(event)).hexdigest()
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return event


def verify_audit() -> dict:
    path = _path()
    if not path.exists():
        return {"valid": True, "events": 0, "message": "No audit events yet"}
    previous = ZERO
    rows = path.read_text(encoding="utf-8").splitlines()
    for index, row in enumerate(rows):
        event = json.loads(row)
        actual = event.get("event_hash")
        body = {k: v for k, v in event.items() if k != "event_hash"}
        if body.get("previous_hash") != previous or hashlib.sha256(_canonical(body)).hexdigest() != actual:
            return {"valid": False, "events": len(rows), "failed_index": index}
        previous = actual
    return {"valid": True, "events": len(rows), "head": previous}


def commitment(event_hash: str) -> tuple[str, str]:
    """Create a salted commitment; retain the salt locally for future proof verification."""
    salt = secrets.token_bytes(32)
    digest = hashlib.sha256(salt + bytes.fromhex(event_hash)).hexdigest()
    return digest, salt.hex()
