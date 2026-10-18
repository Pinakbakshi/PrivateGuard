from __future__ import annotations
import hashlib, json, secrets
from pathlib import Path
from .audit import append_event, verify_audit
from .crypto_service import encrypt_bytes, decrypt_bytes, initialize
from .policy import sanitize_text
from .scanner import scan_directory


def scan(root: str | Path) -> dict:
    report = scan_directory(root)
    summary = {k: report[k] for k in ("root", "files_seen", "files_scanned", "files_with_findings")}
    append_event("directory_scan", summary)
    return report


def sanitize_file(source: str | Path, output: str | Path) -> dict:
    src = Path(source).expanduser().resolve(strict=True)
    if not src.is_file() or src.is_symlink():
        raise ValueError("Source must be a regular file")
    text = src.read_text(encoding="utf-8")
    sanitized, count = sanitize_text(text)
    dest = Path(output).expanduser().resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest == src:
        raise ValueError("Output must not overwrite the source")
    if dest.exists():
        raise FileExistsError("Output exists; choose a new path to avoid overwriting")
    dest.write_text(sanitized, encoding="utf-8")
    append_event("sanitize_file", {"source_name": src.name, "output_name": dest.name, "redaction_count": count, "output_sha256": hashlib.sha256(sanitized.encode()).hexdigest()})
    return {"output": str(dest), "redactions": count, "source_preserved": True}


def encrypt_file(source: str | Path, output: str | Path) -> dict:
    src = Path(source).expanduser().resolve(strict=True)
    if not src.is_file() or src.is_symlink():
        raise ValueError("Source must be a regular file")
    dest = Path(output).expanduser().resolve()
    if dest == src:
        raise ValueError("Output must not overwrite the source")
    if dest.exists():
        raise FileExistsError("Output exists; choose a new path to avoid overwriting")
    dest.parent.mkdir(parents=True, exist_ok=True)
    op_id = secrets.token_hex(16)
    blob = encrypt_bytes(src.read_bytes(), operation_id=op_id)
    # Exclusive creation prevents accidental overwrite.
    with dest.open("xb") as f:
        f.write(blob)
    append_event("encrypt_file", {"operation_id": op_id, "source_name": src.name, "artifact_name": dest.name, "ciphertext_sha256": hashlib.sha256(blob).hexdigest(), "algorithm": "AES-256-GCM"})
    return {"output": str(dest), "operation_id": op_id, "algorithm": "AES-256-GCM", "recoverable": True}


def decrypt_file(source: str | Path, output: str | Path) -> dict:
    src = Path(source).expanduser().resolve(strict=True)
    dest = Path(output).expanduser().resolve()
    if dest.exists():
        raise FileExistsError("Output exists; choose a new path to avoid overwriting")
    dest.parent.mkdir(parents=True, exist_ok=True)
    plaintext = decrypt_bytes(src.read_bytes())
    with dest.open("xb") as f:
        f.write(plaintext)
    append_event("decrypt_file", {"artifact_name": src.name, "output_name": dest.name, "output_sha256": hashlib.sha256(plaintext).hexdigest()})
    return {"output": str(dest), "verified": True}
