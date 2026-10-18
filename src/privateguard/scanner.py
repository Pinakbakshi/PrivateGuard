from __future__ import annotations
import math, re
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".privateguard"}
PATTERNS = [
    ("private_key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws_access_key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("generic_secret_assignment", "high", re.compile(r"(?i)\b(api[_-]?key|client_secret|password|passwd|access_token|secret_key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+\-=]{8,})")),
    ("email", "medium", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone_like", "low", re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{8,}\d)(?!\w)")),
    ("payment_card_candidate", "high", re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")),
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def inspect_text(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rule, severity, pattern in PATTERNS:
        for match in pattern.finditer(text):
            start = match.start()
            line = text.count("\n", 0, start) + 1
            findings.append({"rule_id": rule, "severity": severity, "line": line, "start": start, "end": match.end(), "sample": "[REDACTED]"})
    # High-entropy long tokens are suspicious, not proof of a secret.
    for line_no, line in enumerate(text.splitlines(), 1):
        for token in re.findall(r"[A-Za-z0-9_+/=-]{32,}", line):
            if _entropy(token) >= 4.3 and not any(f["line"] == line_no and f["rule_id"] in {"github_token", "aws_access_key"} for f in findings):
                findings.append({"rule_id": "high_entropy_token_candidate", "severity": "medium", "line": line_no, "start": 0, "end": 0, "sample": "[REDACTED]"})
    # De-duplicate same rule/line/location.
    unique = {(f["rule_id"], f["line"], f["start"], f["end"]): f for f in findings}
    return sorted(unique.values(), key=lambda f: (f["line"], f["start"], f["rule_id"]))


def scan_directory(root: str | Path, *, max_file_bytes: int = MAX_FILE_BYTES) -> dict[str, Any]:
    base = Path(root).expanduser().resolve(strict=True)
    if not base.is_dir():
        raise ValueError("scan_directory requires an existing directory")
    records, errors = [], []
    for path in base.rglob("*"):
        try:
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_symlink():
                errors.append({"path": str(path.relative_to(base)), "status": "skipped_symlink"})
                continue
            if not path.is_file():
                continue
            rel = str(path.relative_to(base))
            size = path.stat().st_size
            if size > max_file_bytes:
                records.append({"path": rel, "status": "skipped_too_large", "size_bytes": size, "findings": []})
                continue
            raw = path.read_bytes()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                records.append({"path": rel, "status": "uninspected_binary", "size_bytes": size, "findings": []})
                continue
            findings = inspect_text(text)
            records.append({"path": rel, "status": "scanned", "size_bytes": size, "findings": findings, "severity_counts": {s: sum(f["severity"] == s for f in findings) for s in ("critical", "high", "medium", "low")}})
        except (OSError, ValueError) as exc:
            errors.append({"path": str(path), "status": "error", "error_type": type(exc).__name__})
    return {"root": str(base), "files_seen": len(records) + len(errors), "files_scanned": sum(r["status"] == "scanned" for r in records), "files_with_findings": sum(bool(r.get("findings")) for r in records), "records": records, "errors": errors}
