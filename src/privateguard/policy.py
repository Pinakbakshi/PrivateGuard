from __future__ import annotations
from .scanner import PATTERNS


def sanitize_text(text: str) -> tuple[str, int]:
    """Redact detected patterns in a copy; never mutates the source file."""
    count = 0
    # Replace longer matches first so nested patterns do not leave partial values.
    matches = []
    for rule, severity, pattern in PATTERNS:
        for match in pattern.finditer(text):
            matches.append((match.start(), match.end()))
    matches.sort()
    merged = []
    for start, end in matches:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    for start, end in reversed(merged):
        text = text[:start] + "[REDACTED]" + text[end:]
        count += 1
    return text, count
