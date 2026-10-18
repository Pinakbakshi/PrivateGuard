from __future__ import annotations
import os
from pathlib import Path


def home_dir() -> Path:
    return Path(os.environ.get("PRIVATEGUARD_HOME", "~/.privateguard")).expanduser().resolve()


def allowed_roots() -> list[Path]:
    raw = os.environ.get("PRIVATEGUARD_ALLOWED_ROOTS", "")
    roots = []
    for part in raw.split(os.pathsep):
        if part.strip():
            roots.append(Path(part.strip()).expanduser().resolve())
    return roots


def ensure_home() -> Path:
    path = home_dir()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    (path / "artifacts").mkdir(mode=0o700, exist_ok=True)
    return path
