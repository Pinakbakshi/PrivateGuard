from __future__ import annotations
import json
from pathlib import Path
from mcp.server.fastmcp import FastMCP
from .config import allowed_roots
from .service import scan, sanitize_file as do_sanitize, encrypt_file as do_encrypt
from .audit import verify_audit

mcp = FastMCP("PrivateGuard", instructions=("PrivateGuard is a local privacy gateway. Only use paths inside explicitly configured allowed roots. "
    "Scan and sanitize before exposing file content to an AI. Never return raw secrets. If a tool fails, do not read the file through another tool to bypass the policy."))


def _within_allowed(path: str, *, must_exist: bool = True) -> Path:
    p = Path(path).expanduser().resolve(strict=must_exist)
    roots = allowed_roots()
    if not roots:
        raise PermissionError("MCP filesystem tools are disabled: set PRIVATEGUARD_ALLOWED_ROOTS before starting the server")
    if not any(p == root or root in p.parents for root in roots):
        raise PermissionError("Path is outside configured PrivateGuard allowed roots")
    # Resolve symlinks then validate containment; reject the final symlink explicitly.
    if Path(path).expanduser().is_symlink():
        raise PermissionError("Symlink paths are not allowed")
    return p

@mcp.tool()
def scan_directory(path: str) -> str:
    """Scan an allowed directory; return finding types and redacted locations, never matched values."""
    p = _within_allowed(path)
    if not p.is_dir(): raise ValueError("path must be a directory")
    return json.dumps(scan(p), indent=2)

@mcp.tool()
def sanitize_file(path: str, output_path: str) -> str:
    """Redact detected sensitive patterns into a new output file; preserve the source."""
    src = _within_allowed(path)
    out = _within_allowed(output_path, must_exist=False)
    if not src.is_file(): raise ValueError("source must be a file")
    return json.dumps(do_sanitize(src, out))

@mcp.tool()
def encrypt_file(path: str, output_path: str) -> str:
    """Encrypt an allowed file to a new artifact with a fresh DEK wrapped for recovery."""
    src = _within_allowed(path)
    out = _within_allowed(output_path, must_exist=False)
    if not src.is_file(): raise ValueError("source must be a file")
    return json.dumps(do_encrypt(src, out))

@mcp.tool()
def verify_audit_log() -> str:
    """Verify local audit hash-chain integrity."""
    return json.dumps(verify_audit())

def main() -> None:
    mcp.run(transport="stdio")

if __name__ == "__main__": main()
