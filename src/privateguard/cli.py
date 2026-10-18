from __future__ import annotations
import argparse, json
from pathlib import Path
from .crypto_service import initialize
from .service import scan, sanitize_file, encrypt_file, decrypt_file
from .audit import verify_audit


def main() -> None:
    parser = argparse.ArgumentParser(prog="privateguard")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    p = sub.add_parser("scan"); p.add_argument("path"); p.add_argument("--json", action="store_true")
    p = sub.add_parser("sanitize"); p.add_argument("source"); p.add_argument("--output", required=True)
    p = sub.add_parser("encrypt"); p.add_argument("source"); p.add_argument("--output", required=True)
    p = sub.add_parser("decrypt"); p.add_argument("source"); p.add_argument("--output", required=True)
    sub.add_parser("verify-audit")
    args = parser.parse_args()
    if args.command == "init": result = {"home": str(initialize()), "master_key_created_or_present": True}
    elif args.command == "scan": result = scan(args.path)
    elif args.command == "sanitize": result = sanitize_file(args.source, args.output)
    elif args.command == "encrypt": result = encrypt_file(args.source, args.output)
    elif args.command == "decrypt": result = decrypt_file(args.source, args.output)
    else: result = verify_audit()
    print(json.dumps(result, indent=2, default=str))
    if args.command == "scan" and args.json:
        return
