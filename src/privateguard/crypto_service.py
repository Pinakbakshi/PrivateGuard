from __future__ import annotations
import base64, json, os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .config import ensure_home, home_dir

MAGIC = b"PGAR1\n"


def _master_key(create: bool = True) -> bytes:
    home = ensure_home() if create else home_dir()
    path = home / "master.key"
    if not path.exists():
        if not create:
            raise FileNotFoundError("PrivateGuard master key is missing; encrypted artifacts cannot be recovered")
        key = AESGCM.generate_key(bit_length=256)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return key
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("Master key file is invalid; expected 32 bytes")
    return key


def initialize() -> Path:
    ensure_home()
    _master_key(create=True)
    return home_dir()


def encrypt_bytes(plaintext: bytes, *, operation_id: str) -> bytes:
    """Encrypt with a fresh DEK; wrap that DEK using the local master key."""
    dek = AESGCM.generate_key(bit_length=256)
    data_nonce = os.urandom(12)
    wrap_nonce = os.urandom(12)
    aad = operation_id.encode("utf-8")
    ciphertext = AESGCM(dek).encrypt(data_nonce, plaintext, aad)
    wrapped_dek = AESGCM(_master_key()).encrypt(wrap_nonce, dek, aad)
    envelope = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "operation_id": operation_id,
        "data_nonce": base64.b64encode(data_nonce).decode(),
        "wrap_nonce": base64.b64encode(wrap_nonce).decode(),
        "wrapped_dek": base64.b64encode(wrapped_dek).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    # JSON envelope is for a prototype; large-file streaming support is a future hardening task.
    return MAGIC + json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def decrypt_bytes(blob: bytes) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("Not a PrivateGuard artifact")
    envelope = json.loads(blob[len(MAGIC):].decode("utf-8"))
    if envelope.get("version") != 1 or envelope.get("algorithm") != "AES-256-GCM":
        raise ValueError("Unsupported artifact format")
    aad = envelope["operation_id"].encode("utf-8")
    dek = AESGCM(_master_key(create=False)).decrypt(base64.b64decode(envelope["wrap_nonce"]), base64.b64decode(envelope["wrapped_dek"]), aad)
    return AESGCM(dek).decrypt(base64.b64decode(envelope["data_nonce"]), base64.b64decode(envelope["ciphertext"]), aad)
