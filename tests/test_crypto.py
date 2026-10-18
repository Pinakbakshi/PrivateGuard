import pytest
from cryptography.exceptions import InvalidTag
from privateguard.crypto_service import encrypt_bytes, decrypt_bytes


def test_round_trip():
    data = b"synthetic secret: test-token-123456789"
    blob = encrypt_bytes(data, operation_id="op-1")
    assert blob != data
    assert decrypt_bytes(blob) == data


def test_each_operation_uses_distinct_envelope():
    a = encrypt_bytes(b"same", operation_id="op-a")
    b = encrypt_bytes(b"same", operation_id="op-b")
    assert a != b


def test_tamper_rejected():
    blob = bytearray(encrypt_bytes(b"private", operation_id="op-x"))
    blob[-3] ^= 1
    with pytest.raises((InvalidTag, ValueError, Exception)):
        decrypt_bytes(bytes(blob))
