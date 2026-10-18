from pathlib import Path
from privateguard.service import encrypt_file, decrypt_file, sanitize_file


def test_file_roundtrip_and_no_overwrite(tmp_path):
    source = tmp_path / "source.txt"; source.write_text("token=supersecretvalue123")
    encrypted = tmp_path / "artifact.pga"
    result = encrypt_file(source, encrypted)
    assert result["recoverable"]
    output = tmp_path / "recovered.txt"
    decrypt_file(encrypted, output)
    assert output.read_text() == source.read_text()
    try:
        encrypt_file(source, encrypted)
        assert False, "expected no-overwrite protection"
    except FileExistsError:
        pass


def test_sanitize_preserves_source(tmp_path):
    source = tmp_path / "source.txt"; original = "email person@example.com"
    source.write_text(original)
    out = tmp_path / "safe.txt"
    result = sanitize_file(source, out)
    assert source.read_text() == original
    assert "person@example.com" not in out.read_text()
    assert result["source_preserved"]
