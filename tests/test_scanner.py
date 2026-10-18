from privateguard.scanner import inspect_text, scan_directory


def test_detects_synthetic_patterns():
    findings = inspect_text("email: person@example.com\npassword = 'verysecretvalue123'\nAKIA1234567890ABCDEF")
    rules = {f["rule_id"] for f in findings}
    assert "email" in rules
    assert "generic_secret_assignment" in rules
    assert "aws_access_key" in rules
    assert all(f["sample"] == "[REDACTED]" for f in findings)


def test_skips_symlink_and_binary(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    (root / "text.txt").write_text("person@example.com")
    (root / "binary.bin").write_bytes(b"\xff\xfe\xfd")
    outside = tmp_path / "outside.txt"; outside.write_text("password=secretvalue123")
    try: (root / "link.txt").symlink_to(outside)
    except OSError: pass
    result = scan_directory(root)
    assert any(r["status"] == "uninspected_binary" for r in result["records"])
    assert result["files_with_findings"] == 1
