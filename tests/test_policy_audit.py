from privateguard.policy import sanitize_text
from privateguard.audit import append_event, verify_audit


def test_sanitization_removes_detected_value():
    original = "Contact person@example.com and password='supersecretvalue123'"
    sanitized, count = sanitize_text(original)
    assert "person@example.com" not in sanitized
    assert "supersecretvalue123" not in sanitized
    assert count >= 2


def test_audit_chain_valid(tmp_path):
    append_event("test", {"status": "ok"})
    append_event("test2", {"count": 2})
    assert verify_audit()["valid"] is True
