import os
import pytest
from pathlib import Path

@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRIVATEGUARD_HOME", str(tmp_path / "pg-home"))
    monkeypatch.setenv("PRIVATEGUARD_ALLOWED_ROOTS", str(tmp_path))
