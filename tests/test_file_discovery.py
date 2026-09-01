import tempfile
from pathlib import Path

import pytest

from scanner import file_discovery

SAMPLE_PROJECT = Path(__file__).parent.parent / "sample_project"


def test_discovers_python_files_in_sample_project():
    discovered, skipped = file_discovery.discover_files(SAMPLE_PROJECT)
    discovered_names = {f.path.name for f in discovered}

    assert "weak_examples.py" in discovered_names
    assert "modern_examples.py" in discovered_names
    assert "no_crypto.py" in discovered_names


def test_ignores_venv_and_git_directories():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".venv").mkdir()
        (root / ".venv" / "should_not_be_found.py").write_text("import os")
        (root / ".git").mkdir()
        (root / ".git" / "config").write_text("not python")
        (root / "real_code.py").write_text("import os")

        discovered, skipped = file_discovery.discover_files(root)
        discovered_names = {f.path.name for f in discovered}

        assert "real_code.py" in discovered_names
        assert "should_not_be_found.py" not in discovered_names


def test_excludes_sensitive_key_extensions():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "private.key").write_text("fake key content, not a real key")
        (root / "cert.pem").write_text("fake cert content, not a real cert")
        (root / "app.py").write_text("import os")

        discovered, skipped = file_discovery.discover_files(root)
        discovered_names = {f.path.name for f in discovered}
        skipped_names = {s.path.name for s in skipped}

        assert "private.key" not in discovered_names
        assert "cert.pem" not in discovered_names
        assert "app.py" in discovered_names
        assert "private.key" in skipped_names
        assert "cert.pem" in skipped_names


def test_raises_on_missing_directory():
    with pytest.raises(FileNotFoundError):
        file_discovery.discover_files("/this/path/does/not/exist/at/all")


def test_skips_oversized_files():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        big_file = root / "huge.py"
        # Write more than MAX_FILE_SIZE_BYTES worth of content.
        big_file.write_text("x = 1\n" * (file_discovery.MAX_FILE_SIZE_BYTES // 4))

        discovered, skipped = file_discovery.discover_files(root)
        discovered_names = {f.path.name for f in discovered}

        assert "huge.py" not in discovered_names
        assert any(s.path.name == "huge.py" for s in skipped)
