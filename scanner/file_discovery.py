"""
file_discovery.py

Responsible for ONE thing: walking a project directory and returning a list
of file paths that are safe and worth scanning.

It does NOT read file contents for crypto patterns (that's pattern_detector.py
and ast_analyzer.py's job) - it only decides WHICH files should be handed to
those modules.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Directories we never want to walk into. These are either huge (node_modules),
# irrelevant to source analysis (.git), or generated/cache files (__pycache__).
IGNORED_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "dist",
    "build",
    "site-packages",
}

# File extensions/names that could contain private key material.
# We actively refuse to scan these - not even to look at "safe" parts of them.
SENSITIVE_FILE_PATTERNS = {
    ".pem",   # could be a private key OR a cert - excluded entirely for now,
              # deliberately conservative until a dedicated, careful cert
              # module (with private-key detection/avoidance) is built later
    ".key",
    ".pfx",
    ".p12",
}

# For Phase 1, we only scan Python source files.
SUPPORTED_EXTENSIONS = {".py"}

# Don't try to read absurdly large files - a 500MB "file" is much more likely
# to be a data blob than source code, and reading it could stall the scanner.
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB


@dataclass
class DiscoveredFile:
    """A file the scanner has decided is safe and relevant to analyze."""
    path: Path
    size_bytes: int


@dataclass
class DiscoverySkip:
    """A file or directory we deliberately did NOT scan, and why.

    This matters for transparency: the tool should always be able to explain
    what it did *not* look at, not just what it found.
    """
    path: Path
    reason: str


def discover_files(project_path: str | Path) -> tuple[list[DiscoveredFile], list[DiscoverySkip]]:
    """
    Recursively find files under `project_path` that are safe to scan.

    Returns a tuple of:
      - list of DiscoveredFile (files we will scan)
      - list of DiscoverySkip (files/dirs we deliberately skipped, with reasons)

    We return skips too (not just discovered files) because a security tool
    should be able to say "here is what I looked at, and here is what I
    intentionally did not touch and why" - that's part of being trustworthy.
    """
    root = Path(project_path).resolve()

    if not root.exists():
        raise FileNotFoundError(f"Project path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Project path is not a directory: {root}")

    discovered: list[DiscoveredFile] = []
    skipped: list[DiscoverySkip] = []

    for current_dir, dir_names, file_names in _safe_walk(root):
        # Prune ignored directories *in place* so os.walk-style traversal
        # never descends into them at all (not just skips reporting them).
        pruned = [d for d in dir_names if d in IGNORED_DIR_NAMES]
        dir_names[:] = [d for d in dir_names if d not in IGNORED_DIR_NAMES]
        for d in pruned:
            skipped.append(DiscoverySkip(
                path=current_dir / d,
                reason="ignored directory (build/venv/vcs/cache)",
            ))

        for name in file_names:
            file_path = current_dir / name
            suffix = file_path.suffix.lower()

            if suffix in SENSITIVE_FILE_PATTERNS:
                skipped.append(DiscoverySkip(
                    path=file_path,
                    reason="potentially sensitive key/cert material - excluded from Phase 1 scope",
                ))
                continue

            if suffix not in SUPPORTED_EXTENSIONS:
                skipped.append(DiscoverySkip(
                    path=file_path,
                    reason=f"unsupported extension '{suffix or '(none)'}' (Phase 1 scans Python only)",
                ))
                continue

            try:
                size = file_path.stat().st_size
            except OSError as exc:
                skipped.append(DiscoverySkip(path=file_path, reason=f"could not stat file: {exc}"))
                continue

            if size > MAX_FILE_SIZE_BYTES:
                skipped.append(DiscoverySkip(
                    path=file_path,
                    reason=f"file too large ({size} bytes > {MAX_FILE_SIZE_BYTES} byte limit)",
                ))
                continue

            if not _is_readable_text_file(file_path):
                skipped.append(DiscoverySkip(path=file_path, reason="unreadable or not valid text"))
                continue

            discovered.append(DiscoveredFile(path=file_path, size_bytes=size))

    return discovered, skipped


def _safe_walk(root: Path):
    """
    A thin wrapper around os.walk that yields (Path, dir_names, file_names)
    instead of raw strings, and never raises on a single unreadable directory
    (it just skips that directory rather than crashing the whole scan).
    """
    import os

    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        yield Path(dirpath), dirnames, filenames


def _is_readable_text_file(path: Path) -> bool:
    """
    Confirm we can actually open and read the file as UTF-8 text.
    Returns False (rather than raising) for permission errors, broken
    symlinks, or files that aren't valid text - the scanner should degrade
    gracefully, not crash, when it meets a file it can't handle.
    """
    try:
        with path.open("r", encoding="utf-8") as f:
            f.read(1)  # touch the file to confirm it's really readable text
        return True
    except (OSError, UnicodeDecodeError):
        return False
