"""
pattern_detector.py

Detects cryptographic *indicators* in raw source text using simple, explicit
regex patterns. This is intentionally the "naive but fast" detector:

- It does NOT understand Python syntax.
- It CANNOT tell the difference between real code, a comment, and a string.
- Its findings are LOW or MEDIUM confidence, never HIGH.

Its value is in catching things AST analysis might miss (e.g. algorithm
names in config files, comments flagging deprecated crypto, or code written
in a style the AST analyzer doesn't specifically pattern-match).

ast_analyzer.py is the module responsible for higher-confidence findings.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models import Confidence, DetectionMethod, RawFinding

# Each entry: (algorithm label, compiled regex, confidence)
#
# Patterns are deliberately word-bounded (\b) so "RSA" doesn't match inside
# an unrelated word like "RSAWorkshop2024". They are still just text
# matches, so a comment saying "# TODO: remove RSA usage" WILL match - the
# evidence field exists precisely so a human (or the future risk engine)
# can see the actual line and judge for themselves.
_PATTERNS: list[tuple[str, re.Pattern, Confidence]] = [
    ("RSA", re.compile(r"\bRSA\b"), Confidence.LOW),
    ("AES", re.compile(r"\bAES\b"), Confidence.LOW),
    ("ECC", re.compile(r"\bECC\b"), Confidence.LOW),
    ("ECDSA", re.compile(r"\bECDSA\b"), Confidence.LOW),
    ("ECDH", re.compile(r"\bECDH\b"), Confidence.LOW),
    ("SHA-256", re.compile(r"\bSHA-?256\b", re.IGNORECASE), Confidence.LOW),
    ("SHA-1", re.compile(r"\bSHA-?1\b", re.IGNORECASE), Confidence.LOW),
    ("MD5", re.compile(r"\bMD5\b", re.IGNORECASE), Confidence.LOW),
    # These two are more specific substrings (an actual import/attribute
    # access pattern), so they earn MEDIUM confidence instead of LOW.
    ("cryptography_library", re.compile(r"\bfrom\s+cryptography\b|\bimport\s+cryptography\b"), Confidence.MEDIUM),
    ("hashlib", re.compile(r"\bhashlib\.\w+"), Confidence.MEDIUM),
]


def scan_file(file_path: str | Path) -> list[RawFinding]:
    """
    Scan a single file's text for cryptographic keyword patterns.
    Returns one RawFinding per matched pattern per line (deduplicated so a
    pattern matching twice on the same line only produces one finding).
    """
    path = Path(file_path)
    findings: list[RawFinding] = []

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # file_discovery.py should have already filtered these out, but we
        # never assume - a detector should never crash the whole scan
        # because one file turned out to be unreadable.
        return findings

    lines = text.splitlines()
    seen_on_line: set[tuple[int, str]] = set()

    for line_number, line in enumerate(lines, start=1):
        for algorithm, pattern, confidence in _PATTERNS:
            if pattern.search(line) and (line_number, algorithm) not in seen_on_line:
                seen_on_line.add((line_number, algorithm))
                findings.append(RawFinding(
                    file_path=str(path),
                    line_number=line_number,
                    algorithm=algorithm,
                    detection_method=DetectionMethod.PATTERN_MATCH,
                    evidence=line.strip()[:200],  # cap length - never dump huge lines
                    confidence=confidence,
                ))

    return findings
