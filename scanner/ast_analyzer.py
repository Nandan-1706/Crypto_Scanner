"""
ast_analyzer.py

Detects ACTUAL Python cryptographic API usage by parsing source code into
an Abstract Syntax Tree (AST) and inspecting real function-call nodes.

Why this is more trustworthy than pattern_detector.py:
A regex sees text. An AST sees *structure*. When this module finds
`hashes.SHA256()`, it knows for certain that's a function call in real code -
not a comment, not a string, not a variable named "hashes_SHA256_backup".
That's why every finding here is Confidence.HIGH.

The trade-off: if code is written in an unusual way (e.g. calling through a
renamed alias we don't recognize, or built dynamically via getattr), the AST
analyzer will miss it. That's a known, documented limitation - not a bug we
try to silently work around.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from scanner.models import Confidence, DetectionMethod, RawFinding

# Each entry maps a recognizable call "shape" (matched against the
# dotted/unparsed function expression, e.g. "hashes.SHA256" or
# "rsa.generate_private_key") to (algorithm, purpose).
#
# The regex is anchored loosely (matches anywhere in the dotted path) so
# `cryptography.hazmat.primitives.hashes.SHA256(...)` and a shorter
# `hashes.SHA256(...)` (after `from ... import hashes`) both match.
_CALL_SIGNATURES: list[tuple[re.Pattern, str, str | None]] = [
    (re.compile(r"\brsa\.generate_private_key\b"), "RSA", "key_generation"),
    (re.compile(r"\bec\.generate_private_key\b"), "ECC", "key_generation"),
    (re.compile(r"\bec\.ECDSA\b"), "ECDSA", "signing"),
    (re.compile(r"\bec\.ECDH\b"), "ECDH", "key_exchange"),
    (re.compile(r"\bhashes\.SHA256\b"), "SHA-256", "hashing"),
    (re.compile(r"\bhashes\.SHA1\b"), "SHA-1", "hashing"),
    (re.compile(r"\bhashes\.MD5\b"), "MD5", "hashing"),
    (re.compile(r"\balgorithms\.AES\b"), "AES", "encryption"),
    (re.compile(r"\bhashlib\.md5\b"), "MD5", "hashing"),
    (re.compile(r"\bhashlib\.sha1\b"), "SHA-1", "hashing"),
    (re.compile(r"\bhashlib\.sha256\b"), "SHA-256", "hashing"),
]

# Import statements that indicate cryptography.hazmat usage, even if we
# don't (yet) have a specific call-signature match for everything imported
# from it. This gives partial credit for "this project touches crypto
# internals" without pretending to know exactly what algorithm is used.
_HAZMAT_IMPORT_PATTERN = re.compile(r"^cryptography\.hazmat")


def scan_file(file_path: str | Path) -> list[RawFinding]:
    """
    Parse a single Python file's AST and return high-confidence findings
    for recognized cryptographic API calls and hazmat imports.
    """
    path = Path(file_path)
    findings: list[RawFinding] = []

    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        # A file that can't be parsed (bad syntax, unreadable, etc.) is
        # skipped by this detector - it does not crash the scan. Other
        # detectors (pattern_detector.py) may still find something in it.
        return findings

    source_lines = source.splitlines()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            findings.extend(_check_call(node, path, source_lines))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            findings.extend(_check_import(node, path, source_lines))

    return findings


def _check_call(call_node: ast.Call, path: Path, source_lines: list[str]) -> list[RawFinding]:
    # Only consider calls whose function expression is a "clean" dotted path
    # (e.g. `hashlib.md5`, `rsa.generate_private_key`) - not something like
    # `hashlib.md5(x).hexdigest`, where the func expression itself contains
    # a nested Call. Without this check, ast.unparse() on the outer
    # `.hexdigest()` call would produce text that still *contains* the
    # substring "hashlib.md5" (from the nested call), causing a false
    # second match on the outer call node.
    if not _is_simple_dotted_path(call_node.func):
        return []

    func_repr = _safe_unparse(call_node.func)
    if func_repr is None:
        return []

    for pattern, algorithm, purpose in _CALL_SIGNATURES:
        if pattern.search(func_repr):
            return [RawFinding(
                file_path=str(path),
                line_number=getattr(call_node, "lineno", None),
                algorithm=algorithm,
                detection_method=DetectionMethod.AST_ANALYSIS,
                evidence=_evidence_line(source_lines, getattr(call_node, "lineno", None)),
                confidence=Confidence.HIGH,
                cryptographic_purpose=purpose,
                key_size=_extract_key_size(call_node),
            )]
    return []


def _extract_key_size(call_node: ast.Call) -> int | None:
    """
    Look for a `key_size=<int literal>` keyword argument on the call, e.g.
    rsa.generate_private_key(public_exponent=65537, key_size=2048).

    Only returns a value when it's an explicit integer literal in the code -
    if key_size is passed as a variable (e.g. key_size=MY_KEY_SIZE), we
    return None rather than guessing what that variable holds.
    """
    for kw in call_node.keywords:
        if kw.arg == "key_size" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
            return kw.value.value
    return None


def _check_import(node: ast.Import | ast.ImportFrom, path: Path, source_lines: list[str]) -> list[RawFinding]:
    findings: list[RawFinding] = []

    module_names: list[str] = []
    if isinstance(node, ast.Import):
        module_names = [alias.name for alias in node.names]
    elif isinstance(node, ast.ImportFrom) and node.module:
        module_names = [node.module]

    for module_name in module_names:
        if _HAZMAT_IMPORT_PATTERN.match(module_name):
            findings.append(RawFinding(
                file_path=str(path),
                line_number=getattr(node, "lineno", None),
                algorithm="cryptography.hazmat",
                detection_method=DetectionMethod.AST_ANALYSIS,
                evidence=_evidence_line(source_lines, getattr(node, "lineno", None)),
                confidence=Confidence.HIGH,
                cryptographic_purpose=None,  # we know hazmat is touched, not what for
            ))

    return findings


def _is_simple_dotted_path(node: ast.AST) -> bool:
    """
    True if `node` is purely a dotted name chain, e.g. `hashlib.md5` or
    `cryptography.hazmat.primitives.hashes.SHA256` - built only from Name
    and Attribute nodes. False for anything containing a nested Call,
    Subscript, or other expression (e.g. the func part of `foo().bar`).
    """
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Attribute):
        return _is_simple_dotted_path(node.value)
    return False


def _safe_unparse(node: ast.AST) -> str | None:
    """ast.unparse can theoretically fail on unusual nodes - never let that
    crash the analyzer for one file."""
    try:
        return ast.unparse(node)
    except Exception:
        return None


def _evidence_line(source_lines: list[str], line_number: int | None) -> str:
    """Return the actual source line as evidence, capped in length. Falls
    back to an empty string if the line number is missing or out of range -
    we never guess or fabricate evidence text."""
    if not line_number or line_number < 1 or line_number > len(source_lines):
        return ""
    return source_lines[line_number - 1].strip()[:200]
