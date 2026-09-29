from pathlib import Path

from scanner import ast_analyzer, pattern_detector

LEGACY_FILE = Path(__file__).parent.parent / "sample_project" / "legacy_examples.py"


def test_pattern_detector_finds_all_new_algorithms():
    findings = pattern_detector.scan_file(LEGACY_FILE)
    algorithms_found = {f.algorithm for f in findings}
    for expected in ("DES", "3DES", "DSA", "DH", "SHA-224", "SHA-384", "SHA-512", "pycryptodome_library"):
        assert expected in algorithms_found, f"expected {expected} in pattern findings"


def test_des_and_3des_pattern_matches_are_distinct():
    """A line with 'algorithms.TripleDES' must match 3DES, not bare DES; a
    line with 'algorithms.DES' must match DES, not 3DES."""
    findings = pattern_detector.scan_file(LEGACY_FILE)
    by_line: dict[int, set[str]] = {}
    for f in findings:
        by_line.setdefault(f.line_number, set()).add(f.algorithm)

    triple_des_lines = [ln for ln, algos in by_line.items() if "3DES" in algos and "DES" not in algos]
    des_only_lines = [ln for ln, algos in by_line.items() if "DES" in algos and "3DES" not in algos]
    assert triple_des_lines, "expected at least one line matching 3DES but not DES"
    assert des_only_lines, "expected at least one line matching DES but not 3DES"


def test_ast_analyzer_detects_dsa_key_generation_with_key_size():
    findings = ast_analyzer.scan_file(LEGACY_FILE)
    dsa_findings = [f for f in findings if f.algorithm == "DSA"]
    assert dsa_findings
    assert dsa_findings[0].key_size == 2048
    assert dsa_findings[0].cryptographic_purpose == "key_generation"


def test_ast_analyzer_detects_dh_key_exchange_with_key_size():
    findings = ast_analyzer.scan_file(LEGACY_FILE)
    dh_findings = [f for f in findings if f.algorithm == "DH"]
    assert dh_findings
    assert dh_findings[0].key_size == 2048
    assert dh_findings[0].cryptographic_purpose == "key_exchange"


def test_ast_analyzer_detects_sha2_variants():
    findings = ast_analyzer.scan_file(LEGACY_FILE)
    algorithms_found = {f.algorithm for f in findings}
    for expected in ("SHA-224", "SHA-384", "SHA-512"):
        assert expected in algorithms_found


def test_ast_analyzer_detects_pycryptodome_import():
    findings = ast_analyzer.scan_file(LEGACY_FILE)
    assert any(f.algorithm == "pycryptodome_library" for f in findings)


def test_no_false_positives_still_holds_on_crypto_free_file():
    """Regression check: expanding the pattern/AST tables must not cause
    false positives on the existing crypto-free sample file."""
    no_crypto = Path(__file__).parent.parent / "sample_project" / "no_crypto.py"
    assert pattern_detector.scan_file(no_crypto) == []
    assert ast_analyzer.scan_file(no_crypto) == []
