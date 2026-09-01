from pathlib import Path

from scanner import pattern_detector
from scanner.models import Confidence

SAMPLE_PROJECT = Path(__file__).parent.parent / "sample_project"


def test_detects_md5_keyword_in_weak_examples():
    findings = pattern_detector.scan_file(SAMPLE_PROJECT / "weak_examples.py")
    algorithms_found = {f.algorithm for f in findings}
    assert "MD5" in algorithms_found


def test_detects_hashlib_usage():
    findings = pattern_detector.scan_file(SAMPLE_PROJECT / "weak_examples.py")
    algorithms_found = {f.algorithm for f in findings}
    assert "hashlib" in algorithms_found


def test_no_findings_in_crypto_free_file():
    findings = pattern_detector.scan_file(SAMPLE_PROJECT / "no_crypto.py")
    assert findings == []


def test_findings_have_low_or_medium_confidence_only():
    findings = pattern_detector.scan_file(SAMPLE_PROJECT / "modern_examples.py")
    assert findings, "expected at least one pattern match in modern_examples.py"
    for f in findings:
        assert f.confidence in (Confidence.LOW, Confidence.MEDIUM)


def test_evidence_is_the_actual_matched_line():
    findings = pattern_detector.scan_file(SAMPLE_PROJECT / "weak_examples.py")
    md5_findings = [f for f in findings if f.algorithm == "MD5"]
    assert md5_findings
    # The evidence should be real source text, not a placeholder.
    assert any("md5" in f.evidence.lower() for f in md5_findings)
