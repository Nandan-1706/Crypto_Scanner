from pathlib import Path

from scanner import ast_analyzer
from scanner.models import Confidence, DetectionMethod

SAMPLE_PROJECT = Path(__file__).parent.parent / "sample_project"


def test_detects_rsa_key_generation_with_key_size():
    findings = ast_analyzer.scan_file(SAMPLE_PROJECT / "weak_examples.py")
    rsa_findings = [f for f in findings if f.algorithm == "RSA"]
    assert rsa_findings
    assert rsa_findings[0].key_size == 1024
    assert rsa_findings[0].cryptographic_purpose == "key_generation"


def test_detects_modern_rsa_key_size_separately():
    findings = ast_analyzer.scan_file(SAMPLE_PROJECT / "modern_examples.py")
    rsa_findings = [f for f in findings if f.algorithm == "RSA"]
    assert rsa_findings
    assert rsa_findings[0].key_size == 3072


def test_all_findings_are_high_confidence_ast():
    findings = ast_analyzer.scan_file(SAMPLE_PROJECT / "weak_examples.py")
    assert findings, "expected at least one AST finding in weak_examples.py"
    for f in findings:
        assert f.confidence == Confidence.HIGH
        assert f.detection_method == DetectionMethod.AST_ANALYSIS


def test_detects_ec_key_generation():
    findings = ast_analyzer.scan_file(SAMPLE_PROJECT / "modern_examples.py")
    algorithms_found = {f.algorithm for f in findings}
    assert "ECC" in algorithms_found


def test_no_findings_in_crypto_free_file():
    findings = ast_analyzer.scan_file(SAMPLE_PROJECT / "no_crypto.py")
    assert findings == []


def test_handles_syntax_error_gracefully(tmp_path):
    broken_file = tmp_path / "broken.py"
    broken_file.write_text("def f(:\n    this is not valid python")
    # Should not raise - just return no findings.
    findings = ast_analyzer.scan_file(broken_file)
    assert findings == []
