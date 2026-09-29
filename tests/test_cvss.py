from scanner.models import Confidence, CryptoAsset, DetectionMethod
from risk_engine.cvss import assess


def _make_asset(algorithm="RSA", asset_id="a1"):
    return CryptoAsset(
        asset_id=asset_id, project="p", file_path="f.py", asset_type="t",
        algorithm=algorithm, key_size=None, cryptographic_purpose=None,
        detection_method=DetectionMethod.AST_ANALYSIS, evidence="ev",
        confidence=Confidence.HIGH, line_number=1,
    )


def test_cvss_never_applies_without_vulnerability_context():
    """Core correctness requirement: CVSS must never be fabricated for a
    bare algorithm-usage finding, regardless of how 'bad' the algorithm is."""
    for algorithm in ("MD5", "DES", "RSA", "AES", "SHA-256"):
        result = assess(_make_asset(algorithm))
        assert result.applies is False
        assert result.score is None
        assert result.severity is None
        assert result.vector is None


def test_cvss_rationale_explains_why_not_applicable():
    result = assess(_make_asset("MD5"))
    assert "vulnerability" in result.rationale.lower()


def test_cvss_result_is_json_safe():
    d = assess(_make_asset("RSA")).to_dict()
    assert d["applies"] is False
    assert d["score"] is None
    assert isinstance(d["rationale"], str)


def test_cvss_asset_id_matches_input():
    result = assess(_make_asset("AES", asset_id="asset-xyz"))
    assert result.asset_id == "asset-xyz"
