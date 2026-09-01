from scanner.models import Confidence, DetectionMethod, RawFinding
from scanner.normalizer import normalize


def _make_finding(algorithm: str, confidence: Confidence = Confidence.LOW) -> RawFinding:
    return RawFinding(
        file_path="some_file.py",
        line_number=10,
        algorithm=algorithm,
        detection_method=DetectionMethod.PATTERN_MATCH,
        evidence="example evidence line",
        confidence=confidence,
    )


def test_normalize_assigns_unique_asset_ids():
    findings = [_make_finding("MD5"), _make_finding("MD5")]
    assets = normalize(findings, project_name="test_project")

    assert len(assets) == 2
    assert assets[0].asset_id != assets[1].asset_id


def test_normalize_preserves_all_findings_without_deduplication():
    findings = [_make_finding("AES"), _make_finding("AES")]
    assets = normalize(findings, project_name="test_project")
    assert len(assets) == 2


def test_normalize_maps_known_algorithm_to_asset_type():
    findings = [_make_finding("RSA")]
    assets = normalize(findings, project_name="test_project")
    assert assets[0].asset_type == "asymmetric_key_usage"


def test_normalize_uses_default_asset_type_for_unknown_algorithm():
    findings = [_make_finding("SOME_UNKNOWN_ALGO")]
    assets = normalize(findings, project_name="test_project")
    assert assets[0].asset_type == "cryptographic_indicator"


def test_normalize_attaches_project_name():
    findings = [_make_finding("SHA-256")]
    assets = normalize(findings, project_name="my_cool_project")
    assert assets[0].project == "my_cool_project"


def test_to_dict_produces_json_safe_values():
    findings = [_make_finding("MD5")]
    asset = normalize(findings, project_name="test_project")[0]
    d = asset.to_dict()

    assert isinstance(d["detection_method"], str)
    assert isinstance(d["confidence"], str)
    assert d["algorithm"] == "MD5"
