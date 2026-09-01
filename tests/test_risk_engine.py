from scanner.models import Confidence, CryptoAsset, DetectionMethod
from risk_engine.engine import assess
from risk_engine.models import ClassicalRiskLevel, QuantumRiskLevel, ScoringStatus


def _make_asset(algorithm: str, key_size=None, confidence=Confidence.HIGH, asset_id="asset-1") -> CryptoAsset:
    return CryptoAsset(
        asset_id=asset_id,
        project="test_project",
        file_path="some_file.py",
        asset_type="test_type",
        algorithm=algorithm,
        key_size=key_size,
        cryptographic_purpose=None,
        detection_method=DetectionMethod.AST_ANALYSIS,
        evidence="example evidence",
        confidence=confidence,
        line_number=1,
    )


def test_low_confidence_assets_are_never_scored():
    asset = _make_asset("MD5", confidence=Confidence.LOW)
    result = assess([asset])[0]

    assert result.scoring_status == ScoringStatus.SKIPPED_LOW_CONFIDENCE
    assert result.classical_risk == ClassicalRiskLevel.UNKNOWN_INSUFFICIENT_DATA
    assert result.quantum_risk == QuantumRiskLevel.UNKNOWN_INSUFFICIENT_DATA


def test_md5_is_critical_classical_risk():
    asset = _make_asset("MD5", confidence=Confidence.HIGH)
    result = assess([asset])[0]
    assert result.classical_risk == ClassicalRiskLevel.CRITICAL


def test_rsa_below_2048_is_critical():
    asset = _make_asset("RSA", key_size=1024, confidence=Confidence.HIGH)
    result = assess([asset])[0]
    assert result.classical_risk == ClassicalRiskLevel.CRITICAL
    assert result.quantum_risk == QuantumRiskLevel.HIGH


def test_rsa_2048_or_above_is_acceptable_today_but_quantum_high():
    asset = _make_asset("RSA", key_size=3072, confidence=Confidence.HIGH)
    result = assess([asset])[0]
    assert result.classical_risk == ClassicalRiskLevel.ACCEPTABLE_TODAY
    assert result.quantum_risk == QuantumRiskLevel.HIGH


def test_rsa_with_unknown_key_size_is_unscored_for_classical_but_quantum_high():
    asset = _make_asset("RSA", key_size=None, confidence=Confidence.HIGH)
    result = assess([asset])[0]
    assert result.classical_risk == ClassicalRiskLevel.UNKNOWN_INSUFFICIENT_DATA
    assert result.quantum_risk == QuantumRiskLevel.HIGH


def test_aes_is_low_quantum_risk():
    asset = _make_asset("AES", confidence=Confidence.HIGH)
    result = assess([asset])[0]
    assert result.classical_risk == ClassicalRiskLevel.ACCEPTABLE_TODAY
    assert result.quantum_risk == QuantumRiskLevel.LOW


def test_sha256_is_low_quantum_risk():
    asset = _make_asset("SHA-256", confidence=Confidence.HIGH)
    result = assess([asset])[0]
    assert result.quantum_risk == QuantumRiskLevel.LOW


def test_unscoreable_algorithm_gets_no_fabricated_verdict():
    asset = _make_asset("cryptography.hazmat", confidence=Confidence.HIGH)
    result = assess([asset])[0]
    assert result.classical_risk == ClassicalRiskLevel.UNKNOWN_INSUFFICIENT_DATA
    assert result.quantum_risk == QuantumRiskLevel.UNKNOWN_INSUFFICIENT_DATA
    assert result.rule_id == "NO-MATCHING-RULE"


def test_every_scored_result_has_a_standard_reference():
    assets = [
        _make_asset("MD5"),
        _make_asset("RSA", key_size=2048),
        _make_asset("AES"),
        _make_asset("SHA-256"),
        _make_asset("ECDSA"),
    ]
    for result in assess(assets):
        assert result.standard_reference
        assert result.standard_reference != "N/A - not scored"


def test_assess_preserves_asset_order_and_count():
    assets = [_make_asset("MD5", asset_id="a1"), _make_asset("AES", asset_id="a2")]
    results = assess(assets)
    assert len(results) == 2
    assert results[0].asset_id == "a1"
    assert results[1].asset_id == "a2"
