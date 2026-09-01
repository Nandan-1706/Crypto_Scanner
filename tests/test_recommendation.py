from scanner.models import Confidence, CryptoAsset, DetectionMethod
from recommendation.rules import recommend_for


def _make_asset(algorithm: str, purpose=None, asset_id="a1") -> CryptoAsset:
    return CryptoAsset(
        asset_id=asset_id,
        project="p",
        file_path="f.py",
        asset_type="t",
        algorithm=algorithm,
        key_size=None,
        cryptographic_purpose=purpose,
        detection_method=DetectionMethod.AST_ANALYSIS,
        evidence="ev",
        confidence=Confidence.HIGH,
        line_number=1,
    )


def test_signing_purpose_recommends_ml_dsa():
    asset = _make_asset("ECDSA", purpose="signing")
    rec = recommend_for(asset)
    assert rec.applies
    assert "ML-DSA" in rec.direction


def test_key_exchange_purpose_recommends_ml_kem():
    asset = _make_asset("ECDH", purpose="key_exchange")
    rec = recommend_for(asset)
    assert rec.applies
    assert "ML-KEM" in rec.direction


def test_ambiguous_rsa_key_generation_does_not_guess():
    asset = _make_asset("RSA", purpose="key_generation")
    rec = recommend_for(asset)
    assert rec.applies is False
    assert rec.direction is None
    assert "cannot determine" in rec.rationale.lower()


def test_aes_gets_no_pqc_family_swap_recommendation():
    asset = _make_asset("AES", purpose=None)
    rec = recommend_for(asset)
    assert rec.applies is False
    assert "symmetric" in rec.rationale.lower()


def test_sha256_explains_it_is_not_part_of_pqc_migration():
    asset = _make_asset("SHA-256", purpose="hashing")
    rec = recommend_for(asset)
    assert rec.applies is False


def test_recommendation_never_blindly_suggests_ml_dsa_for_everything():
    """Sanity check on the spec's core requirement: not every asset gets ML-DSA."""
    algorithms_and_purposes = [
        ("RSA", "key_generation"),
        ("AES", None),
        ("SHA-256", "hashing"),
        ("MD5", "hashing"),
    ]
    for algorithm, purpose in algorithms_and_purposes:
        asset = _make_asset(algorithm, purpose=purpose)
        rec = recommend_for(asset)
        assert rec.direction is None or "ML-DSA" not in rec.direction
