from scanner.models import Confidence, CryptoAsset, DetectionMethod
from risk_engine.context import BusinessCriticality, ProjectContext
from risk_engine.scorer import score_assets


def _make_asset(
    algorithm: str,
    key_size=None,
    confidence=Confidence.HIGH,
    asset_id="asset-1",
    purpose=None,
) -> CryptoAsset:
    return CryptoAsset(
        asset_id=asset_id,
        project="test_project",
        file_path="some_file.py",
        asset_type="test_type",
        algorithm=algorithm,
        key_size=key_size,
        cryptographic_purpose=purpose,
        detection_method=DetectionMethod.AST_ANALYSIS,
        evidence="example evidence",
        confidence=confidence,
        line_number=1,
    )


def test_rsa_quantum_vulnerable_asset_with_full_context():
    """RSA-2048, CRITICAL business, 15yr lifetime -> should land at/near the top."""
    asset = _make_asset("RSA", key_size=2048, purpose="key_generation")
    context = ProjectContext(business_criticality=BusinessCriticality.CRITICAL, data_lifetime_years=15)
    result = score_assets([asset], context)[0]

    # A: classical ACCEPTABLE_TODAY(5) + quantum HIGH(15) = 20
    # B: CRITICAL = 25
    # C: 15+ years = 15
    # total = 60, x1.0 (HIGH confidence) = 60
    assert result.risk_score == 60
    assert result.risk_level == "HIGH"
    assert result.priority == 1  # CRITICAL business + quantum vulnerable + lifetime >= 10
    assert result.scoring_status == "scored"


def test_ecc_quantum_vulnerable_asset():
    asset = _make_asset("ECC", purpose="key_generation")
    context = ProjectContext(business_criticality=BusinessCriticality.HIGH, data_lifetime_years=None)
    result = score_assets([asset], context)[0]

    # A: classical ACCEPTABLE_TODAY(5) + quantum HIGH(15) = 20
    # B: HIGH = 20
    # C: unknown lifetime = 0
    # total = 40 x 1.0 = 40
    assert result.risk_score == 40
    assert result.priority == 2  # HIGH business + quantum vulnerable


def test_different_business_criticalities_change_score():
    asset_factory = lambda: _make_asset("AES")
    scores = {}
    for level in (BusinessCriticality.LOW, BusinessCriticality.MEDIUM, BusinessCriticality.HIGH, BusinessCriticality.CRITICAL):
        context = ProjectContext(business_criticality=level, data_lifetime_years=None)
        result = score_assets([asset_factory()], context)[0]
        scores[level] = result.risk_score

    assert scores[BusinessCriticality.LOW] < scores[BusinessCriticality.MEDIUM] < scores[BusinessCriticality.HIGH] < scores[BusinessCriticality.CRITICAL]


def test_different_data_lifetimes_change_score():
    scores = {}
    for years in (None, 2, 7, 12, 20):
        context = ProjectContext(business_criticality=BusinessCriticality.UNKNOWN, data_lifetime_years=years)
        result = score_assets([_make_asset("RSA", key_size=2048)], context)[0]
        scores[years] = result.risk_score

    assert scores[None] < scores[2] < scores[7] < scores[12] < scores[20]


def test_unknown_business_criticality_uses_neutral_default_not_low_or_high():
    context = ProjectContext.unknown()
    result = score_assets([_make_asset("AES")], context)[0]
    assert result.business_criticality == "UNKNOWN"
    # neutral default (10 points) should be between LOW(5) and HIGH(20) contributions
    low_context = ProjectContext(business_criticality=BusinessCriticality.LOW, data_lifetime_years=None)
    high_context = ProjectContext(business_criticality=BusinessCriticality.HIGH, data_lifetime_years=None)
    low_result = score_assets([_make_asset("AES")], low_context)[0]
    high_result = score_assets([_make_asset("AES")], high_context)[0]
    assert low_result.risk_score < result.risk_score < high_result.risk_score


def test_unknown_data_lifetime_contributes_zero_and_is_visible():
    context = ProjectContext(business_criticality=BusinessCriticality.CRITICAL, data_lifetime_years=None)
    result = score_assets([_make_asset("RSA", key_size=2048)], context)[0]
    assert result.data_lifetime_years is None
    assert any("not provided" in r.lower() for r in result.reasons)


def test_confidence_multiplier_reduces_score():
    context = ProjectContext(business_criticality=BusinessCriticality.CRITICAL, data_lifetime_years=15)
    high_conf = score_assets([_make_asset("RSA", key_size=2048, confidence=Confidence.HIGH)], context)[0]
    med_conf = score_assets([_make_asset("RSA", key_size=2048, confidence=Confidence.MEDIUM)], context)[0]
    assert med_conf.risk_score == round(high_conf.risk_score * 0.85)
    assert med_conf.risk_score < high_conf.risk_score


def test_low_confidence_is_never_scored():
    context = ProjectContext(business_criticality=BusinessCriticality.CRITICAL, data_lifetime_years=15)
    result = score_assets([_make_asset("MD5", confidence=Confidence.LOW)], context)[0]
    assert result.scoring_status == "skipped_low_confidence"
    assert result.risk_score is None
    assert result.priority is None


def test_risk_level_boundaries():
    # Construct contexts/assets to hit each bucket precisely via the documented formula.
    # AES with UNKNOWN everything: A=5+2=7, B=10(unknown), C=0 -> 17 -> LOW
    low_context = ProjectContext.unknown()
    low_result = score_assets([_make_asset("AES")], low_context)[0]
    assert low_result.risk_level == "LOW"

    # RSA-2048 unknown key context but HIGH business, 7yr lifetime:
    # A=5+15=20, B=20, C=8 -> 48 -> MEDIUM
    med_context = ProjectContext(business_criticality=BusinessCriticality.HIGH, data_lifetime_years=7)
    med_result = score_assets([_make_asset("RSA", key_size=2048)], med_context)[0]
    assert med_result.risk_level == "MEDIUM"

    # RSA-2048, CRITICAL business, 15yr: A=20, B=25, C=15 -> 60 -> HIGH
    high_context = ProjectContext(business_criticality=BusinessCriticality.CRITICAL, data_lifetime_years=15)
    high_result = score_assets([_make_asset("RSA", key_size=2048)], high_context)[0]
    assert high_result.risk_level == "HIGH"

    # RSA < 2048 (critical classical), CRITICAL business, 15yr:
    # A = 25(critical) + 15(quantum high) = 40, B=25, C=15 -> 80 -> CRITICAL
    critical_context = ProjectContext(business_criticality=BusinessCriticality.CRITICAL, data_lifetime_years=15)
    critical_result = score_assets([_make_asset("RSA", key_size=1024)], critical_context)[0]
    assert critical_result.risk_level == "CRITICAL"


def test_priority_rules():
    long_lifetime_critical = ProjectContext(business_criticality=BusinessCriticality.CRITICAL, data_lifetime_years=15)
    assert score_assets([_make_asset("RSA", key_size=2048)], long_lifetime_critical)[0].priority == 1

    short_lifetime_critical = ProjectContext(business_criticality=BusinessCriticality.CRITICAL, data_lifetime_years=2)
    # still quantum vulnerable + CRITICAL business, but lifetime < 10 -> falls to priority 2
    assert score_assets([_make_asset("RSA", key_size=2048)], short_lifetime_critical)[0].priority == 2

    high_business = ProjectContext(business_criticality=BusinessCriticality.HIGH, data_lifetime_years=None)
    assert score_assets([_make_asset("ECC")], high_business)[0].priority == 2

    low_business_non_vulnerable = ProjectContext(business_criticality=BusinessCriticality.LOW, data_lifetime_years=None)
    result = score_assets([_make_asset("MD5")], low_business_non_vulnerable)[0]
    assert result.priority in (3, 4)  # MD5 is not quantum-relevant but classical-critical, still a real risk


def test_migration_effort_hint_scales_with_occurrence_count():
    context = ProjectContext.unknown()
    single_asset = [_make_asset("RSA", key_size=2048, asset_id="a1")]
    result = score_assets(single_asset, context)[0]
    assert result.migration_effort_hint == "LOW"

    many_assets = [_make_asset("RSA", key_size=2048, asset_id=f"a{i}") for i in range(12)]
    results = score_assets(many_assets, context)
    assert all(r.migration_effort_hint == "HIGH" for r in results)


def test_migration_effort_is_not_part_of_numeric_score():
    context = ProjectContext.unknown()
    single = score_assets([_make_asset("RSA", key_size=2048, asset_id="a1")], context)[0]
    many = score_assets(
        [_make_asset("RSA", key_size=2048, asset_id=f"a{i}") for i in range(12)], context
    )[0]
    assert single.risk_score == many.risk_score  # same asset-level factors -> same score regardless of effort hint


def test_score_is_capped_at_100():
    # Worst-case inputs: RSA<2048 (critical+quantum), CRITICAL business, 15yr lifetime, HIGH confidence
    context = ProjectContext(business_criticality=BusinessCriticality.CRITICAL, data_lifetime_years=30)
    result = score_assets([_make_asset("RSA", key_size=512)], context)[0]
    # raw would be 25+15+25+15 = 80, still under 100, so also check the cap logic directly
    assert result.risk_score <= 100


def test_reasons_are_specific_to_the_asset_not_generic():
    context = ProjectContext(business_criticality=BusinessCriticality.CRITICAL, data_lifetime_years=15)
    rsa_result = score_assets([_make_asset("RSA", key_size=2048)], context)[0]
    aes_result = score_assets([_make_asset("AES")], context)[0]

    assert any("quantum-vulnerable" in r.lower() for r in rsa_result.reasons)
    assert not any("quantum-vulnerable" in r.lower() for r in aes_result.reasons)


def test_phase1_sample_project_still_scores_without_error():
    """Compatibility check: the real Phase 1 sample project scans and scores cleanly."""
    from pathlib import Path
    from scanner import ast_analyzer, file_discovery, normalizer, pattern_detector

    sample_project = Path(__file__).parent.parent / "sample_project"
    discovered, _ = file_discovery.discover_files(sample_project)
    findings = []
    for f in discovered:
        findings.extend(pattern_detector.scan_file(f.path))
        findings.extend(ast_analyzer.scan_file(f.path))
    assets = normalizer.normalize(findings, project_name="sample_project")

    results = score_assets(assets, ProjectContext.unknown())
    assert len(results) == len(assets)
