from report import build_human_readable_report


def _minimal_report():
    return {
        "project": "test_project",
        "coverage": {"scanned": ["Python source"], "not_scanned": ["Binaries", "Certificates"]},
        "assets": [
            {
                "asset_id": "asset-1",
                "tracking_id": "tid-1",
                "algorithm": "RSA",
                "key_size": 1024,
                "file_path": "auth.py",
                "line_number": 5,
                "risk_assessment": {
                    "scoring_status": "scored",
                    "risk_score": 92,
                    "risk_level": "CRITICAL",
                    "priority": 1,
                    "business_criticality": "CRITICAL",
                    "data_lifetime_years": 15,
                    "algorithm_risk": {"quantum_risk": "high"},
                },
                "pqc_recommendation": {"applies": True, "direction": "NIST FIPS 204 (ML-DSA)"},
                "migration_status": {"status": "NOT_STARTED"},
            },
        ],
    }


def test_report_contains_header_and_project_name():
    text = build_human_readable_report(_minimal_report())
    assert "CRYPTOGRAPHIC RISK REPORT" in text
    assert "Project: test_project" in text


def test_report_shows_risk_level_counts():
    text = build_human_readable_report(_minimal_report())
    assert "CRITICAL: 1" in text
    assert "HIGH: 0" in text


def test_report_shows_top_priority_asset_details():
    text = build_human_readable_report(_minimal_report())
    assert "Algorithm: RSA" in text
    assert "Risk Score: 92" in text
    assert "Priority: 1" in text
    assert "Tracking ID: tid-1" in text


def test_report_shows_migration_summary():
    text = build_human_readable_report(_minimal_report())
    assert "MIGRATION SUMMARY" in text
    assert "NOT_STARTED: 1" in text


def test_report_shows_coverage_section():
    text = build_human_readable_report(_minimal_report())
    assert "Python source: SCANNED" in text
    assert "NOT SCANNED" in text


def test_report_never_hides_recommendation_disclaimer():
    text = build_human_readable_report(_minimal_report())
    assert "not an official NIST or CVSS score" in text
    assert "never performs automatic code changes" in text


def test_report_handles_zero_assets_gracefully():
    empty_report = {
        "project": "empty",
        "coverage": {"scanned": [], "not_scanned": []},
        "assets": [],
    }
    text = build_human_readable_report(empty_report)
    assert "Assets Found: 0" in text
