from migration.verifier import verify_records
from risk_engine.migration import MigrationRecord, MigrationStatus


def _migrated_record(tracking_id, risk_level="CRITICAL", risk_score=80):
    return MigrationRecord(
        asset_id="a1", status=MigrationStatus.MIGRATED, tracking_id=tracking_id,
        file_path="f.py", line_number=10, algorithm="RSA",
        risk_level=risk_level, risk_score=risk_score,
    )


def test_asset_disappears_promotes_to_verified():
    records = {"t1": _migrated_record("t1")}
    results = verify_records(records, current_tracking_ids=set(), current_risk_by_tracking_id={})

    assert records["t1"].status == MigrationStatus.VERIFIED
    assert results[0].outcome == "verified_removed"


def test_risk_reduced_promotes_to_verified():
    records = {"t1": _migrated_record("t1", risk_level="CRITICAL")}
    results = verify_records(
        records,
        current_tracking_ids={"t1"},
        current_risk_by_tracking_id={"t1": ("LOW", 15)},
    )

    assert records["t1"].status == MigrationStatus.VERIFIED
    assert results[0].outcome == "verified_risk_reduced"
    assert records["t1"].risk_level == "LOW"


def test_risk_unchanged_stays_migrated_not_verified():
    records = {"t1": _migrated_record("t1", risk_level="CRITICAL")}
    results = verify_records(
        records,
        current_tracking_ids={"t1"},
        current_risk_by_tracking_id={"t1": ("CRITICAL", 80)},
    )

    assert records["t1"].status == MigrationStatus.MIGRATED  # NOT verified
    assert results[0].outcome == "not_verified_unchanged"


def test_risk_increased_stays_migrated_not_verified():
    records = {"t1": _migrated_record("t1", risk_level="MEDIUM")}
    results = verify_records(
        records,
        current_tracking_ids={"t1"},
        current_risk_by_tracking_id={"t1": ("CRITICAL", 80)},
    )

    assert records["t1"].status == MigrationStatus.MIGRATED
    assert results[0].outcome == "not_verified_unchanged"


def test_non_migrated_records_are_never_touched():
    records = {
        "t1": MigrationRecord(asset_id="a1", status=MigrationStatus.NOT_STARTED, tracking_id="t1"),
        "t2": MigrationRecord(asset_id="a2", status=MigrationStatus.PLANNED, tracking_id="t2"),
        "t3": MigrationRecord(asset_id="a3", status=MigrationStatus.VERIFIED, tracking_id="t3"),
    }
    results = verify_records(records, current_tracking_ids=set(), current_risk_by_tracking_id={})

    assert results == []
    assert records["t1"].status == MigrationStatus.NOT_STARTED
    assert records["t2"].status == MigrationStatus.PLANNED
    assert records["t3"].status == MigrationStatus.VERIFIED


def test_user_setting_migrated_alone_never_equals_verified():
    """The core anti-false-positive requirement: a MIGRATED record with no
    rescan evidence of change must never silently become VERIFIED."""
    records = {"t1": _migrated_record("t1", risk_level="HIGH")}
    verify_records(records, current_tracking_ids={"t1"}, current_risk_by_tracking_id={"t1": ("HIGH", 60)})
    assert records["t1"].status != MigrationStatus.VERIFIED
