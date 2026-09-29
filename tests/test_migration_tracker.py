import pytest

from migration.tracker import InvalidTransitionError, set_status, sync_records
from risk_engine.migration import MigrationRecord, MigrationStatus, compute_tracking_id
from scanner.models import Confidence, CryptoAsset, DetectionMethod


def _make_asset(algorithm="RSA", file_path="f.py", line_number=10, asset_id="a1"):
    return CryptoAsset(
        asset_id=asset_id, project="p", file_path=file_path, asset_type="t",
        algorithm=algorithm, key_size=None, cryptographic_purpose=None,
        detection_method=DetectionMethod.AST_ANALYSIS, evidence="ev",
        confidence=Confidence.HIGH, line_number=line_number,
    )


class _FakeRiskScore:
    def __init__(self, risk_level, risk_score):
        self.risk_level = risk_level
        self.risk_score = risk_score


def test_sync_creates_not_started_record_for_new_finding():
    asset = _make_asset()
    risk_by_id = {"a1": _FakeRiskScore("CRITICAL", 80)}
    synced = sync_records([asset], risk_by_id, existing_records={})

    tid = compute_tracking_id(asset.file_path, asset.line_number, asset.algorithm)
    assert tid in synced
    assert synced[tid].status == MigrationStatus.NOT_STARTED
    assert synced[tid].risk_level == "CRITICAL"


def test_sync_never_overwrites_existing_status():
    asset = _make_asset()
    tid = compute_tracking_id(asset.file_path, asset.line_number, asset.algorithm)
    existing = {tid: MigrationRecord(asset_id="old", status=MigrationStatus.MIGRATED, tracking_id=tid)}

    risk_by_id = {"a1": _FakeRiskScore("HIGH", 60)}
    synced = sync_records([asset], risk_by_id, existing_records=existing)

    assert synced[tid].status == MigrationStatus.MIGRATED  # untouched
    assert synced[tid].risk_level == "HIGH"  # refreshed


def test_sync_does_not_mutate_input_dict():
    asset = _make_asset()
    tid = compute_tracking_id(asset.file_path, asset.line_number, asset.algorithm)
    existing = {tid: MigrationRecord(asset_id="old", status=MigrationStatus.PLANNED, tracking_id=tid)}
    risk_by_id = {"a1": _FakeRiskScore("LOW", 10)}

    sync_records([asset], risk_by_id, existing_records=existing)
    assert existing[tid].status == MigrationStatus.PLANNED  # original dict untouched


def test_set_status_valid_forward_transition():
    records = {"t1": MigrationRecord(asset_id="a1", status=MigrationStatus.NOT_STARTED, tracking_id="t1")}
    record = set_status(records, "t1", "PLANNED")
    assert record.status == MigrationStatus.PLANNED
    assert record.updated_at is not None


def test_set_status_allows_skipping_ahead():
    records = {"t1": MigrationRecord(asset_id="a1", status=MigrationStatus.NOT_STARTED, tracking_id="t1")}
    record = set_status(records, "t1", "MIGRATED")
    assert record.status == MigrationStatus.MIGRATED


def test_set_status_rejects_backward_transition():
    records = {"t1": MigrationRecord(asset_id="a1", status=MigrationStatus.MIGRATED, tracking_id="t1")}
    with pytest.raises(InvalidTransitionError):
        set_status(records, "t1", "PLANNED")


def test_set_status_allows_reset_to_not_started():
    records = {"t1": MigrationRecord(asset_id="a1", status=MigrationStatus.MIGRATED, tracking_id="t1")}
    record = set_status(records, "t1", "NOT_STARTED")
    assert record.status == MigrationStatus.NOT_STARTED


def test_set_status_rejects_verified_directly():
    records = {"t1": MigrationRecord(asset_id="a1", status=MigrationStatus.MIGRATED, tracking_id="t1")}
    with pytest.raises(InvalidTransitionError):
        set_status(records, "t1", "VERIFIED")


def test_set_status_rejects_invalid_status_name():
    records = {"t1": MigrationRecord(asset_id="a1", status=MigrationStatus.NOT_STARTED, tracking_id="t1")}
    with pytest.raises(InvalidTransitionError):
        set_status(records, "t1", "NOT_A_REAL_STATUS")


def test_set_status_rejects_unknown_tracking_id():
    records = {"t1": MigrationRecord(asset_id="a1", status=MigrationStatus.NOT_STARTED, tracking_id="t1")}
    with pytest.raises(InvalidTransitionError):
        set_status(records, "unknown_id", "PLANNED")


def test_tracking_id_is_stable_across_calls():
    id1 = compute_tracking_id("f.py", 10, "RSA")
    id2 = compute_tracking_id("f.py", 10, "RSA")
    assert id1 == id2


def test_tracking_id_changes_with_line_number():
    id1 = compute_tracking_id("f.py", 10, "RSA")
    id2 = compute_tracking_id("f.py", 11, "RSA")
    assert id1 != id2
