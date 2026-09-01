from risk_engine.migration import MigrationStatus, default_migration_record


def test_default_migration_record_is_not_started():
    record = default_migration_record("asset-123")
    assert record.status == MigrationStatus.NOT_STARTED
    assert record.asset_id == "asset-123"
    assert record.notes is None


def test_to_dict_is_json_safe():
    record = default_migration_record("asset-456")
    d = record.to_dict()
    assert d["status"] == "NOT_STARTED"
    assert isinstance(d["status"], str)
