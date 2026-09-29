import json
from pathlib import Path

from migration.state import default_state_path, load_state, save_state
from risk_engine.migration import MigrationRecord, MigrationStatus


def test_load_state_missing_file_returns_empty_dict(tmp_path):
    result = load_state(tmp_path / "does_not_exist.json")
    assert result == {}


def test_save_then_load_round_trips(tmp_path):
    path = tmp_path / "migration_state.json"
    records = {
        "abc123": MigrationRecord(
            asset_id="asset-1", status=MigrationStatus.MIGRATED,
            tracking_id="abc123", file_path="f.py", line_number=10,
            algorithm="RSA", risk_level="CRITICAL", risk_score=80,
        )
    }
    save_state(path, records)
    loaded = load_state(path)

    assert "abc123" in loaded
    assert loaded["abc123"].status == MigrationStatus.MIGRATED
    assert loaded["abc123"].algorithm == "RSA"
    assert loaded["abc123"].risk_level == "CRITICAL"
    assert loaded["abc123"].risk_score == 80


def test_saved_file_is_valid_json(tmp_path):
    path = tmp_path / "migration_state.json"
    records = {"x": MigrationRecord(asset_id="a", status=MigrationStatus.NOT_STARTED, tracking_id="x")}
    save_state(path, records)
    raw = json.loads(path.read_text())
    assert raw["x"]["status"] == "NOT_STARTED"


def test_default_state_path_lives_inside_project_dir():
    path = default_state_path("/some/project")
    assert str(path) == str(Path("/some/project") / "migration_state.json")
