"""
migration/state.py

Persists migration tracking records to a simple local JSON file
(migration_state.json by default). No database - a flat JSON file is
enough for this prototype and keeps the demo easy to explain.

Records are keyed by TRACKING_ID (see risk_engine.migration.compute_tracking_id),
not by CryptoAsset.asset_id - the asset_id is a fresh random UUID on every
scan, so it cannot identify "the same finding" across separate tool runs.
"""

from __future__ import annotations

import json
from pathlib import Path

from risk_engine.migration import MigrationRecord, MigrationStatus

DEFAULT_STATE_FILENAME = "migration_state.json"


def default_state_path(project_path: str | Path) -> Path:
    """migration_state.json lives inside the SCANNED project's directory by
    default, so tracking state travels with the project being tracked
    (scanning a different project uses a different state file automatically)."""
    return Path(project_path) / DEFAULT_STATE_FILENAME


def load_state(path: str | Path) -> dict[str, MigrationRecord]:
    """Load records from `path`. A missing file is NOT an error - it just
    means no tracking has started yet, so we return an empty dict rather
    than fabricating records."""
    state_path = Path(path)
    if not state_path.exists():
        return {}

    raw = json.loads(state_path.read_text(encoding="utf-8"))
    records: dict[str, MigrationRecord] = {}
    for tracking_id, fields in raw.items():
        records[tracking_id] = MigrationRecord(
            asset_id=fields.get("asset_id", tracking_id),
            status=MigrationStatus(fields["status"]),
            notes=fields.get("notes"),
            updated_at=fields.get("updated_at"),
            tracking_id=fields.get("tracking_id", tracking_id),
            file_path=fields.get("file_path"),
            line_number=fields.get("line_number"),
            algorithm=fields.get("algorithm"),
            risk_level=fields.get("risk_level"),
            risk_score=fields.get("risk_score"),
        )
    return records


def save_state(path: str | Path, records: dict[str, MigrationRecord]) -> None:
    data = {tracking_id: record.to_dict() for tracking_id, record in records.items()}
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
