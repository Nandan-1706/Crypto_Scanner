"""
risk_engine/migration.py

Data model for tracking migration progress on a cryptographic asset:
MigrationStatus, MigrationRecord, and compute_tracking_id().

This module holds ONLY the data model - the actual persistence
(save/load JSON), status-update/transition rules, and rescan-based
verification logic live in the migration/ package (migration/state.py,
migration/tracker.py, migration/verifier.py), which import from here
rather than duplicating this model. Kept in risk_engine/ rather than
moved into migration/ to avoid breaking Phase 2's existing imports
(`from risk_engine.migration import ...`).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class MigrationStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    MIGRATED = "MIGRATED"
    VERIFIED = "VERIFIED"


@dataclass
class MigrationRecord:
    """One asset's migration tracking record.

    `asset_id` is the (ephemeral, per-scan-run) CryptoAsset.asset_id at the
    time this record was last touched - kept for backward compatibility
    with Phase 2/3 code and for human-readable display.

    `tracking_id` (added in Phase 4) is the STABLE identifier actually used
    as the persistence key in migration_state.json - see
    compute_tracking_id() below for why asset_id itself cannot be used for
    that. It defaults to None only for records created before Phase 4
    (e.g. via the old default_migration_record() call shape); Phase 4 code
    always sets it.
    """
    asset_id: str
    status: MigrationStatus
    notes: str | None = None
    updated_at: str | None = None  # ISO timestamp, set once real tracking exists
    tracking_id: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    algorithm: str | None = None
    risk_level: str | None = None   # the risk_level captured the last time this record was updated/synced
    risk_score: int | None = None

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "status": self.status.value,
            "notes": self.notes,
            "updated_at": self.updated_at,
            "tracking_id": self.tracking_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "algorithm": self.algorithm,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
        }


def default_migration_record(asset_id: str) -> MigrationRecord:
    """The only migration record Phase 2 could honestly produce: NOT_STARTED,
    since no tracking mechanism existed yet. Kept unchanged for backward
    compatibility - Phase 4's migration/tracker.py creates fuller records
    with a real tracking_id via a different path."""
    return MigrationRecord(asset_id=asset_id, status=MigrationStatus.NOT_STARTED)


def compute_tracking_id(file_path: str, line_number: int | None, algorithm: str) -> str:
    """
    A STABLE fingerprint for one finding, based on (file_path, line_number,
    algorithm) - unlike CryptoAsset.asset_id, which is a fresh random UUID
    generated on every scan and therefore useless as a persistence key
    across separate tool invocations (which is exactly what Phase 4's
    migration tracking needs: "is THIS SAME finding from last time still
    here, or gone, on this rescan?").

    This is a heuristic identity, not a cryptographic guarantee: if a
    developer inserts/removes lines earlier in the same file, every
    subsequent finding's line_number shifts and its tracking_id changes.
    This is a documented limitation, not silently hidden - see the
    migration/ package's README section.
    """
    import hashlib
    key = f"{file_path}|{line_number}|{algorithm}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
