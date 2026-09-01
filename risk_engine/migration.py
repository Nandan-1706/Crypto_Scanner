"""
risk_engine/migration.py

Data model for tracking migration progress on a cryptographic asset.

This is architecture only for Phase 2 - there is no database, no API, and no
UI to change these values yet. Every asset in this phase's output simply
gets MigrationStatus.NOT_STARTED, because that's the only status we can
truthfully claim without a persistence layer. This exists so Phase 3+ (a
FastAPI backend + Supabase) can attach real tracking without changing this
data shape.
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
    """One asset's migration tracking record. `notes` and `updated_at` are
    left for a future phase with real persistence to populate - Phase 2
    only ever produces NOT_STARTED records with no notes."""
    asset_id: str
    status: MigrationStatus
    notes: str | None = None
    updated_at: str | None = None  # ISO timestamp, set once real tracking exists

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "status": self.status.value,
            "notes": self.notes,
            "updated_at": self.updated_at,
        }


def default_migration_record(asset_id: str) -> MigrationRecord:
    """The only migration record Phase 2 can honestly produce: NOT_STARTED,
    since no tracking mechanism exists yet."""
    return MigrationRecord(asset_id=asset_id, status=MigrationStatus.NOT_STARTED)
