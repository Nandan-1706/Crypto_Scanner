"""
migration/tracker.py

Two responsibilities:

1. sync_records(): after every scan (whether or not the user is actively
   updating anything), refresh each tracked record's known file/line/
   algorithm/risk info from the CURRENT scan, and add NOT_STARTED records
   for any newly-seen finding - WITHOUT ever touching an existing record's
   `status`. Status only changes via set_status() (below) or verification
   (migration/verifier.py).

2. set_status(): apply a user-requested status change, enforcing a simple,
   explainable state machine. Rejects invalid transitions and invalid
   status names rather than silently accepting anything.
"""

from __future__ import annotations

import datetime

from risk_engine.migration import MigrationRecord, MigrationStatus, compute_tracking_id
from scanner.models import CryptoAsset

# The "normal" forward order. Skipping ahead (e.g. NOT_STARTED -> MIGRATED)
# is ALLOWED - a developer may migrate something without ever touching this
# CLI along the way - but moving BACKWARD is rejected, except resetting to
# NOT_STARTED, which is always allowed as an explicit undo.
_ORDER = [
    MigrationStatus.NOT_STARTED,
    MigrationStatus.PLANNED,
    MigrationStatus.IN_PROGRESS,
    MigrationStatus.MIGRATED,
    MigrationStatus.VERIFIED,
]


class InvalidTransitionError(ValueError):
    pass


def sync_records(
    assets: list[CryptoAsset],
    risk_by_asset_id: dict,  # asset_id -> object with .risk_level / .risk_score attributes (risk_engine.scorer.RiskScore)
    existing_records: dict[str, MigrationRecord],
) -> dict[str, MigrationRecord]:
    """Merge the current scan's findings into `existing_records`, preserving
    every existing record's `status` untouched. Returns a NEW dict (does not
    mutate the input) containing both the refreshed existing records and any
    brand-new NOT_STARTED records for findings not seen before."""
    updated: dict[str, MigrationRecord] = dict(existing_records)

    for asset in assets:
        tracking_id = compute_tracking_id(asset.file_path, asset.line_number, asset.algorithm)
        risk = risk_by_asset_id.get(asset.asset_id)
        risk_level = getattr(risk, "risk_level", None)
        risk_score = getattr(risk, "risk_score", None)

        if tracking_id in updated:
            existing = updated[tracking_id]
            updated[tracking_id] = MigrationRecord(
                asset_id=asset.asset_id,
                status=existing.status,  # NEVER changed by sync
                notes=existing.notes,
                updated_at=existing.updated_at,
                tracking_id=tracking_id,
                file_path=asset.file_path,
                line_number=asset.line_number,
                algorithm=asset.algorithm,
                risk_level=risk_level,
                risk_score=risk_score,
            )
        else:
            updated[tracking_id] = MigrationRecord(
                asset_id=asset.asset_id,
                status=MigrationStatus.NOT_STARTED,
                tracking_id=tracking_id,
                file_path=asset.file_path,
                line_number=asset.line_number,
                algorithm=asset.algorithm,
                risk_level=risk_level,
                risk_score=risk_score,
            )

    return updated


def set_status(records: dict[str, MigrationRecord], tracking_id: str, new_status_str: str) -> MigrationRecord:
    """
    Apply a user-requested status change. Raises InvalidTransitionError for:
      - an unknown tracking_id (must come from a fresh scan/report - we
        never silently create a record for a typo'd ID)
      - an invalid status name
      - setting VERIFIED directly (only migration/verifier.py can do that,
        based on an actual rescan - never on the user's say-so alone)
      - moving backward in the sequence (other than resetting to NOT_STARTED)
    """
    if tracking_id not in records:
        raise InvalidTransitionError(
            f"Unknown tracking_id '{tracking_id}'. It must come from a tracking_id shown "
            f"in a fresh scan report - run a scan first to get current tracking_ids."
        )

    try:
        new_status = MigrationStatus(new_status_str.upper())
    except ValueError:
        valid = ", ".join(s.value for s in MigrationStatus)
        raise InvalidTransitionError(f"Invalid status '{new_status_str}'. Valid values: {valid}")

    if new_status == MigrationStatus.VERIFIED:
        raise InvalidTransitionError(
            "VERIFIED cannot be set directly. It is only assigned by --verify, after a "
            "rescan actually confirms the risky finding is gone or its risk was reduced."
        )

    record = records[tracking_id]
    current_rank = _ORDER.index(record.status)
    new_rank = _ORDER.index(new_status)

    if new_status != MigrationStatus.NOT_STARTED and new_rank < current_rank:
        raise InvalidTransitionError(
            f"Cannot move backward from {record.status.value} to {new_status.value}. "
            f"(Resetting to NOT_STARTED is always allowed as an explicit undo.)"
        )

    record.status = new_status
    record.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return record
