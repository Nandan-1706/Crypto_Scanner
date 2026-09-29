"""
migration/verifier.py

The --verify workflow: rescans the project and checks whether records
currently marked MIGRATED actually show reduced risk on the rescan, or
whether the original finding has disappeared entirely (crypto usage
removed/replaced). ONLY this module can promote a record to VERIFIED -
never the user directly (see migration/tracker.py's set_status()).

Two ways a MIGRATED record becomes VERIFIED:
  1. "verified_removed": the finding's tracking_id no longer appears in
     the current scan at all - the vulnerable code was removed or
     sufficiently changed that the original pattern/AST match no longer
     fires.
  2. "verified_risk_reduced": the finding is still present (same
     tracking_id), but its risk_level dropped compared to what was
     recorded when MIGRATED was set (e.g. CRITICAL -> LOW after the
     developer switched libraries or algorithms).

If neither is true - the finding is still there with the same or higher
risk - the record explicitly stays MIGRATED, NOT VERIFIED. This is the
core anti-false-positive rule: a status the user typed in is never treated
as proof by itself.
"""

from __future__ import annotations

from dataclasses import dataclass

from risk_engine.migration import MigrationRecord, MigrationStatus

_RISK_LEVEL_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


@dataclass
class VerificationResult:
    tracking_id: str
    outcome: str          # "verified_removed" | "verified_risk_reduced" | "not_verified_unchanged" | "skipped_not_migrated"
    explanation: str


def verify_records(
    records: dict[str, MigrationRecord],
    current_tracking_ids: set[str],
    current_risk_by_tracking_id: dict[str, tuple[str | None, int | None]],
) -> list[VerificationResult]:
    """
    Mutates `records` in place (promoting MIGRATED -> VERIFIED where the
    evidence supports it) and returns a VerificationResult per MIGRATED
    record explaining the outcome. Records that are not currently MIGRATED
    are not touched (nothing to verify - NOT_STARTED/PLANNED/IN_PROGRESS
    haven't claimed to be done yet, and VERIFIED is already final).
    """
    results: list[VerificationResult] = []

    for tracking_id, record in records.items():
        if record.status != MigrationStatus.MIGRATED:
            continue

        if tracking_id not in current_tracking_ids:
            record.status = MigrationStatus.VERIFIED
            results.append(VerificationResult(
                tracking_id=tracking_id,
                outcome="verified_removed",
                explanation=(
                    "The original finding no longer appears in the rescan - the crypto "
                    "usage at this location was removed or changed enough that it no "
                    "longer matches. Marked VERIFIED."
                ),
            ))
            continue

        new_level, new_score = current_risk_by_tracking_id.get(tracking_id, (None, None))
        old_level = record.risk_level

        if old_level is not None and new_level is not None:
            old_rank = _RISK_LEVEL_RANK.get(old_level, -1)
            new_rank = _RISK_LEVEL_RANK.get(new_level, -1)
            if new_rank < old_rank:
                record.status = MigrationStatus.VERIFIED
                record.risk_level = new_level
                record.risk_score = new_score
                results.append(VerificationResult(
                    tracking_id=tracking_id,
                    outcome="verified_risk_reduced",
                    explanation=(
                        f"Risk level dropped from {old_level} to {new_level} on rescan. "
                        f"Marked VERIFIED."
                    ),
                ))
                continue

        results.append(VerificationResult(
            tracking_id=tracking_id,
            outcome="not_verified_unchanged",
            explanation=(
                "The finding still exists with the same or higher risk on rescan. "
                "Status remains MIGRATED, NOT VERIFIED - marking status alone is never "
                "treated as proof of a real fix."
            ),
        ))

    return results
