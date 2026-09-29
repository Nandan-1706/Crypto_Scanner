"""Phase 4: migration tracking, persistence, and rescan-based verification.

Reuses risk_engine.migration for the data model (MigrationStatus,
MigrationRecord, compute_tracking_id) - this package does NOT define a
second model, only the orchestration logic around it:
  - state.py:    load/save migration_state.json
  - tracker.py:  sync records against a fresh scan, apply status changes
                 (with valid-transition checks)
  - verifier.py: rescan-based VERIFIED promotion logic
"""
