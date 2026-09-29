"""
main.py

Command-line entry point for the SIH26164 Cryptographic Discovery, Quantum
Risk Assessment, and Migration Tracking prototype.

    DISCOVER -> INVENTORY -> ASSESS -> PRIORITIZE -> RECOMMEND -> MIGRATE -> VERIFY

Usage:
    # Scan any local project directory (not hard-coded to sample_project):
    python main.py "D:\\some\\real\\project"
    python main.py sample_project --context sample_context/critical_long_lifetime.json

    # Update a tracked finding's migration status (TRACKING_ID comes from a
    # fresh scan's report - it is stable across scans, unlike the internal
    # per-run asset_id):
    python main.py PROJECT_PATH --set-status TRACKING_ID MIGRATED

    # Rescan and check whether MIGRATED findings can be promoted to VERIFIED:
    python main.py PROJECT_PATH --verify

This file coordinates the pipeline; it does not contain scanning, scoring,
CVSS, recommendation, or migration logic itself - see scanner/, risk_engine/,
recommendation/, and migration/ for that.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scanner import ast_analyzer, file_discovery, normalizer, pattern_detector
from scanner.models import RawFinding
from risk_engine import coverage, cvss, scorer
from risk_engine.context import ProjectContext, load_context
from risk_engine.migration import compute_tracking_id
from recommendation import rules as recommendation_rules
from migration import state as migration_state
from migration import tracker as migration_tracker
from migration.tracker import InvalidTransitionError
from migration.verifier import verify_records
from report import build_human_readable_report


def scan_and_score(project_path: str, context: ProjectContext):
    """Run Phase 1 discovery + Phase 2 scoring.
    Returns (assets, risk_by_asset_id, discovered_files, skipped)."""
    root = Path(project_path).resolve()
    discovered_files, skipped = file_discovery.discover_files(root)

    all_findings: list[RawFinding] = []
    for discovered in discovered_files:
        all_findings.extend(pattern_detector.scan_file(discovered.path))
        all_findings.extend(ast_analyzer.scan_file(discovered.path))

    assets = normalizer.normalize(all_findings, project_name=root.name)
    risk_by_asset_id = {rs.asset_id: rs for rs in scorer.score_assets(assets, context)}
    return assets, risk_by_asset_id, discovered_files, skipped


def build_report(project_path: str, context: ProjectContext, state_path: Path) -> dict:
    """Full pipeline: scan, score, sync migration state (never overwriting
    existing statuses), save the refreshed state, and assemble the report
    dict (JSON-shape) with CVSS and PQC recommendation attached per asset."""
    root = Path(project_path).resolve()
    assets, risk_by_asset_id, discovered_files, skipped = scan_and_score(project_path, context)

    existing_records = migration_state.load_state(state_path)
    synced_records = migration_tracker.sync_records(assets, risk_by_asset_id, existing_records)
    migration_state.save_state(state_path, synced_records)

    assets_out = []
    for asset in assets:
        tracking_id = compute_tracking_id(asset.file_path, asset.line_number, asset.algorithm)
        risk_score = risk_by_asset_id[asset.asset_id]
        record = synced_records.get(tracking_id)

        asset_dict = asset.to_dict()
        asset_dict["tracking_id"] = tracking_id
        asset_dict["risk_assessment"] = risk_score.to_dict()
        asset_dict["cvss_assessment"] = cvss.assess(asset).to_dict()
        asset_dict["pqc_recommendation"] = recommendation_rules.recommend_for(asset).to_dict()
        asset_dict["migration_status"] = record.to_dict() if record else None
        assets_out.append(asset_dict)

    return {
        "project": root.name,
        "scan_summary": {
            "files_scanned": len(discovered_files),
            "files_skipped": len(skipped),
            "assets_found": len(assets),
        },
        "context_used": {
            "business_criticality": context.business_criticality.value,
            "data_lifetime_years": context.data_lifetime_years,
        },
        "coverage": coverage.current_coverage().to_dict(),
        "skipped_files": [{"path": str(s.path), "reason": s.reason} for s in skipped],
        "assets": assets_out,
        "migration_state_file": str(state_path),
    }


def cmd_set_status(project_path: str, context: ProjectContext, state_path: Path, tracking_id: str, new_status: str) -> int:
    assets, risk_by_asset_id, _, _ = scan_and_score(project_path, context)
    existing_records = migration_state.load_state(state_path)
    synced_records = migration_tracker.sync_records(assets, risk_by_asset_id, existing_records)

    try:
        record = migration_tracker.set_status(synced_records, tracking_id, new_status)
    except InvalidTransitionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    migration_state.save_state(state_path, synced_records)
    print(f"Updated {tracking_id} ({record.algorithm} @ {record.file_path}:{record.line_number}) -> {record.status.value}")
    return 0


def cmd_verify(project_path: str, context: ProjectContext, state_path: Path) -> int:
    assets, risk_by_asset_id, _, _ = scan_and_score(project_path, context)
    existing_records = migration_state.load_state(state_path)

    if not existing_records:
        print("No migration state found - nothing to verify. Run a scan and --set-status first.")
        return 0

    current_tracking_ids = {
        compute_tracking_id(a.file_path, a.line_number, a.algorithm) for a in assets
    }
    current_risk_by_tracking_id = {
        compute_tracking_id(a.file_path, a.line_number, a.algorithm):
            (risk_by_asset_id[a.asset_id].risk_level, risk_by_asset_id[a.asset_id].risk_score)
        for a in assets
    }

    # IMPORTANT: verify against the PRE-sync records, using each record's
    # risk_level as it was last saved (the baseline from when MIGRATED was
    # set, or from the last verify run) - compared against the CURRENT
    # scan's risk. Syncing first would overwrite that baseline with the
    # current value before the comparison ever happened, making every
    # comparison a no-op. Sync only AFTER verification has used the old
    # baseline.
    results = verify_records(existing_records, current_tracking_ids, current_risk_by_tracking_id)
    synced_records = migration_tracker.sync_records(assets, risk_by_asset_id, existing_records)
    migration_state.save_state(state_path, synced_records)

    if not results:
        print("No MIGRATED findings to verify.")
        return 0

    print("=== Verification Results ===")
    for r in results:
        print(f"[{r.outcome}] {r.tracking_id}: {r.explanation}")
    verified_count = sum(1 for r in results if r.outcome.startswith("verified"))
    print(f"\n{verified_count}/{len(results)} MIGRATED findings promoted to VERIFIED.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Crypto Discovery + Quantum Risk Assessment + Migration "
                     "Tracking prototype. Works against ANY local project "
                     "directory - not hard-coded to sample_project."
    )
    parser.add_argument("project_path", help="Path to the project directory to scan")
    parser.add_argument("--output", "-o", default=None, help="Path to write the JSON report. Default: report.json")
    parser.add_argument("--context", "-c", default=None, help="Path to a context.json file (business_criticality, data_lifetime_years). Default: both UNKNOWN.")
    parser.add_argument("--state-file", default=None, help="Path to the migration state JSON file. Default: <project_path>/migration_state.json")
    parser.add_argument("--set-status", nargs=2, metavar=("TRACKING_ID", "STATUS"), default=None, help="Update one finding's migration status (NOT VERIFIED - see --verify).")
    parser.add_argument("--verify", action="store_true", help="Rescan and check whether MIGRATED findings can be promoted to VERIFIED.")
    parser.add_argument("--json-only", action="store_true", help="Skip the human-readable report; print only JSON.")
    args = parser.parse_args()

    try:
        context = load_context(args.context)
    except ValueError as exc:
        print(f"Error in context file: {exc}", file=sys.stderr)
        return 1

    state_path = Path(args.state_file) if args.state_file else migration_state.default_state_path(args.project_path)

    try:
        if args.set_status:
            tracking_id, new_status = args.set_status
            return cmd_set_status(args.project_path, context, state_path, tracking_id, new_status)

        if args.verify:
            return cmd_verify(args.project_path, context, state_path)

        report = build_report(args.project_path, context, state_path)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not args.json_only:
        print(build_human_readable_report(report))
        print()

    report_json = json.dumps(report, indent=2)
    output_path = Path(args.output) if args.output else Path("report.json")
    output_path.write_text(report_json, encoding="utf-8")
    print(f"(Machine-readable JSON written to {output_path})")

    if args.json_only:
        print(report_json)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
