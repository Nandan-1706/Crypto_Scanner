"""
main.py

Command-line entry point for the SIH26164 Cryptographic Discovery and
Quantum Risk Assessment prototype.

Usage:
    python main.py <project_directory> [--output report.json] [--context context.json]

Pipeline (Phase 1 + Phase 2):
    project directory
        -> file_discovery.discover_files()
        -> pattern_detector.scan_file() + ast_analyzer.scan_file() (per file)
        -> normalizer.normalize()                                    [Phase 1 ends here]
        -> context.load_context()            (business criticality / data lifetime)
        -> scorer.score_assets()              (risk_score, risk_level, priority, reasons)
        -> recommendation.rules.recommend_for() (purpose-based PQC direction, where applicable)
        -> migration.default_migration_record() (always NOT_STARTED in this phase)
        -> coverage.current_coverage()
        -> JSON report

This file deliberately contains almost no logic of its own - it just calls
the other modules in order and assembles the final report dict.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scanner import ast_analyzer, file_discovery, normalizer, pattern_detector
from scanner.models import RawFinding
from risk_engine import coverage, migration, scorer
from risk_engine.context import ProjectContext, load_context
from recommendation import rules as recommendation_rules


def run_scan(project_path: str, context: ProjectContext | None = None) -> dict:
    """Run the full Phase 1 + Phase 2 pipeline and return the report as a plain dict."""
    root = Path(project_path).resolve()
    project_name = root.name
    context = context or ProjectContext.unknown()

    discovered_files, skipped = file_discovery.discover_files(root)

    all_findings: list[RawFinding] = []
    for discovered in discovered_files:
        all_findings.extend(pattern_detector.scan_file(discovered.path))
        all_findings.extend(ast_analyzer.scan_file(discovered.path))

    assets = normalizer.normalize(all_findings, project_name=project_name)
    risk_scores = {rs.asset_id: rs for rs in scorer.score_assets(assets, context)}

    assets_with_risk = []
    for asset in assets:
        asset_dict = asset.to_dict()
        risk_score = risk_scores[asset.asset_id]
        asset_dict["risk_assessment"] = risk_score.to_dict()
        asset_dict["migration_status"] = migration.default_migration_record(asset.asset_id).to_dict()
        asset_dict["pqc_recommendation"] = recommendation_rules.recommend_for(asset).to_dict()
        assets_with_risk.append(asset_dict)

    report = {
        "project": project_name,
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
        "skipped_files": [
            {"path": str(s.path), "reason": s.reason} for s in skipped
        ],
        "assets": assets_with_risk,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Crypto Discovery + Quantum Risk Assessment prototype - "
                     "discovers cryptographic indicators in a Python project, "
                     "scores their risk, and outputs a JSON report."
    )
    parser.add_argument("project_path", help="Path to the project directory to scan")
    parser.add_argument(
        "--output", "-o",
        help="Path to write the JSON report to. If omitted, prints to stdout.",
        default=None,
    )
    parser.add_argument(
        "--context", "-c",
        help="Path to a context.json file with business_criticality and "
             "data_lifetime_years. If omitted, both are treated as UNKNOWN.",
        default=None,
    )
    args = parser.parse_args()

    try:
        context = load_context(args.context)
        report = run_scan(args.project_path, context=context)
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error in context file: {exc}", file=sys.stderr)
        return 1

    report_json = json.dumps(report, indent=2)

    if args.output:
        Path(args.output).write_text(report_json, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(report_json)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
