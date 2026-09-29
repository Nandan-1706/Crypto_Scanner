"""
report.py

Builds the concise, presentation-ready human-readable terminal report from
the machine-readable report dict main.py already assembles. Kept separate
from main.py so "how we format the demo output" stays independent of "how
we orchestrate the pipeline" - main.py stays a coordinator, not a giant file.
"""

from __future__ import annotations

from risk_engine.migration import MigrationStatus

_RISK_LEVELS_IN_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_TOP_N = 5


def build_human_readable_report(report: dict) -> str:
    lines: list[str] = []
    assets = report["assets"]
    scored = [a for a in assets if a["risk_assessment"]["scoring_status"] == "scored"]

    lines += _header(report, len(assets))
    lines += _risk_level_counts(scored)
    lines += ["---", ""]
    lines += _top_priorities(scored)
    lines += ["## MIGRATION SUMMARY", ""]
    lines += _migration_summary(assets)
    lines += ["---", ""]
    lines += _coverage_section(report["coverage"])
    lines += _disclaimers()

    return "\n".join(lines)


def _header(report: dict, asset_count: int) -> list[str]:
    return [
        "=" * 50,
        "CRYPTOGRAPHIC RISK REPORT",
        "=" * 50,
        "",
        f"Project: {report['project']}",
        "",
        f"Assets Found: {asset_count}",
        "",
    ]


def _risk_level_counts(scored: list[dict]) -> list[str]:
    counts = {level: 0 for level in _RISK_LEVELS_IN_ORDER}
    for a in scored:
        level = a["risk_assessment"]["risk_level"]
        if level in counts:
            counts[level] += 1
    lines = [f"{level}: {counts[level]}" for level in _RISK_LEVELS_IN_ORDER]
    lines.append("")
    return lines


def _top_priorities(scored: list[dict]) -> list[str]:
    lines = ["## TOP PRIORITIES", ""]
    ranked = sorted(
        scored,
        key=lambda a: (a["risk_assessment"]["priority"] or 99, -(a["risk_assessment"]["risk_score"] or 0)),
    )
    for a in ranked[:_TOP_N]:
        ra = a["risk_assessment"]
        rec = a.get("pqc_recommendation", {})
        lifetime = ra["data_lifetime_years"]

        lines += [
            f"Asset: {a['asset_id']}",
            f"Tracking ID: {a.get('tracking_id', 'n/a')}",
            f"Algorithm: {a['algorithm']}",
            f"Key Size: {a['key_size'] if a['key_size'] is not None else 'UNKNOWN'}",
            f"File: {a['file_path']}:{a['line_number']}",
            f"Risk Score: {ra['risk_score']}",
            f"Risk Level: {ra['risk_level']}",
            f"Priority: {ra['priority']}",
            f"Quantum Risk: {ra['algorithm_risk']['quantum_risk']}",
            f"Business Criticality: {ra['business_criticality']}",
            f"Data Lifetime: {lifetime if lifetime is not None else 'UNKNOWN'} years",
            "",
            "Migration Recommendation:",
            f"  {rec.get('direction') or rec.get('rationale', 'No specific recommendation available.')}",
            "",
            "Migration Status:",
            f"  {a.get('migration_status', {}).get('status', 'NOT_STARTED')}",
            "",
            "---",
            "",
        ]
    if not ranked:
        lines += ["(No scored assets to prioritize.)", ""]
    return lines


def _migration_summary(assets: list[dict]) -> list[str]:
    counts = {s.value: 0 for s in MigrationStatus}
    for a in assets:
        status = a.get("migration_status", {}).get("status", "NOT_STARTED")
        counts[status] = counts.get(status, 0) + 1
    lines = [f"{status.value}: {counts[status.value]}" for status in MigrationStatus]
    lines.append("")
    return lines


def _coverage_section(coverage: dict) -> list[str]:
    lines = ["## COVERAGE", "", "Python source: SCANNED"]
    for item in coverage.get("not_scanned", []):
        short_label = item.split(" - ")[0].split(" (")[0]
        lines.append(f"{short_label}: NOT SCANNED")
    lines.append("")
    return lines


def _disclaimers() -> list[str]:
    return [
        "---",
        "",
        "NOTE: Migration recommendations above describe a migration DIRECTION only - ",
        "this tool never performs automatic code changes. Risk scores are this",
        "project's own methodology, not an official NIST or CVSS score - see the JSON",
        "output's risk_assessment.algorithm_risk.standard_reference and cvss_assessment",
        "fields for exact citations and applicability per asset.",
        "",
    ]
