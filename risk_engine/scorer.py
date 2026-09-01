"""
risk_engine/scorer.py

Combines several inputs into ONE final, explainable RiskScore per asset:

  - algorithm_risk (classical_risk + quantum_risk)  <- from the EXISTING,
      unchanged risk_engine/engine.py + rules.py (NIST-cited)
  - business_criticality                             <- user-supplied, via context.py
  - data_lifetime                                     <- user-supplied, via context.py
  - migration_effort_hint                              <- derived from real evidence
      (how many places in the project use this algorithm) - reported, but
      NOT part of the numeric score, since more occurrences doesn't make an
      asset more "risky," just harder to fix
  - confidence                                          <- from Phase 1, real evidence

The formula, thresholds, and priority rules below are OUR OWN documented
methodology - not a cited standard - and are clearly labeled as such. Only
the algorithm_risk component (A) traces back to NIST SP 800-131A / IR 8547.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from scanner.models import Confidence, CryptoAsset
from risk_engine import engine as algorithm_risk
from risk_engine import mosca
from risk_engine.context import BusinessCriticality, DataLifetimeBand, ProjectContext
from risk_engine.models import ClassicalRiskLevel, QuantumRiskLevel, RiskAssessment, ScoringStatus

# --- Point tables (our own documented methodology) -------------------------

_CLASSICAL_POINTS = {
    ClassicalRiskLevel.CRITICAL: 25,
    ClassicalRiskLevel.HIGH: 18,
    ClassicalRiskLevel.ACCEPTABLE_TODAY: 5,
    ClassicalRiskLevel.UNKNOWN_INSUFFICIENT_DATA: 10,
}
_QUANTUM_POINTS = {
    QuantumRiskLevel.HIGH: 15,
    QuantumRiskLevel.LOW: 2,
    QuantumRiskLevel.NOT_APPLICABLE: 0,
    QuantumRiskLevel.UNKNOWN_INSUFFICIENT_DATA: 7,
}
_CRITICALITY_POINTS = {
    BusinessCriticality.LOW: 5,
    BusinessCriticality.MEDIUM: 12,
    BusinessCriticality.HIGH: 20,
    BusinessCriticality.CRITICAL: 25,
    BusinessCriticality.UNKNOWN: 10,  # visible neutral default - never silently LOW or HIGH
}
# NOTE: data-lifetime urgency points (component C) come from risk_engine.mosca,
# not a local table here - see mosca.py for the documented heuristic.
_CONFIDENCE_MULTIPLIER = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.85,
    # Confidence.LOW assets never reach the scorer - engine.py already skips them
}

_LEVEL_THRESHOLDS = [  # (minimum score, level) - our own bucketing, not a standard
    (80, "CRITICAL"),
    (60, "HIGH"),
    (35, "MEDIUM"),
    (0, "LOW"),
]

_EFFORT_THRESHOLDS = [  # (minimum occurrence count, hint)
    (10, "HIGH"),
    (3, "MEDIUM"),
    (1, "LOW"),
]


@dataclass
class RiskScore:
    asset_id: str
    scoring_status: str               # "scored" or "skipped_low_confidence"
    business_criticality: str
    data_lifetime_years: int | None
    algorithm_risk: RiskAssessment | None  # None only if skipped for low confidence
    migration_effort_hint: str | None       # LOW/MEDIUM/HIGH, or None if skipped
    risk_score: int | None
    risk_level: str | None
    priority: int | None
    reasons: list[str]
    recommended_action: str

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "scoring_status": self.scoring_status,
            "business_criticality": self.business_criticality,
            "data_lifetime_years": self.data_lifetime_years,
            "algorithm_risk": self.algorithm_risk.to_dict() if self.algorithm_risk else None,
            "migration_effort_hint": self.migration_effort_hint,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "priority": self.priority,
            "reasons": self.reasons,
            "recommended_action": self.recommended_action,
        }


def score_assets(assets: list[CryptoAsset], context: ProjectContext) -> list[RiskScore]:
    """Score every asset. `context` is applied project-wide (see context.py
    docstring for why per-asset context is a documented future extension,
    not built now)."""
    algorithm_assessments = {ra.asset_id: ra for ra in algorithm_risk.assess(assets)}
    effort_hints = _compute_effort_hints(assets)

    return [_score_one(asset, algorithm_assessments[asset.asset_id], context, effort_hints) for asset in assets]


def _compute_effort_hints(assets: list[CryptoAsset]) -> dict[str, str]:
    """
    migration_effort_hint is a REAL, evidence-based signal (not invented):
    how many places in the project use the same algorithm. More occurrences
    is a reasonable proxy for "more places to change," though it is
    explicitly NOT a real engineering estimate - just a rough hint.
    """
    counts = Counter(a.algorithm for a in assets)
    hints: dict[str, str] = {}
    for asset in assets:
        occurrence_count = counts[asset.algorithm]
        hint = "LOW"
        for min_count, label in _EFFORT_THRESHOLDS:
            if occurrence_count >= min_count:
                hint = label
                break
        hints[asset.asset_id] = hint
    return hints


def _score_one(
    asset: CryptoAsset,
    assessment: RiskAssessment,
    context: ProjectContext,
    effort_hints: dict[str, str],
) -> RiskScore:
    if assessment.scoring_status == ScoringStatus.SKIPPED_LOW_CONFIDENCE:
        return RiskScore(
            asset_id=asset.asset_id,
            scoring_status="skipped_low_confidence",
            business_criticality=context.business_criticality.value,
            data_lifetime_years=context.data_lifetime_years,
            algorithm_risk=assessment,
            migration_effort_hint=None,
            risk_score=None,
            risk_level=None,
            priority=None,
            reasons=["Not scored: LOW-confidence evidence (see algorithm_risk.rationale)."],
            recommended_action="Manually review this finding before drawing any conclusion.",
        )

    a_points = _CLASSICAL_POINTS[assessment.classical_risk] + _QUANTUM_POINTS[assessment.quantum_risk]
    b_points = _CRITICALITY_POINTS[context.business_criticality]
    mosca_urgency = mosca.compute_urgency(context.data_lifetime_band)
    c_points = mosca_urgency.urgency_points
    multiplier = _CONFIDENCE_MULTIPLIER[asset.confidence]

    raw_score = min(100, a_points + b_points + c_points)
    final_score = round(raw_score * multiplier)

    risk_level = next(level for min_score, level in _LEVEL_THRESHOLDS if final_score >= min_score)

    quantum_vulnerable = assessment.quantum_risk == QuantumRiskLevel.HIGH
    priority = _compute_priority(
        risk_level=risk_level,
        business_criticality=context.business_criticality,
        quantum_vulnerable=quantum_vulnerable,
    )

    reasons = _build_reasons(asset, assessment, context, quantum_vulnerable)
    recommended_action = _build_recommended_action(risk_level, quantum_vulnerable)

    return RiskScore(
        asset_id=asset.asset_id,
        scoring_status="scored",
        business_criticality=context.business_criticality.value,
        data_lifetime_years=context.data_lifetime_years,
        algorithm_risk=assessment,
        migration_effort_hint=effort_hints[asset.asset_id],
        risk_score=final_score,
        risk_level=risk_level,
        priority=priority,
        reasons=reasons,
        recommended_action=recommended_action,
    )


def _compute_priority(risk_level: str, business_criticality: BusinessCriticality, quantum_vulnerable: bool) -> int:
    """Deterministic priority, matching the spec's example table directly."""
    if (
        business_criticality == BusinessCriticality.CRITICAL
        and quantum_vulnerable
        and risk_level in ("CRITICAL", "HIGH")
    ):
        return 1
    if business_criticality in (BusinessCriticality.CRITICAL, BusinessCriticality.HIGH) and quantum_vulnerable:
        return 2
    if risk_level in ("MEDIUM", "HIGH"):
        return 3
    return 4


def _build_reasons(
    asset: CryptoAsset,
    assessment: RiskAssessment,
    context: ProjectContext,
    quantum_vulnerable: bool,
) -> list[str]:
    reasons: list[str] = []

    if quantum_vulnerable:
        reasons.append(f"{asset.algorithm} is a quantum-vulnerable algorithm ({assessment.standard_reference}).")
    if assessment.classical_risk == ClassicalRiskLevel.CRITICAL:
        reasons.append(f"{asset.algorithm} is considered broken/disallowed under current guidance, independent of quantum risk.")
    elif assessment.classical_risk == ClassicalRiskLevel.HIGH:
        reasons.append(f"{asset.algorithm} is deprecated under current guidance.")

    if context.business_criticality == BusinessCriticality.UNKNOWN:
        reasons.append("Business criticality was not provided - scored with a neutral default. Provide context.json for an accurate priority.")
    else:
        reasons.append(f"Application component is marked {context.business_criticality.value} business criticality.")

    if context.data_lifetime_years is None:
        reasons.append("Data lifetime was not provided - migration urgency contribution is 0. Provide context.json for an accurate priority.")
    elif context.data_lifetime_band in (DataLifetimeBand.TEN_TO_14_YEARS, DataLifetimeBand.FIFTEEN_PLUS_YEARS):
        reasons.append(f"Protected data has a long lifetime ({context.data_lifetime_years} years) - relevant to harvest-now-decrypt-later exposure.")

    if asset.confidence == Confidence.MEDIUM:
        reasons.append("Evidence confidence is MEDIUM (pattern-matched, not AST-confirmed) - score reduced accordingly.")

    return reasons


def _build_recommended_action(risk_level: str, quantum_vulnerable: bool) -> str:
    if risk_level == "CRITICAL":
        return "Begin PQC/hybrid migration planning now; treat as a near-term priority."
    if risk_level == "HIGH":
        return "Plan migration in the near-to-medium term; confirm business criticality and data lifetime if not yet provided."
    if risk_level == "MEDIUM" and quantum_vulnerable:
        return "Track for future migration planning; not urgent today but will require action ahead of NIST's proposed 2030-2035 transition window."
    if risk_level == "MEDIUM":
        return "Review and remediate as part of normal maintenance."
    return "No immediate action required based on current evidence."
