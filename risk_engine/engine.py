"""
risk_engine/engine.py

Applies the rule table in rules.py to a list of CryptoAssets, producing a
RiskAssessment for each one.

Two things this module deliberately does NOT do:
  1. It never scores a LOW-confidence asset. Per Phase 1's documented
     limitation, LOW-confidence findings often come from comments/docstrings/
     unrelated text - scoring those as if they were real, risky code would
     be inventing a security claim not backed by real evidence.
  2. It never invents a risk level for an algorithm/condition the rule table
     doesn't cover. "No matching rule" produces an explicit
     unknown_insufficient_data result with a clear rationale, not a guess.
"""

from __future__ import annotations

from scanner.models import Confidence, CryptoAsset
from risk_engine.models import (
    ClassicalRiskLevel,
    QuantumRiskLevel,
    RiskAssessment,
    ScoringStatus,
)
from risk_engine.rules import find_matching_rule

_NO_RULE_REFERENCE = "No matching rule in current rule table (risk_engine/rules.py)"


def assess(assets: list[CryptoAsset]) -> list[RiskAssessment]:
    """Produce one RiskAssessment per CryptoAsset in `assets`."""
    return [_assess_one(asset) for asset in assets]


def _assess_one(asset: CryptoAsset) -> RiskAssessment:
    if asset.confidence == Confidence.LOW:
        return RiskAssessment(
            asset_id=asset.asset_id,
            scoring_status=ScoringStatus.SKIPPED_LOW_CONFIDENCE,
            classical_risk=ClassicalRiskLevel.UNKNOWN_INSUFFICIENT_DATA,
            quantum_risk=QuantumRiskLevel.UNKNOWN_INSUFFICIENT_DATA,
            rule_id="SKIPPED-LOW-CONFIDENCE",
            rationale=(
                "This finding has LOW confidence (a raw text/keyword match, not "
                "confirmed by AST analysis). It has not been risk-scored because "
                "the underlying evidence is not reliable enough to support a "
                "security judgment - it may be a comment, string, or unrelated "
                "text rather than real cryptographic usage. Manual review recommended."
            ),
            standard_reference="N/A - not scored",
        )

    rule = find_matching_rule(asset.algorithm, asset.key_size)

    if rule is None:
        return RiskAssessment(
            asset_id=asset.asset_id,
            scoring_status=ScoringStatus.SCORED,
            classical_risk=ClassicalRiskLevel.UNKNOWN_INSUFFICIENT_DATA,
            quantum_risk=QuantumRiskLevel.UNKNOWN_INSUFFICIENT_DATA,
            rule_id="NO-MATCHING-RULE",
            rationale=(
                f"No risk rule currently covers algorithm '{asset.algorithm}' "
                f"(this may be a generic library/import indicator rather than a "
                f"specific algorithm, or an algorithm not yet added to the rule table)."
            ),
            standard_reference=_NO_RULE_REFERENCE,
        )

    return RiskAssessment(
        asset_id=asset.asset_id,
        scoring_status=ScoringStatus.SCORED,
        classical_risk=rule.classical_risk,
        quantum_risk=rule.quantum_risk,
        rule_id=rule.rule_id,
        rationale=rule.rationale,
        standard_reference=rule.standard_reference,
    )
