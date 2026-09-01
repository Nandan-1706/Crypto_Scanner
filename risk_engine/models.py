"""
risk_engine/models.py

Defines the RiskAssessment record - the output of the risk engine for one
CryptoAsset.

Two separate, independently-labeled risk dimensions are used rather than one
blended score, because "is this broken today" and "will this need to change
because of quantum computers" are genuinely different questions with
different urgency and different remediation paths. Collapsing them into one
number would hide information a real user needs to prioritize correctly.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ClassicalRiskLevel(str, Enum):
    """How risky an asset is TODAY, ignoring quantum computers entirely."""
    CRITICAL = "critical"                              # broken/disallowed now
    HIGH = "high"                                        # deprecated, phasing out now
    ACCEPTABLE_TODAY = "acceptable_today"                  # currently approved
    UNKNOWN_INSUFFICIENT_DATA = "unknown_insufficient_data"  # can't assess (e.g. key size unknown)


class QuantumRiskLevel(str, Enum):
    """How exposed an asset is to future quantum computers (Shor's/Grover's algorithms)."""
    HIGH = "high"                                          # quantum-vulnerable per NIST IR 8547
    LOW = "low"                                             # not on IR 8547's deprecation schedule
    NOT_APPLICABLE = "not_applicable"                        # question doesn't apply (e.g. already broken classically)
    UNKNOWN_INSUFFICIENT_DATA = "unknown_insufficient_data"    # can't assess


class ScoringStatus(str, Enum):
    """Whether this asset was actually scored, or why it wasn't."""
    SCORED = "scored"
    SKIPPED_LOW_CONFIDENCE = "skipped_low_confidence"  # LOW-confidence evidence - not scored, flagged for manual review instead


@dataclass
class RiskAssessment:
    """The risk engine's verdict for one CryptoAsset, with full traceability
    back to the rule and standard that produced it."""
    asset_id: str                     # links back to the CryptoAsset this assessment is about
    scoring_status: ScoringStatus
    classical_risk: ClassicalRiskLevel
    quantum_risk: QuantumRiskLevel
    rule_id: str                       # which rule in rules.py fired
    rationale: str                       # human-readable explanation
    standard_reference: str                # e.g. "NIST SP 800-131A Rev. 2" - never left blank for a scored asset

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "scoring_status": self.scoring_status.value,
            "classical_risk": self.classical_risk.value,
            "quantum_risk": self.quantum_risk.value,
            "rule_id": self.rule_id,
            "rationale": self.rationale,
            "standard_reference": self.standard_reference,
        }
