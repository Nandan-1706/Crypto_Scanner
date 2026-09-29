"""
risk_engine/cvss.py

CVSS (Common Vulnerability Scoring System) is a SEPARATE, INDEPENDENT
module from the project's own crypto-migration risk score (scorer.py).
Nothing else in this codebase depends on this module's internals - it has
one clean entry point, assess(), and everything downstream only sees its
output shape (CVSSAssessment).

WHY THIS IS SEPARATE FROM algorithm_risk / scorer.py:
CVSS scores the severity of a specific, contextualized VULNERABILITY (e.g.
"CVE-2023-XXXX: an out-of-bounds write in libfoo 1.2 allowing remote code
execution"). It is not designed to score "this code uses MD5" in the
abstract - using an old algorithm is a *weakness pattern*, not itself a
scored vulnerability instance. Assigning an official-looking CVSS score to
every RSA/MD5/AES finding this scanner produces would be fabricating
severity data we don't have a basis for.

WHAT THIS MODULE ACTUALLY DOES (Phase 4):
For every CryptoAsset, assess() honestly reports that CVSS is NOT
APPLICABLE, because static discovery of "an algorithm is used here" is not
the same as "a specific vulnerability instance with known exploitability
characteristics exists here." No numeric score, severity label, or vector
string is fabricated.

WHAT A FUTURE PHASE COULD ADD (documented, not built here):
If this tool is ever extended to cross-reference discovered
library/dependency VERSIONS against a real CVE database (e.g. the NVD),
THAT would give genuine vulnerability context - a specific CVE for a
specific library version - and a real CVSS v4.0 vector/score could be
looked up (not invented) from that CVE's published data. This module's
`CVSSAssessment` shape is intentionally already able to carry a real
score if that data source is added later - see the `applies=True` fields
below, which stay unpopulated in Phase 4.
"""

from __future__ import annotations

from dataclasses import dataclass

from scanner.models import CryptoAsset

_NOT_APPLICABLE_RATIONALE = (
    "CVSS scores a specific, contextualized vulnerability (e.g. a CVE with a known "
    "exploit path), not the abstract presence of an algorithm in code. This scanner "
    "performs static discovery only and has no vulnerability-instance data (no CVE "
    "cross-reference) for this finding, so no CVSS score is assigned. See the "
    "project's own crypto-migration risk_assessment field for a crypto-specific, "
    "explainable risk verdict instead - that is a DIFFERENT, non-CVSS methodology."
)


@dataclass
class CVSSAssessment:
    asset_id: str
    applies: bool                  # True only if real vulnerability-instance data exists (never true in Phase 4)
    score: float | None            # 0.0-10.0, only ever populated from a REAL CVE's published CVSS data
    severity: str | None           # NONE/LOW/MEDIUM/HIGH/CRITICAL per CVSS severity ratings, same rule as score
    vector: str | None             # CVSS vector string (e.g. "CVSS:4.0/AV:N/AC:L/..."), same rule as score
    cve_reference: str | None      # the specific CVE this assessment is based on, if any
    rationale: str

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "applies": self.applies,
            "score": self.score,
            "severity": self.severity,
            "vector": self.vector,
            "cve_reference": self.cve_reference,
            "rationale": self.rationale,
        }


def assess(asset: CryptoAsset) -> CVSSAssessment:
    """
    The ONLY entry point this module exposes. In Phase 4, this ALWAYS
    returns applies=False - see the module docstring for why. This
    function signature is stable so that a future phase adding real CVE
    cross-referencing can change the implementation without changing how
    the rest of the system calls it.
    """
    return CVSSAssessment(
        asset_id=asset.asset_id,
        applies=False,
        score=None,
        severity=None,
        vector=None,
        cve_reference=None,
        rationale=_NOT_APPLICABLE_RATIONALE,
    )
