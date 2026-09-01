"""
risk_engine/rules.py

The rule table that drives all risk scoring. This is deliberately written as
PLAIN DATA (a list of Rule objects), not procedural logic, so every rule can
be read, reviewed, and challenged on its own - and so the "documented
standards" requirement is enforced by construction: every rule requires a
standard_reference field, there is no code path that produces a risk level
without one.

IMPORTANT - accuracy and currency of these rules:
- NIST SP 800-131A Rev. 2 (2019) is FINALIZED guidance and is the basis for
  all `classical_risk` verdicts below.
- NIST IR 8547 (Initial Public Draft, Nov 2024) is the basis for all
  `quantum_risk` verdicts below. It is a DRAFT, not yet a finalized
  standard - this is reflected in the standard_reference text for every
  quantum-risk rule, and should be re-verified against NIST's site before
  this tool is used for anything beyond a hackathon prototype.
- This table reflects standards research done as of August 2026. Standards
  in this space (especially PQC-related ones) are actively evolving -
  the table should be revisited periodically, not treated as permanent.

Engine.py is the ONLY consumer of this file - it never invents a risk level
that isn't backed by a Rule here.
"""

from __future__ import annotations

from dataclasses import dataclass

from risk_engine.models import ClassicalRiskLevel, QuantumRiskLevel

SP_800_131A_REV2 = "NIST SP 800-131A Rev. 2 (2019, finalized)"
SP_800_131A_REV3_DRAFT = "NIST SP 800-131A Rev. 3 (draft, not yet finalized)"
IR_8547_DRAFT = "NIST IR 8547 Initial Public Draft (Nov 2024, not yet finalized)"
NOT_NIST_APPROVED = "Not a NIST-approved algorithm (outside FIPS approval scope)"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    algorithm: str                     # matches CryptoAsset.algorithm
    # condition on key_size: (min_inclusive, max_inclusive) in bits, or None for "any/unknown"
    key_size_min: int | None
    key_size_max: int | None
    requires_known_key_size: bool        # if True and key_size is None, this rule does not apply - falls through to the "unknown" rule instead
    classical_risk: ClassicalRiskLevel
    quantum_risk: QuantumRiskLevel
    rationale: str
    standard_reference: str


# Rules are checked in order; the first matching rule wins. More specific
# rules (with key-size conditions) are listed before their fallback/unknown
# counterparts.
RULES: list[Rule] = [
    Rule(
        rule_id="MD5-001",
        algorithm="MD5",
        key_size_min=None, key_size_max=None, requires_known_key_size=False,
        classical_risk=ClassicalRiskLevel.CRITICAL,
        quantum_risk=QuantumRiskLevel.NOT_APPLICABLE,
        rationale="MD5 is not a NIST-approved algorithm and has known practical collision attacks; it should not be used for any security purpose.",
        standard_reference=NOT_NIST_APPROVED,
    ),
    Rule(
        rule_id="SHA1-001",
        algorithm="SHA-1",
        key_size_min=None, key_size_max=None, requires_known_key_size=False,
        classical_risk=ClassicalRiskLevel.HIGH,
        quantum_risk=QuantumRiskLevel.NOT_APPLICABLE,
        rationale="SHA-1 is deprecated through 2030 and disallowed thereafter for security-relevant use.",
        standard_reference=SP_800_131A_REV3_DRAFT,
    ),
    Rule(
        rule_id="RSA-WEAK-001",
        algorithm="RSA",
        key_size_min=0, key_size_max=2047, requires_known_key_size=True,
        classical_risk=ClassicalRiskLevel.CRITICAL,
        quantum_risk=QuantumRiskLevel.HIGH,
        rationale="RSA with modulus under 2048 bits is disallowed under current NIST guidance, independent of quantum considerations.",
        standard_reference=f"{SP_800_131A_REV2}; {IR_8547_DRAFT}",
    ),
    Rule(
        rule_id="RSA-OK-TODAY-001",
        algorithm="RSA",
        key_size_min=2048, key_size_max=None, requires_known_key_size=True,
        classical_risk=ClassicalRiskLevel.ACCEPTABLE_TODAY,
        quantum_risk=QuantumRiskLevel.HIGH,
        rationale="RSA at 2048 bits or larger is currently approved, but RSA is a quantum-vulnerable public-key algorithm proposed for deprecation after 2030 and disallowance after 2035, regardless of key size.",
        standard_reference=f"{SP_800_131A_REV2}; {IR_8547_DRAFT}",
    ),
    Rule(
        rule_id="RSA-UNKNOWN-SIZE-001",
        algorithm="RSA",
        key_size_min=None, key_size_max=None, requires_known_key_size=False,
        classical_risk=ClassicalRiskLevel.UNKNOWN_INSUFFICIENT_DATA,
        quantum_risk=QuantumRiskLevel.HIGH,
        rationale="Key size was not determinable from the scanned code, so current-day (classical) risk cannot be assessed. RSA is quantum-vulnerable regardless of key size.",
        standard_reference=f"{SP_800_131A_REV2}; {IR_8547_DRAFT}",
    ),
    Rule(
        rule_id="ECC-GENERIC-001",
        algorithm="ECC",
        key_size_min=None, key_size_max=None, requires_known_key_size=False,
        classical_risk=ClassicalRiskLevel.ACCEPTABLE_TODAY,
        quantum_risk=QuantumRiskLevel.HIGH,
        rationale="Elliptic-curve cryptography using NIST-approved curves is currently approved, but is a quantum-vulnerable algorithm family proposed for deprecation after 2030 and disallowance after 2035.",
        standard_reference=f"{SP_800_131A_REV2}; {IR_8547_DRAFT}",
    ),
    Rule(
        rule_id="ECDSA-001",
        algorithm="ECDSA",
        key_size_min=None, key_size_max=None, requires_known_key_size=False,
        classical_risk=ClassicalRiskLevel.ACCEPTABLE_TODAY,
        quantum_risk=QuantumRiskLevel.HIGH,
        rationale="ECDSA is currently approved, but is a quantum-vulnerable signature algorithm proposed for deprecation after 2030 and disallowance after 2035.",
        standard_reference=f"{SP_800_131A_REV2}; {IR_8547_DRAFT}",
    ),
    Rule(
        rule_id="ECDH-001",
        algorithm="ECDH",
        key_size_min=None, key_size_max=None, requires_known_key_size=False,
        classical_risk=ClassicalRiskLevel.ACCEPTABLE_TODAY,
        quantum_risk=QuantumRiskLevel.HIGH,
        rationale="ECDH is currently approved, but is a quantum-vulnerable key-establishment algorithm proposed for deprecation after 2030 and disallowance after 2035.",
        standard_reference=f"{SP_800_131A_REV2}; {IR_8547_DRAFT}",
    ),
    Rule(
        rule_id="AES-001",
        algorithm="AES",
        key_size_min=None, key_size_max=None, requires_known_key_size=False,
        classical_risk=ClassicalRiskLevel.ACCEPTABLE_TODAY,
        quantum_risk=QuantumRiskLevel.LOW,
        rationale="AES is currently approved and is not on NIST IR 8547's quantum-vulnerable deprecation schedule (symmetric algorithms are affected by Grover's algorithm, not Shor's, and are addressed via key-size guidance rather than full deprecation).",
        standard_reference=f"{SP_800_131A_REV2}; {IR_8547_DRAFT}",
    ),
    Rule(
        rule_id="SHA256-001",
        algorithm="SHA-256",
        key_size_min=None, key_size_max=None, requires_known_key_size=False,
        classical_risk=ClassicalRiskLevel.ACCEPTABLE_TODAY,
        quantum_risk=QuantumRiskLevel.LOW,
        rationale="SHA-256 is currently approved and is not on NIST IR 8547's quantum-vulnerable deprecation schedule.",
        standard_reference=f"{SP_800_131A_REV2}; {IR_8547_DRAFT}",
    ),
]

# Algorithms for which we deliberately have no scoring rule - e.g. generic
# library/import indicators that don't identify a specific algorithm. These
# are intentionally NOT given a fabricated risk level.
UNSCOREABLE_ALGORITHMS = {"cryptography_library", "cryptography.hazmat", "hashlib"}


def find_matching_rule(algorithm: str, key_size: int | None) -> Rule | None:
    """
    Return the first Rule that matches the given algorithm and key_size, or
    None if no rule applies (this includes UNSCOREABLE_ALGORITHMS, and any
    algorithm this table simply doesn't cover yet).
    """
    if algorithm in UNSCOREABLE_ALGORITHMS:
        return None

    for rule in RULES:
        if rule.algorithm != algorithm:
            continue
        if rule.requires_known_key_size and key_size is None:
            continue
        if rule.key_size_min is not None and (key_size is None or key_size < rule.key_size_min):
            continue
        if rule.key_size_max is not None and (key_size is None or key_size > rule.key_size_max):
            continue
        return rule

    return None
