"""
recommendation/rules.py

Deterministic, purpose-based PQC direction suggestions.

Core principle from the spec: the correct PQC replacement depends on WHY the
cryptography is used, not just which algorithm it is. RSA used for signing
needs a different replacement than RSA used for key establishment - and
critically, Phase 1's evidence often can't tell us which one we're looking
at (e.g. `rsa.generate_private_key()` alone doesn't reveal whether the key
will sign things or encrypt things). When we don't know the purpose clearly
enough, we say so explicitly rather than guessing - guessing wrong here
would be actively harmful advice.

Cited standards:
- FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
"""

from __future__ import annotations

from recommendation.models import PQCRecommendation
from scanner.models import CryptoAsset

FIPS_203 = "NIST FIPS 203 (ML-KEM)"
FIPS_204 = "NIST FIPS 204 (ML-DSA)"
FIPS_205 = "NIST FIPS 205 (SLH-DSA)"

# Purposes that clearly indicate a specific PQC category.
_SIGNATURE_PURPOSES = {"signing"}
_KEY_ESTABLISHMENT_PURPOSES = {"key_exchange"}

# Purposes that are inherently ambiguous for a given algorithm - Phase 1
# evidence alone cannot tell us the actual use (e.g. an RSA key could sign
# OR encrypt). We deliberately do NOT guess here.
_AMBIGUOUS_KEY_GENERATION_ALGORITHMS = {"RSA", "ECC"}


def recommend_for(asset: CryptoAsset) -> PQCRecommendation:
    purpose = asset.cryptographic_purpose
    algorithm = asset.algorithm

    if purpose in _SIGNATURE_PURPOSES:
        return PQCRecommendation(
            asset_id=asset.asset_id,
            applies=True,
            direction=f"{FIPS_204}, with {FIPS_205} as a conservative hash-based alternative",
            rationale=(
                f"'{algorithm}' is used for digital signatures, which is a quantum-vulnerable "
                f"use case. ML-DSA is the primary NIST-standardized PQC signature scheme; "
                f"SLH-DSA is a more conservative (larger, slower) hash-based alternative for "
                f"contexts wanting an algorithm with a different underlying hardness assumption."
            ),
            standard_reference=f"{FIPS_204}; {FIPS_205}",
        )

    if purpose in _KEY_ESTABLISHMENT_PURPOSES:
        return PQCRecommendation(
            asset_id=asset.asset_id,
            applies=True,
            direction=FIPS_203,
            rationale=(
                f"'{algorithm}' is used for key establishment/exchange, which is a "
                f"quantum-vulnerable use case. ML-KEM is the NIST-standardized PQC "
                f"key-encapsulation mechanism for this purpose."
            ),
            standard_reference=FIPS_203,
        )

    if purpose == "key_generation" and algorithm in _AMBIGUOUS_KEY_GENERATION_ALGORITHMS:
        return PQCRecommendation(
            asset_id=asset.asset_id,
            applies=False,
            direction=None,
            rationale=(
                f"'{algorithm}' key generation was detected, but the scanner cannot determine "
                f"from this evidence alone whether the key is used for signing (→ ML-DSA/SLH-DSA) "
                f"or key establishment (→ ML-KEM). Recommending a specific PQC direction without "
                f"knowing the actual use would be a guess, not documented guidance. Manual review "
                f"of how this key is subsequently used is needed."
            ),
            standard_reference=None,
        )

    if algorithm == "AES":
        return PQCRecommendation(
            asset_id=asset.asset_id,
            applies=False,
            direction=None,
            rationale=(
                "AES is a symmetric algorithm. It is not replaced by a PQC family the way "
                "RSA/ECC are - symmetric algorithms are affected by Grover's algorithm, which "
                "roughly halves effective key strength, so current guidance is to ensure "
                "sufficient key length (e.g. AES-256) rather than migrate to a different "
                "algorithm family."
            ),
            standard_reference="NIST IR 8547 (draft) - symmetric algorithm guidance",
        )

    if algorithm in ("SHA-256", "SHA-1", "MD5"):
        if algorithm == "SHA-256":
            rationale = (
                "SHA-256 is a hash function, not a public-key algorithm - it is not part of "
                "the PQC migration (which addresses quantum-vulnerable public-key crypto). "
                "It remains currently approved."
            )
        else:
            rationale = (
                f"{algorithm} should be replaced with a currently-approved hash "
                f"(e.g. SHA-256) for CLASSICAL security reasons - this is unrelated to "
                f"quantum computing or PQC migration."
            )
        return PQCRecommendation(
            asset_id=asset.asset_id,
            applies=False,
            direction=None,
            rationale=rationale,
            standard_reference=None,
        )

    return PQCRecommendation(
        asset_id=asset.asset_id,
        applies=False,
        direction=None,
        rationale=f"No PQC recommendation rule currently covers algorithm '{algorithm}' with purpose '{purpose}'.",
        standard_reference=None,
    )
