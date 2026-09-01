"""
recommendation/models.py

The output shape of the recommendation layer - one PQCRecommendation per
CryptoAsset that a rule actually covers.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PQCRecommendation:
    asset_id: str
    applies: bool                    # False if we deliberately have no PQC-specific recommendation (see rules.py)
    direction: str | None            # e.g. "ML-KEM (FIPS 203)" - None if applies=False
    rationale: str
    standard_reference: str | None

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "applies": self.applies,
            "direction": self.direction,
            "rationale": self.rationale,
            "standard_reference": self.standard_reference,
        }
