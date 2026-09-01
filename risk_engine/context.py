"""
risk_engine/context.py

Business context that CANNOT be determined by scanning code - it has to come
from a human who understands the application. We never guess these values.

If the user doesn't provide a context.json, every asset is scored with
BusinessCriticality.UNKNOWN and DataLifetime.UNKNOWN, and this is made
visible in the output rather than silently defaulting to something specific.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class BusinessCriticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class DataLifetimeBand(str, Enum):
    """A bucketed view of data_lifetime_years, used by the Mosca-style
    urgency calculation in scorer.py. Buckets (not raw years) keep the
    scoring simple and explainable for a demo."""
    UNKNOWN = "UNKNOWN"
    UNDER_5_YEARS = "UNDER_5_YEARS"
    FIVE_TO_9_YEARS = "5_TO_9_YEARS"
    TEN_TO_14_YEARS = "10_TO_14_YEARS"
    FIFTEEN_PLUS_YEARS = "15_PLUS_YEARS"


@dataclass
class ProjectContext:
    """
    Simple, project-wide context. Phase 2 applies the SAME context to every
    asset in the project - per-file/per-component context is a documented
    future extension (noted in README), not built now, to keep this simple.
    """
    business_criticality: BusinessCriticality
    data_lifetime_years: int | None  # None means unknown - never guessed

    @property
    def data_lifetime_band(self) -> DataLifetimeBand:
        years = self.data_lifetime_years
        if years is None:
            return DataLifetimeBand.UNKNOWN
        if years < 5:
            return DataLifetimeBand.UNDER_5_YEARS
        if years < 10:
            return DataLifetimeBand.FIVE_TO_9_YEARS
        if years < 15:
            return DataLifetimeBand.TEN_TO_14_YEARS
        return DataLifetimeBand.FIFTEEN_PLUS_YEARS

    @classmethod
    def unknown(cls) -> "ProjectContext":
        """The default context when the user provides nothing."""
        return cls(business_criticality=BusinessCriticality.UNKNOWN, data_lifetime_years=None)


def load_context(path: str | Path | None) -> ProjectContext:
    """
    Load a context.json file of the form:
        {"business_criticality": "CRITICAL", "data_lifetime_years": 15}

    Missing keys, a missing file, or path=None all fall back to
    ProjectContext.unknown() - we never fabricate a criticality or lifetime.
    Invalid enum values raise ValueError so the user knows their file has a
    typo, rather than silently being ignored.
    """
    if path is None:
        return ProjectContext.unknown()

    context_path = Path(path)
    if not context_path.exists():
        return ProjectContext.unknown()

    data = json.loads(context_path.read_text(encoding="utf-8"))

    raw_criticality = data.get("business_criticality")
    if raw_criticality is None:
        criticality = BusinessCriticality.UNKNOWN
    else:
        criticality = BusinessCriticality(raw_criticality.upper())

    lifetime_years = data.get("data_lifetime_years")
    if lifetime_years is not None and not isinstance(lifetime_years, int):
        raise ValueError("data_lifetime_years must be an integer number of years")

    return ProjectContext(business_criticality=criticality, data_lifetime_years=lifetime_years)
