"""
risk_engine/mosca.py

A simplified, explicitly-labeled "Mosca-style" planning heuristic.

Michele Mosca's well-known framework compares:
    (how long data must stay protected) + (how long migration will take)
against
    (how long until a cryptanalytically-relevant quantum computer exists)
to decide whether an organization should already be worried.

THIS MODULE DOES NOT PREDICT WHEN A QUANTUM COMPUTER WILL EXIST. It only
uses the one piece of information Phase 2 actually has - the user-supplied
data lifetime - to express migration urgency as a bucketed score. It does
NOT attempt to model migration time or a threat-horizon date, because we
have no real data for either and modeling them would mean inventing
numbers. This is a deliberately narrowed, honest version of the Mosca idea:
"the longer data must stay confidential, the sooner migration should start,"
without pretending to know the return address.

Limitations (documented, not hidden):
- No migration-time estimate is factored in (would require real project
  data we don't have).
- No quantum-threat-horizon date is used or implied - only relative urgency.
- This is a planning aid for prioritization, not a forecast or guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass

from risk_engine.context import DataLifetimeBand

_URGENCY_POINTS: dict[DataLifetimeBand, int] = {
    DataLifetimeBand.UNKNOWN: 0,
    DataLifetimeBand.UNDER_5_YEARS: 3,
    DataLifetimeBand.FIVE_TO_9_YEARS: 8,
    DataLifetimeBand.TEN_TO_14_YEARS: 12,
    DataLifetimeBand.FIFTEEN_PLUS_YEARS: 15,
}

_EXPLANATIONS: dict[DataLifetimeBand, str] = {
    DataLifetimeBand.UNKNOWN: "Data lifetime not provided - no urgency contribution from this factor.",
    DataLifetimeBand.UNDER_5_YEARS: "Data lifetime under 5 years - relatively low harvest-now-decrypt-later exposure.",
    DataLifetimeBand.FIVE_TO_9_YEARS: "Data lifetime of 5-9 years - moderate harvest-now-decrypt-later exposure.",
    DataLifetimeBand.TEN_TO_14_YEARS: "Data lifetime of 10-14 years - meaningful harvest-now-decrypt-later exposure.",
    DataLifetimeBand.FIFTEEN_PLUS_YEARS: "Data lifetime of 15+ years - high harvest-now-decrypt-later exposure; long-lived data is most exposed to future decryption.",
}


@dataclass
class MoscaUrgency:
    band: DataLifetimeBand
    urgency_points: int   # 0-15, feeds directly into the risk_score formula's C component
    explanation: str
    limitations_note: str = (
        "This is a planning heuristic based only on stated data lifetime. "
        "It does not model migration time or a quantum-threat-horizon date, "
        "and must not be read as a prediction of when quantum computers "
        "capable of breaking current cryptography will exist."
    )


def compute_urgency(data_lifetime_band: DataLifetimeBand) -> MoscaUrgency:
    return MoscaUrgency(
        band=data_lifetime_band,
        urgency_points=_URGENCY_POINTS[data_lifetime_band],
        explanation=_EXPLANATIONS[data_lifetime_band],
    )
