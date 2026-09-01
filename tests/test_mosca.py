from risk_engine.context import DataLifetimeBand
from risk_engine.mosca import compute_urgency


def test_unknown_lifetime_has_zero_urgency():
    urgency = compute_urgency(DataLifetimeBand.UNKNOWN)
    assert urgency.urgency_points == 0


def test_fifteen_plus_years_has_max_urgency():
    urgency = compute_urgency(DataLifetimeBand.FIFTEEN_PLUS_YEARS)
    assert urgency.urgency_points == 15


def test_urgency_increases_monotonically_with_band():
    bands_in_order = [
        DataLifetimeBand.UNKNOWN,
        DataLifetimeBand.UNDER_5_YEARS,
        DataLifetimeBand.FIVE_TO_9_YEARS,
        DataLifetimeBand.TEN_TO_14_YEARS,
        DataLifetimeBand.FIFTEEN_PLUS_YEARS,
    ]
    points = [compute_urgency(b).urgency_points for b in bands_in_order]
    assert points == sorted(points)


def test_every_result_carries_a_limitations_note():
    for band in DataLifetimeBand:
        urgency = compute_urgency(band)
        assert "prediction" in urgency.limitations_note.lower()
