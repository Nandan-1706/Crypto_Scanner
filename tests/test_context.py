import json
import tempfile
from pathlib import Path

import pytest

from risk_engine.context import (
    BusinessCriticality,
    DataLifetimeBand,
    ProjectContext,
    load_context,
)


def test_unknown_context_when_no_path_given():
    context = load_context(None)
    assert context.business_criticality == BusinessCriticality.UNKNOWN
    assert context.data_lifetime_years is None


def test_unknown_context_when_file_missing():
    context = load_context("/no/such/context.json")
    assert context.business_criticality == BusinessCriticality.UNKNOWN
    assert context.data_lifetime_years is None


def test_loads_valid_context_file():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "context.json"
        path.write_text(json.dumps({"business_criticality": "CRITICAL", "data_lifetime_years": 15}))

        context = load_context(path)
        assert context.business_criticality == BusinessCriticality.CRITICAL
        assert context.data_lifetime_years == 15


def test_invalid_criticality_value_raises():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "context.json"
        path.write_text(json.dumps({"business_criticality": "NOT_A_REAL_LEVEL"}))

        with pytest.raises(ValueError):
            load_context(path)


@pytest.mark.parametrize(
    "years,expected_band",
    [
        (None, DataLifetimeBand.UNKNOWN),
        (0, DataLifetimeBand.UNDER_5_YEARS),
        (4, DataLifetimeBand.UNDER_5_YEARS),
        (5, DataLifetimeBand.FIVE_TO_9_YEARS),
        (9, DataLifetimeBand.FIVE_TO_9_YEARS),
        (10, DataLifetimeBand.TEN_TO_14_YEARS),
        (14, DataLifetimeBand.TEN_TO_14_YEARS),
        (15, DataLifetimeBand.FIFTEEN_PLUS_YEARS),
        (30, DataLifetimeBand.FIFTEEN_PLUS_YEARS),
    ],
)
def test_data_lifetime_band_boundaries(years, expected_band):
    context = ProjectContext(business_criticality=BusinessCriticality.UNKNOWN, data_lifetime_years=years)
    assert context.data_lifetime_band == expected_band
