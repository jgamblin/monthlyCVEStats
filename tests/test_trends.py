"""Tests for trend analysis."""

import pandas as pd
import pytest

from src.analysis.trends import TrendAnalyzer


def frame(dates):
    return pd.DataFrame({"published": pd.to_datetime(dates, utc=True)})


@pytest.fixture
def year_df():
    """Three months of a year: 2 in January, 4 in February, 3 in March."""
    return frame(
        ["2026-01-05", "2026-01-20"]
        + ["2026-02-03", "2026-02-10", "2026-02-17", "2026-02-24"]
        + ["2026-03-01", "2026-03-15", "2026-03-30"]
    )


def test_monthly_trend_uses_published_column(year_df):
    result = TrendAnalyzer().monthly_trend(year_df)
    assert result, "Monthly trend must not be empty for a multi-month frame"
    assert result["monthly_counts"] == {"2026-01": 2, "2026-02": 4, "2026-03": 3}
    assert result["busiest_month"] == "2026-02"
    assert result["latest_month"] == "2026-03"
    assert result["month_over_month_percent"] == -25.0  # 4 -> 3


def test_growth_rate_across_months(year_df):
    result = TrendAnalyzer().growth_rate(year_df)
    assert result, "Growth rate must not be empty for a multi-month frame"
    assert result["periods_compared"] == 3
    assert result["fastest_growth_period"] == "2026-02"  # 2 -> 4 is +100%
    assert result["fastest_growth_percent"] == 100.0
    assert result["slowest_growth_percent"] == -25.0


def test_growth_rate_needs_two_periods():
    """A single-month frame cannot produce a growth rate, and says so quietly."""
    single_month = frame(["2026-05-01", "2026-05-15"])
    assert TrendAnalyzer().growth_rate(single_month) == {}


def test_year_over_year_comparison():
    df = frame(["2025-01-01", "2025-06-01", "2026-01-01", "2026-06-01", "2026-07-01"])
    result = TrendAnalyzer().year_over_year(df, compare_years=(2025, 2026))
    assert result["year_2025"] == 2
    assert result["year_2026"] == 3
    assert result["growth_percent"] == 50.0


def test_year_over_year_all_years():
    df = frame(["2025-01-01", "2026-01-01", "2026-02-01"])
    result = TrendAnalyzer().year_over_year(df)
    assert result["yearly_counts"] == {2025: 1, 2026: 2}


def test_missing_date_column_returns_empty():
    df = pd.DataFrame({"cve_id": ["CVE-2026-0001"]})
    analyzer = TrendAnalyzer()
    assert analyzer.monthly_trend(df) == {}
    assert analyzer.growth_rate(df) == {}
    assert analyzer.year_over_year(df) == {}
