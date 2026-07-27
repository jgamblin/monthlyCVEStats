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


@pytest.fixture
def year_with_partial_july():
    """Jan-Jun complete, then a 27-day July that outcounts complete June."""
    dates = []
    counts = {1: 4309, 2: 4616, 3: 6234, 4: 5811, 5: 6938, 6: 7947}
    for month, n in counts.items():
        for i in range(n):
            dates.append(f"2026-{month:02d}-{(i % 28) + 1:02d}")
    for i in range(8012):
        dates.append(f"2026-07-{(i % 27) + 1:02d}")
    return frame(dates)


def test_partial_month_excluded_from_rankings(year_with_partial_july):
    """8,012 in 27 days must not be crowned busiest over 7,947 in 30."""
    result = TrendAnalyzer().monthly_trend(
        year_with_partial_july, partial_period="2026-07", partial_days=27
    )

    assert result["busiest_month"] == "2026-06"
    assert result["busiest_month_count"] == 7947
    # Month-over-month compares the last two WHOLE months, June against May.
    assert result["latest_month"] == "2026-06"
    assert result["month_over_month_percent"] == 14.5
    # The average covers completed months only.
    assert result["avg_monthly"] == 5975.8
    # July is still reported, and still visible in the raw counts.
    assert result["monthly_counts"]["2026-07"] == 8012
    assert result["partial_month"] == "2026-07"
    assert result["partial_month_count"] == 8012


def test_partial_month_compared_on_a_daily_rate(year_with_partial_july):
    """The only honest comparison for a part-month is a rate, not a total."""
    result = TrendAnalyzer().monthly_trend(
        year_with_partial_july, partial_period="2026-07", partial_days=27
    )

    assert result["partial_month_days_elapsed"] == 27
    assert result["partial_month_daily_rate"] == 296.7  # 8012 / 27
    assert result["prior_month_daily_rate"] == 264.9  # 7947 / 30
    assert result["daily_rate_change_percent"] == 12.0


def test_growth_rate_excludes_the_partial_month(year_with_partial_july):
    result = TrendAnalyzer().growth_rate(
        year_with_partial_july, partial_period="2026-07"
    )
    assert result["periods_compared"] == 6  # Jan-Jun, not 7
    assert "2026-07" not in result["fastest_growth_period"]


def test_no_partial_period_keeps_every_month(year_df):
    """Without a partial period the behaviour is unchanged."""
    result = TrendAnalyzer().monthly_trend(year_df)
    assert "partial_month" not in result
    assert result["busiest_month"] == "2026-02"
