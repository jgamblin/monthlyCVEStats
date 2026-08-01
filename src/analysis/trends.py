"""Trend analysis for CVE data."""

import logging
from typing import Optional

import pandas as pd

from src.analysis.statistics import DATE_COLUMNS, find_column

# Pandas period codes are not report copy.
_PERIOD_LABELS = {"D": "Daily", "M": "Monthly", "Y": "Yearly"}


class TrendAnalyzer:
    """Analyze trends in CVE data.

    These methods need more than one period to say anything, so callers should
    pass a DataFrame spanning the whole year rather than a single month.
    """

    def __init__(self):
        """Initialize analyzer."""
        self.logger = logging.getLogger(__name__)

    def _dates(self, df: pd.DataFrame) -> Optional[pd.Series]:
        """Parsed publication dates, or None when the column is absent."""
        date_col = find_column(df, DATE_COLUMNS)
        if date_col is None:
            self.logger.warning(
                "No date column found (looked for %s)", ", ".join(DATE_COLUMNS)
            )
            return None
        dates = pd.to_datetime(df[date_col], errors="coerce", utc=True).dropna()
        if dates.empty:
            return None
        # to_period() drops the timezone with a warning. Drop it here instead so
        # the bucketing is explicitly on UTC wall time.
        return dates.dt.tz_convert(None)

    def monthly_trend(
        self,
        df: pd.DataFrame,
        partial_period: Optional[str] = None,
        partial_days: Optional[int] = None,
    ) -> dict:
        """Analyze month-over-month trends.

        Every ranked or averaged figure covers completed months only. A month
        still in progress holds fewer days than the ones it would be compared
        against, so ranking it as busiest or differencing it month-over-month
        states a shortfall of days as a change in publication rate. The partial
        month is still reported, labelled, and compared on a daily rate.

        Args:
            df: CVE DataFrame spanning two or more months
            partial_period: Period to exclude from rankings, e.g. '2026-07'
            partial_days: Days elapsed in that period, for its daily rate

        Returns:
            Dictionary of monthly counts and the latest month-over-month change
        """
        dates = self._dates(df)
        if dates is None:
            return {}

        try:
            counts = dates.dt.to_period("M").value_counts().sort_index()
            monthly_counts = {str(period): int(n) for period, n in counts.items()}

            complete = counts[[str(p) != partial_period for p in counts.index]]
            if complete.empty:
                return {"monthly_counts": monthly_counts}

            result = {
                "monthly_counts": monthly_counts,
                "avg_monthly": round(float(complete.mean()), 1),
                "busiest_month": str(complete.idxmax()),
                "busiest_month_count": int(complete.max()),
            }

            if len(complete) >= 2:
                latest, prior = int(complete.iloc[-1]), int(complete.iloc[-2])
                result["latest_month"] = str(complete.index[-1])
                result["latest_month_count"] = latest
                result["prior_month_count"] = prior
                result["month_over_month_percent"] = (
                    round((latest - prior) / prior * 100, 1) if prior else 0.0
                )

            if partial_period and partial_period in monthly_counts:
                partial_count = monthly_counts[partial_period]
                result["partial_month"] = partial_period
                result["partial_month_count"] = partial_count
                if partial_days:
                    result["partial_month_days_elapsed"] = partial_days
                    rate = partial_count / partial_days
                    result["partial_month_daily_rate"] = round(rate, 1)
                    # Comparable to the last whole month only as a daily rate.
                    last_days = complete.index[-1].days_in_month
                    last_rate = int(complete.iloc[-1]) / last_days
                    result["prior_month_daily_rate"] = round(last_rate, 1)
                    result["daily_rate_change_percent"] = (
                        round((rate - last_rate) / last_rate * 100, 1)
                        if last_rate
                        else 0.0
                    )

            return result
        except Exception as e:
            self.logger.error(f"Error calculating monthly trend: {e}")
            return {}

    def year_over_year(
        self, df: pd.DataFrame, compare_years: Optional[tuple] = None
    ) -> dict:
        """Compare CVE counts across years.

        Args:
            df: CVE DataFrame
            compare_years: Tuple of (earlier_year, later_year) to compare

        Returns:
            Dictionary of YoY comparison
        """
        dates = self._dates(df)
        if dates is None:
            return {}

        try:
            years = dates.dt.year

            if compare_years:
                year1, year2 = compare_years
                count1 = int((years == year1).sum())
                count2 = int((years == year2).sum())
                return {
                    f"year_{year1}": count1,
                    f"year_{year2}": count2,
                    "growth_percent": (
                        round((count2 - count1) / count1 * 100, 1) if count1 else 0.0
                    ),
                }

            return {
                "yearly_counts": {
                    int(year): int(n)
                    for year, n in years.value_counts().sort_index().items()
                }
            }
        except Exception as e:
            self.logger.error(f"Error calculating YoY: {e}")
            return {}

    def growth_rate(
        self,
        df: pd.DataFrame,
        period: str = "M",
        partial_period: Optional[str] = None,
    ) -> dict:
        """Calculate the growth rate of CVE publication over time.

        Args:
            df: CVE DataFrame spanning two or more periods
            period: Period for calculation ('D' daily, 'M' monthly, 'Y' yearly)
            partial_period: Period still in progress, excluded from the rates so
                a shortfall of days is not reported as negative growth

        Returns:
            Dictionary of growth metrics
        """
        dates = self._dates(df)
        if dates is None:
            return {}

        try:
            counts = dates.dt.to_period(period).value_counts().sort_index()
            if partial_period:
                counts = counts[[str(p) != partial_period for p in counts.index]]
            if len(counts) < 2:
                self.logger.info(
                    "Only %d %s period(s) in the data; growth rate needs at least 2",
                    len(counts),
                    period,
                )
                return {}

            growth = counts.pct_change().dropna() * 100
            fastest = growth.idxmax()
            slowest = growth.idxmin()

            return {
                "period": _PERIOD_LABELS.get(period, period),
                # n periods yield n-1 changes; reporting the period count beside
                # a mean of the changes implied one more sample than existed.
                "months_included": int(len(counts)),
                "changes_averaged": int(len(growth)),
                "avg_growth_percent": round(float(growth.mean()), 1),
                "fastest_growth_period": str(fastest),
                "fastest_growth_percent": round(float(growth.max()), 1),
                "slowest_growth_period": str(slowest),
                "slowest_growth_percent": round(float(growth.min()), 1),
            }
        except Exception as e:
            self.logger.error(f"Error calculating growth rate: {e}")
            return {}
