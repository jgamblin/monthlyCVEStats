"""Trend analysis for CVE data."""

import logging
from typing import Optional

import pandas as pd

from src.analysis.statistics import DATE_COLUMNS, find_column


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
        return dates if not dates.empty else None

    def monthly_trend(self, df: pd.DataFrame) -> dict:
        """Analyze month-over-month trends.

        Args:
            df: CVE DataFrame spanning two or more months

        Returns:
            Dictionary of monthly counts and the latest month-over-month change
        """
        dates = self._dates(df)
        if dates is None:
            return {}

        try:
            counts = dates.dt.to_period("M").value_counts().sort_index()
            monthly_counts = {str(period): int(n) for period, n in counts.items()}

            result = {
                "monthly_counts": monthly_counts,
                "avg_monthly": round(float(counts.mean()), 1),
                "busiest_month": str(counts.idxmax()),
                "busiest_month_count": int(counts.max()),
            }

            if len(counts) >= 2:
                latest, prior = int(counts.iloc[-1]), int(counts.iloc[-2])
                result["latest_month"] = str(counts.index[-1])
                result["latest_month_count"] = latest
                result["prior_month_count"] = prior
                result["month_over_month_percent"] = (
                    round((latest - prior) / prior * 100, 1) if prior else 0.0
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

    def growth_rate(self, df: pd.DataFrame, period: str = "M") -> dict:
        """Calculate the growth rate of CVE publication over time.

        Args:
            df: CVE DataFrame spanning two or more periods
            period: Period for calculation ('D' daily, 'M' monthly, 'Y' yearly)

        Returns:
            Dictionary of growth metrics
        """
        dates = self._dates(df)
        if dates is None:
            return {}

        try:
            counts = dates.dt.to_period(period).value_counts().sort_index()
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
                "period": period,
                "periods_compared": int(len(counts)),
                "avg_growth_percent": round(float(growth.mean()), 1),
                "fastest_growth_period": str(fastest),
                "fastest_growth_percent": round(float(growth.max()), 1),
                "slowest_growth_period": str(slowest),
                "slowest_growth_percent": round(float(growth.min()), 1),
            }
        except Exception as e:
            self.logger.error(f"Error calculating growth rate: {e}")
            return {}
