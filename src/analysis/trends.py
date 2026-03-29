"""Trend analysis for CVE data."""

import logging
from typing import Optional
import pandas as pd


class TrendAnalyzer:
    """Analyze trends in CVE data."""

    def __init__(self):
        """Initialize analyzer."""
        self.logger = logging.getLogger(__name__)

    def monthly_trend(self, df: pd.DataFrame) -> dict:
        """Analyze month-over-month trends.
        
        Args:
            df: CVE DataFrame
            
        Returns:
            Dictionary of monthly trends
        """
        date_columns = [col for col in df.columns if 'date' in col.lower()]

        if not date_columns:
            return {}

        date_col = date_columns[0]

        try:
            df[date_col] = pd.to_datetime(df[date_col])
            monthly_counts = df.groupby(df[date_col].dt.to_period('M')).size()

            return {
                "monthly_counts": monthly_counts.to_dict(),
                "avg_monthly": float(monthly_counts.mean()),
            }
        except Exception as e:
            self.logger.error(f"Error calculating monthly trend: {e}")
            return {}

    def year_over_year(self, df: pd.DataFrame, compare_years: tuple = None) -> dict:
        """Compare CVE statistics across years.
        
        Args:
            df: CVE DataFrame
            compare_years: Tuple of (year1, year2) to compare
            
        Returns:
            Dictionary of YoY comparison
        """
        date_columns = [col for col in df.columns if 'date' in col.lower()]

        if not date_columns:
            return {}

        date_col = date_columns[0]

        try:
            df[date_col] = pd.to_datetime(df[date_col])
            df['year'] = df[date_col].dt.year

            if compare_years:
                year1, year2 = compare_years
                df1 = df[df['year'] == year1]
                df2 = df[df['year'] == year2]

                return {
                    f"year_{year1}": len(df1),
                    f"year_{year2}": len(df2),
                    "growth_percent": (len(df2) - len(df1)) / len(df1) * 100 if len(df1) > 0 else 0,
                }

            # Return all years if no specific comparison
            yearly_counts = df.groupby('year').size()
            return {
                "yearly_counts": yearly_counts.to_dict(),
            }
        except Exception as e:
            self.logger.error(f"Error calculating YoY: {e}")
            return {}

    def growth_rate(self, df: pd.DataFrame, period: str = 'M') -> dict:
        """Calculate growth rate of CVEs over time.
        
        Args:
            df: CVE DataFrame
            period: Period for calculation ('D' for daily, 'M' for monthly, 'Y' for yearly)
            
        Returns:
            Dictionary of growth metrics
        """
        date_columns = [col for col in df.columns if 'date' in col.lower()]

        if not date_columns:
            return {}

        date_col = date_columns[0]

        try:
            df[date_col] = pd.to_datetime(df[date_col])
            period_counts = df.groupby(df[date_col].dt.to_period(period)).size()

            if len(period_counts) < 2:
                return {}

            # Calculate growth rate between periods
            growth_rates = period_counts.pct_change() * 100

            return {
                "avg_growth_rate": float(growth_rates.mean()),
                "max_growth_rate": float(growth_rates.max()),
                "min_growth_rate": float(growth_rates.min()),
            }
        except Exception as e:
            self.logger.error(f"Error calculating growth rate: {e}")
            return {}
