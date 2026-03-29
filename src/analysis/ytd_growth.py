"""
Year-to-Date (YTD) CVE growth analysis and comparison.

Generates comprehensive YTD statistics including:
- Cumulative CVE counts by month
- Growth rates (month-over-month and year-over-year)
- Comparison with previous year
- Daily and monthly averages
"""

from datetime import datetime
from pathlib import Path
import pandas as pd
import json


class YTDAnalyzer:
    """Analyze year-to-date CVE growth patterns."""

    def __init__(self, data_file: Path):
        """
        Initialize YTD analyzer.

        Args:
            data_file: Path to NVD JSON data file
        """
        self.data_file = data_file
        self.current_year = datetime.now().year

    def analyze_ytd(self) -> dict:
        """
        Analyze year-to-date CVE statistics.

        Returns:
            Dictionary with:
            - current_year_data: Month-by-month cumulative counts
            - previous_year_data: Last year's month-by-month cumulative counts
            - monthly_breakdown: Individual month counts
            - statistics: Growth rates and comparisons
        """
        # Load current year data
        current_ytd = self._load_year_data(self.current_year)
        previous_ytd = self._load_year_data(self.current_year - 1)

        # Calculate cumulative totals
        current_cumulative = self._calculate_cumulative(current_ytd)
        previous_cumulative = self._calculate_cumulative(previous_ytd)

        # Calculate statistics
        stats = self._calculate_statistics(current_ytd, previous_ytd, current_cumulative, previous_cumulative)

        return {
            "current_year": self.current_year,
            "previous_year": self.current_year - 1,
            "current_year_data": current_ytd,
            "previous_year_data": previous_ytd,
            "current_cumulative": current_cumulative,
            "previous_cumulative": previous_cumulative,
            "statistics": stats,
        }

    def _load_year_data(self, year: int) -> dict:
        """
        Load month-by-month CVE counts for a year.

        Args:
            year: Year to load data for

        Returns:
            Dictionary mapping month number to CVE count
        """
        monthly_counts = {month: 0 for month in range(1, 13)}

        try:
            with open(self.data_file, "r") as f:
                # The file contains a single JSON array
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return monthly_counts

        # Handle both array and object formats
        cves = data if isinstance(data, list) else data.get("CVE_Items", [])

        for cve in cves:
            try:
                # Extract publication date
                date_str = None
                if isinstance(cve, dict):
                    # Try different possible date fields
                    date_str = (
                        cve.get("published")
                        or cve.get("datePublished")
                        or cve.get("date")
                    )
                    if not date_str and "cve" in cve:
                        date_str = (
                            cve["cve"].get("published")
                            or cve["cve"].get("datePublished")
                        )

                if not date_str:
                    continue

                # Parse date
                cve_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))

                # Check if it's in the target year
                if cve_date.year == year:
                    monthly_counts[cve_date.month] += 1

            except (KeyError, ValueError, AttributeError):
                continue

        return monthly_counts

    def _calculate_cumulative(self, monthly_data: dict) -> dict:
        """
        Calculate cumulative CVE counts from monthly data.

        Args:
            monthly_data: Dictionary mapping month to count

        Returns:
            Dictionary with cumulative counts by month
        """
        cumulative = {}
        total = 0

        for month in range(1, 13):
            total += monthly_data.get(month, 0)
            cumulative[month] = total

        return cumulative

    def _calculate_statistics(
        self,
        current_monthly: dict,
        previous_monthly: dict,
        current_cumulative: dict,
        previous_cumulative: dict,
    ) -> dict:
        """
        Calculate growth statistics and comparisons.

        Args:
            current_monthly: Current year monthly counts
            previous_monthly: Previous year monthly counts
            current_cumulative: Current year cumulative counts
            previous_cumulative: Previous year cumulative counts

        Returns:
            Dictionary with calculated statistics
        """
        # Get current YTD (up to today)
        today = datetime.now()
        current_month = today.month

        current_ytd_total = current_cumulative.get(current_month, 0)
        previous_ytd_total = previous_cumulative.get(current_month, 0)

        # Calculate growth rates
        yoy_growth = 0
        yoy_percent = 0
        if previous_ytd_total > 0:
            yoy_growth = current_ytd_total - previous_ytd_total
            yoy_percent = (yoy_growth / previous_ytd_total) * 100

        # Current month stats
        current_month_count = current_monthly.get(current_month, 0)
        previous_month_count = previous_monthly.get(current_month, 0)

        month_growth = 0
        month_percent = 0
        if previous_month_count > 0:
            month_growth = current_month_count - previous_month_count
            month_percent = (month_growth / previous_month_count) * 100

        # Daily average
        avg_per_day = current_ytd_total / current_month if current_month > 0 else 0

        return {
            "current_month": current_month,
            "current_ytd_total": current_ytd_total,
            "previous_ytd_total": previous_ytd_total,
            "yoy_growth": yoy_growth,
            "yoy_percent": yoy_percent,
            "current_month_count": current_month_count,
            "previous_month_count": previous_month_count,
            "month_growth": month_growth,
            "month_percent": month_percent,
            "avg_cves_per_day": avg_per_day,
        }

    def get_summary_text(self, analysis: dict) -> str:
        """
        Generate LinkedIn/social media post summary text.

        Args:
            analysis: Result from analyze_ytd()

        Returns:
            Formatted text summary for social posts
        """
        stats = analysis["statistics"]
        current_month_name = datetime(
            analysis["current_year"], stats["current_month"], 1
        ).strftime("%B")
        previous_year = analysis["previous_year"]

        # Format numbers with commas
        ytd_total = f"{stats['current_ytd_total']:,}"
        ytd_previous = f"{stats['previous_ytd_total']:,}"
        ytd_diff = f"{stats['yoy_growth']:+,}"
        month_count = f"{stats['current_month_count']:,}"
        month_previous = f"{stats['previous_month_count']:,}"
        month_diff = f"{stats['month_growth']:+,}"
        avg_per_day = f"{stats['avg_cves_per_day']:.0f}"

        summary = f"""{current_month_name} {analysis['current_year']} CVE Growth Report:

YTD ({current_month_name}):
► {ytd_total} total CVEs ({stats['yoy_percent']:+.1f}% vs {previous_year} YTD)
► {avg_per_day} new vulnerabilities per day
► {ytd_diff} more CVEs than {previous_year} through {current_month_name}

{current_month_name} alone:
► {month_count} CVEs ({stats['month_percent']:+.1f}% vs {current_month_name} {previous_year})

Context:
After the CVE volume in {current_month_name} {previous_year}, {current_month_name} is tracking at {stats['month_percent']:+.1f}% — {'pushing' if stats['month_percent'] > 0 else 'pulling'} YTD growth from {stats['yoy_percent']:.1f}%."""

        return summary
