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
        stats = self._calculate_statistics(
            current_ytd, previous_ytd, current_cumulative, previous_cumulative
        )

        # Load daily data for chart plotting
        current_daily, previous_daily = self._load_daily_data()

        return {
            "current_year": self.current_year,
            "previous_year": self.current_year - 1,
            "current_year_data": current_ytd,
            "previous_year_data": previous_ytd,
            "current_cumulative": current_cumulative,
            "previous_cumulative": previous_cumulative,
            "current_daily_cumulative": current_daily,
            "previous_daily_cumulative": previous_daily,
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
                # Handle nested cve structure from NVD API format
                cve_data = cve.get("cve", cve) if isinstance(cve, dict) else cve
                if not isinstance(cve_data, dict):
                    continue

                # Skip rejected CVEs
                status = cve_data.get("vulnStatus", "")
                if status == "Rejected":
                    continue

                # Extract publication date
                date_str = (
                    cve_data.get("published")
                    or cve_data.get("datePublished")
                    or cve_data.get("date")
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

    def _load_daily_data(self) -> tuple[dict, dict]:
        """
        Load daily cumulative CVE counts for current and previous year.

        Returns:
            Tuple of (current_year_daily, previous_year_daily) where each is
            a dict mapping day-of-year (1-366) to cumulative CVE count.
        """
        from collections import Counter

        current_year = self.current_year
        previous_year = current_year - 1

        current_daily = Counter()
        previous_daily = Counter()

        try:
            with open(self.data_file, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}, {}

        cves = data if isinstance(data, list) else data.get("CVE_Items", [])

        for cve in cves:
            try:
                cve_data = cve.get("cve", cve) if isinstance(cve, dict) else cve
                if not isinstance(cve_data, dict):
                    continue
                if cve_data.get("vulnStatus", "") == "Rejected":
                    continue

                date_str = (
                    cve_data.get("published")
                    or cve_data.get("datePublished")
                    or cve_data.get("date")
                )
                if not date_str:
                    continue

                cve_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                doy = cve_date.timetuple().tm_yday

                if cve_date.year == current_year:
                    current_daily[doy] += 1
                elif cve_date.year == previous_year:
                    previous_daily[doy] += 1

            except (KeyError, ValueError, AttributeError):
                continue

        # Convert to cumulative
        def to_cumulative(daily_counts: Counter, max_day: int) -> dict:
            cumulative = {}
            total = 0
            for day in range(1, max_day + 1):
                total += daily_counts.get(day, 0)
                cumulative[day] = total
            return cumulative

        # Determine how many days to include
        today = datetime.now()
        if today.day == 1:
            # Report through end of previous month
            current_max = (today - today.replace(month=1, day=1)).days
        else:
            current_max = today.timetuple().tm_yday

        # For previous year, show same number of days for comparison
        current_cum = to_cumulative(current_daily, current_max)
        previous_cum = to_cumulative(previous_daily, current_max)

        return current_cum, previous_cum

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
        # Get current YTD (up to the most recently completed month)
        today = datetime.now()
        if today.day == 1:
            # On the 1st we're reporting on the previous month
            current_month = 12 if today.month == 1 else today.month - 1
        else:
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

        # Daily average (days elapsed through the reporting period)
        if today.day == 1:
            # On the 1st, count days through end of previous month
            day_of_year = (today - today.replace(month=1, day=1)).days
        else:
            day_of_year = today.timetuple().tm_yday
        avg_per_day = current_ytd_total / day_of_year if day_of_year > 0 else 0

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

        summary = f"""{current_month_name} {analysis["current_year"]} CVE Growth Report:

YTD ({current_month_name}):
► {ytd_total} total CVEs ({stats["yoy_percent"]:+.1f}% vs {previous_year} YTD)
► {avg_per_day} new vulnerabilities per day
► {ytd_diff} more CVEs than {previous_year} through {current_month_name}

{current_month_name} alone:
► {month_count} CVEs ({stats["month_percent"]:+.1f}% vs {current_month_name} {previous_year})

Context:
After the CVE volume in {current_month_name} {previous_year}, {current_month_name} is tracking at {stats["month_percent"]:+.1f}% — {"pushing" if stats["month_percent"] > 0 else "pulling"} YTD growth from {stats["yoy_percent"]:.1f}%."""

        return summary

    def get_enriched_text(self, analysis: dict, monthly_report: dict) -> str:
        """
        Generate enriched social media post with CVSS and CWE context.

        Args:
            analysis: Result from analyze_ytd()
            monthly_report: Parsed monthly report JSON (the "data" dict)

        Returns:
            Formatted enriched text for social posts
        """
        stats = analysis["statistics"]
        current_month_name = datetime(
            analysis["current_year"], stats["current_month"], 1
        ).strftime("%B")
        previous_year = analysis["previous_year"]
        year = analysis["current_year"]

        month_count = f"{stats['current_month_count']:,}"
        month_pct = f"{stats['month_percent']:+.1f}%"
        ytd_total = f"{stats['current_ytd_total']:,}"
        ytd_pct = f"{stats['yoy_percent']:+.1f}%"
        avg_day = f"{stats['avg_cves_per_day']:.0f}"

        # Common CWE ID to short name mapping
        cwe_names = {
            "CWE-79": "XSS",
            "CWE-89": "SQL Injection",
            "CWE-862": "Missing Authorization",
            "CWE-22": "Path Traversal",
            "CWE-98": "PHP Remote File Inclusion",
            "CWE-74": "Injection",
            "CWE-787": "Out-of-bounds Write",
            "CWE-119": "Buffer Overflow",
            "CWE-863": "Incorrect Authorization",
            "CWE-918": "SSRF",
            "CWE-78": "OS Command Injection",
            "CWE-416": "Use After Free",
            "CWE-352": "CSRF",
            "CWE-200": "Information Exposure",
            "CWE-476": "NULL Pointer Dereference",
            "CWE-434": "Unrestricted Upload",
            "CWE-125": "Out-of-bounds Read",
            "CWE-502": "Deserialization",
            "CWE-77": "Command Injection",
            "CWE-400": "Resource Exhaustion",
            "CWE-94": "Code Injection",
            "CWE-306": "Missing Authentication",
        }

        # Build CVSS line
        cvss_data = monthly_report.get("cvss", {})
        cvss_line = ""
        if cvss_data.get("median"):
            median = cvss_data["median"]
            p75 = cvss_data.get("percentile_75", "")
            cvss_line = f"\nMedian CVSS: {median}"
            if p75:
                cvss_line += f" (75th percentile: {p75})"
            cvss_line += "\n"

        # Build top CWEs
        cwe_data = monthly_report.get("cwe", {})
        top_cwes = cwe_data.get("top_cwes", {})
        cwe_lines = ""
        if top_cwes:
            items = list(top_cwes.items())[:5]
            cwe_lines = "\nTop weaknesses:\n"
            for cwe_id, count in items:
                name = cwe_names.get(cwe_id, cwe_id)
                cwe_lines += f"  {name} ({cwe_id}): {count:,}\n"

        text = (
            f"{current_month_name} saw {month_count} new CVEs — "
            f"{month_pct} over {current_month_name} {previous_year} "
            f"and pushing {year} YTD to {ytd_total} "
            f"({ytd_pct} YoY). "
            f"That's {avg_day} new vulnerabilities per day."
            f"{cvss_line}"
            f"{cwe_lines}"
            f"\nData: NVD (excluding rejected CVEs)\n\n"
            f"#CVE #VulnerabilityManagement #InfoSec #CyberSecurity"
        )

        return text
