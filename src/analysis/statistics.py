"""Statistical analysis of CVE data."""

import logging
from typing import Optional, Sequence

import pandas as pd

# Columns produced by DataProcessor._flatten_cve. Named explicitly rather than
# discovered by substring: the CNA lives in 'source_identifier' and the date in
# 'published', so a substring probe for 'cna' or 'date' matches nothing and the
# analysis silently returns an empty dict.
CVSS_COLUMNS = ("cvss_v3_score",)
CNA_COLUMNS = ("source_identifier", "cna", "assigner")
CWE_COLUMNS = ("primary_cwe", "cwe")
DATE_COLUMNS = ("published", "date_published", "date")

# CVSS v3 qualitative severity ratings, per the specification.
SEVERITY_BANDS = (
    ("None", 0.0, 0.0),
    ("Low", 0.1, 3.9),
    ("Medium", 4.0, 6.9),
    ("High", 7.0, 8.9),
    ("Critical", 9.0, 10.0),
)


def find_column(df: pd.DataFrame, candidates: Sequence[str]) -> Optional[str]:
    """Return the first candidate column present in the DataFrame."""
    for name in candidates:
        if name in df.columns:
            return name
    return None


class StatisticsAnalyzer:
    """Analyze CVE statistics and metrics."""

    def __init__(self):
        """Initialize analyzer."""
        self.logger = logging.getLogger(__name__)

    def analyze_cvss_distribution(self, df: pd.DataFrame) -> dict:
        """Analyze CVSS score distribution.

        Args:
            df: CVE DataFrame

        Returns:
            Dictionary of CVSS statistics and severity band counts
        """
        cvss_col = find_column(df, CVSS_COLUMNS)
        if cvss_col is None:
            self.logger.warning(
                "No CVSS column found (looked for %s)", ", ".join(CVSS_COLUMNS)
            )
            return {}

        cvss_data = pd.to_numeric(df[cvss_col], errors="coerce").dropna()
        if cvss_data.empty:
            return {}

        severity = {}
        for label, low, high in SEVERITY_BANDS:
            severity[label] = int(cvss_data.between(low, high).sum())

        return {
            "scored_cves": int(len(cvss_data)),
            "unscored_cves": int(len(df) - len(cvss_data)),
            "mean": round(float(cvss_data.mean()), 2),
            "median": round(float(cvss_data.median()), 2),
            "std_dev": round(float(cvss_data.std()), 2),
            "min": round(float(cvss_data.min()), 1),
            "max": round(float(cvss_data.max()), 1),
            "percentile_25": round(float(cvss_data.quantile(0.25)), 1),
            "percentile_75": round(float(cvss_data.quantile(0.75)), 1),
            "severity_counts": severity,
        }

    def analyze_by_cna(self, df: pd.DataFrame, top_n: int = 10) -> dict:
        """Analyze CVEs by CVE Numbering Authority (CNA).

        Args:
            df: CVE DataFrame
            top_n: Number of top CNAs to return

        Returns:
            Dictionary of CNA statistics
        """
        cna_col = find_column(df, CNA_COLUMNS)
        if cna_col is None:
            self.logger.warning(
                "No CNA column found (looked for %s)", ", ".join(CNA_COLUMNS)
            )
            return {}

        cna_counts = df[cna_col].value_counts()
        if cna_counts.empty:
            return {}

        return {
            "top_cnas": cna_counts.head(top_n).to_dict(),
            "total_unique_cnas": int(df[cna_col].nunique()),
        }

    def analyze_by_cwe(self, df: pd.DataFrame, top_n: int = 10) -> dict:
        """Analyze CVEs by Common Weakness Enumeration (CWE).

        Args:
            df: CVE DataFrame
            top_n: Number of top CWEs to return

        Returns:
            Dictionary of CWE statistics
        """
        cwe_col = find_column(df, CWE_COLUMNS)
        if cwe_col is None:
            self.logger.warning(
                "No CWE column found (looked for %s)", ", ".join(CWE_COLUMNS)
            )
            return {}

        cwe_counts = df[cwe_col].value_counts()
        if cwe_counts.empty:
            return {}

        return {
            "top_cwes": cwe_counts.head(top_n).to_dict(),
            "total_unique_cwes": int(df[cwe_col].nunique()),
        }

    def daily_distribution(self, df: pd.DataFrame) -> dict:
        """Analyze daily CVE distribution.

        Args:
            df: CVE DataFrame

        Returns:
            Dictionary with daily statistics
        """
        date_col = find_column(df, DATE_COLUMNS)
        if date_col is None:
            self.logger.warning(
                "No date column found (looked for %s)", ", ".join(DATE_COLUMNS)
            )
            return {}

        try:
            dates = pd.to_datetime(df[date_col], errors="coerce", utc=True).dropna()
            if dates.empty:
                return {}

            daily_counts = dates.dt.date.value_counts().sort_index()
            busiest = daily_counts.idxmax()
            quietest = daily_counts.idxmin()

            return {
                "days_with_cves": int(len(daily_counts)),
                "avg_cves_per_day": round(float(daily_counts.mean()), 1),
                "busiest_day": str(busiest),
                "busiest_day_count": int(daily_counts.max()),
                "quietest_day": str(quietest),
                "quietest_day_count": int(daily_counts.min()),
            }
        except Exception as e:
            self.logger.error(f"Error calculating daily distribution: {e}")
            return {}
