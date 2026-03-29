"""Statistical analysis of CVE data."""

import logging
from typing import Optional
import pandas as pd


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
            Dictionary of CVSS statistics
        """
        cvss_columns = [col for col in df.columns if 'cvss' in col.lower()]

        if not cvss_columns:
            return {}

        cvss_col = cvss_columns[0]
        cvss_data = pd.to_numeric(df[cvss_col], errors='coerce').dropna()

        if cvss_data.empty:
            return {}

        return {
            "mean": float(cvss_data.mean()),
            "median": float(cvss_data.median()),
            "std_dev": float(cvss_data.std()),
            "min": float(cvss_data.min()),
            "max": float(cvss_data.max()),
            "percentile_25": float(cvss_data.quantile(0.25)),
            "percentile_75": float(cvss_data.quantile(0.75)),
        }

    def analyze_by_cna(self, df: pd.DataFrame, top_n: int = 10) -> dict:
        """Analyze CVEs by CVE Numbering Authority (CNA).
        
        Args:
            df: CVE DataFrame
            top_n: Number of top CNAs to return
            
        Returns:
            Dictionary of CNA statistics
        """
        cna_columns = [col for col in df.columns if 'cna' in col.lower()]

        if not cna_columns:
            return {}

        cna_col = cna_columns[0]
        cna_counts = df[cna_col].value_counts().head(top_n)

        return {
            "top_cnas": cna_counts.to_dict(),
            "total_unique_cnas": df[cna_col].nunique(),
        }

    def analyze_by_cwe(self, df: pd.DataFrame, top_n: int = 10) -> dict:
        """Analyze CVEs by Common Weakness Enumeration (CWE).
        
        Args:
            df: CVE DataFrame
            top_n: Number of top CWEs to return
            
        Returns:
            Dictionary of CWE statistics
        """
        cwe_columns = [col for col in df.columns if 'cwe' in col.lower()]

        if not cwe_columns:
            return {}

        cwe_col = cwe_columns[0]
        cwe_counts = df[cwe_col].value_counts().head(top_n)

        return {
            "top_cwes": cwe_counts.to_dict(),
            "total_unique_cwes": df[cwe_col].nunique(),
        }

    def daily_distribution(self, df: pd.DataFrame) -> dict:
        """Analyze daily CVE distribution.
        
        Args:
            df: CVE DataFrame
            
        Returns:
            Dictionary with daily statistics
        """
        date_columns = [col for col in df.columns if 'date' in col.lower()]

        if not date_columns:
            return {}

        date_col = date_columns[0]

        try:
            df[date_col] = pd.to_datetime(df[date_col])
            daily_counts = df[date_col].dt.date.value_counts().sort_index()

            return {
                "total_days_with_cves": len(daily_counts),
                "avg_cves_per_day": float(daily_counts.mean()),
                "max_cves_in_day": int(daily_counts.max()),
                "min_cves_in_day": int(daily_counts.min()),
            }
        except Exception as e:
            self.logger.error(f"Error calculating daily distribution: {e}")
            return {}
