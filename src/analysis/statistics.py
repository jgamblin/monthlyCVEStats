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

        # A CVE with only a v4 score is scored, just not on this scale. Counting
        # it as unscored published a number three times the real one.
        v4_only = 0
        if "cvss_v4_score" in df.columns:
            has_v3 = pd.to_numeric(df[cvss_col], errors="coerce").notna()
            has_v4 = pd.to_numeric(df["cvss_v4_score"], errors="coerce").notna()
            v4_only = int((has_v4 & ~has_v3).sum())
        unscored = int(len(df) - len(cvss_data) - v4_only)

        result = {
            "scored_cves_v3": int(len(cvss_data)),
            "scored_v4_only": v4_only,
            "unscored_cves": unscored,
            "mean": round(float(cvss_data.mean()), 2),
            "median": round(float(cvss_data.median()), 2),
            "std_dev": round(float(cvss_data.std()), 2),
            "min": round(float(cvss_data.min()), 1),
            "max": round(float(cvss_data.max()), 1),
            "percentile_25": round(float(cvss_data.quantile(0.25)), 1),
            "percentile_75": round(float(cvss_data.quantile(0.75)), 1),
            "severity_counts": severity,
        }
        if len(df):
            scored_any = len(cvss_data) + v4_only
            result["scored_share_percent"] = round(scored_any / len(df) * 100, 1)
        return result

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

        Counts every weakness assigned to a CVE, not just the first. A CVE with
        three CWEs contributes to all three, so the totals are assignments rather
        than CVEs and the two are reported separately. Falls back to the single
        'primary_cwe' column when the full list is not present.

        Args:
            df: CVE DataFrame
            top_n: Number of top CWEs to return

        Returns:
            Dictionary of CWE statistics
        """
        if "cwes" in df.columns:
            exploded = df["cwes"].explode().dropna()
            counted_all = True
        else:
            cwe_col = find_column(df, CWE_COLUMNS)
            if cwe_col is None:
                self.logger.warning(
                    "No CWE column found (looked for %s)", ", ".join(CWE_COLUMNS)
                )
                return {}
            exploded = df[cwe_col].dropna()
            counted_all = False

        # NVD-CWE-noinfo and NVD-CWE-Other record the absence of a mapping, so
        # counting them as weaknesses inflates every total and can rank "no
        # information" above real weaknesses, which has already been published
        # once. They are reported separately instead.
        placeholders = exploded[~exploded.astype(str).str.startswith("CWE-")]
        real = exploded[exploded.astype(str).str.startswith("CWE-")]

        if real.empty:
            return {}

        # Sort by count then by id, so a tie does not rank on row order and the
        # same input always produces the same table.
        counts = real.value_counts()
        ordered = sorted(counts.items(), key=lambda item: (-item[1], str(item[0])))

        result = {
            "top_cwes": {name: int(n) for name, n in ordered[:top_n]},
            "total_unique_cwes": int(real.nunique()),
            "total_assignments": int(len(real)),
            "cves_with_a_cwe": int(real.index.nunique()),
            "counts_all_weaknesses": counted_all,
        }
        if not placeholders.empty:
            result["unmapped_records"] = int(placeholders.index.nunique())
        return result

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

            # Divide by calendar days spanned, not by days that happened to have
            # a CVE. A zero-publication day would otherwise vanish from the
            # denominator and silently inflate the average.
            span = (daily_counts.index[-1] - daily_counts.index[0]).days + 1
            calendar_days = max(span, 1)

            # Who drove the biggest day. A quarterly vendor release lands as one
            # source dominating one day, which is a batch rather than a trend and
            # is the single most useful thing to disclose about a spike. The
            # largest publisher over the whole month is a different, duller
            # question, and answering that one instead misattributes the spike.
            busiest_source = busiest_source_count = None
            cna_col = find_column(df, CNA_COLUMNS)
            if cna_col is not None:
                on_busiest = df[dates.dt.date.values == busiest]
                if not on_busiest.empty:
                    sources = on_busiest[cna_col].value_counts()
                    if not sources.empty:
                        busiest_source = str(sources.index[0])
                        busiest_source_count = int(sources.iloc[0])

            result = {
                "days_with_cves": int(len(daily_counts)),
                "calendar_days_covered": int(calendar_days),
                "avg_cves_per_day": round(float(dates.size / calendar_days), 1),
                "busiest_day": str(busiest),
                "busiest_day_count": int(daily_counts.max()),
                "quietest_day": str(quietest),
                "quietest_day_count": int(daily_counts.min()),
            }
            if busiest_source:
                result["busiest_day_top_source"] = busiest_source
                result["busiest_day_top_source_count"] = busiest_source_count
            return result
        except Exception as e:
            self.logger.error(f"Error calculating daily distribution: {e}")
            return {}
