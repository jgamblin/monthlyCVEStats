"""Tests for the statistics analyzers.

These guard a regression: the analyzers used to locate columns by substring
('cna', 'date'), which matched nothing against the columns DataProcessor actually
produces ('source_identifier', 'published'), so four report sections silently came
back empty.
"""

import pandas as pd
import pytest

from src.analysis.statistics import StatisticsAnalyzer

# The exact columns produced by DataProcessor._flatten_cve.
PROCESSOR_COLUMNS = [
    "cve_id",
    "published",
    "last_modified",
    "vuln_status",
    "cvss_v3_score",
    "cvss_v3_vector",
    "source_identifier",
    "primary_cwe",
]


@pytest.fixture
def df():
    """A small frame shaped exactly like processor output."""
    return pd.DataFrame(
        {
            "cve_id": [f"CVE-2026-{n:04d}" for n in range(1, 7)],
            "published": pd.to_datetime(
                [
                    "2026-05-01T10:00:00",
                    "2026-05-01T11:00:00",
                    "2026-05-02T10:00:00",
                    "2026-05-03T10:00:00",
                    "2026-05-03T12:00:00",
                    "2026-05-03T14:00:00",
                ],
                utc=True,
            ),
            "last_modified": ["2026-05-10T10:00:00"] * 6,
            "vuln_status": ["Analyzed"] * 6,
            "cvss_v3_score": [9.8, 7.5, 5.0, 0.0, 3.1, None],
            "cvss_v3_vector": ["AV:N/AC:L"] * 6,
            "source_identifier": [
                "cna@vuldb.com",
                "cna@vuldb.com",
                "security@apache.org",
                "cve@mitre.org",
                "cna@vuldb.com",
                "security@apache.org",
            ],
            "primary_cwe": [
                "CWE-79",
                "CWE-79",
                "CWE-89",
                "NVD-CWE-noinfo",
                "CWE-79",
                "CWE-22",
            ],
        }
    )


def test_fixture_matches_processor_columns(df):
    assert list(df.columns) == PROCESSOR_COLUMNS


def test_cvss_distribution_populated(df):
    result = StatisticsAnalyzer().analyze_cvss_distribution(df)
    assert result, "CVSS section must not be empty"
    assert result["scored_cves"] == 5
    assert result["unscored_cves"] == 1
    assert result["max"] == 9.8
    assert result["min"] == 0.0
    # Rounded for display rather than dumped at full float precision.
    assert result["mean"] == round(result["mean"], 2)


def test_cvss_severity_bands(df):
    severity = StatisticsAnalyzer().analyze_cvss_distribution(df)["severity_counts"]
    assert severity["Critical"] == 1  # 9.8
    assert severity["High"] == 1  # 7.5
    assert severity["Medium"] == 1  # 5.0
    assert severity["Low"] == 1  # 3.1
    assert severity["None"] == 1  # 0.0
    assert sum(severity.values()) == 5


def test_cna_analysis_finds_source_identifier(df):
    """The regression: 'cna' as a substring matches no processor column."""
    result = StatisticsAnalyzer().analyze_by_cna(df)
    assert result, "CNA section must not be empty"
    assert result["total_unique_cnas"] == 3
    assert list(result["top_cnas"])[0] == "cna@vuldb.com"
    assert result["top_cnas"]["cna@vuldb.com"] == 3


def test_cwe_analysis(df):
    result = StatisticsAnalyzer().analyze_by_cwe(df)
    assert result["total_unique_cwes"] == 4
    assert result["top_cwes"]["CWE-79"] == 3


def test_daily_distribution_finds_published(df):
    """The other half of the regression: 'date' matches no processor column."""
    result = StatisticsAnalyzer().daily_distribution(df)
    assert result, "Daily section must not be empty"
    assert result["days_with_cves"] == 3
    assert result["busiest_day"] == "2026-05-03"
    assert result["busiest_day_count"] == 3
    assert result["quietest_day_count"] == 1


def test_analyzers_return_empty_on_unknown_columns():
    """A frame with no recognized columns degrades quietly, not with a crash."""
    analyzer = StatisticsAnalyzer()
    unknown = pd.DataFrame({"something_else": [1, 2, 3]})
    assert analyzer.analyze_cvss_distribution(unknown) == {}
    assert analyzer.analyze_by_cna(unknown) == {}
    assert analyzer.analyze_by_cwe(unknown) == {}
    assert analyzer.daily_distribution(unknown) == {}
