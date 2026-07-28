"""Tests for the shared analysis entry point.

``run-monthly`` and ``generate-reports`` write to the same filenames, so they must
run the same analysis. They previously did not: generate-reports produced a
CVSS-only report, silently gutting whatever run-monthly had written for that
month.
"""

import json

import pandas as pd
import pytest

from src.cli import main as cli
from src.config import Config


@pytest.fixture
def year_frame():
    """Jan through Jul 2026, with July deliberately partial."""
    rows = []
    counts = {1: 3, 2: 4, 3: 6, 4: 5, 5: 8, 6: 10, 7: 2}
    for month, n in counts.items():
        for i in range(n):
            rows.append(
                {
                    "cve_id": f"CVE-2026-{month:02d}{i:02d}",
                    "published": pd.Timestamp(
                        f"2026-{month:02d}-{(i % 27) + 1:02d}T12:00:00Z"
                    ),
                    "vuln_status": "Analyzed",
                    "cvss_v3_score": 5.0 + (i % 5),
                    "source_identifier": f"cna{i % 3}@example.com",
                    "primary_cwe": f"CWE-{79 + (i % 3)}",
                }
            )
    return pd.DataFrame(rows)


@pytest.fixture
def isolated_outputs(tmp_path, monkeypatch, year_frame):
    """Point Config at a temp dir and feed the analysis a synthetic year."""

    class FakeProcessor:
        def __init__(self, *_args, **_kwargs):
            pass

        def load_to_dataframe(self, year=None, month=None):
            return year_frame.copy()

    monkeypatch.setattr(cli, "DataProcessor", FakeProcessor)
    monkeypatch.setattr(Config, "OUTPUT_DIR", tmp_path)
    return tmp_path


def read_report(outputs, year, month_name):
    path = outputs / str(year) / month_name / f"{month_name}.json"
    return json.loads(path.read_text())["data"]


def test_run_analysis_writes_every_section(isolated_outputs):
    assert cli.run_analysis(2026, 6) is True
    data = read_report(isolated_outputs, 2026, "June")

    # The sections that used to arrive empty.
    for section in ("cvss", "cna", "cwe", "daily", "monthly_trend", "growth"):
        assert data[section], f"{section} must not be empty"

    assert data["Summary"]["Month"] == "June"
    assert data["Summary"]["Year"] == 2026
    assert data["Summary"]["Total CVEs"] == 10


def test_trends_stop_at_the_reporting_month(isolated_outputs):
    """A June report must not reach into an in-progress July.

    Otherwise July's partial total is presented as that month's figure and the
    month-over-month change compares a partial month to a complete one.
    """
    cli.run_analysis(2026, 6)
    trend = read_report(isolated_outputs, 2026, "June")["monthly_trend"]

    assert "2026-07" not in trend["monthly_counts"]
    assert list(trend["monthly_counts"]) == [f"2026-{m:02d}" for m in range(1, 7)]
    assert trend["latest_month"] == "2026-06"
    assert trend["latest_month_count"] == 10
    assert trend["prior_month_count"] == 8  # May
    assert trend["month_over_month_percent"] == 25.0


def test_month_statistics_cover_only_that_month(isolated_outputs):
    """The month's own sections are scoped to the month, not the year to date."""
    cli.run_analysis(2026, 6)
    data = read_report(isolated_outputs, 2026, "June")
    assert data["cvss"]["scored_cves"] == 10
    assert data["daily"]["days_with_cves"] <= 30


def test_generate_reports_matches_run_monthly(isolated_outputs):
    """Both commands share one code path, so both produce the full section set."""
    cli.generate_reports(year=2026, month=6)
    via_command = read_report(isolated_outputs, 2026, "June")
    assert set(via_command) == {
        "Summary",
        "cvss",
        "cna",
        "cwe",
        "daily",
        "monthly_trend",
        "growth",
    }
    assert via_command["cna"]["top_cnas"]


def test_annual_report_has_no_month(isolated_outputs):
    """A whole-year run writes Annual.* and omits Month."""
    assert cli.run_analysis(2026, None) is True
    payload = json.loads((isolated_outputs / "2026" / "Annual.json").read_text())
    summary = payload["data"]["Summary"]
    assert summary["Total CVEs"] == 38  # every row in the fixture
    assert "Month" not in summary
    assert summary["Year"] == 2026


def test_run_analysis_reports_no_data(isolated_outputs):
    """A month with no CVEs returns False rather than writing an empty report."""
    assert cli.run_analysis(2026, 11) is False
