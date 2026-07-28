"""Tests for the README stats updater."""

import json
import shutil
from pathlib import Path

import pytest

from src.utils import readme_updater
from src.utils.readme_updater import (
    END_MARKER,
    START_MARKER,
    MarkersNotFound,
    extract_stats,
    render_stats_block,
    update_readme,
    update_readme_file,
)

PROJECT_ROOT = Path(__file__).parent.parent
REAL_README = PROJECT_ROOT / "README.md"

SAMPLE_REPORT = {
    "generated_at": "2026-06-01T12:05:40",
    "data": {
        "Summary": {
            "Month": "May",
            "Year": 2026,
            "Total CVEs": 6952,
        },
        "cvss": {"mean": 6.86, "median": 7.1, "percentile_75": 8.1},
    },
}


def test_real_readme_has_markers():
    """The updater is a no-op without these, so guard them explicitly."""
    content = REAL_README.read_text()
    assert START_MARKER in content
    assert END_MARKER in content
    assert content.index(START_MARKER) < content.index(END_MARKER)


def test_extract_stats_from_report():
    stats = extract_stats(SAMPLE_REPORT)
    assert stats["month"] == "May"
    assert stats["year"] == "2026"
    assert stats["total_cves"] == "6,952"
    # May has 31 days: 6952 / 31 = 224.26
    assert stats["avg_cves_per_day"] == "224.3"
    assert stats["mean_cvss"] == "6.86"
    assert stats["median_cvss"] == "7.1"
    assert stats["through_date"] == "May 31, 2026"


def test_extract_stats_rejects_empty_report():
    assert extract_stats({"data": {"Summary": {}}}) is None


def test_extract_stats_refuses_to_guess_the_month():
    """An annual report has no Month; labelling it with today's is worse than not."""
    no_month = {"data": {"Summary": {"Year": 2026, "Total CVEs": 6952}}}
    assert extract_stats(no_month) is None


def test_update_readme_file_replaces_block(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(
        f"# Title\n\nIntro.\n\n{START_MARKER}\nstale content\n{END_MARKER}\n\nOutro.\n"
    )

    stats = extract_stats(SAMPLE_REPORT)
    assert update_readme_file(readme, stats) is True

    content = readme.read_text()
    assert "stale content" not in content
    assert "6,952" in content
    # Surrounding prose is untouched.
    assert content.startswith("# Title")
    assert content.endswith("Outro.\n")


def test_update_readme_file_is_idempotent(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(f"{START_MARKER}\nold\n{END_MARKER}\n")
    stats = extract_stats(SAMPLE_REPORT)

    assert update_readme_file(readme, stats) is True
    first = readme.read_text()
    assert update_readme_file(readme, stats) is False
    assert readme.read_text() == first


def test_update_readme_file_raises_without_markers(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("# No markers here\n")
    with pytest.raises(MarkersNotFound):
        update_readme_file(readme, extract_stats(SAMPLE_REPORT))


def test_real_readme_survives_a_round_trip(tmp_path):
    """Regenerating the block against the committed README must change only it."""
    readme = tmp_path / "README.md"
    shutil.copy(REAL_README, readme)
    original = readme.read_text()

    stats = extract_stats(SAMPLE_REPORT)
    update_readme_file(readme, stats)
    updated = readme.read_text()

    def outside_block(text):
        head, _, rest = text.partition(START_MARKER)
        _, _, tail = rest.partition(END_MARKER)
        return head, tail

    assert outside_block(original) == outside_block(updated)
    assert render_stats_block(stats) in updated


def test_update_readme_end_to_end(tmp_path, monkeypatch):
    """update_readme() finds the report for the reporting month and writes it."""
    report_dir = tmp_path / "outputs" / "2026" / "May"
    report_dir.mkdir(parents=True)
    (report_dir / "May.json").write_text(json.dumps(SAMPLE_REPORT))

    readme = tmp_path / "README.md"
    readme.write_text(f"# T\n\n{START_MARKER}\nplaceholder\n{END_MARKER}\n")

    monkeypatch.setattr(
        readme_updater, "find_latest_report", lambda _: report_dir / "May.json"
    )

    assert update_readme(report_dir=tmp_path / "outputs", readme_path=readme) is True
    assert "6,952" in readme.read_text()


def test_update_readme_reports_failure_when_no_reports(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(f"{START_MARKER}\n{END_MARKER}\n")
    empty = tmp_path / "nothing"
    assert update_readme(report_dir=empty, readme_path=readme) is False


def _freeze(monkeypatch, year, month, day):
    from datetime import datetime as real_datetime

    class FakeDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime(year, month, day, 12, 0, 0)

    monkeypatch.setattr("src.utils.readme_updater.datetime", FakeDatetime)


def test_completed_month_divides_by_the_whole_month(monkeypatch):
    _freeze(monkeypatch, 2026, 6, 1)  # reporting on May, which has finished
    stats = extract_stats(SAMPLE_REPORT)
    assert stats["in_progress"] is False
    assert stats["avg_cves_per_day"] == "224.3"  # 6952 / 31
    assert stats["through_date"] == "May 31, 2026"
    assert "in progress" not in render_stats_block(stats)


def test_in_progress_month_divides_by_days_elapsed(monkeypatch):
    """8,012 over 27 days is 296.7 a day, not 8,012 spread across 31."""
    _freeze(monkeypatch, 2026, 7, 27)
    report = {
        "data": {
            "Summary": {"Month": "July", "Year": 2026, "Total CVEs": 8012},
            "cvss": {"mean": 7.09, "median": 7.4},
        }
    }
    stats = extract_stats(report)

    assert stats["in_progress"] is True
    assert stats["avg_cves_per_day"] == "296.7"
    assert stats["through_date"] == "July 27, 2026"

    block = render_stats_block(stats)
    assert "July 2026 (in progress)" in block
    assert "Data through July 27, 2026" in block
    # Never claim data through a date that has not happened.
    assert "July 31" not in block


def test_stats_block_carries_ytd_and_all_time(monkeypatch):
    """The front page shows more than one month when a YTD run has happened."""
    _freeze(monkeypatch, 2026, 6, 1)
    stats = extract_stats(SAMPLE_REPORT)
    stats.update(
        {"ytd_total": "43,867", "all_time_total": "352,762", "first_year": "1988"}
    )
    block = render_stats_block(stats)

    assert "| CVEs published, May 2026 | 6,952 |" in block
    assert "| 2026 year to date | 43,867 |" in block
    assert "| All time, since 1988 | 352,762 |" in block
    # The month-scoped rows say which month they belong to.
    assert "| Average per day, May | 224.3 |" in block


def test_stats_block_omits_ytd_rows_when_absent(monkeypatch):
    """Before any YTD run the block still renders, just without those rows."""
    _freeze(monkeypatch, 2026, 6, 1)
    block = render_stats_block(extract_stats(SAMPLE_REPORT))

    assert "| CVEs published, May 2026 | 6,952 |" in block
    assert "year to date" not in block
    assert "All time" not in block


def test_load_ytd_context_reads_the_summary(tmp_path):
    year_dir = tmp_path / "2026"
    year_dir.mkdir()
    (year_dir / "ytd_summary.json").write_text(
        json.dumps(
            {
                "statistics": {
                    "current_ytd_total": 43867,
                    "all_time_total": 352762,
                    "first_year_on_record": 1988,
                }
            }
        )
    )
    context = readme_updater.load_ytd_context(tmp_path, "2026")
    assert context == {
        "ytd_total": "43,867",
        "all_time_total": "352,762",
        "first_year": "1988",
    }


def test_load_ytd_context_tolerates_a_missing_file(tmp_path):
    assert readme_updater.load_ytd_context(tmp_path, "2026") == {}
