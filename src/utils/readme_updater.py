"""
Update README.md with statistics from the latest generated report.

The stats live between two HTML comment markers and the whole block is
regenerated on each run, so the README's prose and structure can change freely
without breaking the monthly update. The previous version matched the README's
badge URL and table rows with regexes; when the wording moved, the substitutions
found nothing and the update reported success having changed nothing.
"""

import calendar
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

START_MARKER = "<!-- STATS:START -->"
END_MARKER = "<!-- STATS:END -->"


class MarkersNotFound(RuntimeError):
    """Raised when README.md is missing the stats markers."""


def update_readme(
    report_dir: Optional[Path] = None, readme_path: Optional[Path] = None
) -> bool:
    """
    Update README.md with statistics from the latest report.

    Args:
        report_dir: Directory containing reports (defaults to outputs/)
        readme_path: README to update (defaults to the repo root README.md)

    Returns:
        bool: True if the file was updated, False otherwise
    """
    project_root = Path(__file__).parent.parent.parent
    if report_dir is None:
        report_dir = project_root / "outputs"
    if readme_path is None:
        readme_path = project_root / "README.md"

    latest_report = find_latest_report(report_dir)
    if not latest_report:
        logger.error("No reports found in %s", report_dir)
        return False

    report = _load_report(latest_report)
    if report is None:
        return False

    stats = extract_stats(report)
    if not stats:
        logger.error("Could not extract statistics from %s", latest_report)
        return False

    stats.update(load_ytd_context(report_dir, stats["year"]))

    try:
        changed = update_readme_file(readme_path, stats)
    except MarkersNotFound as e:
        logger.error("%s", e)
        return False
    except OSError as e:
        logger.error("Error updating README: %s", e)
        return False

    if changed:
        logger.info("Updated README with statistics from %s", latest_report.name)
    else:
        logger.info("README already current with %s", latest_report.name)
    return True


def _load_report(path: Path) -> Optional[dict]:
    """Parse a report JSON, logging and returning None on failure."""
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error("Error reading report %s: %s", path, e)
        return None


def find_latest_report(report_dir: Path) -> Optional[Path]:
    """
    Find the report JSON to publish.

    Prefers the report for the month the pipeline is currently reporting on;
    falls back to the most recently modified JSON so manual runs still work.

    Args:
        report_dir: Root directory containing reports

    Returns:
        Path to the report, or None if none found
    """
    if not report_dir.exists():
        return None

    # Imported here to keep this module importable without the config package.
    from src.config import Config

    year, month = Config.get_current_month_info()
    expected = (
        report_dir
        / str(year)
        / calendar.month_name[month]
        / f"{calendar.month_name[month]}.json"
    )
    if expected.exists():
        return expected

    json_files = list(report_dir.glob("**/*.json"))
    if not json_files:
        return None
    return max(json_files, key=lambda p: p.stat().st_mtime)


def load_ytd_context(report_dir: Path, year: str) -> dict:
    """Year-to-date and all-time figures, written by generate-ytd-report.

    Optional by design: the file is absent until a YTD run has happened, and the
    stats block just omits those rows rather than failing. Reading it is what
    keeps the README from having to load the 1.6 GB feed itself.
    """
    path = report_dir / str(year) / "ytd_summary.json"
    if not path.exists():
        logger.info("No %s yet; omitting year-to-date and all-time rows", path.name)
        return {}

    payload = _load_report(path)
    if not payload:
        return {}

    statistics = payload.get("statistics", {})
    context = {}
    if statistics.get("current_ytd_total"):
        context["ytd_total"] = f"{int(statistics['current_ytd_total']):,}"
    if statistics.get("all_time_total"):
        context["all_time_total"] = f"{int(statistics['all_time_total']):,}"
    if statistics.get("first_year_on_record"):
        context["first_year"] = str(statistics["first_year_on_record"])
    return context


def extract_stats(report: dict) -> Optional[dict]:
    """
    Extract the published statistics from a report JSON.

    Args:
        report: Parsed JSON report

    Returns:
        Dictionary of display-ready strings, or None if the shape is unexpected
    """
    try:
        data = report.get("data", report)
        summary = data.get("Summary", {})
        cvss_stats = data.get("CVSS Statistics") or data.get("cvss") or {}

        total_cves = summary.get("Total CVEs", 0)
        if not total_cves:
            return None

        month_name = summary.get("Month")
        year = int(summary.get("Year", datetime.now().year))

        # Refuse rather than guess. Falling back to the current month would
        # label the block with a month the numbers do not belong to, which is
        # worse than not updating it: an annual report or one written by an
        # older code path has no Month at all.
        if not (month_name and isinstance(month_name, str)):
            logger.error("Report has no Summary.Month; refusing to guess the period")
            return None

        month_num = list(calendar.month_name).index(month_name)

        # Divide by days elapsed, not days in the month. A manual mid-month run
        # would otherwise spread a part-month total across the whole month and
        # understate the daily average, and claim data through a date that has
        # not happened yet.
        now = datetime.now()
        in_progress = (year, month_num) == (now.year, now.month)
        days_elapsed = (
            now.day if in_progress else calendar.monthrange(year, month_num)[1]
        )

        avg_per_day = int(total_cves) / days_elapsed if days_elapsed else 0
        mean_cvss = cvss_stats.get("mean") or 0
        median_cvss = cvss_stats.get("median") or 0

        return {
            "month": month_name,
            "year": str(year),
            "in_progress": in_progress,
            "through_date": f"{month_name} {days_elapsed}, {year}",
            "total_cves": f"{int(total_cves):,}",
            "avg_cves_per_day": f"{avg_per_day:,.1f}",
            "mean_cvss": f"{float(mean_cvss):.2f}",
            "median_cvss": f"{float(median_cvss):.1f}",
        }
    except (KeyError, ValueError, TypeError) as e:
        logger.error("Unexpected report shape: %s", e)
        return None


def render_stats_block(stats: dict) -> str:
    """Render the markdown that sits between the markers.

    The whole table lives inside the block, header included: an HTML comment
    between a table header and its rows would break the table.
    """
    month_label = f"{stats['month']} {stats['year']}"
    if stats.get("in_progress"):
        month_label += " (in progress)"

    rows = [
        "| Metric | Value |",
        "|---|---|",
        f"| CVEs published, {month_label} | {stats['total_cves']} |",
    ]

    # Year-to-date and all-time need a YTD run behind them, so they are optional.
    if stats.get("ytd_total"):
        rows.append(f"| {stats['year']} year to date | {stats['ytd_total']} |")
    if stats.get("all_time_total"):
        since = f", since {stats['first_year']}" if stats.get("first_year") else ""
        rows.append(f"| All time{since} | {stats['all_time_total']} |")

    rows += [
        f"| Average per day, {stats['month']} | {stats['avg_cves_per_day']} |",
        f"| Mean CVSS, {stats['month']} | {stats['mean_cvss']} |",
        f"| Median CVSS, {stats['month']} | {stats['median_cvss']} |",
        "",
        f"Data through {stats['through_date']}, excluding rejected CVEs.",
    ]
    return "\n".join(rows)


def update_readme_file(readme_path: Path, stats: dict) -> bool:
    """
    Replace the marked stats block in README.md.

    Args:
        readme_path: Path to README.md
        stats: Statistics from extract_stats()

    Returns:
        True if the file content changed

    Raises:
        MarkersNotFound: if either marker is absent or they are out of order
    """
    content = readme_path.read_text()

    start = content.find(START_MARKER)
    end = content.find(END_MARKER)
    if start == -1 or end == -1 or end < start:
        raise MarkersNotFound(
            f"{readme_path} must contain {START_MARKER} before {END_MARKER}"
        )

    block = render_stats_block(stats)
    updated = content[: start + len(START_MARKER)] + "\n" + block + "\n" + content[end:]

    if updated == content:
        return False

    readme_path.write_text(updated)
    return True
