"""
Update README.md with latest statistics from generated reports.

This module updates the README badge and statistics section with the latest
data from the most recent monthly report.
"""

import calendar
import json
import re
from pathlib import Path
from datetime import datetime


def update_readme(report_dir: Path = None) -> bool:
    """
    Update README.md with statistics from the latest report.

    Searches for the most recent report in outputs/ and updates:
    - LAST_UPDATE_DATE badge
    - TOTAL_CVES count
    - AVG_CVES_PER_DAY value
    - AVG_CVSS_SCORE value

    Args:
        report_dir: Directory containing reports (defaults to outputs/)

    Returns:
        bool: True if update was successful, False otherwise
    """
    if report_dir is None:
        report_dir = Path(__file__).parent.parent.parent / "outputs"

    # Find the most recent report
    latest_report = find_latest_report(report_dir)
    if not latest_report:
        print(f"No reports found in {report_dir}")
        return False

    # Load the report JSON
    try:
        with open(latest_report, "r") as f:
            report = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error reading report {latest_report}: {e}")
        return False

    # Extract statistics
    stats = extract_stats(report)
    if not stats:
        print("Could not extract statistics from report")
        return False

    # Update README
    readme_path = Path(__file__).parent.parent.parent / "README.md"
    try:
        update_readme_file(readme_path, stats)
        print(f"✓ Updated README with statistics from {latest_report.name}")
        return True
    except Exception as e:
        print(f"Error updating README: {e}")
        return False


def find_latest_report(report_dir: Path) -> Path | None:
    """
    Find the most recent report JSON file in the outputs directory.

    Searches recursively for all .json files and returns the most recently
    modified one.

    Args:
        report_dir: Root directory containing reports

    Returns:
        Path to the latest report, or None if not found
    """
    if not report_dir.exists():
        return None

    json_files = list(report_dir.glob("**/*.json"))
    if not json_files:
        return None

    # Return the most recently modified file
    return max(json_files, key=lambda p: p.stat().st_mtime)


def extract_stats(report: dict) -> dict | None:
    """
    Extract statistics from a report JSON.

    Args:
        report: Parsed JSON report

    Returns:
        Dictionary with keys: update_date, total_cves, avg_cves_per_day, avg_cvss_score
    """
    try:
        # Handle nested "data" structure
        data = report.get("data", report)
        summary = data.get("Summary", {})
        cvss_stats = data.get("CVSS Statistics") or data.get("cvss") or {}

        total_cves = summary.get("Total CVEs", 0)
        avg_cvss = cvss_stats.get("mean", 0) if cvss_stats else 0

        # Calculate average CVEs per day using actual days in the report month
        now = datetime.now()
        report_month = summary.get("Month")
        report_year = summary.get("Year", now.year)
        if report_month and isinstance(report_month, str):
            # Convert month name to number
            month_num = list(calendar.month_name).index(report_month)
            days_in_month = calendar.monthrange(int(report_year), month_num)[1]
        else:
            days_in_month = calendar.monthrange(now.year, now.month)[1]
        avg_per_day = total_cves / days_in_month if total_cves else 0

        return {
            "update_date": datetime.now().strftime("%B %d, %Y"),
            "total_cves": format(int(total_cves), ","),
            "avg_cves_per_day": f"{avg_per_day:.2f}",
            "avg_cvss_score": f"{avg_cvss:.2f}",
        }
    except (KeyError, ValueError, TypeError):
        return None


def update_readme_file(readme_path: Path, stats: dict) -> None:
    """
    Update statistics in README.md with actual values.

    Uses regex to find and replace existing values in the badge and stats table
    so the updater works on subsequent runs (not just the first placeholder run).

    Args:
        readme_path: Path to README.md
        stats: Dictionary of statistics to insert
    """
    content = readme_path.read_text()

    content = re.sub(
        r"(Data%20Updated-)[^)]+(-blue)",
        rf"\g<1>{stats['update_date']}\2",
        content,
    )
    content = re.sub(
        r"(Current Statistics \()[^)]+(\))",
        rf"\g<1>{stats['update_date']}\2",
        content,
    )
    content = re.sub(
        r"(\*\*Total CVEs\*\* \| )\S+",
        rf"\g<1>{stats['total_cves']}",
        content,
    )
    content = re.sub(
        r"(\*\*Average CVEs/Day\*\* \| )\S+",
        rf"\g<1>{stats['avg_cves_per_day']}",
        content,
    )
    content = re.sub(
        r"(\*\*Average CVSS Score\*\* \| )\S+",
        rf"\g<1>{stats['avg_cvss_score']}",
        content,
    )

    readme_path.write_text(content)
