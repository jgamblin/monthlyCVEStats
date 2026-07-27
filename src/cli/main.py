"""Main CLI entry point for CVE statistics."""

import sys
from datetime import datetime
from typing import Any, Optional

try:
    import typer
except ImportError:
    print("Error: typer not installed. Install with: pip install typer")
    sys.exit(1)

from src.config import Config
from src.utils.logging import setup_logging
from src.utils.timezone_check import verify_central_time
from src.utils.readme_updater import update_readme
from src.data.downloader import NVDDownloader
from src.data.processor import DataProcessor
from src.analysis.statistics import StatisticsAnalyzer
from src.analysis.trends import TrendAnalyzer
from src.analysis.ytd_growth import YTDAnalyzer
from src.reports.generator import ReportGenerator
from src.reports.ytd_visualizer import YTDVisualizer

app = typer.Typer(
    help="CVE Statistics - Monthly automated CVE analysis and reporting",
    no_args_is_help=True,
)
logger = setup_logging(__name__)


@app.command()
def download_data(
    resume: bool = typer.Option(
        True, "--resume/--no-resume", help="Resume interrupted downloads"
    ),
) -> None:
    """Download the latest NVD data."""
    logger.info("Starting NVD data download...")
    Config.ensure_directories()

    downloader = NVDDownloader(
        output_file=Config.NVD_DATA_FILE,
        source_url=Config.NVD_SOURCE_URL,
        chunk_size=Config.DOWNLOAD_CHUNK_SIZE,
    )

    if downloader.download(resume=resume):
        if downloader.verify():
            logger.info("✓ NVD data downloaded and verified successfully")
            return
        else:
            logger.error("✗ Download verification failed")
            sys.exit(1)
    else:
        logger.error("✗ Download failed")
        sys.exit(1)


def run_analysis(year: int, month: Optional[int] = None) -> bool:
    """Run the full analysis for one month, or a whole year when month is None.

    Shared by ``run-monthly`` and ``generate-reports`` so both produce the same
    report. They write to the same filenames, so a thinner second code path here
    means one command silently guts the other's output.

    Args:
        year: Year to analyze
        month: Month to report on, or None for the full year

    Returns:
        True if a report was written
    """
    period = f"{year}-{month:02d}" if month else str(year)
    logger.info(f"Analyzing CVE data for {period}")

    # Load the whole year, then slice the reporting month out of it. The trend
    # analyses need more than one month to say anything, so they get the year.
    processor = DataProcessor(Config.NVD_DATA_FILE)
    df_year = processor.load_to_dataframe(year=year)

    if df_year.empty:
        logger.warning("No CVE data found for %d", year)
        return False

    # Three scopes: the reporting month for the month's own statistics, the year
    # through that month for the trend sections, and the raw year for neither.
    # The trend sections must stop at the reporting month, or a report on a
    # completed month picks up the in-progress one after it and presents a
    # partial total as that month's figure.
    if month is None or "published" not in df_year.columns:
        if month is not None:
            logger.warning("No 'published' column; reporting on the full year")
        df = df_ytd = df_year
    else:
        months = df_year["published"].dt.month
        df = df_year[months == month]
        df_ytd = df_year[months <= month]

    if df.empty:
        logger.warning("No CVE data found for %s", period)
        return False

    logger.info(f"Loaded {len(df)} CVE records for {period}")

    stats_analyzer = StatisticsAnalyzer()
    trend_analyzer = TrendAnalyzer()

    # If the reporting month has not finished, it holds fewer days than the
    # months it would be ranked against, so it is excluded from the rankings and
    # reported separately on a daily rate.
    now = datetime.now()
    partial_period = partial_days = None
    if month is not None and (year, month) == (now.year, now.month):
        partial_period = f"{year}-{month:02d}"
        partial_days = now.day

    analysis_results = {
        "cvss": stats_analyzer.analyze_cvss_distribution(df),
        "cna": stats_analyzer.analyze_by_cna(df),
        "cwe": stats_analyzer.analyze_by_cwe(df),
        "daily": stats_analyzer.daily_distribution(df),
        "monthly_trend": trend_analyzer.monthly_trend(
            df_ytd, partial_period=partial_period, partial_days=partial_days
        ),
        "growth": trend_analyzer.growth_rate(df_ytd, partial_period=partial_period),
    }

    logger.info(f"✓ Analysis complete: {len(df)} CVEs processed")

    # A manual run can land inside the month it is reporting on. Say so on the
    # page rather than presenting a part-month total as the month's figure.
    source_note = "NVD, excluding rejected CVEs"
    now = datetime.now()
    if month is not None and (year, month) == (now.year, now.month):
        month_name = datetime(year, month, 1).strftime("%B")
        source_note += (
            f". {month_name} {year} is still in progress: "
            f"data through {month_name} {now.day}"
        )
        logger.warning(
            "Reporting on %s %d while it is still in progress", month_name, year
        )

    generate_reports_internal(year, month, df, analysis_results, source_note)
    return True


@app.command()
def run_monthly() -> None:
    """Run monthly CVE analysis."""
    logger.info("Starting monthly CVE analysis...")
    Config.ensure_directories()

    # Verify timezone
    verify_central_time()

    year, month = Config.get_current_month_info()
    run_analysis(year, month)


@app.command()
def generate_reports(
    year: int = typer.Option(None, "--year", help="Year to generate reports for"),
    month: int = typer.Option(None, "--month", help="Month to generate reports for"),
) -> None:
    """Generate reports for a specific month, or a whole year with no --month."""
    if year is None:
        year, month = Config.get_current_month_info()

    Config.ensure_directories()
    run_analysis(year, month)


@app.command()
def validate() -> None:
    """Validate data and configuration."""
    logger.info("Validating configuration and data...")
    Config.ensure_directories()

    # Check config
    logger.info(f"Config: {Config.to_dict()}")

    # Check data file
    if Config.NVD_DATA_FILE.exists():
        file_size = Config.NVD_DATA_FILE.stat().st_size
        logger.info(f"✓ NVD data file exists ({file_size / 1024 / 1024:.1f} MB)")
    else:
        logger.warning("⚠ NVD data file not found - run 'download-data' first")

    logger.info("✓ Validation complete")


@app.command()
def check_timezone() -> None:
    """Check and display current timezone info."""
    verify_central_time()
    logger.info("✓ Timezone check complete")


@app.command()
def update_readme_stats() -> None:
    """Update README.md with latest statistics from reports."""
    logger.info("Updating README with latest statistics...")
    if update_readme():
        logger.info("✓ README updated successfully")
    else:
        logger.error("✗ Failed to update README")
        sys.exit(1)


@app.command()
def generate_ytd_report() -> None:
    """Generate YTD (Year-to-Date) growth report with visualizations."""
    logger.info("Generating YTD growth report...")
    Config.ensure_directories()

    # Analyze YTD growth
    ytd_analyzer = YTDAnalyzer(Config.NVD_DATA_FILE)
    analysis = ytd_analyzer.analyze_ytd()

    if not analysis["current_year_data"]:
        logger.warning("No CVE data found for YTD analysis")
        return

    logger.info(f"YTD Analysis: {analysis['statistics']['current_ytd_total']} CVEs")

    # Create visualizations
    output_dir = Config.OUTPUT_DIR / str(analysis["current_year"])
    output_dir.mkdir(parents=True, exist_ok=True)

    visualizer = YTDVisualizer(output_dir)
    through_month = analysis["statistics"]["current_month"]

    # Common chart kwargs
    chart_kwargs = dict(
        daily_current=analysis["current_daily_cumulative"],
        daily_previous=analysis["previous_daily_cumulative"],
        stats=analysis["statistics"],
        monthly_data=analysis["current_year_data"],
        previous_monthly_data=analysis["previous_year_data"],
    )

    # Every ratio in both themes: wide for X, square and portrait for the feed.
    logger.info("Creating YTD growth charts...")
    for ratio in ("wide", "square", "portrait"):
        for dark_mode in (True, False):
            visualizer.create_chart(
                analysis["current_cumulative"],
                analysis["previous_cumulative"],
                analysis["current_year"],
                ratio=ratio,
                dark_mode=dark_mode,
                through_month=through_month,
                **chart_kwargs,
            )

    visualizer.create_yoy_comparison(
        analysis["current_year"],
        analysis["previous_year"],
        analysis["statistics"]["current_ytd_total"],
        analysis["statistics"]["previous_ytd_total"],
        analysis["statistics"]["yoy_percent"],
        through_month=through_month,
    )

    # Generate summary text
    logger.info("Generating summary text for social posts...")
    summary_text = ytd_analyzer.get_summary_text(analysis)

    # Save summary to file
    summary_file = output_dir / "post.txt"
    summary_file.write_text(summary_text)
    logger.info(f"✓ Summary saved to {summary_file}")

    # Generate enriched post with CVSS/CWE context from monthly report
    year, month = Config.get_current_month_info()
    month_name = datetime(year, month, 1).strftime("%B")
    report_json = Config.get_report_output_dir(year, month) / f"{month_name}.json"
    if report_json.exists():
        import json

        with open(report_json) as f:
            monthly_report = json.load(f).get("data", {})
        enriched_text = ytd_analyzer.get_enriched_text(analysis, monthly_report)
        enriched_file = output_dir / "enriched_post.txt"
        enriched_file.write_text(enriched_text)
        logger.info(f"✓ Enriched post saved to {enriched_file}")
    else:
        logger.warning(
            f"Monthly report not found at {report_json}, skipping enriched post"
        )

    # Print summary for user
    logger.info("\n" + "=" * 70)
    logger.info("YTD GROWTH REPORT")
    logger.info("=" * 70)
    logger.info(summary_text)
    logger.info("=" * 70)

    logger.info(f"✓ YTD report generated in {output_dir}")


def generate_reports_internal(
    year: int,
    month: Optional[int],
    df,
    analysis_results: dict,
    source_note: str = "NVD, excluding rejected CVEs",
) -> None:
    """Write the Markdown and JSON reports for a month, or a year if month is None."""
    output_dir = Config.get_report_output_dir(year, month)
    report_generator = ReportGenerator(output_dir)

    summary: dict[str, Any]
    if month is None:
        stem = "Annual"
        title = f"CVE Report - {year}"
        summary = {"Year": year, "Total CVEs": len(df)}
    else:
        stem = datetime(year, month, 1).strftime("%B")
        title = f"CVE Report - {stem} {year}"
        # readme_updater requires Month and Year to label the stats block.
        summary = {"Month": stem, "Year": year, "Total CVEs": len(df)}

    report_data = {"Summary": summary, **analysis_results}

    report_generator.generate_markdown(
        title=title,
        data=report_data,
        filename=f"{stem}.md",
        source_note=source_note,
    )

    report_generator.generate_json(
        data=report_data,
        filename=f"{stem}.json",
    )

    logger.info(f"✓ Reports written to {output_dir}")


if __name__ == "__main__":
    app()
