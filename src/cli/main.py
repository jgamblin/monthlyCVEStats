"""Main CLI entry point for CVE statistics."""

import logging
import sys
from datetime import datetime
from pathlib import Path

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
def download_data(resume: bool = typer.Option(
    True,
    "--resume/--no-resume",
    help="Resume interrupted downloads"
)) -> None:
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


@app.command()
def run_monthly() -> None:
    """Run monthly CVE analysis."""
    logger.info("Starting monthly CVE analysis...")
    Config.ensure_directories()

    # Verify timezone
    verify_central_time()

    # Get current month info
    year, month = Config.get_current_month_info()
    logger.info(f"Analyzing CVE data for {year}-{month:02d}")

    # Load and process data
    processor = DataProcessor(Config.NVD_DATA_FILE)
    df = processor.load_to_dataframe(year=year, month=month)

    if df.empty:
        logger.warning("No CVE data found for the specified period")
        return

    logger.info(f"Loaded {len(df)} CVE records")

    # Run analyses
    stats_analyzer = StatisticsAnalyzer()
    trend_analyzer = TrendAnalyzer()

    cvss_stats = stats_analyzer.analyze_cvss_distribution(df)
    cna_stats = stats_analyzer.analyze_by_cna(df)
    cwe_stats = stats_analyzer.analyze_by_cwe(df)
    daily_dist = stats_analyzer.daily_distribution(df)

    monthly_trend = trend_analyzer.monthly_trend(df)
    growth = trend_analyzer.growth_rate(df)

    logger.info(f"✓ Analysis complete: {len(df)} CVEs processed")

    # Generate reports
    generate_reports_internal(year, month, df, {
        "cvss": cvss_stats,
        "cna": cna_stats,
        "cwe": cwe_stats,
        "daily": daily_dist,
        "monthly_trend": monthly_trend,
        "growth": growth,
    })


@app.command()
def generate_reports(
    year: int = typer.Option(None, "--year", help="Year to generate reports for"),
    month: int = typer.Option(None, "--month", help="Month to generate reports for"),
) -> None:
    """Generate reports for specified period."""
    if year is None:
        year, month = Config.get_current_month_info()

    month_str = f"{month:02d}" if month else "all months"
    logger.info(f"Generating reports for {year}-{month_str}")
    Config.ensure_directories()

    processor = DataProcessor(Config.NVD_DATA_FILE)
    df = processor.load_to_dataframe(year=year, month=month)

    if df.empty:
        logger.warning("No CVE data found")
        return

    # Run quick analysis
    stats_analyzer = StatisticsAnalyzer()
    cvss_stats = stats_analyzer.analyze_cvss_distribution(df)

    output_dir = Config.get_report_output_dir(year, month)
    month_name = datetime(year, month, 1).strftime("%B") if month else "Full Year"

    report_generator = ReportGenerator(output_dir)

    # Generate markdown report
    report_data = {
        "Summary": {
            "Total CVEs": len(df),
            "Date": datetime.now().strftime("%Y-%m-%d"),
        },
        "CVSS Statistics": cvss_stats,
    }

    report_generator.generate_markdown(
        title=f"CVE Report - {month_name} {year}",
        data=report_data,
        filename=f"{month_name}.md" if month else "Annual.md",
    )

    # Generate JSON report
    report_generator.generate_json(
        data=report_data,
        filename=f"{month_name}.json" if month else "Annual.json",
    )

    logger.info(f"✓ Reports generated in {output_dir}")


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

    # Create all chart formats
    logger.info("Creating YTD growth charts...")
    visualizer.create_ytd_chart(
        analysis["current_cumulative"],
        analysis["previous_cumulative"],
        analysis["current_year"],
        dark_mode=True,
    )

    visualizer.create_ytd_chart(
        analysis["current_cumulative"],
        analysis["previous_cumulative"],
        analysis["current_year"],
        dark_mode=False,
    )

    visualizer.create_square_chart(
        analysis["current_cumulative"],
        analysis["previous_cumulative"],
        analysis["current_year"],
        dark_mode=True,
    )

    visualizer.create_square_chart(
        analysis["current_cumulative"],
        analysis["previous_cumulative"],
        analysis["current_year"],
        dark_mode=False,
    )

    visualizer.create_yoy_comparison(
        analysis["current_year"],
        analysis["previous_year"],
        analysis["statistics"]["current_ytd_total"],
        analysis["statistics"]["previous_ytd_total"],
        analysis["statistics"]["yoy_percent"],
    )

    # Generate summary text
    logger.info("Generating summary text for social posts...")
    summary_text = ytd_analyzer.get_summary_text(analysis)

    # Save summary to file
    summary_file = output_dir / "YTD_SUMMARY.txt"
    summary_file.write_text(summary_text)
    logger.info(f"✓ Summary saved to {summary_file}")

    # Print summary for user
    logger.info("\n" + "=" * 70)
    logger.info("YTD GROWTH REPORT")
    logger.info("=" * 70)
    logger.info(summary_text)
    logger.info("=" * 70)

    logger.info(f"✓ YTD report generated in {output_dir}")


def generate_reports_internal(year: int, month: int, df, analysis_results: dict) -> None:
    """Internal helper to generate reports."""
    output_dir = Config.get_report_output_dir(year, month)
    month_name = datetime(year, month, 1).strftime("%B")

    report_generator = ReportGenerator(output_dir)

    report_data = {
        "Summary": {
            "Month": month_name,
            "Year": year,
            "Total CVEs": len(df),
            "Generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        **analysis_results,
    }

    report_generator.generate_markdown(
        title=f"CVE Report - {month_name} {year}",
        data=report_data,
        filename=f"{month_name}.md",
    )

    report_generator.generate_json(
        data=report_data,
        filename=f"{month_name}.json",
    )

    logger.info(f"✓ Reports written to {output_dir}")


if __name__ == "__main__":
    app()
