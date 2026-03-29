# Modernization Guide - Monthly CVE Stats

This document outlines the modernization of the monthlyCVEStats repository from Jupyter notebooks to a fully automated, production-ready Python application.

## Overview

The repository has been restructured to:
- **Eliminate notebook dependencies**: Move from `.ipynb` files to pure Python scripts
- **Enable full automation**: Run monthly updates automatically via GitHub Actions at 7 AM Central
- **Improve maintainability**: Modular architecture with clear separation of concerns
- **Add testing & validation**: Comprehensive test suite with CI/CD integration
- **Generate multiple outputs**: Markdown reports, JSON data, and visualizations

## Architecture

### Directory Structure

```
src/
├── __init__.py
├── config.py                 # Centralized configuration
├── data/
│   ├── __init__.py
│   ├── downloader.py        # NVD data downloading
│   ├── processor.py         # Data processing & ETL
│   └── cache.py             # Caching layer (future)
├── analysis/
│   ├── __init__.py
│   ├── statistics.py        # Statistical analysis
│   └── trends.py            # Trend analysis
├── reports/
│   ├── __init__.py
│   ├── generator.py         # Report generation
│   └── visualizations.py    # Chart generation (future)
├── utils/
│   ├── __init__.py
│   ├── logging.py           # Logging setup
│   └── timezone_check.py    # Timezone verification
└── cli/
    ├── __init__.py
    └── main.py              # CLI entry point (Typer)
```

## Key Components

### 1. **Configuration Management** (`src/config.py`)
Centralized settings for paths, data sources, and output formats.

```python
from src.config import Config

# Automatic month detection
year, month = Config.get_current_month_info()

# Output directory management
output_dir = Config.get_report_output_dir(year, month)
```

### 2. **Data Pipeline** (`src/data/`)

#### Downloader (`downloader.py`)
- Resume-capable downloads with progress tracking
- Automatic retry logic for network failures
- File verification before processing

```python
from src.data import NVDDownloader

downloader = NVDDownloader(
    output_file=Config.NVD_DATA_FILE,
    source_url=Config.NVD_SOURCE_URL,
)
downloader.download(resume=True)
```

#### Processor (`processor.py`)
- Load JSONL data into Pandas DataFrames
- Filter by year/month
- Convert to analysis-ready format

```python
from src.data import DataProcessor

processor = DataProcessor(Config.NVD_DATA_FILE)
df = processor.load_to_dataframe(year=2026, month=3)
```

### 3. **Analysis Engine** (`src/analysis/`)

#### Statistics (`statistics.py`)
- CVSS distribution analysis
- CVE Numbering Authority (CNA) rankings
- Common Weakness Enumeration (CWE) patterns
- Daily distribution metrics

```python
from src.analysis import StatisticsAnalyzer

analyzer = StatisticsAnalyzer()
cvss_stats = analyzer.analyze_cvss_distribution(df)
cna_stats = analyzer.analyze_by_cna(df, top_n=10)
```

#### Trends (`trends.py`)
- Month-over-month trends
- Year-over-year comparisons
- Growth rate calculations

```python
from src.analysis import TrendAnalyzer

analyzer = TrendAnalyzer()
yoy = analyzer.year_over_year(df, compare_years=(2025, 2026))
growth = analyzer.growth_rate(df, period='M')
```

### 4. **Report Generation** (`src/reports/`)

Generate output in multiple formats:
- **Markdown** (.md) - For GitHub/documentation
- **JSON** (.json) - For API consumption
- **CSV** (.csv) - For spreadsheet analysis

```python
from src.reports import ReportGenerator

generator = ReportGenerator(output_dir)
generator.generate_markdown(
    title="CVE Report - March 2026",
    data=analysis_results,
)
generator.generate_json(data=analysis_results)
```

### 5. **CLI Interface** (`src/cli/main.py`)

Single entry point using Typer framework:

```bash
# Download NVD data
python -m src.cli.main download-data

# Run monthly analysis
python -m src.cli.main run-monthly

# Generate reports
python -m src.cli.main generate-reports --year 2026 --month 3

# Validate configuration and data
python -m src.cli.main validate

# Check timezone settings
python -m src.cli.main check-timezone
```

## GitHub Actions Automation

### Monthly Update Workflow (monthly-update.yml)

**Trigger**: 1st of every month at 7:00 AM Central Time (13:00 UTC)

**Steps**:
1. Checkout repository
2. Setup Python environment
3. Verify Central Time execution
4. Download latest NVD data
5. Run monthly analysis
6. Generate reports (Markdown + JSON)
7. Validate outputs
8. Commit results to repository
9. Create GitHub release (on success)
10. Create issue (on failure)

### Test Workflow (tests.yml)

**Trigger**: Every push and pull request

**Checks**:
- Pytest unit tests (Python 3.10, 3.11, 3.12)
- Code style with Black and Flake8
- Type checking with MyPy
- Code coverage reporting

### Data Sync Workflow (data-sync.yml)

**Trigger**: Every Sunday at 00:00 UTC + manual trigger

**Purpose**: Keep NVD data fresh between monthly updates

## Local Development

### Setup

```bash
# Clone and setup
git clone https://github.com/jgamblin/monthlyCVEStats.git
cd monthlyCVEStats

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download NVD data (first time only)
python -m src.cli.main download-data
```

### Running Locally

```bash
# Run monthly analysis
python -m src.cli.main run-monthly

# Generate reports for specific month
python -m src.cli.main generate-reports --year 2026 --month 3

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

### Testing

```bash
# All tests
pytest

# Specific test file
pytest tests/test_config.py

# With verbose output
pytest -v

# With coverage
pytest --cov=src

# Quick smoke test
pytest -k "config" -v
```

## Migration from Notebooks

### What Changed

**Before (Notebooks)**:
- Analysis logic scattered across `.ipynb` cells
- Manual execution required monthly
- Version control issues with notebook diffs
- Hard to test individual components
- Difficult to share code between notebooks

**After (Pure Python)**:
- Modular, testable functions in `.py` files
- Fully automated via GitHub Actions
- Clean Git history with code diffs
- Comprehensive test suite
- Reusable components across modules

### Notebook Reference

The original notebooks are kept in the `notebooks/` directory for reference and exploratory work, but are no longer used for the automated pipeline.

To reference analysis from old notebooks:
1. Review the corresponding module in `src/analysis/`
2. Check the CLI command in `src/cli/main.py`
3. Run tests with `pytest tests/` to validate behavior

## Output Structure

Monthly reports are organized as:

```
outputs/
├── 2026/
│   ├── January/
│   │   ├── January.md
│   │   ├── January.json
│   │   └── images/
│   │       ├── cvss_distribution.png
│   │       └── yoy_comparison.png
│   ├── February/
│   └── ...
```

Each report contains:
- **Executive summary** with total CVE counts
- **Statistical analysis** (CVSS scores, CNAs, CWEs)
- **Daily distribution** metrics
- **Trend analysis** (month-over-month, year-over-year)
- **Embedded visualizations**

## Configuration

### Environment Variables

Create a `.env` file (or use GitHub Actions secrets):

```
LOG_LEVEL=INFO
NVD_SOURCE_URL=https://nvd.handsonhacking.org/nvd.jsonl
```

### Config File (`src/config.py`)

Centralized settings:
- **Paths**: Data directory, output directory, cache directory
- **Data sources**: NVD URL, chunk sizes
- **Analysis**: Default filtering, report formats
- **Logging**: Level, format

## Troubleshooting

### Workflow Runs but No Output

1. Check GitHub Actions logs: **Actions** tab in repo
2. Verify NVD data download succeeded
3. Check timezone with: `python -m src.cli.main check-timezone`
4. Run locally: `python -m src.cli.main run-monthly`

### NVD Data Download Fails

1. Check network connectivity
2. Verify source URL is accessible
3. Check disk space for ~1.4 GB file
4. Try manual download: `python -m src.cli.main download-data --no-resume`

### Tests Failing

```bash
# Run tests locally
pytest -v

# Check specific failures
pytest tests/test_config.py -v

# See detailed output
pytest -vv --tb=long
```

## Future Enhancements

- [ ] Visualization module (`src/reports/visualizations.py`)
- [ ] Data caching layer (`src/data/cache.py`)
- [ ] API endpoint for report data
- [ ] Email notifications on update completion
- [ ] Historical trend graphs
- [ ] Slack/Discord webhook notifications
- [ ] Database backend for scaling

## Performance Notes

- **Data processing**: ~30 seconds for full dataset (Pandas 3 + PyArrow)
- **Report generation**: ~5 seconds
- **Total monthly run**: ~2-3 minutes (including download)
- **GitHub Actions runtime**: 5-10 minutes (mostly network I/O)

## Support

For issues or questions:

1. Check GitHub Issues for existing reports
2. Review the [API documentation](src/cli/main.py)
3. Run tests: `pytest -v`
4. Check workflow logs on GitHub Actions

## Contributing

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make changes and write tests: `pytest tests/`
3. Run linting: `black src/ tests/` and `flake8 src/`
4. Commit with clear messages
5. Push and create a pull request

Code will be automatically tested before merging.

## License

MIT License - See LICENSE file
