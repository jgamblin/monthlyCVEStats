# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Automated Python pipeline that downloads CVE data from NIST's NVD, analyzes vulnerability trends, and generates monthly reports with YTD visualizations. Runs on the 1st of each month at 7 AM CT via GitHub Actions.

## Commands

### Run the application

```bash
pip install -r requirements.txt

# CLI entry point (all commands)
python -m src.cli.main --help

# Core pipeline commands
python -m src.cli.main download-data
python -m src.cli.main run-monthly
python -m src.cli.main generate-reports --year 2025 --month 1
python -m src.cli.main generate-ytd-report
python -m src.cli.main update-readme-stats
```

### Testing

```bash
pytest                              # all tests
pytest -v                           # verbose
pytest tests/test_config.py         # single file
pytest --cov=src --cov-report=html  # with coverage
```

### Linting & Formatting

```bash
black --check src/ tests/
flake8 src/ tests/ --select=E9,F63,F7,F82 --show-source
flake8 src/ tests/ --max-complexity=10 --max-line-length=100
mypy src/ --ignore-missing-imports
```

## Architecture

**Data pipeline flow:** Download → Process → Analyze → Report

- **`src/config.py`** — Centralized config: paths, NVD source URL, date selection, CI detection
- **`src/data/downloader.py`** — Downloads ~1.3 GB NVD JSON with resume capability and retry logic
- **`src/data/processor.py`** — Flattens nested CVE JSON into Pandas DataFrames, filters by date, extracts CVSS/CWE/CNA fields
- **`src/analysis/statistics.py`** — CVSS distribution, CNA rankings, CWE analysis
- **`src/analysis/trends.py`** — Month-over-month and year-over-year growth rates
- **`src/analysis/ytd_growth.py`** — Year-to-date cumulative analysis, generates social media summary text
- **`src/reports/generator.py`** — Outputs Markdown, JSON, CSV reports
- **`src/reports/ytd_visualizer.py`** — Matplotlib charts (dark/light themes, landscape/square formats)
- **`src/cli/main.py`** — Typer CLI with all commands

## Output Structure

Reports go to `YYYY/MonthName/` (e.g., `2025/March/March.md`). YTD visualizations and `post.txt` go to `YYYY/`.

## CI/CD

- **`monthly-update.yml`** — Runs full pipeline on 1st of month (13:00 UTC). Creates GitHub Release. Reports failures as issues.
- **`tests.yml`** — Runs on push/PR to main/develop. Matrix: Python 3.10, 3.11, 3.12. Runs flake8, black, mypy, pytest with coverage.
- **`data-sync.yml`** — Weekly Sunday data refresh to keep NVD data current between monthly runs.

## Key Details

- NVD data source: `https://nvd.handsonhacking.org/nvd.jsonl` (single-line JSON array)
- CVSS extraction handles both v3.0 and v3.1 metrics
- Test markers: `@pytest.mark.integration`, `@pytest.mark.unit`, `@pytest.mark.slow`
- The `data/` directory contents (`.jsonl`, `.json`) are gitignored; only code is tracked
