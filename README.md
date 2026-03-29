# 📊 Monthly CVE Statistics

[![Data Updated](https://img.shields.io/badge/Data%20Updated-March 29, 2026-blue)](https://nvd.nist.gov/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![NVD](https://img.shields.io/badge/Source-NVD-orange)](https://nvd.nist.gov/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://www.python.org/)
[![Automated](https://img.shields.io/badge/Automated-Monthly-brightgreen)](https://github.com/jgamblin/monthlyCVEStats/actions)

> **Comprehensive tracking and analysis of CVE (Common Vulnerabilities and Exposures) data from the National Vulnerability Database (NVD).**

This repository provides **fully automated monthly analysis** of vulnerability trends, CVSS score distributions, CNA (CVE Numbering Authority) statistics, and CWE (Common Weakness Enumeration) patterns. All data is sourced directly from [NIST's National Vulnerability Database](https://nvd.nist.gov/).

Reports are **generated automatically on the 1st of each month at 7:00 AM Central Time** via GitHub Actions.

---

## 🔥 Current Statistics (March 29, 2026)

| Metric | Value |
|--------|-------|
| **Total CVEs** | 4,415 |
| **Average CVEs/Day** | 147.17 |
| **Average CVSS Score** | 6.57 |

> **Note:** Statistics are automatically updated every month. See [latest reports](outputs/) for detailed analysis.

---

## 📁 Repository Structure

```
monthlyCVEStats/
├── src/                         # Core Python application
│   ├── config.py               # Configuration management
│   ├── data/
│   │   ├── downloader.py       # NVD data downloader (resume-capable)
│   │   └── processor.py        # Data processor & flattening
│   ├── analysis/
│   │   ├── statistics.py       # CVSS, CNA, CWE analysis
│   │   └── trends.py           # YoY and growth analysis
│   ├── reports/
│   │   └── generator.py        # Report generation (MD, JSON, CSV)
│   ├── cli/
│   │   └── main.py             # Typer CLI interface
│   └── utils/
│       ├── logging.py          # Logging configuration
│       └── timezone_check.py   # Timezone verification
├── tests/
│   └── test_config.py          # Unit tests
├── outputs/                     # Generated reports (auto-updated)
│   ├── 2025/
│   │   ├── January/
│   │   │   ├── January.md
│   │   │   └── January.json
│   │   └── June/
│   │       ├── June.md
│   │       └── June.json
│   └── 2026/
├── data/
│   └── nvd.jsonl               # NVD data (auto-downloaded)
├── archive/                     # Legacy notebooks (2021-2026)
│   ├── 2021/ ... 2026/
│   └── notebooks/
├── .github/workflows/          # GitHub Actions automation
│   ├── monthly-update.yml      # 1st of month at 7 AM Central
│   ├── tests.yml               # PR & push testing
│   └── data-sync.yml           # Weekly data refresh
└── requirements.txt            # Python dependencies
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip or poetry for dependency management

### Installation & Local Testing

```bash
# Clone the repository
git clone https://github.com/jgamblin/monthlyCVEStats.git
cd monthlyCVEStats

# Install dependencies
pip install -r requirements.txt

# Download the latest NVD data (~1.3 GB, supports resume on interruption)
python -m src.cli.main download-data

# Run local analysis for a specific month
python -m src.cli.main generate-reports --year 2025 --month 1

# Validate the entire pipeline
python -m src.cli.main validate
```

> **Note:** The data download is ~1.3 GB. The download script shows a progress bar and supports automatic resume if interrupted.

### Available CLI Commands

```bash
# Download or update NVD data
python -m src.cli.main download-data

# Generate reports for a specific month
python -m src.cli.main generate-reports --year 2025 --month 1

# Run the complete monthly analysis pipeline
python -m src.cli.main run-monthly

# Validate configuration and setup
python -m src.cli.main validate

# Verify timezone is set correctly (for scheduled runs)
python -m src.cli.main check-timezone

# Update README with latest statistics
python -m src.cli.main update-readme-stats
```

### Automated Execution

**Reports are generated automatically every month.** The GitHub Actions workflow runs on the **1st of each month at 7:00 AM Central Time** and:

1. Downloads the latest NVD data
2. Analyzes CVE statistics and trends
3. Generates reports in Markdown and JSON
4. Updates the README with latest statistics
5. Commits and pushes results to the repository
6. Creates a GitHub release with the data

---

## 📈 Available Analyses

Each monthly report includes:

- 📊 **CVE Count Statistics** - Total CVEs, daily averages, growth rates
- 🎯 **CVSS Score Analysis** - Average scores, distribution by severity level
- 🏢 **CNA Rankings** - Most active CVE Numbering Authorities
- 🐛 **CWE Analysis** - Most common weakness enumeration types
- 📈 **Trend Analysis** - YoY growth, month-over-month comparisons

### Generated Report Formats

Each month generates:
- **Markdown** (`outputs/YYYY/MonthName/MonthName.md`) - Human-readable report
- **JSON** (`outputs/YYYY/MonthName/MonthName.json`) - Machine-readable data
- **CSV** (`outputs/YYYY/MonthName/MonthName.csv`) - Spreadsheet-compatible format

### Accessing Reports

View the latest reports in the [outputs/](outputs/) directory, organized by year and month.

---

## ⚙️ Architecture

### Data Pipeline
1. **Download** - NVD JSON data (~1.3 GB) with resume capability
2. **Process** - Flatten nested JSON structure into analyzable format
3. **Analyze** - Calculate statistics, trends, and patterns
4. **Report** - Generate multi-format output (MD, JSON, CSV)
5. **Deploy** - Commit results and create GitHub release

### Technology Stack
- **Python 3.10+** - Core language
- **Typer** - CLI framework
- **Pandas** - Data analysis
- **GitHub Actions** - Automation
- **PyArrow** - Fast data serialization

### Performance
- Processes 316,000+ CVE records in seconds
- Minimal resource footprint on GitHub Actions runners
- Resume-capable downloads (survives interruptions)

---

## 🧪 Testing

Run the test suite locally:

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_config.py
```

The test suite validates:
- Configuration management
- Directory structure
- CLI command functionality
- Report generation

Tests run automatically on all pull requests via GitHub Actions.

---

## 📊 Key Insights

The data reveals several important trends in vulnerability disclosure:

- **Exponential Growth**: CVE publications have grown significantly year-over-year
- **Seasonal Patterns**: Publication rates often spike around major security conferences
- **CNA Diversity**: The number of active CNAs continues to expand
- **CVSS Distribution**: Most vulnerabilities cluster around medium severity (5.0-7.5)

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Issues**: Found a bug or have a suggestion? [Open an issue](https://github.com/jgamblin/monthlyCVEStats/issues)
2. **Submit PRs**: Improvements to analysis, data processing, or features
3. **Share Ideas**: New metrics or analysis types you'd like to see
4. **Improve Docs**: Help improve documentation and examples

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes and add tests
4. Run tests locally (`pytest`)
5. Commit your changes
6. Push to your fork and create a Pull Request

All PRs are tested automatically.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [NIST National Vulnerability Database](https://nvd.nist.gov/) for providing the CVE data
- The security research community for their continued efforts in vulnerability disclosure

---

## 📬 Contact

**Jerry Gamblin** - [@jgamblin](https://twitter.com/jgamblin) - [rogolabs.net](https://rogolabs.net)

---

<p align="center">
  <i>Tracking vulnerabilities, one CVE at a time.</i>
</p>
</p>