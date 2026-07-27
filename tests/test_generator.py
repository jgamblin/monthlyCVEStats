"""Tests for report generation."""

import json

from src.reports.generator import ReportGenerator, _fmt, _label


def test_label_expands_acronyms():
    assert _label("avg_cves_per_day") == "Avg CVEs per day"
    assert _label("mean") == "Mean"
    assert _label("total_unique_cnas") == "Total unique CNAs"
    assert _label("percentile_75") == "Percentile 75"


def test_fmt_number_formatting():
    assert _fmt(6952) == "6,952"
    assert _fmt(6.862877792378449) == "6.86"
    assert _fmt(7.0) == "7"
    assert _fmt(224.26) == "224.26"
    assert _fmt("May") == "May"


def test_fmt_does_not_separate_years():
    """A year is an identifier, not a count: 2026, never 2,026."""
    assert _fmt(2026, "Year") == "2026"
    assert _fmt(2026, "year") == "2026"
    assert _fmt(2026) == "2,026"  # without the key it is just a number


def test_markdown_renders_tables(tmp_path):
    generator = ReportGenerator(tmp_path)
    path = generator.generate_markdown(
        title="CVE Report - May 2026",
        data={
            "Summary": {"Month": "May", "Year": 2026, "Total CVEs": 6952},
            "cvss": {"mean": 6.862877792378449, "median": 7.1},
        },
        filename="May.md",
    )
    content = path.read_text()

    assert content.startswith("# CVE Report - May 2026")
    assert "Source: NVD, excluding rejected CVEs" in content
    # Human headings, not raw analysis keys.
    assert "## CVSS Scores" in content
    assert "## cvss" not in content
    # Tables, not bulleted key-value dumps.
    assert "| Metric | Value |" in content
    assert "| Total CVEs | 6,952 |" in content
    assert "- **mean**" not in content
    # Full float precision never reaches the page.
    assert "6.862877792378449" not in content
    assert "| Mean | 6.86 |" in content
    # Years are not counts.
    assert "| Year | 2026 |" in content
    assert "2,026" not in content


def test_markdown_suppresses_duplicate_timestamps(tmp_path):
    """The header already carries the timestamp; the table should not repeat it."""
    generator = ReportGenerator(tmp_path)
    path = generator.generate_markdown(
        title="CVE Report",
        data={
            "Summary": {
                "Total CVEs": 10,
                "Generated": "2026-06-01 12:05:40",
                "Date": "2026-06-01",
            }
        },
        filename="report.md",
        generated="2026-06-01 12:05:40",
    )
    content = path.read_text()

    assert content.count("2026-06-01 12:05:40") == 1
    assert "| Generated |" not in content
    assert "| Date |" not in content
    assert "| Total CVEs | 10 |" in content


def test_markdown_respects_supplied_timestamp(tmp_path):
    """Regenerating an old report must not restamp it with today's date."""
    generator = ReportGenerator(tmp_path)
    path = generator.generate_markdown(
        title="CVE Report",
        data={"Summary": {"Total CVEs": 10}},
        filename="report.md",
        generated="2026-06-01 12:05:40",
    )
    assert "Generated 2026-06-01 12:05:40" in path.read_text()


def test_markdown_drops_empty_sections(tmp_path, caplog):
    generator = ReportGenerator(tmp_path)
    path = generator.generate_markdown(
        title="CVE Report",
        data={
            "Summary": {"Total CVEs": 10},
            "cna": {},
            "daily": {},
            "growth": {},
        },
        filename="report.md",
    )
    content = path.read_text()

    assert "## CVE Numbering Authorities" not in content
    assert "## Daily Publication" not in content
    assert "## Growth Rate" not in content
    # The omission is logged rather than silent.
    assert "Omitted 3 empty report section(s)" in caplog.text
    assert "cna" in caplog.text


def test_markdown_renders_ranked_nested_tables(tmp_path):
    generator = ReportGenerator(tmp_path)
    path = generator.generate_markdown(
        title="CVE Report",
        data={
            "cwe": {
                "total_unique_cwes": 340,
                "top_cwes": {"CWE-79": 571, "CWE-89": 280},
            },
            "cvss": {"severity_counts": {"Critical": 100, "High": 200}},
        },
        filename="report.md",
    )
    content = path.read_text()

    assert "### Most common weaknesses" in content
    assert "| # | CWE | CVEs |" in content
    assert "| 1 | CWE-79 | 571 |" in content
    assert "| 2 | CWE-89 | 280 |" in content
    # Unranked tables get no rank column.
    assert "### Severity distribution" in content
    assert "| Severity | CVEs |" in content
    assert "| Critical | 100 |" in content


def test_json_report_keys_are_stable(tmp_path):
    """readme_updater and ytd_growth both read this shape."""
    generator = ReportGenerator(tmp_path)
    data = {
        "Summary": {"Month": "May", "Year": 2026, "Total CVEs": 6952},
        "cvss": {"mean": 6.86, "median": 7.1, "percentile_75": 8.1},
        "cwe": {"top_cwes": {"CWE-79": 571}},
    }
    path = generator.generate_json(data=data, filename="May.json")

    loaded = json.loads(path.read_text())
    assert "generated_at" in loaded
    assert loaded["data"]["Summary"]["Total CVEs"] == 6952
    assert loaded["data"]["cvss"]["median"] == 7.1
    assert loaded["data"]["cwe"]["top_cwes"]["CWE-79"] == 571
