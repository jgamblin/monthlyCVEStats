"""Generate reports from CVE analysis."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd

# Internal analysis keys mapped to the headings that appear in the report. Any
# section not listed here falls back to a title-cased version of its key.
SECTION_TITLES = {
    "Summary": "Summary",
    "cvss": "CVSS Scores",
    "cna": "CVE Numbering Authorities",
    "cwe": "Weakness Types",
    "daily": "Daily Publication",
    "monthly_trend": "Monthly Trend",
    "growth": "Growth Rate",
}

# Nested tables: key -> (heading, name column header, value column header, ranked)
NESTED_TABLES = {
    "top_cnas": ("Most active CNAs", "CNA", "CVEs", True),
    "top_cwes": ("Most common weaknesses", "CWE", "CVEs", True),
    "severity_counts": ("Severity distribution", "Severity", "CVEs", False),
    "monthly_counts": ("CVEs by month", "Month", "CVEs", False),
    "yearly_counts": ("CVEs by year", "Year", "CVEs", False),
}

# How acronym tokens are cased when a snake_case key becomes a label. Plurals are
# listed explicitly so 'cves' does not come out as 'CVES'.
_ACRONYM_FORMS = {
    "cvss": "CVSS",
    "cve": "CVE",
    "cves": "CVEs",
    "cna": "CNA",
    "cnas": "CNAs",
    "cwe": "CWE",
    "cwes": "CWEs",
    "yoy": "YoY",
    "ytd": "YTD",
    "id": "ID",
}

_SMALL_WORDS = {"per", "of", "in", "vs", "with", "and", "a"}

# Counts get thousands separators; these are identifiers that happen to be
# numeric, so 'Year: 2026' must not become 'Year: 2,026'.
_UNSEPARATED_KEYS = {"year", "years", "month", "day"}

# Keys dropped from the rendered tables because the report header already
# carries the same timestamp on its own line.
_SUPPRESSED_KEYS = {"generated", "generated_at", "date"}


def _label(key: str) -> str:
    """'avg_cves_per_day' -> 'Avg CVEs per day'.

    Keys that already read as display labels (they contain a space, like the
    'Total CVEs' summary keys) are passed through untouched.
    """
    key = str(key)
    if " " in key:
        return key

    words = key.replace("-", "_").split("_")
    out = []
    for index, word in enumerate(words):
        lowered = word.lower()
        if lowered in _ACRONYM_FORMS:
            out.append(_ACRONYM_FORMS[lowered])
        elif index == 0:
            out.append(word[:1].upper() + word[1:].lower())
        elif lowered in _SMALL_WORDS:
            out.append(lowered)
        else:
            out.append(lowered)
    return " ".join(out)


def _fmt(value, key: str = "") -> str:
    """Format a metric value for display."""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, int):
        if key.lower() in _UNSEPARATED_KEYS:
            return str(value)
        return f"{value:,}"
    if isinstance(value, float):
        if value.is_integer():
            return f"{int(value):,}"
        return f"{value:,.2f}".rstrip("0").rstrip(".")
    return str(value)


class ReportGenerator:
    """Generate reports in multiple formats."""

    def __init__(self, output_dir: Path):
        """Initialize generator.

        Args:
            output_dir: Directory to write reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def generate_markdown(
        self,
        title: str,
        data: dict,
        filename: Optional[str] = None,
        source_note: str = "NVD, excluding rejected CVEs",
        generated: Optional[str] = None,
    ) -> Path:
        """Generate a Markdown report.

        Empty analysis sections are dropped rather than rendered as bare headings,
        and the names of any dropped sections are logged so a silently failing
        analyzer does not just look like a quiet month.

        Args:
            title: Report title
            data: Dictionary of sections to include
            filename: Output filename (auto-generated if not provided)
            source_note: Data provenance line
            generated: Timestamp to record; defaults to now. Pass the companion
                JSON's ``generated_at`` when regenerating an existing report so
                the two do not disagree about when the data was gathered.

        Returns:
            Path to generated report
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.md"

        filepath = self.output_dir / filename
        if generated is None:
            generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines = [f"# {title}", ""]
        lines.append(f"Generated {generated}  ·  Source: {source_note}")
        lines.append("")

        empty_sections = []
        for section, section_data in data.items():
            if not section_data and section_data != 0:
                empty_sections.append(section)
                continue

            lines.append(f"## {SECTION_TITLES.get(section, _label(section))}")
            lines.append("")
            lines.extend(self._render_section(section_data))
            lines.append("")

        if empty_sections:
            self.logger.warning(
                "Omitted %d empty report section(s): %s",
                len(empty_sections),
                ", ".join(empty_sections),
            )

        content = "\n".join(lines).rstrip() + "\n"

        try:
            filepath.write_text(content)
            self.logger.info(f"Markdown report written to {filepath}")
            return filepath
        except IOError as e:
            self.logger.error(f"Error writing markdown report: {e}")
            raise

    def _render_section(self, section_data) -> list[str]:
        """Render one section: a metrics table plus any nested tables."""
        if isinstance(section_data, dict):
            return self._render_dict(section_data)
        if isinstance(section_data, list):
            return [f"- {item}" for item in section_data]
        return [str(section_data)]

    def _render_dict(self, section_data: dict) -> list[str]:
        """Scalars become a two-column metrics table; dicts become sub-tables."""
        scalars = {}
        nested = {}
        for key, value in section_data.items():
            if str(key).lower().replace(" ", "_") in _SUPPRESSED_KEYS:
                continue
            if isinstance(value, dict):
                nested[key] = value
            else:
                scalars[key] = value

        lines = []
        if scalars:
            lines.append("| Metric | Value |")
            lines.append("|---|---|")
            for key, value in scalars.items():
                lines.append(f"| {_label(key)} | {_fmt(value, key)} |")

        for key, table in nested.items():
            if not table:
                continue
            if lines:
                lines.append("")
            lines.extend(self._render_nested_table(key, table))

        return lines

    def _render_nested_table(self, key: str, table: dict) -> list[str]:
        """Render one sub-table, ranked or plain, under its own heading."""
        heading, name_header, value_header, ranked = NESTED_TABLES.get(
            key, (_label(key), "Name", "Value", False)
        )

        lines = [f"### {heading}", ""]
        if ranked:
            lines.append(f"| # | {name_header} | {value_header} |")
            lines.append("|---|---|---|")
            lines.extend(
                f"| {rank} | {name} | {_fmt(value)} |"
                for rank, (name, value) in enumerate(table.items(), start=1)
            )
        else:
            lines.append(f"| {name_header} | {value_header} |")
            lines.append("|---|---|")
            lines.extend(f"| {name} | {_fmt(value)} |" for name, value in table.items())

        return lines

    def generate_json(
        self,
        data: dict,
        filename: Optional[str] = None,
    ) -> Path:
        """Generate JSON report.

        Args:
            data: Dictionary of data to include
            filename: Output filename (auto-generated if not provided)

        Returns:
            Path to generated report
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.json"

        filepath = self.output_dir / filename

        output_data = {
            "generated_at": datetime.now().isoformat(),
            "data": data,
        }

        try:
            with open(filepath, "w") as f:
                json.dump(output_data, f, indent=2, default=str)
            self.logger.info(f"JSON report written to {filepath}")
            return filepath
        except IOError as e:
            self.logger.error(f"Error writing JSON report: {e}")
            raise

    def generate_csv(
        self,
        df: pd.DataFrame,
        filename: Optional[str] = None,
    ) -> Path:
        """Generate CSV report from DataFrame.

        Args:
            df: Data to write
            filename: Output filename (auto-generated if not provided)

        Returns:
            Path to generated report
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.csv"

        filepath = self.output_dir / filename

        try:
            df.to_csv(filepath, index=False)
            self.logger.info(f"CSV report written to {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Error writing CSV report: {e}")
            raise
