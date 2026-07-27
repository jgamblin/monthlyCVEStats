"""Tests for the generated post copy.

The rules being enforced here are the house copy formula in STYLE.md: an arguable
claim first, the load-bearing number second, no em dashes, no decorative glyphs,
and a genuine question to close.
"""

from pathlib import Path

import pytest

from src.analysis.ytd_growth import YTDAnalyzer

BANNED_CHARACTERS = ["—", "–", "►", "▶", "✅", "🔥"]


def analysis(yoy_percent=39.9, month_percent=74.7):
    """A YTD analysis payload shaped like analyze_ytd() output."""
    return {
        "current_year": 2026,
        "previous_year": 2025,
        "statistics": {
            "current_month": 5,
            "current_ytd_total": 27937,
            "previous_ytd_total": 19976,
            "yoy_growth": 7961,
            "yoy_percent": yoy_percent,
            "current_month_count": 6952,
            "previous_month_count": 3979,
            "month_growth": 2973,
            "month_percent": month_percent,
            "avg_cves_per_day": 185.0,
        },
    }


MONTHLY_REPORT = {
    "cvss": {"median": 7.1, "percentile_75": 8.1},
    "cwe": {
        "top_cwes": {
            "CWE-79": 571,
            "CWE-89": 280,
            "NVD-CWE-noinfo": 258,
        }
    },
}


@pytest.fixture
def analyzer():
    return YTDAnalyzer(Path("data/nvd.jsonl"))


@pytest.fixture
def summary(analyzer):
    return analyzer.get_summary_text(analysis())


@pytest.fixture
def enriched(analyzer):
    return analyzer.get_enriched_text(analysis(), MONTHLY_REPORT)


@pytest.mark.parametrize("fixture_name", ["summary", "enriched"])
def test_no_banned_characters(fixture_name, request):
    text = request.getfixturevalue(fixture_name)
    for character in BANNED_CHARACTERS:
        assert character not in text, f"{character!r} is banned in post copy"


@pytest.mark.parametrize("fixture_name", ["summary", "enriched"])
def test_no_n_equals(fixture_name, request):
    text = request.getfixturevalue(fixture_name)
    assert "n=" not in text.lower()


def test_opens_on_a_claim_not_a_statistic(summary):
    """Line one is an arguable sentence, so it carries no digits."""
    first_line = summary.splitlines()[0]
    assert not any(character.isdigit() for character in first_line)
    assert first_line.endswith(".")


def test_load_bearing_number_is_in_the_second_paragraph(summary):
    paragraphs = [p for p in summary.split("\n\n") if p.strip()]
    assert "6,952" in paragraphs[1]


@pytest.mark.parametrize("fixture_name", ["summary", "enriched"])
def test_ends_on_a_question(fixture_name, request):
    text = request.getfixturevalue(fixture_name)
    # The enriched post closes with a source line and hashtags after the question.
    assert "?" in text
    questions = [line for line in text.splitlines() if line.strip().endswith("?")]
    assert questions, "post copy must end on a question"


@pytest.mark.parametrize("fixture_name", ["summary", "enriched"])
def test_counts_use_thousands_separators(fixture_name, request):
    text = request.getfixturevalue(fixture_name)
    assert "27937" not in text
    assert "6952" not in text


@pytest.mark.parametrize("fixture_name", ["summary", "enriched"])
def test_names_the_source(fixture_name, request):
    text = request.getfixturevalue(fixture_name)
    assert "NVD" in text


def test_claim_varies_with_the_data(analyzer):
    """A declining year must not be described with the growth claim."""
    growing = analyzer.get_summary_text(analysis(yoy_percent=39.9, month_percent=74.7))
    declining = analyzer.get_summary_text(
        analysis(yoy_percent=-8.0, month_percent=-12.0)
    )
    slower_month = analyzer.get_summary_text(
        analysis(yoy_percent=12.0, month_percent=-4.0)
    )

    claims = {
        growing.splitlines()[0],
        declining.splitlines()[0],
        slower_month.splitlines()[0],
    }
    assert len(claims) == 3, "each data shape should get its own claim"
    assert "baseline" in growing.splitlines()[0]
    assert "not a trend reversal" in slower_month.splitlines()[0]


def test_enriched_post_translates_cwe_placeholders(enriched):
    """'NVD-CWE-noinfo' is an artifact, not a weakness name."""
    assert "Not specified (NVD-CWE-noinfo)" in enriched
    assert "XSS (CWE-79): 571" in enriched
