"""Tests for the generated post copy.

The rules being enforced here are the house copy formula in STYLE.md: an arguable
claim first, the load-bearing number second, no em dashes, no decorative glyphs,
and a genuine question to close.
"""

from pathlib import Path

import pytest

from src.analysis.ytd_growth import (
    CLAIM_VARIANTS,
    QUESTION_VARIANTS,
    YTDAnalyzer,
)

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


def test_claim_varies_with_the_data():
    """A declining year must not be described with the growth claim.

    A fresh analyzer per shape, because one analyzer is deliberately one
    release: it locks its claim so both post files agree.
    """

    def claim_for(**kwargs):
        return YTDAnalyzer(Path("data/nvd.jsonl")).get_summary_text(analysis(**kwargs))

    growing = claim_for(yoy_percent=39.9, month_percent=74.7)
    declining = claim_for(yoy_percent=-8.0, month_percent=-12.0)
    slower_month = claim_for(yoy_percent=12.0, month_percent=-4.0)

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


def test_in_progress_month_does_not_claim_to_have_closed(analyzer, monkeypatch):
    """A mid-month run reports on a month still running.

    Saying it "closed" is false, and quoting a change against the prior year
    compares a part-month to a whole one.
    """
    from datetime import datetime as real_datetime

    class FakeDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime(2026, 7, 27, 14, 0, 0)

    monkeypatch.setattr("src.analysis.ytd_growth.datetime", FakeDatetime)

    payload = analysis()
    payload["statistics"]["current_month"] = 7  # July, and it is only the 27th
    payload["statistics"]["month_percent"] = 112.2

    text = analyzer.get_summary_text(payload)

    assert "closed at" not in text
    assert "still running" in text
    assert "through July 27" in text
    # The misleading part-month-vs-whole-month change is withheld.
    assert "112.2" not in text
    # The year-to-date figures are still fair game.
    assert "27,937" in text


def test_completed_month_says_closed(analyzer, monkeypatch):
    from datetime import datetime as real_datetime

    class FakeDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime(2026, 6, 1, 5, 0, 0)

    monkeypatch.setattr("src.analysis.ytd_growth.datetime", FakeDatetime)

    text = analyzer.get_summary_text(analysis())  # reporting on May
    assert "May 2026 closed at 6,952 published CVEs" in text
    assert "+74.7%" in text
    assert "still running" not in text


def test_in_progress_claim_ignores_the_part_month(analyzer, monkeypatch):
    """A part-month dip must not flip the claim to a slowdown."""
    from datetime import datetime as real_datetime

    class FakeDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime(2026, 7, 3, 5, 0, 0)

    monkeypatch.setattr("src.analysis.ytd_growth.datetime", FakeDatetime)

    payload = analysis(yoy_percent=59.9, month_percent=-88.0)  # 3 days into July
    payload["statistics"]["current_month"] = 7
    claim = analyzer.get_summary_text(payload).splitlines()[0]

    # The part-month dip is ignored, so this reads as the strong-growth year it
    # is rather than a slowdown.
    assert claim not in CLAIM_VARIANTS["slower_month"]
    assert claim in CLAIM_VARIANTS["runaway"]


def test_unmapped_cwe_renders_its_id_once(analyzer):
    """An id with no friendly name must not print as 'CWE-9999 (CWE-9999)'."""
    report = {"cwe": {"top_cwes": {"CWE-9999": 42, "CWE-79": 10}}}
    text = analyzer.get_enriched_text(analysis(), report)
    assert "  CWE-9999: 42" in text
    assert "CWE-9999 (CWE-9999)" not in text
    # Mapped ids still show both.
    assert "XSS (CWE-79): 10" in text


def _fake_feed(tmp_path):
    """A feed with 2025 and 2026 records either side of a mid-month cut-off."""
    import json

    records = []

    def add(year, month, day, n):
        for i in range(n):
            records.append(
                {
                    "cve": {
                        "id": f"CVE-{year}-{month:02d}{day:02d}{i:02d}",
                        "published": f"{year}-{month:02d}-{day:02d}T12:00:00.000Z",
                        "vulnStatus": "Analyzed",
                    }
                }
            )

    # 2025: 100 in June, 30 through Jul 27, then a 40-record tail Jul 28-31.
    add(2025, 6, 15, 100)
    add(2025, 7, 10, 30)
    add(2025, 7, 29, 40)
    # 2026: 100 in June, 60 through Jul 27. Nothing after, it has not happened.
    add(2026, 6, 15, 100)
    add(2026, 7, 10, 60)

    path = tmp_path / "nvd.jsonl"
    path.write_text(json.dumps(records))
    return path


def test_previous_year_is_cut_at_the_same_calendar_point(tmp_path, monkeypatch):
    """A part-month must not be compared against the prior year's whole month.

    Regression for the released +59.9%: the 2026 total stopped at Jul 27 while the
    2025 baseline ran to Jul 31, so it carried four extra days of 2025 and
    understated growth.
    """
    from datetime import datetime as real_datetime

    class FakeDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime(2026, 7, 27, 12, 0, 0)

    monkeypatch.setattr("src.analysis.ytd_growth.datetime", FakeDatetime)

    analyzer = YTDAnalyzer(_fake_feed(tmp_path))
    analyzer.current_year = 2026
    result = analyzer.analyze_ytd()
    stats = result["statistics"]

    # 2025 through Jul 27 is 130, not 170: the 40-record tail is excluded.
    assert stats["previous_ytd_total"] == 130
    assert stats["current_ytd_total"] == 160
    assert stats["yoy_growth"] == 30
    assert round(stats["yoy_percent"], 1) == 23.1

    # The month figures line up over the same window too.
    assert stats["previous_month_count"] == 30
    assert stats["current_month_count"] == 60


def test_first_of_month_run_compares_whole_months(tmp_path, monkeypatch):
    """On the 1st the reporting month has finished, so nothing is truncated."""
    from datetime import datetime as real_datetime

    class FakeDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime(2026, 8, 1, 5, 0, 0)

    monkeypatch.setattr("src.analysis.ytd_growth.datetime", FakeDatetime)

    analyzer = YTDAnalyzer(_fake_feed(tmp_path))
    analyzer.current_year = 2026
    stats = analyzer.analyze_ytd()["statistics"]

    # Reporting on July: all of July 2025 counts, tail included.
    assert stats["previous_ytd_total"] == 170
    assert stats["previous_month_count"] == 70


def _milestone_analysis(ytd, previous_full, avg_per_day=211.0, current_month=7):
    payload = analysis(yoy_percent=62.9)
    payload["statistics"].update(
        {
            "current_month": current_month,
            "current_ytd_total": ytd,
            "avg_cves_per_day": avg_per_day,
            "previous_year_full_total": previous_full,
            "passed_previous_year_total": ytd >= previous_full,
            "all_time_total": 352762,
        }
    )
    if ytd < previous_full:
        remaining = previous_full - ytd
        payload["statistics"]["cves_to_pass_previous_year"] = remaining
        payload["statistics"]["days_to_pass_previous_year"] = int(
            remaining / avg_per_day
        )
        payload["statistics"]["projected_pass_date"] = "August 15"
    return payload


def test_pending_milestone_projects_the_crossover(analyzer, monkeypatch):
    """43,867 against a full 2025 of 48,162 is a post waiting to happen."""
    from datetime import datetime as real_datetime

    class FakeDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime(2026, 7, 27, 12, 0, 0)

    monkeypatch.setattr("src.analysis.ytd_growth.datetime", FakeDatetime)

    text = analyzer.get_summary_text(_milestone_analysis(43867, 48162))

    assert "All of 2025 came to 48,162" in text
    assert "4,295 CVEs" in text  # what is left to close the gap
    assert "around August 15" in text
    assert text.splitlines()[0] == (
        "This year stops being a trend and starts being the new floor."
    )


def test_passed_milestone_leads_the_post(analyzer, monkeypatch):
    """Overtaking a prior full year outranks any rate-of-growth framing."""
    from datetime import datetime as real_datetime

    class FakeDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime(2026, 9, 1, 5, 0, 0)

    monkeypatch.setattr("src.analysis.ytd_growth.datetime", FakeDatetime)

    text = analyzer.get_summary_text(_milestone_analysis(50000, 48162, current_month=8))

    assert text.splitlines()[0] == (
        "Last year's record is no longer a ceiling, it is a midpoint."
    )
    assert "more CVEs than the whole of 2025 (48,162)" in text
    assert "+1,838 past it" in text
    assert "4 months still to run" in text
    # Still house-clean.
    for character in BANNED_CHARACTERS:
        assert character not in text


def test_no_milestone_line_without_a_prior_year(analyzer):
    payload = analysis()
    payload["statistics"]["previous_year_full_total"] = 0
    text = analyzer.get_summary_text(payload)
    assert "whole of" not in text
    assert "came to" not in text


def situation(analyzer, **kwargs):
    payload = analysis(**{k: v for k, v in kwargs.items() if k != "month_complete"})
    return analyzer._situation(
        payload["statistics"], kwargs.get("month_complete", True)
    )


def test_growth_is_banded_not_one_threshold(analyzer):
    """The old rule fired one branch for anything above 25 percent.

    Across 2026 that ran from 27 to 63 percent, so every month of the year got
    the identical opening sentence.
    """
    assert situation(analyzer, yoy_percent=63.0) == "runaway"
    assert situation(analyzer, yoy_percent=39.9) == "strong"
    assert situation(analyzer, yoy_percent=27.0) == "strong"
    assert situation(analyzer, yoy_percent=18.0) == "steady"
    assert situation(analyzer, yoy_percent=4.0) == "slight"
    assert situation(analyzer, yoy_percent=0.0) == "flat"
    assert situation(analyzer, yoy_percent=-8.0) == "declining"

    # 27 and 63 percent no longer collapse to the same line.
    assert CLAIM_VARIANTS["strong"][0] != CLAIM_VARIANTS["runaway"][0]


def test_a_slower_month_outranks_the_growth_band(analyzer):
    assert situation(analyzer, yoy_percent=39.9, month_percent=-4.0) == "slower_month"


def test_repeated_situations_rotate_the_claim(tmp_path):
    """A run of similar months must not open with the same sentence each time."""
    history = tmp_path / "claim_history.json"
    seen = []
    for _ in range(4):
        analyzer = YTDAnalyzer(Path("data/nvd.jsonl"))
        analyzer.history_file = history
        seen.append(analyzer.get_summary_text(analysis()).splitlines()[0])

    variants = CLAIM_VARIANTS["strong"]
    # Three distinct lines before it has to reuse one, then it cycles.
    assert seen[:3] == variants
    assert seen[3] == variants[0]
    assert len(set(seen[:3])) == 3


def test_questions_rotate_independently(tmp_path):
    history = tmp_path / "claim_history.json"
    asked = []
    for _ in range(3):
        analyzer = YTDAnalyzer(Path("data/nvd.jsonl"))
        analyzer.history_file = history
        text = analyzer.get_summary_text(analysis())
        asked.append([line for line in text.splitlines() if line.endswith("?")][0])

    assert asked == QUESTION_VARIANTS["growing"]


def test_rotation_is_per_situation(tmp_path):
    """Advancing one situation must not burn through another's variants."""
    history = tmp_path / "claim_history.json"

    first = YTDAnalyzer(Path("data/nvd.jsonl"))
    first.history_file = history
    first.get_summary_text(analysis(yoy_percent=39.9))  # strong

    second = YTDAnalyzer(Path("data/nvd.jsonl"))
    second.history_file = history
    declining = second.get_summary_text(analysis(yoy_percent=-8.0, month_percent=-3.0))

    # 'declining' has not been used yet, so it starts at its first variant.
    assert declining.splitlines()[0] == CLAIM_VARIANTS["declining"][0]


def test_without_history_copy_is_deterministic():
    """No history file means reproducible output, which keeps tests stable."""
    a = YTDAnalyzer(Path("data/nvd.jsonl"))
    b = YTDAnalyzer(Path("data/nvd.jsonl"))
    assert a.get_summary_text(analysis()) == b.get_summary_text(analysis())


def test_every_claim_variant_is_house_clean():
    """The formula applies to all of them, not just the ones a test happens to hit."""
    for bucket, variants in CLAIM_VARIANTS.items():
        assert len(variants) >= 3, f"{bucket} needs alternatives to rotate through"
        for claim in variants:
            assert not any(c.isdigit() for c in claim), f"{claim!r} carries a statistic"
            assert claim.endswith("."), f"{claim!r} should be a sentence"
            for character in BANNED_CHARACTERS:
                assert character not in claim
            assert len(claim) < 100, f"{claim!r} is too long for an opening line"


def test_every_question_variant_is_a_question():
    for bucket, variants in QUESTION_VARIANTS.items():
        assert len(variants) >= 3, f"{bucket} needs alternatives to rotate through"
        for question in variants:
            assert question.endswith("?")
            for character in BANNED_CHARACTERS:
                assert character not in question


def test_both_posts_in_one_release_share_the_claim(tmp_path):
    """post.txt and enriched_post.txt are one story, so one claim and question.

    Rotation happens between releases, not between the two files of a release.
    """
    analyzer = YTDAnalyzer(Path("data/nvd.jsonl"))
    analyzer.history_file = tmp_path / "claim_history.json"

    payload = analysis()
    summary = analyzer.get_summary_text(payload)
    enriched = analyzer.get_enriched_text(payload, MONTHLY_REPORT)

    assert summary.splitlines()[0] == enriched.splitlines()[0]
    summary_q = [line for line in summary.splitlines() if line.endswith("?")][0]
    enriched_q = [line for line in enriched.splitlines() if line.endswith("?")][0]
    assert summary_q == enriched_q


def test_one_release_advances_the_history_once(tmp_path):
    """Two files written from one analyzer must not burn two variants."""
    history = tmp_path / "claim_history.json"
    analyzer = YTDAnalyzer(Path("data/nvd.jsonl"))
    analyzer.history_file = history

    payload = analysis()
    analyzer.get_summary_text(payload)
    analyzer.get_enriched_text(payload, MONTHLY_REPORT)

    import json as _json

    recorded = _json.loads(history.read_text())
    assert recorded["strong"] == 0
    assert recorded["_questions"]["growing"] == 0
