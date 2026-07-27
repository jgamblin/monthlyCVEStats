"""The year-over-year figure must agree across every surface that publishes it.

A released chart carried both "+59.9% / vs 2025 (27,426)" on its stat tile and
"+16,939 (+62.9%)" as its in-plot annotation, because the tile came from
month-granularity cumulative totals while the annotation came from the
day-truncated daily series. Nothing tied the two together, so nothing failed.

These tests tie them together.
"""

import json

import pytest

from src.analysis.ytd_growth import YTDAnalyzer


def build_feed(tmp_path, monkeypatch, now):
    """A feed whose 2025 July has a tail beyond the 2026 cut-off."""
    from datetime import datetime as real_datetime

    class FakeDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr("src.analysis.ytd_growth.datetime", FakeDatetime)

    records = []

    def add(year, month, day, n):
        for i in range(n):
            records.append(
                {
                    "cve": {
                        "id": f"CVE-{year}-{month:02d}{day:02d}{i:03d}",
                        "published": f"{year}-{month:02d}-{day:02d}T12:00:00.000Z",
                        "vulnStatus": "Analyzed",
                    }
                }
            )

    for month in range(1, 7):
        add(2025, month, 10, 200)
        add(2026, month, 10, 300)
    add(2025, 7, 10, 100)
    add(2025, 7, 30, 60)  # the tail 2026 cannot have yet
    add(2026, 7, 10, 180)

    path = tmp_path / "nvd.jsonl"
    path.write_text(json.dumps(records))

    analyzer = YTDAnalyzer(path)
    analyzer.current_year = 2026
    return analyzer


@pytest.fixture
def mid_month(tmp_path, monkeypatch):
    from datetime import datetime as real_datetime

    return build_feed(tmp_path, monkeypatch, real_datetime(2026, 7, 27, 12, 0, 0))


@pytest.fixture
def first_of_month(tmp_path, monkeypatch):
    from datetime import datetime as real_datetime

    return build_feed(tmp_path, monkeypatch, real_datetime(2026, 8, 1, 5, 0, 0))


def surfaces(analysis):
    """The three places a YoY figure is published, derived as the code derives them.

    - tile: the stat card and the post copy, from statistics
    - annotation: the chart's in-plot gap, from the daily cumulative series
    """
    stats = analysis["statistics"]
    daily_c = analysis["current_daily_cumulative"]
    daily_p = analysis["previous_daily_cumulative"]
    last = max(daily_c)

    tile_diff = stats["yoy_growth"]
    tile_pct = stats["yoy_percent"]
    annotation_diff = daily_c[last] - daily_p[last]
    annotation_pct = (annotation_diff / daily_p[last] * 100) if daily_p[last] else 0.0
    return tile_diff, tile_pct, annotation_diff, annotation_pct


@pytest.mark.parametrize("fixture_name", ["mid_month", "first_of_month"])
def test_tile_and_annotation_agree(fixture_name, request):
    """The stat tile and the in-plot annotation must be the same number."""
    analyzer = request.getfixturevalue(fixture_name)
    analysis = analyzer.analyze_ytd()
    tile_diff, tile_pct, ann_diff, ann_pct = surfaces(analysis)

    assert tile_diff == ann_diff, (
        f"stat tile publishes {tile_diff:+,} while the chart annotation "
        f"publishes {ann_diff:+,}"
    )
    assert round(tile_pct, 1) == round(ann_pct, 1), (
        f"stat tile publishes {tile_pct:.1f}% while the chart annotation "
        f"publishes {ann_pct:.1f}%"
    )


@pytest.mark.parametrize("fixture_name", ["mid_month", "first_of_month"])
def test_growth_reconciles_with_its_own_totals(fixture_name, request):
    """The published percentage must follow from the two published totals."""
    stats = request.getfixturevalue(fixture_name).analyze_ytd()["statistics"]
    current = stats["current_ytd_total"]
    previous = stats["previous_ytd_total"]

    assert stats["yoy_growth"] == current - previous
    expected = (current - previous) / previous * 100
    assert round(stats["yoy_percent"], 1) == round(expected, 1)


def test_mid_month_excludes_the_prior_year_tail(mid_month):
    """The 60-record Jul 30 tail is outside the window and must not count."""
    stats = mid_month.analyze_ytd()["statistics"]
    assert stats["previous_ytd_total"] == 1300  # 6*200 + 100, tail excluded
    assert stats["current_ytd_total"] == 1980  # 6*300 + 180


def test_first_of_month_includes_the_whole_prior_month(first_of_month):
    """Reporting on a finished July, the tail is inside the window."""
    stats = first_of_month.analyze_ytd()["statistics"]
    assert stats["previous_ytd_total"] == 1360  # tail included
