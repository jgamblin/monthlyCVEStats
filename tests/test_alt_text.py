"""Tests for generated chart alt text."""

from src.reports import alt_text

STATS = {
    "current_ytd_total": 45626,
    "previous_ytd_total": 27426,
    "yoy_percent": 66.36,
    "avg_cves_per_day": 215.2,
}
CURRENT = {1: 4305, 2: 8921, 3: 15155, 4: 20966, 5: 27904, 6: 35851, 7: 45626}
PREVIOUS = {1: 4100, 2: 8000, 3: 12000, 4: 16000, 5: 20000, 6: 23800, 7: 27426}


def growth():
    return alt_text.growth_chart(
        2026,
        "July 31, 2026",
        7,
        STATS,
        CURRENT,
        PREVIOUS,
        extremes=[
            "Busiest completed month: Jul (9,775)",
            "Quietest: Jan (4,305)",
        ],
    )


def test_growth_alt_text_carries_the_numbers():
    """A screen reader user gets the data only from here."""
    text = growth()
    assert "45,626" in text
    assert "27,426" in text
    assert "18,200" in text  # the gap, computed not restated
    assert "66.4 percent" in text
    assert "Source: NVD" in text


def test_growth_alt_text_describes_the_shape():
    text = growth()
    assert "Two rising lines" in text
    assert "2026 in red" in text and "2025 in dashed grey" in text
    # The series separate in February on this data, and the text says so.
    assert "pulls ahead from February" in text


def test_shape_falls_back_when_the_series_never_separate():
    """Close years get an honest description rather than an invented turn."""
    close = {month: PREVIOUS[month] for month in PREVIOUS}
    text = alt_text.growth_chart(2026, "July 31, 2026", 7, STATS, close, PREVIOUS)
    assert "pulls ahead" not in text
    assert "runs above" in text


def test_extremes_are_read_as_sentences():
    """The chart's middot separator is silent to a screen reader."""
    text = growth()
    assert "·" not in text
    assert "Busiest completed month: Jul (9,775). Quietest: Jan (4,305)." in text


def test_long_form_fits_platform_limits():
    assert len(growth()) < 1000


def test_short_form_is_genuinely_short():
    text = alt_text.growth_chart_short(2026, 7, STATS)
    assert len(text) < 300
    assert "45,626" in text and "66.4 percent" in text


def test_yoy_alt_text():
    text = alt_text.yoy_chart(2026, 2025, 45626, 27426, 66.36, "January 1 to July 31")
    assert "Bar chart" in text
    assert "2025 at 27,426" in text and "2026 at 45,626" in text
    assert "up 66.4 percent" in text


def test_yoy_alt_text_reports_a_decline_as_down():
    text = alt_text.yoy_chart(2026, 2025, 20000, 27426, -27.1, "January 1 to July 31")
    assert "down 27.1 percent" in text
    assert "-27.1" not in text  # the sign is carried by the word


def test_rendered_file_groups_every_variant():
    charts = [
        "CVE_Growth_2026_dark_square.png",
        "CVE_Growth_2026_light_landscape.png",
        "YOY_CVE_Comparison_2026_vs_2025.png",
    ]
    rendered = alt_text.render_file("LONG", "SHORT", "YOY", charts)

    assert "## Growth chart" in rendered
    assert "## Year-over-year chart" in rendered
    for name in charts:
        assert name in rendered
    assert "LONG" in rendered and "SHORT" in rendered and "YOY" in rendered
