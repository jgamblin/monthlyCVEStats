"""Tests for chart styling and rendering."""

import struct

import pytest

from src.reports import style
from src.reports.ytd_visualizer import YTDVisualizer


def png_size(path):
    """Width and height from the PNG IHDR chunk, without needing Pillow."""
    header = path.read_bytes()[:24]
    assert header[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    return struct.unpack(">II", header[16:24])


def test_bundled_fonts_are_present():
    """Charts render on a bare CI runner; a missing face degrades silently."""
    assert style.MISSING_FONTS == [], (
        f"missing bundled fonts: {style.MISSING_FONTS}. "
        f"Expected them in {style.FONT_DIR}"
    )


def test_palettes_share_token_names():
    """Dark and light must be interchangeable at every call site."""
    assert set(style.LIGHT_COLORS) == set(style.DARK_COLORS)


def test_figsize_matches_declared_pixels():
    for ratio, (width, height) in style.RATIOS.items():
        figsize = style.figsize_for(ratio)
        assert figsize == (width / style.SAVE_DPI, height / style.SAVE_DPI)


@pytest.fixture
def chart_args():
    monthly = {1: 5000, 2: 5200, 3: 6000, 4: 5800, 5: 6952}
    previous_monthly = {1: 3800, 2: 3900, 3: 4200, 4: 4100, 5: 3979}

    cumulative, previous_cumulative = {}, {}
    running = previous_running = 0
    for month in range(1, 13):
        running += monthly.get(month, 0)
        previous_running += previous_monthly.get(month, 0)
        cumulative[month] = running
        previous_cumulative[month] = previous_running

    daily_current = {day: day * 185 for day in range(1, 152)}
    daily_previous = {day: day * 132 for day in range(1, 152)}

    return {
        "current_cumulative": cumulative,
        "previous_cumulative": previous_cumulative,
        "current_year": 2026,
        "through_month": 5,
        "daily_current": daily_current,
        "daily_previous": daily_previous,
        "monthly_data": monthly,
        "previous_monthly_data": previous_monthly,
        "stats": {
            "current_ytd_total": 27937,
            "previous_ytd_total": 19976,
            "yoy_percent": 39.9,
            "avg_cves_per_day": 185.0,
        },
    }


@pytest.mark.parametrize("ratio", ["wide", "square", "portrait"])
@pytest.mark.parametrize("dark_mode", [True, False])
def test_chart_renders_at_the_declared_size(tmp_path, chart_args, ratio, dark_mode):
    visualizer = YTDVisualizer(tmp_path)
    path = visualizer.create_chart(ratio=ratio, dark_mode=dark_mode, **chart_args)

    assert path.exists()
    assert png_size(path) == style.RATIOS[ratio]


def test_wide_chart_keeps_the_landscape_filename(tmp_path, chart_args):
    """Existing outputs and the release artifact glob use this name."""
    visualizer = YTDVisualizer(tmp_path)
    path = visualizer.create_ytd_chart(dark_mode=True, **chart_args)
    assert path.name == "CVE_Growth_2026_dark_landscape.png"

    light = visualizer.create_ytd_chart(dark_mode=False, **chart_args)
    assert light.name == "CVE_Growth_2026_light_landscape.png"


def test_square_and_portrait_filenames(tmp_path, chart_args):
    visualizer = YTDVisualizer(tmp_path)
    assert (
        visualizer.create_square_chart(dark_mode=True, **chart_args).name
        == "CVE_Growth_2026_dark_square.png"
    )
    assert (
        visualizer.create_portrait_chart(dark_mode=False, **chart_args).name
        == "CVE_Growth_2026_light_portrait.png"
    )


def test_chart_falls_back_to_monthly_series(tmp_path, chart_args):
    """No daily data still renders, using the monthly cumulative points."""
    chart_args = dict(chart_args, daily_current=None, daily_previous=None)
    visualizer = YTDVisualizer(tmp_path)
    path = visualizer.create_chart(ratio="wide", **chart_args)
    assert png_size(path) == style.RATIOS["wide"]


def test_unknown_ratio_is_rejected(tmp_path, chart_args):
    visualizer = YTDVisualizer(tmp_path)
    with pytest.raises(ValueError, match="Unknown ratio"):
        visualizer.create_chart(ratio="banner", **chart_args)


def test_yoy_comparison_renders(tmp_path):
    visualizer = YTDVisualizer(tmp_path)
    path = visualizer.create_yoy_comparison(2026, 2025, 27937, 19976, 39.9)
    assert path.name == "YOY_CVE_Comparison_2026_vs_2025.png"
    assert png_size(path) == style.RATIOS["wide"]


def test_month_extremes_summary(tmp_path, chart_args):
    visualizer = YTDVisualizer(tmp_path)
    parts = visualizer._month_extremes(
        chart_args["monthly_data"], chart_args["previous_monthly_data"], 5
    )
    assert parts[0] == "Busiest completed month: May (6,952)"
    assert parts[1] == "Quietest: Jan (5,000)"
    assert parts[2] == "Fastest YoY: May +74.7% on last year"


def test_month_extremes_handles_no_data(tmp_path):
    visualizer = YTDVisualizer(tmp_path)
    assert visualizer._month_extremes({}, {}, 5) == []
    assert visualizer._month_extremes({1: 0, 2: 0}, {}, 2) == []


def _freeze(monkeypatch, year, month, day):
    from datetime import datetime as real_datetime

    class FakeDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime(year, month, day, 12, 0, 0)

    monkeypatch.setattr("src.reports.ytd_visualizer.datetime", FakeDatetime)


def test_period_end_on_the_first_covers_the_whole_prior_month(tmp_path, monkeypatch):
    """The scheduled run reports on a month that has finished."""
    _freeze(monkeypatch, 2026, 7, 1)
    visualizer = YTDVisualizer(tmp_path)
    assert visualizer._period_end(6) == (2026, 30, True)
    assert visualizer._get_month_name_for_last_day(6) == "June 30, 2026"


def test_period_end_on_jan_first_rolls_back_a_year(tmp_path, monkeypatch):
    _freeze(monkeypatch, 2026, 1, 1)
    visualizer = YTDVisualizer(tmp_path)
    assert visualizer._period_end(12) == (2025, 31, True)


def test_period_end_mid_month_stops_at_today(tmp_path, monkeypatch):
    """A manual run on the 27th covers 27 days, not the month's full length."""
    _freeze(monkeypatch, 2026, 7, 27)
    visualizer = YTDVisualizer(tmp_path)
    assert visualizer._period_end(7) == (2026, 27, False)
    assert visualizer._get_month_name_for_last_day(7) == "July 27, 2026"


def test_incomplete_month_is_not_ranked_busiest(tmp_path, monkeypatch, chart_args):
    """Partial July outcounts complete June, but must not be called the busiest."""
    _freeze(monkeypatch, 2026, 7, 27)
    monthly = {1: 4309, 2: 4616, 3: 6234, 4: 5811, 5: 6938, 6: 7947, 7: 8012}
    previous = {m: 3000 for m in range(1, 8)}
    args = dict(
        chart_args,
        through_month=7,
        monthly_data=monthly,
        previous_monthly_data=previous,
    )

    visualizer = YTDVisualizer(tmp_path)
    path = visualizer.create_chart(ratio="wide", **args)
    assert path.exists()

    # The ranking the chart footer is built from stops at the last whole month.
    parts = visualizer._month_extremes(monthly, previous, 6)
    assert parts[0] == "Busiest completed month: Jun (7,947)"
    assert not any("Jul" in part for part in parts)


def _relative_luminance(hex_color):
    channels = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    channels = [
        c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels
    ]
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def _contrast(a, b):
    la, lb = _relative_luminance(a), _relative_luminance(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_the_two_series_are_distinguishable(theme):
    """The plotted years must differ in luminance, not only in dash and weight.

    The dark palette reused the light "neutral" for its comparison series, putting
    the pair at 1.03:1 -- indistinguishable in grayscale and to a colour-blind
    reader, leaving line style as the only cue.
    """
    colors = style.palette(dark=(theme == "dark"))
    ratio = _contrast(colors["alert"], colors["comparison"])
    assert ratio >= 1.8, (
        f"{theme} series pair is only {ratio:.2f}:1 "
        f"({colors['alert']} vs {colors['comparison']})"
    )


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_each_series_is_visible_against_its_background(theme):
    colors = style.palette(dark=(theme == "dark"))
    for token in ("alert", "comparison"):
        ratio = _contrast(colors[token], colors["background"])
        assert ratio >= 2.5, f"{theme} {token} is only {ratio:.2f}:1 on background"
