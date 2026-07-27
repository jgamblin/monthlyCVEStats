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
    summary = visualizer._month_extremes(
        chart_args["monthly_data"], chart_args["previous_monthly_data"], 5
    )
    assert "Busiest month: May (6,952)" in summary
    assert "Quietest month: Jan (5,000)" in summary
    assert "Fastest YoY growth: May" in summary


def test_month_extremes_handles_no_data(tmp_path):
    visualizer = YTDVisualizer(tmp_path)
    assert visualizer._month_extremes({}, {}, 5) == ""
    assert visualizer._month_extremes({1: 0, 2: 0}, {}, 2) == ""
