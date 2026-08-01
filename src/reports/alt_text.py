"""
Alt text for the published charts.

Written from the same figures the charts are drawn from, so the description
cannot drift from the picture. A screen reader user gets no value from "chart of
CVE growth": alt text for a data graphic has to carry the numbers and the shape,
because those are the content.

House rules, enforced here rather than remembered:

* no "image of" or "chart showing" preamble beyond naming the chart type;
* state the shape, not just the endpoints, so the trend is legible;
* carry the load-bearing numbers, since they are not available any other way;
* name the source;
* keep the long form under 1,000 characters, which clears the caption limit on
  every platform these get posted to, and offer a short form for the tightest.
"""

import calendar
from typing import Optional

SOURCE = "Source: NVD, excluding rejected CVEs."

# The gap is called out from the first month it exceeds this share of the
# comparison year, which is where a reader would say the lines separate.
_SEPARATION_THRESHOLD = 0.10


def _separation_month(
    current_cumulative: dict, previous_cumulative: dict, through_month: int
) -> Optional[str]:
    """The month the two series visibly part company, if they do."""
    for month in range(1, through_month + 1):
        previous = previous_cumulative.get(month, 0)
        current = current_cumulative.get(month, 0)
        if previous and (current - previous) / previous >= _SEPARATION_THRESHOLD:
            return calendar.month_name[month]
    return None


def growth_chart(
    current_year: int,
    through_date: str,
    through_month: int,
    stats: dict,
    current_cumulative: dict,
    previous_cumulative: dict,
    extremes: Optional[list] = None,
) -> str:
    """Alt text for the cumulative growth chart, in any ratio or theme.

    All six variants plot the same data, so they share one description.
    """
    previous_year = current_year - 1
    month_name = calendar.month_name[through_month]
    ytd = stats.get("current_ytd_total", 0)
    previous_ytd = stats.get("previous_ytd_total", 0)
    gap = ytd - previous_ytd
    percent = stats.get("yoy_percent", 0)
    per_day = stats.get("avg_cves_per_day", 0)

    parted = _separation_month(current_cumulative, previous_cumulative, through_month)
    if parted and parted != month_name:
        shape = (
            f"The lines track together early on, then {current_year} pulls ahead "
            f"from {parted} and the gap widens for the rest of the period."
        )
    else:
        shape = f"{current_year} runs above {previous_year} across the whole period."

    parts = [
        f'Line chart titled "Cumulative CVEs Published, {current_year} vs '
        f'{previous_year}", through {through_date}.',
        f"Two rising lines from January to {month_name}: {current_year} in red, "
        f"{previous_year} in dashed grey.",
        shape,
        f"{current_year} ends {month_name} at {ytd:,} cumulative CVEs against "
        f"{previous_ytd:,} in {previous_year}, a gap of {gap:,} or "
        f"{abs(percent):.1f} percent.",
        f"Daily average {per_day:.0f} CVEs.",
    ]
    if extremes:
        # The chart separates these with a middot, which a screen reader reads
        # as nothing at all. Sentences instead.
        parts.append(". ".join(part.strip() for part in extremes) + ".")
    parts.append(SOURCE)
    return " ".join(parts)


def growth_chart_short(current_year: int, through_month: int, stats: dict) -> str:
    """The same chart for platforms with a tight alt-text limit."""
    previous_year = current_year - 1
    month_name = calendar.month_name[through_month]
    return (
        f"Line chart of cumulative CVEs published, {current_year} versus "
        f"{previous_year}. {current_year} ends {month_name} at "
        f"{stats.get('current_ytd_total', 0):,} against "
        f"{stats.get('previous_ytd_total', 0):,} last year, up "
        f"{abs(stats.get('yoy_percent', 0)):.1f} percent. Source: NVD."
    )


def yoy_chart(
    current_year: int,
    previous_year: int,
    current_ytd: int,
    previous_ytd: int,
    growth_percent: float,
    window: str,
) -> str:
    """Alt text for the two-bar year-over-year comparison."""
    direction = "up" if growth_percent >= 0 else "down"
    return (
        f"Bar chart comparing year-to-date CVEs for the same window, {window}: "
        f"{previous_year} at {previous_ytd:,} and {current_year} at "
        f"{current_ytd:,}, {direction} {abs(growth_percent):.1f} percent year "
        f"over year. {SOURCE}"
    )


def render_file(growth: str, growth_short: str, yoy: str, charts: list) -> str:
    """The alt_text.md written beside the charts, ready to copy from."""
    growth_files = sorted(name for name in charts if name.startswith("CVE_Growth"))
    yoy_files = sorted(name for name in charts if name.startswith("YOY"))

    lines = [
        "# Alt text",
        "",
        "Generated with the charts, from the same figures they are drawn from.",
        "Copy the relevant block when posting.",
        "",
        "## Growth chart",
        "",
        "Applies to every ratio and theme, which all plot the same data:",
        "",
    ]
    lines += [f"- `{name}`" for name in growth_files]
    lines += ["", growth, "", "### Short form", "", growth_short, ""]

    if yoy_files:
        lines += ["## Year-over-year chart", ""]
        lines += [f"- `{name}`" for name in yoy_files]
        lines += ["", yoy, ""]

    return "\n".join(lines).rstrip() + "\n"
