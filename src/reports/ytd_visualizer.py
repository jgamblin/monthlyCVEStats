"""
Year-to-date CVE growth charts.

Built on ``src.reports.style``, the port of CVEGraphs' chart styling, so a chart
from this repo and a chart from CVEGraphs sit together in a feed. Each chart
renders in three aspect ratios (wide, square, portrait), in dark and light.

House rule for headings: state what the chart shows, in Title Case. Never an
argument or a verdict.
"""

import calendar
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from src.reports import style  # noqa: E402

logger = logging.getLogger(__name__)

# Per-ratio geometry: the stat card row and the plot area. Values are figure
# fractions, tuned so the card row clears the header subtitle, the plot area
# clears the cards, and the x tick labels clear the footer line. Card heights
# land near 100px at each ratio, which is what draw_stat_card is sized for.
_GEOMETRY: dict[str, dict[str, Any]] = {
    "wide": {  # 1600x900
        "card_y": 0.645,
        "card_h": 0.115,
        "axes": (0.075, 0.185, 0.880, 0.395),
        "footer_y": 0.105,
        "footer_size": 9.5,
    },
    "square": {  # 1080x1080
        "card_y": 0.685,
        "card_h": 0.095,
        "axes": (0.100, 0.155, 0.855, 0.475),
        "footer_y": 0.088,
        "footer_size": 8.5,
    },
    "portrait": {  # 1080x1350
        "card_y": 0.735,
        "card_h": 0.075,
        "axes": (0.100, 0.135, 0.855, 0.545),
        "footer_y": 0.078,
        "footer_size": 8.5,
    },
}

_CARD_W = 0.283
_CARD_GAP = 0.025
_CARD_X0 = 0.05


class YTDVisualizer:
    """Create YTD growth visualizations."""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _period_end(self, through_month: int) -> tuple[int, int, bool]:
        """(year, last day covered, whether that month has finished).

        The scheduled run fires on the 1st and reports on the completed previous
        month. A manual mid-month run covers only part of the current month, and
        must not label the chart with the month's final day or rank a part-month
        against whole ones.
        """
        today = datetime.now()
        if today.day == 1:
            year = today.year if today.month > 1 else today.year - 1
            return year, calendar.monthrange(year, through_month)[1], True
        if through_month == today.month:
            return today.year, today.day, False
        return today.year, calendar.monthrange(today.year, through_month)[1], True

    def _get_month_name_for_last_day(self, through_month: int) -> str:
        """The last date actually covered, e.g. 'May 31, 2026'."""
        year, last_day, _ = self._period_end(through_month)
        return f"{calendar.month_name[through_month]} {last_day}, {year}"

    def create_chart(
        self,
        current_cumulative: dict,
        previous_cumulative: dict,
        current_year: int,
        ratio: str = "wide",
        dark_mode: bool = True,
        filename: Optional[str] = None,
        through_month: int = 12,
        daily_current: Optional[dict] = None,
        daily_previous: Optional[dict] = None,
        stats: Optional[dict] = None,
        monthly_data: Optional[dict] = None,
        previous_monthly_data: Optional[dict] = None,
    ) -> Path:
        """Render the YTD growth chart in one aspect ratio and theme.

        Args:
            current_cumulative: Monthly cumulative counts (current year)
            previous_cumulative: Monthly cumulative counts (previous year)
            current_year: Year being reported on
            ratio: One of 'wide', 'square', 'portrait'
            dark_mode: Use the dark palette
            filename: Override the generated output filename
            through_month: Last month included in the report
            daily_current: Daily cumulative counts (current year)
            daily_previous: Daily cumulative counts (previous year)
            stats: Statistics dict from YTDAnalyzer
            monthly_data: Per-month counts (current year)
            previous_monthly_data: Per-month counts (previous year)

        Returns:
            Path to the written PNG
        """
        if ratio not in _GEOMETRY:
            raise ValueError(
                f"Unknown ratio {ratio!r}; expected one of {list(_GEOMETRY)}"
            )

        colors = style.apply_style(dark=dark_mode)
        geo = _GEOMETRY[ratio]
        previous_year = current_year - 1
        month_name = calendar.month_name[through_month]
        end_year, end_day, month_complete = self._period_end(through_month)
        through_date = f"{month_name} {end_day}, {end_year}"
        # The tile is what survives a crop, so it carries the real cut-off rather
        # than a bare month name that reads as the whole month.
        tile_through = (
            month_name
            if month_complete
            else f"{calendar.month_abbr[through_month]} {end_day}"
        )

        ytd_total = (
            stats.get("current_ytd_total", 0)
            if stats
            else current_cumulative.get(through_month, 0)
        )
        prev_ytd = (
            stats.get("previous_ytd_total", 0)
            if stats
            else previous_cumulative.get(through_month, 0)
        )
        yoy_pct = stats.get("yoy_percent", 0) if stats else 0
        avg_day = stats.get("avg_cves_per_day", 0) if stats else 0

        fig = plt.figure(figsize=style.figsize_for(ratio))
        fig.patch.set_facecolor(colors["background"])

        style.draw_header(
            fig,
            title=f"Cumulative CVEs Published, {current_year} vs {previous_year}",
            subtitle=f"Through {through_date}  ·  {ytd_total:,} CVEs year to date",
            colors=colors,
            ratio=ratio,
            eyebrow_suffix="YTD Growth",
        )

        # --- stat cards -----------------------------------------------------
        cards = [
            ("Total CVEs", f"{ytd_total:,}", f"Through {tile_through}", None),
            (
                "YoY Growth",
                f"{yoy_pct:+.1f}%",
                f"vs {previous_year} ({prev_ytd:,})",
                colors["primary"],
            ),
            ("Daily Average", f"{avg_day:.0f}", "CVEs per day", None),
        ]
        for index, (label, value, sublabel, value_color) in enumerate(cards):
            style.draw_stat_card(
                fig,
                _CARD_X0 + index * (_CARD_W + _CARD_GAP),
                geo["card_y"],
                _CARD_W,
                geo["card_h"],
                label,
                value,
                sublabel,
                colors,
                value_color=value_color,
            )

        # --- main series ----------------------------------------------------
        ax = fig.add_axes(geo["axes"])
        ax.set_facecolor(colors["background"])

        if daily_current and daily_previous:
            days = sorted(daily_current.keys())
            current_values = [daily_current[d] for d in days]
            previous_values = [daily_previous.get(d, 0) for d in days]

            ax.plot(
                days,
                previous_values,
                linewidth=1.8,
                color=colors["comparison"],
                label=str(previous_year),
                linestyle="--",
                zorder=2,
            )
            ax.plot(
                days,
                current_values,
                linewidth=2.6,
                color=colors["alert"],
                label=str(current_year),
                zorder=3,
            )

            month_starts = []
            month_labels = []
            day_accum = 0
            for month in range(1, through_month + 1):
                month_starts.append(day_accum + 1)
                month_labels.append(calendar.month_abbr[month])
                day_accum += calendar.monthrange(current_year, month)[1]
            ax.set_xticks(month_starts)
            ax.set_xticklabels(month_labels)

            if current_values and previous_values:
                self._annotate_gap(ax, days, current_values, previous_values, colors)
        else:
            months = list(range(1, through_month + 1))
            current_values = [current_cumulative.get(m, 0) for m in months]
            previous_values = [previous_cumulative.get(m, 0) for m in months]

            ax.plot(
                months,
                previous_values,
                marker="o",
                markersize=5,
                linewidth=1.8,
                color=colors["comparison"],
                label=str(previous_year),
                linestyle="--",
                zorder=2,
            )
            ax.plot(
                months,
                current_values,
                marker="o",
                markersize=6,
                linewidth=2.6,
                color=colors["alert"],
                label=str(current_year),
                zorder=3,
            )
            ax.set_xticks(months)
            ax.set_xticklabels([calendar.month_abbr[m] for m in months])

        ax.set_ylim(bottom=0)
        ax.set_ylabel("Cumulative CVEs", fontsize=12, fontweight="bold")
        ax.yaxis.set_major_formatter(style.thousands_formatter())
        ax.grid(True, axis="y", color=colors["grid"], linewidth=0.6, alpha=0.8)
        ax.set_axisbelow(True)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color(colors["grid"])
            ax.spines[side].set_linewidth(1.0)

        legend = ax.legend(loc="upper left", fontsize=11, frameon=False)
        for text in legend.get_texts():
            text.set_color(colors["text"])

        # --- footer ---------------------------------------------------------
        # Rank only completed months: a part-month total is not comparable to a
        # whole one, so an in-progress month must not be called the busiest.
        ranked_through = through_month if month_complete else through_month - 1
        footer_parts = self._month_extremes(
            monthly_data, previous_monthly_data, ranked_through
        )
        self._draw_footer(fig, footer_parts, geo, colors)

        style.draw_footnote(fig, "Source: NVD, excluding rejected CVEs", colors)

        if filename is None:
            mode_suffix = "_dark" if dark_mode else "_light"
            ratio_name = "landscape" if ratio == "wide" else ratio
            filename = f"CVE_Growth_{current_year}{mode_suffix}_{ratio_name}.png"

        output_path = style.stamp_and_save(
            fig, self.output_dir / filename, colors, stamp_date=datetime.now()
        )
        logger.info("Chart written to %s", output_path)
        return output_path

    def _draw_footer(self, fig, parts: list, geo: dict, colors: dict) -> None:
        """Draw the month-extremes line, wrapped so it cannot run off the canvas.

        The width is measured rather than guessed. Month names, counts and
        percentages all change length month to month, and a fixed character
        budget sheared the last word off four of the six charts the first time a
        three-digit growth figure appeared.
        """
        if not parts:
            return

        renderer = fig.canvas.get_renderer()
        available = 0.90  # figure fraction between the left and right margins
        size = geo["footer_size"]

        lines = []
        for per_line in (len(parts), 2, 1):
            groups = [parts[i : i + per_line] for i in range(0, len(parts), per_line)]
            lines = ["  ·  ".join(group) for group in groups]
            probes = [
                fig.text(0.05, -1, line, fontfamily=style.BODY_FONT, fontsize=size)
                for line in lines
            ]
            widest = max(
                probe.get_window_extent(renderer).width / fig.bbox.width
                for probe in probes
            )
            for probe in probes:
                probe.remove()
            if widest <= available:
                break

        # Stack upward from the anchor so the block grows away from the footnote.
        line_height = (size * 1.7 / 72) * style.SAVE_DPI / fig.bbox.height
        for index, line in enumerate(lines):
            fig.text(
                0.05,
                geo["footer_y"] + (len(lines) - 1 - index) * line_height,
                line,
                fontfamily=style.BODY_FONT,
                fontsize=size,
                color=colors["secondary"],
                ha="left",
                va="bottom",
            )

    def _annotate_gap(self, ax, days, current_values, previous_values, colors) -> None:
        """Bracket the gap between the two series at the reporting endpoint.

        A vertical span at the last day, labelled to its left. An arrow pointing
        at the endpoint reads as pointing at nothing, because the quantity being
        called out is the distance between the lines rather than a point on them.
        """
        last_day = days[-1]
        last_current = current_values[-1]
        last_previous = previous_values[-1]
        diff = last_current - last_previous
        diff_pct = (diff / last_previous * 100) if last_previous > 0 else 0
        # Sit the label in the lower part of the gap. Centred, it lands on the
        # highlighted current-year line, so the callout about that series was
        # hiding the series.
        label_y = last_previous + (last_current - last_previous) * 0.3

        ax.annotate(
            "",
            xy=(last_day, last_previous),
            xytext=(last_day, last_current),
            arrowprops=dict(
                arrowstyle="<->",
                color=colors["primary"],
                lw=1.2,
                shrinkA=0,
                shrinkB=0,
            ),
            zorder=5,
        )
        ax.text(
            last_day - max(days) * 0.015,
            label_y,
            f"{diff:+,}\n({diff_pct:+.1f}%)",
            fontfamily=style.MONO_FONT,
            fontsize=9.5,
            fontweight="bold",
            color=colors["primary"],
            bbox=dict(
                boxstyle="round,pad=0.4",
                facecolor=colors["soft"],
                edgecolor=colors["grid"],
                linewidth=1.0,
            ),
            ha="right",
            va="center",
            zorder=6,
        )

    def _month_extremes(
        self,
        monthly_data: Optional[dict],
        previous_monthly_data: Optional[dict],
        through_month: int,
    ) -> list:
        """A one-line summary of the busiest, quietest, and fastest-growing month."""
        if not monthly_data:
            return []

        counts = {m: monthly_data.get(m, 0) for m in range(1, through_month + 1)}
        non_zero = {m: c for m, c in counts.items() if c > 0}
        if not non_zero:
            return []

        peak = max(non_zero, key=lambda month: non_zero[month])
        low = min(non_zero, key=lambda month: non_zero[month])
        # "completed" is load-bearing: the ranking deliberately skips a month
        # still in progress, so the label says so rather than leaving a reader to
        # wonder why the highest bar on the chart is not named here.
        # "completed" once, on the first item: it explains why a month still in
        # progress is absent from the ranking, and repeating it on every item
        # pushed this line off the edge of the narrower canvases.
        parts = [
            f"Busiest completed month: {calendar.month_abbr[peak]} "
            f"({non_zero[peak]:,})",
            f"Quietest: {calendar.month_abbr[low]} ({non_zero[low]:,})",
        ]

        previous = previous_monthly_data or {}
        best_month, best_growth = None, float("-inf")
        for month in range(1, through_month + 1):
            prior = previous.get(month, 0)
            if prior > 0 and counts.get(month, 0) > 0:
                growth = (counts[month] - prior) / prior * 100
                if growth > best_growth:
                    best_growth, best_month = growth, month
        if best_month:
            # Name the comparison, so the number is not stranded next to the
            # year-to-date growth figure looking like a rival for it.
            parts.append(
                f"Fastest YoY: {calendar.month_abbr[best_month]} "
                f"{best_growth:+.1f}% on last year"
            )

        return parts

    # -- backwards-compatible entry points ----------------------------------

    def create_ytd_chart(self, *args, **kwargs) -> Path:
        """Render the wide (16:9) chart. Output name keeps the 'landscape' suffix."""
        kwargs.setdefault("ratio", "wide")
        return self.create_chart(*args, **kwargs)

    def create_square_chart(self, *args, **kwargs) -> Path:
        """Render the square (1:1) chart for the feed."""
        kwargs["ratio"] = "square"
        return self.create_chart(*args, **kwargs)

    def create_portrait_chart(self, *args, **kwargs) -> Path:
        """Render the portrait (4:5) chart for Instagram and LinkedIn."""
        kwargs["ratio"] = "portrait"
        return self.create_chart(*args, **kwargs)

    def create_yoy_comparison(
        self,
        current_year: int,
        previous_year: int,
        current_ytd: int,
        previous_ytd: int,
        growth_percent: float,
        dark_mode: bool = False,
        through_month: Optional[int] = None,
    ) -> Path:
        """Render the year-over-year bar comparison.

        This is the most portable asset in the set, so it is the one most likely
        to be reposted stripped of context. It therefore has to name the window
        on its face: a bar labelled only "2025" reads as the whole of 2025.
        """
        colors = style.apply_style(dark=dark_mode)
        ratio = "wide"

        if through_month is not None:
            end_year, end_day, _ = self._period_end(through_month)
            window = (
                f"Jan 1 to {calendar.month_abbr[through_month]} {end_day}, both years"
            )
        else:
            window = "Same period both years"

        fig = plt.figure(figsize=style.figsize_for(ratio))
        fig.patch.set_facecolor(colors["background"])

        style.draw_header(
            fig,
            # Current year first, matching the sibling growth chart's title.
            title=f"Year to Date CVEs, {current_year} vs {previous_year}",
            subtitle=f"{window}  ·  {growth_percent:+.1f}% year over year",
            colors=colors,
            ratio=ratio,
            eyebrow_suffix="YoY Comparison",
        )

        ax = fig.add_axes((0.075, 0.150, 0.880, 0.560))
        ax.set_facecolor(colors["background"])

        years = [str(previous_year), str(current_year)]
        values = [previous_ytd, current_ytd]
        bars = ax.bar(
            years,
            values,
            color=[colors["light"], colors["alert"]],
            width=0.35,
            zorder=3,
        )

        for bar, value in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                f"{int(value):,}",
                ha="center",
                va="bottom",
                fontfamily=style.HEAD_FONT,
                fontsize=20,
                color=colors["text"],
            )

        ax.set_ylabel("CVEs published (YTD)", fontsize=12, fontweight="bold")
        ax.yaxis.set_major_formatter(style.thousands_formatter())
        ax.set_ylim(0, max(values) * 1.18 if max(values) else 1)
        ax.grid(True, axis="y", color=colors["grid"], linewidth=0.6, alpha=0.8)
        ax.set_axisbelow(True)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color(colors["grid"])
            ax.spines[side].set_linewidth(1.0)
        ax.tick_params(labelsize=13)

        style.draw_footnote(fig, "Source: NVD, excluding rejected CVEs", colors)

        filename = f"YOY_CVE_Comparison_{current_year}_vs_{previous_year}.png"
        output_path = style.stamp_and_save(
            fig, self.output_dir / filename, colors, stamp_date=datetime.now()
        )
        logger.info("Chart written to %s", output_path)
        return output_path
