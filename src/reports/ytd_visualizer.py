"""
Create YTD growth visualizations for CVE data.

Generates dashboard-style charts showing:
- Year-to-date cumulative CVE growth (daily granularity)
- Current year vs previous year comparison
- Stat cards with key metrics
- Multiple formats (landscape, square, dark/light modes)
"""

import calendar
from pathlib import Path
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import numpy as np


class YTDVisualizer:
    """Create YTD growth visualizations."""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.dark_colors = {
            "background": "#0d1117",
            "card_bg": "#161b22",
            "card_border": "#30363d",
            "grid": "#21262d",
            "text": "#c9d1d9",
            "text_dim": "#8b949e",
            "current": "#58a6ff",
            "previous": "#484f58",
            "accent": "#3fb950",
            "accent_secondary": "#a371f7",
            "fill_current": "#58a6ff",
            "fill_previous": "#484f58",
        }

        self.light_colors = {
            "background": "#ffffff",
            "card_bg": "#f6f8fa",
            "card_border": "#d0d7de",
            "grid": "#e5e7eb",
            "text": "#1f2937",
            "text_dim": "#6b7280",
            "current": "#0969da",
            "previous": "#9ca3af",
            "accent": "#1a7f37",
            "accent_secondary": "#8250df",
            "fill_current": "#0969da",
            "fill_previous": "#9ca3af",
        }

    def _draw_stat_card(self, fig, x, y, w, h, label, value, sublabel, colors):
        """Draw a stat card on the figure."""
        ax_card = fig.add_axes([x, y, w, h])
        ax_card.set_xlim(0, 1)
        ax_card.set_ylim(0, 1)
        ax_card.set_facecolor(colors["card_bg"])
        ax_card.axis("off")

        # Border
        for spine in ax_card.spines.values():
            spine.set_edgecolor(colors["card_border"])
            spine.set_linewidth(1.5)
            spine.set_visible(True)

        # Label
        ax_card.text(
            0.5,
            0.82,
            label.upper(),
            ha="center",
            va="center",
            fontsize=9,
            color=colors["text_dim"],
            fontweight="bold",
        )
        # Value
        ax_card.text(
            0.5,
            0.48,
            value,
            ha="center",
            va="center",
            fontsize=28,
            color=colors["text"],
            fontweight="bold",
        )
        # Sublabel
        if sublabel:
            ax_card.text(
                0.5,
                0.18,
                sublabel,
                ha="center",
                va="center",
                fontsize=10,
                color=colors["text_dim"],
            )

    def _get_month_name_for_last_day(self, through_month):
        """Get the last date string for the reporting period."""
        today = datetime.now()
        year = today.year
        if today.day == 1:
            year = today.year if today.month > 1 else today.year - 1
        last_day = calendar.monthrange(year, through_month)[1]
        month_name = calendar.month_name[through_month]
        return f"{month_name} {last_day}, {year}"

    def create_ytd_chart(
        self,
        current_cumulative: dict,
        previous_cumulative: dict,
        current_year: int,
        dark_mode: bool = True,
        filename: str = None,
        through_month: int = 12,
        daily_current: dict = None,
        daily_previous: dict = None,
        stats: dict = None,
        monthly_data: dict = None,
    ) -> Path:
        """
        Create dashboard-style YTD growth chart with stat cards.

        Args:
            current_cumulative: Monthly cumulative counts (current year)
            previous_cumulative: Monthly cumulative counts (previous year)
            current_year: Current year
            dark_mode: Use dark theme
            filename: Output filename
            through_month: Last month to show
            daily_current: Daily cumulative counts (current year)
            daily_previous: Daily cumulative counts (previous year)
            stats: Statistics dict from analysis
            monthly_data: Monthly breakdown dict
        """
        colors = self.dark_colors if dark_mode else self.light_colors
        previous_year = current_year - 1
        month_name = calendar.month_name[through_month]
        through_date = self._get_month_name_for_last_day(through_month)

        # Key stats
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
        yoy_diff = ytd_total - prev_ytd

        # Figure
        fig = plt.figure(figsize=(14, 10))
        fig.patch.set_facecolor(colors["background"])

        # Title
        fig.text(
            0.5,
            0.96,
            f"{current_year} CVE Growth Report",
            ha="center",
            va="top",
            fontsize=26,
            color=colors["text"],
            fontweight="bold",
        )
        # Blue underline
        line_ax = fig.add_axes([0.25, 0.945, 0.50, 0.003])
        line_ax.set_facecolor(colors["current"])
        line_ax.axis("off")

        # Subtitle
        fig.text(
            0.5,
            0.93,
            f"Data through {through_date}  ·  Year-over-Year Analysis",
            ha="center",
            va="top",
            fontsize=11,
            color=colors["text_dim"],
        )

        # Stat cards
        card_y = 0.82
        card_h = 0.09
        card_w = 0.25
        gap = 0.03
        start_x = 0.5 - (3 * card_w + 2 * gap) / 2

        self._draw_stat_card(
            fig,
            start_x,
            card_y,
            card_w,
            card_h,
            "Total CVEs",
            f"{ytd_total:,}",
            f"Through {month_name}",
            colors,
        )

        # YoY growth card with colored value
        ax_yoy = fig.add_axes([start_x + card_w + gap, card_y, card_w, card_h])
        ax_yoy.set_xlim(0, 1)
        ax_yoy.set_ylim(0, 1)
        ax_yoy.set_facecolor(colors["card_bg"])
        ax_yoy.axis("off")
        for spine in ax_yoy.spines.values():
            spine.set_edgecolor(colors["card_border"])
            spine.set_linewidth(1.5)
            spine.set_visible(True)
        ax_yoy.text(
            0.5,
            0.82,
            "YoY GROWTH",
            ha="center",
            va="center",
            fontsize=9,
            color=colors["text_dim"],
            fontweight="bold",
        )
        ax_yoy.text(
            0.5,
            0.48,
            f"{yoy_pct:+.1f}%",
            ha="center",
            va="center",
            fontsize=28,
            color=colors["accent"],
            fontweight="bold",
        )
        ax_yoy.text(
            0.5,
            0.18,
            f"vs {previous_year} ({prev_ytd:,})",
            ha="center",
            va="center",
            fontsize=10,
            color=colors["text_dim"],
        )
        # Accent bar on left of YoY card
        bar_ax = fig.add_axes(
            [
                start_x + card_w + gap + card_w * 0.47,
                card_y + card_h * 0.1,
                0.004,
                card_h * 0.8,
            ]
        )
        bar_ax.set_facecolor(colors["accent_secondary"])
        bar_ax.axis("off")

        self._draw_stat_card(
            fig,
            start_x + 2 * (card_w + gap),
            card_y,
            card_w,
            card_h,
            "Daily Average",
            f"{avg_day:.0f}",
            "CVEs per day",
            colors,
        )

        # Main chart area
        ax = fig.add_axes([0.08, 0.15, 0.88, 0.60])
        ax.set_facecolor(colors["background"])

        # Use daily data if available, otherwise monthly
        if daily_current and daily_previous:
            days = sorted(daily_current.keys())
            current_values = [daily_current[d] for d in days]
            previous_values = [daily_previous.get(d, 0) for d in days]

            ax.plot(
                days,
                previous_values,
                linewidth=1.5,
                color=colors["previous"],
                label=f"{previous_year}",
                alpha=0.7,
                linestyle="--",
                zorder=2,
            )
            ax.fill_between(
                days, previous_values, alpha=0.05, color=colors["fill_previous"]
            )

            ax.plot(
                days,
                current_values,
                linewidth=2.5,
                color=colors["current"],
                label=f"{current_year}",
                zorder=3,
            )
            ax.fill_between(
                days, current_values, alpha=0.08, color=colors["fill_current"]
            )

            # Month tick marks
            month_starts = []
            month_labels = []
            day_accum = 0
            for m in range(1, through_month + 1):
                month_starts.append(day_accum + 1)
                month_labels.append(calendar.month_abbr[m])
                day_accum += calendar.monthrange(current_year, m)[1]
            ax.set_xticks(month_starts)
            ax.set_xticklabels(month_labels)

            # Difference annotation at endpoint
            if current_values and previous_values:
                last_day = days[-1]
                last_current = current_values[-1]
                last_previous = previous_values[-1]
                diff = last_current - last_previous
                diff_pct = (diff / last_previous * 100) if last_previous > 0 else 0

                bbox_color = colors["accent"] if diff > 0 else "#f85149"
                ax.annotate(
                    f"{diff:+,}\n({diff_pct:+.1f}%)",
                    xy=(last_day, last_current),
                    xytext=(
                        last_day + max(days) * 0.03,
                        (last_current + last_previous) / 2,
                    ),
                    fontsize=10,
                    fontweight="bold",
                    color=bbox_color,
                    bbox=dict(
                        boxstyle="round,pad=0.4",
                        facecolor=colors["card_bg"],
                        edgecolor=bbox_color,
                        linewidth=1.5,
                    ),
                    arrowprops=dict(arrowstyle="->", color=bbox_color, lw=1.5),
                    ha="left",
                    va="center",
                    zorder=5,
                )
        else:
            # Fallback to monthly
            months = list(range(1, through_month + 1))
            current_values = [current_cumulative.get(m, 0) for m in months]
            previous_values = [previous_cumulative.get(m, 0) for m in months]
            month_labels = [calendar.month_abbr[m] for m in months]

            ax.plot(
                months,
                previous_values,
                marker="o",
                linewidth=2,
                markersize=6,
                color=colors["previous"],
                label=f"{previous_year}",
                linestyle="--",
                alpha=0.7,
                zorder=2,
            )
            ax.plot(
                months,
                current_values,
                marker="o",
                linewidth=3,
                markersize=8,
                color=colors["current"],
                label=f"{current_year}",
                zorder=3,
            )

            ax.set_xticks(months)
            ax.set_xticklabels(month_labels)

        # Styling
        ax.grid(True, color=colors["grid"], alpha=0.3, linestyle="-", linewidth=0.5)
        ax.set_axisbelow(True)
        ax.set_ylim(bottom=0)
        ax.set_ylabel(
            "Cumulative CVEs", fontsize=12, color=colors["text"], fontweight="bold"
        )
        ax.tick_params(colors=colors["text"], labelsize=10)
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{int(x):,}"))
        for spine in ax.spines.values():
            spine.set_color(colors["grid"])
            spine.set_linewidth(0.5)

        # Legend
        legend = ax.legend(loc="upper left", fontsize=11, framealpha=0.95)
        legend.get_frame().set_facecolor(colors["card_bg"])
        legend.get_frame().set_edgecolor(colors["card_border"])
        for text in legend.get_texts():
            text.set_color(colors["text"])

        # Footer stats
        if monthly_data:
            month_counts = {
                m: monthly_data.get(m, 0) for m in range(1, through_month + 1)
            }
            non_zero = {m: c for m, c in month_counts.items() if c > 0}
            if non_zero:
                peak_m = max(non_zero, key=non_zero.get)
                low_m = min(non_zero, key=non_zero.get)
                # Highest growth month
                best_growth_m = None
                best_growth_pct = 0
                for m in range(2, through_month + 1):
                    prev = month_counts.get(m - 1, 0)
                    if prev > 0:
                        g = (month_counts[m] - prev) / prev * 100
                        if g > best_growth_pct:
                            best_growth_pct = g
                            best_growth_m = m

                footer_parts = [
                    f"Peak Month: {calendar.month_abbr[peak_m]} ({non_zero[peak_m]:,})",
                    f"Low Month: {calendar.month_abbr[low_m]} ({non_zero[low_m]:,})",
                ]
                if best_growth_m:
                    footer_parts.append(
                        f"Highest Monthly Growth: {calendar.month_abbr[best_growth_m]} ({best_growth_pct:+.1f}%)"
                    )

                fig.text(
                    0.5,
                    0.06,
                    "  ·  ".join(footer_parts),
                    ha="center",
                    va="center",
                    fontsize=10,
                    color=colors["text_dim"],
                )

        # Attribution
        fig.text(
            0.5,
            0.02,
            f"Data: NIST National Vulnerability Database  ·  @jgamblin · rogolabs.net",
            ha="center",
            va="center",
            fontsize=9,
            color=colors["text_dim"],
            alpha=0.7,
        )

        # Save
        if filename is None:
            mode_suffix = "_dark" if dark_mode else "_light"
            filename = f"CVE_Growth_{current_year}{mode_suffix}_landscape.png"

        output_path = self.output_dir / filename
        plt.savefig(
            output_path,
            dpi=150,
            bbox_inches="tight",
            facecolor=colors["background"],
            edgecolor="none",
        )
        plt.close()
        return output_path

    def create_square_chart(
        self,
        current_cumulative: dict,
        previous_cumulative: dict,
        current_year: int,
        dark_mode: bool = True,
        through_month: int = 12,
        daily_current: dict = None,
        daily_previous: dict = None,
        stats: dict = None,
        monthly_data: dict = None,
    ) -> Path:
        """Create square format (1:1) dashboard chart for social media."""
        # Reuse landscape chart with square dimensions
        colors = self.dark_colors if dark_mode else self.light_colors
        previous_year = current_year - 1
        month_name = calendar.month_name[through_month]
        through_date = self._get_month_name_for_last_day(through_month)

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

        fig = plt.figure(figsize=(10, 10))
        fig.patch.set_facecolor(colors["background"])

        # Title
        fig.text(
            0.5,
            0.96,
            f"{current_year} CVE Growth Report",
            ha="center",
            va="top",
            fontsize=22,
            color=colors["text"],
            fontweight="bold",
        )
        line_ax = fig.add_axes([0.28, 0.945, 0.44, 0.003])
        line_ax.set_facecolor(colors["current"])
        line_ax.axis("off")
        fig.text(
            0.5,
            0.93,
            f"Data through {through_date}  ·  Year-over-Year Analysis",
            ha="center",
            va="top",
            fontsize=10,
            color=colors["text_dim"],
        )

        # Stat cards (smaller for square)
        card_y = 0.83
        card_h = 0.08
        card_w = 0.27
        gap = 0.025
        start_x = 0.5 - (3 * card_w + 2 * gap) / 2

        self._draw_stat_card(
            fig,
            start_x,
            card_y,
            card_w,
            card_h,
            "Total CVEs",
            f"{ytd_total:,}",
            f"Through {month_name}",
            colors,
        )

        # YoY card
        ax_yoy = fig.add_axes([start_x + card_w + gap, card_y, card_w, card_h])
        ax_yoy.set_xlim(0, 1)
        ax_yoy.set_ylim(0, 1)
        ax_yoy.set_facecolor(colors["card_bg"])
        ax_yoy.axis("off")
        for spine in ax_yoy.spines.values():
            spine.set_edgecolor(colors["card_border"])
            spine.set_linewidth(1.5)
            spine.set_visible(True)
        ax_yoy.text(
            0.5,
            0.82,
            "YoY GROWTH",
            ha="center",
            va="center",
            fontsize=8,
            color=colors["text_dim"],
            fontweight="bold",
        )
        ax_yoy.text(
            0.5,
            0.48,
            f"{yoy_pct:+.1f}%",
            ha="center",
            va="center",
            fontsize=24,
            color=colors["accent"],
            fontweight="bold",
        )
        ax_yoy.text(
            0.5,
            0.18,
            f"vs {previous_year} ({prev_ytd:,})",
            ha="center",
            va="center",
            fontsize=9,
            color=colors["text_dim"],
        )

        self._draw_stat_card(
            fig,
            start_x + 2 * (card_w + gap),
            card_y,
            card_w,
            card_h,
            "Daily Average",
            f"{avg_day:.0f}",
            "CVEs per day",
            colors,
        )

        # Chart
        ax = fig.add_axes([0.10, 0.12, 0.84, 0.64])
        ax.set_facecolor(colors["background"])

        if daily_current and daily_previous:
            days = sorted(daily_current.keys())
            current_values = [daily_current[d] for d in days]
            previous_values = [daily_previous.get(d, 0) for d in days]

            ax.plot(
                days,
                previous_values,
                linewidth=1.5,
                color=colors["previous"],
                label=f"{previous_year}",
                alpha=0.7,
                linestyle="--",
                zorder=2,
            )
            ax.fill_between(
                days, previous_values, alpha=0.05, color=colors["fill_previous"]
            )
            ax.plot(
                days,
                current_values,
                linewidth=2.5,
                color=colors["current"],
                label=f"{current_year}",
                zorder=3,
            )
            ax.fill_between(
                days, current_values, alpha=0.08, color=colors["fill_current"]
            )

            month_starts = []
            month_labels = []
            day_accum = 0
            for m in range(1, through_month + 1):
                month_starts.append(day_accum + 1)
                month_labels.append(calendar.month_abbr[m])
                day_accum += calendar.monthrange(current_year, m)[1]
            ax.set_xticks(month_starts)
            ax.set_xticklabels(month_labels)

            if current_values and previous_values:
                last_day = days[-1]
                diff = current_values[-1] - previous_values[-1]
                diff_pct = (
                    (diff / previous_values[-1] * 100) if previous_values[-1] > 0 else 0
                )
                bbox_color = colors["accent"] if diff > 0 else "#f85149"
                ax.annotate(
                    f"{diff:+,}\n({diff_pct:+.1f}%)",
                    xy=(last_day, current_values[-1]),
                    xytext=(
                        last_day + max(days) * 0.03,
                        (current_values[-1] + previous_values[-1]) / 2,
                    ),
                    fontsize=9,
                    fontweight="bold",
                    color=bbox_color,
                    bbox=dict(
                        boxstyle="round,pad=0.3",
                        facecolor=colors["card_bg"],
                        edgecolor=bbox_color,
                        linewidth=1.5,
                    ),
                    arrowprops=dict(arrowstyle="->", color=bbox_color, lw=1.5),
                    ha="left",
                    va="center",
                    zorder=5,
                )
        else:
            months = list(range(1, through_month + 1))
            current_values = [current_cumulative.get(m, 0) for m in months]
            previous_values = [previous_cumulative.get(m, 0) for m in months]
            ax.plot(
                months,
                previous_values,
                marker="o",
                linewidth=2,
                markersize=6,
                color=colors["previous"],
                label=f"{previous_year}",
                linestyle="--",
                alpha=0.7,
            )
            ax.plot(
                months,
                current_values,
                marker="o",
                linewidth=3,
                markersize=8,
                color=colors["current"],
                label=f"{current_year}",
            )
            ax.set_xticks(months)
            ax.set_xticklabels([calendar.month_abbr[m] for m in months])

        ax.grid(True, color=colors["grid"], alpha=0.3, linestyle="-", linewidth=0.5)
        ax.set_axisbelow(True)
        ax.set_ylim(bottom=0)
        ax.set_ylabel(
            "Cumulative CVEs", fontsize=11, color=colors["text"], fontweight="bold"
        )
        ax.tick_params(colors=colors["text"], labelsize=9)
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{int(x):,}"))
        for spine in ax.spines.values():
            spine.set_color(colors["grid"])
            spine.set_linewidth(0.5)

        legend = ax.legend(loc="upper left", fontsize=10, framealpha=0.95)
        legend.get_frame().set_facecolor(colors["card_bg"])
        legend.get_frame().set_edgecolor(colors["card_border"])
        for text in legend.get_texts():
            text.set_color(colors["text"])

        fig.text(
            0.5,
            0.02,
            "Data: NIST National Vulnerability Database  ·  @jgamblin · rogolabs.net",
            ha="center",
            fontsize=8,
            color=colors["text_dim"],
            alpha=0.7,
        )

        mode_suffix = "_dark" if dark_mode else "_light"
        output_path = (
            self.output_dir / f"CVE_Growth_{current_year}{mode_suffix}_square.png"
        )
        plt.savefig(
            output_path,
            dpi=150,
            bbox_inches="tight",
            facecolor=colors["background"],
            edgecolor="none",
        )
        plt.close()
        return output_path

    def create_yoy_comparison(
        self,
        current_year,
        previous_year,
        current_ytd,
        previous_ytd,
        growth_percent,
    ) -> Path:
        """Create year-over-year bar comparison chart."""
        colors = self.dark_colors

        fig, ax = plt.subplots(figsize=(12, 7))
        fig.patch.set_facecolor(colors["background"])
        ax.set_facecolor(colors["background"])

        years = [str(previous_year), str(current_year)]
        values = [previous_ytd, current_ytd]

        bars = ax.bar(
            years,
            values,
            color=[colors["previous"], colors["current"]],
            width=0.6,
            edgecolor=colors["grid"],
            linewidth=2,
        )

        for bar, value in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                f"{int(value):,}",
                ha="center",
                va="bottom",
                fontsize=14,
                fontweight="bold",
                color=colors["text"],
            )

        ax.text(
            0.5,
            max(values) * 0.5,
            f"{growth_percent:+.1f}%",
            ha="center",
            va="center",
            fontsize=32,
            fontweight="bold",
            color=colors["accent"],
            alpha=0.7,
        )

        ax.set_ylabel(
            "Cumulative CVEs (YTD)",
            fontsize=12,
            color=colors["text"],
            fontweight="bold",
        )
        ax.set_title(
            "Year-Over-Year Comparison",
            fontsize=16,
            color=colors["text"],
            fontweight="bold",
            pad=20,
        )
        ax.tick_params(colors=colors["text"], labelsize=11)
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{int(x):,}"))
        ax.grid(
            True,
            axis="y",
            color=colors["grid"],
            alpha=0.2,
            linestyle="-",
            linewidth=0.5,
        )
        ax.set_axisbelow(True)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_color(colors["grid"])
        ax.spines["bottom"].set_color(colors["grid"])

        output_path = (
            self.output_dir
            / f"YOY_CVE_Comparison_{current_year}_vs_{previous_year}.png"
        )
        plt.savefig(
            output_path,
            dpi=150,
            bbox_inches="tight",
            facecolor=colors["background"],
            edgecolor="none",
        )
        plt.close()
        return output_path
