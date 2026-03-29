"""
Create YTD growth visualizations for CVE data.

Generates professional charts showing:
- Year-to-date cumulative CVE growth
- Current year vs previous year comparison
- Multiple formats (landscape, square, dark/light modes)
- Animated GIFs for timeline progression
"""

from pathlib import Path
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.patches import Rectangle
import numpy as np


class YTDVisualizer:
    """Create YTD growth visualizations."""

    def __init__(self, output_dir: Path):
        """
        Initialize visualizer.

        Args:
            output_dir: Directory to save charts
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Color schemes
        self.dark_colors = {
            "background": "#0d1117",
            "grid": "#21262d",
            "text": "#c9d1d9",
            "current": "#58a6ff",  # GitHub blue
            "previous": "#484f58",  # GitHub gray
            "accent": "#3fb950",  # GitHub green
        }

        self.light_colors = {
            "background": "#ffffff",
            "grid": "#e5e7eb",
            "text": "#1f2937",
            "current": "#0ea5e9",  # Sky blue
            "previous": "#9ca3af",  # Gray
            "accent": "#10b981",  # Green
        }

    def create_ytd_chart(
        self,
        current_cumulative: dict,
        previous_cumulative: dict,
        current_year: int,
        dark_mode: bool = True,
        filename: str = None,
    ) -> Path:
        """
        Create YTD growth comparison chart.

        Args:
            current_cumulative: Dict of cumulative counts by month (current year)
            previous_cumulative: Dict of cumulative counts by month (previous year)
            current_year: Current year
            dark_mode: Use dark theme if True
            filename: Output filename (auto-generated if None)

        Returns:
            Path to saved image
        """
        colors = self.dark_colors if dark_mode else self.light_colors

        # Create figure
        fig, ax = plt.subplots(figsize=(14, 8))
        fig.patch.set_facecolor(colors["background"])
        ax.set_facecolor(colors["background"])

        # Prepare data
        months = list(range(1, 13))
        month_names = [
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        ]

        current_values = [current_cumulative.get(m, 0) for m in months]
        previous_values = [previous_cumulative.get(m, 0) for m in months]

        # Plot lines
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

        ax.plot(
            months,
            previous_values,
            marker="o",
            linewidth=2,
            markersize=6,
            color=colors["previous"],
            label=f"{current_year - 1}",
            linestyle="--",
            alpha=0.7,
            zorder=2,
        )

        # Styling
        ax.grid(True, color=colors["grid"], alpha=0.2, linestyle="-", linewidth=0.5)
        ax.set_axisbelow(True)

        # Labels and title
        ax.set_xlabel("Month", fontsize=12, color=colors["text"], fontweight="bold")
        ax.set_ylabel("Cumulative CVEs", fontsize=12, color=colors["text"], fontweight="bold")
        ax.set_title(f"{current_year} CVE Growth Report", fontsize=18, color=colors["text"], fontweight="bold", pad=20)

        # Format axes
        ax.set_xticks(months)
        ax.set_xticklabels(month_names)
        ax.tick_params(colors=colors["text"], labelsize=10)

        # Format Y-axis to show thousands
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{int(x):,}"))

        # Legend
        legend = ax.legend(loc="upper left", fontsize=11, framealpha=0.95)
        legend.get_frame().set_facecolor(colors["background"])
        for text in legend.get_texts():
            text.set_color(colors["text"])
        legend.get_frame().set_edgecolor(colors["grid"])

        # Add attribution
        fig.text(
            0.02,
            0.02,
            "@jgamblin / rogolabs.net",
            fontsize=9,
            color=colors["text"],
            alpha=0.6,
        )

        # Save figure
        if filename is None:
            mode_suffix = "_dark" if dark_mode else "_light"
            filename = f"CVE_Growth_{current_year}{mode_suffix}_landscape.png"

        output_path = self.output_dir / filename
        plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor=colors["background"], edgecolor="none")
        plt.close()

        return output_path

    def create_square_chart(
        self,
        current_cumulative: dict,
        previous_cumulative: dict,
        current_year: int,
        dark_mode: bool = True,
    ) -> Path:
        """
        Create square format YTD chart (1:1 aspect ratio for social media).

        Args:
            current_cumulative: Dict of cumulative counts by month (current year)
            previous_cumulative: Dict of cumulative counts by month (previous year)
            current_year: Current year
            dark_mode: Use dark theme if True

        Returns:
            Path to saved image
        """
        colors = self.dark_colors if dark_mode else self.light_colors

        # Create figure (square)
        fig, ax = plt.subplots(figsize=(10, 10))
        fig.patch.set_facecolor(colors["background"])
        ax.set_facecolor(colors["background"])

        # Prepare data
        months = list(range(1, 13))
        month_names = [
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        ]

        current_values = [current_cumulative.get(m, 0) for m in months]
        previous_values = [previous_cumulative.get(m, 0) for m in months]

        # Plot lines
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

        ax.plot(
            months,
            previous_values,
            marker="o",
            linewidth=2,
            markersize=6,
            color=colors["previous"],
            label=f"{current_year - 1}",
            linestyle="--",
            alpha=0.7,
            zorder=2,
        )

        # Styling
        ax.grid(True, color=colors["grid"], alpha=0.2, linestyle="-", linewidth=0.5)
        ax.set_axisbelow(True)

        # Labels and title
        ax.set_xlabel("Month", fontsize=11, color=colors["text"], fontweight="bold")
        ax.set_ylabel("Cumulative CVEs", fontsize=11, color=colors["text"], fontweight="bold")
        ax.set_title(
            f"{current_year} CVE Growth Report",
            fontsize=16,
            color=colors["text"],
            fontweight="bold",
            pad=15,
        )

        # Format axes
        ax.set_xticks(months)
        ax.set_xticklabels(month_names, fontsize=9)
        ax.tick_params(colors=colors["text"], labelsize=9)

        # Format Y-axis
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{int(x):,}"))

        # Legend
        legend = ax.legend(loc="upper left", fontsize=10, framealpha=0.95)
        legend.get_frame().set_facecolor(colors["background"])
        for text in legend.get_texts():
            text.set_color(colors["text"])
        legend.get_frame().set_edgecolor(colors["grid"])

        # Add attribution
        fig.text(
            0.02,
            0.02,
            "@jgamblin / rogolabs.net",
            fontsize=8,
            color=colors["text"],
            alpha=0.6,
        )

        # Save figure
        mode_suffix = "_dark" if dark_mode else "_light"
        output_path = self.output_dir / f"CVE_Growth_{current_year}{mode_suffix}_square.png"
        plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor=colors["background"], edgecolor="none")
        plt.close()

        return output_path

    def create_yoy_comparison(
        self,
        current_year: int,
        previous_year: int,
        current_ytd: int,
        previous_ytd: int,
        growth_percent: float,
    ) -> Path:
        """
        Create year-over-year comparison chart.

        Args:
            current_year: Current year
            previous_year: Previous year
            current_ytd: Current year YTD total
            previous_ytd: Previous year YTD total
            growth_percent: Growth percentage

        Returns:
            Path to saved image
        """
        colors = self.dark_colors

        fig, ax = plt.subplots(figsize=(12, 7))
        fig.patch.set_facecolor(colors["background"])
        ax.set_facecolor(colors["background"])

        years = [str(previous_year), str(current_year)]
        values = [previous_ytd, current_ytd]

        # Bar chart
        bars = ax.bar(
            years,
            values,
            color=[colors["previous"], colors["current"]],
            width=0.6,
            edgecolor=colors["grid"],
            linewidth=2,
        )

        # Add value labels
        for bar, value in zip(bars, values):
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                height,
                f"{int(value):,}",
                ha="center",
                va="bottom",
                fontsize=14,
                fontweight="bold",
                color=colors["text"],
            )

        # Add growth indicator
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

        # Styling
        ax.set_ylabel("Cumulative CVEs (YTD)", fontsize=12, color=colors["text"], fontweight="bold")
        ax.set_title("Year-Over-Year Comparison", fontsize=16, color=colors["text"], fontweight="bold", pad=20)
        ax.tick_params(colors=colors["text"], labelsize=11)
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{int(x):,}"))

        # Grid
        ax.grid(True, axis="y", color=colors["grid"], alpha=0.2, linestyle="-", linewidth=0.5)
        ax.set_axisbelow(True)

        # Remove top and right spines
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_color(colors["grid"])
        ax.spines["bottom"].set_color(colors["grid"])

        # Save figure
        output_path = self.output_dir / f"YOY_CVE_Comparison_{current_year}_vs_{previous_year}.png"
        plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor=colors["background"], edgecolor="none")
        plt.close()

        return output_path
