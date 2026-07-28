"""
Chart styling for monthly CVE reports.

A port of CVEGraphs/style_social.py so charts from both repos share one visual
language: Host Grotesk headlines, Roboto body, Roboto Mono for the eyebrow and
date stamp, near-black ink on white, a hairline grid, flat fills, generous
whitespace, and a deep-navy accent.

Two departures from the CVEGraphs original, both driven by this repo's needs:

* a dark palette, because the monthly charts have always shipped in dark and
  light pairs (CVEGraphs is light only);
* fonts are committed to the repo, because these charts render in GitHub Actions
  rather than on a laptop that already has them installed.
"""

import logging
from pathlib import Path
from typing import Optional

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib import font_manager as fm

logger = logging.getLogger(__name__)

HANDLE = "@jgamblin"
SITE = "rogolabs.net"

# -----------------------------------------------------------------------------
# Fonts — bundled so rendering is self-contained on a bare CI runner. matplotlib
# falls back silently when a face is missing, which would ship every chart in the
# wrong typeface without failing the build, so a missing file warns loudly.
# -----------------------------------------------------------------------------
FONT_DIR = Path(__file__).resolve().parent.parent.parent / "fonts"
HEAD_FONT = "Host Grotesk"  # headlines (single Light weight — editorial, thin)
BODY_FONT = "Roboto"  # subtitles, axis labels, body copy
MONO_FONT = "Roboto Mono"  # CVE ids, the eyebrow, the date stamp

_FONT_FILES = (
    "HostGrotesk.ttf",
    "Roboto-Regular.ttf",
    "Roboto-Bold.ttf",
    "RobotoMono.ttf",
)


def _register_fonts() -> list[str]:
    """Register the bundled faces with matplotlib. Returns any that are missing."""
    missing = []
    for filename in _FONT_FILES:
        path = FONT_DIR / filename
        if not path.exists():
            missing.append(filename)
            continue
        try:
            fm.fontManager.addfont(str(path))
        except Exception as exc:  # pragma: no cover - matplotlib internals
            logger.warning("Could not register font %s: %s", filename, exc)
            missing.append(filename)
    if missing:
        logger.warning(
            "Missing bundled fonts in %s: %s. Charts will render in a fallback "
            "face and will not match the house style.",
            FONT_DIR,
            ", ".join(missing),
        )
    return missing


MISSING_FONTS = _register_fonts()

# -----------------------------------------------------------------------------
# Output aspect ratios (pixels). "wide" keeps the historical "landscape" output
# name; square and portrait are the feed sizes.
# -----------------------------------------------------------------------------
RATIOS = {
    "square": (1080, 1080),  # LinkedIn / X / Mastodon / Bluesky / IG feed
    "portrait": (1080, 1350),  # Instagram + LinkedIn portrait (4:5)
    "wide": (1600, 900),  # X / Twitter landscape (16:9)
}

SAVE_DPI = 150  # figsize is derived as pixels / SAVE_DPI

# -----------------------------------------------------------------------------
# Palettes — the CVEGraphs deep-navy ramp, plus a dark counterpart that keeps the
# same navy family and token names so charts read as one system either way.
# -----------------------------------------------------------------------------
LIGHT_COLORS = {
    "primary": "#1f3a5f",  # deep navy — primary accent, strongest emphasis
    "accent": "#5a7a9c",  # mid navy — secondary emphasis
    "neutral": "#8da0b5",  # muted navy-grey
    "light": "#afc0d4",  # pale navy tint — non-highlighted fills
    "secondary": "#525559",  # muted ink — subtitles, footnotes, stamp
    "text": "#181818",  # near-black ink — headlines, labels
    "grid": "#dfe2e5",  # hairline grid / axis line
    "soft": "#f6f7f9",  # near-white panel
    "alert": "#dc2626",  # alert red — the highlighted (current year) series
    "comparison": "#8da0b5",  # the prior-year series, 1.8:1 against alert
    "background": "#ffffff",
}

DARK_COLORS = {
    "primary": "#7fa8d4",  # lifted navy — legible as an accent on dark
    "accent": "#5a7a9c",
    "neutral": "#8da0b5",
    "light": "#3d5570",
    "secondary": "#9aa8b8",
    "text": "#eef2f6",
    "grid": "#2a3644",
    "soft": "#18212e",
    "alert": "#f87171",
    # Its own token rather than reusing "neutral": on dark, "neutral" sits at
    # 1.03:1 against alert, so the two series were separated only by dash and
    # weight. This lifts the pair to 2.0:1 and 3.3:1 against the background.
    "comparison": "#4a6b8f",
    "background": "#0f1620",
}

# The uppercase eyebrow that sits above the headline.
EYEBROW = "CVE Insights"


def palette(dark: bool = False) -> dict:
    """The colour tokens for a theme."""
    return DARK_COLORS if dark else LIGHT_COLORS


def figsize_for(ratio: str) -> tuple[float, float]:
    """(width, height) in inches for a named ratio at SAVE_DPI."""
    width, height = RATIOS[ratio]
    return (width / SAVE_DPI, height / SAVE_DPI)


def apply_style(dark: bool = False) -> dict:
    """Apply the house style globally and return the active palette.

    Body text is Roboto; headlines opt into Host Grotesk via ``draw_header``.
    """
    colors = palette(dark)
    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": [
                BODY_FONT,
                "Arial",
                "Helvetica",
                "DejaVu Sans",
                "sans-serif",
            ],
            "font.size": 15,
            "axes.titlesize": 24,
            "axes.titleweight": "bold",
            "axes.titlepad": 14,
            "axes.labelsize": 15,
            "axes.labelweight": "bold",
            "axes.labelpad": 8,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.edgecolor": colors["grid"],
            "axes.linewidth": 1.0,
            "axes.facecolor": colors["background"],
            "figure.facecolor": colors["background"],
            "savefig.facecolor": colors["background"],
            "text.color": colors["text"],
            "axes.labelcolor": colors["text"],
            "axes.grid": True,
            "axes.grid.axis": "y",
            "grid.color": colors["grid"],
            "grid.linewidth": 0.6,
            "grid.alpha": 0.8,
            "xtick.labelsize": 13,
            "ytick.labelsize": 13,
            "xtick.color": colors["text"],
            "ytick.color": colors["text"],
            "figure.dpi": 100,
            "savefig.dpi": SAVE_DPI,
            # Not 'tight': we want exact figure dimensions so aspect ratios are
            # honored and the reserved header/footer margins survive.
            "savefig.bbox": None,
        }
    )
    return colors


# Header geometry per ratio. The eyebrow sits above the title, the subtitle
# below. Tuned to clear the plot area given each chart's subplots_adjust(top=).
_HEADER = {
    "wide": {"eyebrow_y": 0.945, "title_y": 0.900, "sub_y": 0.822, "t1": 26},
    "square": {"eyebrow_y": 0.955, "title_y": 0.917, "sub_y": 0.862, "t1": 22},
    "portrait": {"eyebrow_y": 0.960, "title_y": 0.928, "sub_y": 0.880, "t1": 22},
}


def draw_header(
    fig,
    title: str,
    subtitle: str,
    colors: dict,
    ratio: str = "wide",
    eyebrow: str = EYEBROW,
    x: float = 0.05,
    eyebrow_suffix: Optional[str] = None,
    title_size: Optional[float] = None,
) -> None:
    """Draw the house header: an uppercase mono eyebrow over a short accent rule,
    the Host Grotesk headline, then the Roboto subtitle.

    House rule for ``title``: state what the chart shows, in Title Case. Never an
    argument or a verdict.
    """
    g = _HEADER[ratio]
    label = eyebrow if not eyebrow_suffix else f"{eyebrow}  ·  {eyebrow_suffix}"
    fig.text(
        x,
        g["eyebrow_y"],
        label.upper(),
        fontfamily=MONO_FONT,
        fontsize=10.5,
        fontweight="bold",
        color=colors["primary"],
        ha="left",
        va="center",
    )
    fig.add_artist(
        plt.Line2D(
            [x, x + 0.075],
            [g["eyebrow_y"] - 0.028] * 2,
            color=colors["primary"],
            lw=2.4,
            transform=fig.transFigure,
        )
    )
    fig.text(
        x,
        g["title_y"],
        title,
        fontfamily=HEAD_FONT,
        fontsize=title_size or g["t1"],
        color=colors["text"],
        ha="left",
        va="top",
    )
    fig.text(
        x,
        g["sub_y"],
        subtitle,
        fontfamily=BODY_FONT,
        fontsize=11,
        fontweight="bold",
        color=colors["secondary"],
        ha="left",
        va="top",
    )


def draw_stat_card(
    fig,
    x: float,
    y: float,
    w: float,
    h: float,
    label: str,
    value: str,
    sublabel: str,
    colors: dict,
    value_color: Optional[str] = None,
) -> None:
    """A flat stat panel: mono label, large Host Grotesk value, muted sublabel."""
    ax = fig.add_axes([x, y, w, h])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_facecolor(colors["soft"])
    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(True)
        spine.set_edgecolor(colors["grid"])
        spine.set_linewidth(1.0)

    # Sized to clear each other inside a card roughly 100px tall. The value is
    # the tallest element, so it gets the middle band to itself.
    ax.text(
        0.5,
        0.84,
        label.upper(),
        ha="center",
        va="center",
        fontfamily=MONO_FONT,
        fontsize=8.5,
        fontweight="bold",
        color=colors["secondary"],
    )
    ax.text(
        0.5,
        0.50,
        value,
        ha="center",
        va="center",
        fontfamily=HEAD_FONT,
        fontsize=23,
        color=value_color or colors["text"],
    )
    if sublabel:
        ax.text(
            0.5,
            0.15,
            sublabel,
            ha="center",
            va="center",
            fontfamily=BODY_FONT,
            fontsize=9,
            color=colors["secondary"],
        )


def _format_thousands(x, pos):
    if x >= 1000:
        v = x / 1000
        return f"{v:.0f}K" if abs(v - round(v)) < 1e-9 else f"{v:.1f}K"
    return f"{int(x)}"


def thousands_formatter():
    return ticker.FuncFormatter(_format_thousands)


def draw_footnote(fig, text: str, colors: dict, y: float = 0.045) -> None:
    """Data provenance, bottom left. Kept separate from the stamp."""
    fig.text(
        0.05,
        y,
        text,
        fontfamily=BODY_FONT,
        fontsize=9,
        color=colors["secondary"],
        ha="left",
        va="bottom",
    )


def stamp_and_save(fig, filepath, colors: dict, stamp_date=None) -> Path:
    """Stamp handle / site / date bottom right, write the file, close the figure.

    House rule: the stamp is the day the chart is rendered, never the data-source
    date, so a chart never looks staler or fresher than the day it goes out. Data
    provenance belongs in the footnote.
    """
    stamp = stamp_date.strftime("%b %d, %Y") if stamp_date else ""
    fig.text(
        0.95,
        0.045,
        f"{HANDLE}  ·  {SITE}" + (f"  ·  {stamp}" if stamp else ""),
        transform=fig.transFigure,
        fontfamily=MONO_FONT,
        fontsize=8.5,
        color=colors["secondary"],
        alpha=0.85,
        ha="right",
        va="bottom",
    )
    # Exact dimensions (no 'tight' crop) so the aspect ratio is honored and the
    # reserved header/footer margins survive.
    fig.savefig(
        filepath,
        dpi=SAVE_DPI,
        bbox_inches=None,
        facecolor=colors["background"],
        edgecolor="none",
    )
    plt.close(fig)
    return Path(filepath)
