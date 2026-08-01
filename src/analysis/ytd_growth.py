"""
Year-to-Date (YTD) CVE growth analysis and comparison.

Generates comprehensive YTD statistics including:
- Cumulative CVE counts by month
- Growth rates (month-over-month and year-over-year)
- Comparison with previous year
- Daily and monthly averages
"""

import calendar
import math
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Optional
import json

# Prior full years shown alongside the current year to date.
PRIOR_YEARS_SHOWN = 5

# Opening claims, keyed by the shape of the year. Every variant is an arguable
# sentence carrying no statistic, per the house copy formula. Several are kept
# per situation because the copy is generated: a single line per situation would
# recur month after month, and "CVE growth has stopped looking like a spike"
# alone would have opened every post of 2026.
CLAIM_VARIANTS = {
    "passed_prior_year": [
        "Last year's record is no longer a ceiling, it is a midpoint.",
        "The annual CVE record now falls before most teams finish a roadmap.",
        "Beating last year's total stopped being news once it happened in summer.",
    ],
    "projected_pass": [
        "This is not a spike year, it is the floor the next one starts from.",
        "Last year's record already has an expiry date, and it lands this quarter.",
        "The question is no longer whether the record falls, but by how much.",
    ],
    "runaway": [
        "Growth this steep stops being a trend line and becomes a staffing problem.",
        "Nobody sized their vulnerability programme for this much volume.",
        "The intake problem has outgrown the tooling everyone bought to solve it.",
    ],
    "strong": [
        "CVE growth has stopped looking like a spike and started looking like the "
        "baseline.",
        "The surge everyone called temporary is now old enough to plan around.",
        "Treating this as an anomaly is getting harder to justify.",
    ],
    "steady": [
        "Steady growth is the harder problem, because nothing forces a reaction.",
        "An increase this size never triggers a budget conversation, and that is "
        "the danger.",
        "This is the growth rate that quietly breaks a process nobody revisits.",
    ],
    "slight": [
        "A small increase still compounds, and nobody staffs for compounding.",
        "The pace eased, which is exactly when teams stop paying attention.",
        "Slow growth is still growth, and the backlog does not reset in January.",
    ],
    "slower_month": [
        "One slower month is not a trend reversal.",
        "A quiet month says more about publishing schedules than about software.",
        "Reading a single month as a turning point is how forecasts go wrong.",
    ],
    "flat": [
        "Flat volume is not the same as a solved problem.",
        "Holding steady after years of growth is its own kind of signal.",
        "A plateau invites more complacency than a decline does.",
    ],
    "declining": [
        "The CVE curve is finally bending the other way.",
        "For once the numbers are moving the direction everyone wanted.",
        "A genuine decline deserves more scrutiny than a rise ever gets.",
    ],
}

# Closing questions, rotated on the same mechanism. A formulaic closer kills
# comments as surely as no closer at all.
QUESTION_VARIANTS = {
    "milestone": [
        "What breaks first when a record year becomes an average one?",
        "Are you planning next year against this year's numbers, or last year's?",
        "How far ahead can you plan when the baseline moves every year?",
    ],
    "growing": [
        "If this is the new baseline, what gives out first in your triage?",
        "What did you stop doing this year in order to keep up?",
        "Which part of your intake would break first if this pace held?",
    ],
    "flat": [
        "Does flat volume change how you plan for next quarter?",
        "Is steady better than shrinking, if the work lands the same?",
        "What would you do differently if this held for two more years?",
    ],
    "declining": [
        "Is this a real plateau, or just a quiet stretch?",
        "What would convince you a decline is real rather than seasonal?",
        "Would you re-staff on the strength of one down year?",
    ],
}


# Assigning-source identifiers are email addresses. These are the display names
# for the ones that publish at a volume worth naming in a post.
SOURCE_DISPLAY_NAMES = {
    "oracle.com": "Oracle",
    "github.com": "GitHub",
    "microsoft.com": "Microsoft",
    "google.com": "Google",
    "chromium.org": "Chrome",
    "apache.org": "Apache",
    "vuldb.com": "VulDB",
    "patchstack.com": "Patchstack",
    "wordfence.com": "Wordfence",
    "vulncheck.com": "VulnCheck",
    "mitre.org": "MITRE",
    "redhat.com": "Red Hat",
}

# A source or a single day at or above this share of the month is a batch, not a
# trend, and gets disclosed rather than left for a reader to discover.
CONCENTRATION_THRESHOLD = 0.10


class YTDAnalyzer:
    """Analyze year-to-date CVE growth patterns."""

    def __init__(self, data_file: Path):
        """
        Initialize YTD analyzer.

        Args:
            data_file: Path to NVD JSON data file
        """
        self.data_file = data_file
        self.current_year = datetime.now().year
        self._scan_cache: Optional[dict] = None
        # Set by the CLI once the output directory is known. Records which copy
        # variant each situation last used, so a repeat situation next month
        # picks the next line instead of the same one.
        self.history_file: Optional[Path] = None
        # One release is one story: post.txt and enriched_post.txt must open on
        # the same claim and close on the same question, so the choice is made
        # once per analyzer and reused rather than rotating between the two.
        self._copy_choice: Optional[tuple[str, str]] = None

    def _scan(self) -> dict:
        """One cached pass over the feed.

        Every figure this class publishes comes from the same records, so the
        feed is read once and counted at (year, month, day) granularity. Monthly
        counts, daily-of-year counts, per-year totals, and the all-time total are
        all derived from that. The file is about 1.6 GB, so the three separate
        passes this replaces cost three times as much for the same data.

        Returns:
            {"all_time": int, "yearly": Counter, "by_day": {year: Counter}}
        """
        if self._scan_cache is not None:
            return self._scan_cache

        all_time = 0
        yearly: Counter = Counter()
        by_day: dict = {}

        try:
            with open(self.data_file, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            self._scan_cache = {"all_time": 0, "yearly": Counter(), "by_day": {}}
            return self._scan_cache

        cves = data if isinstance(data, list) else data.get("CVE_Items", [])

        for cve in cves:
            try:
                cve_data = cve.get("cve", cve) if isinstance(cve, dict) else cve
                if not isinstance(cve_data, dict):
                    continue
                if cve_data.get("vulnStatus", "") == "Rejected":
                    continue

                date_str = (
                    cve_data.get("published")
                    or cve_data.get("datePublished")
                    or cve_data.get("date")
                )
                if not date_str:
                    continue

                cve_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                all_time += 1
                yearly[cve_date.year] += 1
                by_day.setdefault(cve_date.year, Counter())[
                    (cve_date.month, cve_date.day)
                ] += 1
            except (KeyError, ValueError, AttributeError):
                continue

        self._scan_cache = {
            "all_time": all_time,
            "yearly": yearly,
            "by_day": by_day,
        }
        return self._scan_cache

    def analyze_ytd(self) -> dict:
        """
        Analyze year-to-date CVE statistics.

        Returns:
            Dictionary with:
            - current_year_data: Month-by-month cumulative counts
            - previous_year_data: Last year's month-by-month cumulative counts
            - monthly_breakdown: Individual month counts
            - statistics: Growth rates and comparisons
        """
        # The current year's data necessarily stops at today. On a mid-month run
        # that leaves the reporting month partial, so the previous year has to be
        # cut at the same calendar point. Without this every year-over-year
        # figure compares a part-month against the prior year's whole month and
        # understates growth: through 2026-07-27 the 2025 baseline picked up an
        # extra four days, 27,426 instead of 26,928, turning +62.9% into +59.9%.
        now = datetime.now()
        through = None if now.day == 1 else (now.month, now.day)

        current_ytd = self._load_year_data(self.current_year)
        previous_ytd = self._load_year_data(self.current_year - 1, through=through)

        # Calculate cumulative totals
        current_cumulative = self._calculate_cumulative(current_ytd)
        previous_cumulative = self._calculate_cumulative(previous_ytd)

        # Calculate statistics
        stats = self._calculate_statistics(
            current_ytd, previous_ytd, current_cumulative, previous_cumulative
        )

        # Load daily data for chart plotting
        current_daily, previous_daily = self._load_daily_data()

        return {
            "current_year": self.current_year,
            "previous_year": self.current_year - 1,
            "current_year_data": current_ytd,
            "previous_year_data": previous_ytd,
            "current_cumulative": current_cumulative,
            "previous_cumulative": previous_cumulative,
            "current_daily_cumulative": current_daily,
            "previous_daily_cumulative": previous_daily,
            "statistics": stats,
        }

    def _load_year_data(
        self, year: int, through: Optional[tuple[int, int]] = None
    ) -> dict:
        """
        Month-by-month CVE counts for a year, from the cached feed scan.

        Args:
            year: Year to load data for
            through: Optional (month, day) cut-off. Records published after this
                point in the year are excluded, so a prior year can be compared
                against a partial current year over the same window.

        Returns:
            Dictionary mapping month number to CVE count
        """
        monthly_counts = {month: 0 for month in range(1, 13)}
        for (month, day), n in self._scan()["by_day"].get(year, {}).items():
            if through is not None and (month, day) > through:
                continue
            monthly_counts[month] += n
        return monthly_counts

    def _load_daily_data(self) -> tuple[dict, dict]:
        """
        Daily cumulative CVE counts for the current and previous year.

        Both years are truncated to the same day of the year, so the two plotted
        series always cover the same window.

        Returns:
            Tuple of (current_year_daily, previous_year_daily), each mapping
            day-of-year to a cumulative count.
        """
        current_year = self.current_year
        previous_year = current_year - 1
        by_day = self._scan()["by_day"]

        def doy_counts(year: int) -> Counter:
            counts: Counter = Counter()
            for (month, day), n in by_day.get(year, {}).items():
                try:
                    counts[date(year, month, day).timetuple().tm_yday] += n
                except ValueError:
                    continue  # e.g. Feb 29 recorded against a non-leap year
            return counts

        current_daily = doy_counts(current_year)
        previous_daily = doy_counts(previous_year)

        def to_cumulative(daily_counts: Counter, max_day: int) -> dict:
            cumulative = {}
            total = 0
            for day in range(1, max_day + 1):
                total += daily_counts.get(day, 0)
                cumulative[day] = total
            return cumulative

        today = datetime.now()
        if today.day == 1:
            # Reporting on the completed previous month.
            current_max = (today - today.replace(month=1, day=1)).days
        else:
            current_max = today.timetuple().tm_yday

        return (
            to_cumulative(current_daily, current_max),
            to_cumulative(previous_daily, current_max),
        )

    def _calculate_cumulative(self, monthly_data: dict) -> dict:
        """
        Calculate cumulative CVE counts from monthly data.

        Args:
            monthly_data: Dictionary mapping month to count

        Returns:
            Dictionary with cumulative counts by month
        """
        cumulative = {}
        total = 0

        for month in range(1, 13):
            total += monthly_data.get(month, 0)
            cumulative[month] = total

        return cumulative

    def _calculate_statistics(
        self,
        current_monthly: dict,
        previous_monthly: dict,
        current_cumulative: dict,
        previous_cumulative: dict,
    ) -> dict:
        """
        Calculate growth statistics and comparisons.

        Args:
            current_monthly: Current year monthly counts
            previous_monthly: Previous year monthly counts
            current_cumulative: Current year cumulative counts
            previous_cumulative: Previous year cumulative counts

        Returns:
            Dictionary with calculated statistics
        """
        # Get current YTD (up to the most recently completed month)
        today = datetime.now()
        if today.day == 1:
            # On the 1st we're reporting on the previous month
            current_month = 12 if today.month == 1 else today.month - 1
        else:
            current_month = today.month

        current_ytd_total = current_cumulative.get(current_month, 0)
        previous_ytd_total = previous_cumulative.get(current_month, 0)

        # Calculate growth rates
        yoy_growth = 0
        yoy_percent = 0
        if previous_ytd_total > 0:
            yoy_growth = current_ytd_total - previous_ytd_total
            yoy_percent = (yoy_growth / previous_ytd_total) * 100

        # Current month stats
        current_month_count = current_monthly.get(current_month, 0)
        previous_month_count = previous_monthly.get(current_month, 0)

        month_growth = 0
        month_percent = 0
        if previous_month_count > 0:
            month_growth = current_month_count - previous_month_count
            month_percent = (month_growth / previous_month_count) * 100

        # Daily average (days elapsed through the reporting period)
        if today.day == 1:
            # On the 1st, count days through end of previous month
            day_of_year = (today - today.replace(month=1, day=1)).days
        else:
            day_of_year = today.timetuple().tm_yday
        avg_per_day = current_ytd_total / day_of_year if day_of_year > 0 else 0

        stats = {
            "current_month": current_month,
            "current_ytd_total": current_ytd_total,
            "previous_ytd_total": previous_ytd_total,
            "yoy_growth": yoy_growth,
            "yoy_percent": yoy_percent,
            "current_month_count": current_month_count,
            "previous_month_count": previous_month_count,
            "month_growth": month_growth,
            "month_percent": month_percent,
            "avg_cves_per_day": avg_per_day,
        }
        month_days = calendar.monthrange(self.current_year, current_month)[1]
        stats.update(
            self._long_run_context(
                current_ytd_total,
                avg_per_day,
                current_month,
                month_rate=current_month_count / month_days if month_days else 0,
            )
        )
        return stats

    def _long_run_context(
        self,
        current_ytd_total: int,
        avg_per_day: float,
        through_month: int,
        month_rate: Optional[float] = None,
    ) -> dict:
        """All-time and prior-full-year context for the year to date.

        The rest of this class only ever compares the current year against the
        same point in the previous one, which cannot see the milestone that
        matters most: the year to date overtaking a prior year's *complete*
        total. Prior-year totals are deliberately not truncated, because "more
        than all of last year" is the claim being tested.
        """
        scan = self._scan()
        yearly = scan["yearly"]
        previous_year = self.current_year - 1
        previous_full = int(yearly.get(previous_year, 0))

        prior_totals = {
            int(year): int(yearly[year])
            for year in sorted(yearly)
            if year < self.current_year
        }
        recent = dict(list(prior_totals.items())[-PRIOR_YEARS_SHOWN:])

        # Count all-time through the same cut-off the rest of the release uses.
        # The raw scan total includes anything published after the reporting
        # month ended, which on the 1st means today's records sitting under a
        # "Data through July 31" footer.
        last_day = calendar.monthrange(self.current_year, through_month)[1]
        all_time = 0
        for year, days in scan["by_day"].items():
            if year < self.current_year:
                all_time += sum(days.values())
            else:
                all_time += sum(
                    n
                    for (month, day), n in days.items()
                    if (month, day) <= (through_month, last_day)
                )

        context: dict[str, Any] = {
            "all_time_total": int(all_time),
            "first_year_on_record": min(prior_totals) if prior_totals else None,
            "prior_year_totals": recent,
            "previous_year_full_total": previous_full,
            "passed_previous_year_total": bool(
                previous_full and current_ytd_total >= previous_full
            ),
        }

        remaining = previous_full - current_ytd_total
        if previous_full and remaining > 0 and avg_per_day > 0:
            context["cves_to_pass_previous_year"] = remaining

            # Count forward from the last day of data, not from today. The two
            # differ on the 1st, which is exactly when this runs.
            last_day = calendar.monthrange(self.current_year, through_month)[1]
            anchor = date(self.current_year, through_month, last_day)

            def project(rate: float, key: str) -> Optional[int]:
                if rate <= 0:
                    return None
                days = math.ceil(remaining / rate)
                landing = anchor + timedelta(days=days)
                if landing.year == self.current_year:
                    context[key] = f"{landing.strftime('%B')} {landing.day}"
                return days

            # The year's average is the conservative estimate; the reporting
            # month's own rate is the one consistent with a post about
            # acceleration. Publishing both makes the spread the story.
            days_at_average = project(avg_per_day, "projected_pass_date")
            if month_rate and month_rate > 0:
                project(month_rate, "projected_pass_date_at_month_rate")
                context["month_daily_rate"] = round(month_rate, 1)
            if days_at_average is not None:
                context["days_to_pass_previous_year"] = days_at_average

        return context

    def _history(self) -> dict:
        """Which variant each situation used last time."""
        if not self.history_file or not self.history_file.exists():
            return {}
        try:
            return json.loads(self.history_file.read_text())
        except (json.JSONDecodeError, IOError):
            return {}

    def _pick(self, pool: dict, key: str, history: dict) -> tuple[str, int]:
        """The next unused variant for a situation, and its index.

        Advances one step past whatever was used last time, so a situation that
        persists for months does not repeat its line. Deterministic: no history
        means the first variant, which keeps generated copy reproducible.
        """
        variants = pool[key]
        previous = history.get(key)
        index = 0 if previous is None else (int(previous) + 1) % len(variants)
        return variants[index], index

    @staticmethod
    def _situation(stats: dict, month_complete: bool = True) -> str:
        """Which claim bucket this month falls into.

        Banded rather than a single threshold: the old rule fired the same
        "stopped looking like a spike" branch for anything above 25 percent,
        which in a year running from 27 to 63 percent meant every single month.

        An in-progress month's change is a part-month against a whole one, so it
        does not get a vote on the framing.
        """
        # Only an achieved milestone takes the opening line. A *projected* one
        # was doing so too, and since a projection exists for most of a growing
        # year that starved every growth band below: runaway, strong, steady and
        # slight were unreachable. The projection still gets its own sentence in
        # the body, so nothing is lost by letting the band speak first.
        if stats.get("passed_previous_year_total"):
            return "passed_prior_year"
        # An imminent crossing is genuine news and earns the lead. A crossing
        # six months out is not, and used to take it anyway.
        days_out = stats.get("days_to_pass_previous_year")
        if days_out is not None and days_out <= 45:
            return "projected_pass"

        yoy = stats["yoy_percent"]
        month = stats["month_percent"] if month_complete else None

        if yoy < 0:
            return "declining"
        if yoy == 0:
            return "flat"
        if month is not None and month < 0:
            return "slower_month"
        if yoy >= 50:
            return "runaway"
        if yoy >= 25:
            return "strong"
        if yoy >= 10:
            return "steady"
        return "slight"

    @staticmethod
    def _question_bucket(stats: dict) -> str:
        """Which closing-question pool fits this month."""
        if stats.get("passed_previous_year_total") or stats.get("projected_pass_date"):
            return "milestone"
        yoy = stats["yoy_percent"]
        if yoy > 0:
            return "growing"
        if yoy < 0:
            return "declining"
        return "flat"

    def _choose_copy(self, stats: dict, month_complete: bool) -> tuple[str, str]:
        """The opening claim and closing question, rotated and recorded."""
        if self._copy_choice is not None:
            return self._copy_choice

        history = self._history()
        claim_key = self._situation(stats, month_complete)
        question_key = self._question_bucket(stats)

        # Rotation advances between releases, not between runs. Re-running a
        # month, which is what a workflow retry does, must reproduce the copy it
        # produced the first time rather than quietly picking a different line.
        release = f"{self.current_year}-{stats.get('current_month', 0):02d}"
        if history.get("_release") == release:
            claim_index = int(history.get(claim_key, 0))
            question_index = int(history.get("_questions", {}).get(question_key, 0))
            claim = CLAIM_VARIANTS[claim_key][
                claim_index % len(CLAIM_VARIANTS[claim_key])
            ]
            question = QUESTION_VARIANTS[question_key][
                question_index % len(QUESTION_VARIANTS[question_key])
            ]
            self._copy_choice = (claim, question)
            return self._copy_choice

        claim, claim_index = self._pick(CLAIM_VARIANTS, claim_key, history)
        question, question_index = self._pick(
            QUESTION_VARIANTS, question_key, history.get("_questions", {})
        )

        if self.history_file:
            history["_release"] = release
            history[claim_key] = claim_index
            history.setdefault("_questions", {})[question_key] = question_index
            try:
                self.history_file.parent.mkdir(parents=True, exist_ok=True)
                self.history_file.write_text(
                    json.dumps(history, indent=2, sort_keys=True)
                )
            except IOError:
                pass  # copy still works, it just will not rotate next month

        self._copy_choice = (claim, question)
        return self._copy_choice

    def _month_is_complete(self, analysis: dict) -> bool:
        """Whether the reporting month has actually finished.

        The scheduled run fires on the 1st, so the reporting month is normally the
        completed previous one. A manual mid-month run reports on the month still
        in progress, and the copy has to stop claiming it closed and stop quoting
        a change against the prior year's complete month.
        """
        now = datetime.now()
        return not (
            analysis["current_year"] == now.year
            and analysis["statistics"]["current_month"] == now.month
        )

    @staticmethod
    def _source_name(identifier: str) -> Optional[str]:
        """A postable name for an assigning-source identifier, if one is known."""
        if not identifier or "@" not in identifier:
            return None
        domain = identifier.rsplit("@", 1)[1].lower()
        for suffix, name in SOURCE_DISPLAY_NAMES.items():
            if domain == suffix or domain.endswith("." + suffix):
                return name
        return None

    def _concentration_line(self, monthly_report: dict, month_total: int) -> str:
        """Disclose a batch that is driving the month's headline.

        A quarterly release from one vendor lands as one source dominating one
        day. That is a batch, not a trend, and a reader who spots it unaided will
        discount the whole release, so it is stated first. Deliberately keyed on
        the biggest *day*, not the biggest publisher over the month: the largest
        publisher is usually just the most prolific one, and naming it here would
        pin a spike on whoever happens to publish continuously.
        """
        daily = (monthly_report or {}).get("daily") or {}
        count = daily.get("busiest_day_count")
        busiest = daily.get("busiest_day")
        if not (count and busiest and month_total):
            return ""
        if count / month_total < CONCENTRATION_THRESHOLD:
            return ""

        try:
            day = datetime.fromisoformat(str(busiest))
            label = f"{day.strftime('%B')} {day.day}"
        except ValueError:
            label = str(busiest)

        source_count = daily.get("busiest_day_top_source_count")
        name = self._source_name(str(daily.get("busiest_day_top_source") or ""))
        if name and source_count and source_count / count >= 0.5:
            return (
                f" {label} alone carried {int(count):,} of them, "
                f"{int(source_count):,} of those from {name}."
            )
        return f" {label} alone carried {int(count):,} of them."

    def get_summary_text(
        self, analysis: dict, monthly_report: Optional[dict] = None
    ) -> str:
        """
        Generate the social post text (also used as the GitHub release body).

        Follows the house copy formula: an arguable claim first, the load-bearing
        number second, no em dashes, and a genuine question to close.

        Args:
            analysis: Result from analyze_ytd()

        Returns:
            Formatted text summary for social posts
        """
        stats = analysis["statistics"]
        year = analysis["current_year"]
        current_month_name = datetime(year, stats["current_month"], 1).strftime("%B")
        previous_year = analysis["previous_year"]

        month_count = f"{stats['current_month_count']:,}"
        month_pct = f"{stats['month_percent']:+.1f}%"
        ytd_total = f"{stats['current_ytd_total']:,}"
        ytd_pct = f"{stats['yoy_percent']:+.1f}%"
        ytd_diff = f"{stats['yoy_growth']:+,}"
        avg_per_day = f"{stats['avg_cves_per_day']:.0f}"

        complete = self._month_is_complete(analysis)
        if complete:
            month_line = (
                f"{current_month_name} {year} closed at {month_count} published "
                f"CVEs against {stats['previous_month_count']:,} in "
                f"{current_month_name} {previous_year}, {month_pct}."
            )
        else:
            # Quoting a change here would compare a part-month against the prior
            # year's whole month.
            now = datetime.now()
            month_line = (
                f"{current_month_name} {year} is at {month_count} published CVEs "
                f"through {now.strftime('%B')} {now.day}, with the month still "
                f"running."
            )

        claim, question = self._choose_copy(stats, complete)

        return (
            f"{claim}\n\n"
            f"{month_line}\n\n"
            f"That puts {year} at {ytd_total} CVEs year to date, {ytd_pct} year over "
            f"year, and {avg_per_day} CVEs published a day so far this year."
            f"{self._concentration_line(monthly_report or {}, stats['current_month_count'])}"
            f"{self._milestone_line(stats, year, previous_year, current_month_name)}\n\n"
            f"{question}\n\n"
            f"Source: NVD, excluding rejected CVEs"
        )

    @staticmethod
    def _milestone_line(
        stats: dict, year: int, previous_year: int, month_name: str = ""
    ) -> str:
        """The prior-full-year comparison, when there is one worth stating.

        Returns a sentence to append, or an empty string. Kept to one sentence so
        it sharpens the paragraph instead of bloating it.
        """
        previous_full = stats.get("previous_year_full_total") or 0
        if not previous_full:
            return ""

        if stats.get("passed_previous_year_total"):
            surplus = stats["current_ytd_total"] - previous_full
            months_left = 12 - stats["current_month"]
            tail = (
                f" with {months_left} months still to run"
                if months_left > 0
                else " before the year is out"
            )
            return (
                f" {year} has now published more CVEs than the whole of "
                f"{previous_year} ({previous_full:,}), and is {surplus:+,} past it"
                f"{tail}."
            )

        projected = stats.get("projected_pass_date")
        if projected:
            remaining = stats["cves_to_pass_previous_year"]
            at_month = stats.get("projected_pass_date_at_month_rate")
            # Two rates, because they disagree and the spread is the point: the
            # year's average is the conservative read, the reporting month's own
            # pace is the one consistent with a post about acceleration.
            if at_month and at_month != projected:
                # One claim, true at both rates. Two dates three days apart
                # reads as declining to commit, and the reporting month's pace
                # can embed a batch the next month has no equivalent of.
                week = _week_of_month(at_month, projected)
                return (
                    f" All of {previous_year} came to {previous_full:,}. {year} "
                    f"passes it in another {remaining:,} CVEs, {week}."
                )
            return (
                f" All of {previous_year} came to {previous_full:,}, so at the "
                f"current rate {year} passes a full {previous_year} in another "
                f"{remaining:,} CVEs, around {projected}."
            )
        return ""

    def get_enriched_text(self, analysis: dict, monthly_report: dict) -> str:
        """
        Generate enriched social media post with CVSS and CWE context.

        Args:
            analysis: Result from analyze_ytd()
            monthly_report: Parsed monthly report JSON (the "data" dict)

        Returns:
            Formatted enriched text for social posts
        """
        stats = analysis["statistics"]
        current_month_name = datetime(
            analysis["current_year"], stats["current_month"], 1
        ).strftime("%B")
        previous_year = analysis["previous_year"]
        year = analysis["current_year"]

        month_count = f"{stats['current_month_count']:,}"
        month_pct = f"{stats['month_percent']:+.1f}%"
        ytd_total = f"{stats['current_ytd_total']:,}"
        ytd_pct = f"{stats['yoy_percent']:+.1f}%"
        avg_day = f"{stats['avg_cves_per_day']:.0f}"

        # Common CWE ID to short name mapping
        cwe_names = {
            "CWE-79": "XSS",
            "CWE-89": "SQL Injection",
            "CWE-862": "Missing Authorization",
            "CWE-22": "Path Traversal",
            "CWE-98": "PHP Remote File Inclusion",
            "CWE-74": "Injection",
            "CWE-787": "Out-of-bounds Write",
            "CWE-119": "Buffer Overflow",
            "CWE-863": "Incorrect Authorization",
            "CWE-918": "SSRF",
            "CWE-78": "OS Command Injection",
            "CWE-416": "Use After Free",
            "CWE-352": "CSRF",
            "CWE-200": "Information Exposure",
            "CWE-476": "NULL Pointer Dereference",
            "CWE-434": "Unrestricted Upload",
            "CWE-125": "Out-of-bounds Read",
            "CWE-502": "Deserialization",
            "CWE-77": "Command Injection",
            "CWE-400": "Resource Exhaustion",
            "CWE-94": "Code Injection",
            "CWE-306": "Missing Authentication",
            "CWE-284": "Improper Access Control",
            "CWE-287": "Improper Authentication",
            "CWE-269": "Improper Privilege Management",
            "CWE-522": "Insufficiently Protected Credentials",
            "CWE-798": "Hard-coded Credentials",
            "CWE-732": "Incorrect Permission Assignment",
            "CWE-611": "XXE",
            "CWE-190": "Integer Overflow",
            "CWE-770": "Allocation Without Limits",
            "CWE-1333": "Inefficient Regular Expression Complexity",
            "NVD-CWE-noinfo": "Not specified",
            "NVD-CWE-Other": "Other",
        }

        # Build CVSS line
        cvss_data = monthly_report.get("cvss", {})
        cvss_line = ""
        if cvss_data.get("median"):
            median = cvss_data["median"]
            p75 = cvss_data.get("percentile_75", "")
            cvss_line = f"\n\nMedian CVSS came in at {median}"
            if p75:
                cvss_line += f", with the 75th percentile at {p75}"
            cvss_line += "."

        # Build top CWEs
        cwe_data = monthly_report.get("cwe", {})
        top_cwes = cwe_data.get("top_cwes", {})
        cwe_lines = ""
        if top_cwes:
            items = list(top_cwes.items())[:5]
            cwe_lines = "\n\nMost frequently assigned weaknesses:\n"
            for cwe_id, count in items:
                # Unmapped ids render once, not as "CWE-284 (CWE-284)".
                name = cwe_names.get(cwe_id)
                label = f"{name} ({cwe_id})" if name else cwe_id
                cwe_lines += f"  {label}: {count:,}\n"
            cwe_lines = cwe_lines.rstrip("\n")

        complete = self._month_is_complete(analysis)
        if complete:
            month_clause = (
                f"{current_month_name} closed at {month_count} published CVEs, "
                f"{month_pct} against {current_month_name} {previous_year}, which "
                f"puts"
            )
        else:
            now = datetime.now()
            month_clause = (
                f"{current_month_name} is at {month_count} published CVEs through "
                f"{now.strftime('%B')} {now.day}, which puts"
            )

        claim, question = self._choose_copy(stats, complete)

        return (
            f"{claim}\n\n"
            f"{month_clause} "
            f"{year} at {ytd_total} year to date ({ytd_pct} year over year) and "
            f"{avg_day} CVEs published a day so far this year."
            f"{cvss_line}"
            f"{cwe_lines}"
            f"\n\n{question}"
            f"\n\nSource: NVD, excluding rejected CVEs"
            f"\n\n#CVE #VulnerabilityManagement #InfoSec"
        )


def _week_of_month(*dates: Optional[str]) -> str:
    """Phrase a projection as the week it lands in.

    Two projected dates a few days apart invite a reader to treat the spread as
    uncertainty about whether it happens at all. The week is the honest unit: it
    is true at either rate, and it commits.
    """
    days, month = [], None
    for value in dates:
        if not value:
            continue
        parts = str(value).split()
        if len(parts) == 2 and parts[1].isdigit():
            month = month or parts[0]
            days.append(int(parts[1]))
    if not days or not month:
        return "some time next month"
    ordinal = {1: "first", 2: "second", 3: "third", 4: "fourth", 5: "fifth"}
    weeks = {(day - 1) // 7 + 1 for day in days}
    if len(weeks) == 1:
        return f"in the {ordinal[weeks.pop()]} week of {month}"
    low, high = min(weeks), max(weeks)
    return f"between the {ordinal[low]} and {ordinal[high]} weeks of {month}"
