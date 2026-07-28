"""
Year-to-Date (YTD) CVE growth analysis and comparison.

Generates comprehensive YTD statistics including:
- Cumulative CVE counts by month
- Growth rates (month-over-month and year-over-year)
- Comparison with previous year
- Daily and monthly averages
"""

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
        "This year stops being a trend and starts being the new floor.",
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
        stats.update(self._long_run_context(current_ytd_total, avg_per_day))
        return stats

    def _long_run_context(self, current_ytd_total: int, avg_per_day: float) -> dict:
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

        context: dict[str, Any] = {
            "all_time_total": int(scan["all_time"]),
            "first_year_on_record": min(prior_totals) if prior_totals else None,
            "prior_year_totals": recent,
            "previous_year_full_total": previous_full,
            "passed_previous_year_total": bool(
                previous_full and current_ytd_total >= previous_full
            ),
        }

        remaining = previous_full - current_ytd_total
        if previous_full and remaining > 0 and avg_per_day > 0:
            days_needed = int(remaining / avg_per_day) + 1
            context["cves_to_pass_previous_year"] = remaining
            context["days_to_pass_previous_year"] = days_needed
            # Only a projection, and only worth stating while it lands this year.
            projected = datetime.now() + timedelta(days=days_needed)
            if projected.year == self.current_year:
                context["projected_pass_date"] = (
                    f"{projected.strftime('%B')} {projected.day}"
                )

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
        if stats.get("passed_previous_year_total"):
            return "passed_prior_year"
        if stats.get("projected_pass_date"):
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

        claim, claim_index = self._pick(CLAIM_VARIANTS, claim_key, history)
        question, question_index = self._pick(
            QUESTION_VARIANTS, question_key, history.get("_questions", {})
        )

        if self.history_file:
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

    def get_summary_text(self, analysis: dict) -> str:
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
                f"CVEs, {month_pct} against {current_month_name} {previous_year}."
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
            f"year, and {avg_per_day} new CVEs every day."
            f"{self._milestone_line(stats, year, previous_year)}\n\n"
            f"{question}\n\n"
            f"Source: NVD, excluding rejected CVEs"
        )

    @staticmethod
    def _milestone_line(stats: dict, year: int, previous_year: int) -> str:
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
            f"{avg_day} new CVEs every day."
            f"{cvss_line}"
            f"{cwe_lines}"
            f"\n\n{question}"
            f"\n\nSource: NVD, excluding rejected CVEs"
            f"\n\n#CVE #VulnerabilityManagement #InfoSec"
        )
