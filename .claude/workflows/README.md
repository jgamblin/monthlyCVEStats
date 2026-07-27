# Review workflows

## post-review

A pre-publish critical review of a monthly release: it verifies every number against
the raw NVD feed, pressure-tests the post copy, audits the report markdown, critiques
the rendered charts as images in both themes, and returns an editor-in-chief go/no-go
verdict with prioritized, concretely-worded fixes.

Ported from [CVEGraphs](../../../CVEGraphs/.claude/workflows/post-review.js). The
persona set is the same; the artifacts and data sources are this repo's.

### How to run

Ask Claude: **"run the post-review workflow on 2026"**. Claude invokes it with:

```
Workflow({ scriptPath: ".claude/workflows/post-review.js", args: "2026" })
```

`args` is the output year (defaults to `2026`). Run the pipeline first so the
artifacts exist and are current:

```bash
python -m src.cli.main run-monthly
python -m src.cli.main generate-ytd-report
python -m src.cli.main update-readme-stats
```

The fact-checker recomputes from `data/nvd.jsonl`, so that file has to be downloaded
(`download-data`) or the data findings will be worthless.

### The panel (13 agents)

1. **Prep** — reads `STYLE.md` as the source of truth for voice, the two post files,
   the newest month report, the chart list, and the README stats block, then extracts
   every load-bearing numeric claim.

Copy and data:

2. **factcheck** — independently recomputes every claim from `data/nvd.jsonl`. Runs
   explicit reconcile checks: severity bands must sum to scored CVEs, scored plus
   unscored must equal the total, per-day averages must divide by days actually
   elapsed, and the four artifacts must not contradict each other.
3. **domain-skeptic** — overclaims, causation-as-correlation, part-month compared to
   whole month, CNA counts read as vendor quality.
4. **brand-editor** — house style as written in `STYLE.md`, voice, hype.
5. **report-editor** — the report markdown as a published artifact: headings, number
   formatting, empty or missing sections, provenance honesty.
6. **consistency** — builds its own post history from the archive and catches
   contradictions between months and formulaic month-over-month repetition.
7. **audience-practitioner** — how it lands for a working analyst; "so what?".
8. **tone-reception** — hook, body tone, and closing question; harshness.
9. **punch-shareability** — opinion-first opening, buried hooks, and whether the
   code-selected claim and question sets are strong enough to carry a post every
   month without readers noticing the repetition.

Visual (these open and look at the PNGs):

10. **dataviz-craft** — Tufte lens on the wide chart and the YoY bars: honest
    encoding, axes, like-for-like comparison window, the annotated gap.
11. **legibility-design** — typography, hierarchy, collisions, spacing across all
    three aspect ratios, since they share one layout system.
12. **color-accessibility** — both themes, color-blind safety, contrast, grayscale,
    theme parity. The dark palette is newer than the light one and gets the hardest
    look.

13. **editor-in-chief** — dedupes, dismisses reviewer overreach, and returns COPY,
    REPORT + README, and GRAPH verdicts with exact-wording fixes. It also separates
    findings that are defects in the **generator** from one-off problems in this
    month's output, because the generators run unattended every month.

### Tuning

Personas are plain lists in the script (`COPY` and `VISUAL`); add or drop lenses as
needed. To iterate, edit `post-review.js` and re-run with the same `scriptPath`.
