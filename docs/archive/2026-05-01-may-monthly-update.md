# May 1st Monthly CVE Update (April 2026 Data) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the monthly CVE statistics pipeline to generate the April 2026 report, YTD visualizations, and update the README — mirroring what the GitHub Actions workflow does on the 1st of each month.

**Architecture:** The pipeline is sequential: download NVD data (~1.3 GB JSONL) → run monthly analysis (filters to April 2026) → generate YTD charts and social post text → update README stats → validate → commit and push.

**Tech Stack:** Python 3.11, Typer CLI, Pandas, Matplotlib, GitHub Actions (for the automated path)

---

## Context

- Today is May 1st 2026. `Config.get_current_month_info()` returns `(2026, 4)` — April.
- Last run produced March 2026 outputs in `outputs/2026/March/`.
- No local `data/nvd.jsonl` exists — it must be downloaded fresh.
- The GitHub Actions workflow (`monthly-update.yml`) runs at 13:00 UTC on the 1st, but we're executing locally to review before the automated run or to replace it.

## Expected Outputs

After a successful run, these files should exist:

```
outputs/2026/April/April.md          # Monthly markdown report
outputs/2026/April/April.json        # Monthly JSON report
outputs/2026/post.txt                # Social media summary (overwrites March)
outputs/2026/enriched_post.txt       # Enriched post with CVSS/CWE context
outputs/2026/CVE_Growth_2026_dark_landscape.png
outputs/2026/CVE_Growth_2026_dark_square.png
outputs/2026/CVE_Growth_2026_light_landscape.png
outputs/2026/CVE_Growth_2026_light_square.png
outputs/2026/YOY_CVE_Comparison_2026_vs_2025.png
README.md                            # Updated stats badge and table
```

---

### Task 1: Install Dependencies

**Files:**

- Read: `requirements.txt`

- [ ] **Step 1: Install Python dependencies**

```bash
pip install -r requirements.txt
```

Expected: All packages install successfully (typer, pandas, matplotlib, etc.)

- [ ] **Step 2: Verify CLI is accessible**

```bash
python -m src.cli.main --help
```

Expected: Shows help text with commands: `download-data`, `run-monthly`, `generate-reports`, `generate-ytd-report`, `update-readme-stats`, `validate`, `check-timezone`

---

### Task 2: Download NVD Data

**Files:**

- Writes: `data/nvd.jsonl` (~1.3 GB)

- [ ] **Step 1: Download latest NVD data**

```bash
python -m src.cli.main download-data
```

Expected: Progress bar, download completes, verification passes. Log line: `✓ NVD data downloaded and verified successfully`

This takes several minutes due to the ~1.3 GB file size. The downloader supports resume (`--resume` is on by default) if interrupted.

- [ ] **Step 2: Verify the data file exists and has reasonable size**

```bash
ls -lh data/nvd.jsonl
```

Expected: File exists, size ~1.3 GB.

---

### Task 3: Run Monthly Analysis (April 2026)

**Files:**

- Read: `data/nvd.jsonl`
- Writes: `outputs/2026/April/April.md`, `outputs/2026/April/April.json`

- [ ] **Step 1: Run the monthly analysis pipeline**

```bash
python -m src.cli.main run-monthly
```

Expected: Log output showing:

- `Analyzing CVE data for 2026-04` (confirms April)
- `Loaded XXXX CVE records` (some thousands)
- `✓ Analysis complete: XXXX CVEs processed`
- `✓ Reports written to .../outputs/2026/April`

- [ ] **Step 2: Verify report files were created**

```bash
ls -la outputs/2026/April/
cat outputs/2026/April/April.md | head -30
```

Expected: Both `April.md` and `April.json` exist with non-trivial content. The markdown report should show April 2026 data with CVSS distribution, CNA rankings, and CWE analysis.

---

### Task 4: Generate YTD Report and Visualizations

**Files:**

- Read: `data/nvd.jsonl`, `outputs/2026/April/April.json`
- Writes: `outputs/2026/post.txt`, `outputs/2026/enriched_post.txt`, 5x PNG charts

- [ ] **Step 1: Generate YTD growth report**

```bash
python -m src.cli.main generate-ytd-report
```

Expected: Log output showing:

- `YTD Analysis: XXXXX CVEs` (cumulative through April)
- `Creating YTD growth charts...`
- `✓ Summary saved to .../outputs/2026/post.txt`
- `✓ Enriched post saved to .../outputs/2026/enriched_post.txt`
- `✓ YTD report generated in .../outputs/2026`

- [ ] **Step 2: Verify all chart files and text files were created/updated**

```bash
ls -la outputs/2026/*.png outputs/2026/*.txt
```

Expected: 5 PNG files and 2 TXT files. All should have today's date as modification time.

- [ ] **Step 3: Review the social post text**

```bash
cat outputs/2026/post.txt
```

Expected: Summary like "April 2026 CVE Growth Report:" with YTD totals, daily average, YoY comparison, and April-specific stats. Should reference April (not March).

- [ ] **Step 4: Spot-check a chart visually**

Open one of the PNG files to confirm it renders correctly and shows data through April (4 months).

```bash
open outputs/2026/CVE_Growth_2026_dark_landscape.png
```

Expected: Chart shows 2026 vs 2025 cumulative CVE growth through April with daily granularity and stat cards.

---

### Task 5: Update README Statistics

**Files:**

- Modify: `README.md` (stats badge and table)

- [ ] **Step 1: Update README with latest statistics**

```bash
python -m src.cli.main update-readme-stats
```

Expected: `✓ README updated successfully`

- [ ] **Step 2: Verify README changes**

```bash
git diff README.md
```

Expected: The "Data Updated" badge date changes from "March 29, 2026" to today's date. The statistics table (Total CVEs, Average CVEs/Day, Average CVSS Score) updates with April numbers.

---

### Task 6: Validate Pipeline

**Files:**

- Read: `data/nvd.jsonl`, config

- [ ] **Step 1: Run validation**

```bash
python -m src.cli.main validate
```

Expected: `✓ Validation complete` with config details and NVD data file size.

---

### Task 7: Review and Commit

**Files:**

- All changed files in `outputs/` and `README.md`

- [ ] **Step 1: Review all changes**

```bash
git status
git diff --stat
```

Expected: New files in `outputs/2026/April/`, modified files in `outputs/2026/` (PNGs, TXTs), and modified `README.md`. No unexpected changes.

- [ ] **Step 2: Stage and commit**

```bash
git add outputs/ README.md
git commit -m "Monthly CVE Update - 2026-05-01"
```

- [ ] **Step 3: Push to remote**

```bash
git push
```

---

### Task 8: Create GitHub Release

- [ ] **Step 1: Create a GitHub release with the April report artifacts**

```bash
gh release create cve-update-April-2026 \
  --title "April 2026 CVE Report" \
  --notes-file outputs/2026/post.txt \
  outputs/2026/April/* \
  outputs/2026/*.png \
  outputs/2026/post.txt \
  outputs/2026/enriched_post.txt
```

Expected: Release created at `https://github.com/jgamblin/monthlyCVEStats/releases/tag/cve-update-April-2026`

---

## Quick-Run Alternative

If you trust the pipeline and want to run everything in one shot (mirroring the CI workflow):

```bash
pip install -r requirements.txt
python -m src.cli.main download-data
python -m src.cli.main run-monthly
python -m src.cli.main generate-ytd-report
python -m src.cli.main update-readme-stats
python -m src.cli.main validate
git add outputs/ README.md
git commit -m "Monthly CVE Update - 2026-05-01"
git push
gh release create cve-update-April-2026 \
  --title "April 2026 CVE Report" \
  --notes-file outputs/2026/post.txt \
  outputs/2026/April/* outputs/2026/*.png outputs/2026/post.txt outputs/2026/enriched_post.txt
```
