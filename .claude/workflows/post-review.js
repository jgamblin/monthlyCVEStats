export const meta = {
  name: 'post-review',
  description: 'Deep persona review of a monthly CVE release: verify every number against the raw feed, pressure-test the post copy for accuracy, reception and punch, audit the report markdown, and critique the rendered charts in both themes, then synthesize a go/no-go verdict',
  whenToUse: 'Before publishing a monthly release, or after changing the generators. Pass the output year as args, e.g. args: "2026".',
  phases: [
    { title: 'Prep', detail: 'read STYLE.md, post copy, report markdown, find the charts, extract claims' },
    { title: 'Review', detail: 'copy (accuracy + domain + brand + reception + punch), report, and visual personas in parallel' },
    { title: 'Synthesize', detail: 'editor-in-chief verdict and prioritized fixes' },
  ],
}

// ---- input ---------------------------------------------------------------
const year = (typeof args === 'string' && args.trim())
  ? args.trim()
  : (args && args.year) ? String(args.year) : '2026'

const outDir = `outputs/${year}`

// Reusable finding shape so every persona reports the same way.
const FINDINGS_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['findings', 'keep'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['severity', 'element', 'problem', 'fix'],
        properties: {
          severity: { type: 'string', enum: ['blocker', 'should-fix', 'nice-to-have'] },
          element: { type: 'string', description: 'exact phrase, number, or visual element at fault' },
          problem: { type: 'string' },
          fix: { type: 'string', description: 'concrete replacement wording or design change' },
        },
      },
    },
    keep: { type: 'string', description: 'one honest thing that already works and should not change' },
    overall: { type: 'string', description: 'optional: a one-line overall read from this lens' },
  },
}

// ---- Phase 1: prep -------------------------------------------------------
phase('Prep')
const prep = await agent(
  `You are prepping a review packet for the monthlyCVEStats release in ${outDir}.\n` +
  `1. Read STYLE.md at the repo root and return its rules verbatim in "houseStyle" (this is the ` +
  `single source of truth for voice; do not paraphrase from memory).\n` +
  `2. Read ${outDir}/post.txt and ${outDir}/enriched_post.txt.\n` +
  `3. Identify the month the release reports on, then read that month's report markdown: run ` +
  `\`ls -t ${outDir}/*/[A-Z]*.md | head -1\` and read the result. Return its path in "reportPath" ` +
  `and its full text in "reportMarkdown".\n` +
  `4. List the chart PNGs: \`ls ${outDir}/*.png\`. Return them in "charts".\n` +
  `5. Read the stats block between the STATS:START and STATS:END markers in README.md and return it ` +
  `in "readmeBlock".\n` +
  `6. List every load-bearing factual or numeric claim across the post copy, the report, the README ` +
  `block, and the chart text (each as one short string a fact-checker could independently recompute, ` +
  `e.g. "July 2026 published 8,012 CVEs through July 27").\n` +
  `Return JSON. If a field is missing, return an empty string / empty list for it.`,
  { phase: 'Prep', label: `prep:${year}`, schema: {
    type: 'object', additionalProperties: false,
    required: ['houseStyle', 'post', 'enriched', 'reportPath', 'reportMarkdown', 'charts', 'readmeBlock', 'claims'],
    properties: {
      houseStyle: { type: 'string' },
      post: { type: 'string' },
      enriched: { type: 'string' },
      reportPath: { type: 'string' },
      reportMarkdown: { type: 'string' },
      charts: { type: 'array', items: { type: 'string' } },
      readmeBlock: { type: 'string' },
      claims: { type: 'array', items: { type: 'string' } },
    } } }
)

const charts = (prep.charts || []).filter(Boolean)
const pick = (want) => charts.find(c => want.every(w => c.includes(w))) || ''
const wideLight = pick(['light', 'landscape']) || charts[0] || `${outDir}/CVE_Growth_${year}_light_landscape.png`
const squareDark = pick(['dark', 'square']) || wideLight
const portraitLight = pick(['light', 'portrait']) || wideLight
const yoyChart = charts.find(c => c.includes('YOY')) || ''

const packet = JSON.stringify(prep, null, 2)

const DATA_NOTE =
  `DATA SOURCES for independent recomputation, in this repo:\n` +
  `- data/nvd.jsonl is the raw NVD feed: a single JSON array, about 1.6 GB. json.load() on it takes ` +
  `roughly 20 seconds and a few GB of RAM, which is fine. Each record has cve.id, cve.published, ` +
  `cve.vulnStatus, cve.sourceIdentifier, cve.metrics.cvssMetricV31/V30[0].cvssData.baseScore, and ` +
  `cve.weaknesses[].description[].value.\n` +
  `- ALWAYS exclude records where cve.vulnStatus == "Rejected", which is what the pipeline does.\n` +
  `- src/data/processor.py (DataProcessor.load_to_dataframe) and src/analysis/ytd_growth.py ` +
  `(YTDAnalyzer.analyze_ytd) are the production loaders; you may import and use them, but prefer at ` +
  `least one number recomputed independently with your own script so you are not just re-running the ` +
  `code that produced the claim.\n` +
  `- The committed report JSONs under ${outDir}/*/ are the pipeline's own output. Treat them as claims ` +
  `to verify, not as ground truth.\n` +
  `- Today is 2026-07-27, so July 2026 is an INCOMPLETE month: 27 days of data, not 31. Any per-day ` +
  `average for July must divide by 27.`

// ---- Phase 2: review panel ----------------------------------------------
const COPY = [
  { key: 'factcheck', prompt:
    `You are a hostile DATA FACT-CHECKER. For EACH claim in the packet, independently recompute it ` +
    `from source using Bash and python in this repo. Report any claim that is wrong, rounded ` +
    `misleadingly, or unsupported, giving the value you computed versus the value stated. A ` +
    `confirmed-correct number is NOT a finding.\n` +
    `${DATA_NOTE}\n` +
    `RECONCILE CHECKS (treat a failure as a BLOCKER):\n` +
    `(a) the severity distribution in the report must sum to the "Scored CVEs" count;\n` +
    `(b) "Scored CVEs" + "Unscored CVEs" must equal "Total CVEs";\n` +
    `(c) the CVEs-by-month table must sum to a year-to-date total consistent with the post copy;\n` +
    `(d) any per-day average must equal the total divided by the number of days actually elapsed;\n` +
    `(e) any percentage change must match the two underlying counts.\n` +
    `Also check the two post files and the README block do not state numbers that CONTRADICT each ` +
    `other or the report for the same quantity.` },
  { key: 'domain-skeptic', prompt:
    `You are a hostile DOMAIN SKEPTIC (senior vuln-management / detection engineer). Attack the ` +
    `technical framing and any overclaim: causation dressed as correlation, "most/every/always" the ` +
    `data does not support, survivorship bias, or a takeaway that contradicts how practitioners ` +
    `actually triage. Two specific traps in a monthly CVE report: (1) comparing a PART-month against ` +
    `a complete month as if they were comparable, and (2) treating a CNA identifier count as a ` +
    `statement about vulnerability quality or vendor behaviour. Be specific about which sentence ` +
    `overreaches.` },
  { key: 'brand-editor', prompt:
    `You are a ruthless COPY EDITOR and brand-risk reviewer for a security audience. Enforce the ` +
    `house style given in the packet's "houseStyle" field exactly as written, and treat any violation ` +
    `of it as at least a should-fix. Hunt: em dashes, "n=", decorative glyph bullets, bloat, hype, ` +
    `hedging, unfair shots at a vendor, missing thousands separators, and whether the post ends on a ` +
    `question. Suggest tighter wording only where it clearly improves the copy.` },
  { key: 'report-editor', prompt:
    `You are the REPORT EDITOR reviewing the monthly report markdown at ${prep.reportPath} (its full ` +
    `text is in the packet as "reportMarkdown"). This is a published artifact, so judge it as a ` +
    `reader would: are the section headings meaningful English rather than internal analysis keys; ` +
    `are numbers formatted for a human (thousands separators, sensible precision); is any value ` +
    `rendered in a way that misleads (a year with a thousands separator, a raw pandas period code, a ` +
    `bare identifier where a name belongs, a CVSS score shown as an integer); is any section present ` +
    `but empty, or absent when it should be there; does the provenance line state the real coverage ` +
    `including whether the month is complete. Quote the exact line for each finding.` },
  { key: 'consistency', prompt:
    `You are the SERIES EDITOR guarding against contradiction across the archive. This repo has no ` +
    `post-history log, so build one: list the prior monthly reports with ` +
    `\`ls ${outDir}/*/[A-Z]*.md\` plus any earlier years under outputs/, and read two or three of ` +
    `them. Flag if this release contradicts an earlier month's figure for the same quantity, if the ` +
    `same hook or claim is being recycled verbatim month over month (the copy is generated, so a ` +
    `formulaic repeat is a real risk worth naming), or if a number restated across post.txt, ` +
    `enriched_post.txt, the report, and the README block disagrees. Name the specific prior report ` +
    `you are comparing against.` },
  { key: 'audience-practitioner', prompt:
    `You are a SKEPTICAL WORKING PRACTITIONER in Jerry's feed (SOC analyst / vuln-management lead / ` +
    `detection engineer) reading this on LinkedIn between meetings. Judge how the post LANDS, not its ` +
    `style: does it tell you something useful you can act on or share, or does it read as stating the ` +
    `obvious, as trivia with no "so what", or as scolding you for how you do your job? Flag lines ` +
    `that feel condescending, preachy, fear-mongering, or that assume the reader is doing it wrong. ` +
    `Flag if the takeaway does not survive a "so what?". Put your one-line gut read of how it lands ` +
    `in "overall". Report only real reception risks, not style nits.` },
  { key: 'tone-reception', prompt:
    `You are an AUDIENCE-RECEPTION and tone reviewer. A post from a 10k-follower researcher should ` +
    `invite good-faith discussion, not dunk, moralize, humblebrag, or bait outrage. Assess three ` +
    `things and cite the exact phrase for each: (1) the HOOK, does it respect the reader or open by ` +
    `implying they are behind; (2) the BODY tone, generous and curious versus lecturing or doom; ` +
    `(3) the CLOSING question, a genuine open question people want to answer, or a rhetorical one ` +
    `that just performs a point. For each, give a warmer wording that keeps the substance and punch. ` +
    `Put an overall harshness read (warm / neutral / harsh, and why in a few words) in "overall".` },
  { key: 'punch-shareability', prompt:
    `You are a PUNCH & SHAREABILITY editor. Reach and comments come from posts that make an ARGUABLE ` +
    `claim, not ones that merely state a fact. Assess and cite the exact phrase for each:\n` +
    `(1) OPENING LINE, the most important check: the first sentence MUST be a one-sentence opinion a ` +
    `reasonable person could DISAGREE with. A statistic or a date as the opener is a BLOCKER. Could a ` +
    `reader argue with sentence one? If not, fail it and give a rewritten opinion-first line.\n` +
    `(2) FORMULAIC RISK, specific to this repo: the opening claim and closing question are SELECTED BY ` +
    `CODE from a small fixed set (see _opening_claim and _closing_question in ` +
    `src/analysis/ytd_growth.py, which you should read). Judge whether that set is strong enough to ` +
    `carry a post every single month, or whether readers will notice the same sentence recurring. ` +
    `Name the weakest line in the set and propose a better one.\n` +
    `(3) BURIED HOOK, is the claim smothered by caveats? Hold caveats to about one line.\n` +
    `(4) CLOSING QUESTION, must be genuine and specific. Do NOT recommend dropping it.\n` +
    `Put a one-line shareability read (would a peer repost this? yes/no and why) in "overall".` },
]

const VISUAL = [
  { key: 'dataviz-craft', prompt:
    `You are a hostile DATA-VISUALIZATION critic in the Tufte tradition. OPEN AND LOOK AT the chart ` +
    `at ${wideLight} using the Read tool` + (yoyChart ? `, and also ${yoyChart}` : '') + `. Judge ` +
    `whether the chart form is the clearest honest encoding: chart-junk, misleading axes, truncated ` +
    `baselines, redundant encodings, poor sorting, or a better chart type. Pay particular attention ` +
    `to whether the two plotted years are compared over a like-for-like window, and whether the ` +
    `annotated gap between the series is measured and labelled honestly. Only raise issues visible ` +
    `in the actual image.` },
  { key: 'legibility-design', prompt:
    `You are a meticulous VISUAL DESIGNER judging whether this looks professionally made. OPEN AND ` +
    `LOOK AT ${wideLight}, then ${portraitLight}, then ${squareDark} (Read tool on each). Scrutinize ` +
    `in every one: title and subtitle hierarchy, typography and font sizes, label collisions or ` +
    `truncation, alignment, spacing and margins, legend placement, overlapping elements, stat-card ` +
    `layout, and overall polish. The three aspect ratios share one layout system, so specifically ` +
    `flag anything that works at one ratio but breaks at another (text overrunning a card, a footer ` +
    `line colliding with axis labels, cramped margins). ALSO read the visible TEXT as a designer ` +
    `would: inconsistent capitalization, orphan sub-labels, labels not parallel in structure, ` +
    `awkward truncation. Every visible string should look deliberate. Point to the exact element.` },
  { key: 'color-accessibility', prompt:
    `You are an ACCESSIBILITY and color reviewer. OPEN AND LOOK AT both themes: ${wideLight} (light) ` +
    `and ${squareDark} (dark), using the Read tool on each. The dark palette is NEW and has had no ` +
    `review, so scrutinize it hardest. Check in each: color-blind safety ` +
    `(deuteranopia/protanopia), contrast of text and marks against the background, whether the chart ` +
    `still reads in grayscale, palette consistency, and whether the red series is justified as a ` +
    `single deliberate highlight rather than an alarm. Compare the two themes for parity: any element ` +
    `legible in one and marginal in the other is a finding. Flag legibility risks at social-feed ` +
    `thumbnail size.` },
]

phase('Review')
const reviews = await parallel(
  [...COPY, ...VISUAL].map(p => () =>
    agent(
      `${p.prompt}\n\nREVIEW PACKET for ${outDir}:\n${packet}\n\n` +
      `Be adversarial but HONEST: report only real issues, no manufactured nitpicks. For each finding ` +
      `give severity, the exact element/phrase/visual at fault, why it is wrong or weak, and a ` +
      `concrete fix. Also give one honest "keep this" note.`,
      { phase: 'Review', label: `review:${p.key}`, schema: FINDINGS_SCHEMA }
    ).then(r => ({ persona: p.key, ...r }))
  )
)

// ---- Phase 3: editor-in-chief synthesis ----------------------------------
phase('Synthesize')
const verdict = await agent(
  `You are the EDITOR-IN-CHIEF making the final call before the ${year} monthly CVE release is ` +
  `published by a well-known CVE-data researcher (10k+ followers). The release comprises the post ` +
  `copy, the monthly report markdown, the README stats block, and the chart set. Below are the ` +
  `packet and every reviewer's findings.\n\n` +
  `PACKET:\n${packet}\n\nREVIEWS:\n${JSON.stringify(reviews.filter(Boolean), null, 2)}\n\n` +
  `Synthesize decisively:\n` +
  `1. Deduplicate overlapping findings. Separate TRUE defects from reviewer overreach and explicitly ` +
  `dismiss the manufactured nitpicks, saying which and why.\n` +
  `2. COPY verdict: a prioritized fix list (blocker / should-fix / nice-to-have) with EXACT ` +
  `replacement wording, then one of POST AS-IS / POST WITH FIXES / REWORK.\n` +
  `3. REPORT + README verdict: the same, for the report markdown and the stats block.\n` +
  `4. GRAPH verdict: the same, for the charts, then one of SHIP AS-IS / FIX FIRST / REWORK. Only ` +
  `include design changes that genuinely raise the professional quality.\n` +
  `5. Lead with the single biggest risk in one sentence.\n` +
  `6. Separately flag any finding that is a defect in the GENERATOR rather than in this month's ` +
  `output, since the generators run unattended every month: a wording or layout problem that will ` +
  `recur is worth more than a one-off. Name the file to change.\n` +
  `TREAT PUNCH AS A FIRST-CLASS DIMENSION, equal to accuracy: a factually perfect but BLAND post is ` +
  `a real defect, not a pass. A number-first opening line is a blocker, a hook buried under caveats ` +
  `is a should-fix, and a missing or statement-only ending is a should-fix. When accuracy or tone ` +
  `conflicts with punch, do NOT resolve it by hedging the claim away or dropping the question; find ` +
  `wording that keeps BOTH the rigor and the edge. Never recommend removing the closing question.\n` +
  `Be concrete and ruthless about priority; most releases should need only a few real changes.`,
  { phase: 'Synthesize', label: 'editor-in-chief', effort: 'high' }
)

return verdict
