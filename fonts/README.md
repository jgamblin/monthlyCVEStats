# Bundled fonts

Charts render inside GitHub Actions, so the typefaces ship with the repo. Without
them matplotlib falls back to DejaVu Sans without raising, and every monthly chart
goes out in the wrong face. `src/reports/style.py` logs a warning if any file
below is missing.

| File | Family | Used for | License |
|------|--------|----------|---------|
| `HostGrotesk.ttf` | Host Grotesk Light (LMNT) | Headlines | [SIL OFL 1.1](LICENSE-OFL-1.1.txt) |
| `Roboto-Regular.ttf` | Roboto (Google) | Body, axis labels | [Apache 2.0](LICENSE-Apache-2.0.txt) |
| `Roboto-Bold.ttf` | Roboto Bold (Google) | Subtitles, emphasis | [Apache 2.0](LICENSE-Apache-2.0.txt) |
| `RobotoMono.ttf` | Roboto Mono (Google) | CVE ids, eyebrow, date stamp | [SIL OFL 1.1](LICENSE-OFL-1.1.txt) |

License assignments were read from each file's own `name` table (entries 13 and
14), not inferred. The two license documents are the canonical upstream texts.

Same set as [CVEGraphs](../../CVEGraphs/fonts), so charts from either repo sit
together in a feed.
