# repo-triage

> The files under `demo/` are intentionally vulnerable examples used to test the tool. Do not use them in production.

Run [Semgrep](https://semgrep.dev) across many repositories, merge duplicate findings, score what is
left, and get a prioritized report. Built to answer the question AppSec teams actually face at scale:
**"Out of 2,000 findings, what should we look at first?"**

## What it does

1. **Scans many repos in parallel** (explicit paths, or every git repo inside a folder).
2. **De-duplicates** in two steps:
   - drops exact repeats (same rule, file and lines, e.g. from overlapping rulesets);
   - merges the *same rule on the same code* across files and repos (copy-pasted bugs become one
     finding that lists every place it appears).
3. **Prioritizes** every finding with a transparent 0-100 score, then bands it Critical / High /
   Medium / Low:

   | Signal | Effect |
   |---|---|
   | Semgrep severity | base score (ERROR 60, WARNING 35, INFO 10) |
   | Rule confidence | multiplier (HIGH 1.0, MEDIUM 0.8, LOW 0.5) |
   | Dangerous CWE (SQLi, command injection, deserialization, hard-coded creds, ...) | bonus up to +15 |
   | Same pattern in several places | small capped bonus (it is systemic) |
   | Path is tests / docs / examples / vendor | score x 0.3 |

   Everything is in constants at the top of `triage.py`, so you can tune it to your own risk model.
4. **Reports** to `report.md` (human readable) and `results.json` (for dashboards or tickets).
5. **Baseline mode** marks only findings that are new since a previous run.
6. **CI friendly**: `--fail-on High` exits 1 if anything at that priority exists.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Try the demo (two tiny intentionally vulnerable repos, offline custom rules)
python triage.py demo/repo-a demo/repo-b --config rules/

# Real use
python triage.py --scan-dir ~/code --config p/default --config p/owasp-top-ten
```

Open `triage-output/report.md`. A sample is in `sample-output/`.

### Useful options

```
--config RULESET        Semgrep config, repeatable (default: p/default). Local folders work too.
--from-json FILE...     Use existing `semgrep --json` output instead of running Semgrep
--baseline OLD.json     Mark only NEW findings versus a previous results.json
--fail-on High          Exit 1 if any finding is High or above (CI gate)
--min-band Medium       Hide anything below Medium
--hide-low-value        Drop findings in tests/docs/vendor paths entirely
--top 20                How many findings to detail in the report
```

Exit codes: `0` ok, `1` a finding met `--fail-on`, `2` nothing to scan, `3` some repo failed to scan.

## Design notes and limitations

- Semgrep OSS often hides matched code in its JSON, so the tool reads the flagged lines from disk
  to fingerprint duplicates. With `--from-json` there is no repo on disk, so it falls back to
  location-based grouping when Semgrep does not provide the code.
- Semgrep skips folders like `tests/` and `node_modules/` by default. The "low value path"
  down-weighting applies to everything that still gets scanned (docs, examples, samples, ...).
- Duplicate merging assumes identical flagged code means the same underlying issue. Very short,
  generic snippets could be merged more aggressively than you want.
- The score ranks *where to look first*. It is not a substitute for confirming exploitability.

## Tests

```bash
pytest
```

## Ideas to extend it

- Add Bandit, gitleaks or Trivy as extra sources feeding the same dedupe and scoring.
- Create tickets (GitHub Issues, Jira) automatically for new Critical findings.
- Use the repo's "internet-facing" or "handles PII" tags to boost scores.
