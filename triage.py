#!/usr/bin/env python3
"""repo-triage: run Semgrep across many repos, de-duplicate, prioritize, report.

Usage examples:
    python triage.py ./repo-a ./repo-b --config rules/
    python triage.py --scan-dir ~/code --config p/default --config p/owasp-top-ten
    python triage.py --from-json semgrep-output.json      # no Semgrep run needed
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ----------------------------------------------------------------------------
# Scoring configuration (tweak these to match your own risk appetite)
# ----------------------------------------------------------------------------
SEVERITY_BASE = {"ERROR": 60, "WARNING": 35, "INFO": 10}
SEVERITY_ALIASES = {"CRITICAL": "ERROR", "HIGH": "ERROR", "MEDIUM": "WARNING",
                    "LOW": "INFO"}
CONFIDENCE_MULT = {"HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.5}

# Extra points for weakness classes that tend to be directly exploitable.
CWE_BOOST = {
    89: 15,   # SQL injection
    78: 15,   # OS command injection
    94: 15,   # Code injection
    502: 15,  # Insecure deserialization
    798: 12,  # Hard-coded credentials
    22: 10,   # Path traversal
    918: 10,  # SSRF
    611: 10,  # XXE
    79: 8,    # XSS
    327: 6,   # Weak crypto
    352: 5,   # CSRF
    601: 5,   # Open redirect
}

# Findings here are usually lower value (tests, vendored code, docs...).
LOW_VALUE_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|docs?|examples?|samples?|fixtures|mocks?|"
    r"vendor|third_party|node_modules)(/|$)|(^|/)test_[^/]*$|_test\.[a-z]+$",
    re.IGNORECASE,
)
LOW_VALUE_FACTOR = 0.3

BANDS = ["Low", "Medium", "High", "Critical"]          # ascending order
BAND_THRESHOLDS = [(70, "Critical"), (45, "High"), (25, "Medium"), (0, "Low")]


# ----------------------------------------------------------------------------
# Data model
# ----------------------------------------------------------------------------
@dataclass
class Finding:
    repo: str
    rule_id: str
    path: str
    start_line: int
    end_line: int
    message: str
    severity: str
    confidence: str
    cwe: list = field(default_factory=list)
    owasp: list = field(default_factory=list)
    snippet: str = ""
    low_value_path: bool = False
    cluster_key: str = ""
    occurrences: list = field(default_factory=list)
    score: float = 0.0
    band: str = "Low"
    is_new: bool = True

    @property
    def id(self) -> str:
        return self.cluster_key[:12]


# ----------------------------------------------------------------------------
# Running and parsing Semgrep
# ----------------------------------------------------------------------------
def run_semgrep(repo: Path, configs: list, timeout: int):
    """Run Semgrep inside `repo`. Returns (json_data | None, error | None)."""
    if not repo.is_dir():
        return None, "path does not exist or is not a directory"
    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off",
           "--disable-version-check"]
    for config in configs:
        cmd += ["--config", config]
    cmd.append(".")
    try:
        proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    except FileNotFoundError:
        return None, "semgrep not found on PATH (pip install semgrep)"
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError:
        return None, (proc.stderr.strip() or "no JSON output")[:300]


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _normalize(code: str) -> str:
    return re.sub(r"\s+", " ", code).strip()


def read_snippet(root, rel_path: str, start: int, end: int, max_lines: int = 8) -> str:
    """Read the flagged lines from disk (Semgrep OSS often hides them)."""
    if root is None:
        return ""
    try:
        lines = (Path(root) / rel_path).read_text(
            encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[max(start - 1, 0):min(end, start - 1 + max_lines)])


def parse_semgrep(data: dict, repo: str, repo_root=None, rule_prefixes=()) -> list:
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        path = r.get("path", "")
        start = (r.get("start") or {}).get("line", 0)
        end = (r.get("end") or {}).get("line", start)

        sev = str(extra.get("severity", "INFO")).upper()
        sev = SEVERITY_ALIASES.get(sev, sev)
        if sev not in SEVERITY_BASE:
            sev = "INFO"

        snippet = read_snippet(repo_root, path, start, end)
        if not snippet:
            lines = extra.get("lines", "")
            snippet = "" if "requires login" in lines else lines

        cwe = sorted({int(n) for c in _as_list(meta.get("cwe"))
                      for n in re.findall(r"CWE-(\d+)", str(c))})
        rule_id = r.get("check_id", "unknown")
        for prefix in rule_prefixes:      # local rules get a path-based prefix
            if rule_id.startswith(prefix):
                rule_id = rule_id[len(prefix):]
                break
        if snippet:
            key_src = f"{rule_id}|{_normalize(snippet)}"        # same code anywhere
        else:
            key_src = f"{rule_id}|{repo}|{path}|{start}"        # fall back to location
        f = Finding(
            repo=repo, rule_id=rule_id, path=path, start_line=start, end_line=end,
            message=_normalize(extra.get("message", "")), severity=sev,
            confidence=str(meta.get("confidence", "MEDIUM")).upper(),
            cwe=cwe, owasp=[str(o) for o in _as_list(meta.get("owasp"))],
            snippet=snippet, low_value_path=bool(LOW_VALUE_PATH.search(path)),
            cluster_key=hashlib.sha1(key_src.encode()).hexdigest(),
        )
        findings.append(f)
    return findings


# ----------------------------------------------------------------------------
# De-duplication and scoring
# ----------------------------------------------------------------------------
def deduplicate(findings: list):
    """Drop exact repeats, then merge the same rule hitting the same code.

    Returns (merged_findings, number_removed).
    """
    seen, unique = set(), []
    for f in findings:                                  # 1) exact duplicates
        key = (f.repo, f.rule_id, f.path, f.start_line, f.end_line)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    clusters = {}
    for f in unique:                                    # 2) copy-pasted code
        clusters.setdefault(f.cluster_key, []).append(f)

    merged = []
    for group in clusters.values():
        # Prefer a production path as the representative so one copy in tests/
        # doesn't drag the whole cluster's score down.
        group.sort(key=lambda g: (g.low_value_path, g.repo, g.path, g.start_line))
        rep = group[0]
        rep.occurrences = [{"repo": g.repo, "path": g.path, "line": g.start_line}
                           for g in group]
        merged.append(rep)
    return merged, len(findings) - len(merged)


def score_finding(f: Finding) -> float:
    s = SEVERITY_BASE.get(f.severity, 10) * CONFIDENCE_MULT.get(f.confidence, 0.8)
    s += max((CWE_BOOST.get(c, 0) for c in f.cwe), default=0)
    s += min(len(f.occurrences) - 1, 5) * 2             # widespread pattern
    if f.low_value_path:
        s *= LOW_VALUE_FACTOR
    return round(max(0.0, min(100.0, s)), 1)


def band_for(score: float) -> str:
    return next(name for limit, name in BAND_THRESHOLDS if score >= limit)


def prioritize(findings: list, baseline_ids=None) -> list:
    for f in findings:
        f.score = score_finding(f)
        f.band = band_for(f.score)
        f.is_new = baseline_ids is None or f.id not in baseline_ids
    return sorted(findings, key=lambda f: (-f.score, f.repo, f.path, f.start_line))


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------
def _cell(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(findings, repos, errors, top, duplicates_removed,
                    show_new=False) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"# Code Security Triage Report", "",
           f"_Generated {now} | {len(repos)} repo(s) | "
           f"{len(findings)} unique findings ({duplicates_removed} duplicates merged)_", ""]

    out += ["## Summary", "", "| Priority | Findings |", "|---|---|"]
    for band in reversed(BANDS):
        out.append(f"| {band} | {sum(1 for f in findings if f.band == band)} |")

    out += ["", "## By repository (a shared finding counts for every repo it appears in)", "",
            "| Repo | Critical | High | Medium | Low |",
            "|---|---|---|---|---|"]
    for repo in sorted(repos):
        counts = [sum(1 for f in findings if f.band == b and
                      any(o["repo"] == repo for o in f.occurrences))
                  for b in reversed(BANDS)]
        out.append(f"| {_cell(repo)} | " + " | ".join(map(str, counts)) + " |")

    rule_counts = {}
    for f in findings:
        rule_counts[f.rule_id] = rule_counts.get(f.rule_id, 0) + 1
    out += ["", "## Noisiest rules (candidates for tuning)", "", "| Rule | Findings |", "|---|---|"]
    for rule, n in sorted(rule_counts.items(), key=lambda kv: -kv[1])[:5]:
        out.append(f"| `{_cell(rule)}` | {n} |")

    out += ["", f"## Top {min(top, len(findings))} findings", ""]
    for i, f in enumerate(findings[:top], 1):
        tags = ", ".join([f"CWE-{c}" for c in f.cwe] + f.owasp) or "n/a"
        new = " **(NEW)**" if show_new and f.is_new else ""
        out += [f"### {i}. [{f.band} - {f.score}] `{f.rule_id}`{new}", "",
                f"- **Where:** `{f.repo}` / `{f.path}:{f.start_line}`",
                f"- **Severity / confidence:** {f.severity} / {f.confidence}",
                f"- **Tags:** {tags}",
                f"- **Why it matters:** {f.message}"]
        if f.low_value_path:
            out.append("- **Note:** in a test/vendor/docs path, so score was reduced")
        if len(f.occurrences) > 1:
            shown = ", ".join(f"`{o['repo']}:{o['path']}:{o['line']}`"
                              for o in f.occurrences[:5])
            more = f" (+{len(f.occurrences) - 5} more)" if len(f.occurrences) > 5 else ""
            out.append(f"- **Same pattern in {len(f.occurrences)} places:** {shown}{more}")
        if f.snippet:
            out += ["", "```", f.snippet, "```"]
        out.append("")

    if errors:
        out += ["## Scan errors", ""] + [f"- `{r}`: {e}" for r, e in errors.items()] + [""]
    return "\n".join(out)


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def discover_repos(scan_dir: Path) -> list:
    return sorted(p.parent for p in scan_dir.glob("*/.git"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run Semgrep across repos, de-duplicate "
                                "and prioritize the findings.")
    p.add_argument("repos", nargs="*", help="repository paths to scan")
    p.add_argument("--scan-dir", help="scan every git repo directly inside this folder")
    p.add_argument("--from-json", nargs="*", default=[],
                   help="use existing Semgrep JSON output instead of running Semgrep")
    p.add_argument("--config", action="append",
                   help="Semgrep config/ruleset (repeatable). Default: p/default")
    p.add_argument("--out-dir", default="triage-output")
    p.add_argument("--top", type=int, default=20, help="findings to detail in the report")
    p.add_argument("--min-band", choices=BANDS, default="Low",
                   help="hide findings below this priority")
    p.add_argument("--hide-low-value", action="store_true",
                   help="drop findings in tests/vendor/docs paths entirely")
    p.add_argument("--baseline", help="previous results.json; marks only new findings")
    p.add_argument("--fail-on", choices=BANDS,
                   help="exit 1 if any finding is at or above this priority (for CI). "
                        "Exit 3 means some repos failed to scan.")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--timeout", type=int, default=600, help="per-repo timeout (seconds)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    configs = [str(Path(c).resolve()) if Path(c).exists() else c
               for c in (args.config or ["p/default"])]

    repos = [Path(r).resolve() for r in args.repos]
    if args.scan_dir:
        repos += discover_repos(Path(args.scan_dir).resolve())

    rule_prefixes = tuple(".".join(Path(c).parts[1:]) + "." for c in configs
                          if Path(c).is_absolute())
    raw, errors, scanned = [], {}, []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        jobs = {pool.submit(run_semgrep, r, configs, args.timeout): r for r in repos}
        for job in as_completed(jobs):
            repo = jobs[job]
            data, err = job.result()
            scanned.append(repo.name)
            if err:
                errors[repo.name] = err
            else:
                raw += parse_semgrep(data, repo.name, repo, rule_prefixes)
    for path in args.from_json:
        name = Path(path).stem
        scanned.append(name)
        try:
            raw += parse_semgrep(json.loads(Path(path).read_text()), name)
        except (OSError, json.JSONDecodeError) as exc:
            errors[name] = str(exc)

    if not scanned:
        print("Nothing to scan. Give repo paths, --scan-dir or --from-json.", file=sys.stderr)
        return 2

    baseline_ids = None
    if args.baseline:
        prev = json.loads(Path(args.baseline).read_text())
        baseline_ids = {f["id"] for f in prev.get("findings", [])}

    if args.hide_low_value:
        raw = [f for f in raw if not f.low_value_path]
    merged, removed = deduplicate(raw)
    findings = prioritize(merged, baseline_ids)
    findings = [f for f in findings if BANDS.index(f.band) >= BANDS.index(args.min_band)]

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(
        render_markdown(findings, scanned, errors, args.top, removed,
                        show_new=bool(args.baseline)), encoding="utf-8")
    payload = {"generated_at": datetime.now(timezone.utc).isoformat(), "repos": scanned,
               "errors": errors, "duplicates_merged": removed,
               "findings": [{**asdict(f), "id": f.id} for f in findings]}
    (out / "results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    counts = {b: sum(1 for f in findings if f.band == b) for b in reversed(BANDS)}
    print(f"Scanned {len(scanned)} repo(s): {len(raw)} raw -> {len(findings)} unique "
          f"({removed} duplicates merged)")
    print("  " + "  ".join(f"{b}: {n}" for b, n in counts.items()))
    for repo, err in errors.items():
        print(f"  ! {repo}: {err}", file=sys.stderr)
    print(f"Report: {out / 'report.md'}\nData:   {out / 'results.json'}")

    if args.fail_on and any(BANDS.index(f.band) >= BANDS.index(args.fail_on)
                            for f in findings):
        return 1
    return 3 if errors else 0        # never let a failed scan look like a clean one


if __name__ == "__main__":
    sys.exit(main())
