import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import triage  # noqa: E402


def make_result(path="app.py", line=10, rule="py.sqli", sev="ERROR", lines="cur.execute(q % x)",
                cwe=("CWE-89: SQL Injection",), confidence="HIGH"):
    return {
        "check_id": rule,
        "path": path,
        "start": {"line": line},
        "end": {"line": line},
        "extra": {
            "severity": sev,
            "message": "Example   message\nwith whitespace",
            "lines": lines,
            "metadata": {"cwe": list(cwe), "confidence": confidence,
                         "owasp": ["A03:2021 - Injection"]},
        },
    }


def parse(results, repo="repo-a"):
    return triage.parse_semgrep({"results": results}, repo)


def test_parse_extracts_cwe_owasp_and_cleans_message():
    f = parse([make_result()])[0]
    assert f.cwe == [89]
    assert f.owasp == ["A03:2021 - Injection"]
    assert f.message == "Example message with whitespace"
    assert f.severity == "ERROR" and f.confidence == "HIGH"


def test_severity_aliases_and_unknown_values():
    assert parse([make_result(sev="HIGH")])[0].severity == "ERROR"
    assert parse([make_result(sev="weird")])[0].severity == "INFO"


def test_exact_duplicates_are_dropped():
    findings = parse([make_result(), make_result()])
    merged, removed = triage.deduplicate(findings)
    assert len(merged) == 1 and removed == 1


def test_same_code_in_two_repos_merges_into_one_cluster():
    a = parse([make_result()], "repo-a")
    b = parse([make_result(path="lib/db.py", line=42)], "repo-b")
    merged, removed = triage.deduplicate(a + b)
    assert len(merged) == 1 and removed == 1
    assert {o["repo"] for o in merged[0].occurrences} == {"repo-a", "repo-b"}


def test_different_code_is_not_merged():
    a = parse([make_result(lines="cur.execute(a % x)")])
    b = parse([make_result(lines="cur.execute(b % y)", line=20)])
    merged, removed = triage.deduplicate(a + b)
    assert len(merged) == 2 and removed == 0


def test_requires_login_placeholder_is_ignored():
    f = parse([make_result(lines="requires login")])[0]
    assert f.snippet == ""


def test_cluster_prefers_production_path_as_representative():
    prod = parse([make_result(path="src/app.py")], "r")
    test = parse([make_result(path="tests/test_app.py", line=3)], "r")
    merged, _ = triage.deduplicate(test + prod)
    assert merged[0].path == "src/app.py" and not merged[0].low_value_path


def test_scoring_orders_injection_above_generic_warning():
    sqli = parse([make_result()])[0]
    generic = parse([make_result(rule="py.other", sev="WARNING", cwe=(), confidence="MEDIUM",
                                 lines="something_else()")])[0]
    ranked = triage.prioritize([generic, sqli])
    assert ranked[0].rule_id == "py.sqli"
    assert ranked[0].band == "Critical"


def test_low_value_paths_are_downweighted():
    prod = parse([make_result(path="src/app.py", lines="x")])[0]
    docs = parse([make_result(path="docs/example.py", lines="y")])[0]
    assert docs.low_value_path and not prod.low_value_path
    assert triage.score_finding(docs) < triage.score_finding(prod)


def test_widespread_pattern_gets_small_bonus_capped():
    f = parse([make_result()])[0]
    f.occurrences = [{}] * 2
    two = triage.score_finding(f)
    f.occurrences = [{}] * 50
    many = triage.score_finding(f)
    assert two < many <= 100
    assert many - two <= 8  # bonus is capped


def test_band_boundaries():
    assert triage.band_for(70) == "Critical"
    assert triage.band_for(69.9) == "High"
    assert triage.band_for(45) == "High"
    assert triage.band_for(25) == "Medium"
    assert triage.band_for(24.9) == "Low"


def test_baseline_marks_only_new_findings():
    findings, _ = triage.deduplicate(parse([make_result(), make_result(rule="py.b", lines="z()")]))
    known = {findings[0].id}
    ranked = triage.prioritize(findings, baseline_ids=known)
    assert [f.is_new for f in ranked if f.id in known] == [False]
    assert any(f.is_new for f in ranked)


def test_cli_from_json_writes_outputs_and_fail_on_exit_code(tmp_path):
    src = tmp_path / "scan.json"
    src.write_text(json.dumps({"results": [make_result()]}))
    out = tmp_path / "out"
    code = triage.main(["--from-json", str(src), "--out-dir", str(out), "--fail-on", "High"])
    assert code == 1
    assert (out / "report.md").exists()
    data = json.loads((out / "results.json").read_text())
    assert data["findings"][0]["band"] == "Critical"

    # Same input, higher threshold than the finding -> passes.
    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"results": []}))
    assert triage.main(["--from-json", str(clean), "--out-dir", str(out), "--fail-on", "High"]) == 0


def test_cli_baseline_round_trip(tmp_path):
    src = tmp_path / "scan.json"
    src.write_text(json.dumps({"results": [make_result()]}))
    out1, out2 = tmp_path / "o1", tmp_path / "o2"
    triage.main(["--from-json", str(src), "--out-dir", str(out1)])
    triage.main(["--from-json", str(src), "--out-dir", str(out2),
                 "--baseline", str(out1 / "results.json")])
    data = json.loads((out2 / "results.json").read_text())
    assert data["findings"][0]["is_new"] is False


def test_nothing_to_scan_returns_error_code():
    assert triage.main([]) == 2


def test_missing_repo_path_is_an_error_not_a_clean_pass(tmp_path):
    code = triage.main([str(tmp_path / "does-not-exist"), "--out-dir", str(tmp_path / "o")])
    assert code == 3
    data = json.loads((tmp_path / "o" / "results.json").read_text())
    assert "does-not-exist" in data["errors"]
