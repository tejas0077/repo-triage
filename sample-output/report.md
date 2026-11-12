# Code Security Triage Report

_Generated 2026-11-12 09:09 UTC | 2 repo(s) | 4 unique findings (1 duplicates merged)_

## Summary

| Priority | Findings |
|---|---|
| Critical | 1 |
| High | 0 |
| Medium | 2 |
| Low | 1 |

## By repository (a shared finding counts for every repo it appears in)

| Repo | Critical | High | Medium | Low |
|---|---|---|---|---|
| repo-a | 1 | 0 | 2 | 0 |
| repo-b | 1 | 0 | 0 | 1 |

## Noisiest rules (candidates for tuning)

| Rule | Findings |
|---|---|
| `demo.python.hardcoded-credential` | 2 |
| `demo.python.sql-injection-string-building` | 1 |
| `demo.python.subprocess-shell-true` | 1 |

## Top 4 findings

### 1. [Critical - 77.0] `demo.python.sql-injection-string-building`

- **Where:** `repo-a` / `app.py:9`
- **Severity / confidence:** ERROR / HIGH
- **Tags:** CWE-89, A03:2021 - Injection
- **Why it matters:** SQL query built with string formatting or concatenation. Use parameterized queries instead.
- **Same pattern in 2 places:** `repo-a:app.py:9`, `repo-b:app.py:3`

```
    cur.execute("SELECT * FROM users WHERE name = '%s'" % username)
```

### 2. [Medium - 43.0] `demo.python.subprocess-shell-true`

- **Where:** `repo-a` / `app.py:14`
- **Severity / confidence:** WARNING / MEDIUM
- **Tags:** CWE-78, A03:2021 - Injection
- **Why it matters:** subprocess call with shell=True can lead to OS command injection if any input is user-controlled.

```
    return subprocess.run("ping -c 1 " + host, shell=True)
```

### 3. [Medium - 40.0] `demo.python.hardcoded-credential`

- **Where:** `repo-a` / `app.py:4`
- **Severity / confidence:** WARNING / MEDIUM
- **Tags:** CWE-798, A07:2021 - Identification and Authentication Failures
- **Why it matters:** Possible hard-coded credential. Load secrets from a secrets manager or environment instead.

```
DB_PASSWORD = "hunter2-prod"
```

### 4. [Low - 12.0] `demo.python.hardcoded-credential`

- **Where:** `repo-b` / `examples/sample.py:2`
- **Severity / confidence:** WARNING / MEDIUM
- **Tags:** CWE-798, A07:2021 - Identification and Authentication Failures
- **Why it matters:** Possible hard-coded credential. Load secrets from a secrets manager or environment instead.
- **Note:** in a test/vendor/docs path, so score was reduced

```
API_TOKEN = "example-token-for-docs"
```
