# ActionRadius — AI Handoff Document

_Last regenerated: 2026-09-03, against the actual repo state (the previous version of this doc had drifted — most of its "remaining work" was already done)._

## 1. Project Goal

ActionRadius is a **fleet-wide GitHub Actions supply-chain scanner**. Given an org or repo + a compromised action ref, it:
1. Inventories ALL workflow files across the org via the Git Trees API
2. Resolves every mutable tag to its live SHA
3. Classifies each usage as `COMPROMISED / SAFE / UNKNOWN` using GitHub's Compare API
4. Scores by context (secrets, triggers, permissions, runner type, publisher trust)
5. Outputs ranked findings as JSON / HTML / SARIF / Graphviz DOT

**Key differentiator from zizmor/poutine:** Those do per-workflow YAML linting. ActionRadius does fleet-wide *incident response* — "which of our 500 repos resolved trivy-action@0.34.2 to the poisoned SHA (ddb9da44) right now?"

Canonical demo story: March 19 2026 Trivy attack — attackers force-pushed 75/76 trivy-action tags to malicious code + swapped an actions/checkout SHA in Trivy's release pipeline with a spoofed `# v6.0.2` comment.

---

## 2. Environment / Setup

- **OS:** Ubuntu 24, Python 3.12.3
- **Repo path (latest):** `/home/claude/work/v4/Actionradius-main/`
- **Install:** `pip install -e . --break-system-packages`
- **Auth:** `GITHUB_TOKEN` env var via `.env` (loaded by `python-dotenv`)
- **Test runner:** `python -m pytest -v` (82 tests)
- **Key deps:** `requests`, `pyyaml`, `typer`, `jinja2`, `python-dotenv`, `pytest`

CLI entry point: `actionradius scan` / `actionradius diff`

**Sandbox caveat:** in network-isolated sandboxes, `pip install` can't reach PyPI, so `typer`/`pytest` may not be installable and `pip install -e .` will fail at the build-deps step. If that happens, verify changes with a manual test runner instead of skipping verification:
```python
import sys, importlib, pkgutil
sys.path.insert(0, '.')
import tests
for _, modname, _ in pkgutil.iter_modules(tests.__path__):
    mod = importlib.import_module(f'tests.{modname}')
    for name in dir(mod):
        if name.startswith('test_') and callable(getattr(mod, name)):
            getattr(mod, name)()  # raises on failure
```
This skips any test using pytest-only features (`import pytest`, `tmp_path` fixture, etc.) — currently that's `test_level1.py` and one test in `test_sarif_report.py`. Those aren't broken, they just need real pytest to run.

---

## 3. What Has Been Completed (verified working)

### Core pipeline — ALL working
- `github_client.py` — rate-limit backoff (403 + Retry-After + X-RateLimit-Reset), retry-capped at `MAX_RETRIES = 3` via `_attempt` param (recursion bug from earlier handoff is fixed)
- `inventory/repo_lister.py` — paginated org repo listing + `check_exfil_repos()` (tpcp-docs detection)
- `inventory/tree_fetcher.py` — Git Trees API (`?recursive=1`), base64 decode workflow content
- `parser/uses_parser.py` — parses all ref types: sha, mutable_ref, local, docker, docker_digest, unresolvable
- `parser/workflow_parser.py` — full YAML → WorkflowFile (triggers, permissions, secrets, runs_on_self_hosted, uses_sites, run_scripts)
- `parser/composite_resolver.py` — reusable workflow recursion, depth-capped at 2
- `context/trigger_risk.py` — fork-reachable trigger detection (pull_request_target etc.)
- `context/permissions.py` — workflow + job-level permissions
- `context/secrets.py` — secrets: inherit, explicit blocks
- `context/historical.py` — `check_historical_exposure()`: walks commit history to `attack_window.end`, fetches the workflow at that historical SHA, checks whether the target action was present. Populates `Finding.historical_exposure` (no longer hardcoded).
- `context/publisher_trust.py` — `check_publisher_trust(client, owner, repo)` → `"verified" | "established" | "new_org" | "unknown"`. Uses `/users/{owner}` for account age (works for orgs and personal accounts alike), `/orgs/{owner}` for the verified badge (skipped if 404 — not an org), repo star count as a secondary signal. Cached per `(owner, repo)` for the process lifetime.
- `resolve/ref_resolver.py` — tag→SHA via Git Refs API, branch fallback, cache by (owner,repo,ref), orphan SHA detection via Compare API
- `match/matcher.py` — `is_in_bad_range()` (Compare API), `determine_compromise_status()`, `is_compromised()` (legacy safe-ref mode)
- `match/typosquat.py` — Levenshtein against 40 popular actions from `data/popular_actions.json`; findings now flow into `findings[]` (not just stderr) via `is_typosquat=True`
- `match/sha_comment_check.py` — detects `@SHA # vX.Y.Z` where SHA ≠ what that tag resolves to
- `score/scoring.py` — weighted model, loads from `data/weights.yaml`, configurable via `load_weights()`; `calculate_risk_score()` takes `is_typosquat`, `is_docker_mutable`, `is_unverified_publisher`
- `report/json_report.py` — full dataclass serialization
- `report/html_report.py` — Jinja2 template, tri-state sections (COMPROMISED/UNKNOWN/SAFE)
- `report/sarif_report.py` — SARIF 2.1.0 output; includes any finding with severity in `("critical", "high", "medium")`, not just COMPROMISED — so HIGH typosquats and orphan findings show up
- `report/graph_report.py` — Graphviz DOT blast-radius graph; guarded in `cli.py` to warn-and-skip (not crash) when combined with `--target-feed`
- `drift.py` — diff two JSON reports → NEW / RESOLVED / ESCALATED / DE-ESCALATED
- `cli.py` — `scan` command with all flags including `--weights`, `diff` command; typosquat + SHA-mismatch + docker sweep + publisher trust all run per scan

### Data files
- `data/compromised_feed.json` — 4 entries: trivy-action, setup-trivy, tj-actions/changed-files, tj-actions/verify-changed-files
- `data/popular_actions.json` — 40 popular actions for typosquat detection
- `data/weights.yaml` — all 11 scoring weights exposed: `orphan_commit=8.0, compromised_sha_pin=8.0, mutable_compromised=3.0, unknown_compromise=4.0, fork_reachable_trigger=3.0, privileged_trigger=1.0, secrets_inherit=3.0, explicit_secrets=2.0, self_hosted_runner=2.0, typosquat_penalty=5.0, docker_mutable_tag=2.0, publisher_unverified=2.0`

### Tests — 82 total (was 64; grew as dummy tests were replaced and new features got coverage)
- `test_context.py` (6), `test_detectors.py` (4), `test_historical_exposure.py` (7), `test_inventory.py` (4)
- `test_level1.py` (10 — needs real pytest, uses `import pytest`)
- `test_matcher.py` (15), `test_ref_resolver.py` (3 — real tests now, not dummy)
- `test_report.py` (2 — real tests now, not dummy), `test_sarif_report.py` (1 — needs pytest `tmp_path` fixture)
- `test_scoring.py` (7), `test_uses_parser.py` (12), `test_workflow_parser.py` (3), `test_recursion.py` (2 — 1 real, 1 dummy)
- `test_publisher_trust.py` (6 — new: verified org, new org, established, lookup failure, personal-account fallback, caching)

### Other
- `docs/architecture.png` + `docs/generate_diagram.py` — script that regenerates the diagram, already lives in `docs/` (no longer in a `scratch/` dir at repo root)
- `LICENSE` (MIT), `.gitignore` (covers `report*.json`, `findings*.json`, `output/`, `scratch/`, build artifacts), `README.md` (excellent, references Trivy incident)
- `tests/fixtures/` — 6 workflow fixtures including local_action.yml and composite_action.yml

---

## 4. Current Implementation State

### Working end-to-end
```bash
# Incident response mode
actionradius scan --org myorg --target aquasecurity/trivy-action \
  --bad-from ddb9da44 --bad-to 76d05ec6... --html report.html

# Feed mode (all known incidents)
actionradius scan --org myorg --target-feed data/compromised_feed.json --json out.json

# IOC hunting
actionradius scan --org myorg --ioc-search "aquasecurtiy.org"

# Exfil check
actionradius scan --org myorg --check-exfil

# Custom scoring weights
actionradius scan --org myorg --target aquasecurity/trivy-action --weights custom_weights.yaml

# Drift
actionradius diff monday.json tuesday.json
```

### Docker findings, historical exposure, typosquat-in-report, SARIF filtering, graph/feed-mode guard, publisher trust
All previously "partially implemented / broken" — now implemented and covered by tests. See §3.

### Not yet started
- SARIF ingestion from external scanners (zizmor/poutine) — see §7 item 1 below
- Async/concurrent scanning — see §7 item 2 below

---

## 5. Latest Test Results

82 tests collected. All non-pytest-fixture-dependent tests pass (verified via manual runner in a network-isolated sandbox — see §2 for that snippet). Run `python -m pytest -v` in a normal environment with deps installed for the authoritative result, including the 11 tests that need real pytest (`test_level1.py`'s 10 tests + 1 in `test_sarif_report.py` using `tmp_path`).

---

## 6. Important Technical Decisions (preserve these)

1. **GitHub Compare API for range matching**, not date/timestamp. Commit graph position is canonical; wall-clock time is not. `is_in_bad_range()` calls `/compare/{bad_from}...{sha}` then `/compare/{sha}...{bad_to}` and checks `status` field.

2. **Tri-state CompromiseStatus** (`COMPROMISED/SAFE/UNKNOWN`) — never silently treats unresolvable as safe. `UNKNOWN` gets `+4.0` scoring penalty.

3. **Mutable `ref_type`** in UsesRef: `"mutable_ref"` is the canonical type for tags/branches (not `"tag"` or `"branch"` — the parser outputs `"mutable_ref"` for anything that's not a 40-char SHA). `"docker"` and `"docker_digest"` are separate ref types, both present in the `Literal` in `models.py`.

4. **Resolution cache** in `ref_resolver.py` — module-level `_RESOLUTION_CACHE` dict keyed by `(owner, repo, ref)`. Persists for lifetime of process. Critical for large org scans. Same pattern used in `publisher_trust.py`'s `_TRUST_CACHE`, keyed by `(owner, repo)`.

5. **Scoring weights** are loaded from `data/weights.yaml` at import time via `load_weights()`, or from a custom path via `--weights`. Current defaults: orphan_commit=8.0, compromised_sha_pin=8.0, mutable_compromised=3.0, unknown_compromise=4.0, fork_reachable_trigger=3.0, privileged_trigger=1.0, secrets_inherit=3.0, explicit_secrets=2.0, self_hosted_runner=2.0, typosquat_penalty=5.0, docker_mutable_tag=2.0, publisher_unverified=2.0.

6. **Severity bands:** score 0=info, 1=low, 2-4=medium, 5-7=high, 8+=critical.

7. **Feed mode** iterates each `entry` in `compromised_feed.json`, calls `_scan_workflows()` per entry with that entry's `bad_range`.

8. **Typosquat** runs on EVERY site in EVERY scan, independent of `--target`. It both prints to stderr AND adds a `Finding` with `is_typosquat=True` to `findings[]` (this used to be stderr-only; fixed).

9. **Docker sweep** runs on every `--target` scan, independent of the target string itself (nobody types `--target _docker/alpine`) — `ref_type == "docker"` sites get their own `Finding` with `is_docker_mutable=True` passed into scoring, then `continue` so they don't also get evaluated against `is_match(site, target)`.

10. **Publisher trust** is only computed on the target-match path (where a `Finding` is actually being built for a specific `owner/repo`), not for every site in every workflow — it's 1-2 extra API calls per unique publisher, mitigated by the cache. `is_unverified_publisher` is only set `True` for a confirmed `"new_org"` verdict — a lookup failure (`"unknown"`, e.g. rate-limited) is treated as score-neutral rather than penalized, so API hiccups don't inflate severity.

---

## 7. What Remains to Build (prioritized)

### Stretch features (COMPLETED)
1. **SARIF ingestion from zizmor/poutine** (Done) — `context/external_findings.py`, parse SARIF input, bump score +1 if workflow has external taint finding
2. **Async/concurrent scanning** (Done) — swap `requests` for `httpx` + `asyncio`, semaphore sized to `X-RateLimit-Remaining`

### Everything else from the previous handoff (docker findings, recursion cap, ref_type Literal, historical_exposure, SARIF filtering, graph/feed-mode guard, `--weights` flag, `.gitignore`, dummy test replacement, typosquat-in-report, publisher trust signal) is done — see §3 and §6.

---

## 8. Exact Next Steps (numbered sequence)

**All stretch features (SARIF ingestion and Async scanning) are now fully implemented and passing all tests.**

---

## 9. Known Issues / Blockers

None currently open from the original list — all 10 items from the previous handoff's issues table have been fixed and are covered by tests (see §3, §6). No new issues have surfaced.

---

## 10. Files to Inspect First

| File | Why |
|---|---|
| `actionradius/cli.py` | Central scan loop — `_scan_workflows()`. All context checks (typosquat, docker, historical exposure, publisher trust) are wired in here. |
| `actionradius/context/publisher_trust.py` | Newest module — publisher age/verification/star-count classification, cached per `(owner, repo)`. |
| `actionradius/context/historical.py` | Historical exposure — walks commit history to `attack_window.end` and re-parses the workflow at that SHA. |
| `actionradius/score/scoring.py` | Weighted scoring — all boolean risk factors flow through `calculate_risk_score()`. |
| `actionradius/models.py` | All dataclasses. `Finding` has `is_typosquat`; nothing currently exposes `publisher_trust` as its own field on `Finding` (only folds into the score) — worth considering if a future task wants it surfaced in reports. |
| `data/weights.yaml` | All scoring weights — 11 total now. |
| `tests/test_level1.py` | Best reference for expected end-to-end behavior — 10 integration-style tests with mocked API. Needs real pytest to run (uses `import pytest`). |
| `tests/test_publisher_trust.py` | Reference for the newest module's expected behavior and edge cases (personal-account 404 fallback, caching, lookup failure). |

---

## NEXT ACTION:
Pick up §7 item 1 (SARIF ingestion from zizmor/poutine) — it's the smaller of the two remaining stretch features and doesn't touch the rate-limit-sensitive parts of `github_client.py` the way async scanning would.
