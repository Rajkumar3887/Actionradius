# ActionRadius Handoff Report

## Project Purpose
ActionRadius is a fleet-wide exposure analysis tool for compromised GitHub Actions dependencies. It connects to the GitHub API, inventories a GitHub organization's workflows via the Git Trees API, parses uses: clauses, resolves mutable tags to exact SHAs, checks if they fall into compromised ranges, and evaluates context (secrets, permissions) for risk scoring.

## Architecture
- `cli.py`: Entry point for all CLI commands.
- `inventory/`: Async Git Trees API fetching and workflow discovery.
- `parser/`: Parses GitHub workflow YAML to extract dependency references.
- `resolve/`: Translates mutable refs (tags/branches) into SHAs via GitHub API.
- `match/`: Evaluates if a SHA is inside a known compromised range.
- `score/`: Calculates a severity score based on multiple risk factors.
- `context/`: Historical exposure, publisher trust, external SARIF ingestion.
- `report/`: JSON, HTML, SARIF, Graphviz output formats.

## Current Verified State
- **Tests**: 137/137 tests pass consistently.
- **Dynamic Concurrency Recalibration**: Implemented (`DynamicSemaphore`, `recalibrate_concurrency` in `github_client_async.py` and `async_scan.py`). Rate limits correctly resize concurrent fetches without deadlock or invalid state.
- **Rate-limit Header Parsing**: Fixed. Missing headers are ignored instead of coerced to -1, preventing false throttling.
- **CLI Validation Ordering**: Fixed. `--org` and `--external-sarif` validation now happens *before* repository fetching to avoid wasted API calls.
- **Sync Client Timeout**: A 30s timeout is implemented to prevent stalls.
- **HTML Reporting**: Jinja2 autoescaping is enabled to prevent stored XSS.
- **External SARIF Documentation**: `README.md` correctly explains the `versionControlProvenance` requirement for org-wide SARIF ingestion.
- **Security Check**: No `subprocess`, `eval`, `exec`, `pickle`, or `shell=True` usage in the codebase.
- **Pagination**: Fully verified for repo listing and exfiltration checks.

## Completed Features
- Core scanner (YAML parsing, mutable-ref resolution, threat matching, risk scoring).
- Async/concurrent fetching.
- Fleet-wide SARIF ingestion.
- Publisher trust scoring.
- Historical exposure checks.
- Drift detection.
- Exfiltration detection (`tpcp-docs`).
- Feed mode & Docker deduplication.
- Nested workflows/composite actions.

## Changed Files (Most Recent Session)
- `actionradius/github_client_async.py`: Added `DynamicSemaphore` and `recalibrate_concurrency()`.
- `actionradius/async_scan.py`: Wired up dynamic semaphore to orchestrator.
- `actionradius/cli.py`: Reordered validation before repo fetching.
- `actionradius/github_client.py`: Added 30-second request timeout.
- `actionradius/report/html_report.py`: Enabled Jinja2 autoescape (XSS fix).
- `README.md`: Documented external SARIF behavior.
- `tests/test_dynamic_concurrency.py`: 20 new tests.
- `tests/test_report.py`: 1 new XSS regression test.

## Remaining Issues & Recommended Next Steps
1. **GitHub API 5xx Retries**: Currently, neither the sync nor async GitHub clients retry on transient 5xx errors (only 403/404 are special-cased). This is currently a low priority as per-repo failures are isolated, but it should be considered if large org scans start experiencing flakiness.

## Known Limitations
- Progress bars (`rich`) were evaluated and skipped as merely cosmetic. The scrolling per-repo log output is deemed sufficient.
- Org-wide `load_external_sarif` without `versionControlProvenance` is intentionally unsupported to prevent mapping false positives across unrelated repositories.

## Exact Instructions for the Next Claude
1. Read this document (`CLAUDE_HANDOFF.md`) to establish context.
2. Verify the test suite continues to pass (`python -m pytest -v`).
3. Focus purely on any newly requested features or the single remaining consideration: **5xx retry/backoff for GitHub API requests**.
4. **DO NOT** repeat completed work, do not restructure the concurrency model, do not rewrite the HTTP clients, and do not weaken existing tests.
