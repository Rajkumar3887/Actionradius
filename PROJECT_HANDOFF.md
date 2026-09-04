# Project Handoff Report

## 1. Project Overview
ActionRadius is a fleet-wide GitHub Actions supply-chain scanner. It identifies vulnerable or compromised third-party GitHub Actions and reusable workflows across an entire GitHub organization. It supports single-target scanning, batch scanning via threat intelligence feeds, IOC hunting, and checking for specific exfiltration artifacts (e.g. `tpcp-docs`).

## 2. Current Architecture
- `cli.py`: Entry point for single-target, feed mode, and IOC scanning. Orchestrates the flow.
- `inventory/`: Discovers repositories and parses workflow files from Git trees asynchronously.
- `parser/`: Parses `uses:` clauses from YAML workflows to extract precise dependency references (tags, branches, SHAs, docker tags). Resolves composite action internal calls.
- `resolve/`: Resolves mutable references (tags, branches) to exact Git SHAs using the GitHub API, explicitly dereferencing annotated tags to their target commits.
- `match/`: Determines if a resolved SHA falls within a known compromised commit range or is whitelisted via safe refs.
- `score/`: Calculates risk severity scores based on execution context (permissions, secrets, self-hosted runners, triggers, external SARIF findings).
- `context/`: Evaluates contextual risk factors like historical exposure, publisher trust, external SARIF ingestion.
- `report/`: Generates structured outputs (JSON, HTML, SARIF).

## 3. Current Feature Status
- **Core Pipeline**: Complete.
- **Async/concurrent scanning**: Complete (file-level concurrency).
- **External SARIF ingestion**: Complete (repo-scoped via `versionControlProvenance`).
- **Publisher trust scoring**: Complete (exposed on the `Finding` model and templated in reports).
- **Historical exposure**: Complete.
- **Feed mode + Docker dedup**: Complete.
- **Dynamic concurrency recalibration**: Missing.

## 4. Work Already Completed
- All core scanner logic (YAML parsing, ref resolution, status matching, scoring, reporting).
- Extracted nested workflows/composite actions.
- Drift detection and exfiltration artifact (`tpcp-docs`) detection.
- Ported tree fetching to `asyncio.gather` for file-level concurrency.
- Surface `publisher_trust` on the `Finding` model and propagated to JSON/HTML.
- Added `__init__.py` files to subpackages for `pip install -e .` compatibility.
- Fixed annotated tag dereferencing in `resolve_mutable_ref` by falling through to `/git/tags/{sha}`.
- Added duplicate Docker finding prevention via `seen_docker` set in `_scan_workflows`.
- Paginated `check_exfil_repos` to fetch all organization members (preventing 100-member cap limit).

## 5. Existing Audit Findings
- **P1: Annotated tag dereference missing**: Fixed. Explicit lookup of `tag` objects to dereference to commits implemented in `ref_resolver.py`. Verified via tests.
- **P1: Broken pip install**: Fixed. Added missing `__init__.py` and configured `pyproject.toml` to use `packages.find`.
- **P2: Duplicate Docker findings**: Fixed. Added `seen_docker` set to deduplicate.
- **P2: Pytest tmp_path in sarif tests**: Fixed. Migrated to `tempfile.mkstemp`.

## 6. Independent Review Findings
- **Concurrency Recalibration**: The async scanner sets a semaphore based on the initial rate limit, but does not adjust it if the rate limit drops during a large organization scan. This could lead to sudden 403s on massive orgs.
- **External SARIF limitations**: Tools that do not emit `versionControlProvenance` in their SARIF output cannot be accurately mapped across an organization, requiring per-repo scanning instead. This needs clear documentation.

## 7. Security Review
- The tool uses the GitHub API safely via `httpx` and `requests`. No `shell=True` or `subprocess` calls observed.
- YAML parsing relies on standard parsers without executing code.
- Data structures are strictly typed using dataclasses.
- Authentication tokens are handled through standard headers and not leaked into logs. 

## 8. Test Results
- `python -m pytest -v`: **116 passed**, 0 failed, 0 skipped.
- Total test coverage spans resolving, parsing, matching, context scoring, reporting, and async client behavior.

## 9. Known Bugs
None observed that fail the current test suite. Edge cases regarding API timeouts are gracefully handled (e.g., tag dereference gracefully falls back to tag object SHA).

## 10. Remaining Work
- **P2**: Dynamic concurrency recalibration mid-scan.
- **P3**: Document `--external-sarif` limitations in README regarding `versionControlProvenance`.

## 11. Recommended Features / Add-ons
- Optional: Configurable timeout backoff parameters.
- Optional: Add progress bars for large organization scans using `rich` or `tqdm`.

## 12. Known Limitations
- The `load_external_sarif` bare-path mode does not support organization-wide scans because paths like `ci.yml` are ambiguous.

## 13. Modified Files
- `actionradius/models.py`: Added `publisher_trust` to `Finding`.
- `actionradius/cli.py`: Surfaced `publisher_trust` to `Finding`, added Docker deduplication.
- `actionradius/resolve/ref_resolver.py`: Dereferences annotated tags.
- `actionradius/inventory/repo_lister.py`: Paginated org member lookups.
- `actionradius/report/templates/report.html.j2`: Added publisher trust to templates.
- `tests/*`: Comprehensive tests added for the above fixes.
- `pyproject.toml` & `__init__.py`: Fixed packaging.

## 14. Recommended Next Development Sequence
1. Implement dynamic concurrency recalibration in `async_scan.py` / `github_client_async.py`.
2. Update the `README.md` to document the SARIF `versionControlProvenance` limitation.

## 15. Current Project State Summary
ActionRadius is in an extremely stable, feature-complete state for its core mission. All critical bugs, packaging issues, and missing fields have been resolved. The test suite is passing 100% (116 tests). The only remaining tasks are an edge-case concurrency enhancement and documentation updates. The next AI should start on the dynamic concurrency recalibration.

**WHAT WAS ALREADY DONE** → Core scanner, async/concurrent scans, fleet-wide SARIF, publisher trust, historical exposure, drift reports, and all P1/P2 fixes.
**WHAT IS VERIFIED** → 116/116 tests pass natively. Packaging and edge case fixes are confirmed.
**WHAT IS BROKEN** → Nothing currently fails the test suite or crashes execution.
**WHAT REMAINS** → Dynamic concurrency recalibration and documentation for SARIF limitations.
**WHAT THE NEXT AI SHOULD DO FIRST** → Implement dynamic concurrency recalibration in `github_client_async.py` and `async_scan.py`.
