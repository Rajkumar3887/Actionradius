# Next Tasks Checklist

* [ ] P2 `actionradius/async_scan.py` & `actionradius/github_client_async.py`: Implement dynamic concurrency recalibration. Track `rate_limit_remaining` from responses and shrink the `asyncio.Semaphore` limit if the budget drops below a safe threshold mid-scan.
* [ ] Documentation `README.md`: Document that `--external-sarif` in org-wide scans requires tools to emit `versionControlProvenance`, otherwise they must be run per-repo.
* [ ] Feature `actionradius/cli.py` (Optional): Add `rich` progress bars for large org scans to improve UX.
