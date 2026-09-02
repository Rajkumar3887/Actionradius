"""
workflow_parser.py

Parses a full workflow YAML file into structured data: its trigger
config, and every `uses:` reference in it (whether at job level —
a reusable workflow call — or step level — an Action call).

This builds directly on uses_parser.py: we find every raw `uses:`
string in the file, then hand each one to parse_uses() to classify it.
"""

import yaml
from dataclasses import dataclass, field
from typing import Optional, Any

from uses_parser import parse_uses, UsesRef


@dataclass
class UsesSite:
    job_id: str
    step_index: Optional[int]   # None = job-level `uses:` (a reusable workflow call)
    uses: UsesRef


@dataclass
class ParsedWorkflow:
    path: str
    name: Optional[str]
    raw_triggers: Any            # interpreted properly in a later step — for now, captured as-is
    uses_sites: list[UsesSite] = field(default_factory=list)


def parse_workflow_yaml(path: str, yaml_text: str) -> ParsedWorkflow:
    parsed = yaml.safe_load(yaml_text)

    if not isinstance(parsed, dict):
        raise ValueError(f"{path}: not a valid workflow file (YAML didn't parse to a mapping)")

    # THE "on:" GOTCHA — see the demo we just ran. YAML 1.1 treats bare
    # on/off/yes/no as booleans, so PyYAML parses the `on:` key as the
    # boolean True, not the string "on". We check both, string first (in
    # case someone quoted it as "on":), boolean True as the common case.
    raw_triggers = parsed.get("on", parsed.get(True))

    name = parsed.get("name")
    uses_sites: list[UsesSite] = []

    jobs = parsed.get("jobs") or {}
    for job_id, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue  # malformed job entry — skip rather than crash the whole scan

        # Job-level `uses:` = this job's entire body IS a call to a
        # reusable workflow (no steps of its own).
        if "uses" in job_def:
            uses_sites.append(UsesSite(
                job_id=job_id,
                step_index=None,
                uses=parse_uses(job_def["uses"]),
            ))

        # Step-level `uses:` = a normal Action call inside a step.
        steps = job_def.get("steps") or []
        for i, step in enumerate(steps):
            if isinstance(step, dict) and "uses" in step:
                uses_sites.append(UsesSite(
                    job_id=job_id,
                    step_index=i,
                    uses=parse_uses(step["uses"]),
                ))

    return ParsedWorkflow(path=path, name=name, raw_triggers=raw_triggers, uses_sites=uses_sites)
