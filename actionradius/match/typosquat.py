"""
Typosquat / lookalike-action detector.

Flags uses: references that are suspiciously close (1-2 edit distance)
to a well-known action. This catches real supply-chain vectors like:
  actions/checout  (missing 'k')
  action/checkout  (missing 's' in owner)
  actions/checkout-v2  (fake variant)
"""

import json
from pathlib import Path
from actionradius.models import UsesSite

# Load the curated popular-actions list once at import time
_POPULAR_ACTIONS: list[str] = []
_POPULAR_ACTIONS_PATH = Path(__file__).parent.parent.parent / "data" / "popular_actions.json"
if _POPULAR_ACTIONS_PATH.exists():
    with open(_POPULAR_ACTIONS_PATH, "r", encoding="utf-8") as f:
        _POPULAR_ACTIONS = [a.lower() for a in json.load(f)]


def _levenshtein(s1: str, s2: str) -> int:
    """Standard Levenshtein edit distance."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            # insertion, deletion, substitution
            curr_row.append(min(
                prev_row[j + 1] + 1,
                curr_row[j] + 1,
                prev_row[j] + (0 if c1 == c2 else 1)
            ))
        prev_row = curr_row

    return prev_row[-1]


def check_typosquat(site: UsesSite) -> dict | None:
    """
    Check if a uses site looks like a typosquat of a popular action.

    Returns a dict with details if suspicious, None if clean.
    Only flags actions that are close to (but not exactly) a known action.
    """
    if not site.uses.owner or not site.uses.repo:
        return None

    full_name = f"{site.uses.owner}/{site.uses.repo}".lower()

    # Skip if it's an exact match — that's not a typosquat
    if full_name in _POPULAR_ACTIONS:
        return None

    for popular in _POPULAR_ACTIONS:
        distance = _levenshtein(full_name, popular)

        # Flag if edit distance is 1 or 2 (very suspicious)
        if 0 < distance <= 2:
            return {
                "suspicious_action": f"{site.uses.owner}/{site.uses.repo}",
                "similar_to": popular,
                "edit_distance": distance,
                "workflow_path": site.workflow_path,
                "job_id": site.job_id,
            }

    return None
