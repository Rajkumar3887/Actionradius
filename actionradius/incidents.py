"""
incidents.py

A curated database of real GitHub Actions supply chain incidents.

WHY THIS EXISTS:
  During an active incident, the IR lead shouldn't have to manually
  look up "which action was compromised?" and "what are the safe SHAs?"
  before they can run ActionRadius. This module bundles that intelligence
  so a scan can be launched with just `--incident trivy-2026`.

  For demos and interviews, this is even more valuable: you can show
  the full incident triage workflow without needing to remember SHA
  hashes or dig through advisories.

IMPORTANT CAVEATS:
  - This is a STATIC, CURATED feed — not a live threat intel stream.
    It's updated manually when new incidents are researched. That's
    intentional: each entry is carefully verified against primary
    sources (CVE records, GitHub advisories, incident discussion
    threads), not scraped from unverified feeds.
  - Safe refs are "known safe at time of research" — if an action
    is compromised AGAIN after our data was written, these won't
    auto-update. Always check the advisory for the latest guidance.

DATA SOURCES for each incident are documented inline so they can be
independently verified — same standard as a pentest report.
"""

from dataclasses import dataclass, field


@dataclass
class KnownIncident:
    """One supply chain incident with enough data to run a targeted scan."""
    id: str                       # short identifier for --incident flag
    name: str                     # human-readable name
    date: str                     # approximate date (YYYY-MM-DD)
    cve: str | None               # CVE ID if assigned
    ghsa: str | None              # GitHub Security Advisory ID
    description: str              # what happened, in 2-3 sentences
    targets: list[dict]           # list of {owner, repo, safe_refs: set[str]}
    references: list[str] = field(default_factory=list)  # URLs to primary sources


# ============================================================
# THE INCIDENTS DATABASE
# ============================================================

INCIDENTS: dict[str, KnownIncident] = {}


def _register(incident: KnownIncident) -> None:
    INCIDENTS[incident.id] = incident


# --- Trivy Supply Chain Attack, March 2026 ---
# 75/76 trivy-action tags and 7 setup-trivy tags were poisoned.
# Exposure windows: ~12hr (trivy-action) and ~4hr (setup-trivy).
# Root cause of second breach: incomplete first credential rotation
# ~3 weeks earlier.
_register(KnownIncident(
    id="trivy-2026",
    name="Aquasecurity Trivy Supply Chain Attack",
    date="2026-03-19",
    cve="CVE-2026-33634",
    ghsa="GHSA-69fq-xp46-6x23",
    description=(
        "75 of 76 trivy-action tags and all 7 setup-trivy tags were force-pushed "
        "to point at malicious commits that exfiltrated CI secrets via workflow logs. "
        "Exposure windows were ~12hr (trivy-action) and ~4hr (setup-trivy). The root "
        "cause of the second breach was an incomplete first credential rotation ~3 weeks earlier."
    ),
    targets=[
        {
            "owner": "aquasecurity",
            "repo": "trivy-action",
            # Official safe pin from Aqua's advisory: v0.35.0 = @57a97c7
            "safe_refs": {"57a97c7"},
        },
        {
            "owner": "aquasecurity",
            "repo": "setup-trivy",
            # Official safe pin from Aqua's advisory: v0.2.6 = @3fb12ec
            "safe_refs": {"3fb12ec"},
        },
    ],
    references=[
        "https://github.com/aquasecurity/trivy-action/issues/571",
        "https://www.aquasec.com/blog/aqua-security-supply-chain-attack-trivy-action/",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-33634",
    ],
))


# --- tj-actions/changed-files, March 2025 ---
# All tags were repointed to a malicious commit that dumped CI secrets
# to workflow logs. Estimated 23,000+ repos affected.
_register(KnownIncident(
    id="tj-actions-2025",
    name="tj-actions/changed-files Supply Chain Attack",
    date="2025-03-14",
    cve="CVE-2025-30066",
    ghsa="GHSA-mrrh-fhqg-pff7",
    description=(
        "All tags of tj-actions/changed-files were force-pushed to point at a "
        "malicious commit that exfiltrated CI secrets by dumping them to workflow "
        "logs. The action was extremely popular (~23,000 dependent repos). The "
        "attack was traced back to a compromised PAT from a maintainer account."
    ),
    targets=[
        {
            "owner": "tj-actions",
            "repo": "changed-files",
            # v46.0.1 was the first clean release after the incident
            "safe_refs": {"6725aeee97b1a52407de7c96341be4450e32e270"},
        },
    ],
    references=[
        "https://github.com/tj-actions/changed-files/issues/2463",
        "https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files",
        "https://nvd.nist.gov/vuln/detail/CVE-2025-30066",
    ],
))


# --- reviewdog Supply Chain Attack, March 2025 ---
# Upstream of tj-actions — the reviewdog/action-setup action was
# compromised first, which was used to pivot into tj-actions.
_register(KnownIncident(
    id="reviewdog-2025",
    name="reviewdog/action-setup Supply Chain Attack",
    date="2025-03-11",
    cve="CVE-2025-30154",
    ghsa="GHSA-qf5v-rp47-55gg",
    description=(
        "reviewdog/action-setup was compromised via a maintainer PAT, and tags were "
        "repointed to inject secret-exfiltrating code. This was the upstream vector "
        "that enabled the tj-actions/changed-files attack days later. Multiple "
        "reviewdog actions were affected."
    ),
    targets=[
        {
            "owner": "reviewdog",
            "repo": "action-setup",
            "safe_refs": {"f5b3c2d3bbf1e40582078a3e09c20c504e8c5ac5"},
        },
    ],
    references=[
        "https://github.com/reviewdog/action-setup/issues/90",
        "https://nvd.nist.gov/vuln/detail/CVE-2025-30154",
    ],
))


def get_incident(incident_id: str) -> KnownIncident | None:
    """Look up an incident by ID. Case-insensitive."""
    return INCIDENTS.get(incident_id.lower())


def list_incidents() -> list[KnownIncident]:
    """Return all known incidents, sorted by date (newest first)."""
    return sorted(INCIDENTS.values(), key=lambda i: i.date, reverse=True)


def format_incident_list() -> str:
    """Format all incidents for CLI display."""
    lines = ["Available incidents:\n"]
    for inc in list_incidents():
        cve_str = f" ({inc.cve})" if inc.cve else ""
        targets_str = ", ".join(f"{t['owner']}/{t['repo']}" for t in inc.targets)
        lines.append(f"  {inc.id:<20s} {inc.name}{cve_str}")
        lines.append(f"  {'':20s} Date: {inc.date} | Targets: {targets_str}")
        lines.append("")
    lines.append("Usage: python scan.py --org <org> --incident <id>")
    return "\n".join(lines)
